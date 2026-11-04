"""GuardedWriteClient over the fake (E5-2): ownership guard, fence gate per mutating call, idempotency, lookups,
error classes. The SDK transport side (allowlist on a real keystoneauth session) is in test_openstack_allowlist.py.

Every "refused" test asserts two things: the typed error, and that **nothing mutating reached the cloud** (the fake
records each operation it receives in ``calls``; the gate recorder records each gate check)."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

import pytest

from ovlm.openstack import errors
from ovlm.openstack.allowlist import TAG_MANAGED, WRITE_OPERATIONS
from ovlm.openstack.fake import FakeOpenStack
from ovlm.openstack.interface import WriteClient
from ovlm.openstack.ownership import InMemoryOwnershipRegistry, ResourceKind, run_tag
from ovlm.openstack.retry import CLASSIFICATION, RetryClass, classify
from ovlm.openstack.types import CreateServerSpec
from ovlm.openstack.write import GuardedWriteClient
from ovlm.workflow import ErrorClass, Fence, FenceLost
from ovlm.workflow.clock import FakeClock

RUN = str(uuid.UUID(int=0xA11CE))
SERVER, VOLUME, FIP = ResourceKind.SERVER, ResourceKind.VOLUME, ResourceKind.FLOATING_IP


@dataclass
class RecordingGate:
    """Stands in for ``ctx.gate``: records each check and the cloud's mutating-call count at that moment."""

    fake: FakeOpenStack
    checks: list[tuple[str, int]] = field(default_factory=list)
    refuse: bool = False

    def __call__(self, action: str) -> None:
        mutating = sum(1 for c in self.fake.calls if c in WRITE_OPERATIONS)
        self.checks.append((action, mutating))
        if self.refuse:
            raise FenceLost(action, "test: deadline passed")

    @property
    def actions(self) -> list[str]:
        return [a for a, _ in self.checks]


@dataclass
class World:
    fake: FakeOpenStack
    reg: InMemoryOwnershipRegistry
    gate: RecordingGate
    client: GuardedWriteClient
    ids: dict[str, str]

    def mutating_calls(self) -> list[str]:
        return [c for c in self.fake.calls if c in WRITE_OPERATIONS]


def make_world() -> World:
    fake = FakeOpenStack(strict_gate=False)  # cloud set-up below acts as the cloud, not as OVLM
    ids = {
        "image": fake.add_image(),
        "flavor": fake.add_flavor(),
        "net": fake.add_network("net"),
        "ext": fake.add_network("ext", external=True),
    }
    ids["blue"] = fake.add_server("blue", tags=[TAG_MANAGED, "team:web"])
    ids["vol"] = fake.add_volume("data", metadata={"ovlm.managed": "true", "owner": "team"})
    fake.attach_volume(ids["blue"], ids["vol"])
    fake.tick(30)
    ids["blue_port"] = fake.add_port(ids["net"], device_id=ids["blue"], ip="10.0.0.5")
    ids["fip"] = fake.add_floating_ip(ids["ext"], tags=[TAG_MANAGED])
    fake.add_router_path(ids["net"], ids["ext"])
    fake.update_floating_ip(ids["fip"], ids["blue_port"])
    fake.tick(5)
    # green, as B3 would leave it
    ids["green"] = fake.add_server("ovlm-web-a11ce-1", tags=[TAG_MANAGED, run_tag(RUN)])
    ids["green_port"] = fake.add_port(ids["net"], device_id=ids["green"], ip="10.0.0.6")
    # resources OVLM must never touch
    ids["foreign"] = fake.add_server(
        "someone-else", tags=[TAG_MANAGED]
    )  # marker, but not registered
    ids["foreign_port"] = fake.add_port(ids["net"], device_id=ids["foreign"], ip="10.0.0.9")

    reg = InMemoryOwnershipRegistry(RUN)
    reg.register(SERVER, ids["blue"])
    reg.register(VOLUME, ids["vol"])
    reg.register(FIP, ids["fip"])
    reg.register(SERVER, ids["green"], origin="created", deletable=True)

    fake.calls.clear()
    fake.strict_gate = True  # from here on, a write without a bound gate is refused
    gate = RecordingGate(fake)
    return World(fake, reg, gate, GuardedWriteClient(fake, reg, gate), ids)


@pytest.fixture
def w() -> World:
    return make_world()


def test_guarded_client_and_fake_satisfy_the_write_protocol(w: World) -> None:
    assert isinstance(w.client, WriteClient)
    assert isinstance(w.fake, WriteClient)


# --- rule 1: an unregistered target is refused before any request -------------------------------------------

UNREGISTERED_CALLS = {
    "stop_server": lambda c, i: c.stop_server(i["foreign"]),
    "start_server": lambda c, i: c.start_server(i["foreign"]),
    "lock_server": lambda c, i: c.lock_server(i["foreign"], f"ovlm:retained:{RUN}"),
    "unlock_server": lambda c, i: c.unlock_server(i["foreign"]),
    "delete_server": lambda c, i: c.delete_server(i["foreign"]),
    "attach_volume (server)": lambda c, i: c.attach_volume(i["foreign"], i["vol"]),
    "detach_volume (server)": lambda c, i: c.detach_volume(i["foreign"], i["vol"]),
    "add_server_tag (claim)": lambda c, i: c.add_server_tag(i["foreign"], TAG_MANAGED),
    "get_console_output": lambda c, i: c.get_console_output(i["foreign"]),
    "update_floating_ip (port of foreign server)": lambda c, i: c.update_floating_ip(
        i["fip"], i["foreign_port"]
    ),
}


@pytest.mark.parametrize("call", list(UNREGISTERED_CALLS), ids=list(UNREGISTERED_CALLS))
def test_unregistered_target_is_refused_before_any_request(w: World, call: str) -> None:
    with pytest.raises(errors.OwnershipViolationError) as exc:
        UNREGISTERED_CALLS[call](w.client, w.ids)
    assert exc.value.reason in {"not_registered", "port_not_owned"}
    assert w.mutating_calls() == []
    assert w.gate.checks == []
    assert classify(exc.value) is RetryClass.NEEDS_HUMAN


@pytest.mark.parametrize(
    "call",
    [
        lambda c, i: c.attach_volume(i["green"], "11111111-0000-0000-0000-000000000000"),
        lambda c, i: c.update_floating_ip("22222222-0000-0000-0000-000000000000", i["green_port"]),
        lambda c, i: c.add_floating_ip_tag("22222222-0000-0000-0000-000000000000", TAG_MANAGED),
        lambda c, i: c.merge_volume_metadata(
            "11111111-0000-0000-0000-000000000000", {"ovlm.managed": "true"}
        ),
    ],
    ids=["volume", "fip", "fip claim", "volume claim"],
)
def test_unregistered_volume_or_fip_is_refused(w: World, call: object) -> None:
    with pytest.raises(errors.OwnershipViolationError, match="not registered"):
        call(w.client, w.ids)  # type: ignore[operator]
    assert w.mutating_calls() == [] and w.gate.checks == []


def test_the_marker_alone_never_grants_authority(w: World) -> None:
    """``foreign`` carries ``ovlm:managed`` (anyone can set it): rule 2 adds nothing without rule 1."""
    assert TAG_MANAGED in w.fake.get_server(w.ids["foreign"]).tags
    with pytest.raises(errors.OwnershipViolationError, match="not registered"):
        w.client.stop_server(w.ids["foreign"])
    assert w.mutating_calls() == []


def test_registration_removed_mid_run_takes_effect_at_the_next_call(w: World) -> None:
    w.client.lock_server(w.ids["blue"], "ovlm:retained:" + RUN)
    w.reg.unregister(SERVER, w.ids["blue"])
    with pytest.raises(errors.OwnershipViolationError):
        w.client.unlock_server(w.ids["blue"])
    assert w.mutating_calls() == ["lock_server"]


# --- rule 2: a registered but unmarked target is refused --------------------------------------------------


def test_untagged_registered_server_is_refused_for_every_mutation(w: World) -> None:
    w.fake.touch_server(w.ids["blue"], tags=["team:web"])  # a member removed the marker
    calls: list[Callable[[], object]] = [
        lambda: w.client.stop_server(w.ids["blue"]),
        lambda: w.client.start_server(w.ids["blue"]),
        lambda: w.client.lock_server(w.ids["blue"], f"ovlm:retained:{RUN}"),
        lambda: w.client.unlock_server(w.ids["blue"]),
        lambda: w.client.detach_volume(w.ids["blue"], w.ids["vol"]),
        lambda: w.client.update_floating_ip(w.ids["fip"], w.ids["blue_port"]),
    ]
    for call in calls:
        with pytest.raises(errors.OwnershipViolationError) as exc:
            call()
        assert exc.value.reason == "marker_missing"
    assert w.mutating_calls() == [] and w.gate.checks == []


def test_created_server_needs_this_runs_tag(w: World) -> None:
    w.fake.touch_server(w.ids["green"], tags=[TAG_MANAGED, run_tag(str(uuid.uuid4()))])
    with pytest.raises(errors.OwnershipViolationError, match="ovlm:run:"):
        w.client.stop_server(w.ids["green"])
    with pytest.raises(errors.OwnershipViolationError):
        w.client.delete_server(w.ids["green"])
    assert w.mutating_calls() == []


def test_unmarked_volume_and_fip_are_refused(w: World) -> None:
    w.fake._volumes[w.ids["vol"]].metadata.pop("ovlm.managed")
    with pytest.raises(errors.OwnershipViolationError, match="ovlm.managed"):
        w.client.detach_volume(w.ids["blue"], w.ids["vol"])
    fip = w.fake._fips[w.ids["fip"]]
    w.fake._fips[w.ids["fip"]] = type(fip)(**{**fip.__dict__, "tags": ()})
    with pytest.raises(errors.OwnershipViolationError, match="lacks ovlm:managed"):
        w.client.update_floating_ip(w.ids["fip"], w.ids["green_port"])
    assert w.mutating_calls() == []


def test_minimal_construct_is_unverifiable(w: World) -> None:
    w.fake.touch_server(w.ids["blue"], minimal=True)
    with pytest.raises(errors.OwnershipViolationError) as exc:
        w.client.stop_server(w.ids["blue"])
    assert exc.value.reason == "unverifiable"


# --- claim_resources: rule 1 only, add/merge only, read back ----------------------------------------------


def test_claim_adds_the_marker_to_an_unmarked_registered_server_and_keeps_foreign_tags(
    w: World,
) -> None:
    w.fake.touch_server(w.ids["blue"], tags=["team:web", "backup"])
    w.client.add_server_tag(w.ids["blue"], TAG_MANAGED)
    assert set(w.fake.get_server(w.ids["blue"]).tags) == {"team:web", "backup", TAG_MANAGED}
    assert w.mutating_calls() == ["add_server_tag"]
    w.client.add_server_tag(
        w.ids["blue"], TAG_MANAGED
    )  # set semantics: nothing sent the second time
    assert w.mutating_calls() == ["add_server_tag"]


def test_claim_merges_volume_metadata_and_keeps_foreign_keys(w: World) -> None:
    w.fake._volumes[w.ids["vol"]].metadata = {"owner": "team", "backup": "daily"}
    w.client.merge_volume_metadata(w.ids["vol"], {"ovlm.managed": "true"})
    assert w.fake.get_volume(w.ids["vol"]).metadata == {
        "owner": "team",
        "backup": "daily",
        "ovlm.managed": "true",
    }
    w.client.merge_volume_metadata(w.ids["vol"], {"ovlm.managed": "true"})
    assert w.mutating_calls() == ["merge_volume_metadata"]


def test_claim_tags_the_fip(w: World) -> None:
    fip = w.fake._fips[w.ids["fip"]]
    w.fake._fips[w.ids["fip"]] = type(fip)(**{**fip.__dict__, "tags": ("dns:web",)})
    w.client.add_floating_ip_tag(w.ids["fip"], TAG_MANAGED)
    assert set(w.fake.get_floating_ip(w.ids["fip"]).tags) == {"dns:web", TAG_MANAGED}


@pytest.mark.parametrize("tag", ["team:web", "x", "ovlm:a/b", "ovlm:" + "x" * 60])
def test_claim_only_adds_valid_ovlm_tags(w: World, tag: str) -> None:
    with pytest.raises(errors.WriteNotAllowedError):
        w.client.add_server_tag(w.ids["blue"], tag)
    with pytest.raises(errors.WriteNotAllowedError):
        w.client.merge_volume_metadata(w.ids["vol"], {"owner": "me"})
    assert w.mutating_calls() == []


def test_claim_at_the_tag_limit_is_fatal(w: World) -> None:
    w.fake.touch_server(w.ids["blue"], tags=[f"t{i}" for i in range(50)])
    with pytest.raises(errors.MarkerLimitError) as exc:
        w.client.add_server_tag(w.ids["blue"], TAG_MANAGED)
    assert classify(exc.value) is RetryClass.FATAL
    assert w.mutating_calls() == []


def test_claim_detects_a_lost_foreign_marker(w: World) -> None:
    """If the cloud's verb replaced instead of merged (verb semantics are AS until the lab), the read-back
    catches it: fatal, never silently accepted."""
    original = w.fake.merge_volume_metadata

    def replacing(volume_id: str, items: Mapping[str, str]) -> None:
        original(volume_id, items)
        w.fake._volumes[volume_id].metadata = dict(items)  # what a replace-all would do

    w.fake.merge_volume_metadata = replacing  # type: ignore[method-assign]
    with pytest.raises(errors.ForeignMarkerLossError) as exc:
        w.client.merge_volume_metadata(w.ids["vol"], {"ovlm.run": RUN})
    assert classify(exc.value) is RetryClass.FATAL


# --- fence gate: before each mutating call, never for reads -------------------------------------------------


def test_gate_fires_before_each_mutating_call_and_never_for_reads(w: World) -> None:
    c, i = w.client, w.ids
    c.get_server(i["blue"])
    c.list_servers(tags=[TAG_MANAGED])
    assert w.gate.checks == []
    c.stop_server(i["blue"])
    w.fake.tick(30)
    c.detach_volume(i["blue"], i["vol"])
    w.fake.tick(30)
    c.attach_volume(i["green"], i["vol"])
    w.fake.tick(30)
    c.update_floating_ip(i["fip"], i["green_port"])
    c.lock_server(i["blue"], f"ovlm:retained:{RUN}")
    assert w.gate.actions == [
        "openstack:stop_server",
        "openstack:detach_volume",
        "openstack:attach_volume",
        "openstack:update_floating_ip",
        "openstack:lock_server",
    ]
    # each check happened while the cloud had seen exactly the previous mutating calls: before, not after
    assert [n for _, n in w.gate.checks] == [0, 1, 2, 3, 4]
    assert w.mutating_calls() == [
        "stop_server",
        "detach_volume",
        "attach_volume",
        "update_floating_ip",
        "lock_server",
    ]


def test_a_lost_fence_sends_nothing(w: World) -> None:
    w.gate.refuse = True
    before = w.fake.snapshot()
    for call in (
        lambda: w.client.stop_server(w.ids["blue"]),
        lambda: w.client.update_floating_ip(w.ids["fip"], w.ids["green_port"]),
        lambda: w.client.delete_server(w.ids["green"]),
        lambda: w.client.add_server_tag(w.ids["blue"], "ovlm:extra"),
    ):
        with pytest.raises(FenceLost):
            call()
    assert w.mutating_calls() == []
    assert w.fake.snapshot() == before


def test_a_real_fence_past_its_deadline_stops_the_call(w: World) -> None:
    clock = FakeClock()
    fence = Fence(clock=clock, lease_duration=30, fence_margin=5, t_send=clock.monotonic())
    client = GuardedWriteClient(w.fake, w.reg, fence.check)
    client.stop_server(w.ids["blue"])  # inside the lease
    clock.advance(26)  # past t_send + 30 - 5
    w.fake.tick(30)
    with pytest.raises(FenceLost):
        client.start_server(w.ids["blue"])
    assert w.mutating_calls() == ["stop_server"]


def test_fence_lost_is_not_an_exception_steps_can_swallow(w: World) -> None:
    w.gate.refuse = True
    with pytest.raises(FenceLost):
        try:
            w.client.stop_server(w.ids["blue"])
        except Exception:  # what a careless step would write
            pytest.fail("FenceLost must not be catchable as Exception")


def test_no_gate_bound_means_no_write(w: World) -> None:
    with pytest.raises(errors.WriteNotAllowedError, match="no fence gate"):
        w.fake.stop_server(w.ids["blue"])  # direct backend call, outside a guarded client
    assert w.mutating_calls() == []


def test_client_needs_a_gate() -> None:
    world = make_world()
    with pytest.raises(errors.WriteNotAllowedError):
        GuardedWriteClient(world.fake, world.reg, None)  # type: ignore[arg-type]


# --- create: intended ledger row, tags at create, lookup by tag + exact name --------------------------------


def _spec(
    w: World, name: str = "ovlm-web-a11ce-2", tags: tuple[str, ...] | None = None
) -> CreateServerSpec:
    return CreateServerSpec(
        name=name,
        image_id=w.ids["image"],
        flavor_id=w.ids["flavor"],
        network_id=w.ids["net"],
        tags=(TAG_MANAGED, run_tag(RUN)) if tags is None else tags,
        user_data="#cloud-config\n",
    )


def test_create_requires_an_intended_ledger_row(w: World) -> None:
    with pytest.raises(errors.OwnershipViolationError, match="intended"):
        w.client.create_server(_spec(w))
    assert w.mutating_calls() == []


def test_create_requires_the_tags_at_create(w: World) -> None:
    w.reg.intend_server("ovlm-web-a11ce-2")
    with pytest.raises(errors.OwnershipViolationError, match="tags"):
        w.client.create_server(_spec(w, tags=(TAG_MANAGED,)))
    assert w.mutating_calls() == []


def test_create_then_lost_response_is_found_by_tag_and_name_and_never_recreated(w: World) -> None:
    w.reg.intend_server("ovlm-web-a11ce-2")
    w.fake.fail(
        "create_server", errors.ServerError("gateway timeout", status=504), when="after_apply"
    )
    with pytest.raises(errors.ServerError) as exc:
        w.client.create_server(_spec(w))
    assert classify(exc.value) is RetryClass.RETRYABLE
    found = w.client.find_run_server("ovlm-web-a11ce-2")
    assert found is not None and run_tag(RUN) in found.tags
    with pytest.raises(errors.DuplicateResourceError):  # the retry must adopt, not create
        w.client.create_server(_spec(w))
    assert w.mutating_calls() == ["create_server"]


def test_create_happy_path_and_build_states(w: World) -> None:
    w.reg.intend_server("ovlm-web-a11ce-2")
    info = w.client.create_server(_spec(w))
    assert info.status == "BUILD" and run_tag(RUN) in info.tags
    assert w.client.build_state(info.openstack_id) is None
    w.fake.tick(60)
    active = w.client.build_state(info.openstack_id)
    assert active is not None and active.status == "ACTIVE"


def test_no_valid_host_is_fatal_with_the_fault_message(w: World) -> None:
    w.reg.intend_server("ovlm-web-a11ce-2")
    w.fake.force_no_valid_host = True
    info = w.client.create_server(_spec(w))
    w.fake.tick(60)
    with pytest.raises(errors.NoValidHostError, match="No valid host") as exc:
        w.client.build_state(info.openstack_id)
    assert classify(exc.value) is RetryClass.FATAL


def test_lookup_with_two_matches_is_a_typed_error(w: World) -> None:
    w.fake.add_server("ovlm-web-a11ce-1", tags=[TAG_MANAGED, run_tag(RUN)])  # same name as green
    with pytest.raises(errors.DuplicateResourceError) as exc:
        w.client.find_run_server("ovlm-web-a11ce-1")
    assert len(exc.value.matches) == 2
    assert classify(exc.value) is RetryClass.NEEDS_HUMAN


def test_lookup_is_exact_and_ignores_metadata(w: World) -> None:
    w.fake.add_server("ovlm-web-a11ce-10", tags=[TAG_MANAGED, run_tag(RUN)])  # prefix, not equal
    w.fake.add_server(
        "ovlm-web-a11ce-1", metadata={"ovlm.run": RUN}
    )  # metadata only: never a match
    found = w.client.find_run_server("ovlm-web-a11ce-1")
    assert found is not None and found.openstack_id == w.ids["green"]


# --- delete: rule 3 ------------------------------------------------------------------------------------------


def test_delete_green_on_rollback(w: World) -> None:
    w.client.delete_server(w.ids["green"])
    with pytest.raises(errors.NotFoundError):
        w.fake.get_server(w.ids["green"])
    w.client.delete_server(w.ids["green"])  # already gone: success, nothing sent
    assert w.mutating_calls() == ["delete_server"]


def test_delete_needs_the_deletable_registration(w: World) -> None:
    with pytest.raises(errors.OwnershipViolationError) as exc:
        w.client.delete_server(
            w.ids["blue"]
        )  # registered, marked, but not the approved retirement target
    assert exc.value.reason == "not_deletable"
    assert w.mutating_calls() == []


def test_delete_refuses_a_server_with_the_data_volume_attached(w: World) -> None:
    w.reg.register(SERVER, w.ids["blue"], deletable=True)  # G3 approved
    with pytest.raises(errors.OwnershipViolationError) as exc:
        w.client.delete_server(w.ids["blue"])
    assert exc.value.reason == "volume_attached"
    assert w.mutating_calls() == []
    assert w.ids["vol"] in w.fake.snapshot()["volumes"]


def test_delete_refuses_any_volume_with_delete_on_termination_not_false(w: World) -> None:
    other = w.fake.add_volume("scratch")
    w.fake.strict_gate = False
    w.fake.attach_volume(w.ids["green"], other)
    w.fake.tick(30)
    w.fake.strict_gate = True
    w.fake._servers[w.ids["green"]].attached[other] = True  # BFV-style flag
    with pytest.raises(errors.OwnershipViolationError) as exc:
        w.client.delete_server(w.ids["green"])
    assert exc.value.reason == "delete_on_termination"
    w.fake._servers[w.ids["green"]].attached[other] = None  # type: ignore[assignment]  # unknown = unsafe
    with pytest.raises(errors.OwnershipViolationError):
        w.client.delete_server(w.ids["green"])
    assert "delete_server" not in w.fake.calls


def test_volume_and_fip_deletion_do_not_exist() -> None:
    """By construction: no such method anywhere on the write client (the allowlist refuses the requests too)."""
    for name in ("delete_volume", "create_volume", "delete_floating_ip", "allocate_floating_ip",
                 "create_floating_ip", "delete_port", "update_security_group", "set_server_metadata",
                 "set_server_tags", "replace_volume_metadata"):  # fmt: skip
        assert not hasattr(GuardedWriteClient, name), name


# --- idempotency: goal reached -> nothing sent ----------------------------------------------------------------


def test_repeated_calls_send_nothing_once_the_goal_is_reached(w: World) -> None:
    c, i = w.client, w.ids
    c.stop_server(i["blue"])
    w.fake.tick(30)
    c.stop_server(i["blue"])
    c.detach_volume(i["blue"], i["vol"])
    w.fake.tick(30)
    c.detach_volume(i["blue"], i["vol"])
    c.attach_volume(i["green"], i["vol"])
    w.fake.tick(30)
    c.attach_volume(i["green"], i["vol"])
    c.update_floating_ip(i["fip"], i["green_port"])
    c.update_floating_ip(i["fip"], i["green_port"])
    c.lock_server(i["blue"], f"ovlm:retained:{RUN}")
    c.lock_server(i["blue"], f"ovlm:retained:{RUN}")
    c.unlock_server(i["blue"])
    c.unlock_server(i["blue"])
    c.start_server(i["green"])
    assert w.mutating_calls() == [
        "stop_server",
        "detach_volume",
        "attach_volume",
        "update_floating_ip",
        "lock_server",
        "unlock_server",
    ]


def test_detach_in_progress_is_not_resent(w: World) -> None:
    w.client.stop_server(w.ids["blue"])
    w.fake.tick(30)
    w.client.detach_volume(w.ids["blue"], w.ids["vol"])
    w.client.detach_volume(w.ids["blue"], w.ids["vol"])  # volume "detaching": the step polls
    assert w.mutating_calls().count("detach_volume") == 1


def test_attach_already_attached_elsewhere_is_not_success(w: World) -> None:
    with pytest.raises(errors.BadRequestError) as exc:  # vol is in-use on blue
        w.client.attach_volume(w.ids["green"], w.ids["vol"])
    assert classify(exc.value) is RetryClass.FATAL


def test_already_attached_400_on_the_target_is_success(w: World) -> None:
    """The volume shows attached to green only in Nova's view yet (race): the 400 is turned into success."""
    w.client.stop_server(w.ids["blue"])
    w.fake.tick(30)
    w.client.detach_volume(w.ids["blue"], w.ids["vol"])
    w.fake.tick(30)
    w.client.attach_volume(w.ids["green"], w.ids["vol"])
    w.fake.tick(2)  # "attaching": not yet in-use
    w.client.attach_volume(w.ids["green"], w.ids["vol"])
    assert (
        w.mutating_calls().count("attach_volume") == 2
    )  # second one answered 400 "already attached"


# --- locks ---------------------------------------------------------------------------------------------------


def test_foreign_lock_is_left_alone(w: World) -> None:
    w.fake.touch_server(w.ids["blue"], locked=True, locked_reason="maintenance by ops")
    with pytest.raises(errors.ForeignLockError) as exc:
        w.client.unlock_server(w.ids["blue"])
    assert classify(exc.value) is RetryClass.NEEDS_HUMAN
    with pytest.raises(errors.ForeignLockError) as exc2:
        w.client.lock_server(w.ids["blue"], f"ovlm:retained:{RUN}")
    assert exc2.value.locked_reason == "maintenance by ops"  # for the step evidence
    assert w.mutating_calls() == []


@pytest.mark.parametrize(
    "reason",
    [
        "ovlm:retained:x",
        "ovlm:retained:other-run",
        f"ovlm:{RUN}",
        f"ovlm:retained:{RUN}:x",
        "ovlm:",
    ],
)
def test_an_ovlm_prefixed_lock_of_another_run_or_unknown_form_is_foreign(
    w: World, reason: str
) -> None:
    """SEC-C-6: any project member can lock with an ``ovlm:`` reason; only this run's full reason is its own."""
    w.fake.touch_server(w.ids["blue"], locked=True, locked_reason=reason)
    with pytest.raises(errors.ForeignLockError) as exc:
        w.client.unlock_server(w.ids["blue"])
    assert exc.value.locked_reason == reason
    assert classify(exc.value) is RetryClass.NEEDS_HUMAN
    with pytest.raises(errors.ForeignLockError):
        w.client.lock_server(w.ids["blue"], f"ovlm:restored:{RUN}")
    assert w.mutating_calls() == []


def test_own_locks_are_recognised_and_can_change_kind(w: World) -> None:
    assert w.client.own_lock_reasons() == {f"ovlm:retained:{RUN}", f"ovlm:restored:{RUN}"}
    w.client.lock_server(w.ids["blue"], f"ovlm:retained:{RUN}")
    w.client.lock_server(w.ids["blue"], f"ovlm:restored:{RUN}")  # own lock, other kind: re-lock
    w.client.unlock_server(w.ids["blue"])
    assert w.mutating_calls() == ["lock_server", "lock_server", "unlock_server"]


def test_ovlm_locks_carry_an_ovlm_reason(w: World) -> None:
    for reason in (None, "", "retention", "ovlm:retained:x", "ovlm:retained:other-run"):
        with pytest.raises(errors.WriteNotAllowedError):
            w.client.lock_server(w.ids["blue"], reason)
    assert w.mutating_calls() == []


def test_admin_lock_cannot_be_unlocked(w: World) -> None:
    w.fake.touch_server(
        w.ids["blue"], locked=True, locked_by="admin", locked_reason=f"ovlm:retained:{RUN}"
    )
    with pytest.raises(errors.ForbiddenError) as exc:
        w.client.unlock_server(w.ids["blue"])
    assert classify(exc.value) is RetryClass.NEEDS_HUMAN


def test_stop_of_a_locked_server_is_409_needs_human(w: World) -> None:
    w.fake.touch_server(
        w.ids["blue"], locked=True, locked_by="admin", locked_reason="ovlm:retained:x"
    )
    with pytest.raises(errors.InstanceLockedError) as exc:
        w.client.stop_server(w.ids["blue"])
    assert classify(exc.value) is RetryClass.NEEDS_HUMAN


# --- floating IP ---------------------------------------------------------------------------------------------


def test_fip_without_router_path_is_the_misleading_404_and_needs_human(w: World) -> None:
    other_net = w.fake.add_network("isolated")
    w.fake.touch_server(w.ids["green"])
    port = w.fake.add_port(other_net, device_id=w.ids["green"], ip="10.1.0.6")
    with pytest.raises(errors.FloatingIpNoRouterPathError) as exc:
        w.client.update_floating_ip(w.ids["fip"], port)
    assert exc.value.status == 404
    assert classify(exc.value) is RetryClass.NEEDS_HUMAN
    assert w.fake.get_floating_ip(w.ids["fip"]).port_id == w.ids["blue_port"]  # nothing changed


def test_fip_disassociation_is_not_offered(w: World) -> None:
    with pytest.raises(errors.WriteNotAllowedError):
        w.client.update_floating_ip(w.ids["fip"], "")
    assert w.mutating_calls() == []


def test_fip_to_an_unbound_port_is_refused(w: World) -> None:
    loose = w.fake.add_port(w.ids["net"], ip="10.0.0.77")
    with pytest.raises(errors.OwnershipViolationError, match="not bound"):
        w.client.update_floating_ip(w.ids["fip"], loose)


# --- injected faults pass through typed ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (errors.ServerError("boom", status=503), RetryClass.RETRYABLE),
        (errors.ConflictError("task_state powering-off", status=409), RetryClass.RETRYABLE),
        (errors.AuthenticationError("expired", status=401), RetryClass.RETRYABLE),
        (errors.OpenStackError("connection reset"), RetryClass.RETRYABLE),
        (errors.ForbiddenError("policy", status=403), RetryClass.NEEDS_HUMAN),
    ],
)
def test_injected_faults_surface_typed(w: World, error: Exception, expected: RetryClass) -> None:
    w.fake.fail("stop_server", error)
    with pytest.raises(type(error)) as exc:
        w.client.stop_server(w.ids["blue"])
    assert classify(exc.value) is expected
    assert w.gate.actions == ["openstack:stop_server"]  # the gate ran before the (failing) send


def test_retry_classes_match_the_engine_error_classes() -> None:
    assert {c.value for c in RetryClass} == {c.value for c in ErrorClass}
    for _cls, retry_class, _why in CLASSIFICATION:
        assert ErrorClass(retry_class.value)


def test_classification_lists_subclasses_before_their_bases() -> None:
    seen: list[type[Exception]] = []
    for cls, _rc, _why in CLASSIFICATION:
        for earlier in seen:
            assert not issubclass(cls, earlier) or cls is earlier, (
                f"{cls.__name__} shadowed by {earlier}"
            )
        seen.append(cls)


def test_unknown_exception_is_retryable() -> None:
    assert classify(ValueError("x")) is RetryClass.RETRYABLE


def test_write_microversions_are_recorded(w: World) -> None:
    assert w.client.write_microversions()["compute_write"] == "2.79"
    w.fake.compute_max = (2, 60)
    with pytest.raises(errors.UnsupportedCloudError):
        w.client.write_microversions()
