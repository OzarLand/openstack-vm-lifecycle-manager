"""The fake models the documented cloud gotchas (testing-strategy.md s.3.3; openstack-integration.md)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from ovlm.openstack import errors
from ovlm.openstack.fake import FakeOpenStack
from ovlm.openstack.interface import ReadClient, WriteClient
from ovlm.openstack.types import CreateServerSpec


def test_fake_implements_both_protocols() -> None:
    fake = FakeOpenStack()
    assert isinstance(fake, ReadClient) and isinstance(fake, WriteClient)


def test_microversion_floor_and_report() -> None:
    assert FakeOpenStack().negotiated_versions().compute_used == (2, 100)
    with pytest.raises(errors.UnsupportedCloudError):
        FakeOpenStack(compute_max=(2, 40)).negotiated_versions()


# --- servers: listing gotchas -----------------------------------------------------------------------------------


def test_metadata_filter_is_ignored_for_non_admins_and_returns_every_server() -> None:
    fake = FakeOpenStack(role="member")
    mine = fake.add_server("mine", metadata={"ovlm": "exp01"})
    fake.add_server("foreign", metadata={"other": "x"})
    result = fake.list_servers(metadata={"ovlm": "exp01"})
    assert len(result) == 2 and mine in {s.openstack_id for s in result}  # LAB-OBSERVED


def test_metadata_filter_works_for_admin() -> None:
    fake = FakeOpenStack(role="admin")
    mine = fake.add_server("mine", metadata={"ovlm": "exp01"})
    fake.add_server("foreign")
    assert [s.openstack_id for s in fake.list_servers(metadata={"ovlm": "exp01"})] == [mine]


def test_tag_filters_work() -> None:
    fake = FakeOpenStack()
    a = fake.add_server("a", tags=["ovlm:managed", "ovlm:run:1"])
    fake.add_server("b", tags=["ovlm:managed"])
    fake.add_server("c")
    assert [s.openstack_id for s in fake.list_servers(tags=["ovlm:managed", "ovlm:run:1"])] == [a]
    assert len(fake.list_servers(tags_any=["ovlm:run:1", "nope"])) == 1
    assert fake.list_servers(tags=["nothing"]) == []


def test_names_are_not_unique() -> None:
    fake = FakeOpenStack()
    fake.add_server("dup")
    fake.add_server("dup")
    assert len(fake.list_servers(name="dup")) == 2


def test_changes_since_returns_tombstones_and_plain_listing_does_not() -> None:
    fake = FakeOpenStack()
    sid = fake.add_server("gone-soon")
    fake.add_server("stays")
    fake.tick(60)
    t0 = fake.now
    fake.delete_server(sid)
    assert [s.name for s in fake.list_servers()] == ["stays"]
    delta = fake.list_servers(changes_since=t0 - timedelta(seconds=1))
    assert [(s.openstack_id, s.status) for s in delta] == [(sid, "DELETED")]
    fake.purge_tombstones()
    assert fake.list_servers(changes_since=t0 - timedelta(seconds=1)) == []


def test_minimal_construct_for_unreachable_cell() -> None:
    fake = FakeOpenStack()
    fake.add_server("hidden", minimal=True)
    (s,) = fake.list_servers()
    assert (
        s.status == "UNKNOWN"
        and s.is_minimal_construct
        and s.name is None
        and s.flavor_original_name is None
    )


# --- create, tags, quota, scheduler ---------------------------------------------------------------------------


def _spec(fake: FakeOpenStack, **kw: object) -> CreateServerSpec:
    return CreateServerSpec(
        name=str(kw.pop("name", "green")),
        image_id=fake.add_image(),
        flavor_id=fake.add_flavor(),
        **kw,  # type: ignore[arg-type]
    )


def test_create_sets_tags_atomically_and_builds_asynchronously() -> None:
    fake = FakeOpenStack()
    s = fake.create_server(_spec(fake, tags=("ovlm:managed", "ovlm:run:abc")))
    assert s.status == "BUILD" and s.tags == ("ovlm:managed", "ovlm:run:abc")
    # listable by tag while still BUILD: a crashed worker never creates a second one (OSI s.3)
    assert [x.openstack_id for x in fake.list_servers(tags=["ovlm:run:abc"])] == [s.openstack_id]
    fake.tick(fake.build_delay)
    assert fake.get_server(s.openstack_id).status == "ACTIVE"


def test_tags_at_create_need_2_52() -> None:
    fake = FakeOpenStack(compute_max=(2, 40))
    with pytest.raises(errors.BadRequestError):
        fake.create_server(_spec(fake, tags=("x",)))


def test_over_quota_is_403_and_no_valid_host_is_an_error_server() -> None:
    fake = FakeOpenStack()
    fake.quota_instances = 1
    fake.create_server(_spec(fake, name="one"))
    with pytest.raises(errors.QuotaExceededError):
        fake.create_server(_spec(fake, name="two"))
    fake2 = FakeOpenStack()
    fake2.force_no_valid_host = True
    s = fake2.create_server(_spec(fake2))
    fake2.tick(fake2.build_delay)
    assert fake2.get_server(s.openstack_id).status == "ERROR"  # quota fine, scheduler failed


def test_create_whose_response_is_lost_is_found_by_tag() -> None:
    fake = FakeOpenStack()
    fake.fail("create_server", errors.OpenStackError("timeout"), when="after_apply")
    with pytest.raises(errors.OpenStackError):
        fake.create_server(_spec(fake, tags=("ovlm:run:r1",)))
    assert (
        len(fake.list_servers(tags=["ovlm:run:r1"])) == 1
    )  # applied although the caller never learned the id


# --- volumes: async states, locks, refusal --------------------------------------------------------------------


def _attached_pair() -> tuple[FakeOpenStack, str, str]:
    fake = FakeOpenStack()
    srv = fake.add_server("blue")
    vol = fake.add_volume("data")
    fake.attach_volume(srv, vol)
    fake.tick(fake.reserve_delay + fake.attach_delay)
    return fake, srv, vol


def test_attach_goes_reserved_attaching_in_use_with_the_clock() -> None:
    fake = FakeOpenStack()
    srv, vol = fake.add_server("blue"), fake.add_volume("data")
    fake.attach_volume(srv, vol)
    assert fake.get_volume(vol).status == "reserved"
    fake.tick(fake.reserve_delay)
    assert fake.get_volume(vol).status == "attaching"
    fake.tick(fake.attach_delay)
    v = fake.get_volume(vol)
    assert v.status == "in-use" and [a.server_openstack_id for a in v.attachments] == [srv]
    assert [
        (a.volume_openstack_id, a.delete_on_termination)
        for a in fake.list_server_volume_attachments(srv)
    ] == [(vol, False)]


def test_detach_goes_detaching_then_available() -> None:
    fake, srv, vol = _attached_pair()
    fake.detach_volume(srv, vol)
    assert fake.get_volume(vol).status == "detaching"
    fake.tick(fake.detach_delay)
    assert (
        fake.get_volume(vol).status == "available" and fake.get_server(srv).attached_volumes == ()
    )


def test_refused_detach_rolls_back_to_in_use_after_the_timeout() -> None:
    fake = FakeOpenStack()
    srv = fake.add_server("blue", guest_refuses_detach=True)
    vol = fake.add_volume("data")
    fake.attach_volume(srv, vol)
    fake.tick(10)
    fake.detach_volume(srv, vol)
    fake.tick(fake.detach_delay + 1)
    assert fake.get_volume(vol).status == "detaching"  # still waiting for the guest
    fake.tick(fake.detach_refusal_timeout)
    assert fake.get_volume(vol).status == "in-use"  # rolled back, not an error state (OSI s.4)


def test_attach_of_in_use_volume_is_400() -> None:
    fake, _srv, vol = _attached_pair()
    other = fake.add_server("green")
    with pytest.raises(errors.BadRequestError, match="status must be available"):
        fake.attach_volume(other, vol)


def test_failed_attach_leaves_the_volume_attaching_with_error_attachment() -> None:
    fake = FakeOpenStack()
    srv, vol = fake.add_server("x"), fake.add_volume("v", attach_fails=True)
    fake.attach_volume(srv, vol)
    fake.tick(100)
    assert fake.get_volume(vol).status == "attaching"
    fake.admin_reset(vol, "available")  # only an operator can fix it
    assert fake.get_volume(vol).status == "available"


@pytest.mark.parametrize("op", ["stop_server", "start_server", "delete_server"])
def test_locked_server_refuses_state_changes_with_409(op: str) -> None:
    fake = FakeOpenStack()
    srv = fake.add_server(
        "blue", status="SHUTOFF" if op == "start_server" else "ACTIVE", locked=True
    )
    with pytest.raises(errors.InstanceLockedError):
        getattr(fake, op)(srv)


def test_locked_server_refuses_attach_and_detach() -> None:
    fake, srv, vol = _attached_pair()
    fake.lock_server(srv, "retention")
    with pytest.raises(errors.InstanceLockedError):
        fake.detach_volume(srv, vol)
    with pytest.raises(errors.InstanceLockedError):
        fake.attach_volume(srv, fake.add_volume("other"))
    fake.unlock_server(srv)  # the owner can unlock their own lock (LAB-OBSERVED)
    fake.detach_volume(srv, vol)


def test_admin_lock_cannot_be_unlocked_by_a_member() -> None:
    fake = FakeOpenStack(role="member")
    srv = fake.add_server("blue", locked=True, locked_by="admin")
    with pytest.raises(errors.ForbiddenError):
        fake.unlock_server(srv)


def test_detach_refused_when_the_compute_host_is_down() -> None:
    fake, srv, vol = _attached_pair()
    fake.set_host_down(srv)
    with pytest.raises(errors.ConflictError, match="down"):
        fake.detach_volume(srv, vol)


def test_server_with_a_task_in_progress_refuses_operations() -> None:
    fake = FakeOpenStack()
    srv = fake.add_server("blue")
    fake.stop_server(srv)
    with pytest.raises(errors.ConflictError):
        fake.delete_server(srv)
    fake.tick(fake.stop_delay)
    assert fake.get_server(srv).status == "SHUTOFF"


def test_delete_on_termination_only_flagged_volumes_die_with_the_server() -> None:
    fake, srv, vol = _attached_pair()
    keep = vol
    kill = fake.add_volume("scratch")
    fake.attach_volume(srv, kill)
    fake.tick(30)
    fake._server_raw(srv).attached[kill] = True
    fake.delete_server(srv)
    ids = {v.openstack_id for v in fake.list_volumes()}
    assert keep in ids and kill not in ids
    assert fake.get_volume(keep).status == "available"


# --- floating IP, pool, volume type, console -----------------------------------------------------------------


def _fip_world() -> tuple[FakeOpenStack, str, str, str]:
    fake = FakeOpenStack()
    net, ext = fake.add_network("tenant"), fake.add_network("ext", external=True)
    port = fake.add_port(net)
    fip = fake.add_floating_ip(ext)
    return fake, net, ext, port + "|" + fip  # packed for brevity


def test_floating_ip_without_router_path_is_the_misleading_404() -> None:
    fake, _net, _ext, packed = _fip_world()
    port, fip = packed.split("|")
    with pytest.raises(
        errors.FloatingIpNoRouterPathError, match="is not reachable from subnet"
    ) as exc:
        fake.update_floating_ip(fip, port)
    assert exc.value.status == 404
    assert fake.list_floating_ips()[0].port_id is None  # nothing changed


def test_floating_ip_association_is_immediate_and_status_follows_the_clock() -> None:
    fake, net, ext, packed = _fip_world()
    port, fip = packed.split("|")
    fake.add_router_path(net, ext)
    assert fake.update_floating_ip(fip, port).port_id == port
    assert fake.list_floating_ips()[0].status == "DOWN"
    fake.tick(fake.fip_status_delay)
    assert fake.list_floating_ips()[0].status == "ACTIVE"


def test_port_with_another_floating_ip_on_the_same_network_is_409() -> None:
    fake, net, ext, packed = _fip_world()
    port, fip = packed.split("|")
    fake.add_router_path(net, ext)
    fake.update_floating_ip(fip, port)
    second = fake.add_floating_ip(ext, address="192.0.2.77")
    with pytest.raises(errors.FloatingIpPortAlreadyAssociatedError):
        fake.update_floating_ip(second, port)


def test_empty_floating_ip_pool_is_400_although_quota_is_free() -> None:
    fake = FakeOpenStack()
    ext = fake.add_network("ext", external=True)
    with pytest.raises(errors.NoFloatingIpAvailableError):
        fake.allocate_floating_ip(ext)
    fake.set_floating_ip_pool(ext, 1)
    assert fake.allocate_floating_ip(ext).floating_network_id == ext


def test_missing_default_volume_type() -> None:
    fake = FakeOpenStack()
    fake.add_volume_type("NVMe")
    assert [t.is_default for t in fake.list_volume_types()] == [False]
    with pytest.raises(errors.ServerError, match="__DEFAULT__"):
        fake.create_volume(1)
    assert fake.get_volume(fake.create_volume(1, volume_type="NVMe")).volume_type == "NVMe"
    fake.add_volume_type("std", default=True)
    assert fake.get_volume(fake.create_volume(1)).volume_type == "std"


def test_console_output_is_empty_by_default() -> None:
    fake = FakeOpenStack()
    srv = fake.add_server("x")
    assert fake.get_console_output(srv) == ""  # HTTP 200 with an empty body (LAB-OBSERVED)
    fake.set_console(srv, "a\nb\nc")
    assert fake.get_console_output(srv, length=2) == "b\nc"


# --- roles and fault injection ---------------------------------------------------------------------------------


def test_reader_cannot_mutate_but_can_read() -> None:
    fake = FakeOpenStack(role="reader")
    srv = fake.add_server("x")
    assert len(fake.list_servers()) == 1
    with pytest.raises(errors.ForbiddenError):
        fake.stop_server(srv)
    with pytest.raises(errors.ForbiddenError):
        fake.lock_server(srv)
    with pytest.raises(errors.ForbiddenError):
        fake.add_server_tag(srv, "t")


def test_fail_before_applies_nothing_and_nth_counts_calls() -> None:
    fake = FakeOpenStack()
    srv = fake.add_server("x")
    fake.fail("lock_server", errors.ConflictError("boom"), nth=2)
    fake.lock_server(srv)  # first call fine
    with pytest.raises(errors.ConflictError):
        fake.lock_server(srv)  # second fails
    fake.lock_server(srv)  # times=1: back to normal


def test_snapshot_shows_plain_state() -> None:
    fake, srv, vol = _attached_pair()
    snap = fake.snapshot()
    assert snap["volumes"][vol] == {"status": "in-use", "attached_to": [srv]}
