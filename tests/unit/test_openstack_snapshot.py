"""W4 pre-handoff snapshot on the OpenStack side: allowlist rule, guarded write client, fake model, SDK backend.

Rules under test (renewal-workflow.md W4, SRE-R-7, SRE-R-30/31, maintainer brief E5-4): snapshot of the registered,
marked, **detached** data volume only, never ``force``; one name per run; never duplicated; OVLM can never delete a
snapshot (no method, no allowlist rule); quota limits readable for the B1 pre-check."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import pytest
import requests

from ovlm.openstack import errors
from ovlm.openstack.allowlist import classify_write
from ovlm.openstack.fake import FakeOpenStack
from ovlm.openstack.types import BlockStorageLimits
from ovlm.openstack.write import SNAPSHOT_RUN_KEY, GuardedWriteClient, snapshot_name
from tests.unit.test_openstack_allowlist import RUN as ALLOW_RUN
from tests.unit.test_openstack_allowlist import VID, B, CannedCloud, _backend, kw
from tests.unit.test_openstack_write import RUN, World, make_world

NAME = f"ovlm-prehandoff-{ALLOW_RUN}"


def _body(**over: Any) -> dict[str, Any]:
    snap: dict[str, Any] = {"volume_id": VID, "name": NAME, "force": False,
                            "metadata": {"ovlm.managed": "true", "ovlm.run": ALLOW_RUN}}  # fmt: skip
    snap.update(over)
    return {"snapshot": {k: v for k, v in snap.items() if v is not None}}


# --- allowlist -------------------------------------------------------------------------------------------------


def test_the_snapshot_create_is_allowlisted() -> None:
    assert classify_write("POST", "/snapshots", kw(B, _body())) == "create_volume_snapshot"
    assert (
        classify_write("POST", "/snapshots", kw(B, _body(force=None))) == "create_volume_snapshot"
    )


@pytest.mark.parametrize(
    "body",
    [
        _body(force=True),  # a snapshot of an attached volume
        _body(force="false"),
        _body(name="backup-1"),  # not OVLM's name
        _body(metadata={"ovlm.run": ALLOW_RUN}),  # no ovlm.managed marker
        _body(metadata={"ovlm.managed": "true", "owner": "x"}),  # foreign metadata key
        _body(volume_id="../volumes"),
        {"snapshot": {**_body()["snapshot"], "snapshot_id": "x"}},  # unknown key
        {"snapshot": _body()["snapshot"], "extra": 1},
        None,
    ],
)
def test_other_snapshot_bodies_are_refused(body: Any) -> None:
    with pytest.raises(errors.WriteNotAllowedError):
        classify_write("POST", "/snapshots", kw(B, body))


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("DELETE", f"/snapshots/{VID}", None),
        ("POST", f"/snapshots/{VID}/action", {"os-force_delete": {}}),
        ("POST", f"/snapshots/{VID}/action", {"os-reset_status": {"status": "available"}}),
        ("PUT", f"/snapshots/{VID}", {"snapshot": {"name": "x"}}),
        ("POST", f"/snapshots/{VID}/metadata", {"metadata": {"ovlm.managed": "true"}}),
        (
            "POST",
            "/volumes",
            {"volume": {"snapshot_id": VID, "size": 1}},
        ),  # restoring from it: never
    ],
)
def test_no_other_snapshot_write_exists(method: str, path: str, body: Any) -> None:
    with pytest.raises(errors.WriteNotAllowedError):
        classify_write(method, path, kw(B, body))


def test_the_write_client_has_no_snapshot_delete() -> None:
    for name in (
        "delete_volume_snapshot",
        "delete_snapshot",
        "force_delete_snapshot",
        "reset_snapshot",
    ):
        assert not hasattr(GuardedWriteClient, name), name


# --- guarded client over the fake ------------------------------------------------------------------------------


def _detached(w: World) -> None:
    w.fake.strict_gate = False
    w.fake.detach_volume(w.ids["blue"], w.ids["vol"])
    w.fake.tick(30)
    w.fake.strict_gate = True


def test_snapshot_of_the_detached_registered_volume(w: World) -> None:
    _detached(w)
    snap = w.client.create_volume_snapshot(w.ids["vol"], snapshot_name(RUN))
    assert snap.status == "creating" and snap.volume_id == w.ids["vol"]
    assert snap.metadata == {"ovlm.managed": "true", SNAPSHOT_RUN_KEY: RUN}
    assert w.gate.actions == ["openstack:create_volume_snapshot"]
    w.fake.tick(30)
    assert w.client.get_volume_snapshot(snap.openstack_id).status == "available"
    assert w.fake.get_volume(w.ids["vol"]).status == "available"  # the volume is unchanged


def test_snapshot_refuses_another_name(w: World) -> None:
    _detached(w)
    with pytest.raises(errors.WriteNotAllowedError):
        w.client.create_volume_snapshot(w.ids["vol"], "ovlm-prehandoff-other-run")
    assert "create_volume_snapshot" not in w.fake.calls


def test_snapshot_refuses_an_attached_volume(w: World) -> None:
    with pytest.raises(errors.WriteNotAllowedError):
        w.client.create_volume_snapshot(w.ids["vol"], snapshot_name(RUN))
    assert "create_volume_snapshot" not in w.fake.calls


def test_snapshot_refuses_an_unregistered_or_unmarked_volume(w: World) -> None:
    other = w.fake.add_volume("other", metadata={"ovlm.managed": "true"})
    with pytest.raises(errors.OwnershipViolationError):
        w.client.create_volume_snapshot(other, snapshot_name(RUN))
    w.fake.strict_gate = False
    _detached(w)
    w.fake._volumes[w.ids["vol"]].metadata.pop("ovlm.managed")  # noqa: SLF001
    with pytest.raises(errors.OwnershipViolationError):
        w.client.create_volume_snapshot(w.ids["vol"], snapshot_name(RUN))
    assert "create_volume_snapshot" not in w.fake.calls


def test_snapshot_is_never_duplicated(w: World) -> None:
    _detached(w)
    w.client.create_volume_snapshot(w.ids["vol"], snapshot_name(RUN))
    with pytest.raises(errors.DuplicateResourceError):
        w.client.create_volume_snapshot(w.ids["vol"], snapshot_name(RUN))
    assert w.fake.calls.count("create_volume_snapshot") == 1


def test_snapshot_without_a_gate_or_past_the_fence_sends_nothing(w: World) -> None:
    _detached(w)
    w.gate.refuse = True
    with pytest.raises(BaseException, match="deadline"):
        w.client.create_volume_snapshot(w.ids["vol"], snapshot_name(RUN))
    assert w.fake.snapshot()["snapshots"] == {}


# --- the fake's model ------------------------------------------------------------------------------------------


@pytest.fixture
def w() -> World:
    return make_world()


def _fake_with_volume(size: int = 5) -> tuple[FakeOpenStack, str]:
    fake = FakeOpenStack(strict_gate=False)
    return fake, fake.add_volume("data", size=size)


@pytest.mark.parametrize(("outcome", "status"), [("available", "available"), ("error", "error"),
                                                  ("stuck", "creating")])  # fmt: skip
def test_fake_snapshot_states(outcome: Any, status: str) -> None:
    fake, vol = _fake_with_volume()
    fake.snapshot_outcome = outcome
    sid = fake.create_volume_snapshot(vol, "s", {}).openstack_id
    assert fake.get_volume_snapshot(sid).status == "creating"
    fake.tick(3600)
    assert fake.get_volume_snapshot(sid).status == status


def test_fake_snapshot_quota_is_413_and_counts_gigabytes() -> None:
    fake, vol = _fake_with_volume(size=5)
    fake.quota_snapshots, fake.quota_gigabytes = 1, 8
    assert fake.block_storage_limits().snapshot_headroom(5) == []
    fake.create_volume_snapshot(vol, "a", {})
    limits = fake.block_storage_limits()
    assert limits.snapshot_headroom(5) == [
        "snapshot quota: 1 of 1 used",
        "gigabytes quota: 5 of 8 used, the snapshot needs 5",
    ]
    with pytest.raises(errors.QuotaExceededError) as exc:
        fake.create_volume_snapshot(vol, "b", {})
    assert exc.value.status == 413


def test_fake_snapshot_of_an_in_use_volume_is_400() -> None:
    fake, vol = _fake_with_volume()
    fake.admin_reset(vol, "in-use")
    with pytest.raises(errors.BadRequestError):
        fake.create_volume_snapshot(vol, "s", {})


def test_unlimited_quota_has_headroom() -> None:
    assert BlockStorageLimits(-1, 99, None, 10_000).snapshot_headroom(500) == []


def test_413_maps_to_quota_exceeded() -> None:
    err = errors.translate_http_error(413, "Maximum number of snapshots allowed (10) exceeded")
    assert isinstance(err, errors.QuotaExceededError)


# --- SDK backend over a canned transport -----------------------------------------------------------------------


class SnapshotCloud(CannedCloud):
    def send(
        self, request: requests.PreparedRequest, *args: Any, **kwargs: Any
    ) -> requests.Response:
        path = urlparse(str(request.url)).path
        method = str(request.method)
        if path.endswith("/snapshots") and method == "POST":
            resp = super().send(request, *args, **kwargs)
            raw = request.body
            body = json.loads(raw if isinstance(raw, (str, bytes)) else b"{}")["snapshot"]
            resp.status_code = 202
            resp._content = json.dumps({"snapshot": {"id": "snap-1", "status": "creating", "size": 1,
                                                     **body}}).encode()  # fmt: skip
            return resp
        if path.endswith("/snapshots/detail") or path.endswith("/limits"):
            resp = super().send(request, *args, **kwargs)
            if path.endswith("/limits"):
                out: Any = {"limits": {"rate": [], "absolute": {
                    "maxTotalSnapshots": 10, "totalSnapshotsUsed": 3, "maxTotalVolumeGigabytes": 100,
                    "totalGigabytesUsed": 40}}}  # fmt: skip
            else:
                out = {"snapshots": [
                    {"id": "snap-1", "name": NAME, "status": "available", "volume_id": VID, "size": 1,
                     "metadata": {"ovlm.run": ALLOW_RUN}, "created_at": "2026-11-04T10:00:00.000000"},
                    {"id": "snap-2", "name": NAME + "-x", "status": "available", "volume_id": VID, "size": 1,
                     "metadata": {}, "created_at": "2026-11-04T10:00:00.000000"},
                ]}  # fmt: skip
            resp._content = json.dumps(out).encode()
            return resp
        return super().send(request, *args, **kwargs)


def test_backend_snapshot_create_sends_exactly_the_allowlisted_request() -> None:
    cloud = SnapshotCloud()
    backend, gate = _backend(cloud)
    with backend.gate_binding.bind(gate):
        snap = backend.create_volume_snapshot(
            VID, NAME, {"ovlm.managed": "true", "ovlm.run": ALLOW_RUN}
        )
    assert snap.openstack_id == "snap-1" and snap.status == "creating" and snap.volume_id == VID
    assert cloud.writes() == [("POST", "/v3/p1/snapshots")]
    body = next(b for m, u, _h, b in cloud.sent if m == "POST" and u.endswith("/snapshots"))
    assert body == {"snapshot": {"volume_id": VID, "name": NAME, "force": False,
                                 "metadata": {"ovlm.managed": "true", "ovlm.run": ALLOW_RUN}}}  # fmt: skip
    assert [a for a, _ in gate.checks] == ["openstack:create_volume_snapshot"]


def test_backend_snapshot_reads_filter_by_exact_name_and_read_limits() -> None:
    cloud = SnapshotCloud()
    backend, _gate = _backend(cloud)
    found = backend.list_volume_snapshots(name=NAME)
    assert [s.openstack_id for s in found] == ["snap-1"]  # the server-side filter is re-checked
    assert found[0].metadata == {"ovlm.run": ALLOW_RUN} and found[0].created is not None
    limits = backend.block_storage_limits()
    assert (limits.max_snapshots, limits.snapshots_used, limits.max_gigabytes, limits.gigabytes_used) == (
        10, 3, 100, 40,
    )  # fmt: skip
    assert cloud.writes() == []
