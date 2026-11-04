"""SEC-C-10 / SEC-R-23: ``adopt_checks``, the pure gate before a found server is adopted as this run's green."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from ovlm.openstack.allowlist import TAG_MANAGED
from ovlm.openstack.fake import FakeOpenStack
from ovlm.openstack.ownership import run_tag
from ovlm.openstack.sdk_read import map_server
from ovlm.openstack.types import AttachedVolume, CreateServerSpec, ServerInfo, VolumeAttachmentInfo
from ovlm.openstack.write import AdoptionExpectation, adopt_checks

RUN = "run-1"
T0 = datetime(2026, 11, 4, 10, 0, tzinfo=UTC)
WRITE_USER = "user-ovlm-write"
EXPECTED = AdoptionExpectation(
    run_id=RUN,
    image_id="img",
    flavor_name="m1.small",
    ledger_committed_at=T0,
    write_user_id=WRITE_USER,
)
GOOD = ServerInfo(
    openstack_id="s1", name="ovlm-web-1-green", status="ACTIVE", created=T0 + timedelta(seconds=5),
    image_id="img", flavor_original_name="m1.small", tags=(TAG_MANAGED, run_tag(RUN)), user_id=WRITE_USER,
)  # fmt: skip


def test_a_server_matching_every_fact_is_adoptable() -> None:
    verdict = adopt_checks(GOOD, EXPECTED)
    assert verdict.ok and verdict.reasons == ()
    assert adopt_checks(replace(GOOD, created=T0), EXPECTED).ok  # same instant as the commit counts


MISMATCHES = {
    "other image": (replace(GOOD, image_id="img-2"), "image"),
    "boot from volume (no image)": (replace(GOOD, image_id=None), "image"),
    "other flavor": (replace(GOOD, flavor_original_name="m1.large"), "flavor"),
    "created before the ledger row": (replace(GOOD, created=T0 - timedelta(seconds=1)), "created before"),
    "no created time": (replace(GOOD, created=None), "created before"),
    "attached volume": (
        replace(GOOD, attached_volumes=(AttachedVolume("v1", False),)), "attached volumes"),
    "created by another user": (replace(GOOD, user_id="someone-else"), "not created by OVLM"),
    "user_id not visible": (replace(GOOD, user_id=None), "not visible"),
    "no run tag": (replace(GOOD, tags=(TAG_MANAGED,)), "this run's tag"),
    "another run's tag": (replace(GOOD, tags=(TAG_MANAGED, run_tag("run-2"))), "this run's tag"),
    "no managed tag": (replace(GOOD, tags=(run_tag(RUN),)), "this run's tag"),
    "deleted": (replace(GOOD, status="DELETED"), "not readable"),
    "minimal construct": (replace(GOOD, is_minimal_construct=True), "not readable"),
}  # fmt: skip


@pytest.mark.parametrize("case", list(MISMATCHES), ids=list(MISMATCHES))
def test_any_mismatch_refuses_adoption(case: str) -> None:
    server, reason = MISMATCHES[case]
    verdict = adopt_checks(server, EXPECTED)
    assert not verdict.ok
    assert any(reason in r for r in verdict.reasons), verdict.reasons


def test_an_attachment_seen_only_in_the_attachment_list_refuses_too() -> None:
    att = VolumeAttachmentInfo("s1", "v1")
    assert not adopt_checks(GOOD, EXPECTED, [att]).ok


def test_every_failed_check_is_reported() -> None:
    bad = replace(GOOD, image_id="x", flavor_original_name="y", user_id="z")
    assert len(adopt_checks(bad, EXPECTED).reasons) == 3


def test_the_user_check_is_skipped_only_when_explicitly_dropped() -> None:
    dropped = replace(EXPECTED, write_user_id=None)
    assert adopt_checks(replace(GOOD, user_id=None), dropped).ok
    assert adopt_checks(replace(GOOD, user_id="someone-else"), dropped).ok


def test_the_fake_and_the_sdk_mapping_carry_user_id() -> None:
    fake = FakeOpenStack(strict_gate=False, now=T0)
    img, fl = fake.add_image(), fake.add_flavor()
    planted = fake.add_server("green", tags=[TAG_MANAGED, run_tag(RUN)], image_id=img)
    created = fake.create_server(
        CreateServerSpec("green-2", img, fl, network_id=fake.add_network("n"),
                         tags=(TAG_MANAGED, run_tag(RUN)))
    )  # fmt: skip
    assert fake.get_server(created.openstack_id).user_id == fake.user_id
    assert fake.get_server(planted).user_id not in (None, fake.user_id)  # a member planted it

    class Sdk:  # the attributes map_server reads from an openstacksdk Server
        id, name, status, vm_state, task_state, power_state = "s", "n", "ACTIVE", "active", None, 1
        created_at = launched_at = updated_at = None
        flavor = image = availability_zone = locked_reason = host_id = None
        is_locked = False
        tags: list[str] = []
        metadata: dict[str, str] = {}
        attached_volumes: list[object] = []
        user_id = "u-1"

    assert map_server(Sdk()).user_id == "u-1"
