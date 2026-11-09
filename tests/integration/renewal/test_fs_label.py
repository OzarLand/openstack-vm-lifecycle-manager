"""Roadmap P0-5: a profile that names the data filesystem by ``label`` (not ``fs_uuid``) gets the label checked in W6.

Before the fix W6 compared ``fs_uuid`` only when the profile had one, so a label profile passed W6 with no filesystem
identity checked at all: green could mount another filesystem and the run would go on to start the service and move
the floating IP. The fake guest reports ``facts.fs_label`` as the reference ``data_volume`` role does (contract 3.3
rule 7, 3.7.1).
"""

from __future__ import annotations

from typing import Any

from tests.integration.renewal.conftest import World, explain, to_cutover


def _step(w: World, key: str) -> Any:
    return next(s for s in reversed(w.steps()) if s["step_key"] == key)


def test_label_profile_with_a_different_label_on_green_parks_w6(world_factory: Any) -> None:
    w: World = world_factory(fs_label="app-data")
    plan = w.q("SELECT resolved FROM renewal_plan WHERE id = :p", p=w.ids["plan"])[0]
    assert plan["resolved"]["data_volume"]["label"] == "app-data"
    w.guest.fs_label = "other-data"  # green mounts a filesystem with another label
    to_cutover(w)
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human", explain(w)
    assert r["needs_human_reason"] == "data_attach_mismatch", explain(w)
    assert not r["auto_restore_used"]
    w6 = _step(w, "data_attach_green")
    assert w6["state"] != "succeeded", explain(w)
    assert w6["error"]["problems"] == ["fs_label differs from the profile"], w6["error"]
    keys = w.keys()
    assert not any(k in keys for k in ("start_service_green", "healthcheck_green", "move_fip"))
    assert w.fip_port() == w.ids["blue_port"]  # the FIP never left blue
    assert ("start_service", w.green_id()) not in w.guest.calls


def test_label_profile_without_a_reported_label_parks_w6(world_factory: Any) -> None:
    w: World = world_factory(fs_label="app-data")
    w.guest.fs_label = None  # a repository whose data_attach reports no label
    to_cutover(w)
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human", explain(w)
    assert r["needs_human_reason"] == "data_attach_mismatch", explain(w)
    assert w.fip_port() == w.ids["blue_port"]


def test_label_profile_with_the_same_label_converges(world_factory: Any) -> None:
    w: World = world_factory(fs_label="app-data")
    w.guest.fs_label = "app-data"
    # a label profile does not compare the UUID
    w.guest.fs_uuid = "99999999-9999-4999-8999-999999999999"
    to_cutover(w)
    w.drive(until="await_retirement")
    w6 = _step(w, "data_attach_green")
    assert w6["state"] == "succeeded", explain(w)
    assert w6["evidence"]["fs_identity_checked"] == "fs_label"
    assert w6["evidence"]["marker_comparison"] == "equal"
    assert _step(w, "healthcheck_green")["state"] == "succeeded", explain(w)
    assert w.fip_port() != w.ids["blue_port"]  # cut over to green


def test_uuid_profile_still_checks_the_uuid(world: World) -> None:
    """The existing behaviour: a UUID profile compares ``fs_uuid`` and ignores the label."""
    w = world
    w.guest.fs_label = None
    w.guest.fs_uuid = "99999999-9999-4999-8999-999999999999"
    to_cutover(w)
    w.drive()
    r = w.run()
    assert r["state"] == "needs_human", explain(w)
    assert r["needs_human_reason"] == "data_attach_mismatch", explain(w)
    problems = _step(w, "data_attach_green")["error"]["problems"]
    assert problems == ["fs_uuid differs from the profile"]
    assert w.fip_port() == w.ids["blue_port"]
