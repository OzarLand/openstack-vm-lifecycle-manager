"""End-to-end ``bluegreen_fip_v1`` against the fake cloud and fake guest: build, G2, window, retention, G3, X1."""

from __future__ import annotations

from tests.integration.renewal.conftest import World, explain, to_cutover


def test_full_renewal_to_retirement(world: World) -> None:
    w = world
    to_cutover(w)
    r = w.drive(until="await_retirement")
    assert r["state"] == "running", explain(w)
    keys = w.keys()
    assert keys[:10] == [
        "preflight",
        "claim_resources",
        "create_green",
        "wait_green_active",
        "wait_green_ssh",
        "prepare_automation",
        "configure_green",
        "verify_cutover_preconditions",
        "await_cutover",
        "verify_green_ready",
    ]
    assert "snapshot_volume" not in keys
    green = w.green_id()
    assert green is not None
    assert w.attached() == [green]
    assert w.fip_port() != w.ids["blue_port"]
    run = w.run()
    assert run["downtime_started_at"] is not None and run["downtime_ended_at"] is not None
    assert run["phase"] == "retained"
    roles = {r["openstack_server_id"]: r["role"] for r in w.q("SELECT * FROM managed_vm")}
    assert roles == {w.ids["blue"]: "retained", green: "current"}
    assert (
        "port",
        w.cloud.snapshot()["floating_ips"][w.ids["fip"]],
    ) in w.locks()  # green's port locked at B4
    snap = w.cloud.snapshot()["servers"]
    assert snap[w.ids["blue"]]["locked"] and snap[w.ids["blue"]]["status"] == "SHUTOFF"
    assert "foreign:keep" in snap[w.ids["blue"]]["tags"]  # B2 never removed a foreign tag
    # G3 by a second approver (two-person rule), then X1 deletes blue
    w.approve("retirement", decider="ap2")
    r = w.drive()
    assert r["state"] == "completed", (w.keys(), w.open_step(), r)
    assert w.cloud.snapshot()["servers"][w.ids["blue"]]["status"] != "ACTIVE"
    assert w.ids["volume"] in w.cloud.snapshot()["volumes"]  # the data volume is never deleted
    assert w.locks() == []
    roles = {r["openstack_server_id"]: r["role"] for r in w.q("SELECT * FROM managed_vm")}
    assert roles[w.ids["blue"]] == "retired"
    assert "renewal.cutover" in w.audit_actions()
