"""Review IS-11 (docs/reviews/verification-host-key-fixes.md): the live host-key re-check must read the managed VM
the plan is **for**, not whatever ``resolved.blue.managed_vm_id`` names.

The api writes ``renewal_plan.resolved`` (``ovlm_api`` has INSERT on the table). The verifier's probe: a compromised
api inserts a plan whose ``blue.server_id`` and ``port_id`` are the victim's (the humans approving G1/G2 see the right
blue), while ``blue.managed_vm_id`` and ``host_key_fingerprint`` name another confirmed managed VM whose key the
attacker controls. Before the fix, W1 ``quiesce_old`` ran on the real blue pinned to the attacker's key. Now
``preflight`` refuses the plan (``needs_human``, before any OpenStack write), and the same binding check guards every
SSH to blue."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import text

from ovlm.inventory.tables import OBSERVED
from ovlm.openstack.allowlist import TAG_MANAGED
from ovlm.renewal.base import blue_host_key_problems
from ovlm.renewal.plans import compute_plan_hash, policy_binding
from ovlm.workflow.ids import new_id
from tests.integration.renewal.conftest import World, explain
from tests.integration.renewal.doubles import SUBNET
from tests.integration.renewal.test_failures import parked

ATTACKER_KEY = "SHA256:" + "K" * 43


def _attacker_vm(w: World) -> str:
    """Another service's managed VM, confirmed for a key the attacker controls (registered, scanned and confirmed
    through the api's own grants; seeded here as the owner)."""
    with w.admin.begin() as c:
        sync = c.execute(text("SELECT id FROM sync_run LIMIT 1")).scalar_one()
        obs = new_id()
        c.execute(
            OBSERVED["server"].insert().values(
                id=obs, project_connection_id=w.ids["pc"], openstack_id="attacker-server", name="attacker",
                payload={}, payload_hash="0" * 64, first_seen_sync_id=sync, last_seen_sync_id=sync,
                status="present", synced_at=datetime.now(UTC), server_status="ACTIVE", availability_zone="az1",
            )
        )  # fmt: skip
        svc = new_id()
        c.execute(text("INSERT INTO service (id, name, slug, project_connection_id) "
                       "VALUES (:i, 'Other', 'other01', :pc)"), {"i": svc, "pc": w.ids["pc"]})  # fmt: skip
        vm = new_id()
        c.execute(text("INSERT INTO managed_vm (id, service_id, observed_server_id, openstack_server_id, role, "
                       "registered_at, ssh_host_key_fingerprint, host_key_confirmed_by, host_key_confirmed_at) "
                       "VALUES (:i, :s, :o, 'attacker-server', 'current', now(), :fp, :u, now())"),
                  {"i": vm, "s": svc, "o": obs, "fp": ATTACKER_KEY, "u": w.users["op"]})  # fmt: skip
    return vm


def _api_inserts_plan(w: World, *, row_vm: str, **blue: Any) -> str:
    """As ``ovlm_api``: a copy of the honest plan with ``resolved.blue`` changed, its hash recomputed so the worker's
    own recomputation agrees, and ``renewal_plan.managed_vm_id = row_vm``."""
    honest = w.q("SELECT * FROM renewal_plan WHERE id = :p", p=w.ids["plan"])[0]
    resolved = dict(honest["resolved"])
    resolved["blue"] = {**resolved["blue"], **blue}
    pv = w.q(
        "SELECT spec_hash, automation_sha FROM profile_version WHERE id = :i",
        i=w.ids["profile_version"],
    )[0]
    pol = w.q("SELECT * FROM policy WHERE id = :i", i=w.ids["policy"])[0]
    plan_hash = compute_plan_hash(resolved=resolved, profile_version_id=w.ids["profile_version"],
                                  spec_hash=pv["spec_hash"], automation_sha=pv["automation_sha"],
                                  policy=policy_binding(pol))  # fmt: skip
    plan = new_id()
    with w.api.begin() as c:
        c.execute(text("INSERT INTO renewal_plan (id, managed_vm_id, service_id, profile_version_id, policy_id, "
                       "policy_version, resolved, plan_hash, state, created_by) VALUES (:i, :vm, :s, :pv, :pol, 1, "
                       "CAST(:r AS jsonb), :h, 'approved', :u)"),
                  {"i": plan, "vm": row_vm, "s": w.ids["service"], "pv": w.ids["profile_version"],
                   "pol": w.ids["policy"], "r": json.dumps(resolved), "h": plan_hash, "u": w.users["op"]})  # fmt: skip
    w.ids["plan"] = plan
    return plan


def _assert_refused_at_preflight(w: World, problem: str) -> None:
    r = parked(w, "blue_host_key_untrusted")
    assert r["downtime_started_at"] is None, explain(w)
    steps = w.steps()
    assert [s["step_key"] for s in steps] == ["preflight"], explain(w)
    assert any(problem in p for p in steps[0]["error"]["problems"]), steps[0]["error"]
    # nothing written to OpenStack (no claim tag, no green) and nothing run on blue
    assert TAG_MANAGED not in w.cloud.get_server(w.ids["blue"]).tags
    assert w.green_id() is None
    assert not [c for c in w.guest.calls if c[0] == "quiesce"]


@pytest.mark.parametrize(
    ("plan_row_vm", "problem"),
    [
        # the plan row names the victim (what the approvers' screens show); only resolved points elsewhere
        ("victim", "is not the plan's managed VM"),
        # the attacker keeps the plan row consistent with resolved: the server binding still refuses
        ("attacker", "is not blue's server"),
    ],
)
def test_is11_verifier_probe_plan_pointing_blue_at_another_confirmed_vm_is_refused(
    world_factory: Any, plan_row_vm: str, problem: str
) -> None:
    w: World = world_factory(g1=False)
    attacker = _attacker_vm(w)
    _api_inserts_plan(
        w,
        row_vm=w.ids["vm"] if plan_row_vm == "victim" else attacker,
        managed_vm_id=attacker,
        host_key_fingerprint=ATTACKER_KEY,
    )  # blue.server_id and port_id stay the victim's
    w.approve("plan", decider="ap3")
    w.start()
    w.drive()
    _assert_refused_at_preflight(w, problem)


def test_is11_preflight_refuses_a_blue_port_that_is_not_on_blue(world_factory: Any) -> None:
    """The plan's blue port is the SSH address of blue (``blue_ref``): its live ``device_id`` must be blue's
    server, not merely the port the floating IP happens to be on."""
    w: World = world_factory(g1=False)
    w.cloud.strict_gate = False
    other = w.cloud.add_server("attacker")
    port = w.cloud.add_port(w.ids["net"], device_id=other, ip="10.0.0.66", subnet=SUBNET)
    w.cloud.update_floating_ip(w.ids["fip"], port)
    w.cloud.strict_gate = True
    _api_inserts_plan(w, row_vm=w.ids["vm"], port_id=port)
    w.approve("plan", decider="ap3")
    w.start()
    w.drive()
    _assert_refused_at_preflight(w, "is not attached to blue's server")


def test_is11_the_live_check_before_each_ssh_to_blue_refuses_a_forged_binding(world: World) -> None:
    """The W1 / ``blue_ref`` check itself (the same function), on a run whose plan is honest, given a ``resolved``
    that points blue at another confirmed VM: refused. The honest ``resolved`` passes."""
    w = world
    attacker = _attacker_vm(w)
    w.start()
    honest = w.q("SELECT resolved FROM renewal_plan WHERE id = :p", p=w.ids["plan"])[0]["resolved"]
    forged = {**honest, "blue": {**honest["blue"], "managed_vm_id": attacker,
                                  "host_key_fingerprint": ATTACKER_KEY}}  # fmt: skip
    with w.worker.connect() as c:
        assert blue_host_key_problems(c, honest, run_id=w.run_id) == []
        problems = blue_host_key_problems(c, forged, run_id=w.run_id)
        assert any("is not the plan's managed VM" in p for p in problems), problems
        assert any("is not blue's server" in p for p in problems), problems
        other_service = {**forged, "service": {**honest["service"], "id": new_id()}}
        assert any(
            "service" in p for p in blue_host_key_problems(c, other_service, run_id=w.run_id)
        )
