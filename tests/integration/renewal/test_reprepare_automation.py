"""``reprepare-automation``: the approver's audited exit for a run stranded inside the window without its checkout.

The run is driven through the **production guest adapter** (:class:`~ovlm.renewal.production.RunnerGuestPort`) over
a runner double. After W5 the worker container "restarts" without a checkout cache (every run-level checkout gone,
a new adapter): W6 cannot adopt B6's checkout and may not re-clone inside the window, so it stops for a human
(``automation_checkout_lost``; in the lab the restore's S2 then stopped on the same refusal). Then:

* an approver (not the run's requester) with a consumed password+TOTP step-up and the TC authorizes **one** re-clone:
  the parked step is re-queued, the guest port clones once (same SHA, same tree digest as B6) and the run converges;
* refused: for the run's requester, without a valid step-up, when the run is not stopped on that refusal, a second
  authorization while one is pending; the consumed authorization is never used again;
* a re-clone whose tree differs from B6's digest is discarded and stops the step for a human (no further exit).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy.exc
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from ovlm.auth.principal import Principal
from ovlm.automation.model import RunnerConfig
from ovlm.automation.store import ArtifactStore
from ovlm.registry.errors import DomainError
from ovlm.renewal import reprepare
from ovlm.renewal import service as svc
from ovlm.renewal.base import Deps, StepRefusal
from ovlm.renewal.definition import BlueGreenFipV1
from ovlm.renewal.production import RunnerGuestPort
from ovlm.renewal.reprobe import RenewalReprobe
from ovlm.workflow.clock import FakeClock
from ovlm.workflow.engine import WorkflowEngine
from ovlm.workflow.fence import FenceLost
from ovlm.workflow.registry import Registry
from tests.integration.renewal.conftest import CFG, World, build_world, explain
from tests.integration.renewal.doubles import FakeGuest, GuestState
from tests.integration.renewal.production_doubles import (
    TREE_DIGEST,
    GuestKeys,
    HttpDouble,
    RunnerDouble,
    SshDouble,
    StaticCredentials,
    TickingFake,
    credentials,
    new_key,
)
from tests.integration.workflow.conftest import TEST_CONFIG

KIND = "reprepare_automation"


class Lab:
    """A world whose guest port is the production adapter; ``restart`` is a worker container restart."""

    def __init__(self, w: World, keys: GuestKeys, creds: StaticCredentials, tmp: Path) -> None:
        self.w, self.keys, self.creds, self.tmp = w, keys, creds, tmp
        self.http = HttpDouble(w.cloud, w.guest, "192.0.2.10")  # type: ignore[arg-type]
        self.runner = RunnerDouble(w.guest, keys, tmp / "checkout")
        self.port: RunnerGuestPort | None = None
        self.restart()

    def restart(self) -> None:
        """New adapter (empty in-memory checkout cache) and a new engine, as a restarted worker has."""
        self.port = RunnerGuestPort(self.w.worker, self.runner, self.creds, ssh=SshDouble(self.keys),
                                    http=self.http, store=ArtifactStore(RunnerConfig(run_root=self.tmp / "run")))  # fmt: skip
        deps = Deps(self.w.worker, CFG, self.w.port, self.port)
        self.w.engine = WorkflowEngine(
            self.w.worker, Registry([BlueGreenFipV1(deps), RenewalReprobe(self.w.worker)]), TEST_CONFIG,
            clock=FakeClock(), audit=self.w.audit,
        )  # fmt: skip

    def strand(self) -> Any:
        """G2 granted, W1-W5 done; then the container restarts without a checkout cache. Returns the parked step."""
        w = self.w
        w.start()
        w.drive(until="await_cutover")
        w.approve("cutover")
        w.drive(until="data_attach_green")
        assert w.open_step()["step_key"] == "data_attach_green", explain(w)
        self.runner.lose_checkouts()
        self.restart()
        r = w.drive()
        assert r["state"] == "needs_human", explain(w)
        st = w.open_step()
        assert st is not None and st["state"] == "needs_human", explain(w)
        assert st["error"]["reason"] == "automation_checkout_lost", st["error"]
        assert w.run()["downtime_started_at"] is not None  # stranded inside the outage
        return st

    def signal(self, user: str = "ap2", *, good_stepup: bool = True) -> str:
        return self.w.signal(KIND, user=user, tc=self.w.blue_tc(), good_stepup=good_stepup)

    def outcome(self, sig: str) -> str:
        return str(self.w.q("SELECT outcome FROM run_signal WHERE id = :i", i=sig)[0]["outcome"])

    def authorizations(self) -> list[Any]:
        return self.w.q(
            "SELECT * FROM automation_reprepare WHERE run_id = :r ORDER BY authorized_at",
            r=self.w.run_id,
        )


@pytest.fixture
def lab(admin_url: URL, fresh_db: str, secrets_dir: Path, tmp_path: Path) -> Iterator[Lab]:
    cloud = TickingFake(now=datetime.now(UTC), strict_gate=False)
    _blue_private, blue_key = new_key()
    guest_private, guest_public = new_key()
    w = build_world(
        admin_url, fresh_db, secrets_dir, blue_fingerprint=blue_key.fingerprint, cloud=cloud
    )
    keys = GuestKeys(cloud, w.guest, guest_public, {w.ids["blue"]: blue_key})
    cloud.on_create = keys.learn_bootstrap
    w.guest = FakeGuest(cloud, w.ids["volume"], phases={"preflight"})
    w.guest.state[w.ids["blue"]] = GuestState(mounted=True, units=True)
    keys.guest = w.guest
    yield Lab(w, keys, credentials(cloud.user_id, guest_private, guest_public), tmp_path)
    for e in (w.admin, w.worker, w.api):
        e.dispose()


def test_an_approver_authorizes_one_reclone_and_the_stranded_step_converges(lab: Lab) -> None:
    w = lab.w
    parked = lab.strand()
    assert lab.runner.prepared == [w.run_id]  # B6 only: no git contact inside the window so far
    sig = lab.signal()
    r = w.drive()
    assert "authorized once" in lab.outcome(
        sig
    ) and f"step {parked['step_key']} re-queued" in lab.outcome(sig)
    # exactly one re-clone, the same SHA, the digest B6 recorded; the parked step finished
    assert lab.runner.prepared == [w.run_id, w.run_id], lab.runner.prepared
    step = next(s for s in w.steps() if s["id"] == parked["id"])
    assert step["state"] == "succeeded", explain(w)
    assert step["evidence"]["reprepare_automation"]["signal_id"] == sig
    # the renewal went on through the window and the cutover to the retirement gate
    assert r["state"] == "running" and w.open_step()["step_key"] == "await_retirement", explain(w)
    [auth] = lab.authorizations()
    assert auth["consumed_at"] is not None and auth["outcome"] == "re-cloned and verified"
    assert str(auth["approver_id"]) == w.users["ap2"] and auth["step_key"] == parked["step_key"]
    sha = w.q("SELECT resolved FROM renewal_plan WHERE id = :p", p=w.ids["plan"])[0]["resolved"][
        "automation"
    ]["sha"]
    assert auth["sha"] == sha
    rows = w.q("SELECT action, actor_id, step_id, after FROM audit_event WHERE run_id = :r "
               "AND action LIKE 'automation.reprepare.%' ORDER BY id", r=w.run_id)  # fmt: skip
    assert [x["action"] for x in rows] == [
        "automation.reprepare.authorized",
        "automation.reprepare.used",
    ]
    authorized, used = rows
    assert str(authorized["actor_id"]) == w.users["ap2"] and authorized["step_id"] == parked["id"]
    assert authorized["after"] == {"run_id": w.run_id, "step_key": parked["step_key"], "sha": sha,
                                   "approver": w.users["ap2"], "signal_id": sig}  # fmt: skip
    assert used["after"]["tree_digest"] == used["after"]["recorded_tree_digest"] == TREE_DIGEST

    # one-shot: the consumed authorization is never used again (the checkout lost a second time, in an outage)
    lab.runner.lose_checkouts()
    lab.restart()
    assert lab.port is not None
    lab.port._in_outage = lambda run_id: True  # type: ignore[method-assign]  # noqa: SLF001
    with pytest.raises(StepRefusal, match="automation_checkout_lost"):
        lab.port._prepared_for(w.run_id)  # noqa: SLF001
    assert len(lab.runner.prepared) == 2 and len(lab.authorizations()) == 1


@pytest.mark.parametrize("case", ["requester", "no_stepup", "operator"])
def test_refused_for_the_requester_without_stepup_and_for_a_non_approver(
    lab: Lab, case: str
) -> None:
    w = lab.w
    lab.strand()
    if (
        case == "requester"
    ):  # op started the run (and created the plan); give op the approver role too
        w.x("INSERT INTO role_binding (id, user_id, role, scope, created_at) VALUES "
            "(gen_random_uuid(), :u, 'approver', :s, now() - interval '1 day')", u=w.users["op"], s=w.ids["scope"])  # fmt: skip
        sig, why = lab.signal("op"), "separation of duties"
    elif case == "no_stepup":
        sig, why = lab.signal(good_stepup=False), "step-up evidence invalid"
    else:
        sig, why = lab.signal("op"), "needs the approver role"
    w.drive()
    assert lab.outcome(sig).startswith("refused") and why in lab.outcome(sig), lab.outcome(sig)
    assert lab.authorizations() == [] and lab.runner.prepared == [w.run_id]
    assert w.open_step()["state"] == "needs_human"


def test_refused_when_the_run_is_not_stopped_on_a_lost_checkout(lab: Lab) -> None:
    w = lab.w
    w.start()
    w.drive(until="await_cutover")  # waiting at G2: nothing parked
    sig = lab.signal()
    w.drive(until="await_cutover")
    assert lab.outcome(sig).startswith("refused: no step in needs_human"), lab.outcome(sig)
    # parked for another reason: refused too
    st = w.open_step()
    w.x("UPDATE workflow_step SET state = 'needs_human', error = '{\"reason\": \"server_locked\"}' WHERE id = :i",
        i=st["id"])  # fmt: skip
    w.x("UPDATE workflow_run SET state = 'needs_human', needs_human_reason = 'server_locked' WHERE id = :r",
        r=w.run_id)  # fmt: skip
    sig = lab.signal()
    w.drive()
    assert "not stopped on a lost or unverifiable automation checkout" in lab.outcome(sig), (
        lab.outcome(sig)
    )
    assert lab.authorizations() == []


def test_a_second_authorization_while_one_is_pending_is_refused(lab: Lab) -> None:
    w = lab.w
    lab.strand()
    first, second = lab.signal(), lab.signal("ap3")
    assert w.engine is not None
    w.engine.process_signals()  # both applied in one pass, before the step runs
    assert "authorized once" in lab.outcome(first)
    assert lab.outcome(second).startswith("refused"), lab.outcome(second)
    assert len(lab.authorizations()) == 1


def test_a_reclone_with_another_tree_digest_stops_for_a_human(lab: Lab) -> None:
    w = lab.w
    parked = lab.strand()
    lab.runner.digest = "e" * 64  # the git host served another tree for the pinned SHA
    sig = lab.signal()
    r = w.drive()
    assert "authorized once" in lab.outcome(sig)
    assert r["state"] == "needs_human", explain(w)
    st = w.open_step()
    assert (
        st["id"] == parked["id"] and st["error"]["reason"] == "automation_reprepare_digest_mismatch"
    ), st["error"]
    assert (
        st["error"]["recorded_tree_digest"] == TREE_DIGEST
        and st["error"]["tree_digest"] == "e" * 64
    )
    assert lab.runner.released == [w.run_id]  # the other tree is discarded, never adopted later
    [auth] = lab.authorizations()
    assert auth["outcome"].startswith("refused: the re-clone differs")
    assert "automation.reprepare.refused" in w.audit_actions()
    # no further exit for that reason: a human looks at the repository first
    again = lab.signal("ap3")
    w.drive()
    assert "not stopped on a lost or unverifiable automation checkout" in lab.outcome(again)


def test_an_unverifiable_cached_checkout_is_an_entry_point_too(lab: Lab) -> None:
    w = lab.w
    lab.strand()
    lab.runner.unverifiable = True  # the copy found does not match B6's digest
    st = w.open_step()
    w.x("UPDATE workflow_step SET error = CAST(:e AS jsonb) WHERE id = :i",
        e='{"reason": "automation_checkout_unverifiable", "message": "x"}', i=st["id"])  # fmt: skip
    sig = lab.signal()
    w.drive()
    assert "authorized once" in lab.outcome(sig)
    assert (
        len(lab.runner.prepared) == 2
        and lab.authorizations()[0]["outcome"] == "re-cloned and verified"
    )


def _who(w: World, user: str, roles: tuple[str, ...] = ("approver",)) -> Principal:
    from uuid import UUID

    return Principal(
        user_id=UUID(w.users[user]), username=f"user-{user}", principal_type="human",
        auth_method="password+totp", grants=frozenset((r, w.ids["scope"]) for r in roles), session_hash="sess",
    )  # fmt: skip


def test_the_api_offers_and_checks_the_action(lab: Lab) -> None:
    from uuid import UUID

    w = lab.w
    lab.strand()
    with Session(w.api) as s:
        body = svc.run_body(s, w.run_id)
        offered = [a["action"] for a in body["available_actions"]]
        assert "reprepare-automation" in offered
        for who, code in ((_who(w, "op", ("operator", "approver")), "sod-violation"),
                          (_who(w, "op", ("operator",)), "forbidden")):  # fmt: skip
            with pytest.raises(DomainError) as exc:
                svc.action(s, who, UUID(w.run_id), "reprepare-automation", typed=w.blue_tc(),
                           stepup_id=None, attestation=None)  # fmt: skip
            assert exc.value.code == code
        with pytest.raises(DomainError) as exc:  # an approver without step-up
            svc.action(s, _who(w, "ap2"), UUID(w.run_id), "reprepare-automation", typed=w.blue_tc(),
                       stepup_id=None, attestation=None)  # fmt: skip
        assert exc.value.code == "human-session-required"


def test_a_consumed_authorization_cannot_be_re_armed_or_deleted(lab: Lab) -> None:
    """Review PMR-6 (b): the worker's column grant would let it set ``consumed_at`` back to NULL; the trigger allows
    only the consume transitions (NULL to a value, once each) and refuses every other change, DELETE and TRUNCATE,
    even for the table owner."""
    w = lab.w
    lab.strand()
    lab.signal()
    w.drive()
    [auth] = lab.authorizations()
    assert auth["consumed_at"] is not None and auth["outcome"] == "re-cloned and verified"
    refused = (sqlalchemy.exc.DBAPIError,)
    for sql in (
        "UPDATE automation_reprepare SET consumed_at = NULL WHERE id = :i",
        "UPDATE automation_reprepare SET consumed_at = now() + interval '1 second' WHERE id = :i",
        "UPDATE automation_reprepare SET outcome = 'x' WHERE id = :i",
        "UPDATE automation_reprepare SET outcome = NULL WHERE id = :i",
        "UPDATE automation_reprepare SET consumed_at = consumed_at WHERE id = :i",
    ):
        with pytest.raises(refused, match="append-only"), w.worker.begin() as c:
            c.execute(text(sql), {"i": auth["id"]})
    with pytest.raises(refused, match="permission denied"), w.worker.begin() as c:
        c.execute(text("DELETE FROM automation_reprepare WHERE id = :i"), {"i": auth["id"]})
    for sql in ("UPDATE automation_reprepare SET sha = :s WHERE id = :i", "DELETE FROM automation_reprepare WHERE id = :i",
                "TRUNCATE automation_reprepare CASCADE"):  # fmt: skip
        with pytest.raises(refused, match="append-only"), w.admin.begin() as c:
            c.execute(text(sql), {"i": auth["id"], "s": "0" * 40})
    # a pending one: its outcome cannot come before its consumption
    w.x("UPDATE workflow_step SET state = 'needs_human', error = '{\"reason\": \"automation_checkout_lost\"}' "
        "WHERE id = (SELECT id FROM workflow_step WHERE run_id = :r AND state = 'waiting')", r=w.run_id)  # fmt: skip
    w.x("UPDATE workflow_run SET state = 'needs_human', needs_human_reason = 'automation_checkout_lost' WHERE id = :r",
        r=w.run_id)  # fmt: skip
    lab.signal("ap3")
    assert w.engine is not None
    w.engine.process_signals()
    pending = next(a for a in lab.authorizations() if a["consumed_at"] is None)
    with pytest.raises(refused, match="append-only"), w.worker.begin() as c:
        c.execute(
            text("UPDATE automation_reprepare SET outcome = 'x' WHERE id = :i"),
            {"i": pending["id"]},
        )
    assert [dict(a) for a in lab.authorizations()][0] == dict(auth)


# --- PMR-2: an authorization is bound to its step and fenced ------------------------------------------------------


class _Fence:
    def __init__(self, lost: bool = False) -> None:
        self.lost, self.checks = lost, []  # type: tuple[bool, list[str]]

    def check(self, action: str) -> None:
        if self.lost:
            raise FenceLost(action, "revoked")
        self.checks.append(action)

    def add_revoke_callback(self, cb: Any) -> Any:
        return lambda: None


def test_an_authorization_is_consumed_only_by_its_step_and_is_void_once_that_step_closed(
    lab: Lab,
) -> None:
    """Review PMR-2: the approver authorized a re-clone for the parked W6; W6 then finishes without it (its checkout
    is back), and much later another step finds the checkout gone inside the outage. That step must not consume the
    old authorization (a git contact nobody authorized for it): it parks ``automation_checkout_lost``, the old row is
    void, and the approver can decide again."""
    w = lab.w
    parked = lab.strand()
    sig = lab.signal()
    assert w.engine is not None and lab.port is not None
    w.engine.process_signals()  # authorized, W6 re-queued (not run yet)
    assert "authorized once" in lab.outcome(sig)
    [auth] = lab.authorizations()
    assert auth["step_id"] == parked["id"] and auth["consumed_at"] is None
    port = lab.port
    port._in_outage = lambda run_id: True  # type: ignore[method-assign]  # noqa: SLF001
    other = next(s for s in w.steps() if s["step_key"] == "prepare_automation")
    # another step's attempt: refused, nothing consumed, no git contact
    with pytest.raises(StepRefusal, match="automation_checkout_lost"):
        port._prepared_for(w.run_id, step_id=str(other["id"]), attempt=1, fence=_Fence())  # noqa: SLF001
    # the step's own id, but no attempt of it holds the lease (W6 is queued, not running): nothing consumed
    with pytest.raises(StepRefusal, match="automation_checkout_lost"):
        port._prepared_for(w.run_id, step_id=str(parked["id"]), attempt=parked["attempt"] + 1,  # noqa: SLF001
                           fence=_Fence())  # fmt: skip
    # an attempt that lost its fence: refused before the authorization is even read
    with pytest.raises(FenceLost):
        port._prepared_for(w.run_id, step_id=str(parked["id"]), attempt=parked["attempt"] + 1,  # noqa: SLF001
                           fence=_Fence(lost=True))  # fmt: skip
    assert lab.runner.prepared == [w.run_id] and lab.authorizations()[0]["consumed_at"] is None
    # W6's checkout is back (found in the cache): it finishes without using the authorization
    spec = port._spec(w.run_id, port._resolved(w.run_id))  # noqa: SLF001
    lab.runner.prepare_automation(spec, w.run_id)
    lab.runner.prepared.pop()
    del port._in_outage  # noqa: SLF001
    r = w.drive()
    assert r["state"] == "running" and w.open_step()["step_key"] == "await_retirement", explain(w)
    assert next(s for s in w.steps() if s["id"] == parked["id"])["state"] == "succeeded"
    with w.worker.connect() as c:
        assert not reprepare.pending(c, w.run_id)  # void: a new authorization is not blocked by it
    # later, the checkout is lost again inside an outage: the open step does not consume the old authorization
    lab.runner.lose_checkouts()
    lab.restart()
    assert lab.port is not None
    lab.port._in_outage = lambda run_id: True  # type: ignore[method-assign]  # noqa: SLF001
    now = w.open_step()
    # an attempt of it holds the lease (as the engine's claim leaves it)
    w.x("UPDATE workflow_step SET state = 'running', attempt = attempt + 1, lease_owner = 'w2', "
        "fencing_token = nextval('fencing_seq'), lease_expires_at = now() + interval '5 minutes' WHERE id = :i",
        i=now["id"])  # fmt: skip
    with pytest.raises(StepRefusal, match="automation_checkout_lost"):
        lab.port._prepared_for(w.run_id, step_id=str(now["id"]), attempt=now["attempt"] + 1,  # noqa: SLF001
                               fence=_Fence())  # fmt: skip
    assert lab.runner.prepared == [w.run_id]  # no git contact since B6
    [auth] = lab.authorizations()
    assert auth["consumed_at"] is not None and auth["outcome"] == reprepare.EXPIRED
    assert "automation.reprepare.expired" in w.audit_actions()
