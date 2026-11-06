"""Lint waivers in the renewal (security follow-up SF-13, automation-contract.md 9, SEC-R-36), on a seeded world.

* Separation of duties: a requester of a plan on the version (here: the run starter) cannot waive it; a step-up
  confirmed with a password alone is refused.
* The plan hash binds the active waivers: granting one voids approvals bound to the old hash.
* B6 (``prepare_automation``) lints with the waivers stored for the run's profile version, and audits every finding a
  waiver covered (``automation.lint_waiver.applied``); without the waiver the same repository is refused.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from ovlm.auth.errors import ProblemError
from ovlm.auth.principal import Principal
from ovlm.auth.sod import Gate
from ovlm.automation.lint import lint_repo
from ovlm.automation.types import AutomationError
from ovlm.profiles import waivers
from ovlm.renewal import service as svc
from ovlm.renewal.base import StepRefusal
from ovlm.renewal.evidence import check_gate
from ovlm.renewal.plans import KIND, STRATEGY, STRATEGY_VERSION, load_facts, now_db
from ovlm.renewal.production import RunnerGuestPort
from ovlm.workflow.contract import ErrorClass
from ovlm.workflow.requests import request_run
from tests.integration.renewal.conftest import CFG, World

REASON = "a read-only probe outside the lint allowlist, reviewed by hand"
PROBE = "- ansible.builtin.command: id\n  check_mode: false\n"


def _who(w: World, user: str, *, roles: tuple[str, ...] = ("approver",)) -> Principal:
    return Principal(
        user_id=UUID(w.users[user]), username=f"user-{user}", principal_type="human",
        auth_method="password+totp", grants=frozenset((r, w.ids["scope"]) for r in roles), session_hash="sess",
    )  # fmt: skip


def _profile(w: World) -> UUID:
    return UUID(
        str(
            w.q("SELECT profile_id FROM profile_version WHERE id = :v", v=w.ids["profile_version"])[
                0
            ]["profile_id"]
        )
    )


def _grant(w: World, user: str, *, method: str = "password+totp") -> dict[str, Any]:
    sid = w.stepup(user, "lint_waiver.grant", w.ids["profile_version"], consumed=False)
    if method != "password+totp":
        w.x("UPDATE stepup SET auth_method = :m WHERE id = :i", m=method, i=sid)
    with Session(w.api) as s:
        got, _, _ = waivers.grant(
            s, _who(w, user), _profile(w), 1, rule="check_mode_forced", path_glob="roles/probe/*",
            reason=REASON, stepup_id=UUID(sid),
        )  # fmt: skip
        s.commit()
    return got


def test_a_plan_requester_cannot_waive_and_a_password_stepup_is_refused(world: World) -> None:
    w = world
    with w.api.begin() as c:  # ap2 starts a run of the plan on this version: a requester
        request_run(c, kind=KIND, strategy=STRATEGY, strategy_version=STRATEGY_VERSION,
                    service_id=w.ids["service"], renewal_plan_id=w.ids["plan"], started_by=w.users["ap2"])  # fmt: skip
    with pytest.raises(ProblemError) as exc:
        _grant(w, "ap2")
    assert exc.value.status_code == 403 and exc.value.code == "sod-violation"
    with pytest.raises(ProblemError) as exc:  # the plan creator, who also authored the version
        _grant(w, "op")
    assert exc.value.code == "sod-violation" and "authored" in str(exc.value.detail)
    with pytest.raises(ProblemError) as exc:
        _grant(w, "ap", method="password")
    assert exc.value.code == "totp-required"
    assert w.q("SELECT count(*) AS n FROM lint_waiver")[0]["n"] == 0
    assert len(w.q("SELECT 1 FROM audit_event WHERE action = 'lint_waiver.grant.refused'")) >= 1


def test_a_new_waiver_changes_the_plan_hash(world: World) -> None:
    w = world
    with w.worker.connect() as c:
        before = load_facts(c, w.ids["plan"])
    assert before.recomputed_hash == w.q("SELECT plan_hash FROM renewal_plan")[0]["plan_hash"]
    assert before.lint_waivers == ()
    granted = _grant(w, "ap")
    with w.worker.connect() as c:
        after = load_facts(c, w.ids["plan"])
    assert (
        after.recomputed_hash != before.recomputed_hash
    )  # every approval bound to the old hash is void
    assert [x["id"] for x in after.lint_waivers] == [granted["id"]]


class _LintingRunner:
    """Stands in for the automation runner at B6: the real static lint on a local repository, with the waivers the
    port hands over (no clone)."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    def prepare_automation(
        self, spec: Any, workflow_id: str, *, waivers: Any = None, on_waiver: Any = None
    ) -> Any:
        res = lint_repo(self.repo, "playbooks", waivers=waivers, on_waiver=on_waiver)
        if not res.ok:
            raise AutomationError(
                f"blocking lint findings: {sorted({f.rule for f in res.blocking})}"
            )
        return SimpleNamespace(
            checkout=self.repo,
            lint=res,
            evidence=lambda: {"waived": [f.waived_by for f in res.waived]},
        )


class _Fence:
    def check(self, action: str) -> None:
        return None

    def add_revoke_callback(self, cb: Callable[[str], None]) -> Callable[[], None]:
        return lambda: None


class _Port(RunnerGuestPort):
    def _spec(self, run_id: str, resolved: Any) -> Any:
        return None


def _repo(tmp_path: Path, tasks: str = PROBE) -> Path:
    repo = tmp_path / "repo"
    (repo / "playbooks").mkdir(parents=True)
    (repo / "playbooks" / "configure.yml").write_text("- hosts: ovlm_target\n  roles: [probe]\n")
    (repo / "roles" / "probe" / "tasks").mkdir(parents=True)
    (repo / "roles" / "probe" / "tasks" / "main.yml").write_text(tasks)
    (repo / "roles" / "probe" / "defaults").mkdir(parents=True)
    (repo / "roles" / "probe" / "defaults" / "main.yml").write_text("probe: true\n")
    return repo


def _port(w: World, repo: Path) -> _Port:
    return _Port(w.worker, _LintingRunner(repo), None, ssh=None, http=None)  # type: ignore[arg-type]


def test_b6_lints_with_the_waivers_of_the_profile_version_and_audits_them(
    world: World, tmp_path: Path
) -> None:
    w = world
    run_id = w.start()
    port = _port(w, _repo(tmp_path))

    with pytest.raises(AutomationError, match="check_mode_forced"):
        port.prepare(run_id, {}, _Fence())  # no waiver yet: blocking
    granted = _grant(w, "ap")
    # SFR-2: the step evidence says how much each waiver matched (files of the checkout, findings it covered)
    assert port.prepare(run_id, {}, _Fence()) == {
        "waived": [granted["id"]],
        "lint_waivers": [{"id": granted["id"], "rule": "check_mode_forced", "path_glob": "roles/probe/*",
                          "files_matched": 2, "findings_matched": 1}],
    }  # fmt: skip
    [row] = w.q(
        "SELECT target_id, run_id, project_scope, after FROM audit_event "
        "WHERE action = 'automation.lint_waiver.applied'"
    )
    assert row["target_id"] == granted["id"] and str(row["run_id"]) == run_id
    assert row["project_scope"] == w.ids["scope"]
    assert (
        row["after"]["rule"] == "check_mode_forced"
        and row["after"]["path"] == "roles/probe/tasks/main.yml"
    )
    assert row["after"]["approver"] == "user-ap" and row["after"]["reason"] == REASON

    # revoked: the next B6 refuses again
    sid = w.stepup("ap2", "lint_waiver.revoke", granted["id"], consumed=False)
    with Session(w.api) as s:
        waivers.revoke(
            s,
            _who(w, "ap2"),
            UUID(granted["id"]),
            reason="the probe is gone now",
            stepup_id=UUID(sid),
        )
        s.commit()
    with pytest.raises(AutomationError, match="check_mode_forced"):
        port.prepare(run_id, {}, _Fence())


def test_sfr2_b6_stops_for_a_human_when_a_waiver_covers_more_than_20_findings(
    world: World, tmp_path: Path
) -> None:
    """Review SFR-2: a glob broader than intended is seen before a run, not after: B6 refuses a waiver that covered
    more than 20 findings (``needs_human``, reason ``lint_waiver_too_broad``), and audits nothing."""
    w = world
    run_id = w.start()
    port = _port(w, _repo(tmp_path, PROBE * 21))
    granted = _grant(w, "ap")
    with pytest.raises(StepRefusal) as exc:
        port.prepare(run_id, {}, _Fence())
    assert (
        exc.value.error_class is ErrorClass.NEEDS_HUMAN
        and exc.value.reason == "lint_waiver_too_broad"
    )
    assert exc.value.detail["waivers"] == [{"id": granted["id"], "rule": "check_mode_forced",
                                           "path_glob": "roles/probe/*", "files_matched": 2,
                                           "findings_matched": 21}]  # fmt: skip
    assert not w.q("SELECT 1 FROM audit_event WHERE action = 'automation.lint_waiver.applied'")
    small = _port(w, _repo(tmp_path / "small", PROBE * 20))
    assert small.prepare(run_id, {}, _Fence())["lint_waivers"][0]["findings_matched"] == 20


def _forge(w: World, granter: str, stepup: str) -> str:
    """A waiver row written past the api and its guard (the admin fixture; the guard covers ``ovlm_api`` only)."""
    wid = str(uuid4())
    w.x(
        "INSERT INTO lint_waiver (id, profile_version_id, rule, path_glob, reason, granted_by, stepup_id) "
        "VALUES (:i, :v, 'check_mode_forced', 'roles/probe/*', :why, :u, :s)",
        i=wid, v=w.ids["profile_version"], why=REASON, u=w.users[granter], s=stepup,
    )  # fmt: skip
    return wid


def _g1(w: World) -> Any:
    with w.worker.connect() as c:
        facts = load_facts(c, w.ids["plan"])
        return check_gate(c, Gate.PLAN, facts, run_id=w.run_id or "", run_starter=None,
                          now=now_db(c), check_expiry=True)  # fmt: skip


def _approve_g1_on_the_live_hash(w: World) -> None:
    with w.worker.connect() as c:
        live = load_facts(c, w.ids["plan"]).recomputed_hash
    w.approve("plan", decider="ap3", bound_hash=live)


@pytest.mark.parametrize(
    ("granter", "stepup", "problems"),
    [
        ("ap", "other_action", ["stepup_invalid"]),
        ("ap", "other_user", ["stepup_invalid"]),
        ("ap", "unconsumed", ["stepup_invalid"]),
        ("op", "own", ["granter_not_approver", "granter_is_author", "granter_is_requester"]),
        ("ap2", "own", ["granter_is_requester"]),
    ],
)
def test_sfr1_the_worker_refuses_a_waiver_whose_provenance_does_not_hold(
    world: World, tmp_path: Path, granter: str, stepup: str, problems: list[str]
) -> None:
    """Review SFR-1 (2): the worker re-checks every active waiver before B6 applies it and when it re-validates an
    approval: the granter's consumed password+TOTP step-up for ``lint_waiver.grant`` on the version, the approver
    role in the scope at ``granted_at``, and a granter who is neither the author nor a requester on the version.
    ``op`` authored the version and created the plan; ``ap2`` starts the run here."""
    w = world
    pv = w.ids["profile_version"]
    with w.api.begin() as c:
        request_run(c, kind=KIND, strategy=STRATEGY, strategy_version=STRATEGY_VERSION,
                    service_id=w.ids["service"], renewal_plan_id=w.ids["plan"], started_by=w.users["ap2"])  # fmt: skip
    run_id = str(w.q("SELECT id FROM workflow_run ORDER BY created_at DESC LIMIT 1")[0]["id"])
    sid = {
        "other_action": lambda: w.stepup(granter, "approval.decide", pv),
        "other_user": lambda: w.stepup("ap3", "lint_waiver.grant", pv),
        "unconsumed": lambda: w.stepup(granter, "lint_waiver.grant", pv, consumed=False),
        "own": lambda: w.stepup(granter, "lint_waiver.grant", pv),
    }[stepup]()
    wid = _forge(w, granter, sid)
    port = _port(w, _repo(tmp_path))
    with pytest.raises(StepRefusal) as exc:
        port.prepare(run_id, {}, _Fence())
    assert (
        exc.value.error_class is ErrorClass.NEEDS_HUMAN
        and exc.value.reason == "lint_waiver_invalid"
    )
    assert exc.value.detail["waivers"] == [{"id": wid, "problems": problems}]
    assert not w.q("SELECT 1 FROM audit_event WHERE action = 'automation.lint_waiver.applied'")

    _approve_g1_on_the_live_hash(w)  # an approver approved the plan with the waiver on it
    res = _g1(w)
    assert not res.ok and res.reason == "approval_evidence_invalid"
    assert "8:lint_waivers" in res.evidence["failures"]
    assert res.evidence["lint_waivers"] == [{"id": wid, "problems": problems}]


def test_sfr1_a_waiver_granted_through_the_api_passes_the_worker_checks(
    world: World, tmp_path: Path
) -> None:
    w = world
    run_id = w.start()
    granted = _grant(w, "ap")
    assert port_prepare_ok(w, tmp_path, run_id)["lint_waivers"][0]["id"] == granted["id"]
    _approve_g1_on_the_live_hash(w)
    res = _g1(w)
    assert res.ok, res.evidence
    assert res.evidence["checks"]["8:lint_waivers"] is True


def test_sfr1_a_granter_who_lost_the_approver_role_before_granting_is_refused(
    world: World, tmp_path: Path
) -> None:
    """The role is checked as of ``granted_at`` (role-binding history), not today."""
    w = world
    run_id = w.start()
    w.x(
        "UPDATE role_binding SET revoked_at = now() - interval '1 hour' WHERE user_id = :u",
        u=w.users["ap3"],
    )
    wid = _forge(w, "ap3", w.stepup("ap3", "lint_waiver.grant", w.ids["profile_version"]))
    with pytest.raises(StepRefusal) as exc:
        _port(w, _repo(tmp_path)).prepare(run_id, {}, _Fence())
    assert exc.value.detail["waivers"] == [{"id": wid, "problems": ["granter_not_approver"]}]


def port_prepare_ok(w: World, tmp_path: Path, run_id: str) -> Any:
    return _port(w, _repo(tmp_path)).prepare(run_id, {}, _Fence())


# --- SFR-3: a waiver granter is a requester of G1 and G2 ------------------------------------------------------------


def _replan(w: World, *, created_by: str = "op") -> str:
    """The plan as if created after the waiver (its stored hash binds the waiver), by ``created_by``."""
    with w.worker.connect() as c:
        live = load_facts(c, w.ids["plan"]).recomputed_hash
    w.x("UPDATE renewal_plan SET plan_hash = :h, created_by = :u WHERE id = :p",
        h=live, u=w.users[created_by], p=w.ids["plan"])  # fmt: skip
    return str(live)


def _request(w: World, user: str) -> Any:
    with Session(w.api) as s:
        out = svc.request_approval(s, _who(w, user, roles=("operator", "approver")), gate=Gate.PLAN,
                                   plan_id=w.ids["plan"], run_id=None, scope=w.ids["scope"])  # fmt: skip
        s.commit()
    return out


def _decide(w: World, user: str, aid: str) -> Any:
    sid = w.stepup(user, "approval.decide", aid, consumed=False)
    with Session(w.api) as s:
        out = svc.decide(s, _who(w, user), CFG, UUID(aid), decision="approved", typed=None, comment=None,
                         stepup_id=UUID(sid))  # fmt: skip
        s.commit()
    return out


def test_sfr3_a_waiver_granter_cannot_request_or_create_the_plan_it_eases(world: World) -> None:
    """Review SFR-3: ``grant`` refused a granter who already requested a plan on the version, not the reverse order
    (grant first, then create the plan or request its approval). security-model.md 3.2: never, whatever
    ``allow_operator_approver`` says."""
    w = world
    _grant(w, "ap2")
    _replan(w)
    with pytest.raises(
        ProblemError
    ) as exc:  # the granter asks for the approval of a plan its waiver eases
        _request(w, "ap2")
    assert exc.value.status_code == 403 and exc.value.code == "sod-violation"
    assert "lint waiver" in str(exc.value.detail)
    _replan(w, created_by="ap2")  # the granter created the plan; another operator asks
    with pytest.raises(ProblemError) as exc:
        _request(w, "op")
    assert exc.value.code == "sod-violation"
    assert len(w.q("SELECT 1 FROM audit_event WHERE action = 'approval.request.refused'")) == 2
    assert not w.q("SELECT 1 FROM approval WHERE decision IS NULL")
    _replan(w)
    assert _request(w, "op")["requested_by"] == w.users["op"]  # nobody plays both parts


def test_sfr3_decide_refuses_a_gate_whose_requester_granted_a_waiver_and_the_granter_as_decider(
    world: World,
) -> None:
    w = world
    _grant(w, "ap2")
    live = _replan(w)
    aid = str(uuid4())  # a request recorded before this check existed: the granter asked for it
    w.x("INSERT INTO approval (id, subject_type, subject_id, plan_id, scope, bound_hash, requester_set, requested_by) "
        "VALUES (:i, 'plan', :p, :p, :s, :h, CAST(:rs AS uuid[]), :u)",
        i=aid, p=w.ids["plan"], s=w.ids["scope"], h=live, rs="{" + w.users["ap2"] + "}", u=w.users["ap2"])  # fmt: skip
    with pytest.raises(ProblemError) as exc:
        _decide(w, "ap3", aid)
    assert exc.value.code == "sod-violation" and "lint waiver" in str(exc.value.detail)
    assert w.q("SELECT 1 FROM audit_event WHERE action = 'approval.decide.refused'")
    w.x("DELETE FROM approval WHERE id = :i", i=aid)
    ok = _request(w, "op")
    with pytest.raises(
        ProblemError
    ) as exc:  # the granter is a requester: it does not approve the plan either
        _decide(w, "ap2", ok["id"])
    assert exc.value.code == "sod-violation" and "lint_waiver_granter" in str(exc.value.detail)
    assert _decide(w, "ap3", ok["id"])["decision"] == "approved"


def test_sfr3_revalidation_refuses_a_waiver_granter_in_the_requester_set(world: World) -> None:
    w = world
    _grant(w, "ap2")
    live = _replan(w)
    w.approve("plan", decider="ap3", bound_hash=live)
    assert _g1(w).ok
    w.x("UPDATE approval SET requested_by = :u", u=w.users["ap2"])  # the granter asked for it
    res = _g1(w)
    assert not res.ok and "2:waiver_granter" in res.evidence["failures"]
    w.x("DELETE FROM approval")
    w.approve("plan", decider="ap2", bound_hash=live)  # the granter decided it
    res = _g1(w)
    assert not res.ok and "2:requester_set" in res.evidence["failures"]
    assert res.evidence["requester_set"]["lint_waiver_granters"] == [w.users["ap2"]]


def test_sfr7_the_approval_stores_who_granted_each_waiver_when_and_why(world: World) -> None:
    """Review SFR-7: ``approval.hash_inputs.lint_waivers`` carries the granter's name, the time and the reason for the
    approval page; the plan hash still binds only id, rule, glob and granter."""
    w = world
    granted = _grant(w, "ap")
    _replan(w)
    approval = _request(w, "op")
    [shown] = w.q("SELECT hash_inputs FROM approval WHERE id = :i", i=approval["id"])[0][
        "hash_inputs"
    ]["lint_waivers"]
    assert shown["id"] == granted["id"] and shown["granted_by"] == w.users["ap"]
    assert (shown["granted_by_name"], shown["reason"]) == ("user-ap", REASON)
    assert shown["granted_at"] == granted["granted_at"] and shown["profile_version"] == 1
    with w.worker.connect() as c:
        assert list(load_facts(c, w.ids["plan"]).lint_waivers) == [
            {k: granted[k] for k in ("id", "rule", "path_glob", "granted_by")}
        ]
