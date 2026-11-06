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
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from ovlm.auth.errors import ProblemError
from ovlm.auth.principal import Principal
from ovlm.automation.lint import lint_repo
from ovlm.automation.types import AutomationError
from ovlm.profiles import waivers
from ovlm.renewal.base import StepRefusal
from ovlm.renewal.plans import KIND, STRATEGY, STRATEGY_VERSION, load_facts
from ovlm.renewal.production import RunnerGuestPort
from ovlm.workflow.contract import ErrorClass
from ovlm.workflow.requests import request_run
from tests.integration.renewal.conftest import World

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
