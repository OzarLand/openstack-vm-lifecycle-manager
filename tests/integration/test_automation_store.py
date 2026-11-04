# ruff: noqa: F811
"""``automation_run`` (migration ``automation_0001``) against real PostgreSQL: grants, the restricted columns,
the opt-in rule for diffs, retention purge and the scope-based read rule."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from ovlm.auth.authz import can_read_restricted
from ovlm.automation.model import RunnerConfig, RunRecord
from ovlm.automation.store import NEVER_EXPORT_COLUMNS, ArtifactStore
from tests.integration.workflow.conftest import WfDb, drive, wf  # noqa: F401
from tests.integration.workflow.dummy import plan_step

SECRET_IN_LOG = "vault-decrypted-workload-secret"


def record(step_id: str, **over: Any) -> RunRecord:
    base: dict[str, Any] = dict(
        workflow_id="wf", step_id=step_id, attempt=1, phase="configure", target_role="new",
        project_scope="proj-a", repo="https://git.example.org/team/app.git", sha="a" * 40,
        requirements_hash="b" * 64, ansible_core_version="2.19.4", extravars_sha256="c" * 64,
        extravars_keys=["ovlm.role"], first_use=False, exit_code=0, classification="ok",
        reported_classification="ok", reason="exit 0 and result.ok",
        result={"schema": "ovlm.result/1", "ok": True}, result_error=None,
        task_summary=[{"task": "t", "host": "h", "status": "ok"}],
        log=f"TASK output {SECRET_IN_LOG}", events=[{"event": "runner_on_ok"}], diff="--- a\n+++ b\n",
        duration_seconds=1.5, host_key_mode="pinned", lint_digest="d" * 64,
    )  # fmt: skip
    base.update(over)
    return RunRecord(**base)


@pytest.fixture
def step_id(wf: WfDb) -> str:  # noqa: F811
    run_id = wf.request([plan_step("set", res="a", value="A")])
    drive(wf.make_engine(), run_id, wf)  # admission creates the step rows
    return str(wf.steps(run_id)[0]["id"])


STORE = ArtifactStore(
    RunnerConfig(run_root=__import__("pathlib").Path("/nonexistent"), run_user=None)
)


def test_worker_saves_and_the_diff_needs_the_profile_opt_in(wf: WfDb, step_id: str) -> None:  # noqa: F811
    with wf.worker_db().begin() as c:
        rid = STORE.save(c, record(step_id), store_diffs=False)
        rid2 = STORE.save(c, record(step_id, attempt=2), store_diffs=True)
    rows = {str(r["id"]): r for r in wf.q("SELECT * FROM automation_run")}
    assert rows[str(rid)]["diff"] is None and rows[str(rid)]["store_diffs"] is False
    assert rows[str(rid2)]["diff"] and rows[str(rid2)]["store_diffs"] is True
    # DB-level backstop: a diff without the recorded opt-in is refused even if the code were wrong
    with pytest.raises(IntegrityError), wf.admin.begin() as c:
        c.execute(
            text("UPDATE automation_run SET diff = 'x', store_diffs = false WHERE id = :i"),
            {"i": rid},
        )


def test_table_constraints(wf: WfDb, step_id: str) -> None:  # noqa: F811
    bad = [
        record(step_id, classification="unknown"),
        record(step_id, phase="rm_rf"),
        record(step_id, target_role="both"),
        record(step_id, sha="main"),
        record(step_id, project_scope=""),
        record(step_id, host_key_mode="off"),
    ]
    for rec in bad:
        with pytest.raises(IntegrityError), wf.worker_db().begin() as c:
            STORE.save(c, rec, store_diffs=False)
    with pytest.raises(IntegrityError), wf.worker_db().begin() as c:  # step must exist
        STORE.save(c, record("00000000-0000-0000-0000-000000000000"), store_diffs=False)


def test_grants_worker_inserts_and_purges_only_api_reads_only(wf: WfDb, step_id: str) -> None:  # noqa: F811
    with wf.worker_db().begin() as c:
        rid = STORE.save(c, record(step_id), store_diffs=True)
    worker, api = wf.worker_db(), wf.api_db()
    denied = (ProgrammingError, DBAPIError)
    for eng, stmt in (
        (api, "INSERT INTO automation_run (id) VALUES (gen_random_uuid())"),
        (api, "UPDATE automation_run SET log = NULL"),
        (api, "DELETE FROM automation_run"),
        (worker, "DELETE FROM automation_run"),
        (worker, "UPDATE automation_run SET classification = 'ok'"),
        (worker, "UPDATE automation_run SET result = '{}'::jsonb"),
        (worker, "UPDATE automation_run SET artifact_expires_at = now() + interval '10 years'"),
    ):
        with pytest.raises(denied, match="permission denied"), eng.begin() as c:
            c.execute(text(stmt))
    with api.connect() as c:
        assert c.execute(text("SELECT count(*) FROM automation_run")).scalar_one() == 1
    with (
        worker.begin() as c
    ):  # the retention purge touches only the restricted columns and the stamp
        c.execute(
            text(
                "UPDATE automation_run SET log = NULL, events = NULL, diff = NULL, artifacts_purged_at = now() WHERE id = :i"
            ),
            {"i": rid},
        )  # noqa: E501


def test_restricted_columns_are_read_by_operator_or_admin_in_scope_only(
    wf: WfDb, step_id: str
) -> None:  # noqa: F811
    with wf.worker_db().begin() as c:
        rid = STORE.save(c, record(step_id, project_scope="proj-a"), store_diffs=True)
    api = wf.api_db()
    allowed = [
        frozenset({("operator", "proj-a")}),
        frozenset({("admin", "proj-a")}),
        frozenset({("operator", "global")}),
        frozenset({("viewer", "proj-a"), ("operator", "proj-a")}),
    ]
    refused = [
        frozenset(),
        frozenset({("viewer", "proj-a")}),
        frozenset({("viewer", "global")}),
        frozenset({("approver", "proj-a")}),
        frozenset({("operator", "proj-b")}),
        frozenset({("admin", "proj-b")}),
    ]
    with api.connect() as c:
        for grants in allowed:
            got = STORE.get_restricted(c, rid, grants)
            assert got is not None and SECRET_IN_LOG in got["log"] and got["diff"], grants
        for grants in refused:
            assert STORE.get_restricted(c, rid, grants) is None, grants
        assert STORE.get_restricted(c, "00000000-0000-0000-0000-000000000000", allowed[0]) is None
        # the viewer tier: validated result and per-task status, but none of the restricted columns
        tier = STORE.get_result_tier(c, rid)
    assert (
        tier is not None
        and tier["result"]["ok"] is True
        and tier["task_summary"][0]["status"] == "ok"
    )
    assert not (set(tier) & NEVER_EXPORT_COLUMNS)
    assert can_read_restricted(frozenset({("operator", "proj-a")}), "proj-a")
    assert not can_read_restricted(frozenset({("operator", "proj-b")}), "proj-a")


def test_retention_purges_restricted_columns_only(wf: WfDb, step_id: str) -> None:  # noqa: F811
    now = datetime.now(UTC)
    store = ArtifactStore(
        RunnerConfig(
            run_root=__import__("pathlib").Path("/x"),
            run_user=None,
            artifact_retention=timedelta(days=30),
        )
    )  # noqa: E501
    with wf.worker_db().begin() as c:
        old = store.save(c, record(step_id), store_diffs=True, now=now - timedelta(days=31))
        fresh = store.save(
            c, record(step_id, attempt=2), store_diffs=True, now=now - timedelta(days=1)
        )
    with wf.worker_db().begin() as c:
        assert store.purge_expired(c, now=now) == 1
        assert store.purge_expired(c, now=now) == 0, "idempotent"
    rows = {str(r["id"]): r for r in wf.q("SELECT * FROM automation_run")}
    assert rows[old]["log"] is None and rows[old]["events"] is None and rows[old]["diff"] is None
    assert rows[old]["artifacts_purged_at"] is not None
    assert rows[old]["result"] and rows[old]["task_summary"], (
        "the validated result survives the purge"
    )
    assert SECRET_IN_LOG in rows[fresh]["log"]
    with wf.api_db().connect() as c:
        got = STORE.get_restricted(c, old, frozenset({("admin", "global")}))
    assert got is not None and got["log"] is None and got["artifacts_purged_at"] is not None


def test_retention_is_its_own_clock(wf: WfDb, step_id: str) -> None:  # noqa: F811
    """artifact_expires_at is computed from automation.artifact_retention, independent of audit retention."""
    now = datetime.now(UTC)
    store = ArtifactStore(
        RunnerConfig(
            run_root=__import__("pathlib").Path("/x"),
            run_user=None,
            artifact_retention=timedelta(days=7),
        )
    )  # noqa: E501
    with wf.worker_db().begin() as c:
        rid = store.save(c, record(step_id), store_diffs=False, now=now)
    row = wf.one("SELECT artifact_expires_at FROM automation_run WHERE id = :i", i=rid)
    assert abs((row["artifact_expires_at"] - (now + timedelta(days=7))).total_seconds()) < 1


def test_the_never_export_set_is_exactly_the_restricted_columns() -> None:
    assert {"log", "events", "diff"} == NEVER_EXPORT_COLUMNS


def test_applied_lint_waivers_are_audited(wf: WfDb, tmp_path: Any) -> None:  # noqa: F811
    from sqlalchemy.orm import Session

    from ovlm.automation.audit import waiver_audit_hook
    from ovlm.automation.lint import StaticWaivers, Waiver, lint_repo

    repo = tmp_path / "r"
    (repo / "playbooks").mkdir(parents=True)
    (repo / "playbooks" / "healthcheck.yml").write_text(
        "- hosts: ovlm_target\n  tasks:\n    - ansible.builtin.command: id\n      check_mode: false\n"
    )
    waivers = StaticWaivers(
        (Waiver("wv-9", "check_mode_forced", "playbooks/*", "approver-7", "read-only probe"),)
    )
    with Session(wf.worker_db()) as session, session.begin():
        hook = waiver_audit_hook(session, project_scope="proj-a", profile_ref="profile-1@3")
        res = lint_repo(repo, "playbooks", waivers=waivers, on_waiver=hook)
    assert res.ok
    row = wf.one("SELECT * FROM audit_event WHERE action = 'automation.lint_waiver.applied'")
    assert row["target_type"] == "automation_lint_waiver" and row["target_id"] == "wv-9"
    assert (
        row["principal_type"] == "worker"
        and row["project_scope"] == "proj-a"
        and row["result"] == "success"
    )
    assert row["after"]["approver"] == "approver-7" and row["after"]["rule"] == "check_mode_forced"
    assert row["after"]["profile_ref"] == "profile-1@3"
