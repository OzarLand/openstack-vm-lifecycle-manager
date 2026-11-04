"""Restricted artefact store: the ``automation_run`` table (security-model 5.2, data-model 3, SEC-R-3).

Tiers:

* **result tier** (``result``, ``task_summary``, evidence columns): the validated ``ovlm.result/1`` and per-task
  changed/unchanged. Visible to anyone who may see the run (viewers included), labelled "reported by guest".
* **restricted tier** (``log``, ``events``, ``diff``): whatever tasks print or template, vault-decrypted workload
  secrets included. Readable only by ``operator``/``admin`` holding the role in the **project scope** of the run,
  under their own retention (``artifact_expires_at``), never exported (:data:`NEVER_EXPORT_COLUMNS`), and the
  diff is stored only when the profile opted in (``store_diffs``).

Writes use the caller's SQLAlchemy ``Connection`` so the engine can make them part of its fenced commit.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

from ovlm.automation.model import RunnerConfig, RunRecord
from ovlm.workflow.ids import new_id

RESTRICTED_COLUMNS: tuple[str, ...] = ("log", "events", "diff")
NEVER_EXPORT_COLUMNS: frozenset[str] = frozenset(RESTRICTED_COLUMNS)
RESTRICTED_READ_ROLES: frozenset[str] = frozenset({"operator", "admin"})
GLOBAL_SCOPE = "global"

_RESULT_TIER = (
    "id, step_id, attempt, phase, target_role, project_scope, repo, sha, requirements_hash, "
    "ansible_core_version, extravars_sha256, extravars_keys, first_use, exit_code, classification, "
    "reported_classification, reason, result, result_error, task_summary, duration_seconds, host_key_mode, "
    "lint_digest, artifact_expires_at, artifacts_purged_at, created_at"
)


def can_read_restricted(grants: frozenset[tuple[str, str]], project_scope: str) -> bool:
    """``grants`` are (role, scope) pairs as in :class:`ovlm.auth.principal.Principal`. ``operator`` and ``admin``
    qualify, in the run's project or globally; ``viewer`` and ``approver`` do not. (Mirrors
    ``ovlm.auth.authz`` semantics without importing it; ``admin`` does not inherit ``operator``, so both are
    listed explicitly.)"""
    return any(
        role in RESTRICTED_READ_ROLES and scope in (GLOBAL_SCOPE, project_scope)
        for role, scope in grants
    )


@dataclass(frozen=True)
class StoredRun:
    id: str
    row: Mapping[str, Any]


class ArtifactStore:
    def __init__(self, config: RunnerConfig) -> None:
        self._retention = config.artifact_retention

    def save(
        self, conn: Connection, record: RunRecord, *, store_diffs: bool, now: datetime | None = None
    ) -> str:
        """Insert the run row. The diff is dropped unless ``store_diffs`` (belt and braces: the runner already
        withholds it, and the table CHECK refuses a diff without the opt-in)."""
        now = now or datetime.now(UTC)
        run_id = new_id()
        conn.execute(
            text(
                """
                INSERT INTO automation_run (
                  id, step_id, attempt, phase, target_role, project_scope, repo, sha, requirements_hash,
                  ansible_core_version, extravars_sha256, extravars_keys, first_use, exit_code, classification,
                  reported_classification, reason, result, result_error, task_summary, duration_seconds,
                  host_key_mode, lint_digest, log, events, diff, artifact_expires_at, store_diffs)
                VALUES (
                  :id, :step_id, :attempt, :phase, :target_role, :project_scope, :repo, :sha, :requirements_hash,
                  :ansible_core_version, :extravars_sha256, :extravars_keys, :first_use, :exit_code,
                  :classification, :reported, :reason, CAST(:result AS jsonb), :result_error,
                  CAST(:task_summary AS jsonb), :duration, :host_key_mode, :lint_digest, :log,
                  CAST(:events AS jsonb), :diff, :expires, :store_diffs)
                """
            ),
            {
                "id": run_id,
                "step_id": record.step_id,
                "attempt": record.attempt,
                "phase": record.phase,
                "target_role": record.target_role,
                "project_scope": record.project_scope,
                "repo": record.repo,
                "sha": record.sha,
                "requirements_hash": record.requirements_hash,
                "ansible_core_version": record.ansible_core_version,
                "extravars_sha256": record.extravars_sha256,
                "extravars_keys": record.extravars_keys,
                "first_use": record.first_use,
                "exit_code": record.exit_code,
                "classification": record.classification,
                "reported": record.reported_classification,
                "reason": record.reason,
                "result": json.dumps(record.result) if record.result is not None else None,
                "result_error": record.result_error,
                "task_summary": json.dumps(record.task_summary),
                "duration": record.duration_seconds,
                "host_key_mode": record.host_key_mode,
                "lint_digest": record.lint_digest,
                "log": record.log,
                "events": json.dumps(record.events),
                "diff": record.diff if store_diffs else None,
                "expires": now + self._retention,
                "store_diffs": store_diffs,
            },
        )
        return run_id

    # ---- reads -------------------------------------------------------------------------------------------

    def get_result_tier(self, conn: Connection, run_id: str) -> Mapping[str, Any] | None:
        row = conn.execute(
            text(f"SELECT {_RESULT_TIER} FROM automation_run WHERE id = :id"),  # noqa: S608 - constant columns
            {"id": run_id},
        ).mappings().first()  # fmt: skip
        return dict(row) if row else None

    def get_restricted(
        self, conn: Connection, run_id: str, grants: frozenset[tuple[str, str]]
    ) -> Mapping[str, Any] | None:
        """Return ``log``/``events``/``diff`` only if ``grants`` allow it for the run's project scope; ``None`` for
        an unknown run *and* for a denied caller (no existence oracle)."""
        row = conn.execute(
            text(
                "SELECT project_scope, log, events, diff, artifacts_purged_at FROM automation_run WHERE id = :id"
            ),
            {"id": run_id},
        ).mappings().first()  # fmt: skip
        if row is None or not can_read_restricted(grants, row["project_scope"]):
            return None
        return {k: row[k] for k in (*RESTRICTED_COLUMNS, "artifacts_purged_at")}

    # ---- retention ---------------------------------------------------------------------------------------

    def purge_expired(self, conn: Connection, *, now: datetime | None = None) -> int:
        """NULL the restricted columns of every run past ``artifact_expires_at``. Metadata and the validated
        result stay (they are part of the run evidence); returns the number of rows purged."""
        now = now or datetime.now(UTC)
        res = conn.execute(
            text(
                """
                UPDATE automation_run
                   SET log = NULL, events = NULL, diff = NULL, artifacts_purged_at = :now
                 WHERE artifact_expires_at <= :now AND artifacts_purged_at IS NULL
                """
            ),
            {"now": now},
        )
        return int(res.rowcount)
