"""Read-only checks run before an upgrade and around a backup or restore (docs/backup-restore-upgrade.md).

Nothing here writes to the database or decrypts a credential: the checks need ``SELECT`` only and run as the api
role (or the owner). The KEK private key is never loaded; key ids come from public keys.

* :func:`migration_findings`: may this release migrate the database? Refused when the database is at a revision
  this release does not know (migrated by a newer release: a downgrade) or off its history. Downgrades are not
  supported: append-only evidence (``run_downtime``, ``step_acceptance``, ``automation_reprepare``) would be dropped
  (review PMR-10). The way back is a restore.
* :func:`runtime_findings`: is it safe to stop the worker and migrate now? Refused while a renewal is inside its
  downtime window or a restore (phase ``window``/``restore``, or an open ``run_downtime`` interval), and, with
  ``worker_stopped``, while a worker still beats or a step still holds an unexpired lease.
* :func:`backup_findings`: can a dump taken now be restored with the keys on hand? Every sealed secret in use must
  be wrapped to one of the given KEK public keys, and every stored TOTP secret must decrypt with the TOTP key.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from sqlalchemy import Connection, text

from ovlm.auth.totp import TotpUnavailableError, TotpVault
from ovlm.secrets.store import kek_usage

Level = Literal["block", "warn", "info"]

#: Workflow run states after which a run holds nothing (migration 0002_workflow).
TERMINAL_RUN_STATES = ("rejected", "cancelled", "failed", "completed", "rolled_back")
#: Run phases in which the service is down or moving (renewal-workflow.md sections 2.2, 4).
OUTAGE_PHASES = ("window", "restore")


@dataclass(frozen=True)
class Finding:
    level: Level
    code: str
    message: str

    def line(self) -> str:
        return f"{self.level.upper()}\t{self.code}\t{self.message}"


def exit_code(findings: Iterable[Finding]) -> int:
    """0 when nothing blocks; 2 when at least one finding blocks."""
    return 2 if any(f.level == "block" for f in findings) else 0


def _exists(conn: Connection, table: str) -> bool:
    return bool(conn.execute(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table}).scalar_one())


def migration_findings(current: str | None, script: ScriptDirectory) -> list[Finding]:
    head = script.get_current_head()
    if head is None:
        return [Finding("block", "no-migrations", "this release has no migration scripts")]
    if current is None:
        return [
            Finding(
                "info",
                "fresh-database",
                f"empty database: `ovlm migrate` creates the schema at {head}",
            )
        ]
    if current == head:
        return [Finding("info", "schema-at-head", f"database at {head}: no migration pending")]
    try:
        known = script.get_revision(current) is not None
    except CommandError:
        known = False
    if not known:
        return [
            Finding(
                "block",
                "database-ahead",
                f"database at {current}, a revision this release does not know (head {head}): it was migrated by "
                "a newer release or another branch. Downgrades are not supported; run that release, or restore the "
                "backup taken before its upgrade",
            )
        ]
    try:
        pending = [r.revision for r in script.iterate_revisions(head, current)]
    except CommandError:
        return [
            Finding(
                "block",
                "database-off-history",
                f"database at {current}, which is not an ancestor of this release's head {head}: refusing to "
                "migrate; restore a backup or run the matching release",
            )
        ]
    pending.reverse()
    return [
        Finding(
            "info",
            "migrations-pending",
            f"database at {current}; `ovlm migrate` applies {len(pending)} revision(s) up to {head}: "
            + ", ".join(pending),
        )
    ]


def runtime_findings(
    conn: Connection,
    *,
    worker_stopped: bool,
    live_worker_age: float,
    planned_window_horizon: timedelta,
) -> list[Finding]:
    out: list[Finding] = []
    if not _exists(conn, "workflow_run"):
        return [
            Finding(
                "info", "no-workflow-tables", "no workflow tables yet: nothing can be in a window"
            )
        ]
    terminal = {"t": list(TERMINAL_RUN_STATES), "o": list(OUTAGE_PHASES)}
    outage = conn.execute(
        text(
            "SELECT id, phase, state, needs_human_reason FROM workflow_run "
            "WHERE NOT (state = ANY(:t)) AND phase = ANY(:o) ORDER BY created_at"
        ),
        terminal,
    ).all()
    for r in outage:
        out.append(
            Finding(
                "block",
                "outage-in-progress",
                f"run {r.id} is in phase {r.phase} (state {r.state}"
                + (f", needs_human {r.needs_human_reason}" if r.needs_human_reason else "")
                + "): the service is down or moving. Never upgrade mid-window: let the window or restore finish",
            )
        )
    if _exists(conn, "run_downtime"):
        listed = [r.id for r in outage]
        for r in conn.execute(
            text(
                "SELECT run_id, kind, started_at FROM run_downtime WHERE ended_at IS NULL "
                "AND NOT (run_id = ANY(CAST(:listed AS uuid[]))) ORDER BY started_at"
            ),
            {"listed": listed},
        ).all():
            out.append(
                Finding(
                    "block",
                    "downtime-open",
                    f"run {r.run_id} has an open {r.kind} downtime interval since {r.started_at.isoformat()}: "
                    "the service is down",
                )
            )
    others = conn.execute(
        text(
            "SELECT coalesce(phase, 'none') AS phase, state, count(*) AS n FROM workflow_run "
            "WHERE NOT (state = ANY(:t)) AND (phase IS NULL OR NOT (phase = ANY(:o))) "
            "GROUP BY 1, 2 ORDER BY 1, 2"
        ),
        terminal,
    ).all()
    for r in others:
        out.append(
            Finding(
                "warn",
                "runs-active",
                f"{r.n} run(s) in state {r.state}, phase {r.phase}: outside the window; they resume after the "
                "upgrade (each step probes before it acts)",
            )
        )
    leased = conn.execute(
        text(
            "SELECT s.run_id, s.step_key, s.lease_owner, s.lease_expires_at FROM workflow_step s "
            "WHERE s.state = 'running' AND s.lease_expires_at > now() ORDER BY s.lease_expires_at"
        )
    ).all()
    for r in leased:
        out.append(
            Finding(
                "block" if worker_stopped else "info",
                "step-leased",
                f"step {r.step_key} of run {r.run_id} is running under a lease until "
                f"{r.lease_expires_at.isoformat()}"
                + (
                    ": the worker did not drain; wait for the step to finish or the lease to expire"
                    if worker_stopped
                    else ""
                ),  # fmt: skip
            )
        )
    live = conn.execute(
        text(
            "SELECT worker_id, draining, last_seen_at FROM worker_heartbeat "
            "WHERE last_seen_at >= now() - make_interval(secs => :age) ORDER BY worker_id"
        ),
        {"age": live_worker_age},
    ).all()
    for r in live:
        state = "draining" if r.draining else "running"
        out.append(
            Finding(
                "block" if worker_stopped else "info",
                "worker-live",
                f"worker {r.worker_id} ({state}) beat at {r.last_seen_at.isoformat()}"
                + (": stop every worker before `ovlm migrate`" if worker_stopped else ""),
            )
        )
    if not live and not worker_stopped:
        out.append(Finding("info", "no-live-worker", "no worker has beaten recently"))
    if _exists(conn, "renewal_plan"):
        for r in conn.execute(
            text(
                "SELECT id, planned_window_start FROM renewal_plan WHERE state = 'approved' "
                "AND planned_window_start IS NOT NULL "
                "AND planned_window_start BETWEEN now() - interval '1 hour' AND now() + :h "
                "ORDER BY planned_window_start"
            ),
            {"h": planned_window_horizon},
        ).all():
            out.append(
                Finding(
                    "warn",
                    "planned-window-soon",
                    f"renewal plan {r.id} plans its window at {r.planned_window_start.isoformat()}: an upgrade "
                    "now may delay it; keep the worker stopped no longer than needed",
                )
            )
    return out


def backup_findings(
    conn: Connection, kek_ids: frozenset[str], totp: TotpVault | None
) -> list[Finding]:
    """Can the database be restored with the KEK(s) named by ``kek_ids`` and this TOTP key?"""
    out: list[Finding] = []
    if _exists(conn, "sealed_secret") and _exists(conn, "credential_ref"):
        usage = {k: n for k, n in kek_usage(conn).items() if n}
        for kid, n in sorted(usage.items()):
            if kid in kek_ids:
                out.append(
                    Finding("info", "kek-in-use", f"kek_id {kid}: {n} sealed secret(s) in use")
                )
            else:
                out.append(
                    Finding(
                        "block",
                        "kek-missing",
                        f"kek_id {kid}: {n} sealed secret(s) in use are wrapped to a key not given: a restore "
                        "needs that private key too. Finish the re-wrap (`ovlm kek status` exit 0) or keep that key",
                    )
                )
        if not usage:
            out.append(Finding("info", "kek-unused", "no sealed secret in use"))
    if _exists(conn, "app_user"):
        blobs = [
            bytes(r[0])
            for r in conn.execute(
                text("SELECT totp_secret_enc FROM app_user WHERE totp_secret_enc IS NOT NULL")
            ).all()
        ]
        if blobs and totp is None:
            out.append(
                Finding(
                    "block",
                    "totp-key-missing",
                    f"{len(blobs)} stored TOTP secret(s) but no TOTP key configured (auth.totp_key_file)",
                )
            )
        elif blobs and totp is not None:
            bad = 0
            for b in blobs:
                try:
                    totp.decrypt(b)
                except TotpUnavailableError:
                    bad += 1
            if bad:
                out.append(
                    Finding(
                        "block",
                        "totp-key-mismatch",
                        f"{bad} of {len(blobs)} stored TOTP secret(s) do not decrypt with the configured TOTP key: "
                        "it is not the key of this database",
                    )
                )
            else:
                out.append(
                    Finding(
                        "info", "totp-key-matches", f"{len(blobs)} stored TOTP secret(s) decrypt"
                    )
                )
        else:
            out.append(Finding("info", "totp-unused", "no stored TOTP secret"))
    return out
