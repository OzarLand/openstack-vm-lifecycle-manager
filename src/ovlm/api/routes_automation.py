"""Restricted automation artefacts, security-model.md 5.2 (SEC-R-3).

``GET /api/v1/automation-runs/{id}/artefacts`` returns the log, events and diff of one runner attempt (whatever
the playbook printed: vault-decrypted workload secrets included, "reported by guest"). Only ``operator`` or
``admin`` in the run's project (or globally) may read them; a viewer of the project gets 403, a caller who cannot see
the project gets 404 (no existence leak). Every read, and every refusal, is audited. The api reads the table
directly: it never imports ``ovlm.automation`` (import-linter).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.api.routes_common import ProblemRoute, audit_change
from ovlm.auth.authz import Action, ScopeDecision, decide_in_scope
from ovlm.auth.deps import get_db, require_role
from ovlm.auth.principal import Principal
from ovlm.registry.errors import DomainError

# Any authenticated reader gets as far as the scope decision; the matrix decides (404 / 403 / allowed).
READER = Depends(require_role("viewer"))
DB = Depends(get_db)

router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)

_NOT_FOUND = ("automation-run-not-found", "Automation run not found", "No such automation run.")


@router.get("/automation-runs/{run_id}/artefacts")
def get_restricted_artefacts(
    run_id: UUID, session: Session = DB, who: Principal = READER
) -> dict[str, Any]:
    row = (
        session.execute(
            text(
                "SELECT project_scope, log, events, diff, store_diffs, artifact_expires_at, artifacts_purged_at "
                "FROM automation_run WHERE id = :id"
            ),
            {"id": str(run_id)},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise DomainError(404, *_NOT_FOUND)
    scope = str(row["project_scope"])
    decision = decide_in_scope(who, Action.AUTOMATION_ARTEFACT_VIEW, scope)
    if decision is not ScopeDecision.ALLOWED:
        audit.record(
            session, action="automation_artefact.view", target_type="automation_run",
            target_id=str(run_id), result="denied", actor_id=who.user_id,
            principal_type=who.principal_type, auth_method=who.auth_method,
            source_ip=who.source_ip, project_scope=scope,
        )  # fmt: skip
        session.commit()
        if decision is ScopeDecision.NOT_FOUND:
            raise DomainError(404, *_NOT_FOUND)
        raise DomainError(
            403, "forbidden", "Forbidden",
            "Automation logs, events and diffs are restricted to operators and admins of the project.",
        )  # fmt: skip
    audit_change(
        session, who, "automation_artefact.view", "automation_run", str(run_id), scope=scope
    )
    session.commit()
    purged = row["artifacts_purged_at"]
    return {
        "run_id": str(run_id),
        "project_scope": scope,
        "label": "reported by guest",
        "log": row["log"],
        "events": row["events"],
        "diff": row["diff"] if row["store_diffs"] else None,
        "store_diffs": bool(row["store_diffs"]),
        "expires_at": row["artifact_expires_at"].isoformat(),
        "purged_at": purged.isoformat() if purged else None,
    }
