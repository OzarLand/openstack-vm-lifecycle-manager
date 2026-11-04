"""Audit adapter for lint waivers: every applied waiver becomes an ``audit_event`` row (contract section 9).

The lint itself touches no database; ``waiver_audit_hook`` returns the ``on_waiver`` callback for
:func:`ovlm.automation.lint.lint_repo` / :meth:`AutomationRunner.prepare_automation`. The row is appended in the
caller's transaction (``Session``), so a rolled-back step leaves no audit of an effect that did not happen.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from sqlalchemy.orm import Session

from ovlm.audit import allowlist, service
from ovlm.automation.lint import Finding, Waiver

ENTITY = "automation_lint_waiver"
allowlist.register_entity(
    ENTITY, ["waiver_id", "rule", "path", "line", "approver", "reason", "profile_ref"]
)


def waiver_audit_hook(
    session: Session,
    *,
    run_id: UUID | None = None,
    step_id: UUID | None = None,
    project_scope: str | None = None,
    profile_ref: str | None = None,
) -> Callable[[Finding, Waiver], None]:
    def hook(finding: Finding, waiver: Waiver) -> None:
        service.record(
            session,
            action="automation.lint_waiver.applied",
            target_type=ENTITY,
            target_id=waiver.id,
            principal_type="worker",
            auth_method="system",
            project_scope=project_scope,
            run_id=run_id,
            step_id=step_id,
            after={
                "waiver_id": waiver.id,
                "rule": finding.rule,
                "path": finding.path,
                "line": finding.line,
                "approver": waiver.approver,
                "reason": waiver.reason,
                "profile_ref": profile_ref,
            },
        )

    return hook
