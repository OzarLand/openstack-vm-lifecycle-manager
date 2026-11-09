"""Consuming a step-up (security-model.md 2.3; api-design.md ``/session/reauth``).

A step-up is issued by :func:`ovlm.auth.login.reauth` for exactly one action and one target, bound to the issuing
session, valid 5 minutes, usable once. The consuming endpoint (approval decision, typed confirmation, ...) calls
:func:`consume_stepup` in the **same transaction** as the change it authorises, so a rolled-back change leaves the
step-up unspent and a committed one spends it.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.auth.errors import ProblemError
from ovlm.auth.events import record_independent
from ovlm.auth.principal import Principal


def consume_stepup(
    db: Session, principal: Principal, stepup_id: UUID, *, action: str, target_id: str,
    signal_id: str | None = None,
) -> UUID:  # fmt: skip
    """Spend the step-up or raise ``403 stepup-invalid``. Returns ``stepup_id`` for the caller to store.

    ``signal_id``: the ``run_signal`` the caller inserts in this transaction for a confirmed run action; it is
    recorded on the step-up (``consumed_by_signal``, write-once) and the worker accepts the signal only with a step-up
    bound to it (review PMR-8, REN-10).

    Unknown, expired, already used, issued to another user or session, or bound to another action or target: all
    the same answer, so nothing is revealed about step-ups the caller does not own.
    """
    row = None
    if principal.is_human and principal.session_hash:
        row = db.execute(
            text(
                """
                UPDATE stepup SET consumed_at = now(), consumed_by_signal = CAST(:sig AS uuid)
                WHERE id = :id AND user_id = :u AND session_id_hash = :s AND action = :a
                  AND target_id = :t AND consumed_at IS NULL AND expires_at > now()
                RETURNING id
                """
            ),
            {
                "id": stepup_id,
                "u": principal.user_id,
                "s": principal.session_hash,
                "a": action,
                "t": target_id,
                "sig": signal_id,
            },
        ).one_or_none()
    if row is None:
        record_independent(
            db,
            action="auth.stepup.refused",
            target_type="stepup",
            target_id=str(stepup_id),
            result="denied",
            actor_id=principal.user_id,
            principal_type="human" if principal.is_human else "token",
            auth_method=principal.auth_method,
            source_ip=principal.source_ip,
            after={"action": action, "target_id": target_id},
        )
        raise ProblemError(
            403,
            "stepup-invalid",
            "Step-up authentication required",
            "A valid step-up for this action and target is required (it is single-use and lasts 5 minutes).",
            next_action="POST /api/v1/session/reauth with your password and TOTP code for this action and target.",
        )
    return stepup_id
