"""Lint waivers for one profile version (automation-contract.md 9, data-model.md ``lint_waiver``, SEC-R-36; SF-13).

An approver grants an exception to one blocking lint rule, on the repository paths a glob matches, for **one** profile
version, with a reason. The rules:

* **Who** (security-model.md 3.1 ``lint_waiver.grant``): an ``approver`` in the profile's project scope, in an
  interactive human session (password + TOTP), never an API token.
* **Separation of duties**: never the version's author, and never a requester of a plan on that version (plan creator,
  approval requester, run starter), whatever ``allow_operator_approver`` says: a waiver is the second pair of eyes on
  automation the author wrote. Holding ``operator`` and ``approver`` in the scope is refused unless the installation
  allows it (the same rule as approvals; the audit row then says ``operator_and_approver``).
* **Step-up**: a TOTP step-up bound to ``lint_waiver.grant`` and the version id, consumed in the same transaction as
  the insert; a step-up reached with a password alone is refused.
* **Revocation**: an approver in scope, with a TOTP step-up bound to ``lint_waiver.revoke`` and the waiver id, and a
  reason. Revoking only tightens, so no SoD condition applies. A revoked waiver stays in the table (append-only).

Effect: the worker's B6 lint (``prepare_automation``) applies the **active** waivers of the run's profile version and
audits every finding a waiver covers (``automation.lint_waiver.applied``); the plan hash binds the active waivers
(:func:`hash_binding`), so a waiver granted or revoked after an approval voids that approval.

Used by the api; the worker reads :func:`active_waivers`. Imports nothing from ``automation`` (import-linter): the rule
names are repeated here, and a unit test checks them against the lint.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth import installation
from ovlm.auth.authz import Action, authorize, authorize_action, scope_covers
from ovlm.auth.errors import ProblemError
from ovlm.auth.events import record_independent
from ovlm.auth.principal import Principal
from ovlm.auth.sod import INTERACTIVE_AUTH, WaiverRecord, check_waivers
from ovlm.auth.stepup import consume_stepup
from ovlm.profiles.errors import ProfileError

GRANT_STEPUP_ACTION = "lint_waiver.grant"
REVOKE_STEPUP_ACTION = "lint_waiver.revoke"
#: Blocking lint rules a waiver may cover (also a CHECK constraint). Never waivable: ``formatting`` (mkfs/wipefs on a
#: data volume), ``quiesce_state``, ``ssh_override``, ``hosts_pattern`` and ``parse_error``.
WAIVABLE_RULES = ("no_log_secret", "check_mode_forced", "delegate_to", "ignore_errors")
#: Repository-relative fnmatch glob: no absolute path, no ``..`` component (also a CHECK constraint).
PATH_GLOB = re.compile(r"^[A-Za-z0-9_.*?/\[\]-]{1,200}$")
_DOTDOT = re.compile(r"(^|/)\.\.(/|$)")
#: At least one **literal path segment** (review SFR-2): a segment with no ``*``, ``?`` or bracket expression and at
#: least one letter, digit, ``_`` or ``-``. ``fnmatch``'s ``*`` matches ``/``, so ``*``, ``**``, ``*/*``, ``**/*``,
#: ``*/**``, ``[a-z]*`` or ``*.yml`` would waive the rule for the whole repository. Same regex in the ``CHECK`` of
#: ``profiles_0002`` (PostgreSQL ARE and Python agree on it; a unit test ties the two).
LITERAL_SEGMENT = re.compile(r"(^|/)[A-Za-z0-9_.-]*[A-Za-z0-9_-][A-Za-z0-9_.-]*(/|$)")
#: B6 refuses (``needs_human``) a waiver that covered more findings than this in one run (review SFR-2).
MAX_WAIVED_FINDINGS = 20


def glob_is_specific(path_glob: str) -> bool:
    """The glob keeps at least one literal path segment (not a catch-all)."""
    return LITERAL_SEGMENT.search(path_glob) is not None


audit.register_entity(
    "lint_waiver",
    ["profile_id", "profile_version_id", "profile_version", "rule", "path_glob", "reason", "stepup_id",
     "operator_and_approver", "revoke_reason", "revoked_at", "refusal"],
)  # fmt: skip

_COLS = (
    "w.id, w.profile_version_id, w.rule, w.path_glob, w.reason, w.granted_by, w.granted_at, w.stepup_id, "
    "w.revoked_by, w.revoked_at, w.revoke_reason, pv.profile_id, pv.number, g.username AS granted_by_name, "
    "r.username AS revoked_by_name"
)
_FROM = (
    "FROM lint_waiver w JOIN profile_version pv ON pv.id = w.profile_version_id "
    "LEFT JOIN app_user g ON g.id = w.granted_by LEFT JOIN app_user r ON r.id = w.revoked_by"
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def waiver_dict(r: Any) -> dict[str, Any]:
    return {
        "id": str(r.id), "profile_id": str(r.profile_id), "profile_version_id": str(r.profile_version_id),
        "profile_version": r.number, "rule": r.rule, "path_glob": r.path_glob, "reason": r.reason,
        "granted_by": str(r.granted_by), "granted_by_name": r.granted_by_name, "granted_at": _iso(r.granted_at),
        "stepup_id": str(r.stepup_id), "state": "revoked" if r.revoked_at else "active",
        "revoked_by": str(r.revoked_by) if r.revoked_by else None, "revoked_by_name": r.revoked_by_name,
        "revoked_at": _iso(r.revoked_at), "revoke_reason": r.revoke_reason,
    }  # fmt: skip


def _not_found() -> ProfileError:
    return ProfileError(
        404, "profile-version-not-found", "Profile version not found", "No such version."
    )


def version_of(db: Session, profile_id: UUID, number: int) -> Any:
    """The version with its author and project (``None`` if missing)."""
    return db.execute(
        text("SELECT pv.id, pv.profile_id, pv.number, pv.created_by, s.project_connection_id "
             "FROM profile_version pv JOIN profile p ON p.id = pv.profile_id JOIN service s ON s.id = p.service_id "
             "WHERE pv.profile_id = :p AND pv.number = :n"), {"p": profile_id, "n": number},
    ).first()  # fmt: skip


def scope_of(row: Any) -> str:
    return f"project:{row.project_connection_id}"


def plan_requesters(db: Session | Connection, profile_version_id: UUID) -> frozenset[UUID]:
    """Everyone who asked for, or started, something on this version: plan creators, approval requesters, run
    starters (security-model.md 3.2 requester set, over every plan of the version)."""
    rows = db.execute(
        text("SELECT p.created_by AS u FROM renewal_plan p WHERE p.profile_version_id = :v "
             "UNION SELECT a.requested_by FROM approval a JOIN renewal_plan p ON p.id = a.plan_id "
             "WHERE p.profile_version_id = :v "
             "UNION SELECT r.started_by FROM workflow_run r JOIN renewal_plan p ON p.id = r.renewal_plan_id "
             "WHERE p.profile_version_id = :v"), {"v": profile_version_id},
    ).scalars()  # fmt: skip
    return frozenset(u for u in rows if u is not None)


def _refuse(
    db: Session, who: Principal, target: str, code: str, detail: str, scope: str
) -> ProblemError:
    record_independent(
        db, action="lint_waiver.grant.refused", target_type="lint_waiver", target_id=target, result="denied",
        actor_id=who.user_id, principal_type=who.principal_type, auth_method=who.auth_method,
        source_ip=who.source_ip, project_scope=scope, after={"profile_version_id": target, "refusal": code},
    )  # fmt: skip
    if code == "human-session-required":
        return ProblemError(403, code, "Forbidden", detail)
    if code == "totp-required":
        return ProblemError(403, code, "TOTP step-up required", detail,
                            next_action="Enrol TOTP, then step up again with your password and a TOTP code.")  # fmt: skip
    return ProblemError(403, code, "Separation of duties", detail,
                        next_action="Ask another person holding the approver role in this scope.")  # fmt: skip


def _holds_operator(who: Principal, scope: str) -> bool:
    return any(r == "operator" and scope_covers(s, scope) for r, s in who.grants)


def _check_input(rule: str, path_glob: str, reason: str) -> None:
    errors = []
    if rule not in WAIVABLE_RULES:
        errors.append(
            f"rule: one of {', '.join(WAIVABLE_RULES)} (the data-safety rules cannot be waived)"
        )
    if not PATH_GLOB.match(path_glob) or path_glob.startswith("/") or _DOTDOT.search(path_glob):
        errors.append(
            "path_glob: a repository-relative glob (letters, digits, _ . * ? / [ ] -), no '..'"
        )
    elif not glob_is_specific(path_glob):
        errors.append(
            "path_glob: keep at least one literal path segment (e.g. roles/probe/*, */tasks/main.yml); "
            "a catch-all such as * or **/* would waive the rule for the whole repository"
        )
    if not 10 <= len(reason.strip()) <= 1000:
        errors.append("reason: 10 to 1000 characters")
    if errors:
        raise ProfileError(422, "invalid-lint-waiver", "Invalid lint waiver", "; ".join(errors))


_TOTP_DETAIL = "A lint waiver needs a step-up confirmed with a TOTP code, not a password alone."


def _stepup_with_totp(
    db: Session,
    who: Principal,
    stepup_id: UUID,
    *,
    action: str,
    target: str,
    scope: str | None = None,
) -> None:
    """Consume the step-up; refuse one reached with a password alone. With ``scope`` (grant), the refusal is audited
    as ``lint_waiver.grant.refused`` (review SFR-6); the transaction then rolls back, so the step-up is not burnt."""
    consume_stepup(db, who, stepup_id, action=action, target_id=target)
    method = db.execute(
        text("SELECT auth_method FROM stepup WHERE id = :i"), {"i": stepup_id}
    ).scalar()
    if method != INTERACTIVE_AUTH:
        if scope is not None:
            raise _refuse(db, who, target, "totp-required", _TOTP_DETAIL, scope)
        raise ProblemError(403, "totp-required", "TOTP step-up required", _TOTP_DETAIL,
                           next_action="Enrol TOTP, then step up again with your password and a TOTP code.")  # fmt: skip


def grant(
    db: Session, who: Principal, profile_id: UUID, number: int, *, rule: str, path_glob: str, reason: str,
    stepup_id: UUID,
) -> tuple[dict[str, Any], str, bool]:  # fmt: skip
    """Grant a waiver; returns ``(waiver, scope, operator_and_approver)``. The caller audits and commits."""
    pv = version_of(db, profile_id, number)
    if pv is None or not authorize(who, "viewer", scope_of(pv)):
        raise _not_found()
    scope = scope_of(pv)
    target = str(pv.id)
    if (
        not who.is_human
    ):  # an API token, whatever its roles (review SFR-6: audited like the other refusals)
        raise _refuse(db, who, target, "human-session-required",
                      "A lint waiver needs an interactive human session with password and TOTP, never an API "
                      "token.", scope)  # fmt: skip
    if not authorize_action(who, Action.LINT_WAIVER_GRANT, scope):
        raise ProblemError(
            403, "forbidden", "Forbidden", "The approver role in this scope is required."
        )
    _check_input(rule, path_glob, reason)
    if not (who.is_human and who.auth_method == INTERACTIVE_AUTH):
        raise _refuse(db, who, target, "human-session-required",
                      "A lint waiver needs an interactive human session with password and TOTP.", scope)  # fmt: skip
    if who.user_id == pv.created_by:
        raise _refuse(db, who, target, "sod-violation",
                      "You authored this profile version: someone else must waive its lint findings.", scope)  # fmt: skip
    if who.user_id in plan_requesters(db, pv.id):
        raise _refuse(db, who, target, "sod-violation",
                      "You requested or started a renewal plan on this profile version.", scope)  # fmt: skip
    both = _holds_operator(who, scope)
    if both and not installation.allow_operator_approver(db):
        raise _refuse(db, who, target, "sod-violation",
                      "You hold operator and approver in this scope (operator_and_approver).", scope)  # fmt: skip
    _stepup_with_totp(db, who, stepup_id, action=GRANT_STEPUP_ACTION, target=target, scope=scope)
    wid = uuid4()
    db.execute(
        text("INSERT INTO lint_waiver (id, profile_version_id, rule, path_glob, reason, granted_by, stepup_id) "
             "VALUES (:i, :v, :r, :g, :why, :u, :s)"),
        {"i": wid, "v": pv.id, "r": rule, "g": path_glob, "why": reason.strip(), "u": who.user_id, "s": stepup_id},
    )  # fmt: skip
    return get(db, wid), scope, both


def get(db: Session, waiver_id: UUID) -> dict[str, Any]:
    row = db.execute(text(f"SELECT {_COLS} {_FROM} WHERE w.id = :i"), {"i": waiver_id}).one()  # noqa: S608
    return waiver_dict(row)


def list_for_version(
    db: Session, who: Principal, profile_id: UUID, number: int, *, include_revoked: bool
) -> list[dict[str, Any]]:
    pv = version_of(db, profile_id, number)
    if pv is None or not authorize(who, "viewer", scope_of(pv)):
        raise _not_found()
    rows = db.execute(
        text(f"SELECT {_COLS} {_FROM} WHERE w.profile_version_id = :v "  # noqa: S608
             f"{'' if include_revoked else 'AND w.revoked_at IS NULL '}ORDER BY w.granted_at, w.id"),
        {"v": pv.id},
    )  # fmt: skip
    return [waiver_dict(r) for r in rows]


def revoke(
    db: Session, who: Principal, waiver_id: UUID, *, reason: str, stepup_id: UUID
) -> tuple[dict[str, Any], str]:
    """Revoke an active waiver; returns ``(waiver, scope)``. The caller audits and commits."""
    row = db.execute(
        text("SELECT w.id, w.revoked_at, s.project_connection_id FROM lint_waiver w "
             "JOIN profile_version pv ON pv.id = w.profile_version_id JOIN profile p ON p.id = pv.profile_id "
             "JOIN service s ON s.id = p.service_id WHERE w.id = :i FOR UPDATE OF w"), {"i": waiver_id},
    ).first()  # fmt: skip
    if row is None or not authorize(who, "viewer", scope_of(row)):
        raise ProfileError(
            404, "lint-waiver-not-found", "Lint waiver not found", "No such lint waiver."
        )
    scope = scope_of(row)
    if not authorize_action(who, Action.LINT_WAIVER_GRANT, scope):
        raise ProblemError(
            403, "forbidden", "Forbidden", "The approver role in this scope is required."
        )
    if not 10 <= len(reason.strip()) <= 1000:
        raise ProfileError(
            422, "invalid-lint-waiver", "Invalid revocation", "reason: 10 to 1000 characters"
        )
    if row.revoked_at is not None:
        raise ProfileError(
            409, "lint-waiver-revoked", "Already revoked", "This lint waiver is already revoked."
        )
    _stepup_with_totp(db, who, stepup_id, action=REVOKE_STEPUP_ACTION, target=str(waiver_id))
    db.execute(
        text("UPDATE lint_waiver SET revoked_by = :u, revoked_at = now(), revoke_stepup_id = :s, "
             "revoke_reason = :r WHERE id = :i AND revoked_at IS NULL"),
        {"u": who.user_id, "s": stepup_id, "r": reason.strip(), "i": waiver_id},
    )  # fmt: skip
    return get(db, waiver_id), scope


# --- worker side and plan hash --------------------------------------------------------------------------------------


def active_waivers(
    db: Session | Connection, profile_version_id: UUID | str
) -> list[dict[str, Any]]:
    """The active waivers of a version, in a stable order: what B6's lint applies and what the plan hash binds."""
    rows = db.execute(
        text(f"SELECT {_COLS} {_FROM} WHERE w.profile_version_id = :v AND w.revoked_at IS NULL "  # noqa: S608
             "ORDER BY w.granted_at, w.id"), {"v": str(profile_version_id)},
    )  # fmt: skip
    return [waiver_dict(r) for r in rows]


def waiver_records(
    db: Session | Connection, profile_version_id: UUID | str
) -> tuple[WaiverRecord, ...]:
    """The active waivers of a version as raw facts, for the worker's provenance checks (review SFR-1)."""
    rows = db.execute(
        text("SELECT id, profile_version_id, granted_by, granted_at, stepup_id FROM lint_waiver "
             "WHERE profile_version_id = :v AND revoked_at IS NULL ORDER BY granted_at, id"),
        {"v": str(profile_version_id)},
    )  # fmt: skip
    return tuple(
        WaiverRecord(id=r.id, profile_version_id=r.profile_version_id, granted_by=r.granted_by,
                     granted_at=r.granted_at, stepup_id=r.stepup_id)
        for r in rows
    )  # fmt: skip


def version_author(db: Session | Connection, profile_version_id: UUID | str) -> UUID | None:
    author: UUID | None = db.execute(
        text("SELECT created_by FROM profile_version WHERE id = :v"), {"v": str(profile_version_id)}
    ).scalar()
    return author


def verify_active_waivers(
    conn: Connection, profile_version_id: UUID | str, scope: str
) -> list[dict[str, Any]]:
    """The active waivers of a version whose provenance fails (empty: all hold). The worker calls it before B6
    applies them (review SFR-1); :func:`ovlm.auth.sod.revalidate_approval_evidence` runs the same checks."""
    records = waiver_records(conn, profile_version_id)
    if not records:
        return []
    with Session(bind=conn) as session:
        return check_waivers(
            session, records, scope=scope, author=version_author(conn, profile_version_id),
            requesters=plan_requesters(conn, UUID(str(profile_version_id))),
        )  # fmt: skip


def hash_binding(waivers: list[dict[str, Any]]) -> list[dict[str, str]]:
    """What the plan hash binds of each active waiver (id, rule, glob, approver): granting or revoking one changes
    the hash, so approvals bound to the old one are void."""
    return [
        {
            "id": w["id"],
            "rule": w["rule"],
            "path_glob": w["path_glob"],
            "granted_by": w["granted_by"],
        }
        for w in waivers
    ]
