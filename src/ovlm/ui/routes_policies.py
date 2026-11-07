"""Policy pages (UI-2): list, detail (current version, bindings, effective windows) and the admin edit form.

The edit form calls ``policies.update_policy`` and writes the ``policy.update`` audit row exactly as
``PUT /api/v1/policies/{id}`` does. Rules of the form:

* **Pre-filled from the current version.** Every field is rendered from the stored row, and the POST must carry every
  field: a missing one is an error, never a default. (A full replace once reset ``require_distinct_approvers`` in the
  Felcloud lab because a script left it out.)
* **Optimistic locking.** The form carries the ETag it was rendered from (``if_match``); the service compares it with
  the row's ``version``. A stale form is refused with ``409`` and nothing is written.
* **Voided approvals.** A new version changes the plan hash, so approvals on open plans under the policy stop
  matching. The form shows how many plans and approvals that touches; when the count is above 0 the admin must type
  the policy name.
* Admin only, human session only (API tokens never reach it), CSRF checked by the auth dependency.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.deps import get_db, require_role
from ovlm.auth.principal import Principal
from ovlm.policies import service as policies
from ovlm.policies.models import PolicyIn
from ovlm.policies.windows import WEEKDAYS, next_window, rule_from_dict
from ovlm.registry import service as registry
from ovlm.registry.errors import DomainError
from ovlm.registry.tables import service, service_group
from ovlm.renewal import service as renewal
from ovlm.ui.support import UiRoute, render

router = APIRouter(route_class=UiRoute, include_in_schema=False)
Db = Annotated[Session, Depends(get_db)]
VIEWER = Depends(require_role("viewer"))
ADMIN = Depends(require_role("admin", human_only=True))

NEW_WINDOW_ROWS = 2  # blank rows offered for adding a window without JavaScript
NOTICES = {"updated": "Policy saved as a new version."}


def _uuid(value: str) -> UUID | None:
    try:
        return UUID(value)
    except ValueError:
        return None


def _load(db: Session, policy_id: str) -> dict[str, Any]:
    pid = _uuid(policy_id)
    found = policies.get_policy(db, pid) if pid else None
    if found is None:
        raise DomainError(404, "policy-not-found", "Policy not found", "No policy has this id.")
    return found


def _window_view(window: dict[str, Any]) -> dict[str, Any]:
    days = {str(d) for d in window["weekdays"]}
    return {"days": days, "start": window["start"], "end": window["end"], "tz": window["timezone"]}


def form_of(pol: dict[str, Any]) -> dict[str, Any]:
    """Every editable field of the stored version, as the form shows it."""
    return {
        "name": pol["name"], "max_age": pol["max_age"], "renewal_interval": pol["renewal_interval"],
        "approval_plan": pol["approvals"].get("plan", True),
        "approval_cutover": pol["approvals"].get("cutover", True),
        "require_distinct_approvers": pol["require_distinct_approvers"],
        "snapshot_retain_after_restore": pol["snapshot_retain_after_restore"],
        "auto_restore_in_window": pol["auto_restore_in_window"],
        "max_window_duration": pol["max_window_duration"],
        "retention_period": pol["retention_period"] or "",
        "windows": [_window_view(w) for w in pol["windows"]],
    }  # fmt: skip


def _flag(value: str | None, label: str, problems: list[str]) -> bool:
    if value not in ("true", "false"):
        problems.append(f"{label}: choose yes or no (the field was missing or invalid).")
        return False
    return value == "true"


def _need(value: str | None, label: str, problems: list[str]) -> str:
    if value is None or not value.strip():
        problems.append(f"{label} is required.")
        return ""
    return value.strip()


def _parse(  # noqa: PLR0913 - one parameter per form field
    *, name: str | None, max_age: str | None, renewal_interval: str | None, approval_plan: str | None,
    approval_cutover: str | None, distinct: str | None, snapshot: str | None, auto_restore: str | None,
    max_window: str | None, retention: str | None, days: list[str], starts: list[str], ends: list[str],
    zones: list[str], removed: list[str],
) -> tuple[dict[str, Any], PolicyIn | None, list[str]]:  # fmt: skip
    """Form values -> (what to show again, the validated body or ``None``, problems). Never fills a default."""
    problems: list[str] = []
    form: dict[str, Any] = {
        "name": _need(name, "Name", problems), "max_age": _need(max_age, "Maximum age", problems),
        "renewal_interval": _need(renewal_interval, "Renewal interval", problems),
        "approval_plan": _flag(approval_plan, "Plan approval", problems),
        "approval_cutover": _flag(approval_cutover, "Cutover approval", problems),
        "require_distinct_approvers": _flag(distinct, "Distinct approvers", problems),
        "snapshot_retain_after_restore": _need(snapshot, "Snapshot retention", problems),
        "auto_restore_in_window": _flag(auto_restore, "Auto restore in window", problems),
        "max_window_duration": _need(max_window, "Maximum window duration", problems),
        "retention_period": (retention or "").strip(),
    }  # fmt: skip
    chosen: dict[int, set[str]] = {}
    for token in days:
        idx, _, day = token.partition(":")
        if idx.isdigit() and day in WEEKDAYS:
            chosen.setdefault(int(idx), set()).add(day)
    drop = {int(i) for i in removed if i.isdigit()}
    windows: list[dict[str, Any]] = []
    raw: list[dict[str, Any]] = []
    for i, (start, end, zone) in enumerate(zip(starts, ends, zones, strict=False)):
        row = {
            "days": chosen.get(i, set()),
            "start": start.strip(),
            "end": end.strip(),
            "tz": zone.strip(),
        }
        if i in drop:
            continue
        if not row["days"] and not row["start"] and not row["end"]:
            continue  # a blank spare row
        raw.append(row)
        windows.append({
            "weekdays": sorted(row["days"], key=WEEKDAYS.index), "start": row["start"], "end": row["end"],
            "timezone": row["tz"] or "UTC",
        })  # fmt: skip
    form["windows"] = raw
    if not raw:
        problems.append("A policy needs at least one window.")
    if problems:
        return form, None, problems
    try:
        body = PolicyIn.model_validate({
            "name": form["name"], "max_age": form["max_age"], "renewal_interval": form["renewal_interval"],
            "windows": windows,
            "approvals": {"plan": form["approval_plan"], "cutover": form["approval_cutover"]},
            "require_distinct_approvers": form["require_distinct_approvers"],
            "snapshot_retain_after_restore": form["snapshot_retain_after_restore"],
            "auto_restore_in_window": form["auto_restore_in_window"],
            "max_window_duration": form["max_window_duration"],
            "retention_period": form["retention_period"] or None,
        })  # fmt: skip
    except ValidationError as exc:
        for err in exc.errors():
            where = ".".join(str(p) for p in err["loc"])
            msg = str(err["msg"]).removeprefix("Value error, ")
            problems.append(f"{where}: {msg}" if where else msg)
        return form, None, problems
    return form, body, problems


# --- list and detail -------------------------------------------------------------------------------------------


@router.get("/policies", response_class=HTMLResponse)
def policy_list(request: Request, db: Db, who: Principal = VIEWER) -> HTMLResponse:
    items: list[dict[str, Any]] = []
    cursor = None
    while True:
        page = policies.list_policies(db, limit=200, cursor=cursor)
        items += page.items
        if not page.next_cursor:
            break
        cursor = page.next_cursor
    counts: dict[str, int] = {}
    for b in policies.list_bindings(db, limit=200).items:
        counts[b["policy_id"]] = counts.get(b["policy_id"], 0) + 1
    return render(
        request, "policies/list.html", active="policies", policies=items, binding_counts=counts
    )


def _scope_names(db: Session, bindings: list[dict[str, Any]]) -> dict[str, str]:
    names: dict[str, str] = {}
    for b in bindings:
        table = service if b["scope_type"] == "service" else service_group
        row = db.execute(select(table.c.name).where(table.c.id == UUID(b["scope_id"]))).first()
        names[b["id"]] = row.name if row else "(deleted)"
    return names


def _all_bindings(db: Session, pid: UUID) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor = None
    while True:
        page = policies.list_bindings(db, policy_id=pid, limit=200, cursor=cursor)
        out += page.items
        if not page.next_cursor:
            return out
        cursor = page.next_cursor


def _effective_windows(pol: dict[str, Any], now: datetime) -> dict[str, Any]:
    """The windows as UTC clock ranges and when the next one opens (what the deadline logic really uses)."""
    rows = []
    for w in pol["windows"]:
        rows.append({**_window_view(w), "days_sorted": sorted(w["weekdays"], key=WEEKDAYS.index)})
    nxt = next_window(now, [rule_from_dict(w) for w in pol["windows"]])
    return {"rows": rows, "next": nxt}


@router.get("/policies/{policy_id}", response_class=HTMLResponse)
def policy_detail(
    request: Request, policy_id: str, db: Db, notice: str = "", who: Principal = VIEWER
) -> HTMLResponse:
    pol = _load(db, policy_id)
    pid = UUID(pol["id"])
    bindings = _all_bindings(db, pid)
    return render(
        request, "policies/detail.html", active="policies", p=pol, bindings=bindings,
        scope_names=_scope_names(db, bindings), eff=_effective_windows(pol, datetime.now(UTC)),
        notice=NOTICES.get(notice), can_edit="admin" in who.roles(),
    )  # fmt: skip


# --- edit ---------------------------------------------------------------------------------------------------------


def _edit_page(
    request: Request, db: Session, pol: dict[str, Any], form: dict[str, Any], *, status: int = 200,
    problems: list[str] | None = None, confirm_error: bool = False, if_match: str | None = None,
) -> HTMLResponse:  # fmt: skip
    return render(
        request, "policies/edit.html", status, active="policies", p=pol, form=form,
        problems=problems or [], impact=renewal.open_plans_for_policy(db, UUID(pol["id"])),
        if_match=if_match if if_match is not None else f'"{pol["version"]}"',
        confirm_error=confirm_error, weekdays=WEEKDAYS, spare=range(NEW_WINDOW_ROWS),
    )  # fmt: skip


@router.get("/policies/{policy_id}/edit", response_class=HTMLResponse)
def policy_edit_form(
    request: Request, policy_id: str, db: Db, who: Principal = ADMIN
) -> HTMLResponse:
    pol = _load(db, policy_id)
    return _edit_page(request, db, pol, form_of(pol))


@router.post("/policies/{policy_id}/edit", response_class=HTMLResponse)
def policy_edit_submit(  # noqa: PLR0913 - one parameter per form field
    request: Request, policy_id: str, db: Db,
    if_match: Annotated[str | None, Form()] = None,
    confirm_name: Annotated[str, Form()] = "",
    name: Annotated[str | None, Form()] = None,
    max_age: Annotated[str | None, Form()] = None,
    renewal_interval: Annotated[str | None, Form()] = None,
    approval_plan: Annotated[str | None, Form()] = None,
    approval_cutover: Annotated[str | None, Form()] = None,
    require_distinct_approvers: Annotated[str | None, Form()] = None,
    snapshot_retain_after_restore: Annotated[str | None, Form()] = None,
    auto_restore_in_window: Annotated[str | None, Form()] = None,
    max_window_duration: Annotated[str | None, Form()] = None,
    retention_period: Annotated[str | None, Form()] = None,
    win_days: Annotated[list[str] | None, Form()] = None,
    win_start: Annotated[list[str] | None, Form()] = None,
    win_end: Annotated[list[str] | None, Form()] = None,
    win_tz: Annotated[list[str] | None, Form()] = None,
    win_remove: Annotated[list[str] | None, Form()] = None,
    who: Principal = ADMIN,
) -> Response:  # fmt: skip
    pol = _load(db, policy_id)
    pid = UUID(pol["id"])
    form, body, problems = _parse(
        name=name, max_age=max_age, renewal_interval=renewal_interval, approval_plan=approval_plan,
        approval_cutover=approval_cutover, distinct=require_distinct_approvers, snapshot=snapshot_retain_after_restore,
        auto_restore=auto_restore_in_window, max_window=max_window_duration, retention=retention_period,
        days=win_days or [], starts=win_start or [], ends=win_end or [], zones=win_tz or [],
        removed=win_remove or [],
    )  # fmt: skip
    if body is None:
        return _edit_page(request, db, pol, form, status=422, problems=problems, if_match=if_match)
    try:
        expected = registry.parse_if_match(if_match)
        if expected != pol["version"]:
            raise DomainError(
                409, "etag-mismatch", "The policy changed", f"You edited version {expected}; the policy is now "
                f"version {pol['version']}. Nothing was saved.", "Reload the policy and apply your change again.",
            )  # fmt: skip
        impact = renewal.open_plans_for_policy(db, pid)
        if impact["plans"] > 0 and confirm_name.strip() != pol["name"]:
            return _edit_page(
                request, db, pol, form, status=422, if_match=if_match, confirm_error=True,
                problems=[f"Type the policy name \"{pol['name']}\" to confirm that {impact['plans']} open plan(s) "
                          "will lose their approvals."],
            )  # fmt: skip
        updated = policies.update_policy(db, pid, expected, body, actor_id=who.user_id)
    except DomainError as exc:
        db.rollback()
        status = 409 if exc.status == 412 else exc.status  # a stale form is a conflict on this page
        return _edit_page(
            request, db, pol, form, status=status, if_match=if_match,
            problems=[f"{exc.title}: {exc.detail}" + (f" {exc.next_action}" if exc.next_action else "")],
        )  # fmt: skip
    audit.record(
        db, action="policy.update", target_type="policy", target_id=str(pid), actor_id=who.user_id,
        principal_type=who.principal_type, auth_method=who.auth_method, source_ip=who.source_ip,
        project_scope="global", before=pol, after=updated,
    )  # fmt: skip
    db.commit()
    return RedirectResponse(f"/policies/{pid}?notice=updated", status_code=303)
