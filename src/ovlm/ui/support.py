"""Shared UI plumbing: templates and filters, the HTML error route class, rendering with the layout context.

Pages call the same service layer as the REST API (``ovlm.inventory.service``, ``ovlm.registry.service``) and the
same authorization dependencies (``ovlm.auth.deps.require_role``). There is no private API behind the UI.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from fastapi import Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.templating import Jinja2Templates

from ovlm import __version__
from ovlm.auth.errors import ProblemError
from ovlm.auth.principal import Principal
from ovlm.registry.errors import DomainError
from ovlm.ui import TEMPLATE_DIR

NAV: tuple[tuple[str, str, str], ...] = (
    ("dashboard", "/", "Dashboard"),
    ("inventory", "/inventory", "Inventory"),
    ("services", "/services", "Services"),
    ("renewals", "/renewals", "Renewals"),
    ("audit", "/audit", "Audit"),
)


# --- filters ----------------------------------------------------------------------------------------------------


def parse_ts(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def age(value: Any, now: datetime | None = None) -> str:
    """``3d 4h``, ``5h 12m``, ``7m``: the elapsed time since ``value`` (an ISO string or datetime)."""
    ts = parse_ts(value)
    if ts is None:
        return "unknown"
    seconds = int(((now or datetime.now(UTC)) - ts).total_seconds())
    if seconds < 0:
        return "0m"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def timestamp(value: Any) -> str:
    ts = parse_ts(value)
    return ts.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if ts else "unknown"


def short_id(value: Any, n: int = 8) -> str:
    return str(value)[:n] if value else ""


templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
templates.env.filters["age"] = age
templates.env.filters["timestamp"] = timestamp
templates.env.filters["short_id"] = short_id


def describe_roles(who: Principal) -> list[tuple[str, str]]:
    """``[(role, scope)]`` for the header: the effective grants, e.g. ``("approver", "global")`` or
    ``("operator", "project 1a2b3c4d")``."""
    return [
        (r, "global" if s == "global" else f"project {s.removeprefix('project:')[:8]}")
        for r, s in sorted(who.grants)
    ]


# --- rendering ------------------------------------------------------------------------------------------------------


def render(
    request: Request, name: str, status: int = 200, *, active: str = "", **ctx: Any
) -> HTMLResponse:
    who: Principal | None = getattr(request.state, "principal", None)
    context = {
        "version": __version__,
        "who": who,
        "roles": describe_roles(who) if who else [],
        "nav": NAV,
        "active": active,
        **ctx,
    }
    return templates.TemplateResponse(request, name, context, status_code=status)


def error_page(
    request: Request,
    status: int,
    title: str,
    detail: str,
    next_action: str | None = None,
    code: str = "",
) -> HTMLResponse:
    return render(
        request,
        "error.html",
        status,
        title=title,
        detail=detail,
        next_action=next_action,
        code=code,
    )


class UiRoute(APIRoute):
    """Renders the auth module's ``ProblemError`` and the registry's ``DomainError`` as HTML pages.

    A missing or expired session sends the browser to the login page (HTMX gets ``HX-Redirect``, because it would
    otherwise swap the login page into a fragment). A privileged role without TOTP goes to the enrolment page.
    """

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except ProblemError as exc:
                if exc.status_code == 401:
                    return _redirect(request, "/login")
                pending = getattr(request.state, "principal", None)
                if (
                    exc.code == "totp-enrolment-required"
                    or (
                        exc.status_code == 403
                        and pending is not None
                        and pending.totp_enrolment_required
                    )
                ):  # a privileged user who has not enrolled TOTP holds no grants yet: send them to enrol
                    return _redirect(request, "/account/totp")
                return error_page(
                    request, exc.status_code, exc.title, str(exc.detail), exc.next_action, exc.code
                )
            except DomainError as exc:
                return error_page(
                    request, exc.status, exc.title, exc.detail, exc.next_action, exc.code
                )

        return handler


def _redirect(request: Request, location: str) -> Response:
    if request.headers.get("hx-request") == "true":
        return Response(status_code=200, headers={"HX-Redirect": location})
    return RedirectResponse(location, status_code=303)
