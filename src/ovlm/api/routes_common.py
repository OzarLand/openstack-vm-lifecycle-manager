"""Shared pieces of the profile and policy routes: RFC 9457 problem+json (with ``errors[]``), audit, ETag, paging."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.errors import ProblemError, problem_response
from ovlm.auth.principal import Principal
from ovlm.inventory.service import InvalidCursorError, Page
from ovlm.profiles.errors import ProfileError
from ovlm.registry.errors import DomainError

IfMatch = Annotated[str | None, Header()]


def _problem(request: Request, status: int, code: str, title: str, detail: str,
             next_action: str | None = None, errors: list[dict[str, Any]] | None = None) -> JSONResponse:  # fmt: skip
    body: dict[str, Any] = {
        "type": f"https://ovlm.dev/problems/{code}",  # placeholder domain (api-design.md)
        "title": title, "status": status, "detail": detail, "instance": request.url.path, "code": code,
    }  # fmt: skip
    if next_action:
        body["next_action"] = next_action
    if errors:
        body["errors"] = errors
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


def _field_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Field path and message only: never the submitted value (it may be a secret reference or a typo of one)."""
    out = []
    for e in exc.errors():
        loc = [str(p) for p in e["loc"] if p != "body"]
        out.append({"field": ".".join(loc), "message": str(e["msg"]).removeprefix("Value error, ")})
    return out


class ProblemRoute(APIRoute):
    """Turns domain, auth and request-validation errors into ``application/problem+json``."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except ProblemError as exc:  # the auth dependencies (401, 403)
                return problem_response(exc, request)
            except (DomainError, ProfileError) as exc:
                return _problem(request, exc.status, exc.code, exc.title, exc.detail, exc.next_action,
                                getattr(exc, "errors", None))  # fmt: skip
            except InvalidCursorError:
                return _problem(request, 400, "invalid-cursor", "Invalid cursor", "The cursor is malformed.",
                                "Restart from the first page.")  # fmt: skip
            except RequestValidationError as exc:
                return _problem(request, 422, "validation-error", "Invalid request",
                                "The request does not match the schema.", "Fix the listed fields.",
                                _field_errors(exc))  # fmt: skip

        return handler


def audit_change(
    session: Session, who: Principal, action: str, target_type: str, target_id: str, *,
    scope: str | None, before: dict[str, Any] | None = None, after: dict[str, Any] | None = None,
) -> None:  # fmt: skip
    """Append the audit row in the request's transaction (the caller commits both together)."""
    audit.record(
        session, action=action, target_type=target_type, target_id=target_id, actor_id=who.user_id,
        principal_type=who.principal_type, auth_method=who.auth_method, source_ip=who.source_ip,
        project_scope=scope, before=before, after=after,
    )  # fmt: skip


def etag_of(version: int) -> str:
    return f'"{version}"'


def page_body(page: Page) -> dict[str, Any]:
    return {"items": page.items, "next_cursor": page.next_cursor}
