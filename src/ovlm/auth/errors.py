"""RFC 9457 problem+json errors (api-design.md section 1) for the auth endpoints and dependencies."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

PROBLEM_BASE = "https://ovlm.dev/problems/"  # placeholder domain, as in api-design.md


class ProblemError(HTTPException):
    """An HTTP error with a stable ``code`` slug. Never carries secrets or stack traces."""

    def __init__(
        self,
        status_code: int,
        code: str,
        title: str,
        detail: str | None = None,
        *,
        next_action: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail or title, headers=headers)
        self.code = code
        self.title = title
        self.next_action = next_action

    def body(self, instance: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "type": f"{PROBLEM_BASE}{self.code}",
            "title": self.title,
            "status": self.status_code,
            "code": self.code,
            "detail": self.detail,
        }
        if instance:
            body["instance"] = instance
        if self.next_action:
            body["next_action"] = self.next_action
        return body


def unauthenticated(detail: str = "Authentication is required.") -> ProblemError:
    return ProblemError(
        401,
        "unauthenticated",
        "Not authenticated",
        detail,
        next_action="Log in, or send a valid API token as 'Authorization: Bearer ovlm_<id>_<secret>'.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def forbidden(code: str = "forbidden", detail: str = "You may not do this.") -> ProblemError:
    return ProblemError(403, code, "Forbidden", detail)


def problem_response(exc: ProblemError, request: Request) -> JSONResponse:
    return JSONResponse(
        exc.body(request.url.path),
        status_code=exc.status_code,
        headers={**(exc.headers or {}), "Content-Type": "application/problem+json"},
        media_type="application/problem+json",
    )


async def problem_exception_handler(request: Request, exc: Exception) -> Response:
    """App-wide handler (register with ``app.add_exception_handler(ProblemError, ...)``)."""
    if not isinstance(exc, ProblemError):
        raise exc
    return problem_response(exc, request)


class ProblemRoute(APIRoute):
    """Route class that renders :class:`ProblemError` (also when raised by a dependency) as problem+json."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except ProblemError as exc:
                return problem_response(exc, request)

        return handler
