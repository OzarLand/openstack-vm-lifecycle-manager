"""CSRF defence for cookie sessions (security-model.md 2.3, T14): synchronizer token plus Origin check.

* Authenticated unsafe requests: ``X-CSRF-Token`` header (HTMX ``hx-headers``) or ``csrf_token`` form field must
  equal the session's token, **and** ``Origin`` (or ``Referer``) must match the external URL.
* Pre-session forms (login, enrolment): Origin check plus a double-submit cookie (there is no session yet).
* Bearer-token requests carry no cookie and are exempt.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from urllib.parse import urlsplit

from fastapi import Request, Response

from ovlm.config import Settings

log = logging.getLogger("ovlm.auth")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SESSION_COOKIE = "__Host-ovlm_session"
FORM_COOKIE = "__Host-ovlm_form"
HEADER = "x-csrf-token"
FIELD = "csrf_token"
_warned_fallback = False


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


def origin_allowed(request: Request, settings: Settings) -> bool:
    """``Origin`` (else ``Referer``) must be present and equal the configured external origin.

    Without ``external_url`` (development) only the host part is compared with the ``Host`` header, because the TLS
    proxy hides the scheme; a cross-site page cannot make its own origin equal our host.
    """
    global _warned_fallback  # noqa: PLW0603
    supplied = request.headers.get("origin")
    if supplied is None or supplied == "null":
        referer = request.headers.get("referer")
        supplied = _origin_of(referer) if referer else None
    else:
        supplied = _origin_of(supplied)
    if supplied is None:
        return False
    if settings.external_url:
        expected = _origin_of(settings.external_url)
        return expected is not None and supplied == expected
    if not _warned_fallback:
        _warned_fallback = True
        log.warning(
            "external_url is not set: CSRF Origin check compares against the Host header only"
        )
    return urlsplit(supplied).netloc == (request.headers.get("host") or "").lower()


def tokens_equal(supplied: str | None, expected: str | None) -> bool:
    if not supplied or not expected:
        return False
    return hmac.compare_digest(supplied.encode(), expected.encode())


async def supplied_csrf_token(request: Request) -> str | None:
    """Token from the header, else from a urlencoded/multipart form field."""
    header = request.headers.get(HEADER)
    if header:
        return header
    ctype = request.headers.get("content-type", "")
    if ctype.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
        form = await request.form()
        value = form.get(FIELD)
        return value if isinstance(value, str) else None
    return None


def new_form_token() -> str:
    return secrets.token_urlsafe(24)


def set_form_cookie(response: Response, token: str) -> None:
    """Double-submit cookie of a pre-session form; the same value is embedded in the form."""
    response.set_cookie(
        FORM_COOKIE, token, httponly=True, secure=True, samesite="strict", path="/", max_age=3600
    )


async def check_form_token(request: Request, settings: Settings) -> bool:
    """Pre-session POST: Origin plus the double-submit cookie."""
    if not origin_allowed(request, settings):
        return False
    return tokens_equal(await supplied_csrf_token(request), request.cookies.get(FORM_COOKIE))
