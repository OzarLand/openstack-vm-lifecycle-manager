"""Errors of the profiles module. The api maps them to RFC 9457 problem+json (api-design.md section 1)."""

from __future__ import annotations

from typing import Any


class ProfileError(Exception):
    """``status`` is the HTTP status, ``code`` the stable slug, ``errors`` the per-field list of a 422."""

    def __init__(
        self,
        status: int,
        code: str,
        title: str,
        detail: str,
        next_action: str | None = None,
        errors: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status, self.code, self.title, self.detail = status, code, title, detail
        self.next_action, self.errors = next_action, errors
