"""Domain errors of the registry. The api maps them to RFC 9457 problem+json (api-design.md section 1)."""

from __future__ import annotations


class DomainError(Exception):
    """``status`` is the HTTP status, ``code`` the stable slug, ``next_action`` says what to do (NFR-10)."""

    def __init__(
        self, status: int, code: str, title: str, detail: str, next_action: str | None = None
    ) -> None:
        super().__init__(detail)
        self.status, self.code, self.title = status, code, title
        self.detail, self.next_action = detail, next_action


def not_found(code: str, what: str) -> DomainError:
    return DomainError(404, code, f"{what} not found", f"No such {what.lower()}.")


def conflict(code: str, title: str, detail: str, next_action: str | None = None) -> DomainError:
    return DomainError(409, code, title, detail, next_action)
