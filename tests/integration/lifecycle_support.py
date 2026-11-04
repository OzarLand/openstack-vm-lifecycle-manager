"""Helpers shared by the profile and policy integration tests: extra users, step-up, audit rows."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from tests.integration.auth_support import PASSWORD
from tests.integration.test_registry_api import Env, Session


def add_user(env: Env, name: str, *roles: str) -> tuple[Session, str | None]:
    """A logged-in user with global ``roles`` (approver and admin enrol TOTP); returns the session and TOTP secret."""
    client, secret = env.auth.user_client(name, [(r, "global") for r in roles])
    return Session(client, UUID(client.get("/api/v1/session").json()["user_id"])), secret


def stepup(env: Env, who: Session, secret: str | None, action: str, target: str) -> str:
    env.auth.clock.advance()
    body: dict[str, Any] = {"password": PASSWORD, "action": action, "target_id": target}
    if secret:
        body["totp_code"] = env.auth.code(secret)
    r = who.client.post("/api/v1/session/reauth", json=body, headers=env.auth.headers(who.client))
    assert r.status_code == 200, r.text
    return str(r.json()["stepup_id"])


def audit_rows(env: Env, action: str) -> list[Any]:
    return env.auth.sql(
        "SELECT action, actor_id, project_scope, target_type, before, after FROM audit_event "
        "WHERE action = :a ORDER BY id",
        a=action,
    )
