"""Shared fixtures and helpers for the auth and audit integration tests (real PostgreSQL, real app)."""

from __future__ import annotations

import io
import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

import pyotp
import pytest
from alembic import command
from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session

from ovlm.api.app import create_app
from ovlm.api.health import CheckResult
from ovlm.auth.deps import get_db, project_scope, require_role
from ovlm.auth.errors import ProblemRoute
from ovlm.auth.principal import Principal
from ovlm.auth.stepup import consume_stepup
from ovlm.db.engine import make_engine, make_session_factory
from ovlm.db.schema import alembic_config
from ovlm.observability.logging import configure_logging
from tests.integration.conftest import role_url, settings_for

ORIGIN = "https://ovlm.test"
PASSWORD = "correct horse battery 42"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class _Probe:
    def check(self) -> list[CheckResult]:
        return [CheckResult("database", True)]


class FakeClock:
    """Controls ``time.time`` inside the TOTP module so codes and replay protection are deterministic."""

    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float = 30) -> None:
        self.now += seconds


@dataclass
class Env:
    app: Any
    settings: Any
    admin_url: URL
    db: str
    owner: Engine
    clock: FakeClock
    log_stream: io.StringIO
    secrets_dir: Path
    secrets: dict[str, str] = field(
        default_factory=dict
    )  # name -> secret, to hunt for in logs/audit

    def client(self) -> TestClient:
        return TestClient(self.app, base_url=ORIGIN, raise_server_exceptions=True)

    def session(self) -> Session:
        return make_session_factory(make_engine(self.settings))()

    def sql(self, statement: str, **params: Any) -> list[Any]:
        """Run SQL as the table owner (test setup/inspection only)."""
        with self.owner.begin() as conn:
            res = conn.execute(text(statement), params)
            return list(res.all()) if res.returns_rows else []

    def role_engine(self, role: str, password: str) -> Engine:
        return create_engine(role_url(self.admin_url, self.db, role, password))

    # --- user lifecycle through the real flows ---------------------------------------------------------

    def create_user(
        self, username: str, roles: list[tuple[str, str]], *, by: UUID | None = None
    ) -> str:
        """Create a pending user with an enrolment link (service level, as the CLI/admin API do)."""
        from ovlm.auth import users

        with self.session() as db:
            uid = users.create_user(
                db,
                username=username,
                display_name=username,
                created_by=by,
                created_via="cli",
                bindings=roles,
            )
            _, raw = users.issue_link(
                db, self.settings, user_id=uid, purpose="enrol", created_by=by
            )
            db.commit()
        self.secrets[f"link:{username}"] = raw
        return raw

    def form_token(self, client: TestClient, path: str) -> str:
        r = client.get(path)
        m = CSRF_RE.search(r.text)
        assert m, f"no csrf field on {path}: {r.status_code} {r.text[:200]}"
        return str(m.group(1))

    def enrol(self, client: TestClient, link: str, password: str = PASSWORD) -> Any:
        token = self.form_token(client, f"/enrol/{link}")
        return client.post(
            f"/enrol/{link}",
            data={"password": password, "password_confirm": password, "csrf_token": token},
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    def code(self, secret: str) -> str:
        return str(pyotp.TOTP(secret).at(int(self.clock.now)))

    def enrol_totp(self, client: TestClient) -> str:
        """Enrol and confirm TOTP in the client's session; returns the secret."""
        me = client.get("/api/v1/session").json()
        h = {"Origin": ORIGIN, "X-CSRF-Token": me["csrf_token"]}
        r = client.post("/api/v1/session/totp/enrol", headers=h)
        assert r.status_code == 200, r.text
        secret = r.json()["secret"]
        self.secrets["totp_secret"] = secret
        r = client.post("/api/v1/session/totp/confirm", json={"code": self.code(secret)}, headers=h)
        assert r.status_code == 200, r.text
        return str(secret)

    def api_login(
        self,
        client: TestClient,
        username: str,
        password: str = PASSWORD,
        totp_secret: str | None = None,
    ) -> Any:
        body: dict[str, Any] = {"username": username, "password": password}
        if totp_secret:
            body["totp_code"] = self.code(totp_secret)
        return client.post("/api/v1/session", json=body, headers={"Origin": ORIGIN})

    def headers(self, client: TestClient, **extra: str) -> dict[str, str]:
        csrf = client.get("/api/v1/session").json()["csrf_token"]
        return {"Origin": ORIGIN, "X-CSRF-Token": csrf, **extra}

    def user_client(
        self, username: str, roles: list[tuple[str, str]], *, totp: bool | None = None
    ) -> tuple[TestClient, str | None]:
        """A logged-in client for a fresh user (enrolled through the link). ``totp`` defaults to
        True for approver/admin."""
        link = self.create_user(username, roles)
        c = self.client()
        r = self.enrol(c, link)
        assert r.status_code == 303, r.text
        secret = None
        if totp if totp is not None else any(role in ("approver", "admin") for role, _ in roles):
            secret = self.enrol_totp(c)
            self.clock.advance()
        return c, secret


def _sample_router() -> APIRouter:
    """Endpoints that exercise ``require_role`` and ``consume_stepup`` the way other modules will."""
    router = APIRouter(prefix="/_t", route_class=ProblemRoute)

    @router.get("/viewer")
    def viewer(who: Annotated[Principal, Depends(require_role("viewer"))]) -> dict[str, str]:
        return {"user": who.username}

    @router.post("/operator")
    def operator(who: Annotated[Principal, Depends(require_role("operator"))]) -> dict[str, str]:
        return {"user": who.username}

    @router.post("/sync")
    def sync(
        who: Annotated[Principal, Depends(require_role("operator", token_scope="inventory:sync"))],
    ) -> dict[str, str]:
        return {"user": who.username}

    @router.post("/approver")
    def approver(
        who: Annotated[Principal, Depends(require_role("approver", human_only=True))],
    ) -> dict[str, str]:
        return {"user": who.username}

    @router.post("/admin")
    def admin(who: Annotated[Principal, Depends(require_role("admin"))]) -> dict[str, str]:
        return {"user": who.username}

    @router.post("/project/{project_id}")
    def project(
        project_id: str,
        who: Annotated[Principal, Depends(require_role("operator", project_scope("project_id")))],
    ) -> dict[str, str]:
        return {"project": project_id}

    @router.post("/decide/{target}")
    def decide(
        target: str,
        stepup_id: UUID,
        db: Annotated[Session, Depends(get_db)],
        who: Annotated[Principal, Depends(require_role("approver", human_only=True))],
    ) -> dict[str, str]:
        consume_stepup(db, who, stepup_id, action="approval.decide", target_id=target)
        db.commit()
        return {"decided": target}

    @router.post("/decide-then-fail/{target}")
    def decide_then_fail(
        target: str,
        stepup_id: UUID,
        db: Annotated[Session, Depends(get_db)],
        who: Annotated[Principal, Depends(require_role("approver", human_only=True))],
    ) -> dict[str, str]:
        consume_stepup(db, who, stepup_id, action="approval.decide", target_id=target)
        raise RuntimeError(
            "the change failed after the step-up was consumed"
        )  # no commit: rolled back

    return router


@pytest.fixture
def env(
    admin_url: URL,
    fresh_db: str,
    secrets_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> Iterator[Env]:
    mig = settings_for("migrate", admin_url, fresh_db, secrets_dir)
    command.upgrade(alembic_config(mig.migrations_dir, mig.db_url()), "heads")
    key_file = tmp_path / "totp.key"
    key_file.write_text(Fernet.generate_key().decode() + "\n")
    overrides: dict[str, Any] = getattr(request, "param", None) or {}
    api = settings_for("api", admin_url, fresh_db, secrets_dir)
    settings = api.model_copy(
        update={
            "external_url": ORIGIN,
            "auth": api.auth.model_copy(update={"totp_key_file": key_file, **overrides}),
        }
    )
    clock = FakeClock()
    monkeypatch.setattr("ovlm.auth.totp.time.time", clock)
    stream = io.StringIO()
    configure_logging("api", "INFO", stream=stream)
    logging.getLogger("httpx").setLevel(
        logging.WARNING
    )  # the test client logs full URLs; the server must not
    app = create_app(settings, probe=_Probe(), start_metrics_server=False)
    app.include_router(_sample_router())
    owner = make_engine(mig)
    e = Env(app, settings, admin_url, fresh_db, owner, clock, stream, secrets_dir)
    e.secrets["totp_key"] = key_file.read_text().strip()
    yield e
    owner.dispose()
    if hasattr(app.state, "auth_engine"):
        app.state.auth_engine.dispose()
    logging.getLogger().handlers.clear()


def log_lines(env: Env) -> list[dict[str, Any]]:
    out = []
    for line in env.log_stream.getvalue().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def iter_api_routes(app: Any) -> Iterator[Any]:
    """Every ``APIRoute`` of the app, looking through the lazily included routers of recent FastAPI versions."""
    from fastapi.routing import APIRoute

    def walk(routes: Any) -> Iterator[Any]:
        for r in routes:
            inner = getattr(r, "original_router", None)
            if inner is not None:
                yield from walk(inner.routes)
            elif isinstance(r, APIRoute):
                yield r

    yield from walk(app.routes)
