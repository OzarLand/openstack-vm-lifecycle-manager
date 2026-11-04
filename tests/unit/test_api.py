from __future__ import annotations

from fastapi.testclient import TestClient

from ovlm.api.app import create_app
from ovlm.api.health import CheckResult
from ovlm.config import Settings


class FakeProbe:
    def __init__(self, ok: bool) -> None:
        self.ok = ok

    def check(self) -> list[CheckResult]:
        return [CheckResult("database", self.ok, "" if self.ok else "database unreachable")]


def client(ok: bool = True) -> TestClient:
    return TestClient(
        create_app(Settings(development_mode=True), probe=FakeProbe(ok), start_metrics_server=False)
    )


def test_healthz() -> None:
    r = client().get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_healthz_ignores_db_state() -> None:
    assert client(ok=False).get("/healthz").status_code == 200


def test_readyz_ready_and_not_ready() -> None:
    ok = client(True).get("/readyz")
    assert ok.status_code == 200 and ok.json()["status"] == "ready"
    bad = client(False).get("/readyz")
    assert bad.status_code == 503
    assert bad.json()["checks"]["database"] == "database unreachable"


def test_metrics_not_on_public_port() -> None:
    assert client().get("/metrics").status_code == 404


def test_request_id_propagation_and_security_headers() -> None:
    c = client()
    r = c.get("/healthz", headers={"X-Request-ID": "abc-12345678"})
    assert r.headers["x-request-id"] == "abc-12345678"
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    generated = c.get("/healthz", headers={"X-Request-ID": "bad id\n"}).headers["x-request-id"]
    assert len(generated) == 32


def test_openapi_and_docs_not_exposed() -> None:
    c = client()
    assert c.get("/openapi.json").status_code == 404
    assert c.get("/docs").status_code == 404
