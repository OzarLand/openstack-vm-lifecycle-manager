"""Egress proxy behaviour (docs/install-guide.md section 5a).

The worker reaches the OpenStack APIs through an operator-provided HTTPS proxy (``HTTPS_PROXY``/``NO_PROXY`` from
``.env``) and the guests directly: the SDK session honours the proxy variables, the guest health probe ignores
them, and SSH is a separate OpenSSH process that never reads them. "Unit tested" only: no real proxy, no cloud."""

from __future__ import annotations

import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from ovlm.openstack.ownership import InMemoryOwnershipRegistry
from ovlm.openstack.sdk_write import SdkWriteBackend, WriteCredential, connect_write
from ovlm.renewal.production import UrllibGetter
from tests.unit.test_openstack_allowlist import AUTH_URL, RUN

PROXY = "http://proxy.example:3128"
PROXY_VARS = (
    "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
)  # fmt: skip


@pytest.fixture(autouse=True)
def _clean_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in PROXY_VARS:
        monkeypatch.delenv(name, raising=False)


class _Recorder(HTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.seen: list[str] = []


class _Handler(BaseHTTPRequestHandler):
    server: _Recorder

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.server.seen.append(self.path)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:  # silence
        return


@pytest.fixture
def servers() -> Iterator[tuple[_Recorder, _Recorder]]:
    """(guest, fake proxy): two local HTTP servers that record the request line path they get."""
    guest, proxy = _Recorder(), _Recorder()
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (guest, proxy)]
    for t in threads:
        t.start()
    yield guest, proxy
    for s in (guest, proxy):
        s.shutdown()
        s.server_close()


def _point_env_at(proxy: _Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"http://127.0.0.1:{proxy.server_address[1]}"
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, url)


def test_the_proxy_variables_would_divert_an_ordinary_urllib_client(
    servers: tuple[_Recorder, _Recorder], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: with these variables a default urllib opener goes to the proxy, so the next test proves something."""
    guest, proxy = servers
    _point_env_at(proxy, monkeypatch)
    url = f"http://127.0.0.1:{guest.server_address[1]}/health"
    with urllib.request.build_opener().open(url, timeout=5) as resp:  # noqa: S310 - loopback test server
        assert resp.status == 200
    assert proxy.seen and not guest.seen


def test_the_guest_probe_never_uses_a_proxy_from_the_environment(
    servers: tuple[_Recorder, _Recorder], monkeypatch: pytest.MonkeyPatch
) -> None:
    guest, proxy = servers
    # no NO_PROXY here: only the client's own setting can keep the request direct
    _point_env_at(proxy, monkeypatch)
    url = f"http://127.0.0.1:{guest.server_address[1]}/health"
    answer = UrllibGetter().get(url, timeout=5)
    assert answer.status == 200 and answer.body == b'{"ok": true}'
    assert guest.seen == ["/health"]  # origin-form request line: it came straight to the guest
    assert proxy.seen == []


def _write_session() -> Any:
    cred = WriteCredential(
        auth_url=AUTH_URL,
        application_credential_id="cred-id",
        application_credential_secret="app-cred-s3cret-value",
        region_name="R1",
    )
    client = connect_write(
        cred, registry=InMemoryOwnershipRegistry(RUN), gate=lambda _a: None, process_role="worker"
    )
    backend = client._backend
    assert isinstance(backend, SdkWriteBackend)
    return backend._conn.session.session  # the requests.Session behind keystoneauth


def _proxies_for(session: Any, url: str) -> dict[str, str]:
    merged = session.merge_environment_settings(url, {}, None, None, None)
    return dict(merged["proxies"])


def test_the_sdk_session_follows_https_proxy_and_no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", PROXY)
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,10.0.0.0/24")
    session = _write_session()
    assert session.trust_env is True
    assert _proxies_for(session, "https://keystone.example:5000/v3").get("https") == PROXY
    assert "https" not in _proxies_for(session, "https://10.0.0.7:8443/")  # project subnet: direct
    assert "https" not in _proxies_for(session, "https://localhost/")


def test_without_proxy_variables_the_sdk_goes_direct(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _write_session()
    assert "https" not in _proxies_for(session, "https://keystone.example:5000/v3")


def _read_session() -> Any:
    """The requests session behind the inventory's read client, built exactly as the sync job builds it."""
    from datetime import UTC, datetime

    from ovlm.connections.credentials import AppCredential, ConnectionInfo, connect_read_credential

    info = ConnectionInfo("pc", "lab", True, AUTH_URL, "R1", "public", "0" * 32)
    cred = AppCredential(
        info, "cred", "os_read", "app-cred-id", "app-cred-r3ad-value", datetime.now(UTC)
    )
    client = connect_read_credential(cred, None, process_role="worker")
    return client._conn.session.session


def test_the_inventory_read_session_follows_https_proxy_and_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", PROXY)
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,10.0.0.0/24")
    session = _read_session()
    assert session.trust_env is True
    assert _proxies_for(session, "https://keystone.example:5000/v3").get("https") == PROXY
    assert "https" not in _proxies_for(session, "https://10.0.0.7:8443/")


def test_without_proxy_variables_the_inventory_read_session_goes_direct() -> None:
    assert "https" not in _proxies_for(_read_session(), "https://keystone.example:5000/v3")
