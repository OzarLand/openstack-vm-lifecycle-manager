"""The GET/HEAD-only hook (security-model.md s.4.1, SEC-R-5): refuses writes, allows the Keystone token POST."""

from __future__ import annotations

import json
from typing import Any

import pytest
import requests
from keystoneauth1 import adapter, session
from keystoneauth1.identity import v3
from requests.adapters import BaseAdapter

from ovlm.openstack.errors import ReadOnlyViolationError
from ovlm.openstack.guard import check_request, install_read_only_guard

AUTH_URL = "http://keystone.invalid/v3"
COMPUTE = "http://nova.invalid/v2.1"

_TOKEN_BODY = {
    "token": {
        "methods": ["application_credential"],
        "expires_at": "2099-01-01T00:00:00.000000Z",
        "issued_at": "2026-01-01T00:00:00.000000Z",
        "user": {"id": "u1", "name": "u", "domain": {"id": "d", "name": "d"}},
        "project": {"id": "p1", "name": "p", "domain": {"id": "d", "name": "d"}},
        "roles": [{"id": "r", "name": "reader"}],
        "catalog": [
            {
                "type": "compute",
                "id": "c",
                "name": "nova",
                "endpoints": [{"id": "e", "interface": "public", "region": "R1", "url": COMPUTE}],
            }
        ],
    }
}


class RecordingTransport(BaseAdapter):
    """Stands in for the network: records every request that actually gets sent."""

    def __init__(self) -> None:
        super().__init__()
        self.sent: list[tuple[str, str]] = []

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        self.sent.append((str(request.method), str(request.url)))
        resp = requests.Response()
        resp.status_code = (
            201 if request.method == "POST" and "auth/tokens" in str(request.url) else 200
        )
        resp.headers["Content-Type"] = "application/json"
        if "auth/tokens" in str(request.url):
            resp.headers["X-Subject-Token"] = "tok-1"
            resp._content = json.dumps(_TOKEN_BODY).encode()
        else:
            resp._content = b'{"servers": []}'
        resp.url = str(request.url)
        resp.request = request
        return resp

    def close(self) -> None:
        pass


@pytest.fixture
def guarded() -> tuple[session.Session, RecordingTransport]:
    auth = v3.ApplicationCredential(
        auth_url=AUTH_URL, application_credential_id="id", application_credential_secret="s3cret"
    )
    sess = session.Session(auth=auth)
    transport = RecordingTransport()
    sess.session.mount("http://", transport)
    install_read_only_guard(sess)
    return sess, transport


@pytest.mark.parametrize("method", ["GET", "get", "HEAD"])
def test_reads_are_allowed(method: str) -> None:
    check_request(method, f"{COMPUTE}/servers", {"endpoint_filter": {"service_type": "compute"}})


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "post"])
def test_writes_are_refused(method: str) -> None:
    with pytest.raises(ReadOnlyViolationError):
        check_request(
            method, f"{COMPUTE}/servers", {"endpoint_filter": {"service_type": "compute"}}
        )


def test_token_post_is_the_one_exemption() -> None:
    check_request("POST", f"{AUTH_URL}/auth/tokens", {"authenticated": False})
    check_request(
        "POST", "http://keystone.invalid/v3/auth/tokens?nocatalog", {"authenticated": False}
    )


@pytest.mark.parametrize(
    ("url", "kwargs"),
    [
        # a service call through the identity proxy carries an endpoint_filter: still refused
        (
            f"{AUTH_URL}/auth/tokens",
            {"authenticated": False, "endpoint_filter": {"service_type": "identity"}},
        ),
        (f"{AUTH_URL}/auth/tokens", {}),  # authenticated defaults to True
        (f"{AUTH_URL}/auth/tokens", {"authenticated": True}),
        (f"{AUTH_URL}/users", {"authenticated": False}),  # other path
        (f"{COMPUTE}/servers/abc/action", {"authenticated": False}),
        ("http://x.invalid/auth/tokens-evil", {"authenticated": False}),
    ],
)
def test_token_exemption_is_narrow(url: str, kwargs: dict[str, Any]) -> None:
    with pytest.raises(ReadOnlyViolationError):
        check_request("POST", url, kwargs)


def test_token_exemption_does_not_cover_other_methods() -> None:
    for verb in ("PUT", "DELETE", "PATCH"):
        with pytest.raises(ReadOnlyViolationError):
            check_request(verb, f"{AUTH_URL}/auth/tokens", {"authenticated": False})


def test_real_session_authenticates_then_reads_and_never_writes(
    guarded: tuple[session.Session, RecordingTransport],
) -> None:
    sess, transport = guarded
    compute = adapter.Adapter(session=sess, service_type="compute", interface="public")
    assert compute.get("/servers").status_code == 200  # token POST (exempt) + GET
    methods = [m for m, _ in transport.sent]
    assert methods == ["POST", "GET"]  # the token request went out, the read went out


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_real_session_refuses_service_writes_before_sending(
    guarded: tuple[session.Session, RecordingTransport], method: str
) -> None:
    sess, transport = guarded
    compute = adapter.Adapter(session=sess, service_type="compute", interface="public")
    compute.get("/servers")  # authenticate
    before = list(transport.sent)
    with pytest.raises(ReadOnlyViolationError):
        getattr(compute, method)("/servers/abc/action", json={"os-stop": None})
    assert transport.sent == before  # nothing reached the network


def test_identity_proxy_cannot_use_the_token_exemption(
    guarded: tuple[session.Session, RecordingTransport],
) -> None:
    sess, transport = guarded
    identity = adapter.Adapter(session=sess, service_type="compute", interface="public")
    identity.get("/servers")
    before = list(transport.sent)
    with pytest.raises(ReadOnlyViolationError):
        identity.post(f"{AUTH_URL}/auth/tokens", json={}, authenticated=False)
    assert transport.sent == before


def test_install_is_idempotent(guarded: tuple[session.Session, RecordingTransport]) -> None:
    sess, _ = guarded
    first = sess.request
    install_read_only_guard(sess)
    assert sess.request is first


def test_sdk_proxy_delete_is_refused(guarded: tuple[session.Session, RecordingTransport]) -> None:
    """The SDK's own proxies are Adapters on the same session: a write through them is refused too."""
    from openstack import connection

    sess, transport = guarded
    conn = connection.Connection(
        session=sess, compute_api_version="2.1", compute_endpoint_override=COMPUTE
    )
    sess.get_token()  # authenticate once (token POST passes the exemption)
    with pytest.raises(ReadOnlyViolationError):
        conn.compute.delete_server("abc")
    assert {m for m, _ in transport.sent} <= {"GET", "HEAD", "POST"}  # version discovery may read
    assert [u for m, u in transport.sent if m == "POST"] == [
        f"{AUTH_URL}/auth/tokens"
    ]  # only the token
