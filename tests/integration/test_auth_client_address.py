# ruff: noqa: F811
"""SEC-C-1: the login limits behind the TLS proxy. Real PostgreSQL, real app.

The per-source limit keys on the client resolved through ``http.trusted_proxies``; the per-account limit is the
only one that escalates; a trusted proxy that names no client never lets one client hold everyone back.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.integration.auth_support import ORIGIN, PASSWORD, Env, env  # noqa: F401

PROXY = "10.9.0.2"
ATTACKER = "203.0.113.7"
VICTIM = "198.51.100.4"


def _trust(env: Env, *networks: str) -> None:
    settings = env.app.state.settings
    http = settings.http.model_copy(
        update={"trusted_proxies": tuple(ipaddress.ip_network(n) for n in networks)}
    )
    env.app.state.settings = settings.model_copy(update={"http": http})


def _client(env: Env, peer: str) -> TestClient:
    return TestClient(env.app, base_url=ORIGIN, client=(peer, 40000))


def _login(c: TestClient, username: str, password: str, forwarded: str | None = None) -> Any:
    headers = {"Origin": ORIGIN}
    if forwarded is not None:
        headers["X-Forwarded-For"] = forwarded
    return c.post(
        "/api/v1/session", json={"username": username, "password": password}, headers=headers
    )


def _spray(c: TestClient, n: int, forwarded: str | None = None) -> None:
    """``n`` failed logins on ``n`` different (unknown) accounts: only the per-source limit can see them."""
    for i in range(n):
        assert _login(c, f"nobody{i}", "wrong password 123", forwarded).status_code == 401


def test_forwarded_client_from_a_trusted_proxy_is_the_rate_limit_key(env: Env) -> None:
    env.create_user("vic", [("viewer", "global")])
    env.enrol(env.client(), env.secrets["link:vic"])
    _trust(env, "10.9.0.0/24")
    proxy = _client(env, PROXY)
    _spray(proxy, env.settings.auth.login_ip_failure_threshold, forwarded=ATTACKER)
    # the attacker's own address is now slowed down ...
    r = _login(proxy, "vic", PASSWORD, forwarded=ATTACKER)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) <= env.settings.auth.login_ip_delay_seconds
    # ... but another client behind the same proxy logs in, and is recorded with its own address
    r = _login(proxy, "vic", PASSWORD, forwarded=VICTIM)
    assert r.status_code == 200, r.text
    rows = env.sql(
        "SELECT source_ip FROM audit_event WHERE action = 'auth.login.success' ORDER BY ts DESC LIMIT 1"
    )
    assert rows[0].source_ip == VICTIM
    failures = env.sql("SELECT DISTINCT source_ip FROM login_attempt WHERE NOT success")
    assert [f.source_ip for f in failures] == [ATTACKER]  # never the proxy's address


def test_forwarded_header_from_an_untrusted_peer_is_ignored(env: Env) -> None:
    env.create_user("ula", [("viewer", "global")])
    env.enrol(env.client(), env.secrets["link:ula"])
    _trust(env, "10.9.0.0/24")
    direct = _client(env, "192.0.2.50")  # not a trusted proxy: it cannot pick its own address
    for i in range(env.settings.auth.login_ip_failure_threshold):
        r = _login(direct, f"nobody{i}", "wrong password 123", forwarded=f"198.51.100.{i + 1}")
        assert r.status_code == 401
    r = _login(direct, "ula", PASSWORD, forwarded="198.51.100.200")
    assert r.status_code == 429  # keyed on the peer, whatever the header claims


@pytest.mark.parametrize("env", [{"login_failure_threshold": 100}], indirect=True)
def test_a_trusted_proxy_naming_no_client_never_locks_out_another_account(env: Env) -> None:
    """The review's case: two usernames from the same source (the proxy, no X-Forwarded-For); 20 failures on the
    first; a correct login on the second still succeeds."""
    env.create_user("ann", [("viewer", "global")])
    env.create_user("bob", [("viewer", "global")])
    env.enrol(env.client(), env.secrets["link:ann"])
    env.enrol(env.client(), env.secrets["link:bob"])
    proxy = _client(env, "127.0.0.1")  # the default trusted proxy (loopback)
    for _ in range(env.settings.auth.login_ip_failure_threshold + 5):
        assert _login(proxy, "ann", "wrong password 123").status_code == 401
    r = _login(proxy, "bob", PASSWORD)
    assert r.status_code == 200, r.text
    assert env.sql("SELECT count(*) AS n FROM login_attempt WHERE kind = 'login' AND source_ip IS NOT NULL")[0].n == 0


@pytest.mark.parametrize("env", [{"login_failure_threshold": 3}], indirect=True)
def test_only_the_per_account_limit_escalates(env: Env) -> None:
    env.create_user("esc", [("viewer", "global")])
    env.enrol(env.client(), env.secrets["link:esc"])
    c = _client(env, "192.0.2.60")
    # per source: many failures, but the delay stays the fixed one
    for n in range(3):
        _spray(c, env.settings.auth.login_ip_failure_threshold if n == 0 else 1)
        r = _login(c, "esc", PASSWORD)
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) <= env.settings.auth.login_ip_delay_seconds
        env.sql("UPDATE login_attempt SET ts = ts - interval '1 minute'")  # let the fixed delay pass
    assert _login(c, "esc", PASSWORD).status_code == 200
    # per account: it doubles past the per-source delay (12 recent failures, threshold 3: 2**9 s)
    env.sql(
        "INSERT INTO login_attempt (kind, username, source_ip, success) "
        "SELECT 'login', 'esc', NULL, false FROM generate_series(1, 12)"
    )
    r = _login(_client(env, "192.0.2.61"), "esc", PASSWORD)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > env.settings.auth.login_ip_delay_seconds
