"""Client address behind the trusted proxies (SEC-C-1): pure resolution rules."""

from __future__ import annotations

import ipaddress

import pytest

from ovlm.auth.clientaddr import ClientAddress, resolve_client
from ovlm.config import Settings

PROXIES = (ipaddress.ip_network("10.9.0.0/24"), ipaddress.ip_network("fd00::/64"))


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        # untrusted peer: the peer is the client, whatever the header says (no spoofing)
        ("192.0.2.50", ["198.51.100.9"], ClientAddress("192.0.2.50", True)),
        ("192.0.2.50", [], ClientAddress("192.0.2.50", True)),
        # trusted proxy: the right-most non-proxy entry is the client
        ("10.9.0.2", ["198.51.100.9"], ClientAddress("198.51.100.9", True)),
        ("10.9.0.2", ["6.6.6.6, 198.51.100.9"], ClientAddress("198.51.100.9", True)),
        ("10.9.0.2", ["6.6.6.6", "198.51.100.9, 10.9.0.3"], ClientAddress("198.51.100.9", True)),
        ("10.9.0.2", ["[2001:db8::7]:443"], ClientAddress("2001:db8::7", True)),
        ("10.9.0.2", ["198.51.100.9:5555"], ClientAddress("198.51.100.9", True)),
        ("fd00::1", ["::ffff:198.51.100.9"], ClientAddress("198.51.100.9", True)),
        # trusted proxy that names no client: unknown, never keyed on (the proxy stands for everyone)
        ("10.9.0.2", [], ClientAddress("10.9.0.2", False)),
        ("10.9.0.2", ["10.9.0.3"], ClientAddress("10.9.0.2", False)),
        ("10.9.0.2", ["198.51.100.9, not-an-ip"], ClientAddress("10.9.0.2", False)),
        ("10.9.0.2", ["  ,  "], ClientAddress("10.9.0.2", False)),
        # no peer / non-IP peer (test transports)
        (None, ["198.51.100.9"], ClientAddress(None, False)),
        ("testclient", [], ClientAddress("testclient", True)),
    ],
)
def test_resolve_client(peer: str | None, xff: list[str], expected: ClientAddress) -> None:
    assert resolve_client(peer, xff, PROXIES) == expected


def test_rate_limit_key_is_none_when_not_attributable() -> None:
    assert ClientAddress("10.9.0.2", False).rate_limit_key is None
    assert ClientAddress("198.51.100.9", True).rate_limit_key == "198.51.100.9"


def test_trusted_proxies_setting_defaults_to_loopback_and_parses_lists() -> None:
    s = Settings(process_role="worker")
    assert [str(n) for n in s.http.trusted_proxies] == ["127.0.0.1/32", "::1/128"]
    s = Settings(process_role="worker", http={"trusted_proxies": "10.9.0.0/24, fd00::1"})
    assert [str(n) for n in s.http.trusted_proxies] == ["10.9.0.0/24", "fd00::1/128"]
    s = Settings(process_role="worker", http={"trusted_proxies": []})
    assert s.http.trusted_proxies == ()
    with pytest.raises(ValueError):
        Settings(process_role="worker", http={"trusted_proxies": ["proxy.example"]})
