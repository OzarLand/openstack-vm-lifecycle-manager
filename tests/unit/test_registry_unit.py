"""Pure parts of inventory.service / registry.service / the authentication guard (no database)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from ovlm.api.app import create_app
from ovlm.api.health import CheckResult
from ovlm.config import Settings
from ovlm.inventory.ids import uuid7
from ovlm.inventory.service import InvalidCursorError, clamp_limit, decode_cursor, encode_cursor
from ovlm.registry.errors import DomainError
from ovlm.registry.service import SLUG, etag, parse_if_match


class _Probe:
    def check(self) -> list[CheckResult]:
        return [CheckResult("database", True, "")]


def test_cursor_round_trip_and_garbage() -> None:
    ts, rid = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), uuid4()
    assert decode_cursor(encode_cursor(ts, rid)) == (ts, rid)
    for bad in ("", "!!!", "e30", "WzEsMl0"):
        with pytest.raises(InvalidCursorError):
            decode_cursor(bad)


def test_limit_clamp() -> None:
    assert (
        clamp_limit(None) == 50
        and clamp_limit(0) == 50
        and clamp_limit(9999) == 200
        and clamp_limit(3) == 3
    )


@pytest.mark.parametrize("slug", ["a", "app01", "my-app-1", "a" * 64])
def test_valid_slugs(slug: str) -> None:
    assert SLUG.match(slug)


@pytest.mark.parametrize("slug", ["", "-a", "a-", "A", "a_b", "a b", "a" * 65, "é"])
def test_invalid_slugs(slug: str) -> None:
    assert not SLUG.match(slug)


def test_if_match_parsing() -> None:
    assert parse_if_match('"3"') == 3 and parse_if_match('W/"7"') == 7 and parse_if_match("5") == 5
    assert etag(4) == '"4"'
    with pytest.raises(DomainError) as missing:
        parse_if_match(None)
    assert missing.value.status == 428
    with pytest.raises(DomainError) as bad:
        parse_if_match('"abc"')
    assert bad.value.status == 412


def test_uuid7_is_time_ordered_valid_v7() -> None:
    a, b = uuid7(), uuid7()
    assert a.version == 7 and a.variant == "specified in RFC 4122"
    assert a != b
    first = [uuid7() for _ in range(3)]
    import time

    time.sleep(0.003)
    later = uuid7()
    assert all(x.int < later.int for x in first)


def test_unauthenticated_requests_are_refused_with_401() -> None:
    """Every route needs a session or token: no credentials means problem+json 401, never data."""
    client = TestClient(
        create_app(Settings(development_mode=True), probe=_Probe(), start_metrics_server=False)
    )
    for method, path in (
        ("GET", "/api/v1/servers"),
        ("GET", "/api/v1/services"),
        ("POST", "/api/v1/services"),
        ("DELETE", f"/api/v1/managed-vms/{uuid4()}"),
    ):
        r = client.request(method, path, json={} if method == "POST" else None)
        assert r.status_code == 401, (method, path, r.status_code)
    r = client.get("/api/v1/servers")
    assert r.headers["content-type"] == "application/problem+json"
    assert r.json()["instance"] == "/api/v1/servers"
