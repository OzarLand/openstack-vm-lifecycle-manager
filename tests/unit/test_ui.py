from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from ovlm.api.app import create_app
from ovlm.config import Settings
from ovlm.ui import STATIC_DIR
from ovlm.ui.support import age, short_id, timestamp
from tests.unit.test_api import FakeProbe

HTMX_SHA256 = "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"


def test_pages_need_a_session_and_static_assets_do_not() -> None:
    c = TestClient(create_app(Settings(), probe=FakeProbe(True), start_metrics_server=False))
    for path in ("/", "/inventory", "/services", "/renewals", "/audit", "/account/stepup"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    assert c.get("/static/htmx.min.js").status_code == 200
    assert c.get("/static/ovlm.css").status_code == 200


def test_age_and_timestamp_helpers() -> None:
    now = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
    assert age((now - timedelta(days=3, hours=4)).isoformat(), now) == "3d 4h"
    assert age((now - timedelta(hours=5, minutes=12)).isoformat(), now) == "5h 12m"
    assert age((now - timedelta(minutes=7)).isoformat(), now) == "7m"
    assert age(None, now) == "unknown" and age("garbage", now) == "unknown"
    assert age((now + timedelta(hours=1)).isoformat(), now) == "0m"
    assert timestamp("2026-11-04T12:00:00+00:00") == "2026-11-04 12:00 UTC"
    assert short_id("0123456789abcdef") == "01234567" and short_id(None) == ""


def test_vendored_htmx_hash() -> None:
    digest = hashlib.sha256((STATIC_DIR / "htmx.min.js").read_bytes()).hexdigest()
    assert digest == HTMX_SHA256
    assert HTMX_SHA256 in (STATIC_DIR / "VENDORED.md").read_text()
