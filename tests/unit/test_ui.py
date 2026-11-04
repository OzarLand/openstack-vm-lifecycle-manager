from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from ovlm.api.app import create_app
from ovlm.config import Settings
from ovlm.ui import STATIC_DIR
from tests.unit.test_api import FakeProbe

HTMX_SHA256 = "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"


def test_index_uses_layout_and_local_htmx() -> None:
    c = TestClient(create_app(Settings(), probe=FakeProbe(True), start_metrics_server=False))
    r = c.get("/")
    assert r.status_code == 200
    assert '<script src="/static/htmx.min.js">' in r.text
    assert "hx-get=" in r.text
    assert "http://" not in r.text and "https://" not in r.text  # no CDN
    assert c.get("/static/htmx.min.js").status_code == 200
    assert c.get("/ui/fragments/status").status_code == 200


def test_vendored_htmx_hash() -> None:
    digest = hashlib.sha256((STATIC_DIR / "htmx.min.js").read_bytes()).hexdigest()
    assert digest == HTMX_SHA256
    assert HTMX_SHA256 in (STATIC_DIR / "VENDORED.md").read_text()
