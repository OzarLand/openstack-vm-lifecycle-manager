"""SEC-C-2: no OpenStack request or response body reaches the log output, even with ``log.level = DEBUG``.

Real keystoneauth session + openstacksdk connection over the canned transport of ``test_openstack_allowlist``:
the server create carries ``user_data`` (stands for the bootstrap private host key, ADR-0006) and the canned
response carries ``adminPass``.
"""

from __future__ import annotations

import base64
import io
import logging
from collections.abc import Iterator

import pytest

from ovlm.observability.logging import SDK_HTTP_LOGGERS, configure_logging
from ovlm.openstack.allowlist import TAG_MANAGED
from ovlm.openstack.ownership import run_tag
from ovlm.openstack.types import CreateServerSpec
from tests.unit.test_openstack_allowlist import NOVA, RUN, SID, CannedCloud, _backend

KEY_MARKER = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA-host-key-marker\n"
ADMIN_PASS = "not-logged"  # what CannedCloud answers in the create response


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    names = ["", *SDK_HTTP_LOGGERS, "keystoneauth.session"]
    saved = {n: (logging.getLogger(n).level, list(logging.getLogger(n).handlers)) for n in names}
    yield
    for n, (level, handlers) in saved.items():
        logging.getLogger(n).setLevel(level)
        logging.getLogger(n).handlers[:] = handlers


def _create_and_stop() -> CannedCloud:
    cloud = CannedCloud()
    backend, gate = _backend(cloud)
    spec = CreateServerSpec(
        name="ovlm-web-1", image_id="img", flavor_id="fl", network_id="net",
        tags=(TAG_MANAGED, run_tag(RUN)), user_data="#cloud-config\nbootstrap_key: |\n  " + KEY_MARKER,
    )  # fmt: skip
    with backend.gate_binding.bind(gate):
        backend.create_server(spec)
        backend.stop_server(SID)
    sent = next(b for m, u, _h, b in cloud.sent if m == "POST" and u.endswith("/servers"))
    assert "host-key-marker" in base64.b64decode(sent["server"]["user_data"]).decode()
    return cloud


def _assert_no_bodies(out: str) -> None:
    encoded = base64.b64encode(("#cloud-config\nbootstrap_key: |\n  " + KEY_MARKER).encode())
    for leaked in ("host-key-marker", "BEGIN OPENSSH", encoded.decode()[:40], ADMIN_PASS):
        assert leaked not in out, leaked


def test_debug_level_logs_no_sdk_http_bodies() -> None:
    buf = io.StringIO()
    configure_logging("worker", "DEBUG", stream=buf)
    logging.getLogger("ovlm.test").debug("root is at DEBUG")
    _create_and_stop()
    out = buf.getvalue()
    assert "root is at DEBUG" in out and "server create accepted" in out  # logging works
    _assert_no_bodies(out)
    assert "REQ: curl" not in out and "RESP BODY" not in out  # no SDK HTTP debug line at all
    assert '"logger": "keystoneauth' not in out


def test_a_later_debug_level_on_an_sdk_logger_is_still_dropped() -> None:
    buf = io.StringIO()
    configure_logging("worker", "DEBUG", stream=buf)
    # what openstack.enable_logging(http_debug=True) or a library would do after start-up
    for name in ("keystoneauth", "keystoneauth.session", "openstack", "urllib3"):
        logging.getLogger(name).setLevel(logging.DEBUG)
    _create_and_stop()
    out = buf.getvalue()
    _assert_no_bodies(out)
    assert "REQ: curl" not in out


def test_development_http_debug_still_never_logs_the_server_create() -> None:
    """With the development flag the SDK logs requests, but the create is sent with ``log=False``."""
    buf = io.StringIO()
    configure_logging("worker", "DEBUG", stream=buf, openstack_http_debug=True)
    _create_and_stop()
    out = buf.getvalue()
    assert "openstack_http_debug is on" in out
    # other requests are logged (the flag works) ...
    assert f"-X POST {NOVA}/servers/{SID}/action" in out
    # ... but the create is not, neither request nor response (not merely redacted by the backstop)
    assert f"-X POST {NOVA}/servers " not in out
    _assert_no_bodies(out)


def test_json_quoted_secrets_are_redacted_by_the_backstop() -> None:
    buf = io.StringIO()
    configure_logging("worker", "INFO", stream=buf)
    logging.getLogger("ovlm.test").info(
        'body {"server": {"adminPass": "Zq9-secret-pw", "user_data": "I2Nsb3VkLWNvbmZpZw=="}}'
    )
    out = buf.getvalue()
    assert "Zq9-secret-pw" not in out and "I2Nsb3VkLWNvbmZpZw" not in out
