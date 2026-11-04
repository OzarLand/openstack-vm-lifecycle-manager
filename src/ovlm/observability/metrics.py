"""Prometheus registry and the internal metrics/health listener (SEC-R-17).

Metrics are served on a separate internal port, never on the public application port.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    generate_latest,
)

log = logging.getLogger(__name__)

REGISTRY = CollectorRegistry(auto_describe=True)

BUILD_INFO = Gauge(
    "ovlm_build_info", "Build information", ["version", "process"], registry=REGISTRY
)
HTTP_REQUESTS = Counter(
    "ovlm_http_requests_total",
    "HTTP requests handled by the api",
    ["method", "status"],
    registry=REGISTRY,
)
WORKER_LOOP = Counter(
    "ovlm_worker_loop_iterations_total", "Worker main loop iterations", registry=REGISTRY
)
WORKER_DB_UP = Gauge(
    "ovlm_worker_db_reachable", "1 if the last worker DB ping succeeded", registry=REGISTRY
)
_heartbeat = Gauge(
    "ovlm_worker_heartbeat_age_seconds",
    "Seconds since the worker loop last beat",
    registry=REGISTRY,
)
_last_beat: list[float | None] = [None]


def record_heartbeat() -> None:
    _last_beat[0] = time.monotonic()


def heartbeat_age() -> float | None:
    beat = _last_beat[0]
    return None if beat is None else time.monotonic() - beat


def _heartbeat_value() -> float:
    age = heartbeat_age()
    return float("nan") if age is None else age


_heartbeat.set_function(_heartbeat_value)


class InternalServer:
    """Tiny threaded HTTP server: ``/metrics`` and ``/healthz`` only."""

    def __init__(self, host: str, port: int, healthy: Callable[[], bool] = lambda: True) -> None:
        healthy_fn = healthy

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib API
                if self.path == "/metrics":
                    body, code, ctype = generate_latest(REGISTRY), 200, CONTENT_TYPE_LATEST
                elif self.path == "/healthz":
                    ok = healthy_fn()
                    body, code, ctype = (
                        (b"ok\n" if ok else b"unhealthy\n"),
                        (200 if ok else 503),
                        "text/plain",
                    )
                else:
                    body, code, ctype = b"not found\n", 404, "text/plain"
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        self._httpd = ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="ovlm-internal-http", daemon=True
        )

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def start(self) -> None:
        self._thread.start()
        log.info("internal listener started", extra={"port": self.port})

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)
