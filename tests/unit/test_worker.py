from __future__ import annotations

import threading
from typing import Any

from sqlalchemy import create_engine

from ovlm.config import Settings
from ovlm.observability import metrics
from ovlm.observability.metrics import InternalServer
from ovlm.worker.main import Worker


class FailingEngine:
    def connect(self) -> Any:
        raise OSError("down")


def make_worker(interval: float = 0.01) -> Worker:
    settings = Settings(process_role="worker", worker={"heartbeat_interval": interval})
    return Worker(settings, create_engine("sqlite://"))  # SELECT 1 works on sqlite


def test_loop_beats_and_stops_gracefully() -> None:
    w = make_worker()
    t = threading.Thread(target=w.run)
    t.start()
    for _ in range(200):
        if metrics.heartbeat_age() is not None and w.healthy():
            break
        threading.Event().wait(0.01)
    assert w.healthy()
    w.request_stop("test")
    t.join(timeout=5)
    assert not t.is_alive()


def test_db_failure_is_reported_not_fatal() -> None:
    w = make_worker()
    w.engine = FailingEngine()  # type: ignore[assignment]
    w.tick()
    assert metrics.WORKER_DB_UP._value.get() == 0  # noqa: SLF001


def test_internal_server_serves_metrics_and_health() -> None:
    import urllib.request

    srv = InternalServer("127.0.0.1", 0)
    srv.start()
    try:
        base = f"http://127.0.0.1:{srv.port}"
        body = urllib.request.urlopen(base + "/metrics", timeout=5).read().decode()  # noqa: S310
        assert "ovlm_worker_heartbeat_age_seconds" in body
        assert urllib.request.urlopen(base + "/healthz", timeout=5).status == 200  # noqa: S310
    finally:
        srv.stop()
