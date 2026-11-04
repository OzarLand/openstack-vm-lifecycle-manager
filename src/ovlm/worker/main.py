"""Worker entry point: ``ovlm-worker`` (also ``ovlm worker``).

Skeleton: main loop with heartbeat metric, DB ping, graceful shutdown on SIGTERM/SIGINT. It refuses to start
when the schema is not at head. No engine logic yet.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import uuid
from types import FrameType

from sqlalchemy import Engine, text

from ovlm import __version__
from ovlm.config import Settings
from ovlm.db.engine import make_engine
from ovlm.db.schema import check_schema_at_head
from ovlm.observability.logging import configure_logging
from ovlm.observability.metrics import (
    BUILD_INFO,
    WORKER_DB_UP,
    WORKER_LOOP,
    InternalServer,
    heartbeat_age,
    record_heartbeat,
)

log = logging.getLogger("ovlm.worker")


class Worker:
    def __init__(self, settings: Settings, engine: Engine) -> None:
        self.settings = settings
        self.engine = engine
        self.instance_id = uuid.uuid4().hex  # new at each process start (ADR-0003)
        self.stop_event = threading.Event()

    def request_stop(self, reason: str = "requested") -> None:
        if not self.stop_event.is_set():
            log.info("shutdown requested", extra={"reason": reason})
        self.stop_event.set()

    def healthy(self) -> bool:
        age = heartbeat_age()
        return age is not None and age < 3 * self.settings.worker.heartbeat_interval

    def tick(self) -> None:
        """One loop iteration: ping the DB and beat."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            WORKER_DB_UP.set(1)
        except Exception:  # noqa: BLE001
            WORKER_DB_UP.set(0)
            log.warning("database ping failed")
        record_heartbeat()
        WORKER_LOOP.inc()

    def run(self) -> None:
        log.info("worker started", extra={"worker_instance_id": self.instance_id})
        record_heartbeat()
        while not self.stop_event.is_set():
            self.tick()
            self.stop_event.wait(self.settings.worker.heartbeat_interval)
        log.info("worker stopped", extra={"worker_instance_id": self.instance_id})


def run(settings: Settings | None = None) -> int:
    settings = settings or Settings(process_role="worker")
    configure_logging("worker", settings.log.level)
    engine = make_engine(settings)
    server: InternalServer | None = None
    try:
        check_schema_at_head(engine, settings.migrations_dir)
        worker = Worker(settings, engine)
        BUILD_INFO.labels(__version__, "worker").set(1)
        server = InternalServer(
            settings.http.metrics_host, settings.http.metrics_port, worker.healthy
        )
        server.start()

        def _handler(signum: int, _frame: FrameType | None) -> None:
            worker.request_stop(signal.Signals(signum).name)

        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)
        worker.run()
        return 0
    finally:
        if server:
            server.stop()
        engine.dispose()


def main() -> None:
    try:
        code = run()
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("ovlm.worker").error("fatal: %s", exc, exc_info=True)
        code = 1
    sys.exit(code)
