"""Worker entry point: ``ovlm-worker`` (also ``ovlm worker``).

Main loop: worker heartbeat metric and row, DB ping, then the workflow engine (signals, admission, scheduler,
claims into ``worker.slots`` step threads, metrics). Graceful shutdown on SIGTERM/SIGINT: stop claiming, let running
steps finish within ``worker.shutdown_grace``; anything still running is left to lease expiry and takeover
(renewal-workflow.md section 5). It refuses to start when the schema is not at head, and when a test crash-point
plan is set in the environment.
"""

from __future__ import annotations

import logging
import os
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
from ovlm.readiness.job import ReadinessDefinition
from ovlm.workflow.crashpoint import ENV_VAR as CRASHPOINT_ENV
from ovlm.workflow.engine import Claim, EngineConfig, WorkflowEngine
from ovlm.workflow.registry import Registry
from ovlm.workflow.workers import SWEEP_AFTER_BEATS

log = logging.getLogger("ovlm.worker")

#: Refresh the workflow gauges every N loop iterations.
METRICS_EVERY = 6


def build_registry(settings: Settings, engine: Engine | None = None) -> Registry:
    """Workflow definitions of this release. Strategies register here (E5-4 adds ``bluegreen_fip_v1``).

    ``readiness`` (E4-1) reads the database only and needs the engine to store its assessment."""
    registry = Registry()
    if engine is not None:
        registry.register(ReadinessDefinition(engine))
    return registry


class Worker:
    def __init__(
        self, settings: Settings, engine: Engine, workflow: WorkflowEngine | None = None
    ) -> None:
        self.settings = settings
        self.engine = engine
        self.workflow = workflow
        # ``lease_owner``: new at each process start (ADR-0003, SRE-R-4).
        self.instance_id = workflow.worker_id if workflow else uuid.uuid4().hex
        self.stop_event = threading.Event()
        self._active: set[threading.Thread] = set()
        self._active_lock = threading.Lock()
        self._iterations = 0
        self._started = False

    def request_stop(self, reason: str = "requested") -> None:
        if not self.stop_event.is_set():
            log.info("shutdown requested", extra={"reason": reason})
        self.stop_event.set()
        if self.workflow:
            self.workflow.stopping.set()

    def healthy(self) -> bool:
        age = heartbeat_age()
        return age is not None and age < 3 * self.settings.worker.heartbeat_interval

    def active_steps(self) -> int:
        with self._active_lock:
            self._active = {t for t in self._active if t.is_alive()}
            return len(self._active)

    def _start_workflow(self) -> None:
        """Once per process: register, then run startup sweepers *before* the first claim (SRE-R-5)."""
        if self.workflow is None:
            return
        self._sweep_automation_orphans()
        self.workflow.register_worker(__version__)
        for sweeper in self.workflow.registry.sweepers:
            sweeper()
        self._started = True

    def _sweep_automation_orphans(self) -> None:
        """Wipe run directories (secrets) a killed worker left behind and stop their processes, before any claim
        (automation-contract.md sections 5 and 8). A failure is logged, not fatal: it must not take the worker down."""
        from ovlm.automation.config import orphan_max_age, runner_config
        from ovlm.automation.rundir import sweep_orphans

        try:
            removed = sweep_orphans(
                self.settings.automation.run_root, orphan_max_age(runner_config(self.settings))
            )
        except Exception:
            log.exception("automation orphan sweep failed")
            return
        if removed:
            log.warning("removed orphan automation run directories", extra={"count": len(removed)})

    def _workflow_tick(self) -> None:
        wf = self.workflow
        if wf is None:
            return
        if not self._started:
            self._start_workflow()
        wf.beat_worker(draining=self.stop_event.is_set())
        wf.process_signals()
        wf.admit_pending()
        wf.run_scheduler()
        if self._iterations % METRICS_EVERY == 0:
            wf.sweep_worker_rows(SWEEP_AFTER_BEATS * self.settings.worker.heartbeat_interval)
            wf.refresh_metrics()
        free = self.settings.worker.slots - self.active_steps()
        if self.stop_event.is_set() or free <= 0:
            return
        for claim in wf.claim(free):
            t = threading.Thread(
                target=self._run_step,
                args=(claim,),
                name=f"ovlm-step-{claim.step.step_key}",
                daemon=True,
            )
            with self._active_lock:
                self._active.add(t)
            t.start()

    def _run_step(self, claim: Claim) -> None:
        if self.workflow is None:
            return
        try:
            self.workflow.execute(claim)
        except Exception:
            log.exception("step execution failed outside the step contract")

    def tick(self) -> None:
        """One loop iteration: ping the DB, beat, run the engine."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            WORKER_DB_UP.set(1)
        except Exception:  # noqa: BLE001
            WORKER_DB_UP.set(0)
            log.warning("database ping failed")
        record_heartbeat()
        WORKER_LOOP.inc()
        try:
            self._workflow_tick()
        except Exception:
            # DB outage etc.: running steps self-fence; the loop retries next iteration (ADR-0003 "DB outage").
            log.exception("workflow tick failed")
        self._iterations += 1

    def run(self) -> None:
        log.info("worker started", extra={"worker_instance_id": self.instance_id})
        record_heartbeat()
        interval = self.settings.worker.heartbeat_interval
        while not self.stop_event.is_set():
            self.tick()
            self.stop_event.wait(interval)
        self._drain()
        log.info("worker stopped", extra={"worker_instance_id": self.instance_id})

    def _drain(self) -> None:
        if self.workflow is None:
            return
        try:
            self.workflow.beat_worker(draining=True)
        except Exception:  # noqa: BLE001
            log.warning("could not mark the worker draining")
        deadline = threading.Event()
        timer = threading.Timer(self.settings.worker.shutdown_grace, deadline.set)
        timer.daemon = True
        timer.start()
        while self.active_steps() and not deadline.wait(0.1):
            record_heartbeat()
        timer.cancel()
        left = self.active_steps()
        if left:
            log.warning(
                "shutdown grace elapsed with running steps; leases will expire and be taken over",
                extra={"running_steps": left},
            )


def run(settings: Settings | None = None) -> int:
    settings = settings or Settings(process_role="worker")
    configure_logging("worker", settings.log.level)
    if os.environ.get(CRASHPOINT_ENV):
        log.error("refusing to start: %s is a test-only setting", CRASHPOINT_ENV)
        return 1
    engine = make_engine(settings)
    server: InternalServer | None = None
    try:
        check_schema_at_head(engine, settings.migrations_dir)
        workflow = WorkflowEngine(
            engine, build_registry(settings, engine), EngineConfig.from_settings(settings)
        )
        worker = Worker(settings, engine, workflow)
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
