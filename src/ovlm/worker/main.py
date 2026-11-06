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
from typing import Any

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
from ovlm.workflow.audit import DbAuditSink
from ovlm.workflow.crashpoint import ENV_VAR as CRASHPOINT_ENV
from ovlm.workflow.engine import Claim, EngineConfig, WorkflowEngine
from ovlm.workflow.registry import Registry
from ovlm.workflow.workers import SWEEP_AFTER_BEATS

log = logging.getLogger("ovlm.worker")

#: Refresh the workflow gauges every N loop iterations.
METRICS_EVERY = 6


def build_registry(
    settings: Settings, engine: Engine | None = None, *, renewal_deps: Any = None
) -> Registry:
    """Workflow definitions of this release.

    ``readiness`` (E4-1) reads the database only. ``inventory_sync`` reads OpenStack with the project's read
    credential (:mod:`ovlm.inventory.job`). ``bluegreen_fip_v1`` (E5-4) gets its production ports from
    :func:`ovlm.renewal.production.production_deps` (guarded SDK write client per project credential, the automation
    runner from ``Settings.automation``, OpenSSH and HTTP probes); tests pass ``renewal_deps`` (doubles). Its
    ``api_unreachable`` re-probe runs every ``poll.max_interval`` (renewal-workflow.md 5)."""
    registry = Registry()
    if engine is not None:
        from ovlm.renewal import reprobe
        from ovlm.renewal.definition import BlueGreenFipV1
        from ovlm.renewal.production import credential_store, production_deps

        store = credential_store(settings, engine)
        registry.register(ReadinessDefinition(engine))
        registry.register(BlueGreenFipV1(renewal_deps or production_deps(settings, engine, store)))
        registry.register(reprobe.RenewalReprobe(engine))
        registry.periodic.append(reprobe.periodic_job(settings.poll.max_interval))
        _register_inventory_jobs(registry, settings, engine, store)
        _register_host_key_scan(registry, settings, engine)
        if store is not None:
            _register_credential_jobs(registry, settings, store)
    return registry


def _register_host_key_scan(registry: Registry, settings: Settings, engine: Engine) -> None:
    """``host_key_scan``: ``ssh-keyscan`` of a newly registered VM; an operator confirms the fingerprint (ADR-0006)."""
    from ovlm.registry.host_key_scan import HostKeyScanDefinition
    from ovlm.renewal.production import OpenSshTransport

    ssh = OpenSshTransport(settings.automation.run_root / f".ssh-scan-{uuid.uuid4().hex[:8]}")
    registry.register(HostKeyScanDefinition(engine, ssh.keyscan))


def _register_inventory_jobs(
    registry: Registry, settings: Settings, engine: Engine, store: Any
) -> None:
    """``inventory_sync`` (one project connection, its read credential from the store) and the periodic job that
    queues one for every enabled connection with a validated read credential every ``inventory.sync_interval``
    (``0``: off). Without a KEK every sync fails with a clear reason."""
    from ovlm.inventory import job as inventory_job

    access = (
        inventory_job.StoreReadAccess(store) if store is not None else inventory_job.NoReadAccess()
    )
    registry.register(
        inventory_job.InventorySyncDefinition(engine, access, inventory_job.sync_config(settings))
    )
    if settings.inventory.sync_interval > 0:
        registry.register(inventory_job.InventorySyncScheduleDefinition(engine))
        registry.periodic.append(inventory_job.periodic_job(settings.inventory.sync_interval))


def _register_credential_jobs(registry: Registry, settings: Settings, store: Any) -> None:
    """Credential validation (out of band, read-only Keystone check) and, during a KEK rotation, the re-wrap job
    (security-model.md 4.4, 5.1)."""
    from ovlm.connections import validation

    registry.register(validation.validation_definition(validation.CredentialValidator(store)))
    registry.periodic.append(validation.validation_job(settings.kek.validation_interval))
    if settings.kek.previous_private_key_files:
        registry.register(validation.rewrap_definition(store))
        registry.periodic.append(validation.rewrap_job(settings.kek.validation_interval))


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
            engine,
            build_registry(settings, engine),
            EngineConfig.from_settings(settings),
            audit=DbAuditSink(),
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
