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
from collections.abc import Callable
from pathlib import Path
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
#: Sweep the checkouts (run_root and checkout cache) of finished runs about this often (seconds; also once at
#: start-up and after each step this worker executes, for that step's run).
CACHE_SWEEP_SECONDS = 3600.0


def _as_uuid(value: str) -> uuid.UUID | None:
    """``value`` as a run id (canonical UUID text, as the run directories are named), else ``None``."""
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value else None


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
        self._sweep_checkouts()

    def _sweep_checkouts(self, run_id: str | None = None) -> None:
        """Remove the run-level checkouts on ``automation.run_root`` (tmpfs: RAM) and their copies in
        ``automation.checkout_cache`` (persistent) of runs that are terminal or unknown (roadmap P0-1, lab finding Z).

        Without ``run_id`` (start-up and every ``CACHE_SWEEP_SECONDS``): a non-terminal run keeps both whatever their
        age (it may wait days at a gate, and the cache copy is what a restarted container re-adopts); a run read
        terminal in the database loses them at once (terminal is final: no step of it can run again); an entry of no
        known run only once older than the orphan max age (a run admitted after the active runs were read is not
        swept). With ``run_id`` (after each step this worker executed): only that run's, and only if the database
        says it is terminal, whoever committed that and whatever this attempt's fate (fenced or not). Each worker
        sweeps its own ``run_root``. Skipped when the runs cannot be read. Never fatal."""
        from ovlm.automation.config import orphan_max_age, runner_config
        from ovlm.automation.runner import sweep_checkout_cache, sweep_run_root_checkouts
        from ovlm.workflow.contract import TERMINAL_RUN_STATES

        a = self.settings.automation
        sweeps: list[tuple[Path, Callable[..., list[Path]]]] = [
            (a.run_root, sweep_run_root_checkouts)
        ]
        if a.checkout_cache is not None:
            sweeps.append((a.checkout_cache, sweep_checkout_cache))
        states = sorted(TERMINAL_RUN_STATES)
        removed: list[Path] = []
        try:
            if run_id is not None:
                if _as_uuid(run_id) is None or not any(
                    (root / run_id).is_dir() for root, _sweep in sweeps
                ):
                    return
                with self.engine.connect() as conn:
                    terminal = (
                        conn.execute(
                            text(
                                "SELECT 1 FROM workflow_run WHERE id = CAST(:i AS uuid) AND state = ANY(:t)"
                            ),
                            {"i": run_id, "t": states},
                        ).first()
                        is not None
                    )
                if not terminal:
                    return
                for root, sweep in sweeps:
                    removed += sweep(root, float("inf"), keep=(), terminal={run_id})
            else:
                names = {e.name for root, _sweep in sweeps if root.is_dir() for e in root.iterdir()}
                if not names:
                    return
                ids = sorted(n for n in names if _as_uuid(n) is not None)
                with self.engine.connect() as conn:
                    active = {
                        str(r[0])
                        for r in conn.execute(
                            text("SELECT id FROM workflow_run WHERE NOT (state = ANY(:t))"),
                            {"t": states},
                        )
                    }
                    finished = (
                        {
                            str(r[0])
                            for r in conn.execute(
                                text(
                                    "SELECT id FROM workflow_run WHERE id = ANY(CAST(:ids AS uuid[])) "
                                    "AND state = ANY(:t)"
                                ),
                                {"ids": ids, "t": states},
                            )
                        }
                        if ids
                        else set()
                    )
                max_age = orphan_max_age(runner_config(self.settings))
                for root, sweep in sweeps:
                    removed += sweep(root, max_age, keep=active, terminal=finished)
        except Exception:
            log.exception("checkout sweep failed")
            return
        if removed:
            log.info("removed checkouts of finished runs", extra={"count": len(removed)})

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
        if (
            self._iterations
            and self._iterations
            % max(1, int(CACHE_SWEEP_SECONDS / self.settings.worker.heartbeat_interval))
            == 0
        ):
            self._sweep_checkouts()
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
        # the run's last step: free its checkout now rather than at the next periodic sweep (roadmap P0-1)
        self._sweep_checkouts(claim.run.id)

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
