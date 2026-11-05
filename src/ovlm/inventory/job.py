"""The ``inventory_sync`` workflow (worker only): sync one project connection with its **read** credential.

A single-step run, requested by ``POST /api/v1/projects/{id}/syncs`` or by the periodic job (:mod:`.requests`).
The step follows the step contract, so a crash at any point is safe to retry:

* ``probe``   the ``sync_run`` rows this run already wrote (``sync_run.workflow_run_id``)
* ``decide``  a finished one: its outcome (``Done``, or ``Fail`` with the recorded reason); otherwise ``Act``
* ``act``     open the guarded read client from the credential store (worker side only), check that the token's
              project is the connection's ``openstack_project_id``, then :func:`~ovlm.inventory.sync.
              run_inventory_sync` under the **real** ``project_connection_id`` (full or servers delta, as
              ``choose_kind`` decides)
* ``verify``  the ``sync_run`` of this run is finished

Credentials (security-model.md 4.1, 5.1): only the connection's active, validated, unexpired ``os_read``
application credential bound to the connection's current endpoint is used (:meth:`CredentialStore.app_credential`:
``usable_row`` and the binding checks of the renewal path). It is decrypted in memory, registered with the log
redaction backstop before any client sees it, and handed to :func:`~ovlm.connections.credentials.
connect_read_credential` (no ``clouds.yaml``, TLS verified, GET/HEAD guard installed before any request). Its
``requests`` session reads ``HTTPS_PROXY``/``NO_PROXY`` like the renewal's write session (install-guide.md 5a).

A credential that is missing, invalid, expired, bound to another endpoint or sealed to a key this worker does not
hold, and a token scoped to another project, are **recorded failures**: a ``failed`` ``sync_run`` with a safe
reason (no secret), the run ends ``failed`` with the same reason, and nothing in the inventory changes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any, ClassVar, Protocol
from uuid import UUID

from sqlalchemy import Engine, func, insert, select, text, update

from ovlm.inventory import requests as req
from ovlm.inventory.ids import uuid7
from ovlm.inventory.sync import (
    SyncAlreadyRunningError,
    SyncConfig,
    _lock_key,
    choose_kind,
    run_inventory_sync,
)
from ovlm.inventory.tables import sync_run
from ovlm.observability.redaction import redact_text
from ovlm.openstack.interface import ReadClient
from ovlm.workflow.contract import (
    Act,
    Admission,
    Decision,
    Defer,
    Done,
    ErrorClass,
    Fail,
    Outcome,
    Reject,
    Step,
    StepContext,
    StepSpec,
    Transition,
    TxContext,
    WorkflowDefinition,
)
from ovlm.workflow.registry import PeriodicJob

log = logging.getLogger("ovlm.inventory.job")

SYNC = "sync"
SCHEDULE = "schedule"

NO_STORE_REASON = (
    "this worker has no credential store key (kek.private_key_file), so it cannot read the project's read "
    "credential (security-model.md 5.1)"
)


class CredentialRefusedError(Exception):
    """No usable read credential; the message is safe to show (it never carries secret material)."""


class ReadAccess(Protocol):
    def open(self, project_connection_id: str) -> tuple[ReadClient, str]:
        """``(guarded read client, the connection's openstack_project_id)``. Raises :class:`CredentialRefusedError`
        with a safe reason when the connection has no usable read credential."""
        ...


class StoreReadAccess:
    """The production :class:`ReadAccess`: the encrypted credential store, worker side."""

    def __init__(
        self, store: Any, *, process_role: str = "worker", connect: Callable[..., Any] | None = None
    ) -> None:
        self.store = store
        self.process_role = process_role
        #: ``connect_read_credential`` in production; tests pass a double that returns the fake cloud.
        self.connect = connect

    def open(self, project_connection_id: str) -> tuple[ReadClient, str]:
        from ovlm.connections.credentials import CredentialUnavailableError, connect_read_credential

        connect = self.connect or connect_read_credential
        try:
            cred = self.store.app_credential(project_connection_id, "os_read")
            client = connect(
                cred, self.store.ca_path(cred.connection), process_role=self.process_role
            )
        except (
            CredentialUnavailableError
        ) as exc:  # missing, failed validation, expired, rebound, key missing
            raise CredentialRefusedError(str(exc)[:300]) from None
        return client, cred.connection.openstack_project_id


class NoReadAccess:
    """No KEK configured: every sync fails with :data:`NO_STORE_REASON`."""

    def open(self, project_connection_id: str) -> tuple[ReadClient, str]:
        raise CredentialRefusedError(NO_STORE_REASON)


def normalise_project_id(value: str | None) -> str:
    return (value or "").strip().lower().replace("-", "")


def _sync_rows(engine: Engine, run_id: str) -> list[Any]:
    with engine.connect() as c:
        return list(
            c.execute(
                select(
                    sync_run.c.id,
                    sync_run.c.status,
                    sync_run.c.error,
                    sync_run.c.counts,
                    sync_run.c.kind,
                )
                .where(sync_run.c.workflow_run_id == UUID(run_id))
                .order_by(sync_run.c.started_at.desc(), sync_run.c.id.desc())
            ).all()
        )


def record_refusal(
    engine: Engine,
    project: UUID,
    run_id: str | None,
    error_type: str,
    message: str,
    config: SyncConfig,
) -> UUID:
    """A ``failed`` ``sync_run`` that changed nothing: the sync could not start (credential, project check)."""
    sync_id = uuid7()
    with engine.begin() as c:
        now = c.execute(select(func.now())).scalar_one()
    kind, _ = choose_kind(engine, project, now, config)
    error = {"type": error_type, "message": redact_text(message)[:500]}
    with engine.begin() as c:
        c.execute(
            insert(sync_run).values(
                id=sync_id, project_connection_id=project, kind=kind, status="failed", started_at=now,
                finished_at=now, error=error, workflow_run_id=UUID(run_id) if run_id else None,
            )
        )  # fmt: skip
    log.warning(
        "inventory sync refused",
        extra={"sync_run_id": str(sync_id), "project_connection_id": str(project), "error": error},
    )
    return sync_id


def close_interrupted(engine: Engine, project: UUID, run_id: str) -> int:
    """Mark ``failed`` the ``running`` sync rows of this run left by a crashed attempt. Only when nobody holds the
    project's sync lock (a live attempt elsewhere keeps its row)."""
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
        if not c.execute(select(func.pg_try_advisory_lock(_lock_key(project)))).scalar():
            return 0
        try:
            return int(
                c.execute(
                    update(sync_run)
                    .where(
                        sync_run.c.workflow_run_id == UUID(run_id), sync_run.c.status == "running"
                    )
                    .values(
                        status="failed",
                        finished_at=func.now(),
                        error={
                            "type": "Interrupted",
                            "message": "the worker stopped during the sync",
                        },
                    )
                ).rowcount
            )
        finally:
            c.execute(select(func.pg_advisory_unlock(_lock_key(project))))


def sync_project(
    engine: Engine,
    access: ReadAccess,
    project_connection_id: str,
    *,
    config: SyncConfig,
    workflow_run_id: str | None = None,
) -> tuple[str, str | None]:
    """One sync of one project connection with its read credential. Returns ``(status, reason)``; ``status`` is
    ``succeeded`` or ``failed``. Raises :class:`SyncAlreadyRunningError` when another sync holds the lock."""
    project = UUID(project_connection_id)
    try:
        client, expected = access.open(project_connection_id)
    except CredentialRefusedError as exc:
        record_refusal(engine, project, workflow_run_id, "CredentialUnavailable", str(exc), config)
        return "failed", str(exc)
    try:
        actual = client.project_id()
    except Exception as exc:  # noqa: BLE001 - Keystone said no, or could not be reached: a recorded failure
        reason = f"the read credential could not obtain a token: {type(exc).__name__}: {redact_text(str(exc))}"
        record_refusal(engine, project, workflow_run_id, "AuthenticationFailed", reason, config)
        return "failed", reason[:300]
    if normalise_project_id(actual) != normalise_project_id(expected):
        reason = (
            f"the read credential's token is scoped to OpenStack project {normalise_project_id(actual)!r}, "
            f"not to this connection's project {normalise_project_id(expected)!r}: nothing was synced"
        )
        record_refusal(engine, project, workflow_run_id, "ProjectMismatch", reason, config)
        return "failed", reason
    result = run_inventory_sync(
        engine, client, project, config=config,
        workflow_run_id=UUID(workflow_run_id) if workflow_run_id else None,
    )  # fmt: skip
    if result.status == "succeeded":
        return "succeeded", None
    return "failed", (result.error or {}).get("message")


# --- workflow definitions -------------------------------------------------------------------------------------------


def _outcome(row: Any) -> Outcome:
    if row.status == "succeeded":
        totals = {res: c.get("seen", 0) for res, c in (row.counts or {}).items()}
        return Done({"sync_run_id": str(row.id), "kind": row.kind, "seen": totals})
    err = row.error or {}
    reason = f"{err.get('type', 'Error')}: {err.get('message', '')}"[:500]
    return Fail(ErrorClass.FATAL, reason, {"sync_run_id": str(row.id)})


class SyncStep(Step):
    key: ClassVar[str] = SYNC

    def __init__(self, engine: Engine, access: ReadAccess, config: SyncConfig) -> None:
        self.engine, self.access, self.config = engine, access, config

    def probe(self, ctx: StepContext) -> Any:
        return _sync_rows(self.engine, ctx.run.id)

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        pc = ctx.run.subject.get("project_connection_id")
        if not pc:
            return Fail(ErrorClass.FATAL, "the run names no project connection")
        finished = [r for r in observed if r.status in ("succeeded", "failed")]
        if finished:  # a previous attempt finished the sync: its outcome is the run's
            return _outcome(finished[0])
        return Act({"project_connection_id": pc, "interrupted": bool(observed)})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        pc = str(intent["project_connection_id"])
        if intent.get("interrupted"):
            close_interrupted(self.engine, UUID(pc), ctx.run.id)
        ctx.gate("inventory:sync")
        status, reason = sync_project(
            self.engine, self.access, pc, config=self.config, workflow_run_id=ctx.run.id
        )
        ctx.checkpoint(evidence={"status": status, "reason": reason})

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        finished = [r for r in self.probe(ctx) if r.status in ("succeeded", "failed")]
        if not finished:
            return Fail(ErrorClass.RETRYABLE, "the sync left no finished record")
        return _outcome(finished[0])

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        if isinstance(exc, SyncAlreadyRunningError):
            return Fail(ErrorClass.RETRYABLE, "another sync of this project is running")
        return Fail(ErrorClass.RETRYABLE, f"{type(exc).__name__}: {redact_text(str(exc))}"[:500])


class InventorySyncDefinition(WorkflowDefinition):
    kind: ClassVar[str] = req.KIND
    strategy: ClassVar[str] = req.STRATEGY
    version: ClassVar[str] = req.STRATEGY_VERSION

    def __init__(
        self, engine: Engine, access: ReadAccess, config: SyncConfig | None = None
    ) -> None:
        self._steps = {SYNC: SyncStep(engine, access, config or SyncConfig())}

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        pc = ctx.run.subject.get("project_connection_id")
        if not pc:
            return Reject("the run names no project connection")
        row = ctx.conn.execute(
            text("SELECT enabled FROM project_connection WHERE id = CAST(:p AS uuid)"),
            {"p": str(pc)},
        ).first()
        if row is None:
            return Reject("no such project connection")
        if not row.enabled:
            return Reject("the project connection is disabled")
        return Admission(StepSpec(SYNC))

    def next(self, ctx: TxContext, done: Done) -> Transition:
        return Transition(run_state="completed")

    def validate_signal(self, ctx: TxContext) -> str | None:
        return "inventory syncs accept no signals"


class ScheduleStep(Step):
    """The periodic job: queue a sync for every eligible connection that has none queued or running."""

    key: ClassVar[str] = SCHEDULE

    def __init__(
        self, engine: Engine, eligible: Callable[[Any], list[str]] = req.eligible_connections
    ) -> None:
        self.engine, self.eligible = engine, eligible

    def probe(self, ctx: StepContext) -> Any:
        return None

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Act({SCHEDULE: True})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        ctx.gate("inventory:schedule")
        counts = enqueue_periodic(self.engine, self.eligible)
        ctx.checkpoint(evidence={"counts": counts})

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Done({})


def enqueue_periodic(
    engine: Engine, eligible: Callable[[Any], list[str]] = req.eligible_connections
) -> dict[str, int]:
    """Queue one sync per eligible connection; skip a connection whose sync is queued or running. One short
    transaction per connection (each takes the connection's request lock)."""
    with engine.connect() as c:
        connections = eligible(c)
    counts = {"queued": 0, "already_pending": 0}
    for pc in connections:
        with engine.begin() as c:
            _, created = req.request_sync(c, pc, requested_by=None, origin="periodic")
        counts["queued" if created else "already_pending"] += 1
    return counts


class InventorySyncScheduleDefinition(WorkflowDefinition):
    kind: ClassVar[str] = req.SCHEDULE_KIND
    strategy: ClassVar[str] = req.SCHEDULE_STRATEGY
    version: ClassVar[str] = "1"

    def __init__(self, engine: Engine) -> None:
        self._steps = {SCHEDULE: ScheduleStep(engine)}

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        return Admission(StepSpec(SCHEDULE))

    def next(self, ctx: TxContext, done: Done) -> Transition:
        return Transition(run_state="completed")

    def validate_signal(self, ctx: TxContext) -> str | None:
        return "this job takes no signals"


def periodic_job(interval: float) -> PeriodicJob:
    return PeriodicJob(
        kind=req.SCHEDULE_KIND, strategy=req.SCHEDULE_STRATEGY, version="1", interval=interval
    )


def sync_config(settings: Any) -> SyncConfig:
    from datetime import timedelta

    inv = settings.inventory
    return SyncConfig(
        gone_after_missed_syncs=inv.gone_after_missed_syncs,
        full_sync_every=timedelta(seconds=inv.full_sync_every),
    )
