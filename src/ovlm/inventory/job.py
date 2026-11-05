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
hold, a read client that cannot be built from it (review IS-8: a configuration error is not retried for ever), and
a token scoped to another project, are **recorded failures**: a ``failed`` ``sync_run``, the run ends ``failed``,
and nothing in the inventory changes.

What viewers see is a fixed code (:mod:`ovlm.inventory.reasons`, review IS-4): ``sync_run.error`` is
``{"code": ...}`` and the step's failure reason is the code. The redacted reason text goes to the worker log and the
step error's ``detail`` only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any, ClassVar, Protocol
from uuid import UUID

from sqlalchemy import Engine, func, insert, select, text, update

from ovlm.inventory import reasons as rc
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
    """No usable read client; the message never carries secret material (still kept out of what viewers see).
    ``code`` is the reason code (:mod:`ovlm.inventory.reasons`)."""

    def __init__(self, message: str, code: str = rc.CREDENTIAL_UNAVAILABLE) -> None:
        super().__init__(message)
        self.code = code


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
        try:  # a database error here stays retryable (the engine's classify)
            cred = self.store.app_credential(project_connection_id, "os_read")
        except (
            CredentialUnavailableError
        ) as exc:  # missing, failed validation, expired, rebound, key missing
            raise CredentialRefusedError(str(exc)[:300]) from None
        try:
            client = connect(
                cred, self.store.ca_path(cred.connection), process_role=self.process_role
            )
        except CredentialUnavailableError as exc:
            raise CredentialRefusedError(str(exc)[:300]) from None
        except Exception as exc:  # noqa: BLE001 - IS-8: building the client sends nothing (a bad CA file, a
            # configuration error): retrying cannot help, so it is a recorded failure, not an endless retry.
            raise CredentialRefusedError(
                f"the read client could not be set up: {type(exc).__name__}: {redact_text(str(exc))}"[
                    :300
                ],
                rc.CLIENT_SETUP_FAILED,
            ) from None
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
    code: str,
    message: str,
    config: SyncConfig,
) -> UUID:
    """A ``failed`` ``sync_run`` that changed nothing: the sync could not start (credential, project check).
    The record carries the code only; the redacted ``message`` is logged (IS-4)."""
    sync_id = uuid7()
    with engine.begin() as c:
        now = c.execute(select(func.now())).scalar_one()
    kind, _ = choose_kind(engine, project, now, config)
    error = {"code": code}
    with engine.begin() as c:
        c.execute(
            insert(sync_run).values(
                id=sync_id, project_connection_id=project, kind=kind, status="failed", started_at=now,
                finished_at=now, error=error, workflow_run_id=UUID(run_id) if run_id else None,
            )
        )  # fmt: skip
    log.warning(
        "inventory sync refused",
        extra={"sync_run_id": str(sync_id), "project_connection_id": str(project), "code": code,
               "reason": redact_text(message)[:500]},
    )  # fmt: skip
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
                        error={"code": rc.INTERRUPTED},
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
) -> tuple[str, str | None, str | None]:
    """One sync of one project connection with its read credential. Returns ``(status, code, reason)``:
    ``status`` is ``succeeded`` or ``failed``, ``code`` the reason code (:mod:`ovlm.inventory.reasons`) and
    ``reason`` the redacted text (worker log and step error detail only). Raises :class:`SyncAlreadyRunningError`
    when another sync holds the lock."""
    project = UUID(project_connection_id)
    try:
        client, expected = access.open(project_connection_id)
    except CredentialRefusedError as exc:
        record_refusal(engine, project, workflow_run_id, exc.code, str(exc), config)
        return "failed", exc.code, str(exc)
    try:
        actual = client.project_id()
    except Exception as exc:  # noqa: BLE001 - Keystone said no, or could not be reached: a recorded failure
        reason = f"the read credential could not obtain a token: {type(exc).__name__}: {redact_text(str(exc))}"
        record_refusal(engine, project, workflow_run_id, rc.AUTH_FAILED, reason, config)
        return "failed", rc.AUTH_FAILED, reason[:300]
    if normalise_project_id(actual) != normalise_project_id(expected):
        reason = (
            f"the read credential's token is scoped to OpenStack project {normalise_project_id(actual)!r}, "
            f"not to this connection's project {normalise_project_id(expected)!r}: nothing was synced"
        )
        record_refusal(engine, project, workflow_run_id, rc.PROJECT_MISMATCH, reason, config)
        return "failed", rc.PROJECT_MISMATCH, reason
    result = run_inventory_sync(
        engine, client, project, config=config,
        workflow_run_id=UUID(workflow_run_id) if workflow_run_id else None,
    )  # fmt: skip
    if result.status == "succeeded":
        return "succeeded", None, None
    err = result.error or {}
    return "failed", str(err.get("code") or rc.CLOUD_ERROR), err.get("message")


# --- workflow definitions -------------------------------------------------------------------------------------------


def _outcome(row: Any, message: str | None = None) -> Outcome:
    """The run's outcome from its finished ``sync_run``. A failure's reason is the code viewers see (IS-4); the
    redacted text, when this attempt has it, goes to the step error's detail only."""
    if row.status == "succeeded":
        totals = {res: c.get("seen", 0) for res, c in (row.counts or {}).items()}
        return Done({"sync_run_id": str(row.id), "kind": row.kind, "seen": totals})
    code = (rc.public_error(row.error) or {}).get("code", rc.OTHER)
    detail: dict[str, Any] = {"sync_run_id": str(row.id)}
    if message:
        detail["message"] = redact_text(message)[:500]
    return Fail(ErrorClass.FATAL, code, detail)


class SyncStep(Step):
    key: ClassVar[str] = SYNC

    def __init__(self, engine: Engine, access: ReadAccess, config: SyncConfig) -> None:
        self.engine, self.access, self.config = engine, access, config
        #: run id -> the redacted reason of the attempt that just acted (act -> verify, same attempt).
        self._reasons: dict[str, str | None] = {}

    def probe(self, ctx: StepContext) -> Any:
        return _sync_rows(self.engine, ctx.run.id)

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        pc = ctx.run.subject.get("project_connection_id")
        if not pc:
            return Fail(ErrorClass.FATAL, "no_project_connection")
        finished = [r for r in observed if r.status in ("succeeded", "failed")]
        if finished:  # a previous attempt finished the sync: its outcome is the run's
            return _outcome(finished[0], (ctx.previous_evidence or {}).get("reason"))
        return Act({"project_connection_id": pc, "interrupted": bool(observed)})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        pc = str(intent["project_connection_id"])
        if intent.get("interrupted"):
            close_interrupted(self.engine, UUID(pc), ctx.run.id)
        ctx.gate("inventory:sync")
        status, code, reason = sync_project(
            self.engine, self.access, pc, config=self.config, workflow_run_id=ctx.run.id
        )
        # evidence is the step's own record (not served to viewers); the redacted reason is kept for verify
        ctx.checkpoint(evidence={"status": status, "code": code, "reason": reason})
        self._reasons[ctx.run.id] = reason

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        finished = [r for r in self.probe(ctx) if r.status in ("succeeded", "failed")]
        if not finished:
            return Fail(ErrorClass.RETRYABLE, "the sync left no finished record")
        return _outcome(finished[0], self._reasons.pop(ctx.run.id, None))

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        if isinstance(exc, SyncAlreadyRunningError):
            return Fail(ErrorClass.RETRYABLE, rc.SYNC_ALREADY_RUNNING)
        log.warning(
            "inventory sync attempt failed",
            extra={
                "run_id": ctx.run.id,
                "error": f"{type(exc).__name__}: {redact_text(str(exc))}"[:500],
            },
        )
        return Fail(
            ErrorClass.RETRYABLE, rc.WORKER_ERROR,
            {"message": f"{type(exc).__name__}: {redact_text(str(exc))}"[:500]},
        )  # fmt: skip


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
            return Reject("no_project_connection")
        row = ctx.conn.execute(
            text("SELECT enabled FROM project_connection WHERE id = CAST(:p AS uuid)"),
            {"p": str(pc)},
        ).first()
        if row is None:
            return Reject("project_not_found")
        if not row.enabled:
            return Reject("project_disabled")
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
