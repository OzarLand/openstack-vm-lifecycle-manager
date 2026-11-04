"""Fixtures for engine tests against a real PostgreSQL (migrated database, worker/api/admin connections)."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy import event as sa_event
from sqlalchemy.engine import URL

from ovlm.workflow import crashpoint
from ovlm.workflow.audit import AuditEvent
from ovlm.workflow.clock import Clock, FakeClock
from ovlm.workflow.engine import EngineConfig, WorkflowEngine
from ovlm.workflow.ids import new_id
from ovlm.workflow.registry import Registry
from ovlm.workflow.requests import request_run, send_signal
from tests.integration.conftest import API_PW, WORKER_PW, role_url
from tests.integration.test_migrations import migrate
from tests.integration.workflow import dummy

TEST_CONFIG = EngineConfig(
    lease_duration=30.0,
    heartbeat_interval=0.2,
    fence_margin=5.0,
    takeover_delay=7.0,
    poll_initial=0.0,
    poll_max=0.0,
    retry_max_attempts=3,
    retry_backoff_initial=0.0,
    retry_backoff_max=0.0,
    watchdog_interval=0.05,  # fake clocks do not move with real time: poll the fence often
)


class RecordingAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def record(self, conn: Connection, event: AuditEvent) -> None:
        """Keep the event only if the engine's transaction commits (a rolled-back effect has no audit)."""

        def _on_commit(_conn: Connection) -> None:
            with self._lock:
                self.events.append(event)

        sa_event.listen(conn, "commit", _on_commit, once=True)

    def actions(self) -> list[str]:
        return [e.action for e in self.events]


@dataclass
class WfDb:
    name: str
    admin: Engine
    worker_url: URL
    api_url: URL
    engines: list[Engine] = field(default_factory=list)

    def worker_db(self) -> Engine:
        eng = create_engine(self.worker_url, pool_pre_ping=True, pool_size=10, max_overflow=10)
        self.engines.append(eng)
        return eng

    def api_db(self) -> Engine:
        eng = create_engine(self.api_url)
        self.engines.append(eng)
        return eng

    def make_engine(
        self,
        *,
        clock: Clock | None = None,
        config: EngineConfig = TEST_CONFIG,
        cap: int | None = None,
        version: str | None = None,
        resumes: frozenset[str] = frozenset(),
        audit: RecordingAudit | None = None,
        worker_id: str | None = None,
    ) -> WorkflowEngine:
        db = self.worker_db()
        wid = worker_id or new_id()
        defn = dummy.DummyDefinition(db, wid, cap=cap, version=version, resumes=resumes)
        return WorkflowEngine(
            db,
            Registry([defn]),
            config,
            worker_id=wid,
            clock=clock or FakeClock(),
            audit=audit or RecordingAudit(),
        )

    # -- helpers ------------------------------------------------------------------------------------------

    def q(self, sql: str, **params: Any) -> list[Any]:
        with self.admin.connect() as c:
            return list(c.execute(text(sql), params).mappings().all())

    def one(self, sql: str, **params: Any) -> Any:
        rows = self.q(sql, **params)
        assert len(rows) == 1, rows
        return rows[0]

    def x(self, sql: str, **params: Any) -> int:
        with self.admin.begin() as c:
            return c.execute(text(sql), params).rowcount

    def request(self, plan: list[dict[str, Any]], **subject: Any) -> str:
        with self.api_db().begin() as c:  # inserted as ovlm_api, like the real api
            return request_run(
                c,
                kind="probe",
                strategy="dummy",
                strategy_version=str(subject.pop("version", "1")),
                subject={"plan": plan, **subject},
                started_by=None,
            )

    def signal(self, run_id: str, kind: str, **payload: Any) -> str:
        with self.api_db().begin() as c:
            return send_signal(c, run_id, kind, actor_id=new_id(), payload=payload)

    def expire_leases(self) -> int:
        """Stand-in for time passing beyond ``lease_expires_at`` (DB clock): the lease is moved back."""
        return self.x(
            "UPDATE workflow_step SET lease_expires_at = now() - interval '1 second' WHERE state = 'running'"
        )

    def run(self, run_id: str) -> Any:
        return self.one("SELECT * FROM workflow_run WHERE id = :id", id=run_id)

    def steps(self, run_id: str) -> list[Any]:
        return self.q("SELECT * FROM workflow_step WHERE run_id = :id ORDER BY seq", id=run_id)

    def attempts(self, run_id: str) -> list[Any]:
        return self.q(
            "SELECT a.*, s.step_key FROM workflow_step_attempt a JOIN workflow_step s ON s.id = a.step_id "
            "WHERE s.run_id = :id ORDER BY s.seq, a.attempt",
            id=run_id,
        )

    def effects(self, key: str | None = None) -> list[Any]:
        if key is None:
            return self.q("SELECT * FROM fake_effect ORDER BY id")
        return self.q("SELECT * FROM fake_effect WHERE key = :k ORDER BY id", k=key)

    def resource(self, key: str) -> str | None:
        rows = self.q("SELECT value FROM fake_resource WHERE key = :k", k=key)
        return rows[0]["value"] if rows else None

    def locks(self, run_id: str | None = None) -> list[tuple[str, str]]:
        sql = "SELECT resource_type, resource_key FROM resource_lock"
        rows = self.q(
            sql + (" WHERE holder_run_id = :id" if run_id else "") + " ORDER BY 1, 2", id=run_id
        )
        return [(r["resource_type"], r["resource_key"]) for r in rows]


def assert_open_step_invariant(wf: WfDb) -> None:
    """Engine invariant (SRE-C-1): a run in ``needs_human`` has exactly one open step, itself in
    ``needs_human``, so retry-step and mark-resolved always have a target."""
    bad = wf.q(
        "SELECT r.id, r.needs_human_reason, "
        "  (SELECT count(*) FROM workflow_step s WHERE s.run_id = r.id "
        "     AND s.state IN ('ready', 'running', 'waiting', 'needs_human')) AS open_steps, "
        "  (SELECT count(*) FROM workflow_step s WHERE s.run_id = r.id AND s.state = 'needs_human') AS nh "
        "FROM workflow_run r WHERE r.state = 'needs_human'"
    )
    bad = [dict(b) for b in bad if b["open_steps"] != 1 or b["nh"] != 1]
    assert not bad, f"runs in needs_human without exactly one open needs_human step: {bad}"


def drive(engine: WorkflowEngine, run_id: str, wf: WfDb, max_passes: int = 100) -> Any:
    """Run synchronous passes until the run is terminal or parked (needs_human / waiting on a signal)."""
    for _ in range(max_passes):
        did = engine.run_once()
        r = wf.run(run_id)
        if r["state"] in (
            "completed",
            "rejected",
            "cancelled",
            "failed",
            "rolled_back",
            "needs_human",
        ):
            return r
        if not did and r["state"] == "running":
            open_steps = [
                s for s in wf.steps(run_id) if s["state"] in ("ready", "running", "waiting")
            ]
            if (
                open_steps
                and open_steps[0]["state"] == "waiting"
                and open_steps[0]["not_before"] is None
            ):
                return r  # parked until a signal
    return wf.run(run_id)


@pytest.fixture
def wf(admin_url: URL, fresh_db: str, secrets_dir: Path) -> Iterator[WfDb]:
    migrate(admin_url, fresh_db, secrets_dir)
    admin = create_engine(admin_url.set(database=fresh_db))
    with admin.begin() as c:
        for stmt in dummy.FAKE_SCHEMA.strip().split(";"):
            if stmt.strip():
                c.execute(text(stmt))
    db = WfDb(
        name=fresh_db,
        admin=admin,
        worker_url=role_url(admin_url, fresh_db, "ovlm_worker", WORKER_PW),
        api_url=role_url(admin_url, fresh_db, "ovlm_api", API_PW),
    )
    dummy.BLOCKERS.clear()
    dummy.REVOKED.clear()
    try:
        yield db
        assert_open_step_invariant(db)
    finally:
        crashpoint.install(None)
        crashpoint.record(None)
        for ev in dummy.BLOCKERS.values():
            ev.set()
        for eng in db.engines:
            eng.dispose()
        admin.dispose()


@pytest.fixture
def plan3() -> Callable[[], list[dict[str, Any]]]:
    """A three-step plan: set, async wait, destructive set."""

    def make() -> list[dict[str, Any]]:
        return [
            dummy.plan_step("set", res="a", value="A"),
            dummy.plan_step("async", res="b", value="B", polls=2),
            dummy.plan_step("set_destructive", res="c", value="C"),
        ]

    return make


def dumps(x: Any) -> str:
    return json.dumps(x, sort_keys=True, default=str)
