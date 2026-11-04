"""Inventory sync against a real PostgreSQL, with the fake OpenStack (testing-strategy.md L2)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from sqlalchemy import Engine, func, select, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import ProgrammingError

from ovlm.db.engine import make_engine
from ovlm.db.schema import alembic_config
from ovlm.inventory import sync as inv_sync
from ovlm.inventory.sync import SyncAlreadyRunningError, SyncConfig, run_inventory_sync
from ovlm.inventory.tables import OBSERVED, RESOURCES, REVISIONS, metadata, sync_run
from ovlm.openstack.errors import OpenStackError
from ovlm.openstack.fake import FakeOpenStack
from tests.integration.conftest import settings_for


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += timedelta(**kw)


@pytest.fixture
def worker_engine(admin_url: URL, fresh_db: str, secrets_dir: Path) -> Iterator[Engine]:
    s = settings_for("migrate", admin_url, fresh_db, secrets_dir)
    command.upgrade(alembic_config(s.migrations_dir, s.db_url()), "inventory_0001")
    engine = make_engine(settings_for("worker", admin_url, fresh_db, secrets_dir))
    yield engine
    engine.dispose()


@pytest.fixture
def project() -> UUID:
    return uuid4()


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _world(clock: Clock | None = None) -> tuple[FakeOpenStack, dict[str, str]]:
    """The fake shares the sync clock's timeline (both are wall clocks in real life)."""
    fake = FakeOpenStack(now=clock.t if clock else None)
    ext = fake.add_network("ext", external=True)
    net = fake.add_network("tenant")
    fake.add_image("ubuntu")
    fake.add_flavor("m1.small")
    srv = fake.add_server("blue", tags=["ovlm:managed"])
    other = fake.add_server("other")
    vol = fake.add_volume("data")
    fake.attach_volume(srv, vol)
    fake.tick(30)
    if clock:
        clock.advance(seconds=30)
    port = fake.add_port(net, device_id=srv)
    fip = fake.add_floating_ip(ext)
    return fake, {"srv": srv, "other": other, "vol": vol, "port": port, "fip": fip}


def _rows(engine: Engine, resource: str) -> dict[str, dict[str, object]]:
    t = OBSERVED[resource]
    with engine.connect() as c:
        return {r.openstack_id: dict(r._mapping) for r in c.execute(select(t))}


def _revisions(engine: Engine, resource: str) -> int:
    query = f"SELECT count(*) FROM observed_{resource}_revision"  # noqa: S608 - fixed table names
    with engine.connect() as c:
        return int(c.execute(text(query)).scalar_one())


CFG = SyncConfig(gone_after_missed_syncs=3)


def test_full_sync_populates_every_resource_with_snapshots(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, ids = _world()
    result = run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    assert result.status == "succeeded" and result.kind == "full"
    assert result.versions["compute_used"] == "2.100"
    assert {r: result.counts[r]["created"] for r in RESOURCES} == {
        "server": 2, "volume": 1, "volume_attachment": 1, "port": 1, "floating_ip": 1,
        "network": 2, "image": 1, "flavor": 1,
    }  # fmt: skip
    servers = _rows(worker_engine, "server")
    blue = servers[ids["srv"]]
    assert (
        blue["name"] == "blue" and blue["server_status"] == "ACTIVE" and blue["status"] == "present"
    )
    assert (
        blue["tags"] == ["ovlm:managed"]
        and blue["synced_at"] == clock.t
        and blue["missed_syncs"] == 0
    )
    att = _rows(worker_engine, "volume_attachment")[f"{ids['srv']}:{ids['vol']}"]
    assert att["delete_on_termination"] is False and att["device"] == "/dev/vdb"
    assert _rows(worker_engine, "floating_ip")[ids["fip"]]["floating_ip_address"] == "192.0.2.10"
    assert all(
        _revisions(worker_engine, r) == result.counts[r]["created"] for r in RESOURCES
    )  # first snapshots
    with worker_engine.connect() as c:
        run = c.execute(select(sync_run)).one()
    assert run.status == "succeeded" and run.kind == "full" and run.finished_at == clock.t
    assert run.versions["compute_max"] == "2.100" and run.error is None


def test_unchanged_resync_adds_no_revisions_but_changes_add_one(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, ids = _world()
    run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    before = _revisions(worker_engine, "server")
    clock.advance(minutes=10)
    again = run_inventory_sync(worker_engine, fake, project, kind="full", config=CFG, clock=clock)
    assert again.counts["server"]["unchanged"] == 2 and again.counts["server"]["changed"] == 0
    assert _revisions(worker_engine, "server") == before
    assert _rows(worker_engine, "server")[ids["srv"]]["synced_at"] == clock.t  # seen again

    fake.lock_server(ids["srv"], "retention")  # someone locks it
    clock.advance(minutes=10)
    third = run_inventory_sync(worker_engine, fake, project, kind="full", config=CFG, clock=clock)
    assert third.counts["server"]["changed"] == 1
    assert _revisions(worker_engine, "server") == before + 1
    assert _rows(worker_engine, "server")[ids["srv"]]["locked"] is True


def test_vanished_resource_becomes_gone_after_n_full_syncs_and_is_never_deleted(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, ids = _world()
    run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    fake.keep_tombstones = False
    fake.delete_server(ids["other"])  # purged: no tombstone for a full listing to see
    fake.remove_volume(ids["vol"])  # Cinder has no tombstones

    for expected_missed in (1, 2):
        clock.advance(hours=1)
        run_inventory_sync(worker_engine, fake, project, kind="full", config=CFG, clock=clock)
        row = _rows(worker_engine, "server")[ids["other"]]
        assert (row["status"], row["missed_syncs"], row["gone_at"]) == (
            "present",
            expected_missed,
            None,
        )
    clock.advance(hours=1)
    third = run_inventory_sync(worker_engine, fake, project, kind="full", config=CFG, clock=clock)
    row = _rows(worker_engine, "server")[ids["other"]]
    assert (row["status"], row["missed_syncs"], row["gone_at"]) == ("gone", 3, clock.t)
    assert row["name"] == "other"  # still there, with its last known state
    assert third.counts["server"]["gone"] == 1 and third.counts["volume"]["gone"] == 1
    assert _rows(worker_engine, "volume")[ids["vol"]]["status"] == "gone"
    assert _rows(worker_engine, "server")[ids["srv"]]["status"] == "present"
    # the volume attachment disappeared with the volume
    assert (
        _rows(worker_engine, "volume_attachment")[f"{ids['srv']}:{ids['vol']}"]["status"] == "gone"
    )

    # a gone row is not touched again by later syncs
    clock.advance(hours=1)
    run_inventory_sync(worker_engine, fake, project, kind="full", config=CFG, clock=clock)
    assert _rows(worker_engine, "server")[ids["other"]]["missed_syncs"] == 3


def test_gone_resource_that_reappears_is_present_again(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, ids = _world()
    cfg = SyncConfig(gone_after_missed_syncs=1)
    run_inventory_sync(worker_engine, fake, project, config=cfg, clock=clock)
    fake.hide_server(ids["other"])
    clock.advance(hours=1)
    run_inventory_sync(worker_engine, fake, project, kind="full", config=cfg, clock=clock)
    assert _rows(worker_engine, "server")[ids["other"]]["status"] == "gone"
    fake.hide_server(ids["other"], hidden=False)
    clock.advance(hours=1)
    back = run_inventory_sync(worker_engine, fake, project, kind="full", config=cfg, clock=clock)
    row = _rows(worker_engine, "server")[ids["other"]]
    assert (row["status"], row["missed_syncs"], row["gone_at"]) == ("present", 0, None)
    assert back.counts["server"]["reappeared"] == 1


def test_failed_sync_changes_nothing_and_marks_nothing_gone(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, ids = _world()
    run_inventory_sync(
        worker_engine, fake, project, config=SyncConfig(gone_after_missed_syncs=1), clock=clock
    )
    snapshot = {r: _rows(worker_engine, r) for r in RESOURCES}
    revs = {r: _revisions(worker_engine, r) for r in RESOURCES}

    fake.keep_tombstones = False
    fake.delete_server(ids["other"])  # would be missed -> gone with N=1 ...
    fake.fail(
        "list_ports", OpenStackError("boom while reading ports secret=hunter2")
    )  # ... but the read fails
    clock.advance(hours=1)
    result = run_inventory_sync(
        worker_engine,
        fake,
        project,
        kind="full",
        config=SyncConfig(gone_after_missed_syncs=1),
        clock=clock,
    )
    assert result.status == "failed" and result.error and result.error["type"] == "OpenStackError"
    assert "hunter2" not in result.error["message"]  # redacted
    assert {r: _rows(worker_engine, r) for r in RESOURCES} == snapshot
    assert {r: _revisions(worker_engine, r) for r in RESOURCES} == revs
    with worker_engine.connect() as c:
        runs = c.execute(select(sync_run.c.status).order_by(sync_run.c.started_at)).scalars().all()
    assert runs == ["succeeded", "failed"]

    clock.advance(hours=1)  # the next good sync does mark it
    ok = run_inventory_sync(
        worker_engine,
        fake,
        project,
        kind="full",
        config=SyncConfig(gone_after_missed_syncs=1),
        clock=clock,
    )
    assert (
        ok.status == "succeeded"
        and _rows(worker_engine, "server")[ids["other"]]["status"] == "gone"
    )


def test_delta_marks_tombstones_gone_at_once_and_touches_only_servers(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, ids = _world(clock)
    run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    fake.tick(3600)
    clock.advance(hours=1)
    fake.delete_server(ids["other"])  # tombstone kept (Nova changes-since returns it)
    fresh = fake.add_server("green", tags=["ovlm:managed"])
    fake.lock_server(ids["srv"], "x")
    fake.remove_volume(ids["vol"])  # a delta must NOT notice Cinder changes

    result = run_inventory_sync(
        worker_engine, fake, project, config=CFG, clock=clock
    )  # auto: delta
    assert result.kind == "servers_delta" and list(result.counts) == ["server"]
    assert result.counts["server"]["gone"] == 1 and result.counts["server"]["created"] == 1
    assert result.counts["server"]["changed"] == 1
    servers = _rows(worker_engine, "server")
    assert servers[ids["other"]]["status"] == "gone" and servers[ids["other"]]["missed_syncs"] == 0
    assert servers[fresh]["status"] == "present"
    assert (
        _rows(worker_engine, "volume")[ids["vol"]]["status"] == "present"
    )  # not a full listing: no verdict
    assert (
        "list_volumes" not in fake.calls[fake.calls.index("list_servers", 3) :]
    )  # no volume read in the delta


def test_delta_ignores_tombstone_of_a_server_never_seen(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, _ = _world(clock)
    run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    fake.tick(3600)
    clock.advance(hours=1)
    ghost = fake.add_server("ghost")
    fake.delete_server(ghost)
    result = run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    assert result.counts["server"]["ignored_tombstones"] == 1
    assert ghost not in _rows(worker_engine, "server")


def test_kind_selection(worker_engine: Engine, project: UUID, clock: Clock) -> None:
    fake, _ = _world()
    cfg = SyncConfig(full_sync_every=timedelta(hours=6))
    assert (
        run_inventory_sync(
            worker_engine, fake, project, kind="servers_delta", config=cfg, clock=clock
        ).kind
        == "full"
    )
    clock.advance(minutes=5)
    assert (
        run_inventory_sync(worker_engine, fake, project, config=cfg, clock=clock).kind
        == "servers_delta"
    )
    clock.advance(hours=7)
    assert run_inventory_sync(worker_engine, fake, project, config=cfg, clock=clock).kind == "full"
    clock.advance(minutes=5)
    assert (
        run_inventory_sync(worker_engine, fake, project, kind="full", config=cfg, clock=clock).kind
        == "full"
    )


def test_minimal_construct_is_unknown_never_gone_and_keeps_the_last_known_payload(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, ids = _world()
    run_inventory_sync(
        worker_engine, fake, project, config=SyncConfig(gone_after_missed_syncs=1), clock=clock
    )
    fake.touch_server(ids["srv"], minimal=True)  # its cell is unreachable
    for _ in range(3):
        clock.advance(hours=1)
        res = run_inventory_sync(
            worker_engine,
            fake,
            project,
            kind="full",
            config=SyncConfig(gone_after_missed_syncs=1),
            clock=clock,
        )
        assert res.counts["server"]["unknown"] == 1
    row = _rows(worker_engine, "server")[ids["srv"]]
    assert (row["status"], row["missed_syncs"], row["gone_at"]) == ("unknown", 0, None)
    assert (
        row["name"] == "blue" and row["flavor_original_name"] == "m1.small"
    )  # not overwritten with empties
    assert row["is_minimal_construct"] is False

    fake.touch_server(ids["srv"], minimal=False)  # the cell is back
    clock.advance(hours=1)
    run_inventory_sync(worker_engine, fake, project, kind="full", config=CFG, clock=clock)
    assert _rows(worker_engine, "server")[ids["srv"]]["status"] == "present"


def test_a_second_sync_of_the_same_project_is_refused_while_one_runs(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, _ = _world()
    with worker_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as other:
        other.execute(select(func.pg_try_advisory_lock(inv_sync._lock_key(project))))
        with pytest.raises(SyncAlreadyRunningError):
            run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
        other.execute(select(func.pg_advisory_unlock(inv_sync._lock_key(project))))
    assert (
        run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock).status
        == "succeeded"
    )
    other_project = uuid4()  # a different project is independent
    assert (
        run_inventory_sync(worker_engine, fake, other_project, config=CFG, clock=clock).status
        == "succeeded"
    )


def test_two_projects_do_not_share_rows(worker_engine: Engine, clock: Clock) -> None:
    fake, ids = _world()
    a, b = uuid4(), uuid4()
    run_inventory_sync(worker_engine, fake, a, config=CFG, clock=clock)
    run_inventory_sync(worker_engine, fake, b, config=CFG, clock=clock)
    with worker_engine.connect() as c:
        n = c.execute(
            text("SELECT count(*) FROM observed_server WHERE openstack_id = :i"), {"i": ids["srv"]}
        ).scalar()
    assert n == 2  # UNIQUE(project_connection_id, openstack_id)


def test_grants_api_reads_worker_cannot_delete_revisions_are_append_only(
    admin_url: URL,
    fresh_db: str,
    secrets_dir: Path,
    worker_engine: Engine,
    project: UUID,
    clock: Clock,
) -> None:
    fake, _ = _world()
    run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    api = make_engine(settings_for("api", admin_url, fresh_db, secrets_dir))
    with api.connect() as c:
        assert c.execute(text("SELECT count(*) FROM observed_server")).scalar() == 2
    with api.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("UPDATE observed_server SET name = 'x'"))
    with api.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("INSERT INTO sync_run (id, project_connection_id, kind, status, started_at) "
                       "VALUES (gen_random_uuid(), gen_random_uuid(), 'full', 'running', now())"))  # fmt: skip
    api.dispose()
    with worker_engine.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("DELETE FROM observed_server"))
    with worker_engine.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("UPDATE observed_server_revision SET payload = '{}'::jsonb"))
    with worker_engine.connect() as c, pytest.raises(ProgrammingError):
        c.execute(text("DELETE FROM observed_server_revision"))


def test_check_constraint_gone_needs_gone_at(
    worker_engine: Engine, project: UUID, clock: Clock
) -> None:
    fake, _ = _world()
    run_inventory_sync(worker_engine, fake, project, config=CFG, clock=clock)
    from sqlalchemy.exc import IntegrityError

    with worker_engine.connect() as c, pytest.raises(IntegrityError):
        c.execute(text("UPDATE observed_server SET status = 'gone'"))


def test_tables_module_matches_the_migrated_schema(
    admin_url: URL, fresh_db: str, secrets_dir: Path, worker_engine: Engine
) -> None:
    del admin_url, fresh_db, secrets_dir
    with worker_engine.connect() as c:
        db = {
            (r.table_name, r.column_name): (r.is_nullable == "NO")
            for r in c.execute(
                text(
                    "SELECT table_name, column_name, is_nullable FROM information_schema.columns "
                    "WHERE table_schema = 'public'"
                )
            )
        }
    for table in metadata.tables.values():
        for col in table.columns:
            assert (table.name, col.name) in db, f"{table.name}.{col.name} missing in the migration"
            assert db[(table.name, col.name)] == (not col.nullable), (
                f"{table.name}.{col.name} nullability"
            )
    modeled = {(t.name, c.name) for t in metadata.tables.values() for c in t.columns}
    ours = {k for k in db if k[0] in {t.name for t in metadata.tables.values()}}
    assert ours == modeled, f"columns only in the migration: {sorted(ours - modeled)}"
    assert set(REVISIONS) == set(OBSERVED) == set(RESOURCES)


def test_cli_sync_command_writes_through_the_real_path(worker_engine: Engine) -> None:
    from ovlm.inventory.cli import sync_command

    fake, _ = _world()
    code, out = sync_command(fake, cloud="lab", engine=worker_engine)
    assert code == 0 and out["status"] == "succeeded" and out["kind"] == "full"
    assert len(_rows(worker_engine, "server")) == 2
    code2, out2 = sync_command(
        fake, cloud="lab", engine=worker_engine
    )  # same project id: a delta now
    assert code2 == 0 and out2["project_connection_id"] == out["project_connection_id"]
    fake.fail("list_volumes", OpenStackError("down"))
    code3, out3 = sync_command(fake, cloud="lab", engine=worker_engine, kind="full")
    assert code3 == 1 and out3["status"] == "failed"
