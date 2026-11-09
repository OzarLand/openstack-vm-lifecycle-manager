"""A renewal "world" on a real PostgreSQL: seeded users, service, inventory, profile, policy, plan and G1, a fake
cloud (``strict_gate`` on: no write without a step's fence gate) and a fake guest; helpers to drive the engine and
to grant G2/G3 the way the api does (approval row + consumed step-up + ``approve`` signal)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import URL

from ovlm.inventory.tables import OBSERVED
from ovlm.openstack.allowlist import TAG_MANAGED
from ovlm.profiles.spec import spec_hash, validate_spec
from ovlm.renewal.base import Deps
from ovlm.renewal.config import RenewalConfig
from ovlm.renewal.definition import BlueGreenFipV1
from ovlm.renewal.plans import (
    KIND,
    STRATEGY,
    STRATEGY_VERSION,
    compute_plan_hash,
    policy_binding,
    resolve_plan,
    tc_of,
)
from ovlm.renewal.reprobe import RenewalReprobe
from ovlm.workflow import crashpoint
from ovlm.workflow.clock import FakeClock
from ovlm.workflow.crashpoint import SimulatedCrash
from ovlm.workflow.engine import WorkflowEngine
from ovlm.workflow.ids import new_id
from ovlm.workflow.registry import Registry
from ovlm.workflow.requests import request_run, send_signal
from tests.integration.conftest import API_PW, WORKER_PW, role_url
from tests.integration.renewal.doubles import (
    SUBNET,
    FakeCloudPort,
    FakeGuest,
    GuestState,
    RenewalFake,
)
from tests.integration.test_migrations import migrate
from tests.integration.workflow.conftest import TEST_CONFIG, RecordingAudit

T = 600.0
CFG = RenewalConfig(
    timeouts={k: T for k in (
        "preflight", "claim_resources", "green_create_call", "green_build", "green_ssh", "green_host_key",
        "green_ready", "server_stop", "server_start", "volume_detach", "snapshot", "volume_attach", "fip_status",
        "external_verify", "server_lock", "server_delete",
    )},
    automation={p: 60.0 for p in (
        "preflight", "configure", "quiesce", "data_attach", "start_service", "healthcheck", "rollback_hooks",
    )},
    green_ready_max_age=3600, healthcheck_max_attempts=3, healthcheck_interval=0, external_required_successes=2,
    external_interval=0, retire_health_max_age=3600, validity_retirement=3600,
)  # fmt: skip
ALL_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
TERMINAL = ("completed", "rejected", "cancelled", "failed", "rolled_back")


@dataclass
class World:
    admin: Engine
    worker: Engine
    api: Engine
    cloud: RenewalFake
    guest: FakeGuest
    port: FakeCloudPort
    ids: dict[str, str]
    users: dict[str, str]
    engine: WorkflowEngine | None = None
    audit: RecordingAudit = field(default_factory=RecordingAudit)
    run_id: str = ""

    # -- db helpers --------------------------------------------------------------------------------------

    def q(self, sql: str, **p: Any) -> list[Any]:
        with self.admin.connect() as c:
            return list(c.execute(text(sql), p).mappings().all())

    def x(self, sql: str, **p: Any) -> int:
        with self.admin.begin() as c:
            return int(c.execute(text(sql), p).rowcount)

    def run(self) -> Any:
        return self.q("SELECT * FROM workflow_run WHERE id = :r", r=self.run_id)[0]

    def steps(self) -> list[Any]:
        return self.q("SELECT * FROM workflow_step WHERE run_id = :r ORDER BY seq", r=self.run_id)

    def keys(self) -> list[str]:
        return [s["step_key"] for s in self.steps()]

    def open_step(self) -> Any:
        rows = self.q(
            "SELECT * FROM workflow_step WHERE run_id = :r AND state IN ('ready','running','waiting','needs_human')",
            r=self.run_id,
        )
        return rows[0] if rows else None

    def locks(self) -> list[tuple[str, str]]:
        rows = self.q("SELECT resource_type, resource_key FROM resource_lock WHERE holder_run_id = :r ORDER BY 1, 2",
                      r=self.run_id)  # fmt: skip
        return [(r["resource_type"], r["resource_key"]) for r in rows]

    def audit_actions(self) -> list[str]:
        return [
            r["action"]
            for r in self.q(
                "SELECT action FROM audit_event WHERE run_id = :r ORDER BY id", r=self.run_id
            )
        ]

    # -- engine ------------------------------------------------------------------------------------------

    cfg: RenewalConfig = CFG
    crashes: int = 0

    def make_engine(self, cfg: RenewalConfig | None = None) -> WorkflowEngine:
        self.cfg = cfg or self.cfg
        deps = Deps(self.worker, self.cfg, self.port, self.guest)
        self.engine = WorkflowEngine(
            self.worker, Registry([BlueGreenFipV1(deps), RenewalReprobe(self.worker)]), TEST_CONFIG,
            clock=FakeClock(), audit=self.audit,
        )  # fmt: skip
        return self.engine

    def start(self) -> str:
        with self.api.begin() as c:
            self.run_id = request_run(
                c, kind=KIND, strategy=STRATEGY, strategy_version=STRATEGY_VERSION, service_id=self.ids["service"],
                renewal_plan_id=self.ids["plan"], started_by=self.users["op"],
            )  # fmt: skip
        return self.run_id

    def drive(self, until: str | None = None, *, max_passes: int = 400, tick: float = 20.0) -> Any:
        """Engine passes (signals, admission, one step) with the fake clock advancing, until the run is terminal,
        parked, waiting on a signal, or the open step is ``until``."""
        eng = self.engine or self.make_engine()
        for _ in range(max_passes):
            try:
                eng.run_once()
            except SimulatedCrash:
                # the worker "died": its lease expires and a new worker process (new lease_owner) takes over
                self.crashes += 1
                self.x(
                    "UPDATE workflow_step SET lease_expires_at = now() - interval '1 second' WHERE state = 'running'"
                )
                eng = self.make_engine()
            self.check_invariants()
            self.cloud.tick(tick)
            r = self.run()
            if r["state"] in (*TERMINAL, "needs_human"):
                return r
            st = self.open_step()
            if (
                st is not None
                and until is not None
                and st["step_key"] == until
                and st["state"] != "running"
            ):
                return r
            if st is not None and st["state"] == "waiting" and st["not_before"] is None:
                return r
        raise AssertionError(f"run did not settle: {self.keys()} {self.open_step()}")

    # -- approvals, as the api records them ----------------------------------------------------------------

    def stepup(self, user: str, action: str, target: str, *, consumed: bool = True,
               signal_id: str | None = None) -> str:  # fmt: skip
        """A step-up as ``POST /session/reauth`` issues it; ``consumed``: already spent (by ``signal_id``, as the api
        spends a run action's step-up in the signal's transaction, review PMR-8)."""
        sid = new_id()
        self.x(
            "INSERT INTO stepup (id, user_id, session_id_hash, action, target_id, auth_method, created_at, expires_at, "
            "consumed_at, consumed_by_signal) VALUES (:i, :u, 'sess', :a, :t, 'password+totp', "
            "now() - interval '1 minute', now() + interval '4 minutes', CASE WHEN :c THEN now() END, "
            "CAST(:sig AS uuid))",
            i=sid, u=self.users[user], a=action, t=target, c=consumed, sig=signal_id if consumed else None,
        )  # fmt: skip
        return sid

    def approve(self, gate: str, *, decider: str = "ap", tc: str | None = None, expires: str = "1 hour",
                bound_hash: str | None = None, operator_confirmed: bool = False, requester_set: str | None = None) -> str:  # fmt: skip
        aid = new_id()
        plan = self.q("SELECT plan_hash FROM renewal_plan WHERE id = :p", p=self.ids["plan"])[0]
        subject = self.ids["plan"] if gate == "plan" else self.run_id
        action = "run.cutover" if operator_confirmed else "approval.decide"
        stepup = self.stepup(decider, action, self.run_id if operator_confirmed else aid)
        self.x(
            "INSERT INTO approval (id, subject_type, subject_id, plan_id, run_id, scope, bound_hash, requester_set, "
            "requested_by, decided_by, decision, typed_confirmation, auth_method, stepup_id, operator_confirmed, "
            "decided_at, expires_at) VALUES (:i, :t, :s, :p, :run, :scope, :h, CAST(:rs AS uuid[]), :rb, :d, "
            "'approved', :tc, 'password+totp', :su, :oc, now(), now() + CAST(:exp AS interval))",
            i=aid, t=gate, s=subject, p=self.ids["plan"], run=self.run_id or None, scope=self.ids["scope"],
            h=bound_hash or plan["plan_hash"], rs=requester_set if requester_set is not None else "{" + self.users["op"] + "}", rb=self.users["op"],
            d=self.users[decider], tc=tc if tc is not None else (None if gate == "plan" else self.blue_tc()),
            su=stepup, oc=operator_confirmed, exp=expires,
        )  # fmt: skip
        if gate != "plan":
            with self.api.begin() as c:
                send_signal(
                    c, self.run_id, "approve", actor_id=self.users[decider], approval_id=aid
                )
        return aid

    def blue_tc(self) -> str:
        return tc_of(self.ids["blue_name"], self.ids["blue"])

    def green_tc(self) -> str:
        g = self.q(
            "SELECT * FROM owned_resource WHERE run_id = :r AND role = 'green'", r=self.run_id
        )[0]
        return tc_of(g["intended_name"], g["openstack_id"])

    def signal(self, kind: str, *, user: str = "op", tc: str | None = None, good_stepup: bool = True,
               stepup_id: str | None = None, **payload: Any) -> str:  # fmt: skip
        """A run action as the api records it: with ``tc``, a step-up spent by this signal (``stepup_id``: send this
        one instead, as a replay would)."""
        body = dict(payload)
        sig = new_id()
        if tc is not None:
            body["typed_confirmation"] = tc
            body["stepup_id"] = stepup_id or self.stepup(
                user, f"run.{kind}" if good_stepup else "run.other", self.run_id, signal_id=sig
            )
        with self.api.begin() as c:
            return send_signal(
                c, self.run_id, kind, actor_id=self.users[user], payload=body, signal_id=sig
            )

    def green_id(self) -> str | None:
        rows = self.q("SELECT openstack_id FROM owned_resource WHERE run_id = :r AND role = 'green' "
                      "ORDER BY created_at DESC LIMIT 1", r=self.run_id)  # fmt: skip
        return rows[0]["openstack_id"] if rows else None

    # -- invariants ----------------------------------------------------------------------------------------

    def check_invariants(self) -> None:
        """Data safety, checked after every engine pass: never two VMs attached to the volume, never two guests with
        the data mounted, never a volume or a FIP deleted."""
        snap = self.cloud.snapshot()
        assert self.ids["volume"] in snap["volumes"], "the data volume was deleted"
        assert self.ids["fip"] in snap["floating_ips"], "the floating IP was deleted"
        assert len(self.attached()) <= 1, f"volume attached to {self.attached()}"
        self.guest.sync()
        mounted = [sid for sid, st in self.guest.state.items() if st.mounted]
        assert len(mounted) <= 1, f"data mounted on {mounted}"

    def attached(self) -> list[str]:
        vol = self.cloud.snapshot()["volumes"][self.ids["volume"]]
        return list(vol["attached_to"])

    def fip_port(self) -> str | None:
        port: str | None = self.cloud.snapshot()["floating_ips"][self.ids["fip"]]
        return port


def _seed(
    admin: Engine, cloud: RenewalFake, *, snapshot: bool, policy: dict[str, Any],
    blue_fingerprint: str = "SHA256:x", service_units: list[str] | None = None, fs_label: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:  # fmt: skip
    ext = cloud.add_network("ext", external=True)
    net = cloud.add_network("net")
    cloud.add_router_path(net, ext)
    image = cloud.add_image("ubuntu-24.04")
    flavor = cloud.add_flavor("m1.small")
    blue = cloud.add_server("app01-prod", tags=["foreign:keep"])
    blue_port = cloud.add_port(net, device_id=blue, ip="10.0.0.5", subnet=SUBNET)
    vol = cloud.add_volume("data", metadata={"owner": "team-a"})
    fip = cloud.add_floating_ip(ext)
    cloud.attach_volume(blue, vol)
    cloud.update_floating_ip(fip, blue_port)
    cloud.tick(60)
    cloud.strict_gate = True  # from now on, no write without a step's fence gate

    users = {n: new_id() for n in ("op", "ap", "ap2", "ap3", "admin")}
    pc = new_id()
    scope = f"project:{pc}"
    ids = {"blue": blue, "blue_port": blue_port, "volume": vol, "fip": fip, "image": image, "flavor": flavor,
           "net": net, "scope": scope, "pc": pc, "blue_name": "app01-prod"}  # fmt: skip
    spec = validate_spec({
        "flavor": "m1.small", "image": {"name": "ubuntu-24.04"},
        "network": {"network_id": net, "subnet_id": SUBNET}, "security_groups": ["default"],
        "data_volume": {"volume_id": vol, "fs_type": "ext4", "mount_point": "/srv/data",
                        "snapshot_before_handoff": snapshot,
                        **({"label": fs_label} if fs_label else {"fs_uuid": "11111111-2222-3333-4444-555555555555"})},
        "automation": {"repo": "https://git.example.invalid/app.git", "sha": "a" * 40,
                       "inventory_vars": {} if service_units == [] else {"service_units": service_units or ["app.service"]}},
        "guest_access": {"ssh_user": "ovlm"},
        "health_check": {"external": {"scheme": "http", "port": 80, "path": "/healthz", "expected_status": 200}},
        "cutover": {"floating_ip_id": fip},
    })  # fmt: skip
    with admin.begin() as c:
        for name, uid in users.items():
            c.execute(
                text(
                    "INSERT INTO app_user (id, username, state, password_hash, created_via, created_at) "
                    "VALUES (:i, :n, 'active', 'x', 'cli', now() - interval '1 day')"
                ),
                {"i": uid, "n": f"user-{name}"},
            )
        for user, role in (
            ("op", "operator"),
            ("ap", "approver"),
            ("ap2", "approver"),
            ("ap3", "approver"),
            ("admin", "admin"),
        ):
            c.execute(text("INSERT INTO role_binding (id, user_id, role, scope, created_at) VALUES "
                           "(:i, :u, :r, :s, now() - interval '1 day')"),
                      {"i": new_id(), "u": users[user], "r": role, "s": scope})  # fmt: skip
        sync = new_id()
        c.execute(
            text(
                "INSERT INTO sync_run (id, project_connection_id, kind, status, started_at, finished_at) "
                "VALUES (:i, :pc, 'full', 'succeeded', now(), now())"
            ),
            {"i": sync, "pc": pc},
        )
        obs = {"server": new_id()}

        def observed(table: str, oid: str, name: str | None, **cols: Any) -> str:
            rid = new_id()
            c.execute(
                OBSERVED[table].insert().values(
                    id=rid, project_connection_id=pc, openstack_id=oid, name=name, payload={}, payload_hash="0" * 64,
                    first_seen_sync_id=sync, last_seen_sync_id=sync, status="present",
                    synced_at=datetime.now(UTC), **cols,
                )
            )  # fmt: skip
            return rid

        obs["server"] = observed(
            "server", blue, "app01-prod", server_status="ACTIVE", availability_zone="az1"
        )
        observed("port", blue_port, "", device_id=blue)
        observed("floating_ip", fip, None, floating_ip_address="192.0.2.10", port_id=blue_port)
        observed("volume", vol, "data", volume_status="in-use", availability_zone="az1", size=1)
        observed(
            "image",
            image,
            "ubuntu-24.04",
            image_status="active",
            visibility="public",
            owner_id=cloud.project_id(),
        )
        observed("flavor", flavor, "m1.small", disk=10)
        svc = new_id()
        c.execute(text("INSERT INTO service (id, name, slug, project_connection_id) VALUES (:i, 'App', 'app01', :pc)"),
                  {"i": svc, "pc": pc})  # fmt: skip
        vm = new_id()
        c.execute(text("INSERT INTO managed_vm (id, service_id, observed_server_id, openstack_server_id, role, "
                       "registered_at, ssh_host_key_fingerprint, host_key_confirmed_by, host_key_confirmed_at) "
                       "VALUES (:i, :s, :o, :b, 'current', now(), :fp, :u, now())"),
                  {"i": vm, "s": svc, "o": obs["server"], "b": blue, "fp": blue_fingerprint,
                   "u": users["op"]})  # fmt: skip
        prof = new_id()
        c.execute(text("INSERT INTO profile (id, service_id, name, latest_version) VALUES (:i, :s, 'p', 1)"),
                  {"i": prof, "s": svc})  # fmt: skip
        pv = new_id()
        from ovlm.profiles.spec import canonical

        c.execute(text("INSERT INTO profile_version (id, profile_id, number, spec, spec_hash, automation_sha, "
                       "created_by) VALUES (:i, :p, 1, CAST(:s AS jsonb), :h, :sha, :u)"),
                  {"i": pv, "p": prof, "s": json.dumps(canonical(spec)), "h": spec_hash(spec), "sha": "a" * 40,
                   "u": users["op"]})  # fmt: skip
        pol = new_id()
        c.execute(text("INSERT INTO policy (id, name, max_age_seconds, renewal_interval_seconds, windows, approvals, "
                       "auto_restore_in_window, max_window_duration_seconds, retention_period_seconds, "
                       "last_edited_by) VALUES (:i, 'pol', 86400, 86400, CAST(:w AS jsonb), CAST(:a AS jsonb), "
                       ":ar, :mw, NULL, :ed)"),
                  {"i": pol, "w": json.dumps(policy.get("windows", [{"weekdays": ALL_DAYS, "start": "00:00",
                                                                       "end": "23:59", "timezone": "UTC"}])),
                   "a": json.dumps(policy.get("approvals", {"plan": True, "cutover": True})),
                   "ar": policy.get("auto_restore", True), "mw": policy.get("budget", 3600), "ed": users["admin"]})  # fmt: skip
        c.execute(text("INSERT INTO policy_binding (id, policy_id, scope_type, scope_id) VALUES (:i, :p, 'service', :s)"),
                  {"i": new_id(), "p": pol, "s": svc})  # fmt: skip
        prow = c.execute(text("SELECT * FROM policy WHERE id = :i"), {"i": pol}).mappings().one()
        resolved = resolve_plan(c, UUID(vm), CFG, policy_row=prow)
        plan_hash = compute_plan_hash(resolved=resolved, profile_version_id=pv, spec_hash=spec_hash(spec),
                                      automation_sha="a" * 40, policy=policy_binding(prow))  # fmt: skip
        plan = new_id()
        c.execute(text("INSERT INTO renewal_plan (id, managed_vm_id, service_id, profile_version_id, policy_id, "
                       "policy_version, resolved, plan_hash, state, created_by) VALUES (:i, :vm, :s, :pv, :pol, 1, "
                       "CAST(:r AS jsonb), :h, 'approved', :u)"),
                  {"i": plan, "vm": vm, "s": svc, "pv": pv, "pol": pol, "r": json.dumps(resolved), "h": plan_hash,
                   "u": users["op"]})  # fmt: skip
    ids |= {"service": svc, "vm": vm, "plan": plan, "policy": pol, "profile_version": pv}
    return ids, users


def build_world(admin_url: URL, db: str, secrets_dir: Path, *, snapshot: bool = False,
                policy: dict[str, Any] | None = None, g1: bool = True, blue_fingerprint: str = "SHA256:x",
                cloud: RenewalFake | None = None, service_units: list[str] | None = None,
                fs_label: str | None = None) -> World:  # fmt: skip
    migrate(admin_url, db, secrets_dir)
    admin = create_engine(admin_url.set(database=db))
    worker = create_engine(
        role_url(admin_url, db, "ovlm_worker", WORKER_PW), pool_size=10, max_overflow=10
    )
    api = create_engine(role_url(admin_url, db, "ovlm_api", API_PW))
    cloud = cloud or RenewalFake(
        now=datetime.now(UTC), strict_gate=False
    )  # seeding the cloud; strict after
    ids, users = _seed(
        admin,
        cloud,
        snapshot=snapshot,
        policy=policy or {},
        blue_fingerprint=blue_fingerprint,
        service_units=service_units,
        fs_label=fs_label,
    )
    port = FakeCloudPort(
        cloud, datetime.now(UTC) + timedelta(days=30), datetime.now(UTC) + timedelta(hours=8)
    )
    w = World(admin, worker, api, cloud, FakeGuest(cloud, ids["volume"]), port, ids, users)
    w.guest.state[ids["blue"]] = GuestState(mounted=True, units=True)  # blue serves
    if g1:
        w.approve("plan", decider="ap3")
    return w


@pytest.fixture
def world_factory(admin_url: URL, fresh_db: str, secrets_dir: Path) -> Iterator[Any]:
    made: list[World] = []

    def make(**kw: Any) -> World:
        w = build_world(admin_url, fresh_db, secrets_dir, **kw)
        made.append(w)
        return w

    yield make
    crashpoint.install(None)
    for w in made:
        for e in (w.admin, w.worker, w.api):
            e.dispose()


@pytest.fixture
def world(world_factory: Any) -> World:
    w: World = world_factory()
    return w


def to_cutover(w: World) -> None:
    """Start and drive the build phase to G2, grant G2."""
    w.start()
    w.drive(until="await_cutover")
    st = w.open_step()
    assert st is not None and st["step_key"] == "await_cutover", explain(w)
    w.approve("cutover")


def explain(w: World) -> Any:
    r = w.run()
    for s in w.steps():
        print("STEP", s["step_key"], s["state"], s["error"], s["evidence"])  # noqa: T201
    return (r["state"], r["end_reason"], r["needs_human_reason"],
            [(s["step_key"], s["state"], s["error"]) for s in w.steps()])  # fmt: skip


MANAGED = TAG_MANAGED
