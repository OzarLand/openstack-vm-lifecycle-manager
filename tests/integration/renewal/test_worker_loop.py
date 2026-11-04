"""A full ``bluegreen_fip_v1`` renewal through the **real worker process loop** (``ovlm.worker.main.Worker``: its
tick, claim threads, heartbeats, drain) with the registry ``build_registry`` builds, the **production guest adapter**
(:class:`~ovlm.renewal.production.RunnerGuestPort`) over a runner double, and the OpenStack fake behind the guarded
write client with the strict fence gate.

plan -> G1 -> build (B1-B8) -> G2 -> B9 -> window (W1-W10) -> cutover -> retain (R1, R2) -> G3 -> retire (X1), with
one crash of the worker **inside the window** (``attach_volume_green`` after its Nova call, before its outcome is
committed). The crashed worker stops; a new worker (new ``lease_owner``, new adapter instance with an empty
checkout cache, as a restarted process has) takes the step over after lease expiry and ``takeover_delay``, re-probes
and finishes the renewal. What the subprocess form of the worker cannot do here: inject the doubles (``run()``
builds production ports), so the loop object is driven in threads; ``test_worker_process.py`` covers the process.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.engine import URL

from ovlm.automation.model import RunnerConfig
from ovlm.automation.store import ArtifactStore
from ovlm.config import Settings
from ovlm.renewal.base import Deps
from ovlm.renewal.production import RunnerGuestPort
from ovlm.worker.main import Worker, build_registry
from ovlm.workflow import crashpoint
from ovlm.workflow.crashpoint import CrashPlan, SimulatedCrash
from ovlm.workflow.engine import EngineConfig, WorkflowEngine
from tests.integration.conftest import settings_for
from tests.integration.renewal.conftest import CFG, World, build_world, explain
from tests.integration.renewal.doubles import FakeGuest, GuestState
from tests.integration.renewal.production_doubles import (
    GuestKeys,
    HttpDouble,
    RunnerDouble,
    SshDouble,
    StaticCredentials,
    TickingFake,
    credentials,
    new_key,
)

ORDER = [
    "preflight", "claim_resources", "create_green", "wait_green_active", "wait_green_ssh", "prepare_automation",
    "configure_green", "verify_cutover_preconditions", "await_cutover", "verify_green_ready",
    "quiesce_old", "stop_old", "detach_volume", "attach_volume_green", "data_attach_green", "start_service_green",
    "healthcheck_green", "move_fip", "verify_external",
    "retain_old", "await_retention", "await_retirement", "retire_old",
]  # fmt: skip


def _settings(base: Settings, tmp: Path) -> Settings:
    data = base.model_dump()
    data["worker"] |= {"heartbeat_interval": 0.05, "lease_duration": 2.0, "fence_margin": 0.5,
                       "takeover_delay": 0.5, "shutdown_grace": 2.0, "slots": 4}  # fmt: skip
    data["poll"] = {"initial_interval": 0.05, "max_interval": 0.2}
    data["retry"] |= {"backoff_initial": 0.05, "backoff_max": 0.1}
    data["automation"] |= {"run_root": str(tmp / "run"), "run_user": None}
    return Settings(**data)


class Harness:
    def __init__(
        self, w: World, settings: Settings, keys: GuestKeys, tmp: Path, creds: StaticCredentials
    ) -> None:
        self.w, self.settings, self.keys, self.tmp, self.creds = w, settings, keys, tmp, creds
        self.runners: list[RunnerDouble] = []
        self.http = HttpDouble(w.cloud, w.guest, "192.0.2.10")  # type: ignore[arg-type]
        self.worker: Worker | None = None
        self.thread: threading.Thread | None = None

    def start_worker(self) -> Worker:
        runner = RunnerDouble(self.w.guest, self.keys, self.tmp / f"checkout-{len(self.runners)}")
        self.runners.append(runner)
        store = ArtifactStore(RunnerConfig(run_root=self.tmp / "run"))
        guest = RunnerGuestPort(self.w.worker, runner, self.creds, ssh=SshDouble(self.keys), http=self.http,
                                store=store)  # fmt: skip
        deps = Deps(self.w.worker, CFG, self.w.port, guest)
        engine = WorkflowEngine(
            self.w.worker, build_registry(self.settings, self.w.worker, renewal_deps=deps),
            EngineConfig.from_settings(self.settings),
        )  # fmt: skip
        worker = Worker(self.settings, self.w.worker, engine)
        self.worker, self.thread = worker, threading.Thread(target=worker.run, name="test-worker")
        self.thread.start()
        return worker

    def stop_worker(self) -> None:
        if self.worker is not None and self.thread is not None:
            self.worker.request_stop("test")
            self.thread.join(timeout=30)
            assert not self.thread.is_alive()

    def wait(self, what: str, cond: Callable[[], bool], timeout: float = 120.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cond():
                return
            r = self.w.run()
            assert r["state"] not in ("failed", "needs_human", "rolled_back", "rejected"), explain(
                self.w
            )
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting for {what}: {explain(self.w)}")

    def waiting_at(self, key: str) -> bool:
        st = self.w.open_step()
        return st is not None and st["step_key"] == key and st["state"] == "waiting"


def test_full_renewal_through_the_worker_loop_with_a_crash_in_the_window(
    admin_url: URL, fresh_db: str, secrets_dir: Path, tmp_path: Path
) -> None:
    cloud = TickingFake(now=datetime.now(UTC), strict_gate=False)
    _blue_private, blue_key = new_key()
    guest_private, guest_public = new_key()
    w = build_world(
        admin_url, fresh_db, secrets_dir, blue_fingerprint=blue_key.fingerprint, cloud=cloud
    )
    keys = GuestKeys(cloud, w.guest, guest_public, {w.ids["blue"]: blue_key})
    cloud.on_create = keys.learn_bootstrap
    w.guest = FakeGuest(cloud, w.ids["volume"], phases={"preflight"})
    w.guest.state[w.ids["blue"]] = GuestState(mounted=True, units=True)
    keys.guest = w.guest
    settings = _settings(settings_for("worker", admin_url, fresh_db, secrets_dir), tmp_path)
    h = Harness(
        w, settings, keys, tmp_path, credentials(cloud.user_id, guest_private, guest_public)
    )

    def crash(name: str) -> None:  # the worker process dies right after W5's Nova call
        assert h.worker is not None
        h.worker.request_stop("simulated crash")
        raise SimulatedCrash(name)

    plan = CrashPlan("attach_volume_green.after_act", action=crash)
    crashpoint.install(plan)
    try:
        w.start()
        h.start_worker()
        h.wait("G2", lambda: h.waiting_at("await_cutover"))
        assert w.keys() == ORDER[:9]
        w.approve("cutover")
        h.wait("the crash in the window", lambda: plan.fired)
        h.stop_worker()  # the crashed process is gone: its step stays 'running' under its lease
        st = w.open_step()
        assert (
            st is not None and st["step_key"] == "attach_volume_green" and st["state"] == "running"
        )
        first_owner = st["lease_owner"]
        assert w.run()["downtime_started_at"] is not None  # we are inside the outage

        h.start_worker()  # restarted worker: new lease owner, new adapter (empty checkout cache)
        h.wait("G3", lambda: h.waiting_at("await_retirement"))
        w.approve("retirement", decider="ap2")
        h.wait("completion", lambda: w.run()["state"] == "completed")
    finally:
        h.stop_worker()
        crashpoint.install(None)

    run = w.run()
    assert run["state"] == "completed" and not run["auto_restore_used"], explain(w)
    succeeded = [s["step_key"] for s in w.steps() if s["state"] == "succeeded"]
    assert succeeded == ORDER, succeeded
    # the takeover: same step, a new attempt, by the restarted worker, after a fresh probe
    attempts = w.q("SELECT a.attempt, a.worker_id, a.takeover, a.outcome FROM workflow_step_attempt a JOIN workflow_step s "
                   "ON s.id = a.step_id WHERE s.run_id = :r AND s.step_key = 'attach_volume_green' "
                   "ORDER BY a.attempt", r=w.run_id)  # fmt: skip
    assert attempts[0]["worker_id"] == first_owner and attempts[0]["outcome"] == "lost", attempts
    assert attempts[1]["worker_id"] != first_owner and attempts[1]["takeover"], attempts
    assert attempts[-1]["outcome"] == "succeeded"
    assert cloud.calls.count("attach_volume") == 2  # blue's at set-up + green's once: never re-sent
    # the outcome in the cloud: volume on green only, FIP on green, blue deleted, data volume untouched
    green = w.green_id()
    assert green is not None and w.attached() == [green]
    assert w.cloud.get_port(w.fip_port() or "").device_id == green
    assert w.cloud._servers[w.ids["blue"]].deleted  # noqa: SLF001
    assert cloud.violations == []
    # the production adapter's guest side
    assert [len(r.prepared) for r in h.runners] == [
        1,
        1,
    ]  # the restarted worker re-prepared (same SHA)
    phases = [(r.phase.value, r.target.role) for runner in h.runners for r in runner.requests]
    assert (
        ("quiesce", "old") in phases
        and ("data_attach", "new") in phases
        and ("healthcheck", "new") in phases
    )
    rotated = [c for c in keys.calls if c[1][:2] == ("sudo", "-n")]
    assert len(rotated) == 1 and rotated[0][0] == green  # B5 rotated green's bootstrap key once
    assert (
        keys.host_keys[green].line not in cloud.user_data[green]
    )  # the pinned key is not the bootstrap key
    green_steps = {s["step_key"]: s for s in w.steps()}
    assert green_steps["wait_green_ssh"]["evidence"]["mode"] == "rotated"
    assert all(u.startswith("http://192.0.2.10:80/healthz") for u in h.http.urls)
    stored = w.q(
        "SELECT phase, target_role, classification FROM automation_run ORDER BY created_at"
    )
    assert {(r["phase"], r["target_role"]) for r in stored} >= {
        ("quiesce", "old"),
        ("data_attach", "new"),
    }
    assert set(h.creds.asked) == {w.ids["pc"]}
    assert set(w.port.projects) == {w.ids["pc"]}
