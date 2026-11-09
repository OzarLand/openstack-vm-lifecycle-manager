"""Lab finding Z: a worker **container** restart inside the downtime window empties the tmpfs ``automation.run_root``.

The production guest port reads the tree digest B6 recorded in its step evidence (``workflow_step.evidence``), the
real automation runner re-adopts the copy it kept in ``automation.checkout_cache`` when the digests match, and no git
command runs. A tampered copy, or a B6 that recorded no digest, stops the step for a human.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ovlm.automation import checkout as co
from ovlm.automation.checkout import CloneOptions
from ovlm.automation.lint import StaticWaivers
from ovlm.automation.model import AutomationSpec, RunnerConfig
from ovlm.automation.runner import AutomationRunner
from ovlm.renewal.base import StepRefusal
from ovlm.renewal.production import RunnerGuestPort, _LazyRunner
from ovlm.workflow.contract import ErrorClass
from tests.integration.renewal.conftest import World
from tests.unit.automation.test_checkout import make_repo
from tests.unit.automation.test_runner import FILES


class _Port(RunnerGuestPort):
    """The production port; only the profile's automation block is given by the test (a local repository)."""

    spec: AutomationSpec

    def _resolved(self, run_id: str) -> Mapping[str, Any]:
        return {}

    def _spec(self, run_id: str, resolved: Mapping[str, Any]) -> AutomationSpec:
        return self.spec

    def _waivers(self, resolved: Mapping[str, Any]) -> StaticWaivers:
        return StaticWaivers()


def _setup(
    w: World, tmp_path: Path, *, record_digest: bool = True
) -> tuple[_Port, Any, str, RunnerConfig]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "ansible").write_text("#!/bin/sh\necho 'ansible [core 2.99.1]'\n")
    (bin_dir / "ansible").chmod(0o755)
    url, sha = make_repo(tmp_path / "src", FILES)
    cfg = RunnerConfig(run_root=tmp_path / "run", checkout_cache=tmp_path / "cache", ansible_bin_dir=bin_dir,
                       run_user=None, clone=CloneOptions(allowed_repos=[url], allow_file=True))  # fmt: skip
    run_id = w.start()
    port = _Port(w.worker, _LazyRunner(lambda: AutomationRunner(cfg)), None, ssh=None, http=None)  # type: ignore[arg-type]
    port.spec = AutomationSpec(repo=url, ref=sha)
    b6 = AutomationRunner(cfg).prepare_automation(port.spec, run_id)  # B6, before the window
    evidence = dict(b6.evidence())
    if not record_digest:
        evidence.pop("tree_digest")
    w.x(
        "INSERT INTO workflow_step (id, run_id, seq, step_key, state, attempt, evidence, finished_at) "
        "VALUES (:i, :r, 9000, 'prepare_automation', 'succeeded', 1, CAST(:e AS jsonb), now())",
        i=str(uuid.uuid4()), r=run_id, e=json.dumps({"prepared": evidence, "green_preflight": "absent"}),
    )  # fmt: skip
    w.x(
        "UPDATE workflow_run SET phase = 'window', downtime_started_at = now() WHERE id = :r",
        r=run_id,
    )
    co.remove_tree(
        cfg.run_root
    )  # the worker container restarted: tmpfs empty, the cache volume kept
    return port, b6, run_id, cfg


def test_restarted_container_in_the_window_adopts_the_cached_checkout_by_recorded_digest(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    port, b6, run_id, cfg = _setup(world, tmp_path)
    assert port._in_outage(run_id)  # noqa: SLF001
    assert port._recorded_tree_digest(run_id) == b6.tree_digest  # noqa: SLF001
    git: list[Any] = []
    monkeypatch.setattr(co, "_git", lambda *a, **k: git.append(a))
    monkeypatch.setattr(co, "clone_verified", lambda *a, **k: git.append(a))
    prepared = port._prepared_for(run_id)  # noqa: SLF001
    assert git == [], "no git host contact inside the downtime window"
    assert prepared.tree_digest == b6.tree_digest and prepared.sha == b6.sha
    assert prepared.checkout == cfg.run_root / run_id / "_checkout" and prepared.checkout.is_dir()
    assert port.has_phase(run_id, "data_attach") and port.has_phase(run_id, "start_service")


def test_a_tampered_cached_checkout_stops_for_a_human(world: World, tmp_path: Path) -> None:
    port, _b6, run_id, cfg = _setup(world, tmp_path)
    f = cfg.checkout_cache / run_id / "_checkout" / "playbooks" / "quiesce.yml"  # type: ignore[operator]
    f.chmod(0o644)
    f.write_text("- hosts: ovlm_target\n  tasks: [{ansible.builtin.ping: {}}]\n")
    f.chmod(0o444)
    with pytest.raises(StepRefusal, match="automation_checkout_unverifiable") as exc:
        port._prepared_for(run_id)  # noqa: SLF001
    assert exc.value.error_class is ErrorClass.NEEDS_HUMAN
    assert "does not match the tree digest" in exc.value.detail["message"]
    # PMR-6 (a): the tampered copy is kept aside for a human, with its path and both digests in the step's refusal
    # evidence and the audit trail
    moved = Path(exc.value.detail["quarantined_checkout"])
    assert cfg.checkout_cache is not None and moved.parent == cfg.checkout_cache / run_id
    assert moved.name.startswith("_checkout.mismatch-")
    assert (moved / "playbooks" / "quiesce.yml").read_text().startswith("- hosts: ovlm_target")
    assert (
        exc.value.detail["recorded_tree_digest"]
        == _b6.tree_digest
        != exc.value.detail["cached_tree_digest"]
    )
    [row] = world.q("SELECT after FROM audit_event WHERE run_id = :r AND action = 'automation.checkout.quarantined'",
                    r=run_id)  # fmt: skip
    assert row["after"]["quarantined_checkout"] == str(moved)
    assert row["after"]["cached_tree_digest"] == exc.value.detail["cached_tree_digest"]


def test_a_b6_without_a_recorded_digest_cannot_adopt_the_cache(
    world: World, tmp_path: Path
) -> None:
    port, _b6, run_id, _cfg = _setup(world, tmp_path, record_digest=False)
    assert port._recorded_tree_digest(run_id) is None  # noqa: SLF001
    with pytest.raises(StepRefusal, match="automation_checkout_unverifiable") as exc:
        port._prepared_for(run_id)  # noqa: SLF001
    assert exc.value.error_class is ErrorClass.NEEDS_HUMAN
    assert "no recorded tree digest" in exc.value.detail["message"]


def _worker_settings(admin_url: Any, fresh_db: str, secrets_dir: Path, cfg_or_tmp: Any) -> Any:
    from ovlm.config import Settings
    from tests.integration.conftest import settings_for

    run_root, cache = (
        (cfg_or_tmp.run_root, cfg_or_tmp.checkout_cache)
        if isinstance(cfg_or_tmp, RunnerConfig)
        else (cfg_or_tmp / "run", cfg_or_tmp / "cache")
    )
    base = settings_for("worker", admin_url, fresh_db, secrets_dir).model_dump()
    base["automation"] |= {
        "run_root": str(run_root),
        "checkout_cache": str(cache),
        "run_user": None,
    }
    return Settings(**base)


def test_the_worker_sweeps_checkouts_of_finished_runs_only(
    world: World, admin_url: Any, fresh_db: str, secrets_dir: Path, tmp_path: Path
) -> None:
    """Neither the cache nor the tmpfs run_root may grow forever (roadmap P0-1): the worker removes the entries of
    terminal runs at once and those of unknown runs once older than the orphan max age, in both places; a live run
    keeps its own whatever their age (it may wait days at a gate)."""
    import os
    import time

    from ovlm.worker.main import Worker

    w = world
    done = w.start()
    w.x("UPDATE workflow_run SET state = 'completed', finished_at = now() WHERE id = :r", r=done)
    live = w.start()  # one active renewal per service: the finished run first
    settings = _worker_settings(admin_url, fresh_db, secrets_dir, tmp_path)
    old = time.time() - 365 * 86400
    unknown_old, unknown_new = str(uuid.uuid4()), str(uuid.uuid4())
    for root in (tmp_path / "cache", tmp_path / "run"):
        for name in (live, unknown_old, unknown_new, done):
            (root / name / "_checkout").mkdir(parents=True)
            co.make_read_only(root / name / "_checkout")
            if name in (live, unknown_old):
                os.utime(root / name, (old, old))
    (tmp_path / "cache" / "fresh").mkdir()  # an unknown run, but just written: kept until it is old
    (tmp_path / "run" / ".ca").mkdir()  # the worker's own files on run_root are never swept
    Worker(settings, w.worker)._sweep_checkouts()  # noqa: SLF001
    assert sorted(p.name for p in (tmp_path / "cache").iterdir()) == sorted(
        [live, unknown_new, "fresh"]
    )
    assert sorted(p.name for p in (tmp_path / "run").iterdir()) == sorted(
        [live, unknown_new, ".ca"]
    )


def _prepared_run(w: World, tmp_path: Path) -> tuple[str, RunnerConfig]:
    """A live run whose B6 left its verified checkout on run_root and its copy in the cache (real runner)."""
    port, _b6, run_id, cfg = _setup(w, tmp_path)
    assert port._prepared_for(run_id).checkout.is_dir()  # noqa: SLF001  (adopted back onto run_root)
    return run_id, cfg


def test_a_run_reaching_a_terminal_state_releases_its_checkout(
    world: World, admin_url: Any, fresh_db: str, secrets_dir: Path, tmp_path: Path
) -> None:
    """Roadmap P0-1: the run's last step, through the worker's step thread, frees the run-level checkout on the
    tmpfs run_root and its cached copy as soon as the run is terminal in the database. Before that both stay."""
    from ovlm.worker.main import Worker

    w = world
    run_id, cfg = _prepared_run(w, tmp_path)
    assert cfg.checkout_cache is not None
    on_disk = [cfg.run_root / run_id, cfg.checkout_cache / run_id]
    state = {"next": "running"}

    class Wf:
        worker_id = "w"

        def execute(self, claim: Any) -> str:
            # a terminal state comes with finished_at, as the engine writes it
            w.x("UPDATE workflow_run SET state = :s, finished_at = CASE WHEN :s = 'completed' THEN now() END "
                "WHERE id = :r", s=state["next"], r=claim.run.id)  # fmt: skip
            return "succeeded"

    worker = Worker(_worker_settings(admin_url, fresh_db, secrets_dir, cfg), w.worker, Wf())  # type: ignore[arg-type]
    claim = SimpleNamespace(run=SimpleNamespace(id=run_id))
    worker._run_step(claim)  # type: ignore[arg-type]  # noqa: SLF001  (a step of a live run: nothing released)
    assert all(p.is_dir() for p in on_disk)
    assert (cfg.run_root / run_id / "_checkout").is_dir()
    state["next"] = "completed"
    worker._run_step(claim)  # type: ignore[arg-type]  # noqa: SLF001  (its last step)
    assert not any(p.exists() for p in on_disk), (
        "the finished run's checkout is gone from run_root and the cache"
    )


def test_the_start_up_sweep_keeps_a_live_run_and_removes_orphans(
    world: World, admin_url: Any, fresh_db: str, secrets_dir: Path, tmp_path: Path
) -> None:
    """Before the first claim, the worker removes run_root checkouts left by runs that ended while it was down (and
    unknown ones once old), never the checkout or the cached copy of a run still live (a run in its window)."""
    import os
    import time

    from ovlm.worker.main import Worker

    w = world
    run_id, cfg = _prepared_run(w, tmp_path)
    assert cfg.checkout_cache is not None
    orphan = str(uuid.uuid4())
    (cfg.run_root / orphan / "_checkout").mkdir(parents=True)
    (cfg.run_root / orphan / "_checkout.sha").write_text("a" * 40 + "\n")
    os.utime(cfg.run_root / orphan, (time.time() - 365 * 86400,) * 2)

    class Wf:
        worker_id = "w"
        registry = SimpleNamespace(sweepers=[])

        def register_worker(self, _v: str) -> None: ...

    worker = Worker(_worker_settings(admin_url, fresh_db, secrets_dir, cfg), w.worker, Wf())  # type: ignore[arg-type]
    worker._start_workflow()  # noqa: SLF001
    assert not (cfg.run_root / orphan).exists()
    assert (cfg.run_root / run_id / "_checkout").is_dir() and (
        cfg.checkout_cache / run_id / "_checkout"
    ).is_dir()
    # the same run, once terminal (it ended while this worker was down): removed at the next start-up
    w.x(
        "UPDATE workflow_run SET state = 'rolled_back', finished_at = now() WHERE id = :r", r=run_id
    )
    again = Worker(_worker_settings(admin_url, fresh_db, secrets_dir, cfg), w.worker, Wf())  # type: ignore[arg-type]
    again._start_workflow()  # noqa: SLF001
    assert not (cfg.run_root / run_id).exists() and not (cfg.checkout_cache / run_id).exists()


def test_a_live_run_that_loses_its_run_root_checkout_in_the_window_re_adopts_it_from_the_cache(
    world: World,
    admin_url: Any,
    fresh_db: str,
    secrets_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression for lab finding Z with the P0-1 sweeps in place: the worker's sweeps keep a live run's cached copy,
    and the guest port that already used the run's checkout does not hand out the vanished one; it re-adopts the
    cached copy by B6's recorded digest, with no git host contact inside the window."""
    from ovlm.worker.main import Worker

    w = world
    port, b6, run_id, cfg = _setup(w, tmp_path)
    first = port._prepared_for(run_id)  # noqa: SLF001
    assert first.checkout.is_dir() and port._in_outage(run_id)  # noqa: SLF001
    co.remove_tree(cfg.run_root)  # run_root lost mid-window (tmpfs emptied)
    worker = Worker(_worker_settings(admin_url, fresh_db, secrets_dir, cfg), w.worker)
    worker._sweep_checkouts()  # noqa: SLF001
    worker._sweep_checkouts(run_id)  # noqa: SLF001
    assert cfg.checkout_cache is not None and (cfg.checkout_cache / run_id / "_checkout").is_dir()
    git: list[Any] = []
    monkeypatch.setattr(co, "_git", lambda *a, **k: git.append(a))
    monkeypatch.setattr(co, "clone_verified", lambda *a, **k: git.append(a))
    again = port._prepared_for(run_id)  # noqa: SLF001
    assert git == [], "no git host contact inside the downtime window"
    assert again is not first and again.checkout.is_dir() and again.tree_digest == b6.tree_digest
    assert port.has_phase(run_id, "data_attach")
