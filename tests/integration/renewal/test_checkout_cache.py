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


def test_a_b6_without_a_recorded_digest_cannot_adopt_the_cache(
    world: World, tmp_path: Path
) -> None:
    port, _b6, run_id, _cfg = _setup(world, tmp_path, record_digest=False)
    assert port._recorded_tree_digest(run_id) is None  # noqa: SLF001
    with pytest.raises(StepRefusal, match="automation_checkout_unverifiable") as exc:
        port._prepared_for(run_id)  # noqa: SLF001
    assert exc.value.error_class is ErrorClass.NEEDS_HUMAN
    assert "no recorded tree digest" in exc.value.detail["message"]


def test_the_worker_sweeps_cached_checkouts_of_finished_runs_only(
    world: World, admin_url: Any, fresh_db: str, secrets_dir: Path, tmp_path: Path
) -> None:
    """The cache must not grow forever: the worker removes the entries of terminal or unknown runs once they are
    older than the orphan max age; a live run keeps its copy whatever its age (it may wait days at a gate)."""
    import os
    import time

    from ovlm.config import Settings
    from ovlm.worker.main import Worker
    from tests.integration.conftest import settings_for

    w = world
    done = w.start()
    w.x("UPDATE workflow_run SET state = 'completed', finished_at = now() WHERE id = :r", r=done)
    live = w.start()  # one active renewal per service: the finished run first
    base = settings_for("worker", admin_url, fresh_db, secrets_dir).model_dump()
    base["automation"] |= {
        "run_root": str(tmp_path / "run"),
        "checkout_cache": str(tmp_path / "cache"),
    }
    settings = Settings(**base)
    cache = tmp_path / "cache"
    old = time.time() - 365 * 86400
    for name in (live, done, str(uuid.uuid4())):
        (cache / name / "_checkout").mkdir(parents=True)
        co.make_read_only(cache / name / "_checkout")
        os.utime(cache / name, (old, old))
    (cache / "fresh").mkdir()  # an unknown run, but just written: kept until it is old
    Worker(settings, w.worker)._sweep_checkout_cache()  # noqa: SLF001
    assert sorted(p.name for p in cache.iterdir()) == sorted([live, "fresh"])
