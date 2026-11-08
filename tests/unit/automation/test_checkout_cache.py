"""The persistent copy of the verified checkout (``automation.checkout_cache``, lab finding Z).

A worker *container* restart empties the tmpfs ``run_root``; the run's checkout is then re-adopted from the cache,
but only when the tree digest of what is copied back equals the digest B6 recorded. Nothing contacts the git host.
"""

from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from ovlm.automation import checkout as co
from ovlm.automation.checkout import CloneOptions, tree_digest
from ovlm.automation.model import AutomationSpec, RunnerConfig
from ovlm.automation.runner import AutomationRunner, sweep_checkout_cache
from ovlm.automation.types import AutomationError, Classification, Phase
from tests.unit.automation.test_checkout import make_repo
from tests.unit.automation.test_runner import FILES

# ---- tree_digest ------------------------------------------------------------------------------------------------


def _tree(root: Path) -> Path:
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "f.yml").write_text("x: 1\n")
    (root / "run.sh").write_text("#!/bin/sh\n")
    (root / "run.sh").chmod(0o755)
    (root / "link").symlink_to("a/b/f.yml")
    return root


def _rewrite(path: Path, text: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(mode | stat.S_IWUSR)
    path.write_text(text)
    path.chmod(mode)


def test_tree_digest_is_deterministic_and_independent_of_the_location(tmp_path: Path) -> None:
    a = _tree(tmp_path / "one")
    b = _tree(tmp_path / "two")
    assert tree_digest(a) == tree_digest(a) == tree_digest(b)
    assert len(tree_digest(a)) == 64
    co.make_read_only(a)
    copy = tmp_path / "copy"
    co.copy_exact(a, copy)
    assert tree_digest(copy) == tree_digest(a) != tree_digest(b)  # read-only modes are part of it


@pytest.mark.parametrize("change", ["content", "mode", "symlink", "new_file", "rename", "dir_mode"])
def test_tree_digest_changes_with_any_change(tmp_path: Path, change: str) -> None:
    root = _tree(tmp_path / "t")
    before = tree_digest(root)
    if change == "content":
        _rewrite(root / "a" / "b" / "f.yml", "x: 2\n")
    elif change == "mode":
        (root / "run.sh").chmod(0o644)
    elif change == "symlink":
        (root / "link").unlink()
        (root / "link").symlink_to("run.sh")
    elif change == "new_file":
        (root / "a" / "extra").write_text("")
    elif change == "rename":
        (root / "run.sh").rename(root / "run2.sh")
    else:
        (root / "a").chmod(0o700)
    assert tree_digest(root) != before


def test_tree_digest_never_follows_symlinks(tmp_path: Path) -> None:
    root = _tree(tmp_path / "t")
    outside = tmp_path / "outside"
    outside.write_text("one")
    (root / "out").symlink_to(outside)
    before = tree_digest(root)
    outside.write_text("two")
    assert tree_digest(root) == before


def test_tree_digest_refuses_special_files(tmp_path: Path) -> None:
    root = _tree(tmp_path / "t")
    os.mkfifo(root / "fifo")
    with pytest.raises(AutomationError, match="unsupported file type"):
        tree_digest(root)


# ---- the runner with a checkout cache -----------------------------------------------------------------------


@pytest.fixture
def cached(tmp_path: Path) -> tuple[AutomationRunner, Any, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "ansible").write_text("#!/bin/sh\necho 'ansible [core 2.99.1]'\n")
    (bin_dir / "ansible").chmod(0o755)
    url, sha = make_repo(tmp_path / "src", {**FILES, "roles/r/tasks/main.yml": "- ansible.builtin.ping:\n"},
                         links={"playbooks/roles": "../roles"})  # fmt: skip
    cache = tmp_path / "cache"
    cfg = RunnerConfig(
        run_root=tmp_path / "run", checkout_cache=cache, ansible_bin_dir=bin_dir, run_user=None,
        clone=CloneOptions(allowed_repos=[url], allow_file=True),
        max_timeout={p: 100 for p in Phase}, default_timeout={p: 50 for p in Phase},
    )  # fmt: skip
    runner = AutomationRunner(cfg)
    prepared = runner.prepare_automation(AutomationSpec(repo=url, ref=sha), "wf1")
    return runner, prepared, cache


def _no_git(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Fail the test on any git call (the adoption path must never contact the git host)."""
    calls: list[list[str]] = []

    def forbidden(args: list[str], *_a: Any, **_k: Any) -> str:
        calls.append(args)
        raise AssertionError(f"git called on the adoption path: {args}")

    monkeypatch.setattr(co, "_git", forbidden)
    real_run = subprocess.run

    def run(cmd: Any, *a: Any, **k: Any) -> Any:
        if isinstance(cmd, list) and cmd and str(cmd[0]).endswith("git"):
            calls.append(cmd)
            raise AssertionError(f"git spawned on the adoption path: {cmd}")
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def _container_restart(runner: AutomationRunner) -> None:
    """The tmpfs run_root is empty after a container restart."""
    co.remove_tree(runner.cfg.run_root)


def test_prepare_records_the_digest_and_writes_a_private_read_only_copy(cached: Any) -> None:
    runner, prepared, cache = cached
    assert prepared.tree_digest == tree_digest(prepared.checkout)
    assert prepared.evidence()["tree_digest"] == prepared.tree_digest
    copy = cache / "wf1" / "_checkout"
    assert tree_digest(copy) == prepared.tree_digest
    for d in (cache, cache / "wf1"):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700 and d.stat().st_uid == os.geteuid()
    f = copy / "playbooks" / "configure.yml"
    assert stat.S_IMODE(f.stat().st_mode) & 0o222 == 0, "cached files stay read-only"
    assert (copy / "playbooks" / "roles").is_symlink()
    assert not (cache / "wf1" / "_checkout.tmp").exists()


def test_without_a_cache_prepare_writes_none(tmp_path: Path) -> None:
    url, sha = make_repo(tmp_path / "src", FILES)
    r = AutomationRunner(RunnerConfig(run_root=tmp_path / "run", run_user=None,
                                      clone=CloneOptions(allowed_repos=[url], allow_file=True)))  # fmt: skip
    prepared = r.prepare_automation(AutomationSpec(repo=url, ref=sha), "wf")
    assert prepared.tree_digest == tree_digest(prepared.checkout)
    assert not (tmp_path / "cache").exists()


def test_after_a_container_restart_the_cached_copy_is_adopted_when_the_digest_matches(
    cached: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, prepared, _cache = cached
    _container_restart(runner)
    calls = _no_git(monkeypatch)
    again = runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
    assert calls == []
    assert again is not None
    assert (again.sha, again.checkout, again.tree_digest) == (
        prepared.sha,
        prepared.checkout,
        prepared.tree_digest,
    )
    assert again.lint.ok and again.requirements_hash == prepared.requirements_hash
    assert tree_digest(again.checkout) == prepared.tree_digest  # same layout and modes in run_root
    assert (again.checkout.parent / "_checkout.sha").read_text().strip() == prepared.sha
    assert not (again.checkout.parent / "_checkout.adopt").exists()
    # the adopted checkout is usable as before: a later process restart adopts it from run_root
    assert (
        runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
        is not None
    )


def test_a_modified_cached_file_is_refused_for_a_human(
    cached: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, prepared, cache = cached
    _container_restart(runner)
    _rewrite(cache / "wf1" / "_checkout" / "playbooks" / "configure.yml", "- hosts: all\n")
    _no_git(monkeypatch)
    with pytest.raises(AutomationError, match="does not match the tree digest") as exc:
        runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN
    assert (
        not prepared.checkout.exists()
        and not (prepared.checkout.parent / "_checkout.adopt").exists()
    )
    assert not (prepared.checkout.parent / "_checkout.sha").exists()


def test_an_added_cached_file_is_refused(cached: Any) -> None:
    runner, prepared, cache = cached
    _container_restart(runner)
    pb = cache / "wf1" / "_checkout" / "playbooks"
    pb.chmod(0o755)
    (pb / "evil.yml").write_text("- hosts: all\n")
    pb.chmod(0o555)
    with pytest.raises(AutomationError) as exc:
        runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN


@pytest.mark.parametrize("expected", [None, ""])
def test_a_cached_copy_without_a_recorded_digest_is_refused(
    cached: Any, expected: str | None
) -> None:
    runner, prepared, _cache = cached
    _container_restart(runner)
    with pytest.raises(AutomationError, match="no recorded tree digest") as exc:
        runner.reverify_checkout(prepared.spec, "wf1", expected_digest=expected)
    assert exc.value.classification is Classification.NEEDS_HUMAN
    assert not prepared.checkout.exists()


def test_no_cache_copy_keeps_the_current_behaviour(cached: Any) -> None:
    runner, prepared, cache = cached
    _container_restart(runner)
    co.remove_tree(cache / "wf1")
    assert (
        runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest) is None
    )


def test_without_a_configured_cache_a_container_restart_leaves_nothing(tmp_path: Path) -> None:
    url, sha = make_repo(tmp_path / "src", FILES)
    r = AutomationRunner(RunnerConfig(run_root=tmp_path / "run", run_user=None,
                                      clone=CloneOptions(allowed_repos=[url], allow_file=True)))  # fmt: skip
    prepared = r.prepare_automation(AutomationSpec(repo=url, ref=sha), "wf")
    co.remove_tree(tmp_path / "run")
    assert r.reverify_checkout(prepared.spec, "wf", expected_digest=prepared.tree_digest) is None


def test_the_cache_is_not_trusted_for_another_sha(cached: Any) -> None:
    runner, prepared, _cache = cached
    _container_restart(runner)
    other = AutomationSpec(repo=prepared.spec.repo, ref="0" * 40)
    with pytest.raises(AutomationError):
        runner.reverify_checkout(other, "wf1", expected_digest="f" * 64)


def test_a_run_root_checkout_that_differs_from_the_recorded_digest_is_refused(cached: Any) -> None:
    runner, prepared, _cache = cached
    assert runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
    _rewrite(
        prepared.checkout / "playbooks" / "configure.yml", "- hosts: ovlm_target\n  tasks: []\n"
    )
    with pytest.raises(AutomationError, match="tree digest") as exc:
        runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN
    # a run prepared before the digest existed: no expected digest, no comparison (previous behaviour)
    assert runner.reverify_checkout(prepared.spec, "wf1") is not None


def test_a_cache_directory_not_owned_by_the_worker_is_refused(
    cached: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, prepared, _cache = cached
    _container_restart(runner)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    with pytest.raises(AutomationError, match="not a directory owned by the worker user") as exc:
        runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN


def test_a_loose_cache_directory_mode_is_tightened(cached: Any) -> None:
    runner, prepared, cache = cached
    cache.chmod(0o755)
    _container_restart(runner)
    assert runner.reverify_checkout(prepared.spec, "wf1", expected_digest=prepared.tree_digest)
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700


def test_release_and_a_failed_prepare_remove_the_cached_copy(cached: Any) -> None:
    runner, prepared, cache = cached
    runner.release(prepared)
    assert not (cache / "wf1").exists() and not prepared.checkout.exists()
    bad = AutomationSpec(repo=prepared.spec.repo, ref=prepared.sha, requirements="../../etc/passwd")
    with pytest.raises(AutomationError, match="escapes"):
        runner.prepare_automation(bad, "wf2")
    assert not (cache / "wf2").exists()


def test_sweep_removes_old_entries_of_finished_runs_only(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    for name in ("live", "done-old", "done-new"):
        (cache / name / "_checkout").mkdir(parents=True)
        (cache / name / "_checkout" / "f").write_text("x")
        co.make_read_only(cache / name / "_checkout")
    now = time.time()
    for name in ("live", "done-old"):
        os.utime(cache / name, (now - 10_000, now - 10_000))
    (cache / "stray-file").write_text("")
    removed = sweep_checkout_cache(cache, 3600, keep={"live"}, now=now)
    assert removed == [cache / "done-old"]
    assert sorted(p.name for p in cache.iterdir()) == ["done-new", "live", "stray-file"]
    assert sweep_checkout_cache(tmp_path / "missing", 1, keep=set()) == []


def test_settings_wire_the_cache_and_refuse_bad_paths() -> None:
    from ovlm.automation.config import runner_config
    from ovlm.config import Settings
    from ovlm.config.settings import AutomationSettings

    s = Settings(
        process_role="worker",
        automation=AutomationSettings(checkout_cache=Path("/var/lib/ovlm/checkouts")),
    )
    assert runner_config(s).checkout_cache == Path("/var/lib/ovlm/checkouts")
    assert runner_config(Settings(process_role="worker")).checkout_cache is None
    with pytest.raises(ValueError, match="absolute"):
        AutomationSettings(checkout_cache=Path("rel"))
    with pytest.raises(ValueError, match="outside automation.run_root"):
        AutomationSettings(checkout_cache=Path("/run/ovlm/cache"))
