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
from ovlm.automation.runner import (
    CACHE_MARKER,
    AutomationRunner,
    check_checkout_cache,
    sweep_checkout_cache,
    sweep_run_root_checkouts,
)
from ovlm.automation.types import AutomationError, Classification, Phase
from tests.unit.automation.test_checkout import make_repo
from tests.unit.automation.test_runner import FILES

WF1 = "6f1d9a3e-0000-4000-8000-0000000000f1"
#: run ids as the worker names cache entries (canonical UUIDs)
LIVE, DONE_OLD, DONE_NEW, DONE, UNKNOWN = (
    f"6f1d9a3e-0000-4000-8000-00000000000{i}" for i in range(1, 6)
)

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
    prepared = runner.prepare_automation(AutomationSpec(repo=url, ref=sha), WF1)
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
    copy = cache / WF1 / "_checkout"
    assert tree_digest(copy) == prepared.tree_digest
    for d in (cache, cache / WF1):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700 and d.stat().st_uid == os.geteuid()
    f = copy / "playbooks" / "configure.yml"
    assert stat.S_IMODE(f.stat().st_mode) & 0o222 == 0, "cached files stay read-only"
    assert (copy / "playbooks" / "roles").is_symlink()
    assert not (cache / WF1 / "_checkout.tmp").exists()


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
    again = runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
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
        runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
        is not None
    )


def test_a_modified_cached_file_is_refused_for_a_human(
    cached: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, prepared, cache = cached
    _container_restart(runner)
    _rewrite(cache / WF1 / "_checkout" / "playbooks" / "configure.yml", "- hosts: all\n")
    _no_git(monkeypatch)
    with pytest.raises(AutomationError, match="does not match the tree digest") as exc:
        runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN
    assert (
        not prepared.checkout.exists()
        and not (prepared.checkout.parent / "_checkout.adopt").exists()
    )
    assert not (prepared.checkout.parent / "_checkout.sha").exists()


def test_an_added_cached_file_is_refused(cached: Any) -> None:
    runner, prepared, cache = cached
    _container_restart(runner)
    pb = cache / WF1 / "_checkout" / "playbooks"
    pb.chmod(0o755)
    (pb / "evil.yml").write_text("- hosts: all\n")
    pb.chmod(0o555)
    with pytest.raises(AutomationError) as exc:
        runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN


@pytest.mark.parametrize("expected", [None, ""])
def test_a_cached_copy_without_a_recorded_digest_is_refused(
    cached: Any, expected: str | None
) -> None:
    runner, prepared, _cache = cached
    _container_restart(runner)
    with pytest.raises(AutomationError, match="no recorded tree digest") as exc:
        runner.reverify_checkout(prepared.spec, WF1, expected_digest=expected)
    assert exc.value.classification is Classification.NEEDS_HUMAN
    assert not prepared.checkout.exists()


def test_no_cache_copy_keeps_the_current_behaviour(cached: Any) -> None:
    runner, prepared, cache = cached
    _container_restart(runner)
    co.remove_tree(cache / WF1)
    assert (
        runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest) is None
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
        runner.reverify_checkout(other, WF1, expected_digest="f" * 64)


def test_a_run_root_checkout_that_differs_from_the_recorded_digest_is_refused(cached: Any) -> None:
    runner, prepared, _cache = cached
    assert runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
    _rewrite(
        prepared.checkout / "playbooks" / "configure.yml", "- hosts: ovlm_target\n  tasks: []\n"
    )
    with pytest.raises(AutomationError, match="tree digest") as exc:
        runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN
    # a run prepared before the digest existed: no expected digest, no comparison (previous behaviour)
    assert runner.reverify_checkout(prepared.spec, WF1) is not None


def test_a_cache_directory_not_owned_by_the_worker_is_refused(
    cached: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, prepared, _cache = cached
    _container_restart(runner)
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    with pytest.raises(AutomationError, match="not a directory owned by the worker user") as exc:
        runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
    assert exc.value.classification is Classification.NEEDS_HUMAN


def test_a_loose_cache_directory_mode_is_tightened(cached: Any) -> None:
    runner, prepared, cache = cached
    cache.chmod(0o755)
    _container_restart(runner)
    assert runner.reverify_checkout(prepared.spec, WF1, expected_digest=prepared.tree_digest)
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700


def test_release_and_a_failed_prepare_remove_the_cached_copy(cached: Any) -> None:
    runner, prepared, cache = cached
    runner.release(prepared)
    assert not (cache / WF1).exists() and not prepared.checkout.exists()
    bad = AutomationSpec(repo=prepared.spec.repo, ref=prepared.sha, requirements="../../etc/passwd")
    with pytest.raises(AutomationError, match="escapes"):
        runner.prepare_automation(bad, "wf2")
    assert not (cache / "wf2").exists()


def test_sweep_removes_old_entries_of_finished_runs_only(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    for name in (LIVE, DONE_OLD, DONE_NEW):
        (cache / name / "_checkout").mkdir(parents=True)
        (cache / name / "_checkout" / "f").write_text("x")
        co.make_read_only(cache / name / "_checkout")
    now = time.time()
    for name in (LIVE, DONE_OLD):
        os.utime(cache / name, (now - 10_000, now - 10_000))
    (cache / "stray-file").write_text("")
    removed = sweep_checkout_cache(cache, 3600, keep={LIVE}, now=now)
    assert removed == [cache / DONE_OLD]
    assert sorted(p.name for p in cache.iterdir()) == sorted([DONE_NEW, LIVE, "stray-file"])
    assert sweep_checkout_cache(tmp_path / "missing", 1, keep=set()) == []


def test_sweep_removes_the_entry_of_a_terminal_run_at_once(tmp_path: Path) -> None:
    """Terminal is final: no age guard for a run the database reads terminal (roadmap P0-1)."""
    cache = tmp_path / "cache"
    for name in (LIVE, DONE, UNKNOWN):
        (cache / name / "_checkout").mkdir(parents=True)
        co.make_read_only(cache / name / "_checkout")
    removed = sweep_checkout_cache(cache, 3600, keep={LIVE}, terminal={DONE, LIVE})
    assert removed == [cache / DONE]
    assert sorted(p.name for p in cache.iterdir()) == sorted([LIVE, UNKNOWN])


def test_sweep_leaves_entries_ovlm_did_not_write(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Review PMR-3 (the review's probe): the cache root named next to other worker state. A ``credentials``
    directory, a run-id-shaped directory holding something else than checkout copies, a non-canonical id and a run
    entry are all old; only the run entry goes, the rest is left alone and logged."""
    cache = tmp_path / "cache"
    (cache / "credentials").mkdir(parents=True)
    (cache / "credentials" / "secret.json").write_text("x")
    (cache / DONE / "_checkout").mkdir(parents=True)
    (cache / UNKNOWN / "notes.txt").parent.mkdir()
    (cache / UNKNOWN / "notes.txt").write_text("operator's")
    (cache / DONE_OLD.upper()).mkdir()
    (cache / LIVE).symlink_to(cache / "credentials")
    old = time.time() - 10 * 3600
    for p in cache.iterdir():
        os.utime(p, (old, old), follow_symlinks=False)
    with caplog.at_level("WARNING", logger="ovlm.automation.runner"):
        removed = sweep_checkout_cache(cache, 3600, keep=set())
    assert removed == [cache / DONE]
    assert (cache / "credentials" / "secret.json").read_text() == "x"
    assert (cache / UNKNOWN / "notes.txt").is_file() and (cache / DONE_OLD.upper()).is_dir()
    assert "checkout cache sweep left entries OVLM did not write" in caplog.text
    # a run-id directory with copies moved aside on a digest mismatch (PMR-6) is still OVLM's
    (cache / DONE / "_checkout").mkdir(parents=True)
    (cache / DONE / "_checkout.mismatch-20261109T101500.123456Z").mkdir()
    assert sweep_checkout_cache(cache, 3600, keep=set(), terminal={DONE}) == [cache / DONE]


def test_the_cache_directory_must_be_the_workers_own(tmp_path: Path) -> None:
    """Review PMR-3: a cache directory that holds other entries (shared with other worker state) is refused before
    anything is chmod-ed or swept there; a new one gets OVLM's marker, an existing one holding only run entries gets
    it too; after that, a foreign entry is tolerated (the sweep leaves it alone)."""
    shared = tmp_path / "var-lib-ovlm"
    (shared / "credentials").mkdir(parents=True)
    os.chmod(shared, 0o755)  # noqa: S103 - an operator's directory, readable by others
    with pytest.raises(AutomationError, match="entries OVLM did not write"):
        check_checkout_cache(shared)
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755 and not (shared / CACHE_MARKER).exists()
    fresh = tmp_path / "checkouts"
    check_checkout_cache(fresh)
    assert (fresh / CACHE_MARKER).is_file() and stat.S_IMODE(fresh.stat().st_mode) == 0o700
    legacy = tmp_path / "legacy"  # a cache from before the marker, on a filesystem of its own
    (legacy / DONE / "_checkout").mkdir(parents=True)
    (legacy / "lost+found").mkdir()
    check_checkout_cache(legacy)
    assert (legacy / CACHE_MARKER).is_file()
    (legacy / "other").mkdir()  # marked as OVLM's: tolerated, the sweep leaves it alone
    check_checkout_cache(legacy)
    link = tmp_path / "link"
    link.symlink_to(fresh)
    with pytest.raises(AutomationError, match="not a directory owned by the worker user"):
        check_checkout_cache(link)


def test_the_worker_refuses_to_start_on_a_shared_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ovlm.config import Settings
    from ovlm.worker import main as worker_main

    shared = tmp_path / "var-lib-ovlm"
    (shared / "credentials").mkdir(parents=True)
    s = Settings(process_role="worker", development_mode=True,
                 automation={"run_root": str(tmp_path / "run"), "checkout_cache": str(shared)})  # fmt: skip
    monkeypatch.setattr(
        worker_main, "make_engine", lambda settings: type("E", (), {"dispose": lambda self: None})()
    )
    monkeypatch.setattr(worker_main, "check_schema_at_head", lambda engine, d: None)
    assert worker_main.run(s) == 1


def test_settings_refuse_a_cache_that_holds_or_sits_in_other_worker_state() -> None:
    from ovlm.config import Settings

    for cache, creds in (("/var/lib/ovlm", "/var/lib/ovlm/credentials"), ("/var/lib/ovlm/c", "/var/lib/ovlm/c"),
                         ("/srv/creds/cache", "/srv/creds")):  # fmt: skip
        with pytest.raises(ValueError, match="must not be or contain the renewal.credentials_dir"):
            Settings(process_role="worker", development_mode=True, automation={"checkout_cache": cache},
                     renewal={"credentials_dir": creds})  # fmt: skip
    with pytest.raises(ValueError, match="kek key directory"):
        Settings(process_role="worker", automation={"checkout_cache": "/run/secrets", "run_user": "ovlm-ansible"},
                 kek={"private_key_file": "/run/secrets/kek.pem"})  # fmt: skip
    Settings(process_role="worker", development_mode=True, automation={"checkout_cache": "/var/lib/ovlm/checkouts"},
             renewal={"credentials_dir": "/var/lib/ovlm/credentials"})  # fmt: skip


def _run_root_checkout(run_root: Path, name: str, *, age: float = 0.0) -> Path:
    entry = run_root / name
    (entry / "_checkout" / "playbooks").mkdir(parents=True)
    (entry / "_checkout" / "playbooks" / "quiesce.yml").write_text("- hosts: all\n")
    co.make_read_only(entry / "_checkout")
    (entry / "_checkout.sha").write_text("a" * 40 + "\n")
    if age:
        then = time.time() - age
        os.utime(entry, (then, then))
    return entry


def test_run_root_sweep_removes_checkouts_of_terminal_and_old_unknown_runs_only(
    tmp_path: Path,
) -> None:
    """Roadmap P0-1: the run-level checkouts on the tmpfs run_root follow the checkout cache rules."""
    root = tmp_path / "run"
    live = _run_root_checkout(root, "live", age=10_000)
    done = _run_root_checkout(root, "done")  # just finished: removed at once
    old = _run_root_checkout(root, "old-unknown", age=10_000)
    young = _run_root_checkout(root, "young-unknown")  # may be a run admitted after keep was read
    (old / "_checkout.adopt").mkdir()  # an interrupted adoption goes with it
    os.utime(old, (time.time() - 10_000,) * 2)
    for dot in (".ca", ".cp", ".ssh-1234abcd"):
        (root / dot).mkdir()
        os.utime(root / dot, (0, 0))
    removed = sweep_run_root_checkouts(root, 3600, keep={"live"}, terminal={"done"})
    assert sorted(removed) == sorted([done, old])
    assert not done.exists() and not old.exists()
    assert (live / "_checkout").is_dir() and (live / "_checkout.sha").is_file()
    assert (young / "_checkout").is_dir()
    assert sorted(p.name for p in root.iterdir()) == [
        ".ca", ".cp", ".ssh-1234abcd", "live", "young-unknown",
    ]  # fmt: skip
    assert sweep_run_root_checkouts(tmp_path / "missing", 1, keep=()) == []


def test_run_root_sweep_leaves_step_run_directories_to_the_orphan_sweeper(tmp_path: Path) -> None:
    """A step run dir (secrets, maybe a live process) is never removed here: only the checkout goes."""
    root = tmp_path / "run"
    entry = _run_root_checkout(root, "done")
    (entry / "step1" / "1" / "env").mkdir(parents=True)
    (entry / "nothing-here").mkdir()
    assert sweep_run_root_checkouts(root, 3600, keep=(), terminal={"done"}) == [entry]
    assert sorted(p.name for p in entry.iterdir()) == ["nothing-here", "step1"]
    # an entry without a checkout is not reported
    assert sweep_run_root_checkouts(root, 3600, keep=(), terminal={"done"}) == []


def test_the_terminal_sweep_of_both_roots_leaves_nothing_of_a_prepared_run(cached: Any) -> None:
    """``prepare_automation`` writes ``<run_root>/<id>/_checkout`` + ``_checkout.sha`` and the cache copy; the
    terminal sweep of both roots leaves nothing of the run, and a live run's are kept."""
    runner, prepared, cache = cached
    run_root = runner.cfg.run_root
    assert (
        prepared.checkout == run_root / WF1 / "_checkout"
        and (run_root / WF1 / "_checkout.sha").is_file()
    )
    assert sweep_run_root_checkouts(run_root, 0, keep={WF1}, terminal={WF1}) == []
    assert sweep_checkout_cache(cache, 0, keep={WF1}, terminal={WF1}) == []
    assert prepared.checkout.is_dir() and (cache / WF1 / "_checkout").is_dir()
    assert sweep_run_root_checkouts(run_root, 3600, keep=(), terminal={WF1}) == [run_root / WF1]
    assert sweep_checkout_cache(cache, 3600, keep=(), terminal={WF1}) == [cache / WF1]
    assert not (run_root / WF1).exists() and not (cache / WF1).exists()


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
