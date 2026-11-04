from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import pytest

from ovlm.automation.rundir import MARKER, RunDir, is_tmpfs, sweep_orphans
from ovlm.automation.types import AutomationError


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_layout_and_modes(tmp_path: Path) -> None:
    rd = RunDir.create(tmp_path / "root", "wf1", "step-1", 2)
    assert rd.path == tmp_path / "root" / "wf1" / "step-1" / "2"
    assert mode(rd.path) == 0o700
    for sub in ("project", "inventory", "env", "artifacts", "tmp", "home"):
        assert mode(rd.path / sub) == 0o700
    assert (rd.path / MARKER).is_file() and mode(rd.path / MARKER) == 0o600


def test_secret_files_are_0600_exclusive_and_wiped(tmp_path: Path) -> None:
    rd = RunDir.create(tmp_path, "wf", "s", 1)
    key = rd.write_secret("env/guest_key", b"PRIVATE")
    assert mode(key) == 0o600
    with pytest.raises(FileExistsError):
        rd.write_secret("env/guest_key", b"again")  # never silently reused
    inode = key.stat().st_ino
    fd = os.open(key, os.O_RDONLY)  # keep the inode alive to inspect what was left behind
    try:
        rd.wipe()
        assert not rd.path.exists()
        assert os.fstat(fd).st_nlink == 0 and os.read(fd, 100) == b"\0" * 7, (
            "contents overwritten before unlink"
        )
    finally:
        os.close(fd)
    assert inode


def test_umask_does_not_matter(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        rd = RunDir.create(tmp_path, "wf", "s", 1)
        assert mode(rd.write_secret("env/x", b"y")) == 0o600
        assert mode(rd.path) == 0o700
    finally:
        os.umask(old)


@pytest.mark.parametrize("bad", ["", "..", "a/b", "../x", ".hidden", "a b", "x" * 65, "a\nb"])
def test_ids_cannot_traverse(tmp_path: Path, bad: str) -> None:
    with pytest.raises(AutomationError):
        RunDir.create(tmp_path, bad, "s", 1)
    with pytest.raises(AutomationError):
        RunDir.create(tmp_path, "wf", bad, 1)


def test_writes_cannot_escape_the_run_dir(tmp_path: Path) -> None:
    rd = RunDir.create(tmp_path, "wf", "s", 1)
    with pytest.raises(AutomationError):
        rd.write_file("../evil", b"x")
    with pytest.raises(AutomationError):
        rd.write_file("/etc/evil", b"x")
    (rd.path / "tmp" / "link").symlink_to(tmp_path / "target")
    with pytest.raises((OSError, AutomationError)):
        rd.write_file("tmp/link", b"x")  # O_NOFOLLOW / resolve check


def test_attempts_never_share_a_directory(tmp_path: Path) -> None:
    RunDir.create(tmp_path, "wf", "s", 1)
    with pytest.raises(AutomationError, match="already exists"):
        RunDir.create(tmp_path, "wf", "s", 1)
    RunDir.create(tmp_path, "wf", "s", 2)


def test_require_tmpfs_refuses_a_disk_root(tmp_path: Path) -> None:
    if is_tmpfs(tmp_path):
        pytest.skip("tmp_path is on tmpfs here; the refusal path needs a non-tmpfs root")
    with pytest.raises(AutomationError, match="tmpfs"):
        RunDir.create(tmp_path, "wf", "s", 1, require_tmpfs=True)


SHM = Path("/dev") / "shm"


def test_is_tmpfs_detects_dev_shm() -> None:
    if not SHM.is_dir():
        pytest.skip("no /dev/shm")
    assert is_tmpfs(SHM)


def test_wipe_is_idempotent_and_removes_empty_parents(tmp_path: Path) -> None:
    rd = RunDir.create(tmp_path, "wf", "s", 1)
    rd.wipe()
    rd.wipe()
    assert not (tmp_path / "wf").exists()


def test_sweeper_wipes_old_orphans_only(tmp_path: Path) -> None:
    old = RunDir.create(tmp_path, "wf", "old", 1)
    fresh = RunDir.create(tmp_path, "wf", "fresh", 1)
    live = RunDir.create(tmp_path, "wf", "live", 1)
    for rd in (old, fresh, live):
        rd.write_secret("env/k", b"secret")
    # forge the markers: a dead creator long ago, a dead creator just now, a live creator long ago
    import json

    (old.path / MARKER).write_text(
        json.dumps({"pid": 2**22 + 12345, "created": time.time() - 10_000})
    )
    (fresh.path / MARKER).write_text(json.dumps({"pid": 2**22 + 12345, "created": time.time()}))
    (live.path / MARKER).write_text(json.dumps({"pid": 1, "created": time.time() - 10_000}))
    removed = sweep_orphans(tmp_path, max_age=3600)
    assert removed == [old.path]
    assert not old.path.exists() and fresh.path.exists() and live.path.exists()
    # a run dir with no readable marker counts as ancient and unowned
    (fresh.path / MARKER).write_text("garbage")
    assert sweep_orphans(tmp_path, max_age=3600) == [fresh.path]
