"""Lab bug W (2026-11-07): the reference ``quiesce`` role's "mount busy" check must be false on an idle mount.

``fuser -vm`` lists the ``kernel mount`` pseudo-entry and exits 0 on every mount, so the role parked every real
cutover at W1 with ``quiesce_old_failed``. CI never saw it: test mode skips the fuser branch. These tests take the
command from the role itself and run it on a real mount (root with a working ``mount -t tmpfs``; skipped otherwise),
plus a static guard that needs nothing.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

ROLE = Path(__file__).resolve().parents[3] / "ansible" / "roles" / "quiesce" / "tasks" / "main.yml"
BUSY_TASK = "Confirm no process holds the mount (read-only; fuser -m rc 0 means somebody does)"


def busy_check_argv(mount_point: str) -> list[str]:
    tasks = yaml.safe_load(ROLE.read_text())
    task = next(t for t in tasks if t.get("name") == BUSY_TASK)
    template = task["ansible.builtin.command"]
    rendered = template.replace("{{ ovlm_mount_point | quote }}", shlex.quote(mount_point))
    assert "{{" not in rendered, f"unrendered template: {template}"
    return shlex.split(rendered)


def test_the_busy_check_never_uses_verbose_fuser() -> None:
    argv = busy_check_argv("/srv/data")
    assert argv[0] == "fuser"
    flags = "".join(a.lstrip("-") for a in argv[1:] if a.startswith("-"))
    assert "m" in flags and "v" not in flags, argv


@pytest.fixture
def idle_mount(tmp_path: Path) -> Iterator[Path]:
    if os.geteuid() != 0 or shutil.which("fuser") is None:
        pytest.skip("needs root and fuser (psmisc)")
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    if subprocess.run(
        ["mount", "-t", "tmpfs", "none", str(mnt)], capture_output=True, check=False
    ).returncode:  # noqa: S603, S607
        pytest.skip("this environment cannot mount a tmpfs")
    try:
        yield mnt
    finally:
        subprocess.run(["umount", "-l", str(mnt)], capture_output=True, check=False)  # noqa: S603, S607


def test_an_idle_mount_is_not_busy(idle_mount: Path) -> None:
    proc = subprocess.run(
        busy_check_argv(str(idle_mount)), capture_output=True, text=True, check=False
    )  # noqa: S603
    assert proc.returncode != 0, f"idle mount reported busy: {proc.stdout!r} {proc.stderr!r}"


def test_a_process_inside_the_mount_is_busy(idle_mount: Path) -> None:
    holder = subprocess.Popen(["sleep", "60"], cwd=idle_mount)  # noqa: S603, S607
    try:
        proc = subprocess.run(
            busy_check_argv(str(idle_mount)), capture_output=True, text=True, check=False
        )  # noqa: S603
        assert proc.returncode == 0 and str(holder.pid) in proc.stdout, (proc.stdout, proc.stderr)
    finally:
        holder.kill()
        holder.wait()
