"""Supervised subprocess: process group, kill escalation, PDEATHSIG, scrubbed env, user switch."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from ovlm.automation import process as proc
from ovlm.automation.process import descendants, run_supervised, scrubbed_env
from ovlm.automation.rundir import RunUser
from ovlm.automation.types import AutomationError


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def wait_dead(pid: int, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return False


def sup(tmp_path: Path, argv: list[str], **kw: Any) -> Any:
    (tmp_path / "art").mkdir(exist_ok=True)
    args: dict[str, Any] = dict(
        cwd=tmp_path, env=scrubbed_env({}), out_path=tmp_path / "out", watch_dir=tmp_path / "art",
        timeout=30, idle_timeout=30, max_artifact_bytes=10_000_000, kill_grace=1.0, poll=0.05,
    )  # fmt: skip
    args.update(kw)
    return run_supervised(argv, **args)


def test_runs_and_reports_exit_code_and_output(tmp_path: Path) -> None:
    out = sup(tmp_path, ["sh", "-c", "echo hello; exit 3"])
    assert out.exit_code == 3 and not out.timed_out and not out.killed
    assert (tmp_path / "out").read_text().strip() == "hello"


def test_own_session_and_process_group(tmp_path: Path) -> None:
    out = sup(tmp_path, ["sh", "-c", "ps -o pid=,pgid=,sid= -p $$"])
    pid, pgid, sid = map(int, (tmp_path / "out").read_text().split())
    assert pid == pgid == sid and pgid != os.getpgrp()
    assert out.exit_code == 0


def test_timeout_kills_the_whole_tree_including_other_sessions(tmp_path: Path) -> None:
    # a grandchild in a NEW session (as ansible-runner's pexpect does) is not in the process group
    script = tmp_path / "gc.sh"
    script.write_text(
        "setsid sh -c 'echo $$ > " + str(tmp_path / "gc.pid") + "; exec sleep 60' & wait\n"
    )
    out = sup(tmp_path, ["sh", str(script)], timeout=0.5, idle_timeout=30)
    assert out.timed_out and not out.killed and out.reason == "timeout"
    gc = int((tmp_path / "gc.pid").read_text())
    assert wait_dead(gc), "the grandchild in another session survived"


def test_sigterm_ignored_escalates_to_sigkill_after_grace(tmp_path: Path) -> None:
    script = "trap '' TERM; while :; do sleep 0.1; done"
    t0 = time.monotonic()
    out = sup(tmp_path, ["sh", "-c", script], timeout=0.3, kill_grace=1.0)
    assert out.timed_out and out.termination_signal == signal.SIGKILL
    assert 1.0 <= time.monotonic() - t0 < 6


def test_idle_timeout_when_no_progress(tmp_path: Path) -> None:
    out = sup(tmp_path, ["sleep", "30"], idle_timeout=0.5)
    assert out.timed_out and out.reason == "idle"


def test_progress_resets_the_idle_timer(tmp_path: Path) -> None:
    art = tmp_path / "art"
    art.mkdir()
    script = f"for i in 1 2 3 4 5 6; do echo $i >> {art}/log; sleep 0.4; done"
    out = sup(tmp_path, ["sh", "-c", script], idle_timeout=1.5)
    assert out.exit_code == 0 and not out.timed_out


def test_output_cap_kills(tmp_path: Path) -> None:
    art = tmp_path / "art"
    art.mkdir()
    script = f"while :; do head -c 100000 /dev/zero >> {art}/big; sleep 0.05; done"
    out = sup(tmp_path, ["sh", "-c", script], max_artifact_bytes=500_000)
    assert out.killed and out.reason == "output cap"


def test_fence_revocation_stops_the_process_at_once(tmp_path: Path) -> None:
    callbacks: list[Any] = []

    def register(cb: Any) -> Any:
        callbacks.append(cb)
        return lambda: callbacks.remove(cb)

    threading.Timer(0.5, lambda: [cb("lease lost") for cb in list(callbacks)]).start()
    t0 = time.monotonic()
    out = sup(tmp_path, ["sleep", "60"], register_revoke=register)
    assert out.killed and not out.timed_out and out.reason.startswith("revoked: lease lost")
    assert time.monotonic() - t0 < 5 and not callbacks, "callback unregistered after the run"


def test_parent_death_kills_the_child(tmp_path: Path) -> None:
    """PR_SET_PDEATHSIG: SIGKILL the worker mid-run and the runner process must die with it."""
    pidfile = tmp_path / "child.pid"
    parent = tmp_path / "parent.py"
    parent.write_text(
        textwrap.dedent(
            f"""
            import sys
            sys.path.insert(0, {str(Path(proc.__file__).parents[2])!r})
            from pathlib import Path
            from ovlm.automation.process import run_supervised, scrubbed_env
            Path({str(tmp_path / "art")!r}).mkdir(exist_ok=True)
            run_supervised(["sh", "-c", "echo $$ > {pidfile}; exec sleep 120"], cwd=Path({str(tmp_path)!r}),
                env=scrubbed_env({{}}), out_path=Path({str(tmp_path / "out")!r}),
                watch_dir=Path({str(tmp_path / "art")!r}), timeout=300, idle_timeout=300,
                max_artifact_bytes=10**9)
            """
        )
    )
    p = subprocess.Popen([sys.executable, str(parent)])  # noqa: S603
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(0.1)
    child = int(pidfile.read_text())
    assert alive(child)
    p.kill()
    p.wait()
    assert wait_dead(child), "the child survived its parent (PR_SET_PDEATHSIG not effective)"


def test_launcher_refuses_to_run_if_parent_is_not_the_expected_one(tmp_path: Path) -> None:
    r = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", proc._LAUNCHER, "999999", "true"],
        capture_output=True,
        check=False,
    )
    assert r.returncode == 125  # raced: the parent already died


def test_environment_is_built_from_scratch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for k, v in {
        "OS_PASSWORD": "x",
        "OVLM_DB_PASSWORD_FILE": "/x",
        "SSH_AUTH_SOCK": "/s",
        "KEK": "/k",
        "HOME": "/root",
    }.items():
        monkeypatch.setenv(k, v)
    env = scrubbed_env({"HOME": "/run/x"}, bin_dirs=[tmp_path])
    assert set(env) == {
        "PATH",
        "LANG",
        "LC_ALL",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONUNBUFFERED",
        "HOME",
    }
    assert env["HOME"] == "/run/x" and env["PATH"].startswith(str(tmp_path))
    out = sup(tmp_path, ["env"], env=env)
    seen = (tmp_path / "out").read_text()
    assert (
        out.exit_code == 0
        and "OS_PASSWORD" not in seen
        and "SSH_AUTH_SOCK" not in seen
        and "OVLM_" not in seen
    )


@pytest.mark.parametrize(
    "key",
    ["OS_AUTH_URL", "OVLM_DB", "DATABASE_URL", "PGPASSWORD", "MY_SECRET", "X_PASSWORD", "AWS_KEY"],
)
def test_credential_variables_are_refused(key: str) -> None:
    with pytest.raises(AutomationError):
        scrubbed_env({key: "v"})


def test_user_switch_uses_popen_credentials_not_preexec(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}
    real = subprocess.Popen

    class Spy(real):  # type: ignore[valid-type,misc]
        def __init__(self, *a: Any, **kw: Any) -> None:
            seen.update(kw)
            for k in ("user", "group", "extra_groups"):
                kw.pop(k, None)
            super().__init__(*a, **kw)

    monkeypatch.setattr(subprocess, "Popen", Spy)
    sup(tmp_path, ["true"], run_user=RunUser("ovlm-ansible", 12345, 23456), umask=0o007)
    assert seen["user"] == 12345 and seen["group"] == 23456 and seen["extra_groups"] == []
    assert "preexec_fn" not in seen and seen["start_new_session"] is True and seen["umask"] == 0o007
    assert seen["stdin"] == subprocess.DEVNULL and seen["close_fds"] is True


def test_signal_prefix_is_used_when_a_direct_kill_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def refuse(*_: Any) -> None:
        raise PermissionError

    monkeypatch.setattr(os, "kill", refuse)
    monkeypatch.setattr(os, "killpg", refuse)
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: calls.append(list(argv)))
    proc._send(signal.SIGTERM, [4321], 4000, ["sudo", "-n", "-u", "ovlm-ansible"])
    assert calls == [["sudo", "-n", "-u", "ovlm-ansible", "kill", "-15", "--", "4321", "-4000"]]


def test_descendants_walks_the_whole_tree() -> None:
    p = subprocess.Popen(["sh", "-c", "sleep 30 & setsid sleep 30 & wait"])  # noqa: S603, S607
    try:
        time.sleep(0.4)
        assert len(descendants(p.pid)) >= 2
    finally:
        for d in [*descendants(p.pid), p.pid]:
            with contextlib.suppress(ProcessLookupError):
                os.kill(d, signal.SIGKILL)
        p.wait()
