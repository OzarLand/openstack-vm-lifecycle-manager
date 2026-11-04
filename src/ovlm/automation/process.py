"""Supervised subprocess: own session/process group, parent-death signal, timeouts, scrubbed environment.

* The child is a tiny launcher (``python -I -c``) that sets ``PR_SET_PDEATHSIG(SIGKILL)``, checks the parent is
  still the expected one (no race between fork and prctl), then ``exec``s ansible-runner. It runs as the
  separate OS user (``Popen(user=...)``), so the credential change happens *before* the prctl (a credential
  change clears the signal) and no ``preexec_fn`` is needed (it is unsafe in a threaded worker).
* PDEATHSIG fires when the *thread* that spawned the child exits: the caller must spawn and wait in the same
  (step) thread, which :func:`run_supervised` does.
* ansible-runner runs ansible-playbook in a new session, so the process group alone does not reach it: signals
  go to the process group *and* to every descendant found in ``/proc``; after the run, anything still
  referencing the run directory is killed (:func:`ovlm.automation.rundir.processes_referencing`).
* Signalling another user's processes needs privilege: if a direct ``kill`` is refused, ``signal_prefix``
  (e.g. ``["sudo", "-n", "-u", "ovlm-ansible"]``) is prepended to ``kill`` (deployment: a sudoers rule limited to
  ``/bin/kill``). The runner's own job/idle timeouts need no cross-user signal.
* The environment is built from scratch: nothing is inherited (no ``OS_*``, no DB URL, no KEK path).
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ovlm.automation.rundir import RunUser
from ovlm.automation.types import KILL_GRACE_SECONDS, AutomationError

log = logging.getLogger("ovlm.automation.process")

_LAUNCHER = (
    "import ctypes,os,signal,sys\n"
    "libc=ctypes.CDLL(None,use_errno=True)\n"
    "if libc.prctl(1,int(signal.SIGKILL),0,0,0)!=0: os._exit(126)\n"  # PR_SET_PDEATHSIG = 1
    "if os.getppid()!=int(sys.argv[1]): os._exit(125)\n"  # the parent died before the prctl took effect
    "os.execvpe(sys.argv[2],sys.argv[2:],dict(os.environ))\n"
)
_SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"


def scrubbed_env(extra: dict[str, str], *, bin_dirs: Sequence[Path] = ()) -> dict[str, str]:
    """A from-scratch environment: a fixed PATH (plus the directories of the ansible binaries), a UTF-8 locale and
    what the caller passes explicitly. Refuses to carry anything that looks like a credential variable."""
    path = ":".join([*(str(d) for d in bin_dirs), _SAFE_PATH])
    env = {
        "PATH": path,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        **extra,
    }
    for key in env:
        up = key.upper()
        # a ``*_FILE`` variable carries a path (e.g. ANSIBLE_VAULT_PASSWORD_FILE), never the value
        names_a_value = ("SECRET" in up or "PASSWORD" in up) and not up.endswith("_FILE")
        if up.startswith(("OS_", "OVLM_", "AWS_", "DATABASE", "PG")) or names_a_value:
            raise AutomationError(f"refusing to pass {key} to the runner")
    return env


# ---- signalling ---------------------------------------------------------------------------------------------


def descendants(root_pid: int) -> list[int]:
    """All descendants of ``root_pid`` (children, grandchildren, ... in other sessions too), via /proc."""
    children: dict[int, list[int]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as fh:
                data = fh.read().decode("utf-8", "replace")
            ppid = int(data.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(int(entry))
    out: list[int] = []
    stack = [root_pid]
    while stack:
        for child in children.get(stack.pop(), []):
            out.append(child)
            stack.append(child)
    return out


def _send(sig: int, pids: Iterable[int], pgid: int | None, prefix: Sequence[str]) -> None:
    refused: list[str] = []
    targets: list[tuple[str, int]] = [("pid", p) for p in pids]
    if pgid is not None:
        targets.append(("pgid", pgid))
    for kind, ident in targets:
        try:
            if kind == "pgid":
                os.killpg(ident, sig)
            else:
                os.kill(ident, sig)
        except ProcessLookupError:
            continue
        except PermissionError:
            refused.append(str(-ident if kind == "pgid" else ident))
    if refused and prefix:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(  # noqa: S603
                [*prefix, "kill", f"-{int(sig)}", "--", *refused],
                capture_output=True, timeout=10, check=False,
            )  # fmt: skip
    elif refused:
        log.error("signal refused (different user) and no signal_prefix configured")


def kill_pids(pids: Iterable[int], *, prefix: Sequence[str] = ()) -> None:
    """SIGKILL ``pids`` (used for stragglers and by the orphan sweeper)."""
    _send(signal.SIGKILL, list(pids), None, prefix)


# ---- supervision --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessOutcome:
    exit_code: int | None
    timed_out: bool
    killed: bool
    reason: str  # "", "timeout", "idle", "revoked: ...", "output cap"
    duration: float
    termination_signal: int | None = None


def _dir_state(path: Path) -> tuple[int, float]:
    """(total bytes, newest mtime) under ``path`` - cheap progress/size probe for the idle and size watchdogs."""
    total, newest = 0, 0.0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(Path(e.path))
                        else:
                            st = e.stat(follow_symlinks=False)
                            total += st.st_size
                            newest = max(newest, st.st_mtime)
                    except OSError:
                        continue
        except OSError:
            continue
    return total, newest


def run_supervised(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: dict[str, str],
    out_path: Path,
    watch_dir: Path,
    timeout: float,
    idle_timeout: float,
    max_artifact_bytes: int,
    run_user: RunUser | None = None,
    signal_prefix: Sequence[str] = (),
    register_revoke: Callable[[Callable[[str], None]], Callable[[], None]] | None = None,
    kill_grace: float = KILL_GRACE_SECONDS,
    umask: int = 0o077,
    poll: float = 0.2,
) -> ProcessOutcome:
    """Run ``argv`` to completion or to the first limit. ``register_revoke`` is ``Fence.add_revoke_callback``: it
    stops the process group at once when the attempt loses ownership."""
    cmd = [sys.executable, "-I", "-c", _LAUNCHER, str(os.getpid()), *argv]
    kwargs: dict[str, object] = {}
    if run_user is not None:
        kwargs.update(user=run_user.uid, group=run_user.gid, extra_groups=[])
    start = time.monotonic()
    stop_reason: list[str] = []
    stop_at: list[float] = []
    lock = threading.Lock()
    with open(out_path, "wb") as out:
        proc = subprocess.Popen(  # noqa: S603
            cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=True, umask=umask, **kwargs,  # type: ignore[call-overload]
        )  # fmt: skip
        pgid = proc.pid  # start_new_session: the child leads its own group and session

        def stop(reason: str) -> None:
            with lock:
                if stop_reason:
                    return
                stop_reason.append(reason)
                stop_at.append(time.monotonic())
            _send(signal.SIGTERM, descendants(proc.pid), pgid, signal_prefix)

        unregister = register_revoke(lambda r: stop(f"revoked: {r}")) if register_revoke else None
        last_state, last_change = (-1, 0.0), time.monotonic()
        next_probe = 0.0
        try:
            while True:
                try:
                    proc.wait(timeout=poll)
                    break
                except subprocess.TimeoutExpired:
                    pass
                now = time.monotonic()
                if stop_reason and now - stop_at[0] > kill_grace:
                    _send(signal.SIGKILL, descendants(proc.pid), pgid, signal_prefix)
                if not stop_reason:
                    if now - start > timeout:
                        stop("timeout")
                    elif now >= next_probe:
                        next_probe = now + 1.0
                        state = _dir_state(watch_dir)
                        if state != last_state:
                            last_state, last_change = state, now
                        if state[0] > max_artifact_bytes:
                            stop("output cap")
                        elif now - last_change > idle_timeout:
                            stop("idle")
        finally:
            if unregister:
                unregister()
            # whatever happened, nothing of this run may survive the supervisor
            leftovers = descendants(proc.pid)
            if leftovers:
                _send(signal.SIGKILL, leftovers, None, signal_prefix)
            if proc.poll() is None:
                _send(signal.SIGKILL, [], pgid, signal_prefix)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=5)
    rc = proc.returncode
    reason = stop_reason[0] if stop_reason else ""
    timed_out = reason in {"timeout", "idle"}
    killed = bool(reason) and not timed_out
    sig = -rc if rc is not None and rc < 0 else None
    return ProcessOutcome(
        exit_code=None if rc is not None and rc < 0 else rc,
        timed_out=timed_out,
        killed=killed or (sig is not None and not timed_out),
        reason=reason or (f"signal {sig}" if sig else ""),
        duration=time.monotonic() - start,
        termination_signal=sig,
    )
