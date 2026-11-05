"""Per-run private directory (automation-contract.md sections 2 and 5, security-model 6.5).

Layout ``<run_root>/<workflow_id>/<step_id>/<attempt>/{project,inventory,env,artifacts,tmp,home}``, mode 0700
(tmpfs recommended: ``architecture.md`` mounts ``automation.run_root`` as tmpfs). Secrets are created with
``O_EXCL`` at 0600, overwritten and unlinked at the end, and never appear on a command line. A marker file lets
the startup sweeper find and wipe orphans (worker killed mid-run).

Cross-user access: ansible runs as ``ovlm-ansible``. When the worker is root (or has CAP_CHOWN) the run dir is
chowned to that user and keeps 0700/0600. Otherwise it is group-owned by the runner's group (the worker must be
a member) with 0770/0660 and the ancestors below ``run_root`` are traversable by the group only (0710). The KEK
and DB secret files stay unreadable to ``ovlm-ansible`` either way: they are owned by the worker user, mode 0400.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ovlm.automation.types import AutomationError

log = logging.getLogger("ovlm.automation.rundir")

MARKER = ".ovlm-run"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SUBDIRS = ("project", "inventory", "env", "artifacts", "tmp", "home")


@dataclass(frozen=True)
class RunUser:
    """The unprivileged OS user ansible runs as (``ovlm-ansible``)."""

    name: str
    uid: int
    gid: int

    @classmethod
    def lookup(cls, name: str) -> RunUser:
        import pwd

        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            raise AutomationError(f"runner OS user {name!r} does not exist") from None
        return cls(name, pw.pw_uid, pw.pw_gid)


def is_tmpfs(path: Path) -> bool:
    """True if ``path`` lives on a tmpfs/ramfs mount (longest mount-point prefix in /proc/mounts)."""
    try:
        real = str(path.resolve())
        best, fstype = "", ""
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mnt = parts[1].replace("\\040", " ")
                if (real == mnt or real.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(
                    best
                ):
                    best, fstype = mnt, parts[2]
        return fstype in {"tmpfs", "ramfs"}
    except OSError:
        return False


def _check_id(value: str, what: str) -> str:
    if not _ID_RE.match(value):
        raise AutomationError(f"invalid {what} for a run directory")
    return value


class RunDir:
    def __init__(self, path: Path, run_user: RunUser | None, owned: bool) -> None:
        self.path = path
        self.run_user = run_user
        self._owned = owned  # True: chowned to the run user, strict modes
        self._secrets: list[Path] = []
        self._extra_dirs: list[Path] = []
        self._wiped = False

    # ---- creation ---------------------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        run_root: Path,
        workflow_id: str,
        step_id: str,
        attempt: int,
        *,
        run_user: RunUser | None = None,
        require_tmpfs: bool = False,
    ) -> RunDir:
        if attempt < 0:
            raise AutomationError("invalid attempt")
        run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not is_tmpfs(run_root):
            if require_tmpfs:
                raise AutomationError("automation run_root is not tmpfs and require_tmpfs is set")
            log.warning("automation run_root is not tmpfs; secrets touch persistent storage")
        path = (
            run_root
            / _check_id(workflow_id, "workflow id")
            / _check_id(step_id, "step id")
            / str(attempt)
        )
        if path.exists():
            raise AutomationError("run directory already exists (attempts never share a directory)")
        owned = False
        if run_user is not None:
            owned = os.geteuid() == 0
        # ancestors, run_root included: traversal only (the runner user must reach its own run dir)
        anc_mode = 0o711 if owned else 0o710
        for parent in (run_root, path.parent.parent, path.parent):
            parent.mkdir(exist_ok=True, mode=anc_mode)
            if run_user is not None:
                cls._allow_traversal(parent, run_user, owned, anc_mode)
        path.mkdir(mode=0o700)
        rd = cls(path, run_user, owned)
        rd._share_path(path, is_dir=True)
        for sub in SUBDIRS:
            d = path / sub
            d.mkdir(mode=0o700)
            rd._share_path(d, is_dir=True)
        rd.write_file(
            MARKER, json.dumps({"pid": os.getpid(), "created": time.time()}).encode(), mode=0o600
        )
        return rd

    @staticmethod
    def allow_traversal(p: Path, user: RunUser, owned: bool) -> None:
        RunDir._allow_traversal(p, user, owned, 0o711 if owned else 0o710)

    def adopt_dir(self, path: Path) -> None:
        """A directory outside the run dir (the short ssh control dir) that must disappear with it."""
        self._extra_dirs.append(path)

    @staticmethod
    def _allow_traversal(p: Path, user: RunUser, owned: bool, mode: int) -> None:
        """Ancestors stay owned by the worker; the runner user may only pass through (``x``)."""
        try:
            if not owned:
                os.chown(p, -1, user.gid)
            os.chmod(p, mode)
        except PermissionError as exc:
            raise AutomationError(
                f"cannot make {p.name} traversable for the runner user ({exc.strerror}); "
                "the worker must be root or a member of the runner's group"
            ) from None

    @staticmethod
    def _share(p: Path, user: RunUser, owned: bool, mode: int, *, is_dir: bool) -> None:
        try:
            if owned:
                os.chown(p, user.uid, user.gid)
            else:
                os.chown(p, -1, user.gid)  # needs membership of the group
        except PermissionError as exc:
            raise AutomationError(
                f"cannot give {p.name} to the runner user/group ({exc.strerror}); "
                "the worker must be root or a member of the runner's group"
            ) from None
        os.chmod(p, mode)

    def _share_path(self, p: Path, *, is_dir: bool) -> None:
        if self.run_user is None:
            return
        mode = {
            (True, True): 0o700,
            (True, False): 0o600,
            (False, True): 0o770,
            (False, False): 0o660,
        }[(self._owned, is_dir)]
        self._share(p, self.run_user, self._owned, mode, is_dir=is_dir)

    @property
    def owned(self) -> bool:
        """True when the run dir was chowned to the runner user (strict 0700/0600 modes)."""
        return self._owned

    def share_path(self, p: Path) -> None:
        self._share_path(p, is_dir=p.is_dir())

    def share_tree(self, root: Path) -> None:
        """Hand an already-populated tree (the project copy) to the runner user, keeping exec bits."""
        if self.run_user is None:
            return
        for dirpath, _dirs, files in os.walk(root):
            self._share_path(Path(dirpath), is_dir=True)
            for f in files:
                fp = Path(dirpath) / f
                if fp.is_symlink():
                    continue
                self._share_path(fp, is_dir=False)
                if os.stat(fp).st_mode & 0o100:
                    os.chmod(fp, os.stat(fp).st_mode | (0o100 if self._owned else 0o110))

    # ---- files ------------------------------------------------------------------------------------------

    def sub(self, name: str) -> Path:
        return self.path / name

    def write_file(self, rel: str, data: bytes, *, mode: int = 0o600, secret: bool = False) -> Path:
        """Create ``rel`` exclusively with ``mode`` (never world-readable). ``secret`` registers it for the wipe."""
        target = (self.path / rel).resolve()
        if not target.is_relative_to(self.path.resolve()):
            raise AutomationError("path escapes the run directory")
        old = os.umask(0o077)
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        finally:
            os.umask(old)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        except BaseException:
            with contextlib.suppress(OSError):
                target.unlink()
            raise
        if self.run_user is not None and rel != MARKER:
            self._share_path(target, is_dir=False)
        else:
            os.chmod(target, mode)
        if secret:
            self._secrets.append(target)
        return target

    def write_secret(self, rel: str, data: bytes) -> Path:
        return self.write_file(rel, data, mode=0o600, secret=True)

    # ---- wipe -------------------------------------------------------------------------------------------

    def wipe_secrets(self) -> None:
        for p in self._secrets:
            with contextlib.suppress(OSError):
                size = p.stat().st_size
                with open(p, "r+b", buffering=0) as fh:
                    fh.write(b"\0" * size)
                    os.fsync(fh.fileno())
            with contextlib.suppress(OSError):
                p.unlink()
        self._secrets.clear()

    def _remove_as_run_user(self) -> None:
        """Group-shared mode only: run ``rm -rf`` on the run directory's entries as the run user. Never raises."""
        if self.run_user is None or self._owned or not self.path.is_dir():
            return
        with contextlib.suppress(OSError, ValueError, subprocess.SubprocessError):
            entries = [str(e) for e in self.path.iterdir()]
            if entries:
                subprocess.run(  # noqa: S603 - fixed argv, paths inside the run directory
                    ["/bin/rm", "-rf", "--", *entries],
                    user=self.run_user.uid, group=self.run_user.gid, extra_groups=[],
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                    capture_output=True, timeout=120, check=False,
                )  # fmt: skip

    def wipe(self) -> None:
        """Overwrite and delete secrets, then remove the directory. Idempotent; never raises."""
        if self._wiped:
            return
        self.wipe_secrets()
        # The run user (ansible) creates private directories of its own (~/.ansible, its local temp, artefacts):
        # the worker cannot enter or empty them. Let the run user remove what it can first (lab bug K).
        self._remove_as_run_user()
        shutil.rmtree(self.path, ignore_errors=True)
        for extra in self._extra_dirs:
            shutil.rmtree(extra, ignore_errors=True)
        for parent in (self.path.parent, self.path.parent.parent):
            with contextlib.suppress(OSError):
                parent.rmdir()  # only if empty
        self._wiped = True
        if self.path.exists():
            log.error("run directory could not be fully wiped", extra={"run_dir": str(self.path)})


# ---- orphan sweeper (worker killed mid-run) ----------------------------------------------------------------


def processes_referencing(path: Path) -> list[int]:
    """PIDs whose command line mentions ``path`` (ansible-runner and ansible-playbook carry the run dir in argv)."""
    needle = str(path).encode()
    pids: list[int] = []
    me = os.getpid()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    for entry in entries:
        if not entry.isdigit() or int(entry) == me:
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                if needle in fh.read(65536):
                    pids.append(int(entry))
        except OSError:
            continue
    return pids


def sweep_orphans(run_root: Path, max_age: float, *, now: float | None = None) -> list[Path]:
    """Wipe run dirs older than ``max_age`` seconds (the maximum timeout) whose creating process is gone, killing
    any process still referencing them. Run at worker start-up. Returns the removed directories."""
    now = time.time() if now is None else now
    removed: list[Path] = []
    if not run_root.is_dir():
        return removed
    for marker in run_root.glob(f"*/*/*/{MARKER}"):
        run = marker.parent
        try:
            info = json.loads(marker.read_bytes())
            created, pid = float(info["created"]), int(info["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            created, pid = 0.0, 0
        if now - created < max_age:
            continue
        if pid and pid != os.getpid() and os.path.exists(f"/proc/{pid}"):
            continue  # the creating worker process is alive and owns the run
        from ovlm.automation.process import kill_pids

        kill_pids(processes_referencing(run))
        rd = RunDir(run, None, False)
        for sec in ("env",):
            for f in (run / sec).glob("*") if (run / sec).is_dir() else []:
                rd._secrets.append(f)
        rd.wipe()
        removed.append(run)
    return removed
