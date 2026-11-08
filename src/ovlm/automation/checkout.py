"""One verified clone per run (automation-contract.md section 2, SRE-R-8, SEC-R-12, security-model 6.5).

``clone_verified`` fetches exactly the pinned commit, checks ``git rev-parse HEAD == sha``, refuses submodules
and symlinks that leave the tree, drops ``.git`` and makes the tree read-only. Each phase attempt then takes a
local copy (:func:`copy_for_attempt`): nothing contacts the git host inside the downtime window.

Git runs with a scrubbed environment (no user config, no hooks, no prompts, protocol allowlist).

:func:`tree_digest` fingerprints a verified checkout (paths, types, modes, symlink targets, contents). B6 records it in
its step evidence, so a copy kept on persistent storage (``automation.checkout_cache``) can be re-adopted after a
worker container restart only if it is byte-for-byte the tree that was verified (lab finding Z).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ovlm.automation.types import AutomationError, Classification

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
GIT_TIMEOUT = 300
_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy")


@dataclass(frozen=True)
class CloneOptions:
    #: Allowlisted repository URL prefixes (admin-managed). Empty means "refuse everything".
    allowed_repos: Sequence[str] = ()
    #: Tests only: also allow ``file://`` URLs. Never set in production.
    allow_file: bool = False
    #: Optional deploy key for ssh URLs: path of a 0600 key file and a known_hosts file for the git host.
    ssh_key_path: Path | None = None
    ssh_known_hosts: Path | None = None
    timeout: float = GIT_TIMEOUT
    max_bytes: int = 256 * 1024 * 1024


def validate_repo_url(url: str, options: CloneOptions) -> None:
    parts = urlsplit(url)
    scheme = parts.scheme
    if scheme == "file":
        if not options.allow_file:
            raise AutomationError("file:// repositories are not allowed")
    elif scheme not in {"https", "ssh"}:
        raise AutomationError("repository URL must be https or ssh")
    if parts.password or (parts.username and scheme == "https"):
        raise AutomationError("credentials in a repository URL are refused")
    if not any(url == a or url.startswith(a.rstrip("/") + "/") for a in options.allowed_repos):
        raise AutomationError("repository is not in the allowlist")
    if any(c in url for c in " \t\r\n\0") or url.startswith("-"):
        raise AutomationError("malformed repository URL")


def validate_sha(sha: str) -> None:
    if not _SHA_RE.match(sha):
        raise AutomationError(
            "ref must be a full lowercase commit SHA (no branch or tag at run time)"
        )


def _git_env(options: CloneOptions) -> dict[str, str]:
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "https:ssh" + (":file" if options.allow_file else ""),
        "LC_ALL": "C",
    }
    # Egress proxy only (install-guide 5a): a worker on a network without direct Internet reaches an https git
    # host through the operator's HTTPS proxy. Only these four variables cross the scrub; nothing else does.
    for name in _PROXY_VARS:
        value = os.environ.get(name)
        if value:
            env[name] = value
    if options.ssh_key_path is not None:
        known = options.ssh_known_hosts
        if known is None:
            raise AutomationError("an ssh deploy key needs a pinned known_hosts file")
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {options.ssh_key_path} -o IdentitiesOnly=yes -o BatchMode=yes "
            f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known} -o GlobalKnownHostsFile=/dev/null "
            "-o ForwardAgent=no"
        )
    return env


def _git(args: list[str], cwd: Path, options: CloneOptions, *, retryable: bool = True) -> str:
    cmd = [
        "git",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "submodule.recurse=false",
        "-c", "protocol.version=2",
        "-c", f"protocol.file.allow={'always' if options.allow_file else 'never'}",
        *args,
    ]  # fmt: skip
    try:
        proc = subprocess.run(  # noqa: S603
            cmd, cwd=cwd, env=_git_env(options), capture_output=True, text=True,
            timeout=options.timeout, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AutomationError(
            f"git {args[0]} failed: {type(exc).__name__}", Classification.RETRYABLE
        ) from None
    if proc.returncode != 0:
        # git's stderr can echo the URL; it is not a secret (credentials in URLs are refused) but stay terse.
        raise AutomationError(
            f"git {args[0]} failed (exit {proc.returncode})",
            Classification.RETRYABLE if retryable else Classification.FATAL,
        )
    return proc.stdout.strip()


def _tree_size(root: Path) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                continue
    return total


def check_tree(root: Path) -> None:
    """Refuse submodules and any symlink resolving outside ``root`` (it would escape the run directory)."""
    root = root.resolve()
    if (root / ".gitmodules").exists():
        raise AutomationError("git submodules are not supported")
    for dirpath, dirs, files in os.walk(root):
        for name in [*dirs, *files]:
            p = Path(dirpath) / name
            if p.is_symlink():
                target = p.resolve()
                if not target.is_relative_to(root):
                    raise AutomationError(f"symlink leaves the repository: {p.relative_to(root)}")


def make_read_only(root: Path) -> None:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            if not os.path.islink(p):
                os.chmod(p, 0o555 if os.stat(p).st_mode & stat.S_IXUSR else 0o444)  # noqa: S103
    for dirpath, _dirs, _files in os.walk(root, topdown=False):
        os.chmod(dirpath, 0o555)  # noqa: S103 - read-only run-level checkout


def make_writable(root: Path) -> None:
    for dirpath, dirs, files in os.walk(root):
        os.chmod(dirpath, 0o700)
        for f in files:
            p = os.path.join(dirpath, f)
            if not os.path.islink(p):
                os.chmod(p, os.stat(p).st_mode | stat.S_IWUSR)
        for d in dirs:
            os.chmod(os.path.join(dirpath, d), 0o700)


def clone_verified(url: str, sha: str, dest: Path, options: CloneOptions) -> str:
    """Clone ``url`` at ``sha`` into ``dest`` (must not exist). Returns the verified SHA."""
    validate_repo_url(url, options)
    validate_sha(sha)
    if dest.exists():
        raise AutomationError("checkout destination already exists")
    dest.mkdir(parents=True, mode=0o700)
    try:
        _git(["init", "-q", "--template="], dest, options)
        _git(["remote", "add", "origin", url], dest, options)
        try:
            _git(
                ["fetch", "-q", "--depth=1", "--no-tags", "--no-recurse-submodules", "origin", sha],
                dest,
                options,
            )
        except AutomationError:
            # Servers that refuse fetch-by-SHA: fall back to a full fetch of branch heads (still no tags).
            _git(["fetch", "-q", "--no-tags", "--no-recurse-submodules", "origin", "+refs/heads/*:refs/remotes/origin/*"], dest, options)  # fmt: skip
        # a SHA the server does not have is a wrong pin, not a transient error: no retry
        _git(
            ["checkout", "-q", "--detach", "--no-recurse-submodules", sha],
            dest,
            options,
            retryable=False,
        )
        head = _git(["rev-parse", "HEAD"], dest, options, retryable=False)
        if head != sha:
            raise AutomationError("checked-out commit does not match the pinned SHA")
        shutil.rmtree(dest / ".git")
        check_tree(dest)
        if _tree_size(dest) > options.max_bytes:
            raise AutomationError("repository is larger than the allowed size")
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    make_read_only(dest)
    return head


def copy_for_attempt(checkout: Path, dest: Path) -> None:
    """A private writable copy of the run-level checkout for one phase attempt (symlinks kept as symlinks and
    re-checked: they were verified to stay inside the tree, and the copy keeps the same layout)."""
    shutil.copytree(checkout, dest, symlinks=True)
    make_writable(dest)
    check_tree(dest)


TREE_DIGEST_VERSION = "ovlm.tree/1"


def tree_digest(root: Path) -> str:
    """Deterministic sha256 of a checkout: a sorted manifest of one JSON line per entry, ``[relative path, type
    (dir/file/symlink), permission bits, symlink target, sha256 of the content]``; the root itself is ``"."``.
    Symlinks are never followed. Anything else than a directory, a regular file or a symlink is refused."""
    lines: list[str] = []

    def entry(rel: str, path: Path) -> None:
        st = os.lstat(path)
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            lines.append(json.dumps([rel, "symlink", 0, os.readlink(path), ""]))
        elif stat.S_ISDIR(st.st_mode):
            lines.append(json.dumps([rel, "dir", mode, "", ""]))
            for name in sorted(os.listdir(path)):
                entry(name if rel == "." else f"{rel}/{name}", path / name)
        elif stat.S_ISREG(st.st_mode):
            h = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            lines.append(json.dumps([rel, "file", mode, "", h.hexdigest()]))
        else:
            raise AutomationError(f"unsupported file type in the checkout: {rel}")

    if not root.is_dir() or root.is_symlink():
        raise AutomationError("checkout to digest is not a directory")
    entry(".", root)
    manifest = TREE_DIGEST_VERSION + "\n" + "\n".join(lines) + "\n"
    return hashlib.sha256(manifest.encode("utf-8", "surrogateescape")).hexdigest()


def copy_exact(src: Path, dest: Path) -> None:
    """Copy a read-only checkout keeping its layout and permission bits (symlinks as symlinks); ``dest`` must not
    exist. The copy has the same :func:`tree_digest` as ``src``."""
    shutil.copytree(src, dest, symlinks=True, copy_function=shutil.copy2)


def remove_tree(root: Path) -> None:
    """Delete a (possibly read-only) tree."""
    if not root.exists():
        return
    for dirpath, _dirs, _files in os.walk(root):
        try:
            os.chmod(dirpath, 0o700)
        except OSError:
            continue
    shutil.rmtree(root, ignore_errors=True)
