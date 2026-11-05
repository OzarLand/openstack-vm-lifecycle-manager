"""Verified clone: pinned SHA only, no submodules, no escaping symlinks, no git hooks/config, read-only result."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from ovlm.automation import checkout as co
from ovlm.automation.checkout import CloneOptions, clone_verified, copy_for_attempt, remove_tree
from ovlm.automation.types import AutomationError, Classification

GIT_ENV = {
    "PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
}  # fmt: skip


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, env=GIT_ENV, check=True, capture_output=True, text=True
    ).stdout.strip()  # noqa: S603, S607


def make_repo(
    root: Path, files: dict[str, str] | None = None, links: dict[str, str] | None = None
) -> tuple[str, str]:
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    for rel, text in (files or {"playbooks/configure.yml": "- hosts: ovlm_target\n"}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    for rel, target in (links or {}).items():
        (root / rel).symlink_to(target)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "c")
    return f"file://{root}", git(root, "rev-parse", "HEAD")


def opts(url: str, **kw: object) -> CloneOptions:
    return CloneOptions(allowed_repos=[url], allow_file=True, **kw)  # type: ignore[arg-type]


def test_clone_verifies_head_drops_git_and_is_read_only(tmp_path: Path) -> None:
    url, sha = make_repo(tmp_path / "src")
    dest = tmp_path / "co"
    assert clone_verified(url, sha, dest, opts(url)) == sha
    assert not (dest / ".git").exists()
    f = dest / "playbooks" / "configure.yml"
    assert f.read_text().startswith("- hosts") and not os.access(f, os.W_OK) or os.geteuid() == 0
    assert stat.S_IMODE(f.stat().st_mode) & 0o222 == 0, "files are not writable"
    remove_tree(dest)
    assert not dest.exists()


def test_it_clones_the_pinned_commit_not_the_branch_tip(tmp_path: Path) -> None:
    url, sha1 = make_repo(tmp_path / "src")
    (tmp_path / "src" / "later.txt").write_text("new")
    git(tmp_path / "src", "add", "-A")
    git(tmp_path / "src", "commit", "-q", "-m", "later")
    dest = tmp_path / "co"
    clone_verified(url, sha1, dest, opts(url))
    assert not (dest / "later.txt").exists()


@pytest.mark.parametrize(
    "ref",
    ["main", "HEAD", "v1.0", "stable/2025.1", "abc123", "A" * 40, "0" * 39, "0" * 41, "../x", ""],
)
def test_only_full_lowercase_shas_are_accepted(tmp_path: Path, ref: str) -> None:
    url, _ = make_repo(tmp_path / "src")
    with pytest.raises(AutomationError, match="full lowercase commit SHA"):
        clone_verified(url, ref, tmp_path / "co", opts(url))


def test_unknown_sha_is_fatal_not_retryable(tmp_path: Path) -> None:
    url, _ = make_repo(tmp_path / "src")
    with pytest.raises(AutomationError) as exc:
        clone_verified(url, "1" * 40, tmp_path / "co", opts(url))
    assert exc.value.classification is Classification.FATAL
    assert not (tmp_path / "co").exists(), "a failed clone leaves nothing behind"


def test_unreachable_git_host_is_retryable(tmp_path: Path) -> None:
    url = f"file://{tmp_path}/nonexistent"
    with pytest.raises(AutomationError) as exc:
        clone_verified(url, "1" * 40, tmp_path / "co", opts(url))
    assert exc.value.classification is Classification.RETRYABLE


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pw@git.example.org/r.git",
        "https://user@git.example.org/r.git",
        "ext::sh -c 'id'",
        "ftp://git.example.org/r.git",
        "-u/bin/sh",
        "https://git.example.org/r.git evil",
        "file:///etc",
    ],
)
def test_hostile_urls_are_refused(tmp_path: Path, url: str) -> None:
    with pytest.raises(AutomationError):
        clone_verified(
            url,
            "1" * 40,
            tmp_path / "co",
            CloneOptions(allowed_repos=[url, "https://git.example.org/"]),
        )


def test_allowlist_is_enforced_and_file_urls_need_the_test_flag(tmp_path: Path) -> None:
    url, sha = make_repo(tmp_path / "src")
    with pytest.raises(AutomationError, match="allowlist"):
        clone_verified(
            url,
            sha,
            tmp_path / "a",
            CloneOptions(allowed_repos=["https://git.example.org/"], allow_file=True),
        )
    with pytest.raises(AutomationError, match="file://"):
        clone_verified(url, sha, tmp_path / "b", CloneOptions(allowed_repos=[url]))
    with pytest.raises(AutomationError, match="allowlist"):
        clone_verified(
            url, sha, tmp_path / "c", CloneOptions(allow_file=True)
        )  # empty allowlist refuses everything


def test_prefix_allowlist_matches_on_path_boundary() -> None:
    o = CloneOptions(allowed_repos=["https://git.example.org/team"])
    co.validate_repo_url("https://git.example.org/team/app.git", o)
    with pytest.raises(AutomationError):
        co.validate_repo_url("https://git.example.org/team-evil/app.git", o)


def test_submodules_are_refused(tmp_path: Path) -> None:
    url, sha = make_repo(
        tmp_path / "src",
        {
            "playbooks/configure.yml": "x",
            ".gitmodules": '[submodule "x"]\n\tpath = x\n\turl = https://e/x\n',
        },
    )
    with pytest.raises(AutomationError, match="submodule"):
        clone_verified(url, sha, tmp_path / "co", opts(url))
    assert not (tmp_path / "co").exists()


def test_symlinks_leaving_the_tree_are_refused_inside_are_kept(tmp_path: Path) -> None:
    url, sha = make_repo(tmp_path / "bad", links={"playbooks/passwd": "/etc/passwd"})
    with pytest.raises(AutomationError, match="symlink"):
        clone_verified(url, sha, tmp_path / "co1", opts(url))
    url2, sha2 = make_repo(tmp_path / "up", links={"playbooks/up": "../../../etc"})
    with pytest.raises(AutomationError, match="symlink"):
        clone_verified(url2, sha2, tmp_path / "co2", opts(url2))
    url3, sha3 = make_repo(tmp_path / "ok", {"roles/a/tasks/main.yml": "x"}, links={"roles/b": "a"})
    clone_verified(url3, sha3, tmp_path / "co3", opts(url3))
    assert (tmp_path / "co3" / "roles" / "b").is_symlink()


def test_user_and_system_git_config_and_hooks_are_not_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, sha = make_repo(tmp_path / "src")
    marker = tmp_path / "ran"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    cfg = tmp_path / "gitconfig"
    cfg.write_text(
        f'[core]\n\thooksPath = {hooks}\n[url "https://evil.example/"]\n\tinsteadOf = file://\n'
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("HOME", str(tmp_path))
    clone_verified(url, sha, tmp_path / "co", opts(url))
    assert not marker.exists()


def test_attempt_copy_is_private_and_writable_and_independent(tmp_path: Path) -> None:
    url, sha = make_repo(tmp_path / "src")
    dest = tmp_path / "co"
    clone_verified(url, sha, dest, opts(url))
    a, b = tmp_path / "a", tmp_path / "b"
    copy_for_attempt(dest, a)
    copy_for_attempt(dest, b)
    (a / "playbooks" / "configure.yml").write_text("changed by attempt a")
    assert (b / "playbooks" / "configure.yml").read_text().startswith("- hosts")
    assert (dest / "playbooks" / "configure.yml").read_text().startswith("- hosts")


def test_size_cap(tmp_path: Path) -> None:
    url, sha = make_repo(tmp_path / "src", {"playbooks/big.bin": "x" * 5000})
    with pytest.raises(AutomationError, match="larger"):
        clone_verified(url, sha, tmp_path / "co", opts(url, max_bytes=1000))


def test_ssh_deploy_key_needs_pinned_known_hosts(tmp_path: Path) -> None:
    with pytest.raises(AutomationError, match="known_hosts"):
        co._git_env(CloneOptions(ssh_key_path=tmp_path / "k"))
    env = co._git_env(CloneOptions(ssh_key_path=tmp_path / "k", ssh_known_hosts=tmp_path / "kh"))
    assert (
        "StrictHostKeyChecking=yes" in env["GIT_SSH_COMMAND"]
        and "IdentitiesOnly=yes" in env["GIT_SSH_COMMAND"]
    )


def test_only_the_egress_proxy_variables_cross_the_scrub(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
        "HTTP_PROXY",
        "ALL_PROXY",
        "GIT_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    assert not {"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} & set(
        co._git_env(CloneOptions())
    )
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("NO_PROXY", "localhost,.internal.example")
    monkeypatch.setenv("HTTP_PROXY", "http://plain.example:3128")
    monkeypatch.setenv("ALL_PROXY", "socks5://other.example:1080")
    monkeypatch.setenv("GIT_DIR", "/nonexistent/elsewhere")
    env = co._git_env(CloneOptions())
    assert env["HTTPS_PROXY"] == "http://proxy.example:3128"
    assert env["NO_PROXY"] == "localhost,.internal.example"
    assert not {"HTTP_PROXY", "ALL_PROXY", "GIT_DIR", "https_proxy", "no_proxy"} & set(env)
