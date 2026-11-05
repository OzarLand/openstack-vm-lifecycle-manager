# ruff: noqa: F811
"""The separate OS user (``ovlm-ansible``): needs root to create/switch to it. Skipped with the reason otherwise;
a CI job that runs as root (the dev container does) exercises the real credential switch."""

from __future__ import annotations

import contextlib
import json
import os
import pwd
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ovlm.automation.rundir import RunDir, RunUser
from ovlm.automation.runner import AutomationRunner
from ovlm.automation.types import AutomationError, Classification, Phase
from tests.unit.automation.test_runner import env as runner_env  # noqa: F401
from tests.unit.automation.test_runner import good, request

RUNNER_USER = "ovlm-test-runner"


@pytest.fixture(scope="module")
def run_user() -> RunUser:
    if os.geteuid() != 0:
        pytest.skip("switching to a separate OS user needs root")
    with contextlib.suppress(AutomationError):
        return RunUser.lookup(RUNNER_USER)
    proc = subprocess.run(  # noqa: S603
        ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", RUNNER_USER],  # noqa: S607
        capture_output=True, check=False,
    )  # fmt: skip
    if proc.returncode != 0:
        pytest.skip(f"cannot create the {RUNNER_USER} OS user: {proc.stderr.decode()[:100]}")
    return RunUser.lookup(RUNNER_USER)


def user_runner(base: AutomationRunner, tmp: Path) -> AutomationRunner:
    from ovlm.automation.model import RunnerConfig

    cfg = RunnerConfig(**{**base.cfg.__dict__, "run_user": RUNNER_USER, "run_root": tmp / "urun"})
    # the run root must be traversable by the separate user (a deployment concern: /run/ovlm is 0711)
    (tmp / "urun").mkdir(mode=0o711)
    for p in (tmp, *tmp.parents):
        if p == Path("/tmp"):  # noqa: S108
            break
        p.chmod(p.stat().st_mode | 0o711)
    return AutomationRunner(cfg)


def test_subprocess_runs_as_the_runner_user_and_cannot_read_the_kek(
    runner_env: Any, run_user: RunUser, tmp_path: Path
) -> None:  # noqa: F811
    base, prepared, tmp = runner_env
    runner = user_runner(base, tmp)
    kek = tmp / "kek.pem"
    kek.write_text("KEK")
    kek.chmod(0o400)  # owned by the worker user (root here), as security-model 5.1 requires
    (tmp / "probe").mkdir(mode=0o777)
    (tmp / "probe").chmod(0o777)
    probe = tmp / "probe" / "p.json"
    out = runner.run_phase(
        prepared,
        request(
            Phase.CONFIGURE,
            fake={
                "record": str(probe),
                "result": good("configure"),
                "try_read": str(kek),
                "vault": 1,
            },
        ),
    )
    assert out.decision.classification is Classification.OK, (
        out.record.log,
        out.record.result_error,
    )
    rec = json.loads(probe.read_text())
    assert rec["uid"] == run_user.uid and rec["uid"] != 0
    assert rec["run_dir_mode"] == "0o700" and rec["key_mode"] == "0o600"
    assert rec["read_attempt"] == "denied", "ovlm-ansible must not be able to read the KEK file"
    assert "OVLM" not in json.dumps(rec["env"]) and "HOME" in rec["env"]
    assert not (tmp / "urun" / "wf1" / "step1").exists(), (
        "wiped by the worker although the runner user created files"
    )
    assert out.record.exit_code == 0


def test_run_dir_ownership_and_modes_when_the_worker_is_root(
    run_user: RunUser, tmp_path: Path
) -> None:
    os.chmod(tmp_path, 0o755)  # noqa: S103
    root = tmp_path / "r"
    rd = RunDir.create(root, "wf", "s", 1, run_user=run_user)
    assert rd.owned
    st = rd.path.stat()
    assert (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (run_user.uid, run_user.gid, 0o700)
    key = rd.write_secret("env/k", b"x")
    assert (key.stat().st_uid, stat.S_IMODE(key.stat().st_mode)) == (run_user.uid, 0o600)
    assert stat.S_IMODE(rd.path.parent.stat().st_mode) == 0o711  # traversal only for the ancestors
    rd.wipe()
    assert not rd.path.exists()


def test_non_root_worker_uses_group_modes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A worker without CAP_CHOWN shares through the runner's group: 0770/0660, ancestors 0710 (documented)."""
    chowns: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "geteuid", lambda: 1234)
    monkeypatch.setattr(os, "chown", lambda p, uid, gid: chowns.append((Path(p).name, uid, gid)))
    user = RunUser("ovlm-ansible", 996, 995)
    rd = RunDir.create(tmp_path / "r", "wf", "s", 1, run_user=user)
    assert not rd.owned and all(uid == -1 and gid == 995 for _, uid, gid in chowns), (
        "group only, never the uid"
    )
    assert stat.S_IMODE(rd.path.stat().st_mode) == 0o770
    assert stat.S_IMODE(rd.path.parent.stat().st_mode) == 0o710
    key = rd.write_secret("env/k", b"x")
    assert stat.S_IMODE(key.stat().st_mode) == 0o660
    monkeypatch.setattr(
        os,
        "chown",
        lambda *a: (_ for _ in ()).throw(PermissionError(1, "Operation not permitted")),
    )
    with pytest.raises(AutomationError, match="member of the runner's group"):
        RunDir.create(tmp_path / "r2", "wf", "s", 1, run_user=user)


def test_unknown_user_is_a_configuration_error() -> None:
    with pytest.raises(AutomationError, match="does not exist"):
        RunUser.lookup("no-such-user-ovlm")
    assert pwd.getpwnam("root").pw_uid == 0


def test_wipe_lets_the_run_user_remove_its_private_dirs_first(
    run_user: RunUser, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lab bug K: in group-shared mode ansible leaves 0700 directories the worker cannot empty. The wipe now runs
    ``rm -rf`` as the run user first (real user switch; needs root)."""
    os.chmod(tmp_path, 0o755)  # noqa: S103
    rd = RunDir.create(tmp_path / "r", "wf", "s", 1, run_user=run_user)
    monkeypatch.setattr(rd, "_owned", False)  # what a non-root worker gets
    private = rd.path / "home" / ".ansible" / "tmp"
    private.mkdir(parents=True)
    (private / "x").write_text("x")
    for p in (private, private.parent, private.parent.parent):
        os.chown(p, run_user.uid, run_user.gid)
        os.chmod(p, 0o700)
    os.chown(private / "x", run_user.uid, run_user.gid)
    calls: list[list[str]] = []
    real_run = subprocess.run

    def spy(argv: list[str], **kw: Any) -> Any:
        calls.append(argv)
        assert kw["user"] == run_user.uid and kw["group"] == run_user.gid
        return real_run(argv, **kw)

    monkeypatch.setattr(subprocess, "run", spy)
    rd._remove_as_run_user()  # noqa: SLF001
    assert calls and calls[0][:3] == ["/bin/rm", "-rf", "--"]
    assert not (rd.path / "home").exists()
    rd.wipe()
    assert not rd.path.exists()


def test_owned_mode_needs_no_user_switch_for_the_wipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rd = RunDir(tmp_path, RunUser("ovlm-ansible", 996, 995), owned=True)
    called: list[object] = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(a))
    rd._remove_as_run_user()  # noqa: SLF001
    assert not called
