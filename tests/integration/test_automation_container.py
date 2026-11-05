"""The real ``ansible/`` reference workload, run through the OVLM automation runner against a local container.

No fakes: a real ansible-runner subprocess drives real ansible-core over SSH (strict, pinned host key) to an
unprivileged Ubuntu 24.04 container built from ``ansible/tests/Dockerfile``. Docker Hub may rate-limit pulls
(HTTP 429); the base image is then taken from ``OVLM_TEST_BASE_IMAGE`` or a public mirror. The tests **skip only
when Docker itself is unavailable**; any other missing prerequisite (ssh, ansible-runner, the pinned collection)
fails loudly. ``data_attach`` is not executed (no block device in an unprivileged container); its decision table
is covered by ``ansible/tests/decision_table.yml``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ovlm.automation.checkout import CloneOptions
from ovlm.automation.hostkeys import HostKeyPolicy, PublicKey, parse_public_key
from ovlm.automation.lint import StaticWaivers, Waiver
from ovlm.automation.model import (
    AutomationSpec,
    DataVolume,
    GuestTarget,
    PhaseRequest,
    PreparedAutomation,
    RunnerConfig,
)
from ovlm.automation.runner import AutomationRunner
from ovlm.automation.types import AutomationError, Classification, Phase, SecretBytes

ROOT = Path(__file__).parents[2]
ANSIBLE_DIR = ROOT / "ansible"
BASE_IMAGES = [
    *([os.environ["OVLM_TEST_BASE_IMAGE"]] if os.environ.get("OVLM_TEST_BASE_IMAGE") else []),
    "ubuntu:24.04",
    "mirror.gcr.io/library/ubuntu:24.04",
    "public.ecr.aws/ubuntu/ubuntu:24.04",
]
WAIVE_PROBES = Waiver(
    id="waiver-ref-probes",
    rule="check_mode_forced",
    path_glob="roles/*/tasks/*.yml",
    approver="test-approver",
    reason="a read-only task outside the lint allowlist must also run under --check (test fixture)",
)
VOLUME = DataVolume(
    id="0f1e2d3c-4b5a-4697-8877-665544332211", mount_point="/srv/data", fs_type="ext4"
)


def _docker_ok() -> bool:
    try:
        return (
            subprocess.run(
                ["docker", "info"], capture_output=True, timeout=30, check=False
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(not _docker_ok(), reason="Docker is not available")


def _need(binary: str) -> None:
    if shutil.which(binary) is None:
        pytest.fail(
            f"{binary} is required for the automation integration test (uv sync --group automation)"
        )


def _collections(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Pinned collections, never fetched by the runner. Same sources as ansible/tests/run.sh."""
    given = os.environ.get("OVLM_CI_COLLECTIONS_PATH")
    if given and (Path(given) / "ansible_collections/ansible/posix/MANIFEST.json").is_file():
        return Path(given)
    dest = tmp_path_factory.mktemp("collections")
    reqs = ANSIBLE_DIR / "requirements.yml"
    galaxy = shutil.which("ansible-galaxy") or str(Path(sys.executable).parent / "ansible-galaxy")
    proc = subprocess.run(
        [galaxy, "collection", "install", "-r", str(reqs), "-p", str(dest)],
        capture_output=True, text=True, check=False, timeout=300,
    )  # fmt: skip
    if proc.returncode != 0:
        version = "2.2.2"
        proc = subprocess.run(
            [galaxy, "collection", "install",
             f"git+https://github.com/ansible-collections/ansible.posix.git,{version}", "-p", str(dest)],
            capture_output=True, text=True, check=False, timeout=300,
        )  # fmt: skip
    if not (dest / "ansible_collections/ansible/posix/MANIFEST.json").is_file():
        pytest.fail(
            "cannot obtain the pinned ansible.posix collection (Galaxy and the git tag both failed); set "
            f"OVLM_CI_COLLECTIONS_PATH to a directory that has it: {proc.stderr[-300:]}"
        )
    return dest


@dataclass
class Target:
    host: str
    port: int
    container: str
    key: SecretBytes
    host_key: PublicKey

    def policy(self) -> HostKeyPolicy:
        return HostKeyPolicy.pinned([self.host_key])

    def guest(self, *cmd: str) -> str:
        return subprocess.run(
            ["docker", "exec", self.container, *cmd], capture_output=True, text=True, check=True
        ).stdout


@pytest.fixture(scope="module")
def target() -> Iterator[Target]:
    _need("ssh")
    _need("ansible-runner")
    built = False
    errors = []
    for base in BASE_IMAGES:
        proc = subprocess.run(
            ["docker", "build", "-q", "--build-arg", f"BASE_IMAGE={base}", "-t", "ovlm-ci-target",
             str(ANSIBLE_DIR / "tests")],
            capture_output=True, text=True, check=False, timeout=600,
        )  # fmt: skip
        if proc.returncode == 0:
            built = True
            break
        errors.append(f"{base}: {proc.stderr.strip()[-160:]}")
    if not built:
        pytest.fail("cannot build the SSH target image from any base image:\n" + "\n".join(errors))
    cid = subprocess.run(
        ["docker", "run", "-d", "--rm", "-p", "127.0.0.1::22", "ovlm-ci-target"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip
    try:
        port = int(
            subprocess.run(
                ["docker", "port", cid, "22/tcp"], capture_output=True, text=True, check=True
            )
            .stdout.splitlines()[0]
            .rsplit(":", 1)[1]
        )
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
        pub = priv.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        subprocess.run(
            ["docker", "exec", "-i", cid, "sh", "-c",
             "cat > /home/ovlm/.ssh/authorized_keys && chown ovlm:ovlm /home/ovlm/.ssh/authorized_keys "
             "&& chmod 600 /home/ovlm/.ssh/authorized_keys"],
            input=pub + b"\n", check=True, capture_output=True,
        )  # fmt: skip
        host_pub = subprocess.run(
            ["docker", "exec", cid, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"],
            capture_output=True, text=True, check=True,
        ).stdout  # fmt: skip
        yield Target("127.0.0.1", port, cid, SecretBytes(pem), parse_public_key(host_pub))
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False)


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """The reference workload as a throw-away git repo (file:// URL, commit SHA)."""
    root = tmp_path_factory.mktemp("repo")
    shutil.copytree(
        ANSIBLE_DIR, root, dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("work", "__pycache__", "*.pyc"),
    )  # fmt: skip
    # The reference roles pass the lint with no waiver (their forced tasks are allowlisted read-only probes). To keep
    # the waiver path under test, add one harmless forced task whose program is not on the read-only list.
    preflight = root / "roles" / "preflight" / "tasks" / "main.yml"
    preflight.write_text(
        preflight.read_text()
        + "\n- name: \"Kernel release (read-only; not on the lint allowlist, so it needs the waiver)\"\n"
        "  ansible.builtin.command: uname -r\n  changed_when: false\n  check_mode: false\n"
    )
    env = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    for cmd in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "add", "-A"],
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "-m",
            "ref",
        ],
    ):
        subprocess.run(cmd, cwd=root, env=env, check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()
    return f"file://{root}", sha


@pytest.fixture(scope="module")
def runner(tmp_path_factory: pytest.TempPathFactory, repo: tuple[str, str]) -> AutomationRunner:
    url, _sha = repo
    cfg = RunnerConfig(
        run_root=tmp_path_factory.mktemp("run_root") / "run",
        collections_paths=[_collections(tmp_path_factory)],
        run_user=None,  # the separate-user path is covered by test_automation_user.py
        clone=CloneOptions(allowed_repos=[url], allow_file=True),
        allow_test_extravars=True,
    )
    return AutomationRunner(cfg)


class Hooks:
    def __init__(self) -> None:
        self.waived: list[str] = []

    def __call__(self, finding: Any, waiver: Waiver) -> None:
        self.waived.append(f"{waiver.id}:{finding.rule}:{finding.path}")


@pytest.fixture(scope="module")
def prepared(runner: AutomationRunner, repo: tuple[str, str]) -> Iterator[PreparedAutomation]:
    url, sha = repo
    spec = AutomationSpec(
        repo=url,
        ref=sha,
        inventory_vars={"app_port": 8080, "service_units": ["ovlm-counter.service"]},
    )
    hooks = Hooks()
    prep = runner.prepare_automation(
        spec, "wf-it", waivers=StaticWaivers((WAIVE_PROBES,)), on_waiver=hooks
    )
    assert hooks.waived, "the audit hook must be called for every applied waiver"
    yield prep
    runner.release(prep)


def req(
    target: Target, phase: Phase, step: str, *, marker: str | None = None, check: bool = False,
    policy: HostKeyPolicy | None = None,
) -> PhaseRequest:  # fmt: skip
    return PhaseRequest(
        workflow_id="wf-it",
        step_id=step,
        attempt=1,
        phase=phase,
        target=GuestTarget(
            host=target.host,
            port=target.port,
            user="ovlm",
            role="new",
            host_keys=policy or target.policy(),
        ),  # fmt: skip
        ssh_key=target.key,
        service_name="ovlm-counter",
        project_scope="proj-1",
        data_volume=VOLUME,
        expected_marker_checksum=marker,
        check_mode=check,
        test_extravars={"ovlm_test_mode": True},
    )


def test_lint_blocks_without_waiver_and_names_the_rule(
    runner: AutomationRunner, repo: tuple[str, str]
) -> None:
    url, sha = repo
    with pytest.raises(AutomationError, match="check_mode_forced"):
        runner.prepare_automation(AutomationSpec(repo=url, ref=sha), "wf-nolint")


def test_branch_names_are_refused(runner: AutomationRunner, repo: tuple[str, str]) -> None:
    url, _ = repo
    with pytest.raises(AutomationError, match="full lowercase commit SHA"):
        runner.prepare_automation(AutomationSpec(repo=url, ref="main"), "wf-branch")


def test_prepared_evidence(prepared: PreparedAutomation, repo: tuple[str, str]) -> None:
    assert prepared.sha == repo[1]
    ev = prepared.evidence()
    assert len(ev["requirements_hash"]) == 64 and ev["ansible_core_version"].startswith("2.")
    assert ev["lint_waived"], "waived findings are part of the run evidence"


def _keys_named(value: Any, names: set[str]) -> bool:
    if isinstance(value, dict):
        return any(k in names or _keys_named(v, names) for k, v in value.items())
    if isinstance(value, list):
        return any(_keys_named(v, names) for v in value)
    return False


def test_preflight_then_configure_twice_is_idempotent(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target
) -> None:  # noqa: E501
    out = runner.run_phase(prepared, req(target, Phase.PREFLIGHT, "s-pre"))
    assert out.decision.classification is Classification.OK, (
        out.record.result_error,
        out.record.log[-1500:],
    )
    assert out.result and out.result.ok and not out.result.changed
    first = runner.run_phase(prepared, req(target, Phase.CONFIGURE, "s-conf1"))
    assert first.decision.classification is Classification.OK, first.record.log[-3000:]
    assert first.result and first.result.changed
    second = runner.run_phase(prepared, req(target, Phase.CONFIGURE, "s-conf2"))
    assert second.decision.classification is Classification.OK
    assert second.result and not second.result.changed, "second configure must report changed=0"
    assert second.record.task_summary, "per-task status is kept"
    assert all(t["status"] in {"ok", "skipped"} for t in second.record.task_summary)


def test_healthcheck_result_is_authoritative_not_the_exit_code(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target
) -> None:  # noqa: E501
    out = runner.run_phase(prepared, req(target, Phase.HEALTHCHECK, "s-hc0"))
    # the service is not started yet: ansible exits non-zero, the validated result says "unhealthy, retryable"
    assert out.result is not None and not out.result.ok
    assert out.decision.classification is Classification.RETRYABLE
    assert out.decision.reported_classification is Classification.RETRYABLE
    assert out.record.exit_code not in (0, None)


def test_start_healthcheck_marker_quiesce_restart(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target
) -> None:  # noqa: E501
    start = runner.run_phase(prepared, req(target, Phase.START_SERVICE, "s-start"))
    assert start.decision.classification is Classification.OK, start.record.log[-2000:]
    ok = runner.run_phase(prepared, req(target, Phase.HEALTHCHECK, "s-hc1"))
    assert ok.decision.classification is Classification.OK, ok.record.log[-2000:]
    # the same healthcheck in check mode must also pass and change nothing
    chk = runner.run_phase(prepared, req(target, Phase.HEALTHCHECK, "s-hc2", check=True))
    assert chk.decision.classification is Classification.OK, (
        chk.record.result_error,
        chk.record.log[-2500:],
    )
    assert not (chk.result and chk.result.changed)

    for _ in range(3):
        target.guest(
            "python3",
            "-c",
            "import urllib.request as u;u.urlopen('http://127.0.0.1:8080/',timeout=10).read()",
        )
    body = target.guest(
        "python3", "-c",
        "import urllib.request as u;print(u.urlopen(u.Request('http://127.0.0.1:8080/marker',method='POST',data=b''),timeout=10).read().decode())",
    )  # fmt: skip
    marker = json.loads(body)["marker_sha256"]

    quiesce = runner.run_phase(prepared, req(target, Phase.QUIESCE, "s-q1", marker=marker))
    assert quiesce.decision.classification is Classification.OK, quiesce.record.log[-2000:]
    assert quiesce.result and quiesce.result.facts["marker_sha256"] == marker
    after = runner.run_phase(prepared, req(target, Phase.HEALTHCHECK, "s-hc3", marker=marker))
    assert after.decision.classification is Classification.RETRYABLE  # service stopped

    again = runner.run_phase(prepared, req(target, Phase.START_SERVICE, "s-start2"))
    assert again.decision.classification is Classification.OK
    survived = runner.run_phase(prepared, req(target, Phase.HEALTHCHECK, "s-hc4", marker=marker))
    assert survived.decision.classification is Classification.OK, survived.record.log[-2000:]
    assert survived.result and survived.result.facts.get("marker_sha256") == marker


def test_wrong_pinned_host_key_never_reaches_the_guest(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target
) -> None:  # noqa: E501
    wrong = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    )
    out = runner.run_phase(
        prepared,
        req(target, Phase.CONFIGURE, "s-badkey", policy=HostKeyPolicy.pinned([wrong.decode()])),
    )
    assert out.decision.classification is not Classification.OK
    assert out.result is None and out.record.result_error
    assert (
        "Host key verification failed" in out.record.log
        or "REMOTE HOST IDENTIFICATION" in out.record.log
    )


def test_tofu_is_an_explicit_audited_optin_and_returns_the_observed_key(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target
) -> None:  # noqa: E501
    out = runner.run_phase(
        prepared,
        req(target, Phase.PREFLIGHT, "s-tofu", policy=HostKeyPolicy.tofu("accepted-risk:test")),
    )
    assert out.decision.classification is Classification.OK, out.record.log[-2000:]
    assert [k.fingerprint for k in out.observed_host_keys] == [target.host_key.fingerprint]
    assert out.record.host_key_mode == "tofu"


def test_secret_never_in_stored_artefacts_and_rundir_wiped(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target
) -> None:  # noqa: E501
    seen: dict[str, Any] = {}

    class SpyFence:
        def check(self, action: str) -> None:
            run = runner.cfg.run_root / "wf-it" / "s-spy" / "1"
            seen["action"] = action
            seen["mode"] = oct(run.stat().st_mode & 0o777)
            seen["key_mode"] = oct((run / "env" / "guest_key").stat().st_mode & 0o777)
            seen["extravars_mode"] = oct((run / "env" / "extravars").stat().st_mode & 0o777)

        def add_revoke_callback(self, cb: Any) -> Any:
            return lambda: None

    out = runner.run_phase(prepared, req(target, Phase.PREFLIGHT, "s-spy"), fence=SpyFence())
    assert (
        seen["action"] == "automation:spawn:preflight"
    )  # the fence gate ran right before the spawn
    assert (
        seen["mode"] == "0o700"
        and seen["key_mode"] == "0o600"
        and seen["extravars_mode"] == "0o600"
    )
    assert not (runner.cfg.run_root / "wf-it" / "s-spy").exists(), "run dir wiped"
    blob = json.dumps(out.record.__dict__, default=str)
    key_body = target.key.value.decode().splitlines()[1]
    assert key_body not in blob and "BEGIN OPENSSH PRIVATE KEY" not in blob
    assert "guest_key" not in out.record.extravars_keys and out.record.extravars_sha256
    assert not out.record.diff, "diffs are stored only when the profile opts in"


def test_check_mode_configure_makes_no_change_and_keeps_no_diff(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target
) -> None:  # noqa: E501
    out = runner.run_phase(prepared, req(target, Phase.CONFIGURE, "s-chk", check=True))
    assert out.decision.classification is Classification.OK, out.record.log[-2000:]
    assert out.result is not None and not out.result.changed
    assert out.record.diff is None
    assert not _keys_named(out.record.events, {"diff", "diff_before"})


def test_real_ansible_as_the_separate_os_user(
    runner: AutomationRunner, prepared: PreparedAutomation, target: Target, tmp_path_factory: pytest.TempPathFactory
) -> None:  # fmt: skip
    """The same real ansible-runner, but started as a different OS user with a scrubbed environment."""
    if os.geteuid() != 0:
        pytest.skip("switching to a separate OS user needs root")
    name = "ovlm-test-runner"
    if subprocess.run(["id", name], capture_output=True, check=False).returncode != 0:
        made = subprocess.run(
            ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name],
            capture_output=True, check=False,
        )  # fmt: skip
        if made.returncode != 0:
            pytest.skip(f"cannot create the {name} OS user")
    from ovlm.automation.model import RunnerConfig

    root = Path(tempfile.mkdtemp(prefix="o", dir="/tmp"))  # noqa: S108 - short on purpose: ssh ControlPath limit
    root.chmod(0o711)
    coll = Path(runner.cfg.collections_paths[0])
    for p in (coll, *coll.parents):
        if p == Path("/"):
            break
        p.chmod(p.stat().st_mode | 0o755)
    cfg = RunnerConfig(**{**runner.cfg.__dict__, "run_user": name, "run_root": root / "run"})
    urunner = AutomationRunner(cfg)
    out = urunner.run_phase(prepared, req(target, Phase.PREFLIGHT, "s-user"))
    assert out.decision.classification is Classification.OK, (
        out.record.result_error,
        out.record.log[-2000:],
    )
    assert out.result and out.result.ok
    assert not (root / "run" / "wf-it" / "s-user").exists()
    assert not list((root / "run" / ".cp").iterdir()), (
        "the per-run ssh control dir is removed with the run"
    )
    shutil.rmtree(root, ignore_errors=True)
