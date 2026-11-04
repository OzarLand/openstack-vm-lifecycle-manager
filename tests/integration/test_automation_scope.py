# ruff: noqa: F811
"""Step B6 checks (``--syntax-check`` and ``--list-hosts``) run by the real ansible-playbook, in containment, and
the audit hook of lint waivers. No Docker needed: nothing connects to a guest."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ovlm.automation.checkout import CloneOptions
from ovlm.automation.hostkeys import HostKeyPolicy
from ovlm.automation.lint import StaticWaivers
from ovlm.automation.model import (
    AutomationSpec,
    GuestTarget,
    PhaseRequest,
    PreparedAutomation,
    RunnerConfig,
)
from ovlm.automation.runner import AutomationRunner
from ovlm.automation.types import SecretBytes
from tests.integration.test_automation_container import (  # noqa: F401
    ANSIBLE_DIR,
    WAIVE_PROBES,
    _collections,
    repo,
)

PIN = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwLM199YxaNqwwlrFbz6zrsuROa7AzsYbaXTnF5qNWB"


def need_ansible() -> None:
    if (
        shutil.which("ansible-playbook") is None
        and not (Path(__import__("sys").executable).parent / "ansible-playbook").exists()
    ):
        pytest.fail("ansible-core is required (uv sync --group automation)")


def req() -> PhaseRequest:
    return PhaseRequest(
        workflow_id="wf-scope", step_id="b6", attempt=1, phase=__import__("ovlm.automation.types", fromlist=["Phase"]).Phase.CONFIGURE,  # noqa: E501
        target=GuestTarget("127.0.0.1", HostKeyPolicy.pinned([PIN]), "new"),
        ssh_key=SecretBytes(b"unused"), service_name="svc",
    )  # fmt: skip


def make(
    tmp_path_factory: pytest.TempPathFactory, url: str, sha: str
) -> tuple[AutomationRunner, PreparedAutomation]:
    need_ansible()
    cfg = RunnerConfig(
        run_root=tmp_path_factory.mktemp("rr") / "run",
        collections_paths=[_collections(tmp_path_factory)], run_user=None,
        clone=CloneOptions(allowed_repos=[url], allow_file=True),
    )  # fmt: skip
    runner = AutomationRunner(cfg)
    return runner, runner.prepare_automation(
        AutomationSpec(repo=url, ref=sha), "wf-scope", waivers=StaticWaivers((WAIVE_PROBES,))
    )  # noqa: E501


def test_reference_workload_passes_the_scope_check(
    tmp_path_factory: pytest.TempPathFactory, repo: tuple[str, str]
) -> None:
    runner, prepared = make(tmp_path_factory, *repo)
    assert runner.check_scope(prepared, req()) == []
    assert not (runner.cfg.run_root / "wf-scope" / "b6").exists(), "run dir wiped"


def git_repo(root: Path, files: dict[str, str]) -> tuple[str, str]:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    env = {
        "PATH": __import__("os").environ["PATH"],
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x"]):  # fmt: skip
        subprocess.run(cmd, cwd=root, env=env, check=True, capture_output=True)  # noqa: S603
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()  # noqa: S603, S607, E501
    return f"file://{root}", sha


def test_syntax_error_and_foreign_hosts_are_reported(
    tmp_path_factory: pytest.TempPathFactory, tmp_path: Path
) -> None:
    files = {
        # ``hosts`` built from a variable: the static lint cannot see it, list-hosts shows what it really targets
        "playbooks/configure.yml": "- hosts: localhost\n  gather_facts: false\n  tasks: []\n",
        "playbooks/healthcheck.yml": "- hosts: ovlm_target\n  tasks:\n    - ansible.builtin.ping\n  broken: [\n",
        "playbooks/preflight.yml": "- hosts: ovlm_target\n  gather_facts: false\n  tasks:\n    - ansible.builtin.ping:\n",
    }
    url, sha = git_repo(tmp_path / "r", files)
    need_ansible()
    cfg = RunnerConfig(
        run_root=tmp_path / "run",
        run_user=None,
        clone=CloneOptions(allowed_repos=[url], allow_file=True),
    )
    runner = AutomationRunner(cfg)
    # lint is told to ignore hosts_pattern here so that the run-time check is what catches it
    from ovlm.automation.lint import Waiver

    waivers = StaticWaivers(
        (
            Waiver("w", "hosts_pattern", "*", "a", "test"),
            Waiver("w2", "parse_error", "*", "a", "test"),
        )
    )
    prepared = runner.prepare_automation(
        AutomationSpec(repo=url, ref=sha), "wf-scope", waivers=waivers
    )
    problems = runner.check_scope(prepared, req())
    joined = "; ".join(problems)
    assert "configure: targets ['localhost']" in joined
    assert "healthcheck: syntax-check failed" in joined
    assert not any(p.startswith("preflight") for p in problems)
