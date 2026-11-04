"""Settings -> RunnerConfig, the start-up sweep, and the restricted-artefact read rule."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ovlm.auth.authz import can_read_restricted
from ovlm.automation.config import orphan_max_age, runner_config
from ovlm.automation.types import Phase
from ovlm.config import Settings
from ovlm.worker.main import Worker


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in list(os.environ):
        if key.startswith("OVLM_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(tmp_path / "absent.toml"))
    monkeypatch.setenv("OVLM_DEVELOPMENT_MODE", "true")


def test_defaults_are_the_contract_defaults() -> None:
    cfg = runner_config(Settings(process_role="worker"))
    assert cfg.run_user == "ovlm-ansible" and cfg.run_root == Path("/run/ovlm")
    assert cfg.collections_paths == (Path("/opt/ovlm/collections"),)
    assert cfg.default_timeout[Phase.CONFIGURE] == 1800 and cfg.idle_timeout[Phase.CONFIGURE] == 300
    assert cfg.max_timeout[Phase.CONFIGURE] == 7200
    assert cfg.clone.allowed_repos == ()  # empty allowlist refuses everything


def test_settings_reach_the_runner_config(tmp_path: Path) -> None:
    s = Settings(
        process_role="worker",
        automation={
            "run_root": str(tmp_path / "run"), "run_user": None, "signal_prefix": "sudo -n -u ovlm-ansible",
            "timeout": {"configure": 900}, "idle_timeout": {"configure": 120},
            "max_timeout": {"configure": 1000}, "artifact_retention_days": 7,
            "allowed_repos": ["https://git.example.org/team"], "require_tmpfs": True,
        },
    )  # fmt: skip
    cfg = runner_config(s)
    assert cfg.run_root == tmp_path / "run" and cfg.run_user is None and cfg.require_tmpfs
    assert cfg.signal_prefix == ("sudo", "-n", "-u", "ovlm-ansible")
    assert (cfg.default_timeout[Phase.CONFIGURE], cfg.idle_timeout[Phase.CONFIGURE]) == (900, 120)
    assert cfg.max_timeout[Phase.CONFIGURE] == 1000
    assert cfg.artifact_retention.days == 7
    assert cfg.clone.allowed_repos == ("https://git.example.org/team",)
    assert orphan_max_age(cfg) > 1000


@pytest.mark.parametrize(
    "bad",
    [
        {"timeout": {"nonsense": 5}},
        {"timeout": {"configure": 0}},
        {"run_root": "relative/path"},
        {"collections_paths": ["rel"]},
        {"run_user": "Not A User!"},
        {"allowed_repos": ["http://git.example.org/x"]},
        {"allowed_repos": ["https://user:pw@git.example.org/x"]},
        {"git_ssh_key_file": "/run/secrets/k"},  # key without known_hosts
        {"surprise": 1},
    ],
)
def test_invalid_automation_settings_are_refused(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Settings(process_role="worker", automation=bad)


def test_inconsistent_timeouts_are_refused() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        runner_config(Settings(process_role="worker", automation={"timeout": {"configure": 9000}}))
    with pytest.raises(ValueError, match="idle"):
        runner_config(
            Settings(process_role="worker", automation={"idle_timeout": {"healthcheck": 90}})
        )


def test_production_worker_needs_the_separate_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OVLM_DEVELOPMENT_MODE")
    with pytest.raises(ValidationError, match="run_user"):
        Settings(process_role="worker", automation={"run_user": None})
    Settings(process_role="worker")  # default: ovlm-ansible


def test_env_and_toml_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "ovlm.toml"
    cfg.write_text('[automation]\nallowed_repos = ["https://git.example.org/a"]\n')
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("OVLM_AUTOMATION__RUN_ROOT", "/run/x")
    monkeypatch.setenv("OVLM_AUTOMATION__REQUIRE_TMPFS", "true")
    monkeypatch.setenv("OVLM_AUTOMATION__COLLECTIONS_PATHS", "/opt/a, /opt/b")
    monkeypatch.setenv("OVLM_AUTOMATION__SIGNAL_PREFIX", "sudo -n")
    a = Settings(process_role="worker").automation
    assert a.allowed_repos == ("https://git.example.org/a",) and a.run_root == Path("/run/x")
    assert a.require_tmpfs is True
    assert a.collections_paths == (Path("/opt/a"), Path("/opt/b")) and a.signal_prefix == (
        "sudo",
        "-n",
    )


def test_worker_start_sweeps_orphans_before_registering(tmp_path: Path) -> None:
    run = tmp_path / "wf1" / "step1" / "1"
    (run / "env").mkdir(parents=True)
    (run / "env" / "guest_key").write_text("KEY")
    from ovlm.automation.rundir import MARKER

    (run / MARKER).write_text(json.dumps({"pid": 0, "created": time.time() - 10 * 3600}))
    s = Settings(process_role="worker", automation={"run_root": str(tmp_path), "run_user": None})
    order: list[str] = []

    class Wf:
        worker_id = "w"
        registry = type("R", (), {"sweepers": [lambda: order.append("sweepers")]})()

        def register_worker(self, _v: str) -> None:
            order.append("register")

    w = Worker(s, None, Wf())  # type: ignore[arg-type]
    w._start_workflow()  # noqa: SLF001
    assert not run.exists(), "the orphan run directory (with its key) was removed"
    assert order == ["register", "sweepers"]


def test_a_failing_sweep_does_not_stop_the_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ovlm.automation.rundir as rd

    def boom(*_a: object, **_k: object) -> list[Path]:
        raise OSError("unreadable")

    monkeypatch.setattr(rd, "sweep_orphans", boom)
    s = Settings(process_role="worker", automation={"run_root": str(tmp_path), "run_user": None})

    class Wf:
        worker_id = "w"
        registry = type("R", (), {"sweepers": []})()

        def register_worker(self, _v: str) -> None: ...

    w = Worker(s, None, Wf())  # type: ignore[arg-type]
    w._start_workflow()  # noqa: SLF001
    assert w._started  # noqa: SLF001


def test_restricted_read_rule() -> None:
    p = "project:6f1d9a3e-0000-4000-8000-000000000001"
    q = "project:6f1d9a3e-0000-4000-8000-000000000002"
    assert can_read_restricted({("operator", p)}, p)
    assert can_read_restricted({("admin", p)}, p)
    assert can_read_restricted({("operator", "global")}, p)
    assert not can_read_restricted({("operator", q)}, p)
    assert not can_read_restricted({("viewer", p)}, p)
    assert not can_read_restricted({("approver", p)}, p)
    assert not can_read_restricted(set(), p)
    assert not can_read_restricted({("operator", p)}, "global")
