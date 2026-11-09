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


# ---- the run-level checkouts on run_root (roadmap P0-1) ----------------------------------------------------------


class _Runs:
    """A database double for the checkout sweep: ``workflow_run`` reduced to ``{id: state}``."""

    def __init__(self, states: dict[str, str]) -> None:
        self.states = states
        self.queries = 0

    def connect(self) -> Any:
        runs = self

        class _Conn:
            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_a: object) -> None: ...

            def execute(self, _sql: Any, p: dict[str, Any]) -> Any:
                runs.queries += 1
                t = set(p["t"])
                rows: list[tuple[Any]]
                if "i" in p:  # one run: is it terminal?
                    rows = [(1,)] if runs.states.get(p["i"]) in t else []
                elif "ids" in p:  # the terminal runs among these ids
                    rows = [(i,) for i in p["ids"] if runs.states.get(i) in t]
                else:  # every non-terminal run
                    rows = [(i,) for i, st in runs.states.items() if st not in t]
                return type("R", (), {"first": lambda _s: rows[0] if rows else None,
                                      "__iter__": lambda _s: iter(rows)})()  # fmt: skip

        return _Conn()


_LIVE, _DONE, _GONE = (
    "6f1d9a3e-0000-4000-8000-00000000000a",
    "6f1d9a3e-0000-4000-8000-00000000000b",
    "6f1d9a3e-0000-4000-8000-00000000000c",
)


def _checkout(root: Path, run_id: str, *, old: bool = False) -> Path:
    from ovlm.automation import checkout as co

    entry = root / run_id
    (entry / "_checkout").mkdir(parents=True)
    (entry / "_checkout" / "site.yml").write_text("- hosts: all\n")
    co.make_read_only(entry / "_checkout")
    if (
        root.name == "run"
    ):  # the commit record sits next to the run_root checkout only (not in the cache)
        (entry / "_checkout.sha").write_text("a" * 40 + "\n")
    if old:
        then = time.time() - 365 * 86400
        os.utime(entry, (then, then))
    return entry


def _worker(tmp_path: Path, runs: _Runs, wf: Any = None, *, cache: bool = True) -> Worker:
    automation: dict[str, Any] = {"run_root": str(tmp_path / "run"), "run_user": None}
    if cache:
        automation["checkout_cache"] = str(tmp_path / "cache")
    return Worker(Settings(process_role="worker", automation=automation), runs, wf)  # type: ignore[arg-type]


def test_a_finished_runs_checkout_is_released_after_its_last_step(tmp_path: Path) -> None:
    """The step thread that ran the run's last step frees its checkout on run_root and its cached copy as soon as
    the database reads the run terminal; another run's checkout is not touched."""
    runs = _Runs({_DONE: "running", _LIVE: "waiting"})
    for root in (tmp_path / "run", tmp_path / "cache"):
        _checkout(root, _DONE)
        _checkout(root, _LIVE)

    class Wf:
        worker_id = "w"

        def execute(self, claim: Any) -> str:
            runs.states[claim.run.id] = (
                "completed"  # the last step committed the terminal transition
            )
            return "succeeded"

    w = _worker(tmp_path, runs, Wf())
    claim = type("C", (), {"run": type("V", (), {"id": _DONE})()})()
    w._run_step(claim)  # noqa: SLF001
    for root in (tmp_path / "run", tmp_path / "cache"):
        assert not (root / _DONE).exists(), root
        assert (root / _LIVE / "_checkout").is_dir(), root


@pytest.mark.parametrize("state", ["completed", "rolled_back", "failed", "cancelled", "rejected"])
def test_every_terminal_state_releases_the_checkout(tmp_path: Path, state: str) -> None:
    runs = _Runs({_DONE: state})
    _checkout(tmp_path / "run", _DONE)
    _worker(tmp_path, runs)._sweep_checkouts(_DONE)  # noqa: SLF001
    assert not (tmp_path / "run" / _DONE).exists()


@pytest.mark.parametrize("state", ["requested", "running", "waiting", "needs_human"])
def test_a_non_terminal_runs_checkout_is_kept_after_a_step(tmp_path: Path, state: str) -> None:
    runs = _Runs({_LIVE: state})
    for root in (tmp_path / "run", tmp_path / "cache"):
        _checkout(root, _LIVE, old=True)
    w = _worker(tmp_path, runs)
    w._sweep_checkouts(_LIVE)  # noqa: SLF001
    w._sweep_checkouts()  # noqa: SLF001  (the periodic sweep: kept whatever its age)
    for root in (tmp_path / "run", tmp_path / "cache"):
        assert (root / _LIVE / "_checkout").is_dir()
    assert (tmp_path / "run" / _LIVE / "_checkout.sha").is_file()


def test_a_step_of_a_run_without_a_checkout_does_not_read_the_database(tmp_path: Path) -> None:
    runs = _Runs({})
    w = _worker(tmp_path, runs)
    w._sweep_checkouts(_DONE)  # noqa: SLF001
    w._sweep_checkouts("not-a-run-id")  # noqa: SLF001
    assert runs.queries == 0


def test_the_start_up_sweep_removes_run_root_checkouts_of_finished_and_unknown_runs(
    tmp_path: Path,
) -> None:
    """Before the first claim: a terminal run's checkout goes at once, an unknown one once older than the orphan max
    age; a live run keeps its own whatever its age, and so do the worker's own files (``.ca``, ``.ssh-*``)."""
    root = tmp_path / "run"
    runs = _Runs({_LIVE: "needs_human", _DONE: "rolled_back"})
    live, done = _checkout(root, _LIVE, old=True), _checkout(root, _DONE)
    gone, fresh = (
        _checkout(root, _GONE, old=True),
        _checkout(root, "6f1d9a3e-0000-4000-8000-00000000000d"),
    )
    (root / ".ca").mkdir()
    (root / ".ssh-1234abcd").mkdir()

    class Wf:
        worker_id = "w"
        registry = type("R", (), {"sweepers": []})()

        def register_worker(self, _v: str) -> None: ...

    w = _worker(tmp_path, runs, Wf(), cache=False)
    w._start_workflow()  # noqa: SLF001
    assert not done.exists() and not gone.exists()
    assert (live / "_checkout").is_dir() and (fresh / "_checkout").is_dir()
    assert sorted(p.name for p in root.iterdir()) == sorted(
        [".ca", ".ssh-1234abcd", live.name, fresh.name]
    )


def test_a_failing_checkout_sweep_is_not_fatal(tmp_path: Path) -> None:
    class Down:
        def connect(self) -> Any:
            raise OSError("database down")

    _checkout(tmp_path / "run", _DONE)
    w = _worker(tmp_path, Down())  # type: ignore[arg-type]
    w._sweep_checkouts()  # noqa: SLF001
    w._sweep_checkouts(_DONE)  # noqa: SLF001
    assert (tmp_path / "run" / _DONE / "_checkout").is_dir()  # nothing removed without the database


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
