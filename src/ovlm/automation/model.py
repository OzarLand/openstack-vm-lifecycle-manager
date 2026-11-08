"""Configuration and request/response types of the runner."""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from ovlm.automation.checkout import CloneOptions
from ovlm.automation.classify import Decision
from ovlm.automation.hostkeys import HostKeyPolicy, PublicKey
from ovlm.automation.lint import LintResult
from ovlm.automation.result import DEFAULT_MAX_BYTES, ValidatedResult
from ovlm.automation.types import DEFAULT_TIMEOUTS, Phase, SecretBytes


@dataclass(frozen=True)
class RunnerConfig:
    """Mirror of ``automation.*`` settings (architecture.md): the settings module wires it from the TOML file."""

    run_root: Path
    #: Persistent, worker-only directory keeping a copy of each run's verified checkout, so a worker *container*
    #: restart (tmpfs ``run_root`` emptied) inside the downtime window does not strand the run (lab finding Z). The
    #: copy is re-adopted only when its :func:`~ovlm.automation.checkout.tree_digest` equals the one B6 recorded.
    #: ``None``: no copy (the checkout lives on ``run_root`` only).
    checkout_cache: Path | None = None
    #: Directory holding ``ansible-runner`` and ``ansible``: the venv the worker image ships (pinned versions).
    ansible_bin_dir: Path = field(default_factory=lambda: Path(sys.executable).parent)
    #: Pre-provisioned, pinned collections (image or vendored); never populated at run time (no Galaxy).
    collections_paths: Sequence[Path] = ()
    #: OS user ansible runs as. ``None`` only for tests/dev: the subprocess then runs as the worker user.
    run_user: str | None = "ovlm-ansible"
    signal_prefix: Sequence[str] = ()
    require_tmpfs: bool = False
    #: OVLM maximums; the effective timeout is ``min(profile value, maximum)`` (contract section 6).
    max_timeout: Mapping[Phase, int] = field(
        default_factory=lambda: {p: t * 4 for p, (t, _i) in DEFAULT_TIMEOUTS.items()}
    )
    default_timeout: Mapping[Phase, int] = field(
        default_factory=lambda: {p: t for p, (t, _i) in DEFAULT_TIMEOUTS.items()}
    )
    idle_timeout: Mapping[Phase, int] = field(
        default_factory=lambda: {p: i for p, (_t, i) in DEFAULT_TIMEOUTS.items()}
    )
    result_max_bytes: int = DEFAULT_MAX_BYTES
    log_max_bytes: int = 5 * 1024 * 1024  # contract section 7 (ASSUMPTION)
    max_artifact_bytes: int = 64 * 1024 * 1024
    artifact_retention: timedelta = timedelta(
        days=30
    )  # automation.artifact_retention, separate from audit
    clone: CloneOptions = field(default_factory=CloneOptions)
    #: Seconds added to the runner's own job/idle timeouts before the supervisor stops the process itself (the
    #: runner's timeouts fire first and need no cross-user signal).
    supervisor_slack: float = 15.0
    #: ``first_use=True`` is reserved for a future initial-provisioning strategy (contract section 3).
    allow_first_use: bool = False
    #: Tests only: lets the caller add top-level extra-vars (e.g. the reference workload's ``ovlm_test_mode``).
    allow_test_extravars: bool = False


@dataclass(frozen=True)
class AutomationSpec:
    """The profile's ``automation`` block (contract section 1), already validated by the profiles module."""

    repo: str
    ref: str  # full commit SHA
    playbook_dir: str = "playbooks"
    requirements: str = "requirements.yml"
    inventory_vars: Mapping[str, Any] = field(default_factory=dict)  # non-secret only
    timeouts: Mapping[str, int] = field(default_factory=dict)
    store_diffs: bool = False
    accept_degraded: bool = False


@dataclass(frozen=True)
class GuestTarget:
    host: str
    host_keys: HostKeyPolicy
    role: Literal["old", "new"]
    port: int = 22
    user: str = "ovlm"


@dataclass(frozen=True)
class DataVolume:
    id: str
    mount_point: str
    fs_type: str
    expected_serial: str | None = None  # defaults to the volume id (contract 3.3, ASSUMPTION)
    first_use: bool = False


@dataclass(frozen=True)
class PhaseRequest:
    workflow_id: str
    step_id: str
    attempt: int
    phase: Phase
    target: GuestTarget
    ssh_key: SecretBytes
    service_name: str
    project_scope: str = (
        "global"  # the project whose operators/admins may read the restricted artefacts
    )
    vault_password: SecretBytes | None = None
    data_volume: DataVolume | None = None
    expected_marker_checksum: str | None = None
    expected_fs_uuid: str | None = None
    #: ``quiesce`` on the NEW VM during restore (S2) only: a data volume that is not mounted and has no earlier
    #: quiesce record is a safe end state there (the worker died between W5 and W6, green never mounted it), not
    #: "state unknown". Never set for W1 on the old VM; :func:`~ovlm.automation.render.build_extravars` refuses it
    #: for any other phase or role (lab finding AA, contract 3.4).
    quiesce_allow_unmounted: bool = False
    rollback_phase: Phase | None = None
    check_mode: bool = False
    #: Extra known secret values to redact besides the key and vault password (e.g. profile secret refs).
    extra_secrets: tuple[str, ...] = ()
    test_extravars: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class PreparedAutomation:
    spec: AutomationSpec
    workflow_id: str
    checkout: Path
    sha: str
    requirements_hash: str
    ansible_core_version: str
    lint: LintResult
    #: :func:`~ovlm.automation.checkout.tree_digest` of the verified checkout, recorded in B6's step evidence: the
    #: only proof a cached copy may be re-adopted after a container restart.
    tree_digest: str | None = None

    def evidence(self) -> dict[str, Any]:
        return {
            "tree_digest": self.tree_digest,
            "repo": self.spec.repo,
            "sha": self.sha,
            "requirements_hash": self.requirements_hash,
            "ansible_core_version": self.ansible_core_version,
            "lint_digest": self.lint.as_json()["digest"],
            "lint_waived": [f.as_json() for f in self.lint.waived],
        }


@dataclass(frozen=True)
class RunRecord:
    """What is persisted in ``automation_run`` (data-model.md section 3). Restricted columns: ``log``, ``events``,
    ``diff``."""

    workflow_id: str
    step_id: str
    attempt: int
    phase: str
    target_role: str
    project_scope: str
    repo: str
    sha: str
    requirements_hash: str
    ansible_core_version: str
    extravars_sha256: str
    extravars_keys: list[str]
    first_use: bool | None
    exit_code: int | None
    classification: str
    reported_classification: str | None
    reason: str
    result: dict[str, Any] | None
    result_error: str | None
    task_summary: list[dict[str, Any]]
    log: str
    events: list[dict[str, Any]]
    diff: str | None
    duration_seconds: float
    host_key_mode: str
    lint_digest: str


@dataclass(frozen=True)
class PhaseOutcome:
    decision: Decision
    result: ValidatedResult | None
    record: RunRecord
    #: With the audited TOFU policy: the keys seen at first connect, for the caller to record (never auto-trusted
    #: later: the caller pins them explicitly).
    observed_host_keys: tuple[PublicKey, ...] = ()
