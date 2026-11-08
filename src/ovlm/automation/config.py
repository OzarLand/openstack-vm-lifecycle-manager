"""Build the runner's configuration from ``Settings.automation`` (worker only).

``ovlm.config`` imports no other ovlm module, so the translation lives here. Secret files are checked, not read:
the deploy key stays a path the git subprocess uses."""

from __future__ import annotations

from datetime import timedelta

from ovlm.automation.checkout import CloneOptions
from ovlm.automation.model import RunnerConfig
from ovlm.automation.types import DEFAULT_TIMEOUTS, Phase
from ovlm.config import Settings
from ovlm.config.settings import AutomationSettings


def runner_config(settings: Settings) -> RunnerConfig:
    a: AutomationSettings = settings.automation
    default = {p: t for p, (t, _i) in DEFAULT_TIMEOUTS.items()}
    idle = {p: i for p, (_t, i) in DEFAULT_TIMEOUTS.items()}
    ceiling = {p: t * 4 for p, t in default.items()}
    for table, target in ((a.timeout, default), (a.idle_timeout, idle), (a.max_timeout, ceiling)):
        for name, seconds in table.items():
            target[Phase(name)] = seconds
    for phase in Phase:
        if default[phase] > ceiling[phase]:
            raise ValueError(
                f"automation: default timeout of {phase.value} exceeds its max_timeout"
            )
        if idle[phase] > default[phase]:
            raise ValueError(f"automation: idle_timeout of {phase.value} exceeds its timeout")
    kwargs: dict[str, object] = {}
    if a.ansible_bin_dir is not None:
        kwargs["ansible_bin_dir"] = a.ansible_bin_dir
    return RunnerConfig(
        run_root=a.run_root,
        checkout_cache=a.checkout_cache,
        collections_paths=a.collections_paths,
        run_user=a.run_user,
        signal_prefix=a.signal_prefix,
        require_tmpfs=a.require_tmpfs,
        max_timeout=ceiling,
        default_timeout=default,
        idle_timeout=idle,
        result_max_bytes=a.result_max_bytes,
        log_max_bytes=a.log_max_bytes,
        artifact_retention=timedelta(days=a.artifact_retention_days),
        clone=CloneOptions(
            allowed_repos=a.allowed_repos,
            ssh_key_path=a.git_ssh_key_file,
            ssh_known_hosts=a.git_ssh_known_hosts_file,
        ),
        **kwargs,  # type: ignore[arg-type]
    )


def orphan_max_age(config: RunnerConfig) -> float:
    """A run dir older than the largest phase ceiling (plus the kill grace and slack) cannot belong to a live run."""
    from ovlm.automation.types import KILL_GRACE_SECONDS

    return max(config.max_timeout.values()) + KILL_GRACE_SECONDS + 60.0
