"""Renewal configuration: the named keys of renewal-workflow.md, with no invented defaults (api-safe module).

Every timeout is a config key whose default is "TBD in lab". This module therefore has **no** defaults: a key the
strategy needs and the configuration does not set is reported by :meth:`RenewalConfig.missing`; the worker rejects
the run at admission with that list, and the api refuses to create a plan (the worst-case window shown at G2 could
not be computed). The only defaults are the two the security model states (approval validity: plan 24 h, cutover
4 h), carried by ``Settings``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ovlm.config import Settings

#: Step -> ``timeouts.<key>`` (renewal-workflow.md sections 2.1-2.3, 4). ``server_start`` is not named by the
#: design (S6 "stop/start retryable"); it is added here as its own key (reported).
STEP_TIMEOUT_KEYS: Mapping[str, str] = {
    "preflight": "preflight",
    "claim_resources": "claim_resources",
    "create_green": "green_create_call",
    "wait_green_active": "green_build",
    "wait_green_ssh": "green_ssh",
    "verify_cutover_preconditions": "preflight",
    "verify_green_ready": "green_ready",
    "stop_old": "server_stop",
    "detach_volume": "volume_detach",
    "snapshot_volume": "snapshot",
    "attach_volume_green": "volume_attach",
    "move_fip": "fip_status",
    "verify_external": "external_verify",
    "retain_old": "server_lock",
    "retire_old": "server_delete",
    "unlock_old": "server_lock",
    "stop_green": "server_stop",
    "detach_from_green": "volume_detach",
    "attach_to_old": "volume_attach",
    "boot_old": "server_start",
    "move_fip_to_old": "fip_status",
    "verify_external_old": "external_verify",
    "lock_green": "server_lock",
    "discard_green": "server_delete",
}

#: Step -> automation phase whose ``automation.timeout.<phase>`` bounds it.
STEP_AUTOMATION_PHASES: Mapping[str, str] = {
    "prepare_automation": "preflight",
    "configure_green": "configure",
    "quiesce_old": "quiesce",
    "data_attach_green": "data_attach",
    "start_service_green": "start_service",
    "healthcheck_green": "healthcheck",
    "quiesce_green": "quiesce",
    "recover_old_service": "healthcheck",
}

AUTOMATION_PHASES = (
    "preflight",
    "configure",
    "quiesce",
    "data_attach",
    "start_service",
    "healthcheck",
    "rollback_hooks",
)

WINDOW_STEPS = (
    "quiesce_old",
    "stop_old",
    "detach_volume",
    "snapshot_volume",
    "attach_volume_green",
    "data_attach_green",
    "start_service_green",
    "healthcheck_green",
    "move_fip",
    "verify_external",
)
RESTORE_STEPS = (
    "unlock_old",
    "quiesce_green",
    "stop_green",
    "detach_from_green",
    "attach_to_old",
    "boot_old",
    "recover_old_service",
    "move_fip_to_old",
    "verify_external_old",
    "lock_green",
)
#: Kill grace + slack a supervised Ansible phase needs on top of its timeout (runner.lease_needed).
ANSIBLE_SLACK = 60.0


@dataclass(frozen=True)
class RenewalConfig:
    timeouts: Mapping[str, float] = field(default_factory=dict)
    automation: Mapping[str, float] = field(default_factory=dict)
    green_ready_max_age: float | None = None
    healthcheck_max_attempts: int | None = None
    healthcheck_interval: float | None = None
    external_required_successes: int | None = None
    external_interval: float | None = None
    retire_health_max_age: float | None = None
    validity_plan: float = 24 * 3600
    validity_cutover: float = 4 * 3600
    validity_retirement: float | None = None
    max_concurrent_runs: int = 5
    #: ``renewal.accept_probe_timeout``: total budget of the accept-step guest probe (seconds, PMR-1).
    accept_probe_timeout: float = 20.0

    @classmethod
    def from_settings(cls, s: Settings) -> RenewalConfig:
        r = s.renewal
        return cls(
            timeouts=dict(r.timeouts),
            automation=dict(r.automation_timeouts),
            green_ready_max_age=r.green_ready.max_age,
            healthcheck_max_attempts=r.healthcheck.max_attempts,
            healthcheck_interval=r.healthcheck.interval,
            external_required_successes=r.external_verify.required_successes,
            external_interval=r.external_verify.interval,
            retire_health_max_age=r.retire.health_max_age,
            validity_plan=r.approval_validity.plan,
            validity_cutover=r.approval_validity.cutover,
            validity_retirement=r.approval_validity.retirement,
            max_concurrent_runs=r.max_concurrent_runs,
            accept_probe_timeout=r.accept_probe_timeout,
        )

    def missing(self, *, snapshot: bool = False) -> list[str]:
        """Config keys this strategy needs that are not set (sorted, by their documented names)."""
        needed = set(STEP_TIMEOUT_KEYS.values()) | {"green_host_key"}
        if not snapshot:
            needed.discard("snapshot")
        out = [f"timeouts.{k}" for k in sorted(needed) if self.timeouts.get(k) is None]
        out += [
            f"automation.timeout.{p}" for p in AUTOMATION_PHASES if self.automation.get(p) is None
        ]
        for name, value in (
            ("green_ready.max_age", self.green_ready_max_age),
            ("healthcheck.max_attempts", self.healthcheck_max_attempts),
            ("healthcheck.interval", self.healthcheck_interval),
            ("external_verify.required_successes", self.external_required_successes),
            ("external_probe.interval", self.external_interval),
            ("retire.health_max_age", self.retire_health_max_age),
            ("approval.validity.retirement", self.validity_retirement),
        ):
            if value is None:
                out.append(name)
        return out

    def automation_timeout(self, phase: str) -> float:
        value = self.automation.get(phase)
        if value is None:
            raise KeyError(f"automation.timeout.{phase} is not configured")
        return float(value)

    def step_timeout(self, step_key: str) -> float | None:
        """The step's deadline (seconds from ready). ``None`` for waiting gates (G2, R2, G3, await_discard)."""
        if step_key == "wait_green_ssh":
            return float(self.timeouts["green_ssh"]) + float(self.timeouts["green_host_key"])
        if step_key == "healthcheck_green":
            attempts = int(self.healthcheck_max_attempts or 1)
            per = self.automation_timeout("healthcheck") + ANSIBLE_SLACK
            return attempts * (per + float(self.healthcheck_interval or 0))
        if step_key == "recover_old_service":
            return (
                self.automation_timeout("rollback_hooks")
                + ANSIBLE_SLACK
                + int(self.healthcheck_max_attempts or 1)
                * (self.automation_timeout("start_service") + ANSIBLE_SLACK)
                + int(self.healthcheck_max_attempts or 1)
                * (self.automation_timeout("healthcheck") + ANSIBLE_SLACK)
            )
        if step_key == "verify_green_ready":
            return float(self.timeouts["green_ready"]) + self.automation_timeout("preflight")
        if step_key == "boot_old":
            return float(self.timeouts["server_stop"]) + float(self.timeouts["server_start"])
        if step_key == "prepare_automation":
            return self.automation_timeout("preflight") + ANSIBLE_SLACK
        phase = STEP_AUTOMATION_PHASES.get(step_key)
        if phase is not None:
            return self.automation_timeout(phase) + ANSIBLE_SLACK
        key = STEP_TIMEOUT_KEYS.get(step_key)
        return None if key is None else float(self.timeouts[key])

    def worst_case_window(self, *, snapshot: bool, stateless: bool) -> float:
        """Σ deadlines(W1–W10) + Σ deadlines(S1–S10) (renewal-workflow.md section 3), from the effective config."""
        total = 0.0
        for key in (*WINDOW_STEPS, *RESTORE_STEPS):
            if key == "snapshot_volume" and not snapshot:
                continue
            if stateless and key in (
                "detach_volume",
                "snapshot_volume",
                "attach_volume_green",
                "data_attach_green",
                "detach_from_green",
                "attach_to_old",
            ):
                continue
            total += self.step_timeout(key) or 0.0
        return total
