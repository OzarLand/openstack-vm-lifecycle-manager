"""Renewal configuration: the named keys of renewal-workflow.md (api-safe module).

Every timeout is a named config key. A key the configuration leaves out takes the built-in default of
``ovlm.config.renewal_defaults`` (roadmap P1-8; each value's source in ``docs/timeouts.md``): explicit, versioned
(:data:`DEFAULTS_ID`), logged at start (:func:`log_effective`) and recorded in each plan (:meth:`RenewalConfig.record`,
bound into the plan hash and shown at G1/G2). :meth:`RenewalConfig.missing` stays for a config built by hand (tests,
tools): a key it does not set is still refused at plan creation and at admission.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ovlm.config import Settings
from ovlm.config.renewal_defaults import (
    ANSIBLE_SLACK,
    DEFAULTS_ID,
    KEYSTONE_DEFAULT_TOKEN_LIFETIME,
)

__all__ = ["ANSIBLE_SLACK", "DEFAULTS_ID", "RenewalConfig", "log_effective"]

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
    #: Settings paths that took the built-in default (empty for a config built by hand).
    defaulted: tuple[str, ...] = ()

    @classmethod
    def from_settings(cls, s: Settings) -> RenewalConfig:
        r = s.renewal
        eff = s.renewal_effective()
        sc = eff.scalars
        return cls(
            timeouts=dict(eff.timeouts),
            automation=dict(eff.automation),
            green_ready_max_age=float(sc["green_ready.max_age"]),
            healthcheck_max_attempts=int(sc["healthcheck.max_attempts"]),
            healthcheck_interval=float(sc["healthcheck.interval"]),
            external_required_successes=int(sc["external_verify.required_successes"]),
            external_interval=float(sc["external_verify.interval"]),
            retire_health_max_age=float(sc["retire.health_max_age"]),
            validity_plan=r.approval_validity.plan,
            validity_cutover=r.approval_validity.cutover,
            validity_retirement=float(sc["approval_validity.retirement"]),
            max_concurrent_runs=r.max_concurrent_runs,
            accept_probe_timeout=r.accept_probe_timeout,
            defaulted=eff.defaulted,
        )

    def values(self) -> dict[str, float | int | None]:
        """Every renewal key by its settings path (as ``EffectiveRenewal.values``), sorted."""
        out: dict[str, float | int | None] = {
            f"renewal.timeouts.{k}": float(v) for k, v in self.timeouts.items()
        }
        out |= {f"renewal.automation_timeouts.{k}": float(v) for k, v in self.automation.items()}
        out |= {
            "renewal.green_ready.max_age": self.green_ready_max_age,
            "renewal.healthcheck.max_attempts": self.healthcheck_max_attempts,
            "renewal.healthcheck.interval": self.healthcheck_interval,
            "renewal.external_verify.required_successes": self.external_required_successes,
            "renewal.external_verify.interval": self.external_interval,
            "renewal.retire.health_max_age": self.retire_health_max_age,
            "renewal.approval_validity.retirement": self.validity_retirement,
        }
        return dict(sorted(out.items()))

    def record(self) -> dict[str, Any]:
        """What a plan records (``resolved.renewal_settings``, bound into the plan hash): the effective value of every
        key, which of them came from the built-in defaults, and the defaults' identifier."""
        return {"defaults": DEFAULTS_ID, "defaulted": list(self.defaulted), "values": self.values()}

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


def log_effective(cfg: RenewalConfig, log: logging.Logger) -> None:
    """Start-up notice (api and worker): which renewal keys use the built-in defaults, and the worst-case windows
    they give. Warns when a worst case reaches Keystone's default token lifetime (W1 would be refused)."""
    worst = {
        "stateless": cfg.worst_case_window(snapshot=False, stateless=True),
        "volume": cfg.worst_case_window(snapshot=False, stateless=False),
        "volume_snapshot": cfg.worst_case_window(snapshot=True, stateless=False),
    }
    log.info(
        "renewal settings: %d key(s) use the built-in defaults %s; worst-case windows %s",
        len(cfg.defaulted), DEFAULTS_ID, ", ".join(f"{k} {v:.0f} s" for k, v in worst.items()),
        extra={"renewal_defaults": DEFAULTS_ID, "renewal_defaulted_keys": list(cfg.defaulted),
               "renewal_worst_case_window_seconds": worst},
    )  # fmt: skip
    if max(worst.values()) >= KEYSTONE_DEFAULT_TOKEN_LIFETIME:
        log.warning(
            "renewal worst-case window (%.0f s) reaches Keystone's default token lifetime (%.0f s): W1 is refused "
            "unless the cloud issues longer tokens; lower the renewal timeouts (docs/timeouts.md)",
            max(worst.values()), KEYSTONE_DEFAULT_TOKEN_LIFETIME,
        )  # fmt: skip
