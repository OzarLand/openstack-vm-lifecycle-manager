"""Built-in renewal timeout defaults and the checks that tie them together (roadmap P1-8, ``docs/timeouts.md``).

Every value here is a **named, versioned default**, never a hidden one:

* a key the configuration sets wins (``[renewal.*]`` in the TOML file, or ``OVLM_RENEWAL__...``);
* a key it leaves out takes the value below, and the process logs at start which keys did (api and worker);
* the effective values of every key, and which of them came from these defaults (with :data:`DEFAULTS_ID`), are
  written into the plan's ``resolved`` document at plan creation, so they are bound into the plan hash and shown to
  the approvers at G1 and G2, together with the worst-case window computed from them.

Where each number comes from (Felcloud lab measurement or estimate, and the margin) is documented per key in
``docs/timeouts.md``; change a value there and here together, and bump :data:`DEFAULTS_ID`.

This module imports no other ``ovlm`` module (the ``ovlm.config`` rule).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

#: Identifies this table in plans and logs. Bump it whenever a value below changes.
DEFAULTS_ID = "ovlm-renewal-defaults/1"

#: automation-contract.md section 6: (runner timeout, idle timeout) in seconds per Ansible phase. The runner stops
#: the playbook at the timeout (``automation.timeout.<phase>`` overrides it, capped by ``automation.max_timeout``);
#: the renewal's step bound for the phase (``renewal.automation_timeouts.<phase>``) defaults to this same timeout.
AUTOMATION_PHASE_DEFAULTS: Mapping[str, tuple[int, int]] = {
    "preflight": (120, 60),
    "configure": (1800, 300),
    "quiesce": (120, 90),
    "data_attach": (120, 90),
    "start_service": (120, 90),
    "healthcheck": (60, 30),
    "rollback_hooks": (120, 90),
}

#: ``renewal.timeouts.<key>`` (seconds): one OpenStack-side deadline per step (renewal-workflow.md section 2).
TIMEOUT_DEFAULTS: Mapping[str, float] = {
    "preflight": 120.0,
    "claim_resources": 120.0,
    "green_create_call": 120.0,
    "green_build": 900.0,
    "green_ssh": 600.0,
    "green_host_key": 300.0,
    "green_ready": 300.0,
    "server_stop": 90.0,
    "server_start": 90.0,
    "server_lock": 30.0,
    "server_delete": 600.0,
    "volume_detach": 60.0,
    "volume_attach": 90.0,
    "snapshot": 300.0,
    "fip_status": 30.0,
    "external_verify": 60.0,
}

#: The other renewal keys, by their settings path below ``renewal.``.
SCALAR_DEFAULTS: Mapping[str, float | int] = {
    "green_ready.max_age": 1800.0,
    "healthcheck.max_attempts": 2,
    "healthcheck.interval": 10.0,
    "external_verify.required_successes": 2,
    "external_verify.interval": 5.0,
    "retire.health_max_age": 3600.0,
    "approval_validity.retirement": 4 * 3600.0,
}

#: Kill grace (30 s) + preparation/collection slack (30 s) a supervised Ansible phase needs on top of its timeout:
#: the step lease (``automation.runner.lease_needed``) and the step deadline both add it.
ANSIBLE_SLACK = 60.0

#: Keystone's default token lifetime (``[token] expiration``). W1 is refused unless a fresh token outlives the
#: worst-case window (renewal-workflow.md 2.2), so a worst case at or above this never starts on a default cloud.
KEYSTONE_DEFAULT_TOKEN_LIFETIME = 3600.0


@dataclass(frozen=True)
class EffectiveRenewal:
    """The renewal keys as the processes use them: configured value, else default."""

    timeouts: Mapping[str, float]
    automation: Mapping[str, float]
    scalars: Mapping[str, float | int]
    #: Settings paths (``renewal.timeouts.green_build``) that took the built-in default.
    defaulted: tuple[str, ...] = field(default=())

    def values(self) -> dict[str, float | int]:
        """Every key by its settings path, sorted: what a plan records."""
        out: dict[str, float | int] = {f"renewal.timeouts.{k}": v for k, v in self.timeouts.items()}
        out |= {f"renewal.automation_timeouts.{k}": v for k, v in self.automation.items()}
        out |= {f"renewal.{k}": v for k, v in self.scalars.items()}
        return dict(sorted(out.items()))


def runner_timeout(phase: str, automation_timeout: Mapping[str, int]) -> int:
    """The runner's timeout of a phase before any profile request: ``automation.timeout.<phase>`` or the contract."""
    return int(automation_timeout.get(phase, AUTOMATION_PHASE_DEFAULTS[phase][0]))


def effective(renewal: Any, automation_timeout: Mapping[str, int]) -> EffectiveRenewal:
    """Merge a ``RenewalSettings`` with the defaults. ``automation_timeout``: ``Settings.automation.timeout``, from
    which the default step bound of each Ansible phase is taken."""
    defaulted: list[str] = []
    timeouts: dict[str, float] = {}
    for key, default in TIMEOUT_DEFAULTS.items():
        value = renewal.timeouts.get(key)
        if value is None:
            defaulted.append(f"renewal.timeouts.{key}")
            value = default
        timeouts[key] = float(value)
    automation: dict[str, float] = {}
    for phase in AUTOMATION_PHASE_DEFAULTS:
        value = renewal.automation_timeouts.get(phase)
        if value is None:
            defaulted.append(f"renewal.automation_timeouts.{phase}")
            value = runner_timeout(phase, automation_timeout)
        automation[phase] = float(value)
    configured: dict[str, float | int | None] = {
        "green_ready.max_age": renewal.green_ready.max_age,
        "healthcheck.max_attempts": renewal.healthcheck.max_attempts,
        "healthcheck.interval": renewal.healthcheck.interval,
        "external_verify.required_successes": renewal.external_verify.required_successes,
        "external_verify.interval": renewal.external_verify.interval,
        "retire.health_max_age": renewal.retire.health_max_age,
        "approval_validity.retirement": renewal.approval_validity.retirement,
    }
    scalars: dict[str, float | int] = {}
    for key, default in SCALAR_DEFAULTS.items():
        value = configured[key]
        if value is None:
            defaulted.append(f"renewal.{key}")
            value = default
        scalars[key] = value
    return EffectiveRenewal(timeouts, automation, scalars, tuple(sorted(defaulted)))


def problems(eff: EffectiveRenewal, automation_timeout: Mapping[str, int]) -> list[str]:
    """Relations between the effective keys that must hold, or a step deadline would be wrong or unreachable."""
    out: list[str] = []
    for phase, bound in eff.automation.items():
        runner = runner_timeout(phase, automation_timeout)
        if bound < runner:
            out.append(
                f"renewal.automation_timeouts.{phase} ({bound:g} s) is below the runner's timeout of that phase "
                f"({runner} s, automation.timeout.{phase} or the contract default): the step deadline and lease "
                "would end while the playbook may still run"
            )
    t, a, s = eff.timeouts, eff.automation, eff.scalars
    b9 = t["green_ready"] + a["preflight"]
    if s["green_ready.max_age"] < b9:
        out.append(
            f"renewal.green_ready.max_age ({s['green_ready.max_age']:g} s) is below the B9 step deadline "
            f"({b9:g} s = timeouts.green_ready + automation_timeouts.preflight): W1 could find every B9 stale"
        )
    span = (int(s["external_verify.required_successes"]) - 1) * float(s["external_verify.interval"])
    if span >= t["external_verify"]:
        out.append(
            f"renewal.timeouts.external_verify ({t['external_verify']:g} s) must exceed "
            f"(external_verify.required_successes - 1) x external_verify.interval ({span:g} s): "
            "W10 and S9 could never collect their successes in time"
        )
    hc = a["healthcheck"] + ANSIBLE_SLACK
    if t["server_delete"] < hc:
        out.append(
            f"renewal.timeouts.server_delete ({t['server_delete']:g} s) bounds X1, which runs a fresh green "
            f"healthcheck first: it must be at least automation_timeouts.healthcheck + {ANSIBLE_SLACK:g} s ({hc:g} s)"
        )
    return out
