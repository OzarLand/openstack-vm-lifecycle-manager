"""Exit-code and result classification (automation-contract.md sections 3.6, 6).

Pure functions: the table of section 6 in code. Principles:

* the engine never proceeds on anything but ``ok``;
* a failure in a data phase (``quiesce``, ``data_attach``, ``rollback_hooks``) is **always** ``needs_human``,
  whatever the playbook claims: the data must not be retried or rolled back blindly (section 6, last paragraph);
* for ``healthcheck`` the validated ``result.json`` is authoritative, the exit code only counts when the result
  is missing or malformed (section 3.6);
* what the guest reports never makes a run *more* permissive than the exit code allows, except for ``healthcheck``.
"""

from __future__ import annotations

from dataclasses import dataclass

from ovlm.automation.result import ValidatedResult
from ovlm.automation.types import DATA_PHASES, Classification, Phase

#: ansible-playbook / ansible-runner exit codes (DOCUMENTED-UNVERIFIED in the contract; checked against
#: ansible-core 2.19 / runner 2.4 by the integration test).
RC_OK = 0
RC_ERROR = 1
RC_HOST_FAILED = 2
RC_UNREACHABLE = 3
RC_PARSE_ERROR = 4
RC_BAD_OPTIONS = 5
RC_INTERRUPTED = 99
RC_UNEXPECTED = 250
_FATAL_RCS = frozenset({RC_PARSE_ERROR, RC_BAD_OPTIONS})


@dataclass(frozen=True)
class RunFacts:
    """What the supervisor observed about the process (no guest-controlled input except the result)."""

    exit_code: int | None  # None: no exit code (killed before runner reported one)
    timed_out: bool = False
    killed: bool = False  # revoked by the fence, worker shutdown, size cap exceeded
    unreachable: bool = False  # an unreachable host event was seen (non-authoritative hint)


@dataclass(frozen=True)
class Decision:
    classification: Classification
    reason: str  # short and secret-free; stored in the step evidence
    reported_classification: Classification | None = (
        None  # what the playbook said, if it said anything
    )


def classify(
    phase: Phase,
    facts: RunFacts,
    result: ValidatedResult | None,
    *,
    accept_degraded: bool = False,
) -> Decision:
    data = phase in DATA_PHASES

    if facts.killed:
        return _kill_decision(phase, "process killed (revoked, shutdown or output cap)")
    if facts.timed_out:
        if data:
            return Decision(Classification.NEEDS_HUMAN, f"timeout in {phase.value}")
        # preflight / configure / healthcheck are named in the contract; start_service is idempotent
        # (`state: started`) so a bounded retry is safe too. The engine bounds the retries.
        return Decision(Classification.RETRYABLE, f"timeout in {phase.value}")

    rc = facts.exit_code
    reported = result.classification if result is not None else None

    if result is not None:
        if phase is Phase.HEALTHCHECK:
            return _healthcheck(result, accept_degraded)
        if result.ok and rc == RC_OK:
            return Decision(Classification.OK, "exit 0 and result.ok", reported)
        if result.ok:  # playbook says ok but the run exited non-zero: do not trust either side
            return _by_exit_code(phase, rc, facts, "result.ok but non-zero exit", reported)
        if rc == RC_OK:  # result says failed but the run exited 0: inconsistent
            if data:
                return Decision(Classification.NEEDS_HUMAN, "result failed with exit 0", reported)
            return Decision(Classification.RETRYABLE, "result failed with exit 0", reported)
        failed_as = result.classification
        if data:
            return Decision(
                Classification.NEEDS_HUMAN,
                f"{phase.value} failed (reported {failed_as.value})",
                failed_as,
            )
        return Decision(failed_as, "result classification", failed_as)

    # No usable result.
    if data:
        return Decision(Classification.NEEDS_HUMAN, "missing or invalid result in a data phase")
    return _by_exit_code(phase, rc, facts, "missing or invalid result", None)


def _healthcheck(result: ValidatedResult, accept_degraded: bool) -> Decision:
    if result.ok:
        return Decision(Classification.OK, "healthcheck result ok", result.classification)
    if (
        accept_degraded
        and result.facts.get("health_state") == "degraded"
        and result.classification is Classification.RETRYABLE
    ):
        return Decision(
            Classification.OK, "degraded but serving, accepted by profile", result.classification
        )
    return Decision(result.classification, "healthcheck result", result.classification)


def _by_exit_code(
    phase: Phase, rc: int | None, facts: RunFacts, why: str, reported: Classification | None
) -> Decision:
    if rc in _FATAL_RCS:
        return Decision(
            Classification.FATAL, f"{why}; exit {rc} (parse error / bad options)", reported
        )
    if rc == RC_UNREACHABLE or facts.unreachable:
        return Decision(Classification.RETRYABLE, f"{why}; host unreachable", reported)
    if phase in DATA_PHASES:
        return Decision(Classification.NEEDS_HUMAN, f"{why}; exit {rc}", reported)
    # exit 0 with no result, 1, 2, 99, 250, None: idempotent phase, bounded retry then escalation.
    return Decision(Classification.RETRYABLE, f"{why}; exit {rc}", reported)


def _kill_decision(phase: Phase, why: str) -> Decision:
    if phase in DATA_PHASES:
        return Decision(Classification.NEEDS_HUMAN, why)
    return Decision(Classification.RETRYABLE, why)


def classify_orphaned(phase: Phase) -> Decision:
    """A run whose process died with the worker (contract section 6, "unknown"): on resume, data phases need a
    human, the idempotent phases are re-run."""
    return _kill_decision(phase, "process lost with the worker; state unknown")
