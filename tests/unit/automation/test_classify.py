"""The classification table of automation-contract.md section 6, in code."""

from __future__ import annotations

import pytest

from ovlm.automation.classify import RunFacts, classify, classify_orphaned
from ovlm.automation.result import ValidatedResult
from ovlm.automation.types import Classification as C
from ovlm.automation.types import Phase as P


def res(phase: P, ok: bool, cls: C | None = None, **facts: object) -> ValidatedResult:
    return ValidatedResult(
        phase=phase,
        ok=ok,
        changed=False,
        classification=cls or (C.OK if ok else C.RETRYABLE),
        facts=dict(facts),
    )


def test_ok_needs_exit_zero_and_result_ok() -> None:
    assert classify(P.CONFIGURE, RunFacts(0), res(P.CONFIGURE, True)).classification is C.OK


def test_result_ok_with_nonzero_exit_is_not_trusted() -> None:
    d = classify(P.CONFIGURE, RunFacts(2), res(P.CONFIGURE, True))
    assert d.classification is C.RETRYABLE
    assert classify(P.QUIESCE, RunFacts(2), res(P.QUIESCE, True)).classification is C.NEEDS_HUMAN


def test_exit_zero_with_failed_result_is_inconsistent() -> None:
    assert classify(P.CONFIGURE, RunFacts(0), res(P.CONFIGURE, False)).classification is C.RETRYABLE
    assert (
        classify(P.DATA_ATTACH, RunFacts(0), res(P.DATA_ATTACH, False)).classification
        is C.NEEDS_HUMAN
    )


@pytest.mark.parametrize("reported", [C.RETRYABLE, C.FATAL, C.NEEDS_HUMAN])
def test_playbook_class_is_used_for_idempotent_phases(reported: C) -> None:
    d = classify(P.CONFIGURE, RunFacts(2), res(P.CONFIGURE, False, reported))
    assert d.classification is reported and d.reported_classification is reported


@pytest.mark.parametrize("phase", [P.QUIESCE, P.DATA_ATTACH, P.ROLLBACK_HOOKS])
@pytest.mark.parametrize("reported", [C.RETRYABLE, C.FATAL, C.NEEDS_HUMAN])
def test_every_data_phase_failure_needs_a_human(phase: P, reported: C) -> None:
    d = classify(phase, RunFacts(2), res(phase, False, reported))
    assert d.classification is C.NEEDS_HUMAN
    assert d.reported_classification is reported  # what the playbook said stays in the evidence


@pytest.mark.parametrize("phase", [P.QUIESCE, P.DATA_ATTACH])
@pytest.mark.parametrize(
    "facts",
    [
        RunFacts(None, timed_out=True),
        RunFacts(None, killed=True),
        RunFacts(3),
        RunFacts(0),
        RunFacts(250),
    ],
)
def test_data_phase_without_result_needs_a_human(phase: P, facts: RunFacts) -> None:
    assert classify(phase, facts, None).classification is C.NEEDS_HUMAN


@pytest.mark.parametrize("phase", [P.PREFLIGHT, P.CONFIGURE, P.HEALTHCHECK, P.START_SERVICE])
def test_timeouts_and_kills_of_idempotent_phases_retry(phase: P) -> None:
    assert classify(phase, RunFacts(None, timed_out=True), None).classification is C.RETRYABLE
    assert classify(phase, RunFacts(None, killed=True), None).classification is C.RETRYABLE


def test_unreachable_is_retryable() -> None:
    assert classify(P.CONFIGURE, RunFacts(3), None).classification is C.RETRYABLE
    assert (
        classify(P.CONFIGURE, RunFacts(4, unreachable=False), None).classification is C.FATAL
    )  # 4 = parse error
    assert classify(P.PREFLIGHT, RunFacts(2, unreachable=True), None).classification is C.RETRYABLE


@pytest.mark.parametrize("rc", [4, 5])
def test_parse_error_and_bad_options_are_fatal(rc: int) -> None:
    assert classify(P.CONFIGURE, RunFacts(rc), None).classification is C.FATAL


def test_missing_result_on_idempotent_phase_is_bounded_retry() -> None:
    for rc in (0, 1, 2, 99, 250, None):
        assert classify(P.CONFIGURE, RunFacts(rc), None).classification is C.RETRYABLE


def test_kill_wins_over_a_result() -> None:
    d = classify(P.CONFIGURE, RunFacts(None, killed=True), res(P.CONFIGURE, True))
    assert (
        d.classification is C.RETRYABLE
    )  # an ok result of a killed run is not evidence of success


def test_healthcheck_result_is_authoritative() -> None:
    ok = classify(P.HEALTHCHECK, RunFacts(2), res(P.HEALTHCHECK, True))
    assert ok.classification is C.OK
    bad = classify(P.HEALTHCHECK, RunFacts(0), res(P.HEALTHCHECK, False, C.RETRYABLE))
    assert bad.classification is C.RETRYABLE


def test_healthcheck_exit_code_used_only_without_a_result() -> None:
    assert (
        classify(P.HEALTHCHECK, RunFacts(0), None).classification is C.RETRYABLE
    )  # never "ok" without a result
    assert classify(P.HEALTHCHECK, RunFacts(5), None).classification is C.FATAL


def test_degraded_is_unhealthy_unless_the_profile_accepts_it() -> None:
    r = res(P.HEALTHCHECK, False, C.RETRYABLE, health_state="degraded")
    assert classify(P.HEALTHCHECK, RunFacts(2), r).classification is C.RETRYABLE
    assert classify(P.HEALTHCHECK, RunFacts(2), r, accept_degraded=True).classification is C.OK
    unhealthy = res(P.HEALTHCHECK, False, C.RETRYABLE, health_state="unhealthy")
    assert (
        classify(P.HEALTHCHECK, RunFacts(2), unhealthy, accept_degraded=True).classification
        is C.RETRYABLE
    )
    fatal = res(P.HEALTHCHECK, False, C.FATAL, health_state="degraded")
    assert (
        classify(P.HEALTHCHECK, RunFacts(2), fatal, accept_degraded=True).classification is C.FATAL
    )


def test_orphaned_runs() -> None:
    assert classify_orphaned(P.QUIESCE).classification is C.NEEDS_HUMAN
    assert classify_orphaned(P.DATA_ATTACH).classification is C.NEEDS_HUMAN
    assert classify_orphaned(P.CONFIGURE).classification is C.RETRYABLE
    assert classify_orphaned(P.HEALTHCHECK).classification is C.RETRYABLE
