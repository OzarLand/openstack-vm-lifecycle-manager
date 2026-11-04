"""Run every check against one snapshot and derive the level. Pure: no database, no OpenStack."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from ovlm.readiness.checks import CHECKS
from ovlm.readiness.levels import derive_level, summarize
from ovlm.readiness.model import Check, CheckResult, Level, Outcome, Result

log = logging.getLogger("ovlm.readiness")


def run_check(check: Check, snapshot: dict[str, Any]) -> CheckResult:
    """A crashing check is ``unknown`` with the error class as evidence (never a silent pass, never a lost
    assessment): the severity decides whether that holds the level back."""
    try:
        out = check.run(snapshot)
    except Exception as exc:  # noqa: BLE001 - isolation of one check from the others is the point
        log.warning(
            "readiness check crashed", extra={"check": check.key, "error": type(exc).__name__}
        )
        out = Outcome(
            Result.UNKNOWN,
            {"error": f"the check could not be evaluated ({type(exc).__name__})"},
            "Report this to the OVLM maintainers; the check is not evaluated until it is fixed.",
        )
    return CheckResult(
        check.key, check.version, check.category, check.severity, out.result, out.evidence,
        out.recommendation,
    )  # fmt: skip


def run_checks(
    snapshot: dict[str, Any], checks: Sequence[Check] = CHECKS
) -> tuple[Level, dict[str, Any], list[CheckResult]]:
    results = [run_check(c, snapshot) for c in checks]
    return derive_level(results), summarize(results), results
