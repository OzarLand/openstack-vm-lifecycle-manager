"""The readiness level, by explicit rules (FR-RDY-3). There is no weighted score and no threshold.

1. any **failed blocker**            -> ``not-ready``
2. else any **unknown blocker**      -> at most ``partially-ready``
3. otherwise                         -> ``ready``

``warning`` and ``info`` checks never change the level, and ``not-applicable`` checks never count as a pass or a
fail. The count summary exists for orientation only ("7/9 checks pass"); nothing derives the level from it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ovlm.readiness.model import CheckResult, Level, Result, Severity


def derive_level(results: Iterable[CheckResult]) -> Level:
    items = list(results)
    blockers = [r for r in items if r.severity is Severity.BLOCKER]
    if any(r.result is Result.FAIL for r in blockers):
        return Level.NOT_READY
    if any(r.result is Result.UNKNOWN for r in blockers):
        return Level.PARTIALLY_READY
    return Level.READY


def summarize(results: Iterable[CheckResult]) -> dict[str, Any]:
    """Counts for orientation, plus the keys that decided the level, so the reason is never a bare number."""
    items = list(results)
    counts = {r.value: sum(1 for i in items if i.result is r) for r in Result}
    failed = [i.key for i in items if i.severity is Severity.BLOCKER and i.result is Result.FAIL]
    unknown = [
        i.key for i in items if i.severity is Severity.BLOCKER and i.result is Result.UNKNOWN
    ]
    applicable = (
        counts[Result.PASS.value] + counts[Result.FAIL.value] + counts[Result.UNKNOWN.value]
    )
    return {
        "counts": counts,
        "total": len(items),
        "applicable": applicable,
        "text": f"{counts[Result.PASS.value]}/{applicable} applicable checks pass",
        "failed_blockers": failed,
        "unknown_blockers": unknown,
        "orientation_only": True,
    }
