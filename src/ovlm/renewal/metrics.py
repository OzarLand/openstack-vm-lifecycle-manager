"""Renewal metrics (architecture.md section 6). No ids or names as labels.

Paging (D-1 = B, architecture.md 6): ``OvlmPostStartFailure`` fires on ``ovlm_runs_needing_attention{reason=
"post_start_failure"}`` (engine gauge) and on increases of :data:`POST_START_FAILURES`; see ``alert_rules.yml``.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

from ovlm.observability.metrics import REGISTRY

AUTO_RESTORE = Counter(
    "ovlm_auto_restore_total",
    "Automatic restores started in the window",
    ["trigger"],
    registry=REGISTRY,
)
EVIDENCE_INVALID = Counter(
    "ovlm_approval_evidence_invalid_total",
    "Approval evidence re-validations that failed (renewal-workflow.md 3.1)",
    ["gate"],
    registry=REGISTRY,
)
BUDGET_EXCEEDED = Counter(
    "ovlm_window_budget_exceeded_total",
    "Window budget (max_window_duration) breaches",
    registry=REGISTRY,
)
POST_START_FAILURES = Counter(
    "ovlm_post_start_failures_total",
    "Failures after the service started on green with no snapshot: needs_human + page (D-1 = B)",
    registry=REGISTRY,
)
DOWNTIME = Histogram(
    "ovlm_renewal_downtime_seconds",
    "OVLM-measured length of one downtime interval (renewal-workflow.md 3): kind=window (W1 claim to W10, or to S9 "
    "after an in-window restore) or kind=restore (S2 to S9 of a revert after the cutover)",
    ["kind"],
    registry=REGISTRY,
    buckets=(15, 30, 60, 120, 300, 600, 1800, 3600, 7200),
)
