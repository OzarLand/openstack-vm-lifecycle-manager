"""Workflow metrics (architecture.md section 6). No IDs or names as labels; step keys are a fixed, small set."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

from ovlm.observability.metrics import REGISTRY

RUNS = Gauge(
    "ovlm_workflow_runs", "Workflow runs by kind and state", ["kind", "state"], registry=REGISTRY
)
RUNS_NEEDING_ATTENTION = Gauge(
    "ovlm_runs_needing_attention",
    "Runs in needs_human by phase and reason",
    ["phase", "reason"],
    registry=REGISTRY,
)
STEP_ATTEMPTS = Counter(
    "ovlm_step_attempts_total",
    "Finished step attempts",
    ["step_key", "outcome", "error_class"],
    registry=REGISTRY,
)
STEP_DURATION = Histogram(
    "ovlm_step_duration_seconds",
    "Duration of one step attempt (claim to commit)",
    ["step_key"],
    registry=REGISTRY,
    buckets=(0.1, 0.5, 1, 5, 15, 60, 300, 900, 1800, 3600),
)
LEASE_TAKEOVERS = Counter(
    "ovlm_lease_takeovers_total", "Claims of a running step whose lease expired", registry=REGISTRY
)
FENCED_COMMIT_REJECTED = Counter(
    "ovlm_fenced_commit_rejected_total",
    "Fenced writes that matched 0 rows (ownership lost)",
    registry=REGISTRY,
)
FENCE_REFUSALS = Counter(
    "ovlm_fence_refusals_total",
    "Actions refused locally by the fence gate",
    ["action", "reason"],
    registry=REGISTRY,
)
HEARTBEAT_LOST = Counter(
    "ovlm_step_heartbeat_lost_total",
    "Step heartbeats that matched 0 rows (step stopped at once)",
    registry=REGISTRY,
)
STEP_HEARTBEAT_AGE = Gauge(
    "ovlm_step_heartbeat_age_max_seconds",
    "Oldest heartbeat among running steps (DB time)",
    registry=REGISTRY,
)
EXPIRED_LEASES = Gauge(
    "ovlm_step_leases_expired",
    "Running steps whose lease has expired and are not yet taken over",
    registry=REGISTRY,
)
REQUESTED_OLDEST = Gauge(
    "ovlm_runs_requested_oldest_seconds",
    "Age of the oldest run waiting for admission (SRE-R-25)",
    registry=REGISTRY,
)
REQUESTED_OVERDUE = Gauge(
    "ovlm_runs_requested_overdue",
    "Runs in requested longer than admission.alert_after (SRE-R-25)",
    registry=REGISTRY,
)
SIGNALS_PENDING_OLDEST = Gauge(
    "ovlm_run_signals_pending_oldest_seconds",
    "Age of the oldest unconsumed run signal (SRE-R-24)",
    registry=REGISTRY,
)
SIGNALS_PENDING_OVERDUE = Gauge(
    "ovlm_run_signals_pending_overdue",
    "Unconsumed run signals older than signal.alert_after (SRE-R-24)",
    registry=REGISTRY,
)
