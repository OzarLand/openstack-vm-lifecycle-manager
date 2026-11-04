"""The closed automatic-restore table of renewal-workflow.md 4.1 (SEC-R-30), with maintainer decision D-1 = B. Pure.

Automatic restore runs only for a row marked "yes", only with the policy's ``auto_restore_in_window`` on, only once
per run, only when a **fresh** probe (``truth``) read the volume status, its attachments and the FIP port, and never
while the OpenStack API is unreachable. Anything not in the table parks the run in ``needs_human``.

D-1 = B: a failure at W7-W10 (or a budget breach / evidence failure that reaches W7-W9) parks with
``post_start_failure`` and pages, **unless** a snapshot of this run reached ``available`` in W4 (then: restore).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

PRE_START = (
    "stop_old",
    "detach_volume",
    "snapshot_volume",
    "attach_volume_green",
    "data_attach_green",
)
POST_START = ("start_service_green", "healthcheck_green", "move_fip", "verify_external")

TRIGGER_BUDGET = "budget"
TRIGGER_EVIDENCE = "approval_evidence_invalid"


@dataclass(frozen=True)
class TableDecision:
    restore: bool
    #: ``needs_human_reason`` when not restoring; the restore trigger label when restoring.
    reason: str
    #: Pages (architecture.md section 6): every needs_human in the window pages; this flags the D-1 case.
    post_start: bool = False


def _vol(truth: Mapping[str, Any]) -> tuple[str | None, list[str]]:
    v = truth.get("volume") or {}
    return v.get("status"), list(v.get("attached_to") or [])


def known_state(truth: Mapping[str, Any] | None, *, stateless: bool) -> bool:
    """The fresh probe read what the table needs: volume status + attachments (unless stateless) and FIP port."""
    if not truth or not truth.get("api_reachable"):
        return False
    if not stateless and (truth.get("volume") or {}).get("status") is None:
        return False
    return (truth.get("fip") or {}).get("readable") is True


def decide(
    step_key: str,
    *,
    reason: str,
    trigger: str | None,
    truth: Mapping[str, Any] | None,
    blue_id: str,
    green_id: str | None,
    stateless: bool,
    auto_restore: bool,
    already_used: bool,
    snapshot_available: bool,
) -> TableDecision:
    """Decide restore vs needs_human for a failure of ``step_key`` (a W step) inside the window."""
    if truth is not None and not truth.get("api_reachable", False):
        return TableDecision(False, "api_unreachable")
    if not known_state(truth, stateless=stateless):
        return TableDecision(False, "api_unreachable" if truth is None else "ambiguous_state")
    assert truth is not None  # noqa: S101 - narrowed by known_state
    status, attached = _vol(truth)
    blue = truth.get("blue") or {}
    fip_on = (truth.get("fip") or {}).get("on")
    on_blue_only = stateless or (status == "in-use" and attached == [blue_id])
    free = stateless or (status == "available" and not attached)
    on_green_only = stateless or (
        status == "in-use" and green_id is not None and attached == [green_id]
    )

    def gate(label: str) -> TableDecision:
        if not auto_restore:
            return TableDecision(False, "auto_restore_disabled")
        if already_used:
            return TableDecision(False, "auto_restore_already_used")
        return TableDecision(True, label)

    def d1(label: str) -> TableDecision:
        if snapshot_available:
            return gate(label)
        return TableDecision(False, "post_start_failure", post_start=True)

    park_reason = "approval_evidence_invalid" if trigger == TRIGGER_EVIDENCE else None

    if step_key == "quiesce_old":
        return TableDecision(False, reason or "quiesce_failed")
    if trigger in (TRIGGER_BUDGET, TRIGGER_EVIDENCE):
        if step_key in PRE_START:
            if fip_on == "blue" and (on_blue_only or free or on_green_only):
                return gate(trigger)
            return TableDecision(False, park_reason or "window_budget_exceeded")
        if (
            step_key in ("start_service_green", "healthcheck_green", "move_fip")
            and fip_on == "blue"
        ):
            result = d1(trigger)
            if not result.restore and park_reason:
                return TableDecision(False, park_reason, post_start=True)
            return result
        return TableDecision(False, park_reason or "window_budget_exceeded")
    if step_key == "data_attach_green":
        return TableDecision(False, reason or "data_attach_failed")
    if step_key == "stop_old":
        if reason in ("server_locked", "compute_host_down"):
            return TableDecision(False, reason)
        if on_blue_only and blue.get("task_state") is None and fip_on == "blue":
            return gate("stop_old_exhausted")
        return TableDecision(False, reason or "ambiguous_state")
    if step_key == "detach_volume":
        if status == "detaching":
            return TableDecision(False, "volume_stuck_detaching")
        if reason == "compute_host_down":
            return TableDecision(False, reason)
        if on_blue_only and fip_on == "blue":
            return gate("detach_rolled_back")
        return TableDecision(False, reason or "ambiguous_state")
    if step_key == "snapshot_volume":
        if free and blue.get("status") == "SHUTOFF" and fip_on == "blue":
            return gate("snapshot_failed")
        return TableDecision(False, reason or "ambiguous_state")
    if step_key == "attach_volume_green":
        if free and fip_on == "blue":
            return gate("attach_not_done")
        return TableDecision(
            False, "volume_stuck_attaching" if status in ("reserved", "attaching") else reason
        )
    if step_key in ("start_service_green", "healthcheck_green"):
        return d1(step_key)
    if step_key == "move_fip":
        if fip_on == "blue":
            return d1("move_fip_failed")
        return TableDecision(False, "fip_state_unknown")
    if step_key == "verify_external":
        return d1("verify_external_failed")
    return TableDecision(False, reason or "ambiguous_state")
