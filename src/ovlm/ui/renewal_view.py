"""View models for the renewal pages (E6-3, E6-4): plain-language step names, needs_human reasons with the next
action, the hash inputs an approver must see, the automatic-restore table, durations and evidence rows.

Pure functions over the dicts the service layer returns (``ovlm.renewal.service``): nothing here reads the database
or calls OpenStack, so the wording is unit-testable and the pages cannot show anything the API does not return.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from ovlm.ui.readiness_view import evidence_lines
from ovlm.ui.support import parse_ts, templates

# --- steps ---------------------------------------------------------------------------------------------------------

#: step_key -> (code in renewal-workflow.md, what it does in plain words)
STEP_TITLES: Mapping[str, tuple[str, str]] = {
    "preflight": ("B1", "Re-check the plan against the live cloud"),
    "claim_resources": ("B2", "Mark the old VM, floating IP and data volume as managed"),
    "create_green": ("B3", "Create the new VM (green)"),
    "wait_green_active": ("B4", "Wait for the new VM to become ACTIVE"),
    "wait_green_ssh": ("B5", "Reach the new VM over SSH and pin its host key"),
    "prepare_automation": ("B6", "Fetch and verify the automation repository"),
    "configure_green": ("B7", "Configure the new VM (no data yet)"),
    "verify_cutover_preconditions": ("B8", "Re-check everything the cutover needs"),
    "await_cutover": ("G2", "Wait for the cutover approval and an open window"),
    "verify_green_ready": ("B9", "Prove the new VM is ready before any downtime"),
    "quiesce_old": (
        "W1",
        "Stop the service on the old VM and unmount the data volume (downtime starts)",
    ),
    "stop_old": ("W2", "Stop the old VM"),
    "detach_volume": ("W3", "Detach the data volume from the old VM"),
    "snapshot_volume": ("W4", "Snapshot the data volume (a manual way back)"),
    "attach_volume_green": ("W5", "Attach the data volume to the new VM"),
    "data_attach_green": ("W6", "Mount the data volume on the new VM"),
    "start_service_green": ("W7", "Start the service on the new VM"),
    "healthcheck_green": ("W8", "Health-check the service on the new VM"),
    "move_fip": ("W9", "Move the floating IP to the new VM"),
    "verify_external": ("W10", "Check the service from outside through the floating IP"),
    "retain_old": ("R1", "Lock and keep the old VM, stopped"),
    "await_retention": ("R2", "Wait for the retention period (revert is possible)"),
    "await_retirement": ("G3", "Wait for the retirement approval"),
    "retire_old": ("X1", "Delete the old VM (irreversible)"),
    "unlock_old": ("S1", "Restore: unlock the old VM"),
    "quiesce_green": ("S2", "Restore: stop the service on the new VM"),
    "stop_green": ("S3", "Restore: stop the new VM"),
    "detach_from_green": ("S4", "Restore: detach the data volume from the new VM"),
    "attach_to_old": ("S5", "Restore: attach the data volume to the old VM"),
    "boot_old": ("S6", "Restore: boot the old VM"),
    "recover_old_service": ("S7", "Restore: health-check the service on the old VM"),
    "move_fip_to_old": ("S8", "Restore: move the floating IP back to the old VM"),
    "verify_external_old": ("S9", "Restore: check the service from outside"),
    "lock_green": ("S10", "Restore: lock the new VM so nobody starts it by hand"),
    "await_discard": ("D0", "Wait for an operator to discard the new VM"),
    "discard_green": ("D1", "Delete the new VM (green)"),
}
#: Steps whose evidence includes text the guest produced (security-model.md 6.4: shown escaped, labelled).
GUEST_STEPS = frozenset({
    "wait_green_ssh", "prepare_automation", "configure_green", "verify_green_ready", "quiesce_old",
    "data_attach_green", "start_service_green", "healthcheck_green", "verify_external", "quiesce_green",
    "recover_old_service", "verify_external_old", "retire_old",
})  # fmt: skip
PHASE_TEXT = {
    "build": "Build: the new VM is being prepared; the service is not affected",
    "window": "Downtime window: the service is down or moving",
    "retained": "Retention: the service runs on the new VM; the old VM is kept stopped",
    "retire": "Retirement: the old VM is being deleted",
    "restore": "Restore: the service is being brought back to the old VM",
}
RUN_STATE_TEXT = {
    "requested": "Waiting for the worker to admit the run",
    "running": "Running",
    "needs_human": "Stopped: needs a human",
    "completed": "Completed",
    "rolled_back": "Rolled back: the service runs on the old VM",
    "failed": "Failed",
    "rejected": "Rejected by the worker at admission",
    "cancelled": "Cancelled",
}
STEP_BADGE = {
    "succeeded": "ok", "running": "info", "ready": "info", "waiting": "info",
    "needs_human": "err", "failed": "err", "skipped": "", "cancelled": "",
}  # fmt: skip


def step_title(key: str) -> tuple[str, str]:
    return STEP_TITLES.get(key, ("", key.replace("_", " ")))


# --- needs_human: what happened and what to do next ----------------------------------------------------------------

_ADMIN = "This needs someone with OpenStack admin rights: OVLM's credential cannot do it."
_PROBE = "Press Probe to refresh the current truth, then check the panel against what you see in OpenStack."
_AFTER_FIX = "When the cause is fixed, use Mark resolved (say what you did) or Retry step."

#: reason -> (what happened, [what to do next])
NEEDS_HUMAN: Mapping[str, tuple[str, list[str]]] = {
    "api_unreachable": (
        "OpenStack stopped answering before the step finished. OVLM sent nothing more.",
        [
            "Check that the OpenStack API is reachable from the worker.",
            "OVLM re-probes by itself and continues only if nothing changed and the budget is not spent; otherwise it stays here.",
            _PROBE,
        ],
    ),  # fmt: skip
    "post_start_failure": (
        "The service had already started on the new VM and then failed. The data volume may hold writes made by the new VM, "
        "so OVLM did not restore by itself (decision D-1). This pages an operator.",
        [
            "Look at the service on the new VM first: a retry may be enough.",
            "Rollback starts the old VM on the data as the new VM left it; read the effect of Rollback below before you use it.",
            _PROBE,
        ],
    ),  # fmt: skip
    "window_budget_exceeded": (
        "The downtime window ran past the budget the approver accepted. Nothing continues without a human.",
        [
            "Decide: finish forward with Retry step, or go back with Rollback (read its effect below).",
            _PROBE,
        ],
    ),
    "budget": (
        "The downtime window ran past the budget the approver accepted.",
        ["Decide: finish forward with Retry step, or go back with Rollback.", _PROBE],
    ),
    "approval_evidence_invalid": (
        "The worker re-checked the approval and it no longer holds (changed plan, expired, or the approver was not allowed).",
        [
            "Do not retry blindly: the approval is not valid.",
            "If the downtime has not started, Abort and create a new plan. In the window, read the effect of Rollback below.",
        ],
    ),
    "deadline_exceeded": (
        "A step took longer than its deadline.",
        [
            _PROBE,
            "If the resource is fine now, use Retry step; otherwise fix the cause and Mark resolved.",
        ],
    ),
    "host_key_unverifiable": (
        "The new VM's SSH host key could not be verified, so OVLM refused to connect.",
        [
            "Check the new VM's console log in OpenStack.",
            "Retry step re-checks; if it keeps failing, Rollback deletes the new VM.",
        ],
    ),
    "lint_waiver_invalid": (
        "A lint waiver of the profile version has no valid grant behind it (wrong or missing TOTP step-up, the "
        "granter did not hold approver then, or the granter authored or requested this work), so OVLM did not "
        "apply it and changed nothing. The row may have been written outside the API.",
        [
            "Read the step evidence: it lists each failing waiver and why. Treat it as a security event.",
            "Have an approver revoke the waiver and, if it is still needed, grant it again through the API; then "
            "start a new plan.",
        ],
    ),
    "lint_waiver_too_broad": (
        "A lint waiver of the profile version covered more than 20 findings in the automation, so OVLM stopped "
        "before running it: the waiver's path glob is probably broader than intended.",
        [
            "Read the step evidence: it lists each waiver with the files and findings it matched.",
            "Ask an approver to revoke the waiver and grant a narrower one, then start a new plan.",
        ],
    ),
    "compute_host_down": (
        "OpenStack refused the call because the VM's compute host is down.",
        [_ADMIN + " Fix the host or evacuate the VM.", _AFTER_FIX],
    ),
    "server_locked": (
        "A server is locked by an administrator, so OVLM's member credential cannot act on it.",
        [_ADMIN + " Unlock the server.", _AFTER_FIX],
    ),
    "foreign_lock": (
        "The old VM is locked by someone other than OVLM.",
        [_ADMIN + " Unlock the server.", _AFTER_FIX],
    ),
    "snapshot_adoption_refused": (
        "A snapshot with this run's name exists but does not look like the one OVLM created (wrong source "
        "volume, missing run marker, or older than OVLM's record). OVLM did not use it and changed nothing.",
        [
            "Inspect the snapshot named in the evidence: who created it and from which volume.",
            "Do not delete it unless you are sure it holds nothing you need.",
            _AFTER_FIX,
        ],
    ),
    "volume_stuck_attaching": (
        "The data volume is stuck in an attaching or reserved state.",
        [_ADMIN + " Typically a Cinder reset-state or force-detach.", _AFTER_FIX],
    ),
    "volume_unexpected_state": (
        "The data volume is not where OVLM expects it. OVLM changed nothing further.",
        [
            _PROBE,
            "Compare the volume status and attachment in the panel with OpenStack. " + _ADMIN,
            _AFTER_FIX,
        ],
    ),
    "detach_rolled_back": (
        "The volume detach was rolled back by OpenStack: the volume is attached to the old VM again.",
        [
            _PROBE,
            "If the old VM is healthy, Rollback restores service; otherwise fix the detach cause and Retry step.",
        ],
    ),
    "attach_not_done": (
        "The volume attach did not complete.",
        [_PROBE, "Check the volume in OpenStack. " + _ADMIN, _AFTER_FIX],
    ),
    "data_attach_mismatch": (
        "The volume mounted on the new VM does not match the profile (filesystem UUID or label, or data marker). "
        "OVLM never formats an existing volume.",
        [
            "Do not retry until you know why. Check the filesystem on the new VM.",
            "Rollback moves the volume back to the old VM (read its effect below).",
        ],
    ),
    "data_phase_interrupted": (
        "The worker died while it was moving data. OVLM probed read-only and attached the result as evidence.",
        [
            "Read the evidence of this step and the current truth.",
            _PROBE,
            "Then Retry step (it starts with a probe) or Rollback.",
        ],
    ),
    "healthcheck_exhausted": (
        "The service on the new VM did not become healthy within the allowed attempts.",
        [
            "Look at the service on the new VM.",
            "Retry step re-runs the health check; Rollback goes back to the old VM (read its effect below).",
        ],
    ),
    "old_service_unhealthy": (
        "The service did not come back healthy on the old VM after the restore.",
        [
            "Check the old VM and its service by hand: the restore reached the old VM but it is not healthy.",
            _PROBE,
            _AFTER_FIX,
        ],
    ),
    "blue_not_stopped": (
        "The old VM did not stop.",
        [_PROBE, "Check the old VM in OpenStack (task state, lock).", _AFTER_FIX],
    ),
    "blue_unexpected_state": (
        "The old VM is not in the state OVLM expects.",
        [_PROBE, "Compare with OpenStack. " + _ADMIN, _AFTER_FIX],
    ),
    "blue_probe_failed": (
        "OVLM could not read the old VM's mount and services over SSH.",
        ["Check that the old VM answers on SSH.", _AFTER_FIX],
    ),
    "blue_unhealthy_after_boot": (
        "The old VM booted but its service or mount is not healthy.",
        ["Log in to the old VM and check the mount point and the service units.", _AFTER_FIX],
    ),
    "fip_move_back_failed": (
        "The floating IP could not be moved back to the old VM.",
        [
            "Check the floating IP in OpenStack: which port is it on?",
            "L3/OVN agent problems need an administrator.",
            _AFTER_FIX,
        ],
    ),
    "fip_state_unknown": (
        "OVLM cannot read which port the floating IP is on, so it will not move it.",
        [_PROBE, "Look at the floating IP in OpenStack.", _AFTER_FIX],
    ),
    "green_disappeared": (
        "The new VM is gone from OpenStack.",
        [
            _PROBE,
            "Find out who deleted it. If the build phase is still running, Rollback ends the run cleanly.",
        ],
    ),
    "green_unknown": (
        "OVLM does not know which VM is the new one.",
        [
            _PROBE,
            "Do not create anything by hand with the run's name. Rollback after you checked OpenStack.",
        ],
    ),
    "green_port_ambiguous": (
        "The new VM has more than one port and OVLM will not guess.",
        [
            "Check the new VM's ports in OpenStack.",
            "Rollback deletes the new VM; fix the cause and plan again.",
        ],
    ),
    "green_has_volume": (
        "The new VM still has the data volume attached, so OVLM will not delete it.",
        [
            _ADMIN,
            "Move the volume back to the old VM by hand (or with Rollback in the window), then Retry step.",
        ],
    ),
    "adoption_refused": (
        "OVLM found a server that looks like the new VM from an earlier attempt, but it does not match what this run "
        "would have created (image, flavor, age or attached volumes), so it refused to adopt it.",
        [
            "Look at the server tagged with this run in OpenStack: who created it, and with what?",
            "Do not delete it blindly. If it is not OVLM's, Rollback ends the run and leaves it alone.",
        ],
    ),
    "duplicate_resource": (
        "More than one resource matches what OVLM created for this run.",
        [
            "Look for duplicates tagged with this run in OpenStack and remove the extra one.",
            _AFTER_FIX,
        ],
    ),
    "snapshot_failed": (
        "The pre-handoff snapshot failed.",
        [_PROBE, "Check the volume and the snapshot in OpenStack.", _AFTER_FIX],
    ),
    "snapshot_unsupported": (
        "The snapshot step is not supported for this volume.",
        ["Change the profile to not require a snapshot, then plan again."],
    ),
    "retain_precondition": (
        "The old VM is not in the state OVLM needs before it keeps it stopped and locked.",
        [_PROBE, "Check the old VM in OpenStack.", _AFTER_FIX],
    ),
    "retire_precondition_mismatch": (
        "Before deleting the old VM OVLM found something that does not match what was approved. "
        "Nothing was deleted and the retirement approval is void.",
        [
            "Read the evidence of this step: it lists each mismatch.",
            "Fix the cause, then request a new retirement approval.",
        ],
    ),
    "w1_rerun_unexpected_state": (
        "The downtime had already started when the quiesce step ran again, and the old VM or its data volume is not "
        "where OVLM left it. Nothing was run on the old VM.",
        [
            _PROBE,
            "Read the evidence of this step: it lists what differs.",
            "Rollback restores the old VM (read its effect below); Retry step only once the state is back.",
        ],
    ),  # fmt: skip
    "w1_reclaim_refused": (
        "The downtime had already started, and the quiesce step could not be claimed again. The run stays in the "
        "window: it never goes back to the build phase while the old VM may be stopped.",
        [_PROBE, "Rollback restores the old VM (read its effect below)."],
    ),
    "outage_open_build_refused": (
        "OVLM refused to leave the downtime window for the build phase: the old VM may be stopped, and the build "
        "phase can only delete the new VM. This is a safety stop.",
        [
            _PROBE,
            "Rollback restores the old VM (read its effect below).",
            "Report this to your OVLM administrator.",
        ],
    ),  # fmt: skip
    "volume_not_on_blue": (
        "During the restore, the data volume is not attached to the old VM, so OVLM did not start it: it would boot "
        "without its data.",
        [_PROBE, "Attach the data volume to the old VM (and only to it), then Retry step."],
    ),
    "green_unrecorded": (
        "A server tagged for this run exists, but OVLM never recorded its id (the create answer was lost). OVLM did "
        "not delete it.",
        [
            "Read the evidence of this step: it names the server.",
            "Check that server in OpenStack and delete it by hand if it is the new VM of this run, then Retry step.",
        ],
    ),  # fmt: skip
    "state_lookup_failed": (
        "OVLM could not read a resource it needs.",
        [_PROBE, "Check that the resource exists in OpenStack.", _AFTER_FIX],
    ),
    "no_next_step": (
        "The run finished a step and found no next step. This is a bug or a version mismatch.",
        ["Do not retry. Ask your OVLM administrator."],
    ),
    "unknown_step": (
        "The run reached a step this OVLM version does not know. This is a bug or a version mismatch.",
        ["Do not retry. Ask your OVLM administrator."],
    ),
    "quiesce_failed": (
        "The service could not be stopped and unmounted cleanly on the old VM, so the data may not be consistent.",
        [
            "Log in to the old VM and check the service and the mount.",
            "Retry step, or Abort to stop the window safely.",
        ],
    ),
    "quiesce_green_failed": (
        "Restore step S2: the pinned quiesce playbook refused on the new VM. The restore cannot go on past it by "
        "itself, and the pinned repository cannot change during the run.",
        [
            "Read the step's error below: it is what the playbook reported (untrusted text from the guest).",
            "If the cause is fixable on the new VM, fix it and use Retry step.",
            "If the playbook refuses a state that is safe (for example a data volume that was never mounted), an "
            "approver who is not the run's requester can use Accept the step without running its playbook: press "
            "Probe first; OVLM offers it only while its own read-only probe shows the volume attached to the new VM "
            "only, mounted nowhere there, and the service units stopped.",
        ],
    ),  # fmt: skip
    "quiesce_no_marker": (
        "The service on the old VM was stopped and the data volume unmounted, but the automation reported no data "
        "marker checksum. Without it OVLM cannot prove on the new VM that the data survived, so it stopped before "
        "stopping the old VM or detaching the volume.",
        [
            "Rollback restores the old VM (read its effect below).",
            "Before a new renewal: make the automation repository's quiesce phase report facts.marker_sha256 "
            "(automation contract 3.4, 3.7) and make sure the data marker file exists on the volume.",
        ],
    ),  # fmt: skip
    "data_attach_failed": (
        "The data volume could not be mounted on the new VM.",
        [
            "Check the new VM: device, filesystem, mount.",
            "Retry step, or Rollback (read its effect below).",
        ],
    ),
    "ambiguous_state": (
        "The failure left the resources in a state OVLM could not classify, so it did not restore by itself.",
        [_PROBE, "Compare the panel with OpenStack before you choose Retry step or Rollback."],
    ),
    "automation_error": (
        "The automation (Ansible) step failed.",
        [
            "Operators and admins can read the automation log from the step's attempts below.",
            _AFTER_FIX,
        ],
    ),
}
_GENERIC = (
    "The run stopped because OVLM could not decide safely what to do next.",
    [_PROBE, "Read the failed step's error and evidence below.", _AFTER_FIX],
)


def needs_human_text(reason: str | None) -> dict[str, Any]:
    """What an operator at 3 a.m. reads: the reason in words and the ordered next actions."""
    what, todo = NEEDS_HUMAN.get(reason or "", _GENERIC)
    return {
        "reason": reason or "unknown",
        "what": what,
        "todo": list(todo),
        "known": reason in NEEDS_HUMAN,
    }


# --- durations and the downtime timer -----------------------------------------------------------------------------


def duration(seconds: Any) -> str:
    """``1h 05m``, ``12m 03s``, ``45s``."""
    try:
        total = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return "unknown"
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def downtime_duration(seconds: Any) -> str:
    """A measured downtime: ``None`` is "not measured", a sub-second value is shown as such, never as ``0s`` (P2-3:
    a demo run on the fake cloud measured 0.04 s and the page said "0s", which reads as "no downtime")."""
    if seconds is None:
        return "not measured"
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return "not measured"
    if value < 0.1:
        return "under 0.1s"
    if value < 1:
        return f"{value:.1f}s"
    return duration(value)


#: interval kind -> plain words
DOWNTIME_KIND_TEXT = {
    "window": "Renewal window",
    "restore": "Restore to the old VM",
}


def _intervals_from_columns(run: Mapping[str, Any], now: datetime) -> list[dict[str, Any]]:
    start = parse_ts(run.get("downtime_started_at"))
    if start is None:
        return []
    end = parse_ts(run.get("downtime_ended_at"))
    return [{"kind": "window", "started_at": start, "started_by_step": "quiesce_old", "ended_at": end,
             "ended_by_step": None, "ongoing": end is None, "end_measured": True,
             "seconds": ((end or now) - start).total_seconds()}]  # fmt: skip


def downtime(run: Mapping[str, Any], now: datetime | None = None) -> dict[str, Any] | None:
    """The downtime panel: every interval the run recorded (window, restore after a revert), their total, and the
    window's elapsed time against the budget the approver accepted. ``None`` before the first outage. Reads the run
    representation's ``downtime`` object; a run dict without it is read through the first-interval columns."""
    now = now or datetime.now(UTC)
    body = run.get("downtime")
    if isinstance(body, Mapping):
        items = [dict(i) for i in body.get("intervals") or []]
    else:
        items = _intervals_from_columns(run, now)
    if not items:
        return None
    rows: list[dict[str, Any]] = []
    for it in items:
        started = parse_ts(it.get("started_at"))
        ended = parse_ts(it.get("ended_at"))
        seconds = it.get("seconds")
        if it.get("ongoing") and started is not None:
            seconds = max(float(seconds or 0), (now - started).total_seconds())
        rows.append({
            "kind": it.get("kind"), "kind_text": DOWNTIME_KIND_TEXT.get(str(it.get("kind")), str(it.get("kind"))),
            "started": started, "ended": ended, "ongoing": bool(it.get("ongoing")),
            "end_measured": it.get("end_measured", True) is not False,
            "started_by": step_title(str(it.get("started_by_step") or ""))[0] or None,
            "ended_by": step_title(str(it.get("ended_by_step") or ""))[0] or None,
            "seconds": None if seconds is None else float(seconds),
            "text": downtime_duration(seconds),
        })  # fmt: skip
    measured = [r["seconds"] for r in rows if r["seconds"] is not None]
    total = sum(measured) if measured else None
    running = any(r["ongoing"] for r in rows)
    window = rows[0]
    elapsed = window["seconds"]
    budget = run.get("max_window_duration_seconds")
    cap = int(budget) if budget else 0
    over = bool(cap) and elapsed is not None and elapsed > cap
    window_running = window["ongoing"]
    return {
        "running": running, "intervals": rows, "total": total, "total_text": downtime_duration(total),
        "complete": all(r["end_measured"] for r in rows),
        "elapsed": elapsed, "budget": budget, "worst_case": run.get("worst_case_window_seconds"), "over": over,
        "window_running": window_running,
        "remaining": int(cap - elapsed) if cap and window_running and elapsed is not None else None,
        "percent": min(100, round(100 * elapsed / cap)) if cap and elapsed is not None else None,
        "started": window["started"],
    }  # fmt: skip


def truth_age_seconds(run: Mapping[str, Any], now: datetime | None = None) -> int | None:
    at = parse_ts(run.get("current_truth_at"))
    return int(((now or datetime.now(UTC)) - at).total_seconds()) if at else None


# --- approvals: everything the approver must see -------------------------------------------------------------------

GATE_TEXT = {
    "plan": ("G1", "Plan approval", "Approves this plan: what will be built and with which automation. Nothing runs yet."),
    "cutover": ("G2", "Cutover approval", "Approves the downtime window: the service is stopped on the old VM and moved to the new one."),
    "retirement": ("G3", "Retirement approval", "Approves deleting the old VM. This is irreversible."),
}  # fmt: skip

#: (trigger, auto restore without snapshot, with a W4 snapshot) from renewal-workflow.md 4.1
_ALWAYS, _NEVER = "yes", "no: stops and waits for an operator"
_PAGE = "no: stops and pages an operator"
RESTORE_ROWS: tuple[tuple[str, str, str], ...] = (
    ("W1 quiesce the old VM fails", _NEVER, _NEVER),
    ("W2 stop of the old VM fails (not a lock)", _ALWAYS, _ALWAYS),
    ("W3 detach is rolled back by OpenStack", _ALWAYS, _ALWAYS),
    ("W3 detach is stuck", _NEVER, _NEVER),
    ("W4 snapshot fails", _ALWAYS, _ALWAYS),
    ("W5 attach not done", _ALWAYS, _ALWAYS),
    ("W5 attach in error or stuck", _NEVER, _NEVER),
    ("W6 mounting the data on the new VM fails", _NEVER, _NEVER),
    ("W7 service start fails on the new VM", _PAGE, _ALWAYS),
    ("W8 health check fails on the new VM", _PAGE, _ALWAYS),
    ("W9 floating IP move is refused", _PAGE, _ALWAYS),
    ("W10 external check fails", _PAGE, _ALWAYS),
    ("Budget exceeded before W2-W6", _ALWAYS, _ALWAYS),
    ("Budget exceeded before W7-W8", _PAGE, _ALWAYS),
    ("OpenStack API unreachable", "no: nothing is sent while it is down", "no: nothing is sent while it is down"),
)  # fmt: skip


def restore_table(resolved: Mapping[str, Any]) -> dict[str, Any]:
    """The closed automatic-restore table for this plan: what happens on each failure, given the policy switch and
    whether a pre-handoff snapshot is taken (renewal-workflow.md 4.1, decision D-1)."""
    auto = bool(resolved.get("auto_restore_in_window"))
    snapshot = bool((resolved.get("data_volume") or {}).get("snapshot_before_handoff"))
    rows = []
    for trigger, no_snap, with_snap in RESTORE_ROWS:
        outcome = (
            (with_snap if snapshot else no_snap)
            if auto
            else "no: every failure stops and pages an operator"
        )
        if trigger.startswith("OpenStack API"):
            outcome = no_snap
        rows.append({"trigger": trigger, "outcome": outcome, "restores": outcome == "yes"})
    return {"enabled": auto, "snapshot": snapshot, "rows": rows,
            "once": "OVLM restores automatically at most once per run; a failed restore stops for an operator."}  # fmt: skip


def hash_inputs(approval: Mapping[str, Any]) -> dict[str, Any]:
    """The inputs bound into the plan hash, from the approval's own copy (what the approver actually approves)."""
    hi = approval.get("hash_inputs") or {}
    res = hi.get("resolved") or {}
    policy = hi.get("policy") or {}
    auto = res.get("automation") or {}
    diff = hi.get("automation_diff") or {}
    return {
        "bound_hash": approval.get("bound_hash"),
        "profile": res.get("profile_version") or {},
        "automation": {"repo": auto.get("repo"), "sha": auto.get("sha"), "playbook_dir": auto.get("playbook_dir"),
                       "store_diffs": auto.get("store_diffs")},  # fmt: skip
        "diff": {"previous": diff.get("previous_approved_sha"), "sha": diff.get("sha"), "summary": diff.get("summary"),
                 "changed_files": diff.get("changed_files"), "note": diff.get("note")},  # fmt: skip
        "blue": res.get("blue") or {},
        "image": res.get("image") or {},
        "flavor": res.get("flavor") or {},
        "security_groups": res.get("security_groups") or [],
        "network_id": res.get("network_id"),
        "floating_ip": res.get("floating_ip") or {},
        "data_volume": res.get("data_volume"),
        "service": res.get("service") or {},
        "policy": policy,
        "lint_waivers": hi.get("lint_waivers") or [],
    }  # fmt: skip


def policy_rows(policy: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The policy fields the renewal acts on, as label/value rows."""
    appr = policy.get("approvals") or {}
    rows = [
        ("policy version", f"{policy.get('version', '?')} (id {policy.get('id', '?')})"),
        ("approvals required", ", ".join(k for k, v in sorted(appr.items()) if v) or "none"),
        ("distinct approvers required", "yes" if policy.get("require_distinct_approvers") else "no"),
        ("automatic restore in the window", "on" if policy.get("auto_restore_in_window") else "off"),
        ("maximum window duration", duration(policy.get("max_window_duration_seconds"))),
        ("retention period", duration(policy.get("retention_period_seconds")) if policy.get("retention_period_seconds") else "not set"),
        ("allowed windows", _windows(policy.get("windows"))),
    ]  # fmt: skip
    return rows


def _windows(windows: Any) -> str:
    out = []
    for w in windows or []:
        days = ",".join(w.get("weekdays") or []) if isinstance(w, dict) else ""
        out.append(f"{days} {w.get('start', '?')}-{w.get('end', '?')} {w.get('timezone', '')}".strip()
                   if isinstance(w, dict) else str(w))  # fmt: skip
    return "; ".join(out) or "any time"


def accept_form(run: Mapping[str, Any]) -> dict[str, Any]:
    """The accept-step form (ADR-0008): the refused playbook result (reported by the guest: untrusted, shown
    escaped), OVLM's latest probe of the postcondition with its id, time and checks, and what the request carries."""
    step = run.get("current_step") or {}
    truth = run.get("current_truth")
    probe = truth.get("accept_probe") if isinstance(truth, Mapping) else None
    offer = next(
        (a for a in run.get("available_actions") or () if a.get("action") == "accept-step"), None
    )
    checks = [
        (c.get("check", ""), bool(c.get("ok")), str(c.get("detail", "")))
        for c in (probe or {}).get("checks") or ()
    ]
    return {
        "step_id": str(step.get("id") or ""), "step_key": step.get("step_key"),
        "refused_rows": evidence_lines(step.get("error")), "probe": probe, "checks": checks,
        "probe_id": str((probe or {}).get("id") or ""), "probe_at": (probe or {}).get("at"),
        "available": bool(offer and offer.get("available")), "why": (offer or {}).get("effect"),
    }  # fmt: skip


def typed_target(tc: str) -> dict[str, str]:
    """Split a typed confirmation string (``name last6``) for display. The string itself is never rendered."""
    name, _, tail = tc.rpartition(" ")
    return {"name": name or tc, "tail": tail if name else ""}


# --- filters -------------------------------------------------------------------------------------------------------

templates.env.filters["duration"] = duration
templates.env.filters["downtime_duration"] = downtime_duration
templates.env.filters["step_code"] = lambda k: step_title(str(k))[0]
templates.env.filters["step_text"] = lambda k: step_title(str(k))[1]
templates.env.filters["step_badge"] = lambda s: STEP_BADGE.get(str(s), "")
templates.env.filters["evidence_rows"] = evidence_lines
templates.env.globals["PHASE_TEXT"] = PHASE_TEXT
templates.env.globals["RUN_STATE_TEXT"] = RUN_STATE_TEXT
templates.env.globals["GATE_TEXT"] = GATE_TEXT


def truth_sections(truth: Any) -> list[tuple[str, list[tuple[str, str]]]]:
    """The current-truth panel as ``(section, rows)``: one section per resource (blue, green, volume, FIP ...)."""
    if not isinstance(truth, dict) or not truth:
        return []
    general: list[tuple[str, str]] = []
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    for key, value in truth.items():
        if isinstance(value, dict) and value:
            sections.append((str(key).replace("_", " "), evidence_lines(value)))
        else:
            general.extend(evidence_lines({key: value}))
    return ([("general", general)] if general else []) + sections


templates.env.filters["duration_since"] = lambda v: duration(
    (datetime.now(UTC) - parsed).total_seconds() if (parsed := parse_ts(v)) else None
)
