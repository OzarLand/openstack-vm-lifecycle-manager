"""``bluegreen_fip_v1``: the workflow definition (renewal-workflow.md, ADR-0004). Worker only.

State machine on top of the engine (ADR-0003). Phases: ``build`` (B1-B9, G2, Discarding of a build), ``window``
(W1-W10), ``retained`` (R1, R2, G3), ``retire`` (X1), ``restore`` (S1-S10, Restored, Discarding after a restore).
``needs_human`` is the engine's overlay: a parked step keeps the phase and **all locks** (SRE-R-18); retry-step
retries the same step.

Failure handling (:meth:`BlueGreenFipV1.on_failure`):

* B1/B2 fatal: run ``failed`` (nothing created; B2 markers stay). Any later build failure parks the run
  (``BuildFailed``): locks kept, green kept for diagnosis, operator rollback (TC) deletes it. Never terminal while
  OVLM may hold a resource, so locks are never released under a live green.
* W1 claim refused: back to G2 or B9, no outage. **Never once the outage started** (REN-1): from the moment W1 wrote
  ``downtime_started_at`` (in the transaction that precedes the quiesce play) until ``downtime_ended_at``, no
  transition may lead back to the build phase or to Discarding; :meth:`BlueGreenFipV1._seal` enforces it for every
  transition the definition returns, and a rollback/abort in that state restores blue (S1-S10).
* Downtime: every interval is a ``run_downtime`` row (:mod:`ovlm.renewal.downtime`): the window (W1 claim to W10, or
  to S9 after an in-window restore) and a restore after the cutover (S2 to S9). Closed in the W10/S9 success commit.
* W1-W10: the closed table (:mod:`ovlm.renewal.closed_table`), D-1 = B. One automatic restore per run
  (``workflow_run.auto_restore_used``), audited ``restore.auto`` (system, authority = the G2 approval id).
* Restore, retention, retirement, Discarding: needs_human.

Signals (re-validated here, SEC-R-1): ``rollback``/``abort``/``revert``/``discard`` need an operator in scope, a
consumed step-up ``run.<kind>`` on the run and the TC of the affected VM; ``mark_resolved`` additionally needs the
approver role when the current step (re-queued by the engine, so its own act comes next) or the following step is
destructive (REN-5); ``reprepare_automation`` needs the approver role (never the run's requester), the step-up and
TC, and a step parked on a lost/unverifiable automation checkout (:mod:`ovlm.renewal.reprepare`); ``accept_step``
(ADR-0008, :mod:`ovlm.renewal.accept`) needs an approver who is not the requester, the step-up, the TC of green, an
attestation, S2 parked in restore because its playbook refused, and OVLM's own fresh probe meeting S2's postcondition
(:meth:`BlueGreenFipV1.accept_probe`); it closes S2 without running it and the run goes on with S3; ``revert`` is
refused once X1 has persisted its delete intent (REN-4); ``probe`` refreshes the current-truth panel and, sent by the
re-probe job for ``api_unreachable``, applies the self-resolution rules of section 5.1.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.sod import INTERACTIVE_AUTH, STEPUP_VALIDITY, role_held_at
from ovlm.openstack.errors import WriteNotAllowedError
from ovlm.renewal import accept, closed_table, downtime, metrics, reprepare
from ovlm.renewal.base import Deps, RStep, project_of, read_truth
from ovlm.renewal.config import RESTORE_STEPS, WINDOW_STEPS
from ovlm.renewal.ledger import DbOwnershipRegistry, green_row, plan_resolved, snapshot_row
from ovlm.renewal.plans import (
    KIND,
    STRATEGY,
    STRATEGY_VERSION,
    effective_phase,
    load_facts,
    now_db,
    outage_marks,
    tc_target,
)
from ovlm.renewal.ports import GuestProbe, GuestProbeTimeout, GuestRef
from ovlm.renewal.steps_after import (
    AttachToOld,
    AwaitDiscard,
    AwaitRetention,
    AwaitRetirement,
    BootOld,
    DetachFromGreen,
    DiscardGreen,
    LockGreen,
    MoveFipToOld,
    QuiesceGreen,
    RecoverOldService,
    RetainOld,
    RetireOld,
    StopGreen,
    UnlockOld,
    VerifyExternalOld,
)
from ovlm.renewal.steps_build import (
    AwaitCutover,
    ClaimResources,
    ConfigureGreen,
    CreateGreen,
    Preflight,
    PrepareAutomation,
    VerifyCutoverPreconditions,
    VerifyGreenReady,
    WaitGreenActive,
    WaitGreenSsh,
)
from ovlm.renewal.steps_window import (
    AttachVolumeGreen,
    DataAttachGreen,
    DetachVolume,
    HealthcheckGreen,
    MoveFip,
    QuiesceOld,
    SnapshotVolume,
    StartServiceGreen,
    StopOld,
    VerifyExternal,
)
from ovlm.workflow.contract import (
    AcceptStep,
    Admission,
    Defer,
    Done,
    ErrorClass,
    Fail,
    LockSpec,
    Outcome,
    Reject,
    RunView,
    SignalView,
    Step,
    StepSpec,
    Transition,
    TxContext,
    Wake,
    WorkflowDefinition,
)
from ovlm.workflow.ids import new_id

log = logging.getLogger("ovlm.renewal")


BUILD = (
    "preflight",
    "claim_resources",
    "create_green",
    "wait_green_active",
    "wait_green_ssh",
    "prepare_automation",
    "configure_green",
    "verify_cutover_preconditions",
    "await_cutover",
    "verify_green_ready",
)
AFTER = ("retain_old", "await_retention", "await_retirement", "retire_old")
HANDOFF = ("detach_volume", "snapshot_volume", "attach_volume_green", "data_attach_green")
ORDER = (*BUILD, *WINDOW_STEPS, *AFTER)
RESTORE_ORDER = (*RESTORE_STEPS, "await_discard")
#: Park reason when a transition would leave the outage for the build phase or Discarding (REN-1, by construction).
OUTAGE_SEAL_REASON = "outage_open_build_refused"


def phase_of(key: str, current: str | None = None) -> str:
    if key in BUILD:
        return "build"
    if key in WINDOW_STEPS:
        return "window"
    if key in ("retain_old", "await_retention", "await_retirement"):
        return "retained"
    if key == "retire_old":
        return "retire"
    if key == "discard_green":
        return current or "build"
    return "restore"


def _no_writes(action: str) -> None:
    raise WriteNotAllowedError(f"read-only re-probe refused {action}")


class GuestProbeInProgress(Exception):  # noqa: N818 - a state, read as "guest unknown"
    """An earlier accept-step guest probe of the run is still running (PMR-1): no second one is started."""


def _elapsed(prepared: Mapping[str, Any]) -> float:
    """Seconds since the worker started the accept probe in ``prepare_signal`` (monotonic); infinite without one."""
    t0 = prepared.get("t0")
    return time.monotonic() - float(t0) if isinstance(t0, (int, float)) else float("inf")


class BlueGreenFipV1(WorkflowDefinition):
    kind = KIND
    strategy = STRATEGY
    version = STRATEGY_VERSION

    def __init__(self, deps: Deps) -> None:
        self.d = deps
        classes: list[type[RStep]] = [
            Preflight, ClaimResources, CreateGreen, WaitGreenActive, WaitGreenSsh, PrepareAutomation,
            ConfigureGreen, VerifyCutoverPreconditions, AwaitCutover, VerifyGreenReady,
            QuiesceOld, StopOld, DetachVolume, SnapshotVolume, AttachVolumeGreen, DataAttachGreen,
            StartServiceGreen, HealthcheckGreen, MoveFip, VerifyExternal,
            RetainOld, AwaitRetention, AwaitRetirement, RetireOld,
            UnlockOld, QuiesceGreen, StopGreen, DetachFromGreen, AttachToOld, BootOld, RecoverOldService,
            MoveFipToOld, VerifyExternalOld, LockGreen, AwaitDiscard, DiscardGreen,
        ]  # fmt: skip
        self._steps: dict[str, Step] = {c.key: c(deps) for c in classes}
        # PMR-1: the accept-step guest probe of each run still running in its own thread (one per run at most)
        self._guest_probes: dict[str, threading.Thread] = {}
        self._guest_probes_lock = threading.Lock()

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def concurrency_cap(self) -> int | None:
        return self.d.cfg.max_concurrent_runs

    def spec(self, key: str) -> StepSpec:
        return StepSpec(key, timeout=self.d.cfg.step_timeout(key))

    # ---- admission -------------------------------------------------------------------------------------

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        run = ctx.run
        if not run.renewal_plan_id:
            return Reject("renewal run without a plan")
        try:
            facts = load_facts(ctx.conn, run.renewal_plan_id)
        except LookupError:
            return Reject("renewal plan not found")
        r = facts.resolved
        dv = r.get("data_volume") or {}
        missing = self.d.cfg.missing(snapshot=bool(dv.get("snapshot_before_handoff")))
        if missing:
            return Reject("configuration keys missing: " + ", ".join(missing))
        unavailable = self.d.cloud.unavailable_reason(project_of(r))
        if unavailable:
            return Reject(unavailable)
        if facts.recomputed_hash is None or facts.recomputed_hash != facts.plan["plan_hash"]:
            return Reject(
                "the plan's sources changed since it was created (plan hash differs); create a new plan"
            )
        locks = [
            LockSpec("service", str(r["service"]["id"]), "renewal"),
            LockSpec("server", r["blue"]["server_id"], "blue"),
            LockSpec("floating_ip", r["floating_ip"]["id"], "service fip"),
        ]
        if dv:
            locks.append(LockSpec("volume", dv["volume_id"], "data volume"))
        ctx.conn.execute(
            text("UPDATE renewal_plan SET state = 'started', updated_at = now() WHERE id = :p"),
            {"p": run.renewal_plan_id},
        )
        return Admission(first_step=self.spec("preflight"), locks=locks, phase="build")

    # ---- transitions -----------------------------------------------------------------------------------

    def _following(self, key: str, resolved: Mapping[str, Any]) -> str | None:
        order = RESTORE_ORDER if key in RESTORE_ORDER else ORDER
        i = order.index(key) + 1
        dv = resolved.get("data_volume")
        while i < len(order):
            k = order[i]
            if k in HANDOFF and not dv:
                i += 1
                continue
            if k == "snapshot_volume" and not (dv or {}).get("snapshot_before_handoff"):
                i += 1
                continue
            return k
        return None

    def next(self, ctx: TxContext, done: Done) -> Transition:
        sealed = self._seal(ctx, self._next(ctx, done))
        return sealed if sealed is not None else Transition(park_reason=OUTAGE_SEAL_REASON)

    def _next(self, ctx: TxContext, done: Done) -> Transition:
        c, run = ctx.conn, ctx.run
        key = ctx.step.step_key if ctx.step else ""
        resolved = plan_resolved(c, run.id)
        ev = dict(done.evidence)
        if "truth" in ev:
            _write_truth(c, run.id, ev["truth"])
        if key == "discard_green":
            c.execute(
                text("UPDATE owned_resource SET state = 'deleted', updated_at = now() WHERE run_id = :r AND role = 'green' "
                     "AND state IN ('intended', 'present')"), {"r": run.id})  # fmt: skip
            return Transition(run_state="rolled_back")
        if key == "retire_old":
            _set_role(c, resolved["blue"]["server_id"], "retired")
            return Transition(run_state="completed", phase="retire")
        if key == "wait_green_active":
            c.execute(
                text("UPDATE owned_resource SET detail = detail || CAST(:d AS jsonb), updated_at = now() "
                     "WHERE run_id = :r AND role = 'green' AND state = 'present'"),
                {"r": run.id, "d": json.dumps({k: ev.get(k) for k in ("port_id", "fixed_ip", "subnet_id")})},
            )  # fmt: skip
            return Transition(
                next_step=self.spec("wait_green_ssh"),
                phase="build",
                acquire_locks=[
                    LockSpec("server", ev["green_id"], "green"),
                    LockSpec("port", ev["port_id"], "green"),
                ],
            )
        if key == "quiesce_green":
            # S2 skipped (volume not on an ACTIVE green) opened nothing before: the service stops at S3 at the latest.
            downtime.open_interval(c, run.id, kind=downtime.RESTORE, step_key=key)
        if key == "verify_external":
            self._cutover_commit(c, run, resolved, ev)
        if key == "verify_external_old":
            _end_downtime(c, run.id)
            downtime.close_open(c, run.id, step_key=key)
            if (
                _role(c, resolved["blue"]["server_id"]) == "retained"
            ):  # revert after cutover: blue current again
                g = green_row(c, run.id)
                if g is not None and g["openstack_id"]:
                    _set_role(c, g["openstack_id"], "candidate")
                _set_role(c, resolved["blue"]["server_id"], "current")
        nxt = self._following(key, resolved)
        if nxt is None:  # unreachable: every order ends with a gate or a terminal step
            return Transition(park_reason="no_next_step")
        return Transition(next_step=self.spec(nxt), phase=phase_of(nxt, run.phase))

    def _cutover_commit(
        self, c: Connection, run: RunView, resolved: Mapping[str, Any], ev: Mapping[str, Any]
    ) -> None:
        """W10 success, one transaction: ``downtime_ended_at``, the window interval closed, roles (green current, blue
        retained), audit."""
        _end_downtime(c, run.id)
        downtime.close_open(c, run.id, step_key="verify_external")
        g = green_row(c, run.id)
        if g is None or not g["openstack_id"]:
            raise RuntimeError("cutover without a green in the ledger")
        _set_role(c, resolved["blue"]["server_id"], "retained")
        _register_green(c, run.id, resolved, g["openstack_id"], ev.get("green_observed") or {})
        with Session(bind=c) as s:
            audit.record(
                s, action="renewal.cutover", target_type="renewal_run", target_id=run.id, principal_type="system",
                auth_method="none", run_id=UUID(run.id), after={"outcome": "green current", "reason": "W10 ok"},
            )  # fmt: skip

    # ---- failures --------------------------------------------------------------------------------------

    def on_failure(self, ctx: TxContext, fail: Fail) -> Transition | None:
        return self._seal(ctx, self._on_failure(ctx, fail))

    def _on_failure(self, ctx: TxContext, fail: Fail) -> Transition | None:
        c, run = ctx.conn, ctx.run
        key = ctx.step.step_key if ctx.step else ""
        detail = dict(fail.detail)
        truth = detail.get("truth") or (detail.get("waited_evidence") or {}).get("truth")
        if truth:
            _write_truth(c, run.id, truth)
        reason = fail.needs_human_reason or fail.reason
        if key in ("preflight", "claim_resources") and fail.error_class == ErrorClass.FATAL:
            return None  # run failed: nothing was created
        if key == "quiesce_old" and fail.reason == "w1_claim_refused":
            if _outage_started(c, run.id):
                # REN-1: a refused claim after the outage started is a failure inside the window, never a way back
                # to the build phase (blue may be quiesced). W1's re-claim probe does not refuse; this is the belt.
                return Transition(park_reason="w1_reclaim_refused", phase="window")
            back = detail.get("back_to") or "await_cutover"
            return Transition(next_step=self.spec(back), phase="build")
        if key in BUILD:
            return Transition(
                park_reason=reason if fail.error_class != ErrorClass.FATAL else "build_failed"
            )
        if key in WINDOW_STEPS:
            return self._window_failure(ctx, key, fail, reason, truth)
        return Transition(park_reason=reason)

    def _window_failure(
        self, ctx: TxContext, key: str, fail: Fail, reason: str, truth: Mapping[str, Any] | None
    ) -> Transition:
        c, run = ctx.conn, ctx.run
        if reason == "deadline_exceeded" and not truth:
            # REN-3: the deadline passed with no fresh probe attached (right after act, or before acting). The API
            # was not shown unreachable, so this is not ``api_unreachable`` (no self-resolution, no automatic
            # restore): park with the true reason; the operator's probe/retry decide from a fresh read.
            return Transition(park_reason="deadline_exceeded")
        resolved = plan_resolved(c, run.id)
        g = green_row(c, run.id)
        flags = c.execute(
            text("SELECT auto_restore_used FROM workflow_run WHERE id = :r"), {"r": run.id}
        ).one()
        decision = closed_table.decide(
            key,
            reason=reason,
            trigger=fail.detail.get("trigger"),
            truth=truth,
            blue_id=resolved["blue"]["server_id"],
            green_id=g["openstack_id"] if g is not None else None,
            stateless=bool(resolved.get("stateless")),
            auto_restore=bool(resolved.get("auto_restore_in_window")),
            already_used=bool(flags[0]),
            snapshot_available=_snapshot_available(c, run.id, ctx),
        )
        if decision.restore:
            if key == "snapshot_volume":
                _orphan_snapshot(c, run.id, decision.reason)
            return self._restore(
                c, run, trigger=decision.reason, step_key=key, fail=fail, truth=truth, auto=True
            )
        if decision.post_start:
            metrics.POST_START_FAILURES.inc()
        park = decision.reason
        if (
            park in ("ambiguous_state", "auto_restore_disabled", "auto_restore_already_used")
            and reason
        ):
            park = reason if reason not in ("deadline_exceeded", "retries_exhausted") else park
        return Transition(park_reason=park)

    def _restore(
        self,
        c: Connection,
        run: RunView,
        *,
        trigger: str,
        step_key: str,
        fail: Fail | None,
        truth: Mapping[str, Any] | None,
        auto: bool,
        actor: str | None = None,
    ) -> Transition:
        g2 = c.execute(
            text("SELECT id FROM approval WHERE subject_type = 'cutover' AND subject_id = :r AND decision = 'approved' "
                 "ORDER BY decided_at DESC LIMIT 1"), {"r": run.id}).scalar()  # fmt: skip
        if auto:
            c.execute(
                text("UPDATE workflow_run SET auto_restore_used = true WHERE id = :r"),
                {"r": run.id},
            )
            metrics.AUTO_RESTORE.labels(trigger).inc()
        snap = snapshot_row(c, run.id)
        with Session(bind=c) as s:
            audit.record(
                s, action="restore.auto" if auto else "restore.operator", target_type="renewal_run", target_id=run.id,
                principal_type="system" if auto else "human", auth_method="none" if auto else INTERACTIVE_AUTH,
                actor_id=UUID(actor) if actor else None, run_id=UUID(run.id),
                authority_ref=str(g2) if (auto and g2) else None,
                after={"trigger": trigger, "step_key": step_key, "reason": fail.reason if fail else None,
                       "error_class": fail.error_class.value if fail else None,
                       "snapshot_id": snap["openstack_id"] if snap is not None else None, "truth": truth},
            )  # fmt: skip
        return Transition(next_step=self.spec("unlock_old"), phase="restore")

    # ---- abort -----------------------------------------------------------------------------------------

    def on_abort(self, ctx: TxContext, outcome: Outcome | None) -> Transition | None:
        return self._seal(ctx, self._on_abort(ctx, outcome))

    def _on_abort(self, ctx: TxContext, outcome: Outcome | None) -> Transition | None:
        key = ctx.step.step_key if ctx.step else ""
        in_outage = _outage_open(ctx.conn, ctx.run.id)
        if key in BUILD and not in_outage:
            return Transition(next_step=self.spec("discard_green"), phase="build")
        if key in BUILD or (in_outage and key == "discard_green"):
            # REN-1 belt: a build step with the outage open (a run left there by an older version): restore blue.
            return self._restore(ctx.conn, ctx.run, trigger="abort", step_key=key, fail=None, truth=None,
                                 auto=False, actor=_abort_actor(ctx.conn, ctx.run.id))  # fmt: skip
        if key in WINDOW_STEPS:
            state = ctx.step.state if ctx.step else ""
            if outcome is None and state != "needs_human":
                return None  # a waiting window step finishes first; restore at its boundary
            if outcome is not None and not isinstance(outcome, (Done, Fail)):
                return None
            if key == "verify_external" and isinstance(outcome, Done):
                return None  # cutover completed: abort no longer applies (use revert)
            fail = outcome if isinstance(outcome, Fail) else None
            return self._restore(ctx.conn, ctx.run, trigger="abort", step_key=key, fail=fail, truth=None, auto=False,
                                 actor=_abort_actor(ctx.conn, ctx.run.id))  # fmt: skip
        return None

    # ---- signals ---------------------------------------------------------------------------------------

    def validate_signal(self, ctx: TxContext) -> str | None:
        sig, run, c = ctx.signal, ctx.run, ctx.conn
        if sig is None:
            return "no signal"
        step = ctx.step.step_key if ctx.step else None
        if sig.kind == "admit":
            return "admit is not used by this strategy"
        if sig.kind == "approve":
            return None if sig.actor_id else "approval wake-up without an actor"
        if sig.kind == "probe" and sig.actor_id is None:
            return (
                None
                if sig.payload.get("auto") == "api_unreachable"
                else "system probe without a reason"
            )
        if sig.actor_id is None:
            return "a human actor is required"
        resolved = plan_resolved(c, run.id)
        scope = resolved["scope"]
        now = datetime.now(UTC)
        with Session(bind=c) as s:
            operator = role_held_at(s, UUID(sig.actor_id), "operator", scope, now)
            approver = role_held_at(s, UUID(sig.actor_id), "approver", scope, now)
        if sig.kind == "reprepare_automation":
            return self._validate_reprepare(ctx, resolved, approver)
        if sig.kind == "accept_step":
            return self._validate_accept(ctx, resolved, approver)
        # probe is read-only: an approver may refresh the probe an accept-step decision rests on (ADR-0008).
        if not operator and not (sig.kind in ("mark_resolved", "probe") and approver):
            return "the actor does not hold the operator role in this scope"
        if sig.kind == "probe":
            return None
        phase = effective_phase(run.phase, *outage_marks(c, run.id))
        if sig.kind == "abort" and (
            phase in ("restore", "retained", "retire") or step == "discard_green"
        ):
            return "abort is not available in this phase (use revert after cutover; restore cannot be aborted)"
        if sig.kind == "rollback" and (
            phase in ("restore", "retained", "retire") or step == "discard_green"
        ):
            return "rollback is not available in this phase (use revert after cutover)"
        if sig.kind == "revert" and phase not in ("retained", "retire"):
            return "revert is only available after the cutover"
        if sig.kind == "revert" and _retire_intent(c, run.id):
            # REN-4: X1 persisted its unlock + delete intent; blue may be gone. A restore would park on a deleted
            # blue with no terminal path. retry-step lets X1 finish (its probe sees the 404 and completes).
            return "revert impossible: X1 has sent (or may have sent) the delete of the old VM"
        if sig.kind == "discard" and step != "await_discard":
            return "discard is only available once the service is restored to the old VM"
        destructive_retry = (
            sig.kind == "retry_step" and ctx.step is not None and ctx.step.destructive
        )
        if sig.kind in ("retry_step",) and not destructive_retry:
            return None
        if sig.kind == "mark_resolved":
            # REN-5: the engine re-queues the *current* step, so its own act is the next destructive call; the
            # following step matters too (the current one may reach Done from its probe alone).
            nxt = (
                self._following(step, resolved)
                if step and step in (*ORDER, *RESTORE_ORDER)
                else None
            )
            current_destructive = ctx.step is not None and (
                bool(ctx.step.destructive)
                or getattr(self._steps.get(step or ""), "destructive", False)
            )
            next_destructive = nxt is not None and getattr(self._steps[nxt], "destructive", False)
            if (current_destructive or next_destructive) and not approver:
                return (
                    "the current or next step is destructive: mark-resolved needs the approver role"
                )
        target = tc_target(c, run.id, sig.kind, phase, resolved)
        return _check_confirmation(c, sig, run.id, target)

    def _validate_reprepare(
        self, ctx: TxContext, resolved: Mapping[str, Any], approver: bool
    ) -> str | None:
        """``reprepare_automation`` (the exit of :mod:`ovlm.renewal.reprepare`): an approver who is not the run's
        requester (run starter, plan creator), a parked step whose refusal is the lost or unverifiable checkout, no
        authorization already pending, and the step-up + typed confirmation of the affected VM."""
        sig, run, c, step = ctx.signal, ctx.run, ctx.conn, ctx.step
        assert sig is not None  # noqa: S101 - checked by the caller
        if not approver:
            return "reprepare-automation needs the approver role"
        creator = c.execute(
            text("SELECT created_by FROM renewal_plan WHERE id = :p"), {"p": run.renewal_plan_id}
        ).scalar()
        if sig.actor_id in {run.started_by, str(creator) if creator else None}:
            return "separation of duties: the run's requester cannot authorize a re-clone"
        if run.state != "needs_human" or step is None or step.state != "needs_human":
            return "no step in needs_human"
        error = c.execute(
            text("SELECT error FROM workflow_step WHERE id = :i"), {"i": step.id}
        ).scalar()
        if not reprepare.applies_to(error):
            return "the parked step is not stopped on a lost or unverifiable automation checkout"
        if reprepare.pending(c, run.id):
            return "a re-clone is already authorized for this run"
        if not str((resolved.get("automation") or {}).get("sha") or ""):
            return "the plan pins no automation commit"
        phase = effective_phase(run.phase, *outage_marks(c, run.id))
        return _check_confirmation(c, sig, run.id, tc_target(c, run.id, sig.kind, phase, resolved))

    def _validate_accept(
        self, ctx: TxContext, resolved: Mapping[str, Any], approver: bool
    ) -> str | None:
        """``accept_step`` (ADR-0008, :mod:`ovlm.renewal.accept`). Every refusal is also a ``step_acceptance`` row
        (``refused``, with its code) and an audit row ``run.accept_step.refused``, in this transaction."""
        refusal = self._accept_refusal(ctx, resolved, approver)
        if refusal is None:
            return None
        code, why = refusal
        sig, run, step = ctx.signal, ctx.run, ctx.step
        assert sig is not None and sig.actor_id is not None  # noqa: S101 - checked by the caller
        error = self._step_error(ctx.conn, step.id) if step is not None else None
        prepared = ctx.prepared if isinstance(ctx.prepared, Mapping) else {}
        accept.record(
            ctx.conn, outcome="refused", run_id=run.id, signal_id=sig.id, approver_id=sig.actor_id,
            step_id=step.id if step else None, step_key=step.step_key if step else None,
            attempt=step.attempt if step else None, attestation=str(sig.payload.get("attestation") or ""),
            pinned_sha=str((resolved.get("automation") or {}).get("sha") or "") or None,
            parked_reason=(error or {}).get("reason"), refused_sha256=accept.refused_result_sha256(error) if error else None,
            probe=prepared.get("probe"), probe_id=str(sig.payload.get("probe_id") or "") or None,
            probe_elapsed=_elapsed(prepared), refusal_code=code, refusal=why,
        )  # fmt: skip
        return f"{code}: {why}"

    def _accept_refusal(
        self, ctx: TxContext, resolved: Mapping[str, Any], approver: bool
    ) -> tuple[str, str] | None:
        sig, run, c, step = ctx.signal, ctx.run, ctx.conn, ctx.step
        assert sig is not None  # noqa: S101 - checked by the caller
        if not approver:
            return accept.FORBIDDEN, "accept-step needs the approver role"
        creator = c.execute(
            text("SELECT created_by FROM renewal_plan WHERE id = :p"), {"p": run.renewal_plan_id}
        ).scalar()
        if sig.actor_id in {run.started_by, str(creator) if creator else None}:
            return accept.SOD, "separation of duties: the run's requester cannot accept a step"
        error = self._step_error(c, step.id) if step is not None else None
        phase = effective_phase(run.phase, *outage_marks(c, run.id))
        why = accept.not_applicable(
            run_state=run.state, step_key=step.step_key if step else None,
            step_state=step.state if step else None, phase=phase, error=error,
        )  # fmt: skip
        if why is not None:
            return accept.NOT_APPLICABLE, why
        assert step is not None  # noqa: S101 - not_applicable refuses without a parked step
        if (
            str(sig.payload.get("step_id") or "") != step.id
            or sig.payload.get("attempt") != step.attempt
        ):
            # compare-and-set on (needs_human, attempt): the request was made against another attempt
            return (
                accept.NOT_APPLICABLE,
                "the parked step changed since the request (another attempt ran)",
            )
        if accept.already_accepted(c, run.id, step.step_key):
            return accept.ALREADY, f"{step.step_key} was already accepted once in this run"
        if (problem := accept.attestation_problem(sig.payload.get("attestation"))) is not None:
            return accept.ATTESTATION, problem
        tc = _check_confirmation(c, sig, run.id, tc_target(c, run.id, sig.kind, phase, resolved))
        if tc is not None:
            return (accept.CONFIRMATION if "typed confirmation" in tc else accept.STEPUP), tc
        # The probe the approver saw: the latest one stored for this step and attempt, fresh, meeting the
        # postcondition; then the worker's own probe, taken just before this transaction, must agree with it.
        truth = c.execute(
            text("SELECT current_truth FROM workflow_run WHERE id = :r"), {"r": run.id}
        ).scalar()
        shown = accept.shown_probe(truth)
        if shown is None or str(shown.get("id")) != str(sig.payload.get("probe_id") or ""):
            return (
                accept.PROBE_MISMATCH,
                "the probe shown to the approver is not the run's latest probe",
            )
        if shown.get("step_id") != step.id or shown.get("attempt") != step.attempt:
            return (
                accept.PROBE_MISMATCH,
                "the probe shown to the approver was taken for another step or attempt",
            )
        age = accept.probe_age(shown, now_db(c))
        if age is None or age > accept.FRESH_SECONDS:
            return (
                accept.PROBE_STALE,
                f"the probe is older than {int(accept.FRESH_SECONDS)} s: probe again",
            )
        if not shown.get("ok"):
            return accept.POSTCONDITION, "; ".join(accept.failing(shown))
        prepared = ctx.prepared if isinstance(ctx.prepared, Mapping) else {}
        fresh = prepared.get("probe")
        if not isinstance(fresh, Mapping) or _elapsed(prepared) > accept.FRESH_SECONDS:
            return (
                accept.PROBE_STALE,
                "the worker's own probe is missing or older than the freshness limit",
            )
        if not fresh.get("ok"):
            return accept.POSTCONDITION, "; ".join(accept.failing(fresh))
        if accept.facts(fresh) != accept.facts(shown):
            return (
                accept.PROBE_MISMATCH,
                "the state changed since the probe shown to the approver: probe again",
            )
        return None

    @staticmethod
    def _step_error(c: Connection, step_id: str) -> Mapping[str, Any] | None:
        error: Mapping[str, Any] | None = c.execute(
            text("SELECT error FROM workflow_step WHERE id = :i"), {"i": step_id}
        ).scalar()
        return error

    def accept_probe(self, run_id: str) -> dict[str, Any] | None:
        """OVLM's own read-only probe of S2's postcondition (ADR-0008), for the run's parked step when accept-step
        may apply to it; ``None`` otherwise. Cloud: read calls through a client whose gate refuses every write.
        Guest: the fixed OVLM command list on green (never repository code). Network I/O: call it outside any
        transaction (``prepare_signal``)."""
        with self.d.db.connect() as c:
            row = c.execute(
                text("SELECT r.state AS run_state, r.phase, r.downtime_started_at, r.downtime_ended_at, s.id, "
                     "s.step_key, s.state, s.attempt, s.error FROM workflow_run r JOIN workflow_step s "
                     "ON s.run_id = r.id AND s.state = 'needs_human' WHERE r.id = :r"), {"r": run_id},
            ).mappings().first()  # fmt: skip
            if row is None:
                return None
            phase = effective_phase(
                row["phase"], row["downtime_started_at"], row["downtime_ended_at"]
            )
            if accept.not_applicable(run_state=row["run_state"], step_key=row["step_key"], step_state=row["state"],
                                     phase=phase, error=row["error"]) is not None:  # fmt: skip
                return None
            resolved = plan_resolved(c, run_id)
            g = green_row(c, run_id)
        dv = resolved.get("data_volume") or {}
        units = tuple(resolved.get("service_units") or ())
        green_id = (
            g["openstack_id"] if g is not None and g["state"] in ("intended", "present") else None
        )
        try:
            client = self.d.cloud.write_client(
                DbOwnershipRegistry(self.d.db, run_id), _no_writes, project=project_of(resolved)
            )
            truth = read_truth(client, resolved, g)
            cloud = {
                "api_reachable": True,
                "green": truth.get("green"),
                "volume": truth.get("volume"),
            }
        except Exception as exc:  # noqa: BLE001 - an unreachable API is a failed check
            cloud = {"api_reachable": False, "error": type(exc).__name__}
        guest: dict[str, Any] = {"reachable": False, "mount_point": dv.get("mount_point")}
        if green_id is not None and g is not None and dv:
            det = g["detail"] or {}
            ref = GuestRef(
                green_id, det.get("fixed_ip") or "", "new", tuple(det.get("pinned") or ())
            )
            try:
                gp = self._bounded_guest_probe(run_id, ref, mount_point=dv.get("mount_point"), units=units,
                                               data_volume_id=dv.get("volume_id"))  # fmt: skip
                guest |= {
                    "reachable": gp.reachable, "mount_point_mounted": gp.mounted,
                    "device": "/dev/disk/by-id/virtio-" + str(dv.get("volume_id"))[:20],
                    "device_mounted": gp.device_mounted, "device_mountpoints": list(gp.device_mountpoints),
                    "unit_states": dict(gp.unit_states) if gp.unit_states is not None else None,
                }  # fmt: skip
            except Exception as exc:  # noqa: BLE001 - an unreachable guest is a failed check
                guest["error"] = type(exc).__name__
        checks = accept.evaluate(cloud=cloud, guest=guest, green_id=green_id, units=units)
        return {
            "id": new_id(), "step_id": str(row["id"]), "step_key": row["step_key"], "attempt": row["attempt"],
            "green_id": green_id, "volume_id": dv.get("volume_id"), "cloud": cloud, "guest": guest,
            "checks": checks, "ok": all(x["ok"] for x in checks),
        }  # fmt: skip

    def _bounded_guest_probe(
        self, run_id: str, ref: GuestRef, *, mount_point: str | None, units: tuple[str, ...],
        data_volume_id: str | None,
    ) -> GuestProbe:  # fmt: skip
        """The guest probe of :meth:`accept_probe` under a total deadline (``renewal.accept_probe_timeout``, review
        PMR-1). It runs on its own thread; the caller (the worker's main loop, through ``prepare_signal``) waits at
        most the budget, so a green that answers TCP but hangs a command cannot hold other runs' signals and claims
        behind it. The port also gets the budget, so its SSH commands end soon after. While a probe of the run is
        still running (it overran the budget), no second one is started: the new request reads
        :class:`GuestProbeInProgress` at once (a failed check), so queued Re-probe clicks do not pile up."""
        budget = float(self.d.cfg.accept_probe_timeout)
        box: dict[str, Any] = {}

        def work() -> None:
            try:
                box["result"] = self.d.guest.probe(run_id, ref, mount_point=mount_point, units=units,
                                                   data_volume_id=data_volume_id, timeout=budget)  # fmt: skip
            except BaseException as exc:  # noqa: BLE001 - handed to the waiting caller
                box["error"] = exc
            finally:
                with self._guest_probes_lock:
                    if self._guest_probes.get(run_id) is threading.current_thread():
                        del self._guest_probes[run_id]

        with self._guest_probes_lock:
            running = self._guest_probes.get(run_id)
            if running is not None and running.is_alive():
                raise GuestProbeInProgress("a guest probe of this run is still running")
            thread = threading.Thread(target=work, name=f"accept-probe-{run_id[:8]}", daemon=True)
            self._guest_probes[run_id] = thread
            thread.start()
        thread.join(budget)
        if thread.is_alive():
            log.warning(
                "accept probe: green did not answer within %g s", budget, extra={"run_id": run_id}
            )
            raise GuestProbeTimeout(f"the guest probe did not finish within {budget:g} s")
        if "error" in box:
            raise box["error"]
        result: GuestProbe = box["result"]
        return result

    def prepare_signal(self, run: RunView, signal: SignalView) -> Any:
        if signal.kind == "accept_step":
            t0 = time.monotonic()
            return {"probe": self.accept_probe(run.id), "t0": t0}
        if signal.kind != "probe":
            return None
        try:
            with self.d.db.connect() as c:
                resolved = plan_resolved(c, run.id)
                g = green_row(c, run.id)
            client = self.d.cloud.write_client(
                DbOwnershipRegistry(self.d.db, run.id), _no_writes, project=project_of(resolved)
            )
            truth = read_truth(client, resolved, g)
        except Exception as exc:  # noqa: BLE001 - an unreachable API is the result
            return {"api_reachable": False, "error": type(exc).__name__}
        try:
            probe = self.accept_probe(run.id)
        except Exception as exc:  # noqa: BLE001 - the panel still refreshes; no accept probe
            log.warning("accept probe failed: %s", type(exc).__name__)
            probe = None
        if probe is not None:
            truth[accept.TRUTH_KEY] = probe
        return truth

    def on_signal(self, ctx: TxContext) -> Transition | Wake | AcceptStep | str | None:
        res = self._on_signal(ctx)
        return self._seal(ctx, res) if isinstance(res, Transition) else res

    def _on_signal(self, ctx: TxContext) -> Transition | Wake | AcceptStep | str | None:
        sig, run, c = ctx.signal, ctx.run, ctx.conn
        if sig is None:
            return None
        step = ctx.step
        key = step.step_key if step else ""
        if sig.kind == "approve":
            if (
                step is not None
                and key in ("await_cutover", "await_retirement")
                and step.state == "waiting"
            ):
                return Wake()
            return "ignored: no gate is waiting"
        if sig.kind == "probe":
            truth = dict(ctx.prepared or {"api_reachable": False})
            if isinstance(truth.get(accept.TRUTH_KEY), Mapping):
                # stored with the DB time: the approver's form and the worker judge its age on the same clock
                truth[accept.TRUTH_KEY] = {**truth[accept.TRUTH_KEY], "at": now_db(c).isoformat()}
            _write_truth(c, run.id, truth)
            if sig.actor_id is None:
                return self._self_resolve(ctx, truth)
            return "current truth refreshed"
        if sig.kind == "reprepare_automation":
            if step is None:
                return "refused: no parked step"
            sha = str(plan_resolved(c, run.id)["automation"]["sha"])
            aid = reprepare.authorize(c, run_id=run.id, signal_id=sig.id, step_id=step.id, step_key=key,
                                      sha=sha, approver_id=str(sig.actor_id))  # fmt: skip
            return f"re-clone of {sha} authorized once ({aid})"
        if sig.kind == "accept_step":
            return self._accept(ctx)
        if sig.kind == "discard":
            return Transition(next_step=self.spec("discard_green"), phase="restore")
        if sig.kind == "rollback":
            # REN-1: judged on the effective phase: with the outage open, rollback always restores blue.
            if effective_phase(run.phase, *outage_marks(c, run.id)) == "build":
                return Transition(next_step=self.spec("discard_green"), phase="build")
            return self._restore(c, run, trigger="rollback", step_key=key, fail=None, truth=None, auto=False,
                                 actor=sig.actor_id)  # fmt: skip
        if sig.kind == "revert":
            return self._restore(c, run, trigger="revert", step_key=key, fail=None, truth=None, auto=False,
                                 actor=sig.actor_id)  # fmt: skip
        return None

    def _accept(self, ctx: TxContext) -> AcceptStep | str:
        """``accept_step`` validated (:meth:`_validate_accept`): record the acceptance, then close the parked step as
        if it had reached Done without running its playbook. The transition is :meth:`next`'s for that step, so S2
        accepted counts as S2 done for the downtime interval it opens (P0-3) and for the REN-1 seal."""
        sig, run, c, step = ctx.signal, ctx.run, ctx.conn, ctx.step
        assert sig is not None and sig.actor_id is not None  # noqa: S101 - validated
        if step is None:
            return "refused: no parked step"
        resolved = plan_resolved(c, run.id)
        error = self._step_error(c, step.id)
        prepared = ctx.prepared if isinstance(ctx.prepared, Mapping) else {}
        probe = dict(prepared.get("probe") or {})
        sha = str((resolved.get("automation") or {}).get("sha") or "") or None
        refused = accept.refused_result_sha256(error)
        attestation = str(sig.payload.get("attestation") or "").strip()
        aid = accept.record(
            c, outcome="accepted", run_id=run.id, signal_id=sig.id, approver_id=sig.actor_id, step_id=step.id,
            step_key=step.step_key, attempt=step.attempt, attestation=attestation, pinned_sha=sha,
            parked_reason=(error or {}).get("reason"), refused_sha256=refused, probe=probe,
            probe_id=str(sig.payload.get("probe_id")), probe_elapsed=_elapsed(prepared),
        )  # fmt: skip
        metrics.STEP_ACCEPTED.labels(step.step_key).inc()
        at = now_db(c).isoformat()
        accepted = {
            "by": sig.actor_id, "at": at, "signal_id": sig.id, "acceptance_id": aid, "attestation": attestation,
            "attestation_ref": f"step_acceptance:{aid}", "probe_id": str(sig.payload.get("probe_id")),
            "probe": probe, "playbook_not_run": True, "refused_result_sha256": refused,
        }  # fmt: skip
        evidence: dict[str, Any] = {
            "resolution": "accepted",
            "playbook_not_run": True,
            "accepted": accepted,
        }
        if step.step_key == "quiesce_green":
            evidence["marker_comparison"] = "skipped: step accepted, playbook not run"
        return AcceptStep(
            transition=self.next(ctx, Done(evidence)), evidence=evidence, attempt=step.attempt
        )

    # ---- REN-1: the outage seal -------------------------------------------------------------------------

    def _seal(self, ctx: TxContext, t: Transition | None) -> Transition | None:
        """Make "back to build with the outage open" impossible by construction (REN-1). While
        ``downtime_started_at`` is set and ``downtime_ended_at`` is not, blue may be quiesced: a transition to a
        build step, to Discarding, to phase ``build``, or to a terminal state would discard the only way back (or
        drop the locks under an open outage). Such a transition is replaced by needs_human in phase ``window``,
        where rollback/abort restore blue (S1-S10)."""
        if t is None or not _outage_open(ctx.conn, ctx.run.id):
            return t
        target = t.next_step.step_key if t.next_step is not None else None
        if (
            target in BUILD
            or target == "discard_green"
            or t.phase == "build"
            or t.run_state is not None
        ):
            log.error("refused a transition out of the open outage: run=%s step=%s to=%s phase=%s state=%s",
                      ctx.run.id, ctx.step.step_key if ctx.step else None, target, t.phase, t.run_state)  # fmt: skip
            return Transition(park_reason=OUTAGE_SEAL_REASON, phase="window")
        return t

    # ---- section 5.1: self-resolution of api_unreachable ------------------------------------------------

    def _self_resolve(self, ctx: TxContext, truth: Mapping[str, Any]) -> Transition | str:
        c, run, step = ctx.conn, ctx.run, ctx.step
        if (
            run.state != "needs_human"
            or run.needs_human_reason != "api_unreachable"
            or step is None
        ):
            return "no api_unreachable run to resolve"
        if not truth.get("api_reachable"):
            return "api still unreachable"
        row = c.execute(
            text("SELECT EXTRACT(EPOCH FROM now() - downtime_started_at), current_truth, auto_restore_used "
                 "FROM workflow_run WHERE id = :r"), {"r": run.id}).one()  # fmt: skip
        resolved = plan_resolved(c, run.id)
        elapsed, last_truth, used = row
        if (
            run.phase != "window"
            or elapsed is None
            or float(elapsed) > float(resolved["max_window_duration_seconds"])
        ):
            return self._resume_audit(
                c, run, "rule 0: outside the window or past the budget; stays needs_human"
            )
        g = green_row(c, run.id)
        gid = g["openstack_id"] if g is not None else None
        if step.step_key not in ("move_fip", "verify_external") and _expected(
            step.step_key, truth, resolved, gid
        ):
            nxt = self._following(step.step_key, resolved)
            if nxt is not None:
                self._resume_audit(
                    c, run, f"rule 1: {step.step_key} landed; continue forward", truth
                )
                return Transition(next_step=self.spec(nxt), phase="window")
        if last_truth and _same_state(last_truth, truth):
            decision = closed_table.decide(
                step.step_key, reason="api_unreachable_resolved", trigger=None, truth=truth,
                blue_id=resolved["blue"]["server_id"], green_id=gid, stateless=bool(resolved.get("stateless")),
                auto_restore=bool(resolved.get("auto_restore_in_window")), already_used=bool(used),
                snapshot_available=_snapshot_available(c, run.id, ctx),
            )  # fmt: skip
            if decision.restore:
                self._resume_audit(c, run, "rule 2: unchanged state matches a restore row", truth)
                return self._restore(c, run, trigger="api_unreachable", step_key=step.step_key, fail=None,
                                     truth=truth, auto=True)  # fmt: skip
        return self._resume_audit(c, run, "rule 3: state differs; stays needs_human", truth)

    def _resume_audit(self, c: Connection, run: RunView, rule: str, truth: Any = None) -> str:
        with Session(bind=c) as s:
            audit.record(
                s, action="resume.auto", target_type="renewal_run", target_id=run.id, principal_type="system",
                auth_method="none", run_id=UUID(run.id), after={"rule": rule, "truth": truth},
            )  # fmt: skip
        return rule


# --- helpers ---------------------------------------------------------------------------------------------------


def _write_truth(c: Connection, run_id: str, truth: Mapping[str, Any]) -> None:
    """The current-truth panel. A W4 snapshot of the run is named in it (renewal-workflow.md 4: "the snapshot id is
    recorded in current_truth"), with its ledger state (``present``; ``orphan`` when W4 failed)."""
    out = dict(truth)
    snap = snapshot_row(c, run_id)
    if snap is not None and snap["openstack_id"]:
        out["snapshot"] = {"id": snap["openstack_id"], "ledger_state": snap["state"]}
    c.execute(
        text(
            "UPDATE workflow_run SET current_truth = CAST(:t AS jsonb), current_truth_at = now() WHERE id = :r"
        ),
        {"r": run_id, "t": json.dumps(out, default=str)},
    )


def _outage_started(c: Connection, run_id: str) -> bool:
    return outage_marks(c, run_id)[0] is not None


def _outage_open(c: Connection, run_id: str) -> bool:
    started, ended = outage_marks(c, run_id)
    return started is not None and ended is None


def _retire_intent(c: Connection, run_id: str) -> bool:
    """X1 persisted an intent (unlock + delete of blue decided; it may have been sent)."""
    return (
        c.execute(
            text(
                "SELECT 1 FROM workflow_step WHERE run_id = :r AND step_key = 'retire_old' AND intent IS NOT NULL "
                "LIMIT 1"
            ),
            {"r": run_id},
        ).first()  # fmt: skip
        is not None
    )


def _end_downtime(c: Connection, run_id: str) -> None:
    """End the run's **first** interval on the run row (kept for the budget, the REN-1 seal and the retention timer;
    the full record is ``run_downtime``, :mod:`ovlm.renewal.downtime`)."""
    c.execute(
        text(
            "UPDATE workflow_run SET downtime_ended_at = COALESCE(downtime_ended_at, now()) WHERE id = :r"
        ),
        {"r": run_id},
    )


def _role(c: Connection, server_id: str) -> str | None:
    return c.execute(
        text("SELECT role FROM managed_vm WHERE openstack_server_id = :s"), {"s": server_id}
    ).scalar()


def _set_role(c: Connection, server_id: str, role: str) -> None:
    c.execute(
        text(
            "UPDATE managed_vm SET role = :role, updated_at = now() WHERE openstack_server_id = :s"
        ),
        {"s": server_id, "role": role},
    )


def _register_green(
    c: Connection,
    run_id: str,
    resolved: Mapping[str, Any],
    green_id: str,
    observed: Mapping[str, Any],
) -> None:
    """Green becomes the service's ``current`` managed VM (data-model.md 4). ``managed_vm`` needs an
    ``observed_server`` row: if the inventory has not seen green yet, the worker records what W10 read, under a
    ``sync_run`` marked ``failed`` with ``error.source = renewal_registration`` so it never counts as a sync baseline
    (reported deviation: the inventory module owns these tables)."""
    pc = resolved["service"]["project_connection_id"]
    obs_id = c.execute(
        text(
            "SELECT id FROM observed_server WHERE project_connection_id = :pc AND openstack_id = :g"
        ),
        {"pc": pc, "g": green_id},
    ).scalar()
    if obs_id is None:
        from ovlm.workflow.ids import new_id

        sync_id, obs_id = new_id(), new_id()
        c.execute(
            text("INSERT INTO sync_run (id, project_connection_id, kind, status, started_at, finished_at, error, "
                 "workflow_run_id) VALUES (:id, :pc, 'servers_delta', 'failed', now(), now(), "
                 "CAST(:e AS jsonb), :run)"),
            {"id": sync_id, "pc": pc, "run": run_id,
             "e": json.dumps({"source": "renewal_registration", "note": "not an inventory sync"})},
        )  # fmt: skip
        payload = observed.get("payload") or {"openstack_id": green_id}
        c.execute(
            text("INSERT INTO observed_server (id, project_connection_id, openstack_id, name, server_status, "
                 "image_id, availability_zone, tags, payload, payload_hash, first_seen_sync_id, last_seen_sync_id, "
                 "status, synced_at) VALUES (:id, :pc, :g, :n, :st, :img, :az, CAST(:tags AS text[]), "
                 "CAST(:p AS jsonb), :h, :s, :s, 'present', now())"),
            {"id": obs_id, "pc": pc, "g": green_id, "n": observed.get("name"), "st": observed.get("status", "ACTIVE"),
             "img": resolved["image"]["id"], "az": resolved.get("availability_zone"),
             "tags": "{" + ",".join(f'"{t}"' for t in observed.get("tags", [])) + "}",
             "p": json.dumps(payload, default=str), "h": observed.get("payload_hash") or "0" * 64, "s": sync_id},
        )  # fmt: skip
    from ovlm.workflow.ids import new_id as _nid

    c.execute(
        text("INSERT INTO managed_vm (id, service_id, observed_server_id, openstack_server_id, role, registered_at) "
             "VALUES (:id, :svc, :obs, :g, 'current', now()) "
             "ON CONFLICT (openstack_server_id) DO UPDATE SET role = 'current', updated_at = now()"),
        {"id": _nid(), "svc": resolved["service"]["id"], "obs": obs_id, "g": green_id},
    )  # fmt: skip


def _snapshot_available(c: Connection, run_id: str, ctx: TxContext) -> bool:
    """A snapshot of this run reached ``available`` in W4 (step succeeded, ledger present)."""
    snap = snapshot_row(c, run_id)
    if snap is None or snap["state"] != "present":
        return False
    ok = c.execute(
        text(
            "SELECT 1 FROM workflow_step WHERE run_id = :r AND step_key = 'snapshot_volume' AND state = 'succeeded'"
        ),
        {"r": run_id},
    ).first()
    return ok is not None


def _orphan_snapshot(c: Connection, run_id: str, why: str) -> None:
    """W4 failed and the run leaves it for good: a snapshot that exists (``creating`` or ``error``) is reported as an
    orphan candidate, never deleted (SRE-R-7, SRE-R-31). The run counts as "no snapshot" from here on."""
    c.execute(
        text("UPDATE owned_resource SET state = 'orphan', updated_at = now(), detail = detail || CAST(:d AS jsonb) "
             "WHERE run_id = :r AND role = 'snapshot' AND state IN ('intended', 'present') "
             "AND openstack_id IS NOT NULL"),
        {"r": run_id, "d": json.dumps({"orphan_candidate": why, "never_deleted_by_ovlm": True})},
    )  # fmt: skip


def _abort_actor(c: Connection, run_id: str) -> str | None:
    value = c.execute(
        text("SELECT abort_requested_by FROM workflow_run WHERE id = :r"), {"r": run_id}
    ).scalar()
    return str(value) if value else None


def _check_confirmation(
    c: Connection, sig: SignalView, run_id: str, expected_tc: str
) -> str | None:
    """Re-validate the step-up (``run.<kind>`` on this run, consumed, interactive, of the actor) and the TC."""
    import hmac

    typed = " ".join(str(sig.payload.get("typed_confirmation") or "").split())
    if not expected_tc or not hmac.compare_digest(typed, expected_tc):
        return "typed confirmation does not match the affected VM"
    sid = sig.payload.get("stepup_id")
    if not sid:
        return "no step-up"
    row = c.execute(
        text(
            "SELECT user_id, action, target_id, auth_method, created_at, consumed_at FROM stepup WHERE id = :i"
        ),
        {"i": sid},
    ).first()
    action = "run." + sig.kind
    ok = (
        row is not None
        and str(row.user_id) == sig.actor_id
        and row.action == action
        and row.target_id == run_id
        and row.auth_method == INTERACTIVE_AUTH
        and row.consumed_at is not None
        and row.created_at <= row.consumed_at <= row.created_at + STEPUP_VALIDITY
    )
    return None if ok else "step-up evidence invalid"


def _expected(
    key: str, truth: Mapping[str, Any], resolved: Mapping[str, Any], green_id: str | None
) -> bool:
    """Section 5.1 rule 1: the fresh probe equals the failed step's expected post-state exactly."""
    blue = truth.get("blue") or {}
    vol = truth.get("volume") or {}
    fip_blue = (truth.get("fip") or {}).get("on") == "blue"
    blue_off = blue.get("status") == "SHUTOFF" and blue.get("task_state") is None
    bid = resolved["blue"]["server_id"]
    if key == "stop_old":
        return (
            blue_off
            and fip_blue
            and (not vol or (vol.get("status") == "in-use" and vol.get("attached_to") == [bid]))
        )
    if key == "detach_volume":
        return (
            blue_off
            and fip_blue
            and vol.get("status") == "available"
            and not vol.get("attached_to")
        )
    if key == "attach_volume_green":
        return (
            blue_off
            and fip_blue
            and vol.get("status") == "in-use"
            and vol.get("attached_to") == [green_id]
        )
    return False


def _same_state(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    def norm(t: Mapping[str, Any]) -> Any:
        return {k: t.get(k) for k in ("blue", "green", "volume")} | {
            "fip": {k: (t.get("fip") or {}).get(k) for k in ("port_id", "on")}
        }

    return bool(norm(a) == norm(b))
