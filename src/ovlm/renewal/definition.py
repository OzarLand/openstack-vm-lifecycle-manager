"""``bluegreen_fip_v1``: the workflow definition (renewal-workflow.md, ADR-0004). Worker only.

State machine on top of the engine (ADR-0003). Phases: ``build`` (B1-B9, G2, Discarding of a build), ``window``
(W1-W10), ``retained`` (R1, R2, G3), ``retire`` (X1), ``restore`` (S1-S10, Restored, Discarding after a restore).
``needs_human`` is the engine's overlay: a parked step keeps the phase and **all locks** (SRE-R-18); retry-step
retries the same step.

Failure handling (:meth:`BlueGreenFipV1.on_failure`):

* B1/B2 fatal: run ``failed`` (nothing created; B2 markers stay). Any later build failure parks the run
  (``BuildFailed``): locks kept, green kept for diagnosis, operator rollback (TC) deletes it. Never terminal while
  OVLM may hold a resource, so locks are never released under a live green.
* W1 claim refused: back to G2 or B9, no outage.
* W1-W10: the closed table (:mod:`ovlm.renewal.closed_table`), D-1 = B. One automatic restore per run
  (``workflow_run.auto_restore_used``), audited ``restore.auto`` (system, authority = the G2 approval id).
* Restore, retention, retirement, Discarding: needs_human.

Signals (re-validated here, SEC-R-1): ``rollback``/``abort``/``revert``/``discard`` need an operator in scope, a
consumed step-up ``run.<kind>`` on the run and the TC of the affected VM; ``mark_resolved`` additionally needs the
approver role when the next step is destructive; ``probe`` refreshes the current-truth panel and, sent by the
re-probe job for ``api_unreachable``, applies the self-resolution rules of section 5.1.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.auth.sod import INTERACTIVE_AUTH, STEPUP_VALIDITY, role_held_at
from ovlm.openstack.errors import WriteNotAllowedError
from ovlm.renewal import closed_table, metrics
from ovlm.renewal.base import Deps, RStep, read_truth
from ovlm.renewal.config import RESTORE_STEPS, WINDOW_STEPS
from ovlm.renewal.ledger import DbOwnershipRegistry, green_row, plan_resolved, snapshot_row
from ovlm.renewal.plans import KIND, STRATEGY, STRATEGY_VERSION, load_facts, tc_target
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
#: Steps after which the run's next step is destructive (mark_resolved then needs the approver role).


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
        if key == "verify_external":
            self._cutover_commit(c, run, resolved, ev)
        if key == "verify_external_old":
            _end_downtime(c, run.id)
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
        """W10 success, one transaction: ``downtime_ended_at``, roles (green current, blue retained), audit."""
        seconds = _end_downtime(c, run.id)
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
        if seconds is not None:
            metrics.DOWNTIME.observe(seconds)

    # ---- failures --------------------------------------------------------------------------------------

    def on_failure(self, ctx: TxContext, fail: Fail) -> Transition | None:
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
        resolved = plan_resolved(c, run.id)
        g = green_row(c, run.id)
        flags = c.execute(
            text("SELECT auto_restore_used FROM workflow_run WHERE id = :r"), {"r": run.id}
        ).one()
        decision = closed_table.decide(
            key,
            reason=reason if reason != "deadline_exceeded" or truth else "api_unreachable",
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
        key = ctx.step.step_key if ctx.step else ""
        if key in BUILD:
            return Transition(next_step=self.spec("discard_green"), phase="build")
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
        if not operator and not (sig.kind == "mark_resolved" and approver):
            return "the actor does not hold the operator role in this scope"
        if sig.kind == "probe":
            return None
        phase = run.phase or "build"
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
        if sig.kind == "discard" and step != "await_discard":
            return "discard is only available once the service is restored to the old VM"
        destructive_retry = (
            sig.kind == "retry_step" and ctx.step is not None and ctx.step.destructive
        )
        if sig.kind in ("retry_step",) and not destructive_retry:
            return None
        if sig.kind == "mark_resolved":
            nxt = (
                self._following(step, resolved)
                if step and step in (*ORDER, *RESTORE_ORDER)
                else None
            )
            if nxt is not None and getattr(self._steps[nxt], "destructive", False) and not approver:
                return "the next step is destructive: mark-resolved needs the approver role"
        target = tc_target(c, run.id, sig.kind, phase, resolved)
        return _check_confirmation(c, sig, run.id, target)

    def prepare_signal(self, run: RunView, signal: SignalView) -> Any:
        if signal.kind != "probe":
            return None
        try:
            client = self.d.cloud.write_client(DbOwnershipRegistry(self.d.db, run.id), _no_writes)
            with self.d.db.connect() as c:
                resolved = plan_resolved(c, run.id)
                g = green_row(c, run.id)
            return read_truth(client, resolved, g)
        except Exception as exc:  # noqa: BLE001 - an unreachable API is the result
            return {"api_reachable": False, "error": type(exc).__name__}

    def on_signal(self, ctx: TxContext) -> Transition | Wake | str | None:
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
            truth = ctx.prepared or {"api_reachable": False}
            _write_truth(c, run.id, truth)
            if sig.actor_id is None:
                return self._self_resolve(ctx, truth)
            return "current truth refreshed"
        if sig.kind == "discard":
            return Transition(next_step=self.spec("discard_green"), phase="restore")
        if sig.kind == "rollback":
            if (run.phase or "build") == "build":
                return Transition(next_step=self.spec("discard_green"), phase="build")
            return self._restore(c, run, trigger="rollback", step_key=key, fail=None, truth=None, auto=False,
                                 actor=sig.actor_id)  # fmt: skip
        if sig.kind == "revert":
            return self._restore(c, run, trigger="revert", step_key=key, fail=None, truth=None, auto=False,
                                 actor=sig.actor_id)  # fmt: skip
        return None

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
    c.execute(
        text(
            "UPDATE workflow_run SET current_truth = CAST(:t AS jsonb), current_truth_at = now() WHERE id = :r"
        ),
        {"r": run_id, "t": json.dumps(dict(truth), default=str)},
    )


def _end_downtime(c: Connection, run_id: str) -> float | None:
    row = c.execute(
        text("UPDATE workflow_run SET downtime_ended_at = COALESCE(downtime_ended_at, now()) WHERE id = :r "
             "RETURNING EXTRACT(EPOCH FROM downtime_ended_at - downtime_started_at)"), {"r": run_id}).first()  # fmt: skip
    return None if row is None or row[0] is None else float(row[0])


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
