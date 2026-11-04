"""Retention and retirement (R1, R2, G3, X1), the convergent restore sequence (S1-S10) and Discarding.

Restore (renewal-workflow.md 4): one sequence for in-window auto restore, operator rollback and revert. Each step
probes and is **skipped if already satisfied**, so it converges from any intermediate state, after any crash.
Target: volume on blue, blue ACTIVE and serving, FIP on blue's port, green SHUTOFF and locked. Restore never
auto-restores again: every failure is needs_human. Data carries forward (what green wrote stays on the volume).

Discarding deletes green only from the ``discard_green`` step (the only step for which the ownership registry marks
green deletable), only with no volume attached (guard rule 3 re-reads attachments just before the call).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import text

from ovlm.auth.sod import Gate
from ovlm.openstack.allowlist import LOCK_REASON_PREFIX
from ovlm.openstack.errors import NotFoundError
from ovlm.renewal.base import RStep, StepRefusal
from ovlm.renewal.ledger import snapshot_row
from ovlm.renewal.steps_build import AnsibleStep, gate_check
from ovlm.renewal.steps_window import ExternalVerify, WindowAnsible
from ovlm.workflow.contract import Act, Decision, Done, ErrorClass, Fail, Outcome, StepContext, Wait

E = ErrorClass


def _gone(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except NotFoundError as exc:
        if type(exc) is NotFoundError:
            return None
        raise


# --- retention / retirement ----------------------------------------------------------------------------------------


class RetainOld(RStep):
    """R1: lock blue (``ovlm:retained:<run>``) after the cutover succeeded."""

    key = "retain_old"

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        s = self.wc(ctx).get_server(r["blue"]["server_id"])
        dv = (r.get("data_volume") or {}).get("volume_id")
        return {"status": s.status, "locked": s.locked, "reason": s.locked_reason,
                "data_attached": any(v.volume_id == dv for v in s.attached_volumes)}  # fmt: skip

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        want = f"ovlm:retained:{ctx.run.id}"
        if observed["locked"] and observed["reason"] == want:
            return Done({"blue_locked": want})
        if observed["status"] != "SHUTOFF" or observed["data_attached"]:
            return self.fail(ctx, E.NEEDS_HUMAN, "retain_precondition", blue=observed)
        return Act({"reason": want})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).lock_server(self.resolved(ctx)["blue"]["server_id"], intent["reason"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        s = self.wc(ctx).get_server(self.resolved(ctx)["blue"]["server_id"])
        if s.locked and s.locked_reason == intent["reason"]:
            return Done({"blue_locked": intent["reason"]})
        return self.fail(ctx, E.RETRYABLE, "lock_not_visible")


class AwaitRetention(RStep):
    """R2: timer until the policy ``retention_period`` has elapsed since the cutover; revert stays available."""

    key = "await_retention"

    def probe(self, ctx: StepContext) -> Any:
        with ctx.read() as c:
            period = c.execute(
                text(
                    "SELECT p.retention_period_seconds FROM workflow_run r JOIN renewal_plan pl "
                    "ON pl.id = r.renewal_plan_id JOIN policy p ON p.id = pl.policy_id WHERE r.id = :r"
                ),
                {"r": ctx.run.id},
            ).scalar()
        return {
            "elapsed": self.db_seconds_since(ctx, "downtime_ended_at") or 0.0,
            "period": float(period or 0),
        }

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        left = observed["period"] - observed["elapsed"]
        if left <= 0:
            return Done({"retention_seconds": observed["period"]})
        return Wait(poll_after=left, evidence={"retention_left": round(left, 1)})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:  # pragma: no cover - timer
        raise AssertionError("timer")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("timer")


class AwaitRetirement(RStep):
    """G3: a valid retirement approval (two-person rule, never self-approved, no revert since)."""

    key = "await_retirement"

    def probe(self, ctx: StepContext) -> Any:
        return gate_check(self, ctx, Gate.RETIREMENT, check_expiry=False)

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed["ok"]:
            return Done({"g3_approval_id": observed["approval_id"]})
        return Wait(until_signal=True, evidence={"g3": observed["reason"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:  # pragma: no cover - gate
        raise AssertionError("gate")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("gate")


class RetireOld(AnsibleStep):
    """X1: re-validate G3, prove the whole post-state (SRE-R-10, SEC-R-8, SEC-R-33), unlock and delete blue, delete
    this run's snapshot. Any mismatch: needs_human and the G3 approval is void. The data volume is never touched;
    a leftover boot-from-volume root volume is reported, not deleted."""

    key = "retire_old"
    destructive = True
    phase = "healthcheck"

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        wc = self.wc(ctx)
        blue = _gone(wc.get_server, r["blue"]["server_id"])
        if blue is None:
            return {"gone": True}
        g3 = gate_check(self, ctx, Gate.RETIREMENT, check_expiry=False)
        problems: list[str] = [] if g3["ok"] else [f"G3 {g3['reason']}"]
        if (
            blue.status != "SHUTOFF"
            or not blue.locked
            or not (blue.locked_reason or "").startswith(LOCK_REASON_PREFIX)
        ):
            problems.append("blue is not SHUTOFF and locked by OVLM")
        dv = (r.get("data_volume") or {}).get("volume_id")
        attachments = wc.list_server_volume_attachments(r["blue"]["server_id"])
        if dv and any(a.volume_openstack_id == dv for a in attachments):
            problems.append("data volume attached to blue")
        fip = wc.get_floating_ip(r["floating_ip"]["id"])
        if fip.port_id == r["blue"]["port_id"]:
            problems.append("service FIP is on blue's port")
        gid = self.green_id(ctx)
        green = _gone(wc.get_server, gid) if gid else None
        if green is None or green.status != "ACTIVE":
            problems.append("green is not ACTIVE")
        if dv:
            v = wc.get_volume(dv)
            if v.status != "in-use" or [a.server_openstack_id for a in v.attachments] != [gid]:
                problems.append("data volume is not in-use on green")
        with ctx.read() as c:
            roles: dict[str, str] = dict(
                c.execute(
                    text(
                        "SELECT openstack_server_id, role FROM managed_vm WHERE openstack_server_id IN (:b, :g)"
                    ),
                    {"b": r["blue"]["server_id"], "g": gid or ""},
                ).all()
            )
            restored = c.execute(
                text(
                    "SELECT 1 FROM workflow_step WHERE run_id = :r AND step_key = 'unlock_old' LIMIT 1"
                ),
                {"r": ctx.run.id},
            ).first()
        if roles.get(r["blue"]["server_id"]) != "retained" or roles.get(gid or "") != "current":
            problems.append(f"managed VM roles are {roles}")
        if restored is not None:
            problems.append("the run entered Restoring")
        health = None
        if not problems:
            health = self.run(ctx)
            if not health.ok:
                problems.append(f"fresh green healthcheck failed: {health.reason}")
        root = [a.volume_openstack_id for a in attachments if a.volume_openstack_id != dv]
        return {"problems": problems, "g3": g3, "leftover_root_volumes": root,
                "attachments_dot": [a.delete_on_termination for a in attachments]}  # fmt: skip

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed.get("gone"):
            return Done({"blue": "deleted"})
        if observed["problems"]:
            return self.fail(ctx, E.NEEDS_HUMAN, "retire_precondition_mismatch", problems=observed["problems"],
                             voids_approval=observed["g3"].get("approval_id"))  # fmt: skip
        return Act({"g3_approval_id": observed["g3"]["approval_id"],
                    "leftover_root_volumes": observed["leftover_root_volumes"]})  # fmt: skip

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        blue = self.resolved(ctx)["blue"]["server_id"]
        wc = self.wc(ctx)
        wc.unlock_server(blue)
        wc.delete_server(
            blue
        )  # guard rule 3: no registered volume, delete_on_termination exactly false
        with ctx.read() as c:
            snap = snapshot_row(c, ctx.run.id)
        port = self.d.cloud.snapshots()
        if snap is not None and snap["openstack_id"] and port is not None:
            port.delete_snapshot(snap["openstack_id"], ctx.gate)

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        if _gone(self.wc(ctx).get_server, self.resolved(ctx)["blue"]["server_id"]) is None:
            return Done(
                {"blue": "deleted", "leftover_root_volumes": intent["leftover_root_volumes"]}
            )
        return Wait(poll_after=None)


# --- restore S1-S10 ------------------------------------------------------------------------------------------------


class RestoreStep(RStep):
    attach_truth = True

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        f = super().classify(ctx, exc)
        if (
            f.error_class == E.FATAL
        ):  # inside restore everything that is not retryable stops for a human
            return Fail(
                E.NEEDS_HUMAN,
                f.reason,
                f.detail,
                needs_human_reason=f.needs_human_reason or f.reason,
            )
        return f


class UnlockOld(RestoreStep):
    """S1: unlock blue (own lock only); an admin lock -> needs_human."""

    key = "unlock_old"
    destructive = True

    def probe(self, ctx: StepContext) -> Any:
        s = self.wc(ctx).get_server(self.resolved(ctx)["blue"]["server_id"])
        return {"locked": s.locked, "reason": s.locked_reason}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if not observed["locked"]:
            return Done({"skipped": "not locked"})
        if not (observed["reason"] or "").startswith(LOCK_REASON_PREFIX):
            return self.fail(ctx, E.NEEDS_HUMAN, "foreign_lock", lock=observed)
        return Act({"unlock": True})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).unlock_server(self.resolved(ctx)["blue"]["server_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return (
            Done({"unlocked": True})
            if not self.probe(ctx)["locked"]
            else self.fail(ctx, E.RETRYABLE, "still")
        )


class QuiesceGreen(WindowAnsible):
    """S2: AC quiesce on green (role ``new``) before any detach. Skipped if the volume is not on green or green is
    not ACTIVE."""

    key = "quiesce_green"
    phase = "quiesce"
    data_phase = True

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        dv = r.get("data_volume")
        gid = self.green_id(ctx)
        green = _gone(self.wc(ctx).get_server, gid) if gid else None
        on_green = False
        if dv and gid:
            v = self.wc(ctx).get_volume(dv["volume_id"])
            on_green = any(a.server_openstack_id == gid for a in v.attachments)
        if green is None or green.status != "ACTIVE" or not on_green:
            return {"skip": True}
        if (f := self.interrupted(ctx, dv["mount_point"] if dv else None)) is not None:
            return {"fail": f}
        return {"skip": False}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        if observed["skip"]:
            return Done({"skipped": "volume not on an ACTIVE green"})
        return Act({"phase": "quiesce"})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        dv = self.resolved(ctx).get("data_volume") or {}
        self.run(ctx, data_volume={"id": dv["volume_id"], "mount_point": dv["mount_point"], "fs_type": dv["fs_type"],
                                   "expected_serial": dv["volume_id"], "first_use": False})  # fmt: skip

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        f = super().classify(ctx, exc)
        return Fail(
            E.NEEDS_HUMAN, f.reason, f.detail, needs_human_reason=f.needs_human_reason or f.reason
        )


class _Power(RestoreStep):
    """Stop or start a server, skip if already there; polls; ``None`` server id or gone = done."""

    want = "SHUTOFF"

    def server_id(self, ctx: StepContext) -> str | None:
        raise NotImplementedError

    def probe(self, ctx: StepContext) -> Any:
        sid = self.server_id(ctx)
        s = _gone(self.wc(ctx).get_server, sid) if sid else None
        return None if s is None else {"status": s.status, "task": s.task_state}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed is None:
            return Done({"skipped": "server gone"})
        if observed["status"] == self.want and observed["task"] is None:
            return Done({"status": self.want})
        if observed["task"] is not None:
            return Wait(evidence={"server": observed})
        return Act({"to": self.want})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        sid = self.server_id(ctx) or ""
        (self.wc(ctx).stop_server if self.want == "SHUTOFF" else self.wc(ctx).start_server)(sid)

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


class StopGreen(_Power):
    """S3: Nova stop green (skip if SHUTOFF or gone)."""

    key = "stop_green"
    destructive = True

    def server_id(self, ctx: StepContext) -> str | None:
        return self.green_id(ctx)


class _Volume(RestoreStep):
    destructive = True

    def vol(self, ctx: StepContext) -> dict[str, Any] | None:
        dv = self.resolved(ctx).get("data_volume")
        if not dv:
            return None
        v = self.wc(ctx).get_volume(dv["volume_id"])
        return {
            "status": v.status,
            "attached": sorted(a.server_openstack_id for a in v.attachments),
        }


class DetachFromGreen(_Volume):
    """S4: detach the volume from (stopped) green; skip if not attached to green."""

    key = "detach_from_green"

    def probe(self, ctx: StepContext) -> Any:
        return self.vol(ctx)

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        gid = self.green_id(ctx)
        if observed is None or gid not in observed["attached"]:
            return Done({"skipped": "not attached to green"})
        if observed["status"] == "detaching":
            return Wait(evidence={"volume": observed})
        if ctx.previous_intent and int(ctx.previous_intent.get("try", 0)) >= 2:
            return self.fail(ctx, E.NEEDS_HUMAN, "detach_rolled_back", volume=observed)
        return Act({"detach": gid, "try": int((ctx.previous_intent or {}).get("try", 0)) + 1})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).detach_volume(intent["detach"], self.resolved(ctx)["data_volume"]["volume_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


class AttachToOld(_Volume):
    """S5: attach the volume to the **stopped** blue (allowed in STOPPED); skip if already on blue."""

    key = "attach_to_old"

    def probe(self, ctx: StepContext) -> Any:
        return self.vol(ctx)

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        blue = self.resolved(ctx)["blue"]["server_id"]
        if observed is None:
            return Done({"skipped": "stateless"})
        if observed["attached"] == [blue] and observed["status"] == "in-use":
            return Done({"volume": "in-use on blue"})
        if observed["status"] in ("reserved", "attaching"):
            return Wait(evidence={"volume": observed})
        if observed["status"] == "available" and not observed["attached"]:
            if ctx.previous_intent:
                return self.fail(ctx, E.NEEDS_HUMAN, "attach_not_done", volume=observed)
            return Act({"attach": blue})
        return self.fail(ctx, E.NEEDS_HUMAN, "volume_unexpected_state", volume=observed)

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).attach_volume(intent["attach"], self.resolved(ctx)["data_volume"]["volume_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


class BootOld(RestoreStep):
    """S6: ensure blue has **booted since quiesce** (SRE-R-1): SHUTOFF -> start; ACTIVE -> read-only probe: mounted
    and units active -> skip, else stop and start. fstab (UUID, nofail) remounts; enabled units start."""

    key = "boot_old"
    destructive = True

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        s = self.wc(ctx).get_server(r["blue"]["server_id"])
        obs: dict[str, Any] = {"status": s.status, "task": s.task_state}
        if s.status == "ACTIVE" and s.task_state is None:
            dv = r.get("data_volume") or {}
            gp = self.d.guest.probe(self.blue_ref(ctx), mount_point=dv.get("mount_point"),
                                    units=tuple(r["service_units"]))  # fmt: skip
            obs["guest"] = gp.as_json()
        return obs

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        prev = (ctx.previous_intent or {}).get("action")
        if observed["task"] is not None:
            return Wait(evidence={"blue": observed})
        if observed["status"] == "SHUTOFF":
            return Act({"action": "start"})
        if observed["status"] != "ACTIVE":
            return self.fail(ctx, E.NEEDS_HUMAN, "blue_unexpected_state", blue=observed)
        g = observed["guest"]
        if not g["reachable"]:
            if prev == "start":
                return Wait(
                    evidence={"blue": observed}
                )  # booting: SSH not up yet (bounded by the deadline)
            return self.fail(ctx, E.NEEDS_HUMAN, "blue_probe_failed", guest=g)
        healthy = g["mounted"] is not False and g["units_active"] is not False
        if healthy:
            return Done({"blue": "ACTIVE, mounted, units active", "booted": prev == "start"})
        if prev == "start":
            return self.fail(ctx, E.NEEDS_HUMAN, "blue_unhealthy_after_boot", guest=g)
        return Act({"action": "stop"})  # quiesced but ACTIVE: boot-cycle

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        blue = self.resolved(ctx)["blue"]["server_id"]
        (self.wc(ctx).start_server if intent["action"] == "start" else self.wc(ctx).stop_server)(
            blue
        )

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


class RecoverOldService(WindowAnsible):
    """S7: AC ``rollback_hooks.yml`` on blue if present (defence in depth), then ``healthcheck.yml`` (role old)."""

    key = "recover_old_service"
    phase = "healthcheck"
    target_role = "old"

    def lease_for(self, params: Mapping[str, Any]) -> float | None:
        return (
            self.d.cfg.automation_timeout("rollback_hooks")
            + self.d.cfg.automation_timeout("healthcheck")
            + 120
        )

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        target = self.target(ctx)
        if self.d.guest.has_phase(ctx.run.id, "rollback_hooks"):
            hooks = self.d.guest.run_phase(
                run_id=ctx.run.id, step_id=ctx.step.id, attempt=ctx.attempt, phase="rollback_hooks", target=target,
                timeout=self.d.cfg.automation_timeout("rollback_hooks"), fence=ctx.fence,
            )  # fmt: skip
            if not hooks.ok:
                self.memo(ctx)["result"] = hooks
                return
        self.run(ctx)

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        res = self.memo(ctx)["result"]
        if res.ok:
            return Done({"healthcheck_old": res.reason})
        done = int((ctx.previous_evidence or {}).get("hc_attempts", 0)) + 1
        if done >= int(self.d.cfg.healthcheck_max_attempts or 1):
            return self.fail(
                ctx, E.NEEDS_HUMAN, "old_service_unhealthy", attempts=done, phase_reason=res.reason
            )
        return Wait(
            poll_after=float(self.d.cfg.healthcheck_interval or 0), evidence={"hc_attempts": done}
        )

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        f = super().classify(ctx, exc)
        return Fail(
            E.NEEDS_HUMAN, f.reason, f.detail, needs_human_reason=f.needs_human_reason or f.reason
        )


class MoveFipToOld(RestoreStep):
    """S8: FIP back to blue's port (skip if already there)."""

    key = "move_fip_to_old"
    destructive = True

    def probe(self, ctx: StepContext) -> Any:
        fip = self.wc(ctx).get_floating_ip(self.resolved(ctx)["floating_ip"]["id"])
        return {"port_id": fip.port_id, "status": fip.status}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        blue_port = self.resolved(ctx)["blue"]["port_id"]
        if observed["port_id"] == blue_port:
            return (
                Done({"fip": "on blue"})
                if observed["status"] == "ACTIVE"
                else Wait(evidence={"fip": observed})
            )
        if ctx.previous_intent and int(ctx.previous_intent.get("try", 0)) >= 2:
            return self.fail(ctx, E.NEEDS_HUMAN, "fip_move_back_failed", fip=observed)
        return Act(
            {"port_id": blue_port, "try": int((ctx.previous_intent or {}).get("try", 0)) + 1}
        )

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).update_floating_ip(self.resolved(ctx)["floating_ip"]["id"], intent["port_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=0.0)


class VerifyExternalOld(ExternalVerify):
    """S9: external probe via the FIP; the identity must equal **blue** (SRE-R-13)."""

    key = "verify_external_old"
    expect_role = "blue"
    attach_truth = True


class LockGreen(RestoreStep):
    """S10: lock green (``ovlm:restored:<run>``) so nobody starts it by hand on its empty mount point (SRE-R-17)."""

    key = "lock_green"

    def probe(self, ctx: StepContext) -> Any:
        gid = self.green_id(ctx)
        s = _gone(self.wc(ctx).get_server, gid) if gid else None
        return None if s is None else {"locked": s.locked, "reason": s.locked_reason}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        want = f"ovlm:restored:{ctx.run.id}"
        if observed is None:
            return Done({"skipped": "no green"})
        if observed["locked"] and observed["reason"] == want:
            return Done({"green_locked": want})
        return Act({"reason": want})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).lock_server(self.green_id(ctx) or "", intent["reason"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        obs = self.probe(ctx)
        if obs is None or (obs["locked"] and obs["reason"] == intent["reason"]):
            return Done({"green_locked": intent["reason"]})
        return self.fail(ctx, E.RETRYABLE, "lock_not_visible")


class AwaitDiscard(RStep):
    """Restored: blue serves; green stays stopped and locked until an operator discards it (maintainer decision 3)."""

    key = "await_discard"

    def probe(self, ctx: StepContext) -> Any:
        return {}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Wait(until_signal=True, evidence={"waiting_for": "discard (TC of green)"})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:  # pragma: no cover
        raise AssertionError("gate")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("gate")


class DiscardGreen(RStep):
    """Discarding: unlock green (own lock), check no volume is attached, delete it (ledger + tag + guard)."""

    key = "discard_green"
    destructive = True

    def probe(self, ctx: StepContext) -> Any:
        gid = self.green_id(ctx)
        if gid is None:
            return None
        s = _gone(self.wc(ctx).get_server, gid)
        if s is None:
            return None
        return {"id": gid, "status": s.status, "task": s.task_state, "volumes": [v.volume_id for v in s.attached_volumes],
                "locked": s.locked}  # fmt: skip

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed is None:
            return Done({"green": "absent"})
        if observed["volumes"]:
            return self.fail(ctx, E.NEEDS_HUMAN, "green_has_volume", green=observed)
        if observed["task"] is not None:
            return Wait(evidence={"green": observed})
        return Act({"delete": observed["id"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        wc = self.wc(ctx)
        wc.unlock_server(intent["delete"])
        wc.delete_server(intent["delete"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        if _gone(self.wc(ctx).get_server, intent["delete"]) is None:
            return Done({"green": "deleted", "green_id": intent["delete"]})
        return Wait(poll_after=None)

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        if isinstance(exc, StepRefusal):
            return super().classify(ctx, exc)
        f = super().classify(ctx, exc)
        return (
            f
            if f.error_class == E.RETRYABLE
            else Fail(
                E.NEEDS_HUMAN,
                f.reason,
                f.detail,
                needs_human_reason=f.needs_human_reason or f.reason,
            )
        )
