"""Downtime window W1-W10 (renewal-workflow.md 2.2).

* **W1 claim checks** run in W1's probe (read) and again in the first transaction of ``act``, which also writes
  ``downtime_started_at`` (first claim only) before the quiesce starts: G2 valid now with its evidence re-validated,
  policy window open, B9 younger than ``green_ready.max_age``, write credential and Keystone token valid beyond the
  worst-case window. A refused claim sends the run back to G2 or B9 with no outage.
* **Budget** (SRE-R-6): before W2-W8, ``now - downtime_started_at > max_window_duration`` fails with trigger
  ``budget``; the closed table decides. From W9 the run finishes forward.
* **Evidence** (SEC-R-1): G2 integrity (not expiry) is re-validated before W2, W3, W5 and W9.
* **Data phases** (W1, W6): a takeover (the previous attempt's worker died) goes to needs_human with a read-only
  probe attached; nothing is re-run blindly (AC section 6). OpenStack steps re-probe and never re-send a call whose
  effect is already visible (probe -> decide).
* Every failure carries a fresh probe (``truth``) for the closed table; ``first_use`` is always ``false`` (SRE-R-3).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy import text

from ovlm.auth.sod import Gate
from ovlm.renewal import metrics
from ovlm.renewal.base import RStep, StepRefusal
from ovlm.renewal.closed_table import TRIGGER_BUDGET, TRIGGER_EVIDENCE
from ovlm.renewal.ledger import fenced_write, ledger_intend, ledger_present, snapshot_row
from ovlm.renewal.plans import load_facts, now_db
from ovlm.renewal.steps_build import (
    AnsibleStep,
    b9_age,
    credential_ok,
    gate_check,
    phase_outcome,
    window_state,
)
from ovlm.workflow.contract import Act, Decision, Done, ErrorClass, Fail, Outcome, StepContext, Wait

E = ErrorClass


class WindowStep(RStep):
    attach_truth = True
    budget_checked = True
    evidence_checked = False

    def window_gates(self, ctx: StepContext) -> Fail | None:
        """Budget then evidence, before the step does anything (sections 2.2, 3.1)."""
        if self.budget_checked:
            elapsed = self.db_seconds_since(ctx, "downtime_started_at")
            budget = float(self.resolved(ctx)["max_window_duration_seconds"])
            if elapsed is not None and elapsed > budget:
                metrics.BUDGET_EXCEEDED.inc()
                return self.fail(ctx, E.NEEDS_HUMAN, "window_budget_exceeded", trigger=TRIGGER_BUDGET,
                                 elapsed=round(elapsed, 1), budget=budget)  # fmt: skip
        if self.evidence_checked:
            g2 = gate_check(self, ctx, Gate.CUTOVER, check_expiry=False)
            if not g2["ok"]:
                return self.fail(ctx, E.NEEDS_HUMAN, "approval_evidence_invalid", trigger=TRIGGER_EVIDENCE,
                                 g2=g2)  # fmt: skip
            self.memo(ctx)["g2"] = g2
        return None

    def wait(self, ctx: StepContext, **ev: Any) -> Wait:
        return Wait(evidence={**ev, "truth": self.safe_truth(ctx)})


class WindowAnsible(AnsibleStep):
    attach_truth = True

    def interrupted(self, ctx: StepContext, mount_point: str | None) -> Fail | None:
        """Data phase taken over after a worker death: needs_human with an automatic read-only probe (section 5)."""
        if not (self.data_phase and ctx.takeover):
            return None
        r = self.resolved(ctx)
        try:
            gp = self.d.guest.probe(
                self.target(ctx), mount_point=mount_point, units=tuple(r["service_units"])
            )
            probe = gp.as_json()
        except Exception as exc:  # noqa: BLE001
            probe = {"reachable": False, "error": type(exc).__name__}
        return self.fail(ctx, E.NEEDS_HUMAN, "data_phase_interrupted", guest_probe=probe)

    def budget(self, ctx: StepContext) -> Fail | None:
        elapsed = self.db_seconds_since(ctx, "downtime_started_at")
        budget = float(self.resolved(ctx)["max_window_duration_seconds"])
        if elapsed is not None and elapsed > budget:
            metrics.BUDGET_EXCEEDED.inc()
            return self.fail(ctx, E.NEEDS_HUMAN, "window_budget_exceeded", trigger=TRIGGER_BUDGET)
        return None


class QuiesceOld(WindowAnsible):
    """W1: the outage starts. Claim checks, ``downtime_started_at``, then AC quiesce on blue (stop, unmount, sync)."""

    key = "quiesce_old"
    destructive = True
    phase = "quiesce"
    target_role = "old"
    data_phase = True

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        dv = r.get("data_volume") or {}
        if (f := self.interrupted(ctx, dv.get("mount_point"))) is not None:
            return {"fail": f}
        refusals: list[str] = []
        back = "await_cutover"
        g2 = gate_check(self, ctx, Gate.CUTOVER, check_expiry=True)
        if not g2["ok"]:
            refusals.append(f"G2 {g2['reason']}")
        with ctx.read() as c:
            facts = load_facts(c, ctx.run.renewal_plan_id or "")
            now = now_db(c)
        if not window_state(facts.policy, now)[0]:
            refusals.append("policy window closed")
        age = b9_age(ctx)
        if age is None or age > float(self.d.cfg.green_ready_max_age or 0):
            if not refusals:
                back = "verify_green_ready"  # only B9 is stale: re-prove green, then claim again
            refusals.append("verify_green_ready too old")
        worst = float(r["worst_case_window_seconds"])
        token = (
            self.d.cloud.token_expires_at()
        )  # obtained before the claim transaction (SRE-R-28 b)
        if not credential_ok(self.d.cloud.write_credential_expires_at(), worst, now):
            refusals.append("write credential expires within the worst-case window")
        if not credential_ok(token, worst, now):
            refusals.append("Keystone token expires within the worst-case window")
        blue = self.wc(ctx).get_server(r["blue"]["server_id"])
        if blue.status != "ACTIVE" or blue.task_state is not None:
            refusals.append(f"blue {blue.status}/{blue.task_state}")
        if dv:
            v = self.wc(ctx).get_volume(dv["volume_id"])
            if [a.server_openstack_id for a in v.attachments] != [r["blue"]["server_id"]]:
                refusals.append("volume not attached to blue only")
        if g2["reason"] == "approval_evidence_invalid":
            return {"fail": self.fail(ctx, E.NEEDS_HUMAN, "approval_evidence_invalid", g2=g2)}
        return {"refusals": refusals, "back": back, "g2": g2}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        if observed["refusals"]:
            return Fail(
                E.FATAL,
                "w1_claim_refused",
                {"refusals": observed["refusals"], "back_to": observed["back"]},
            )
        return Act({"phase": "quiesce", "g2_approval_id": observed["g2"]["approval_id"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        claimed = fenced_write(
            self.d.db,
            ctx,
            "UPDATE workflow_run SET downtime_started_at = COALESCE(downtime_started_at, now()), updated_at = now() "
            "WHERE id = :r AND EXISTS (SELECT 1 FROM approval WHERE id = :a AND decision = 'approved' "
            "AND void_reason IS NULL AND expires_at > now())",
            {"r": ctx.run.id, "a": intent["g2_approval_id"]},
        )
        if claimed != 1:
            raise StepRefusal(
                E.FATAL,
                "w1_claim_refused",
                refusals=["G2 expired at claim"],
                back_to="await_cutover",
            )
        dv = self.resolved(ctx).get("data_volume")
        self.run(ctx, data_volume=_dv(dv))

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        res = self.memo(ctx)["result"]
        out = phase_outcome(self, ctx, res, data_phase=True)
        if isinstance(out, Done):
            return Done({**dict(out.evidence), "marker_checksum": res.facts.get("marker_checksum")})
        return out

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        if isinstance(exc, StepRefusal) and exc.reason == "w1_claim_refused":
            return Fail(E.FATAL, exc.reason, exc.detail)
        f = super().classify(ctx, exc)
        # A data phase never retries: whatever failed after the claim is needs_human (AC section 6).
        return Fail(
            E.NEEDS_HUMAN, f.reason, f.detail, needs_human_reason=f.needs_human_reason or f.reason
        )


def _dv(dv: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not dv:
        return None
    return {"id": dv["volume_id"], "mount_point": dv["mount_point"], "fs_type": dv["fs_type"],
            "expected_serial": dv["volume_id"], "first_use": False}  # fmt: skip


class StopOld(WindowStep):
    """W2: Nova stop blue. 409 locked -> needs_human directly (admin lock)."""

    key = "stop_old"
    destructive = True
    evidence_checked = True

    def probe(self, ctx: StepContext) -> Any:
        if (f := self.window_gates(ctx)) is not None:
            return {"fail": f}
        s = self.wc(ctx).get_server(self.resolved(ctx)["blue"]["server_id"])
        return {"status": s.status, "task": s.task_state}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        if observed["status"] == "SHUTOFF" and observed["task"] is None:
            return Done({"blue": "SHUTOFF"})
        if observed["task"] is not None:
            return self.wait(ctx, blue=observed)
        if observed["status"] != "ACTIVE":
            return self.fail(ctx, E.NEEDS_HUMAN, "blue_unexpected_state", blue=observed)
        return Act({"stop": self.resolved(ctx)["blue"]["server_id"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).stop_server(intent["stop"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


class DetachVolume(WindowStep):
    """W3: detach from the stopped blue. Rolled back to ``in-use`` -> retried once -> restore; stuck -> needs_human."""

    key = "detach_volume"
    destructive = True
    evidence_checked = True

    def probe(self, ctx: StepContext) -> Any:
        if (f := self.window_gates(ctx)) is not None:
            return {"fail": f}
        r = self.resolved(ctx)
        v = self.wc(ctx).get_volume(r["data_volume"]["volume_id"])
        s = self.wc(ctx).get_server(r["blue"]["server_id"])
        return {"status": v.status, "attached": sorted(a.server_openstack_id for a in v.attachments),
                "blue": s.status, "blue_task": s.task_state, "blue_locked": s.locked}  # fmt: skip

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        blue = self.resolved(ctx)["blue"]["server_id"]
        if observed["status"] == "available" and not observed["attached"]:
            return Done({"volume": "available"})
        if observed["status"] == "detaching":
            return self.wait(ctx, volume="detaching")
        if observed["status"] == "in-use" and observed["attached"] == [blue]:
            tries = int((ctx.previous_intent or {}).get("detach_try", 0))
            if tries >= 2:
                return self.fail(ctx, E.NEEDS_HUMAN, "detach_rolled_back", tries=tries)
            if (
                observed["blue"] != "SHUTOFF"
                or observed["blue_task"] is not None
                or observed["blue_locked"]
            ):
                return self.fail(ctx, E.NEEDS_HUMAN, "blue_not_stopped", blue=observed)
            return Act({"detach_try": tries + 1})
        return self.fail(ctx, E.NEEDS_HUMAN, "volume_unexpected_state", volume=observed)

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        r = self.resolved(ctx)
        self.wc(ctx).detach_volume(r["blue"]["server_id"], r["data_volume"]["volume_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


class SnapshotVolume(WindowStep):
    """W4 (optional): Cinder snapshot of the ``available`` volume; failure or deadline -> auto restore (SRE-R-7).
    A snapshot stuck ``creating`` is reported as an orphan candidate, never deleted."""

    key = "snapshot_volume"

    def _port(self) -> Any:
        port = self.d.cloud.snapshots()
        if port is None:
            raise StepRefusal(E.NEEDS_HUMAN, "snapshot_unsupported")
        return port

    def probe(self, ctx: StepContext) -> Any:
        if (f := self.window_gates(ctx)) is not None:
            return {"fail": f}
        name = f"ovlm-prehandoff-{ctx.run.id}"
        with ctx.read() as c:
            row = snapshot_row(c, ctx.run.id)
        snap = self._port().find_snapshot(name)
        return {"name": name, "row": dict(row) if row else None,
                "snap": None if snap is None else {"id": snap.openstack_id, "status": snap.status}}  # fmt: skip

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        snap = observed["snap"]
        if snap is None:
            if ctx.previous_intent:
                return self.fail(
                    ctx, E.NEEDS_HUMAN, "snapshot_failed", snapshot="missing after create"
                )
            return Act({"name": observed["name"]})
        if snap["status"] == "available":
            return Done({"snapshot_id": snap["id"]})
        if snap["status"] in ("creating",):
            return self.wait(ctx, snapshot=snap)
        return self.fail(ctx, E.NEEDS_HUMAN, "snapshot_failed", snapshot=snap)

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        ledger_intend(self.d.db, ctx, role="snapshot", rtype="snapshot", name=intent["name"])
        snap = self._port().create_snapshot(
            self.resolved(ctx)["data_volume"]["volume_id"], intent["name"], ctx.gate
        )
        ledger_present(self.d.db, ctx, role="snapshot", openstack_id=snap.openstack_id)

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


class AttachVolumeGreen(WindowStep):
    """W5: hot attach to green. ``available`` again after the call -> restore; stuck states -> needs_human."""

    key = "attach_volume_green"
    destructive = True
    evidence_checked = True

    def probe(self, ctx: StepContext) -> Any:
        if (f := self.window_gates(ctx)) is not None:
            return {"fail": f}
        r = self.resolved(ctx)
        v = self.wc(ctx).get_volume(r["data_volume"]["volume_id"])
        return {
            "status": v.status,
            "attached": sorted(a.server_openstack_id for a in v.attachments),
        }

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        gid = self.green_id(ctx)
        if observed["status"] == "in-use" and observed["attached"] == [gid]:
            return Done({"volume": "in-use on green"})
        if observed["status"] in ("reserved", "attaching"):
            return self.wait(ctx, volume=observed)
        if observed["status"] == "available" and not observed["attached"]:
            if ctx.previous_intent:
                return self.fail(ctx, E.NEEDS_HUMAN, "attach_not_done", volume=observed)
            return Act({"attach": gid})
        return self.fail(ctx, E.NEEDS_HUMAN, "volume_unexpected_state", volume=observed)

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).attach_volume(intent["attach"], self.resolved(ctx)["data_volume"]["volume_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=None)


def w1_marker(ctx: StepContext) -> str | None:
    with ctx.read() as c:
        ev = c.execute(
            text(
                "SELECT evidence FROM workflow_step WHERE run_id = :r AND step_key = 'quiesce_old' "
                "AND state = 'succeeded' ORDER BY seq DESC LIMIT 1"
            ),
            {"r": ctx.run.id},
        ).scalar()
    return None if not ev else ev.get("marker_checksum")


class DataAttachGreen(WindowAnsible):
    """W6: AC data_attach on green: by-id device, blkid decision table, mount by UUID. ``first_use=false``."""

    key = "data_attach_green"
    phase = "data_attach"
    data_phase = True

    def probe(self, ctx: StepContext) -> Any:
        dv = self.resolved(ctx)["data_volume"]
        if (f := self.interrupted(ctx, dv["mount_point"])) is not None:
            return {"fail": f}
        if (f := self.budget(ctx)) is not None:
            return {"fail": f}
        return {}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        return Act({"phase": "data_attach", "first_use": False})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        dv = self.resolved(ctx)["data_volume"]
        self.run(
            ctx,
            data_volume=_dv(dv),
            expected_marker=w1_marker(ctx),
            expected_fs_uuid=dv.get("fs_uuid"),
        )

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        res = self.memo(ctx)["result"]
        out = phase_outcome(self, ctx, res, data_phase=True)
        if not isinstance(out, Done):
            return out
        dv = self.resolved(ctx)["data_volume"]
        marker = w1_marker(ctx)
        problems = []
        if dv.get("fs_uuid") and res.facts.get("fs_uuid") != dv["fs_uuid"]:
            problems.append("fs_uuid differs from the profile")
        if marker is not None and res.facts.get("marker_checksum") != marker:
            problems.append("marker checksum differs from W1")
        if problems:
            return self.fail(ctx, E.NEEDS_HUMAN, "data_attach_mismatch", problems=problems)
        return Done({**dict(out.evidence), "first_use": False})

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        f = super().classify(ctx, exc)
        return Fail(
            E.NEEDS_HUMAN, f.reason, f.detail, needs_human_reason=f.needs_human_reason or f.reason
        )


class StartServiceGreen(WindowAnsible):
    """W7: AC start_service on green. Exhausted -> needs_human + page, or restore if a W4 snapshot exists."""

    key = "start_service_green"
    phase = "start_service"

    def probe(self, ctx: StepContext) -> Any:
        return {"fail": f} if (f := self.budget(ctx)) is not None else {}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        return Act({"phase": self.phase})


class HealthcheckGreen(WindowAnsible):
    """W8: AC healthcheck on green, repeated with backoff (``healthcheck.max_attempts``, ``.interval``); marker
    checksum must equal W1's. Waits on the check, never on a fixed delay."""

    key = "healthcheck_green"
    phase = "healthcheck"

    def probe(self, ctx: StepContext) -> Any:
        return {"fail": f} if (f := self.budget(ctx)) is not None else {}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        return Act({"phase": self.phase})

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        res = self.memo(ctx)["result"]
        marker = w1_marker(ctx)
        if res.ok and (marker is None or res.facts.get("marker_checksum") == marker):
            return Done(
                {"healthcheck": res.reason, "marker_checksum": res.facts.get("marker_checksum")}
            )
        done = int((ctx.previous_evidence or {}).get("hc_attempts", 0)) + 1
        if done >= int(self.d.cfg.healthcheck_max_attempts or 1) or res.classification in (
            "fatal",
            "needs_human",
        ):
            return self.fail(
                ctx, E.NEEDS_HUMAN, "healthcheck_exhausted", attempts=done, phase_reason=res.reason
            )
        return Wait(
            poll_after=float(self.d.cfg.healthcheck_interval or 0), evidence={"hc_attempts": done}
        )


class MoveFip(WindowStep):
    """W9: one PUT moves the FIP to green's port; repeat-safe. From here the run finishes forward (no budget)."""

    key = "move_fip"
    destructive = True
    budget_checked = False
    evidence_checked = True

    def probe(self, ctx: StepContext) -> Any:
        if (f := self.window_gates(ctx)) is not None:
            return {"fail": f}
        fip = self.wc(ctx).get_floating_ip(self.resolved(ctx)["floating_ip"]["id"])
        return {"port_id": fip.port_id, "status": fip.status}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "fail" in observed:
            fail: Fail = observed["fail"]
            return fail
        r = self.resolved(ctx)
        green_port = ((self.green(ctx) or {}).get("detail") or {}).get("port_id")
        if observed["port_id"] == green_port:
            if observed["status"] == "ACTIVE":
                return Done({"fip": "on green", "status": "ACTIVE"})
            return self.wait(ctx, fip=observed)
        if observed["port_id"] == r["blue"]["port_id"]:
            return Act({"port_id": green_port})
        return self.fail(ctx, E.NEEDS_HUMAN, "fip_state_unknown", fip=observed)

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.wc(ctx).update_floating_ip(self.resolved(ctx)["floating_ip"]["id"], intent["port_id"])

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Wait(poll_after=0.0)


class ExternalVerify(WindowStep):
    """External HTTP probe via the FIP; the answer must come from ``expect`` (marker/identity), N times."""

    budget_checked = False
    expect_role = "green"

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        res = self.d.guest.external_probe(
            r["floating_ip"]["address"], r["health_check"]["external"]
        )
        expect = self.green_id(ctx) if self.expect_role == "green" else r["blue"]["server_id"]
        return {"ok": res.ok and res.identity == expect, "identity": res.identity}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        prev = int((ctx.previous_evidence or {}).get("external_successes", 0))
        n = prev + 1 if observed["ok"] else 0
        if n >= int(self.d.cfg.external_required_successes or 1):
            ev: dict[str, Any] = {"external_successes": n, "identity": observed["identity"]}
            if self.expect_role == "green":  # what the W10 commit records for green's registration
                from ovlm.inventory.sync import server_item

                s = self.wc(ctx).get_server(observed["identity"])
                item = server_item(s)
                ev["green_observed"] = {"payload": item.payload, "payload_hash": item.digest, "name": s.name,
                                        "status": s.status, "tags": list(s.tags)}  # fmt: skip
            return Done(ev)
        return Wait(poll_after=float(self.d.cfg.external_interval or 0),
                    evidence={"external_successes": n, "last_identity": observed["identity"],
                              "truth": self.safe_truth(ctx)})  # fmt: skip

    def act(
        self, ctx: StepContext, intent: Mapping[str, Any]
    ) -> None:  # pragma: no cover - read-only
        raise AssertionError("read-only")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("read-only")


class VerifyExternal(ExternalVerify):
    """W10: starts immediately after W9 (no settle delay, EXP-01b)."""

    key = "verify_external"
