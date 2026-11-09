"""Build phase B1-B9 and the cutover gate G2 (renewal-workflow.md 2.1). No service impact: blue keeps serving."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text

from ovlm.auth.sod import Gate
from ovlm.openstack.allowlist import TAG_MANAGED, VOLUME_MARKER_KEY, VOLUME_MARKER_VALUE
from ovlm.openstack.errors import DuplicateResourceError, NotFoundError
from ovlm.openstack.ownership import run_tag
from ovlm.openstack.types import CreateServerSpec, ServerInfo
from ovlm.openstack.write import AdoptionExpectation, adopt_checks
from ovlm.policies.windows import next_window, rule_from_dict
from ovlm.renewal import metrics
from ovlm.renewal.base import BLUE_HOST_KEY_UNTRUSTED, RStep, StepRefusal, blue_host_key_problems
from ovlm.renewal.evidence import check_gate
from ovlm.renewal.ledger import ledger_detail, ledger_intend, ledger_present
from ovlm.renewal.plans import green_name, load_facts, now_db
from ovlm.workflow.contract import Act, Decision, Done, ErrorClass, Outcome, StepContext, Wait

E = ErrorClass


def window_state(policy: Mapping[str, Any] | None, now: datetime) -> tuple[bool, float | None]:
    """(open now, seconds until the next window opens)."""
    rules = [rule_from_dict(w) for w in (policy or {}).get("windows") or []]
    nxt = next_window(now, rules) if rules else None
    if nxt is None:
        return False, None
    start, _end = nxt
    return start <= now, max(0.0, (start - now).total_seconds())


def gate_check(
    step: RStep, ctx: StepContext, gate: Gate, *, check_expiry: bool
) -> Mapping[str, Any]:
    with ctx.read() as c:
        facts = load_facts(c, ctx.run.renewal_plan_id or "")
        now = now_db(c)
        starter = ctx.run.started_by
        res = check_gate(
            c,
            gate,
            facts,
            run_id=ctx.run.id,
            run_starter=_uuid(starter),
            now=now,
            check_expiry=check_expiry,
        )
    if res.reason == "approval_evidence_invalid":
        metrics.EVIDENCE_INVALID.labels(gate.value).inc()
    return {
        "ok": res.ok,
        "reason": res.reason,
        "approval_id": res.approval_id,
        "evidence": dict(res.evidence),
    }


def _uuid(value: str | None) -> Any:
    from uuid import UUID

    return UUID(value) if value else None


def server_checks(s: ServerInfo, *, expect: str = "ACTIVE") -> list[str]:
    out = []
    if s.is_minimal_construct:
        out.append("server in an unreachable cell")
    if s.status != expect or s.task_state is not None:
        out.append(f"server {s.status}/{s.task_state}, expected {expect} with no task")
    if s.locked:
        out.append("server locked")
    return out


def live_preconditions(step: RStep, ctx: StepContext) -> list[str]:
    """Section 1 re-checked live (B1, B8): what the member credential can observe."""
    r = step.resolved(ctx)
    wc = step.wc(ctx)
    problems = server_checks(wc.get_server(r["blue"]["server_id"]))
    dv = r.get("data_volume")
    if dv:
        v = wc.get_volume(dv["volume_id"])
        targets = sorted(a.server_openstack_id for a in v.attachments)
        if v.status != "in-use" or targets != [r["blue"]["server_id"]]:
            problems.append(
                f"data volume {v.status} attached to {targets}, expected in-use on blue only"
            )
        if v.multiattach:
            problems.append("data volume is multiattach")
        for a in wc.list_server_volume_attachments(r["blue"]["server_id"]):
            if a.volume_openstack_id == dv["volume_id"] and a.delete_on_termination is not False:
                problems.append("data attachment delete_on_termination is not false")
    fip = wc.get_floating_ip(r["floating_ip"]["id"])
    if fip.port_id != r["blue"]["port_id"]:
        problems.append("floating IP is not on blue's port")
    return problems


class Preflight(RStep):
    """B1: re-validate the plan live; G1 evidence; image facts; config; write-credential expiry."""

    key = "preflight"

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        # IS-11: before any OpenStack call, the plan's blue must be the plan's own confirmed managed VM (the api
        # writes ``resolved``), and the port the plan uses as blue's SSH address must be attached to blue.
        with ctx.read() as c:
            untrusted = blue_host_key_problems(c, r, run_id=ctx.run.id, check_confirmer=True)
        if untrusted:
            return {"untrusted": untrusted}
        wc = self.wc(ctx)
        if wc.get_port(r["blue"]["port_id"]).device_id != r["blue"]["server_id"]:
            return {"untrusted": ["the plan's blue port is not attached to blue's server"]}
        problems = live_preconditions(self, ctx)
        images = {i.openstack_id: i for i in wc.list_images()}
        img = images.get(r["image"]["id"])
        if img is None or img.status != "active":
            problems.append("image missing or not active")
        elif (img.owner_id, img.visibility) != (r["image"]["owner"], r["image"]["visibility"]):
            problems.append("image owner or visibility changed since the plan (SEC-R-29)")
        if r["flavor"]["id"] not in {f.openstack_id for f in wc.list_flavors()}:
            problems.append("flavor missing")
        dv = r.get("data_volume") or {}
        if dv.get("snapshot_before_handoff"):
            # SRE-R-7: room for one more snapshot of the volume's size, checked before any outage. W4 still
            # restores automatically if the create is refused later (the check is advisory against a race).
            v = wc.get_volume(dv["volume_id"])
            problems += wc.block_storage_limits().snapshot_headroom(
                int(v.size or dv.get("size") or 0)
            )
        missing = self.d.cfg.missing(snapshot=bool(dv.get("snapshot_before_handoff")))
        if missing:
            problems.append("configuration keys missing: " + ", ".join(missing))
        with ctx.read() as c:
            facts = load_facts(c, ctx.run.renewal_plan_id or "")
        needs_g1 = bool(((facts.policy or {}).get("approvals") or {}).get("plan"))
        g1 = (
            gate_check(self, ctx, Gate.PLAN, check_expiry=True)
            if needs_g1
            else {"ok": True, "reason": "not_required"}
        )
        if facts.recomputed_hash is None:
            problems.append("plan sources (profile version or policy) are missing")
        expires = self.d.cloud.write_credential_expires_at(self.project(ctx))
        with ctx.read() as c:
            now = now_db(c)
        if not credential_ok(
            expires, 0.0, now
        ):  # an expired write credential blocks new runs (security-model 4.4)
            problems.append("the write credential has expired")
        return {
            "problems": problems,
            "g1": g1,
            "credential_expires_at": expires.isoformat() if expires else None,
        }

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if (
            "untrusted" in observed
        ):  # stop for a human: nothing has been written, nothing runs on blue
            return self.fail(
                ctx, E.NEEDS_HUMAN, BLUE_HOST_KEY_UNTRUSTED, problems=observed["untrusted"]
            )
        if not observed["g1"]["ok"]:
            reason = observed["g1"]["reason"]
            return self.fail(
                ctx,
                E.NEEDS_HUMAN if reason == "approval_evidence_invalid" else E.FATAL,
                reason,
                g1=observed["g1"],
            )
        if observed["problems"]:
            return self.fail(ctx, E.FATAL, "preflight_failed", problems=observed["problems"])
        return Done(
            {"g1": observed["g1"], "credential_expires_at": observed["credential_expires_at"]}
        )

    def act(
        self, ctx: StepContext, intent: Mapping[str, Any]
    ) -> None:  # pragma: no cover - read-only step
        raise AssertionError("preflight never acts")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("preflight never acts")


class ClaimResources(RStep):
    """B2: ``ovlm:managed`` on blue and FIP, ``ovlm.managed`` metadata on the volume: add/merge only (SEC-R-24)."""

    key = "claim_resources"

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        wc = self.wc(ctx)
        blue = wc.get_server(r["blue"]["server_id"])
        fip = wc.get_floating_ip(r["floating_ip"]["id"])
        dv = r.get("data_volume")
        vol_ok = True
        if dv:
            vol_ok = (
                wc.get_volume(dv["volume_id"]).metadata.get(VOLUME_MARKER_KEY)
                == VOLUME_MARKER_VALUE
            )
        return {"blue": TAG_MANAGED in blue.tags, "fip": TAG_MANAGED in fip.tags, "volume": vol_ok}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if all(observed.values()):
            return Done({"markers": observed})
        return Act({"missing": [k for k, v in observed.items() if not v]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        r = self.resolved(ctx)
        wc = self.wc(ctx)
        wc.add_server_tag(r["blue"]["server_id"], TAG_MANAGED)
        wc.add_floating_ip_tag(r["floating_ip"]["id"], TAG_MANAGED)
        if r.get("data_volume"):
            wc.merge_volume_metadata(
                r["data_volume"]["volume_id"], {VOLUME_MARKER_KEY: VOLUME_MARKER_VALUE}
            )

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        observed = self.probe(ctx)
        if all(observed.values()):
            return Done({"markers": observed})
        return self.fail(ctx, E.RETRYABLE, "markers_missing", markers=observed)


class CreateGreen(RStep):
    """B3: ledger ``intended`` first; lookup by run tag + exact name: 0 create, 1 adopt only if
    :func:`~ovlm.openstack.write.adopt_checks` passes (SEC-R-23), >1 needs_human."""

    key = "create_green"

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        g = self.green(ctx)
        name = green_name(r, ctx.run.id)
        if g is not None and g["state"] == "present" and g["openstack_id"]:
            try:
                s = self.wc(ctx).get_server(g["openstack_id"])
                return {"present": s.openstack_id, "name": name}
            except NotFoundError:
                raise StepRefusal(
                    E.NEEDS_HUMAN, "green_disappeared", green=g["openstack_id"]
                ) from None
        try:
            found = self.wc(ctx).find_run_server(name)
        except DuplicateResourceError as exc:
            raise StepRefusal(
                E.NEEDS_HUMAN, "duplicate_resource", matches=list(exc.matches)
            ) from None
        if found is None:
            return {"name": name, "found": None}
        if g is None:  # a run-tagged server without our ledger row: never adopt
            return {
                "name": name,
                "found": found.openstack_id,
                "problems": ["no intended ledger row"],
            }
        verdict = adopt_checks(
            found,
            AdoptionExpectation(
                run_id=ctx.run.id, image_id=r["image"]["id"], flavor_name=r["flavor"]["name"],
                ledger_committed_at=g["intent_committed_at"], write_user_id=self.d.cloud.write_user_id(self.project(ctx)),
            ),
            self.wc(ctx).list_server_volume_attachments(found.openstack_id),
        )  # fmt: skip
        return {"name": name, "found": found.openstack_id, "problems": list(verdict.reasons)}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if "present" in observed:
            return Done({"green_id": observed["present"]})
        if observed["found"] is not None:
            if observed["problems"]:
                return self.fail(
                    ctx,
                    E.NEEDS_HUMAN,
                    "adoption_refused",
                    server=observed["found"],
                    problems=observed["problems"],
                )
            return Act({"adopt": observed["found"], "name": observed["name"]})
        return Act({"create": observed["name"]})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        r = self.resolved(ctx)
        if "adopt" in intent:
            ledger_present(
                self.d.db, ctx, role="green", openstack_id=intent["adopt"], detail={"adopted": True}
            )
            return
        name = intent["create"]
        ledger_intend(self.d.db, ctx, role="green", rtype="server", name=name)
        boot = self.d.guest.bootstrap(
            ctx.run.id, r["guest_access"].get("host_key_policy", "injected")
        )
        ledger_detail(
            self.d.db,
            ctx,
            role="green",
            detail={"bootstrap_public": boot.public_key, "bootstrap_key_id": boot.key_id},
        )
        spec = CreateServerSpec(
            name=name,
            image_id=r["image"]["id"],
            flavor_id=r["flavor"]["id"],
            network_id=r["network_id"],
            tags=(TAG_MANAGED, run_tag(ctx.run.id)),
            availability_zone=r["availability_zone"],
            security_group_names=tuple(r["security_groups"]),
            user_data=boot.user_data,
        )
        created = self.wc(ctx).create_server(spec)
        ledger_present(self.d.db, ctx, role="green", openstack_id=created.openstack_id)

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        gid = self.green_id(ctx)
        if gid is None:
            return self.fail(ctx, E.RETRYABLE, "green_not_recorded")
        self.wc(ctx).get_server(gid)
        return Done({"green_id": gid, "adopted": "adopt" in intent})


class WaitGreenActive(RStep):
    """B4: poll until ACTIVE (port locked in the success transaction); ERROR is fatal, green kept."""

    key = "wait_green_active"

    def probe(self, ctx: StepContext) -> Any:
        gid = self.green_id(ctx)
        if gid is None:
            raise StepRefusal(E.NEEDS_HUMAN, "green_unknown")
        server = self.wc(ctx).build_state(
            gid
        )  # ERROR -> ServerBuildFailedError (fatal, fault in message)
        if server is None:
            return {"active": False, "green_id": gid}
        ports = [p for p in self.wc(ctx).list_ports() if p.device_id == gid]
        if len(ports) != 1 or not ports[0].fixed_ips:
            raise StepRefusal(
                E.NEEDS_HUMAN, "green_port_ambiguous", ports=[p.openstack_id for p in ports]
            )
        return {"active": True, "green_id": gid, "port_id": ports[0].openstack_id, "fixed_ip": ports[0].fixed_ips[0][0],
                "subnet_id": ports[0].fixed_ips[0][1]}  # fmt: skip

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed["active"]:
            return Done(observed)
        return Wait(evidence={"green_id": observed["green_id"], "status": "building"})

    def act(
        self, ctx: StepContext, intent: Mapping[str, Any]
    ) -> None:  # pragma: no cover - poll only
        raise AssertionError("poll only")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("poll only")


class WaitGreenSsh(RStep):
    """B5: pin green's host key per ``host_key_policy`` (ADR-0006); SSH waits on reachability, not on ACTIVE."""

    key = "wait_green_ssh"

    def probe(self, ctx: StepContext) -> Any:
        g = self.green(ctx)
        if g is None or not g["openstack_id"]:
            raise StepRefusal(E.NEEDS_HUMAN, "green_unknown")
        return dict(g["detail"] or {})

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Act({"policy": self.resolved(ctx)["guest_access"].get("host_key_policy", "injected"),
                    "rerun": bool(observed.get("pinned"))})  # fmt: skip

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        det = dict((self.green(ctx) or {}).get("detail") or {})
        ref = self.green_ref(ctx)
        console = None
        if intent["policy"] == "console":
            console = self.wc(ctx).get_console_output(ref.server_id)
        accept = tuple(det.get("pinned") or ())
        # Once a pin is recorded the bootstrap key is dead evidence (REN-2): never hand it to the guest port again.
        bootstrap = None if accept else det.get("bootstrap_public")
        res = self.d.guest.pin_host_key(
            run_id=ctx.run.id, target=ref, policy=intent["policy"], bootstrap_public=bootstrap, accept=accept,
            console=console, fence=ctx.fence,
        )  # fmt: skip
        self.memo(ctx)["pin"] = res
        if res.ok:
            ledger_detail(
                self.d.db,
                ctx,
                role="green",
                detail={"pinned": list(res.pinned), "host_key_mode": res.mode},
            )

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        res = self.memo(ctx)["pin"]
        if res.ok:
            return Done(
                {
                    "pinned_fingerprints": len(res.pinned),
                    "mode": res.mode,
                    "policy": intent["policy"],
                }
            )
        if res.reason == "unreachable":
            return Wait(evidence={"ssh": "unreachable"})
        return self.fail(ctx, E.NEEDS_HUMAN, "host_key_unverifiable", detail_reason=res.reason)


def phase_outcome(step: RStep, ctx: StepContext, res: Any, *, data_phase: bool = False) -> Outcome:
    if res.ok:
        return Done({"phase_reason": res.reason, **dict(res.evidence), "facts": dict(res.facts)})
    cls = E(res.classification) if res.classification != "ok" else E.RETRYABLE
    if data_phase:
        cls = E.NEEDS_HUMAN  # contract section 6: any data-phase anomaly stops for a human
    # ``playbook_reported``: the playbook ran and refused with this classification (the accept-step entry, ADR-0008).
    extra = {"playbook_reported": res.reported} if getattr(res, "reported", None) else {}
    return step.fail(
        ctx, cls, f"{step.key}_failed", phase_reason=res.reason, facts=dict(res.facts), **extra
    )


class AnsibleStep(RStep):
    """A step that runs one automation phase on a guest. Lease = phase timeout + slack (ADR-0003 Ansible rule)."""

    phase: str = ""
    target_role: str = "new"
    data_phase = False

    def lease_for(self, params: Mapping[str, Any]) -> float | None:
        return self.d.cfg.automation_timeout(self.phase) + 60.0

    def target(self, ctx: StepContext) -> Any:
        return self.green_ref(ctx) if self.target_role == "new" else self.blue_ref(ctx)

    def run(self, ctx: StepContext, **kw: Any) -> Any:
        res = self.d.guest.run_phase(
            run_id=ctx.run.id, step_id=ctx.step.id, attempt=ctx.attempt, phase=self.phase,
            target=self.target(ctx), timeout=self.d.cfg.automation_timeout(self.phase), fence=ctx.fence, **kw,
        )  # fmt: skip
        self.memo(ctx)["result"] = res
        return res

    def probe(self, ctx: StepContext) -> Any:
        return {}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Act({"phase": self.phase})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        self.run(ctx)

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return phase_outcome(self, ctx, self.memo(ctx)["result"], data_phase=self.data_phase)


class PrepareAutomation(AnsibleStep):
    """B6: one verified clone per run (SHA, lint, no Galaxy), then AC ``preflight.yml`` on green if present."""

    key = "prepare_automation"
    phase = "preflight"

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        ev = self.d.guest.prepare(ctx.run.id, self.resolved(ctx)["automation"], ctx.fence)
        self.memo(ctx)["prepared"] = dict(ev)
        if self.d.guest.has_phase(ctx.run.id, "preflight"):
            self.run(ctx)

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        res = self.memo(ctx).get("result")
        if res is None:
            return Done({"prepared": self.memo(ctx)["prepared"], "green_preflight": "absent"})
        out = phase_outcome(self, ctx, res)
        if isinstance(out, Done):
            return Done({**dict(out.evidence), "prepared": self.memo(ctx)["prepared"]})
        return out


class ConfigureGreen(AnsibleStep):
    """B7: AC ``configure.yml`` on green, no data."""

    key = "configure_green"
    phase = "configure"


class VerifyCutoverPreconditions(RStep):
    """B8: section 1 live + green port on the subnet + no FIP on green's port + external baseline via the FIP."""

    key = "verify_cutover_preconditions"

    def probe(self, ctx: StepContext) -> Any:
        r = self.resolved(ctx)
        problems = live_preconditions(self, ctx)
        det = (self.green(ctx) or {}).get("detail") or {}
        port = self.wc(ctx).get_port(det.get("port_id") or "")
        if not any(sub == r["subnet_id"] for _ip, sub in port.fixed_ips):
            problems.append("green port has no fixed IP on the plan's subnet")
        if any(f.port_id == port.openstack_id for f in self.wc(ctx).list_floating_ips()):
            problems.append("a floating IP is already on green's port (SRE-R-13)")
        probe = self.external(ctx)
        return {"problems": problems, "baseline": {"ok": probe.ok, "identity": probe.identity}}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed["problems"]:
            return self.fail(
                ctx, E.FATAL, "cutover_preconditions_failed", problems=observed["problems"]
            )
        b = observed["baseline"]
        if not b["ok"] or b["identity"] != self.resolved(ctx)["blue"]["server_id"]:
            return self.fail(ctx, E.RETRYABLE, "external_baseline_failed", baseline=b)
        return Done({"baseline": b})

    def act(
        self, ctx: StepContext, intent: Mapping[str, Any]
    ) -> None:  # pragma: no cover - read-only
        raise AssertionError("read-only")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("read-only")


class AwaitCutover(RStep):
    """G2: a valid cutover approval (bound to the plan hash, re-validated) **and** an open policy window."""

    key = "await_cutover"

    def probe(self, ctx: StepContext) -> Any:
        g2 = gate_check(self, ctx, Gate.CUTOVER, check_expiry=True)
        with ctx.read() as c:
            facts = load_facts(c, ctx.run.renewal_plan_id or "")
            now = now_db(c)
        is_open, wait_s = window_state(facts.policy, now)
        return {"g2": g2, "window_open": is_open, "window_in": wait_s}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        g2 = observed["g2"]
        if g2["reason"] == "approval_evidence_invalid":
            return self.fail(ctx, E.NEEDS_HUMAN, "approval_evidence_invalid", g2=g2)
        if not g2["ok"]:
            return Wait(until_signal=True, evidence={"g2": g2["reason"]})
        if not observed["window_open"]:
            wait = observed["window_in"]
            return Wait(poll_after=wait if wait is not None else None, until_signal=wait is None,
                        evidence={"g2": "ok", "window": "closed"})  # fmt: skip
        return Done({"g2_approval_id": g2["approval_id"], "g2": g2["evidence"]})

    def act(
        self, ctx: StepContext, intent: Mapping[str, Any]
    ) -> None:  # pragma: no cover - waiting gate
        raise AssertionError("gate")

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:  # pragma: no cover
        raise AssertionError("gate")


class VerifyGreenReady(RStep):
    """B9: green proven ready without data, after G2 and immediately before T0 (EXP-01b finding 2)."""

    key = "verify_green_ready"

    def lease_for(self, params: Mapping[str, Any]) -> float | None:
        return self.d.cfg.automation_timeout("preflight") + 60.0

    def probe(self, ctx: StepContext) -> Any:
        gid = self.green_id(ctx) or ""
        s = self.wc(ctx).get_server(gid)
        return {"status": s.status, "task_state": s.task_state}

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        if observed["status"] != "ACTIVE" or observed["task_state"] is not None:
            return self.fail(ctx, E.RETRYABLE, "green_not_active", server=observed)
        return Act({"check": "ready"})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        ref = self.green_ref(ctx)
        probe = self.d.guest.probe(ctx.run.id, ref, mount_point=None, units=())
        self.memo(ctx)["probe"] = probe
        if probe.reachable and self.d.guest.has_phase(ctx.run.id, "preflight"):
            self.memo(ctx)["pre"] = self.d.guest.run_phase(
                run_id=ctx.run.id, step_id=ctx.step.id, attempt=ctx.attempt, phase="preflight", target=ref,
                timeout=self.d.cfg.automation_timeout("preflight"), fence=ctx.fence,
            )  # fmt: skip

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        probe = self.memo(ctx)["probe"]
        pre = self.memo(ctx).get("pre")
        ok = (
            probe.reachable
            and probe.cloud_init_done is True
            and probe.system_state not in (None, "starting", "initializing")
            and (pre is None or pre.ok)
        )
        if ok:
            return Done({"probe": probe.as_json(), "preflight": pre.reason if pre else "absent"})
        return self.fail(ctx, E.RETRYABLE, "green_not_ready", probe=probe.as_json(),
                         preflight=pre.reason if pre else None)  # fmt: skip


def credential_ok(expires: datetime | None, worst_case: float, now: datetime) -> bool:
    """W1 claim: ``expires_at > now + worst-case window`` (an unknown expiry is not refused: entered by the admin)."""
    if expires is None:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires > now + timedelta(seconds=worst_case)


def b9_age(ctx: StepContext) -> float | None:
    with ctx.read() as c:
        value = c.execute(
            text(
                "SELECT EXTRACT(EPOCH FROM now() - finished_at) FROM workflow_step WHERE run_id = :r "
                "AND step_key = 'verify_green_ready' AND state = 'succeeded' ORDER BY seq DESC LIMIT 1"
            ),
            {"r": ctx.run.id},
        ).scalar()
    return None if value is None else float(value)
