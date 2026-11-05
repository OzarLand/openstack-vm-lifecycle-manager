"""Shared machinery of the ``bluegreen_fip_v1`` steps (worker only).

Every step is a :class:`~ovlm.workflow.contract.Step`: the engine drives probe -> decide -> act -> verify, persists
the intent before ``act`` and starts every attempt (re-claim, takeover) at ``probe``. Steps keep no state between
attempts; within one attempt, :meth:`RStep.memo` carries what ``act`` learnt to ``verify``.

Error classes: OpenStack adapter errors map through :func:`ovlm.openstack.retry.classify` (renewal-workflow.md "retry
class"); automation errors carry their class; :class:`StepRefusal` is a step's own classified stop. Window and
restore steps attach a **fresh** probe (``truth``) to every failure so the closed table (section 4.1) can decide.
"""

from __future__ import annotations

import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from sqlalchemy import Engine, text

from ovlm.automation.types import AutomationError
from ovlm.openstack import errors as oe
from ovlm.openstack.retry import classify as os_classify
from ovlm.openstack.write import GuardedWriteClient
from ovlm.registry.ssh_target import first_fixed_address
from ovlm.renewal.config import RenewalConfig
from ovlm.renewal.ledger import DbOwnershipRegistry, green_row, plan_resolved
from ovlm.renewal.ports import CloudPort, GuestPort, GuestRef
from ovlm.workflow.contract import ErrorClass, Fail, Step, StepContext


@dataclass(frozen=True)
class Deps:
    db: Engine
    cfg: RenewalConfig
    cloud: CloudPort
    guest: GuestPort


class StepRefusal(Exception):  # noqa: N818 - a classified stop, not a programming error
    def __init__(self, error_class: ErrorClass, reason: str, **detail: Any) -> None:
        super().__init__(reason)
        self.error_class = error_class
        self.reason = reason
        self.detail = detail


_NH_REASONS: tuple[tuple[type[Exception], str], ...] = (
    (oe.InstanceLockedError, "server_locked"),
    (oe.ForeignLockError, "foreign_lock"),
    (oe.FloatingIpNoRouterPathError, "fip_no_router_path"),
    (oe.OwnershipViolationError, "ownership_violation"),
    (oe.DuplicateResourceError, "duplicate_resource"),
    (oe.ServerBuildFailedError, "green_build_failed"),
)


class RStep(Step):
    #: Window / restore steps attach a fresh probe to failures.
    attach_truth: ClassVar[bool] = False

    def __init__(self, deps: Deps) -> None:
        self.d = deps
        self._memo: weakref.WeakKeyDictionary[Any, dict[str, Any]] = weakref.WeakKeyDictionary()

    # -- per-attempt memo and accessors ------------------------------------------------------------------

    def memo(self, ctx: StepContext) -> dict[str, Any]:
        return self._memo.setdefault(ctx, {})

    def resolved(self, ctx: StepContext) -> Mapping[str, Any]:
        m = self.memo(ctx)
        if "resolved" not in m:
            with ctx.read() as c:
                m["resolved"] = plan_resolved(c, ctx.run.id)
        resolved: Mapping[str, Any] = m["resolved"]
        return resolved

    def green(self, ctx: StepContext) -> Mapping[Any, Any] | None:
        with ctx.read() as c:
            return green_row(c, ctx.run.id)

    def green_id(self, ctx: StepContext) -> str | None:
        g = self.green(ctx)
        return (
            g["openstack_id"] if g is not None and g["state"] in ("intended", "present") else None
        )

    def project(self, ctx: StepContext) -> str:
        """The run's project connection: the credentials of every cloud call are this project's."""
        return project_of(self.resolved(ctx))

    def wc(self, ctx: StepContext) -> GuardedWriteClient:
        m = self.memo(ctx)
        if "wc" not in m:
            m["wc"] = self.d.cloud.write_client(
                DbOwnershipRegistry(self.d.db, ctx.run.id), ctx.gate, project=self.project(ctx)
            )
        client: GuardedWriteClient = m["wc"]
        return client

    def external(self, ctx: StepContext) -> Any:
        """External probe via the service FIP; blue and green (with their names) are the candidate answerers."""
        r = self.resolved(ctx)
        g = self.green(ctx)
        candidates: dict[str, str | None] = {r["blue"]["server_id"]: r["blue"].get("name")}
        if g is not None and g["openstack_id"] and g["state"] in ("intended", "present"):
            candidates[g["openstack_id"]] = g["intended_name"]
        return self.d.guest.external_probe(
            r["floating_ip"]["address"], r["health_check"]["external"], candidates
        )

    def green_ref(self, ctx: StepContext) -> GuestRef:
        g = self.green(ctx)
        if g is None or not g["openstack_id"]:
            raise StepRefusal(ErrorClass.NEEDS_HUMAN, "green_unknown")
        det = g["detail"] or {}
        return GuestRef(
            g["openstack_id"], det.get("fixed_ip") or "", "new", tuple(det.get("pinned") or ())
        )

    def blue_ref(self, ctx: StepContext) -> GuestRef:
        r = self.resolved(ctx)
        port = self.wc(ctx).get_port(r["blue"]["port_id"])
        address = first_fixed_address(port.fixed_ips) or ""  # the scan's rule too (IS-3)
        return GuestRef(
            r["blue"]["server_id"],
            address,
            "old",
            fingerprint=r["blue"].get("host_key_fingerprint"),
        )

    def db_seconds_since(self, ctx: StepContext, column: str) -> float | None:
        with ctx.read() as c:
            value = c.execute(
                text(
                    f"SELECT EXTRACT(EPOCH FROM now() - {column}) FROM workflow_run WHERE id = :r"  # noqa: S608
                ),
                {"r": ctx.run.id},
            ).scalar()
        return None if value is None else float(value)

    # -- fresh probe ---------------------------------------------------------------------------------------

    def truth(self, ctx: StepContext) -> dict[str, Any]:
        return read_truth(self.wc(ctx), self.resolved(ctx), self.green(ctx))

    def safe_truth(self, ctx: StepContext) -> dict[str, Any]:
        try:
            return self.truth(ctx)
        except Exception as exc:  # noqa: BLE001 - a failed probe is itself the information
            return {"api_reachable": False, "error": type(exc).__name__}

    def fail(self, ctx: StepContext, cls: ErrorClass, reason: str, **detail: Any) -> Fail:
        if self.attach_truth and "truth" not in detail:
            detail["truth"] = self.safe_truth(ctx)
        nh = reason if cls != ErrorClass.RETRYABLE else None
        return Fail(cls, reason, detail, needs_human_reason=detail.pop("needs_human_reason", nh))

    def classify(self, ctx: StepContext, exc: Exception) -> Fail:
        if isinstance(exc, StepRefusal):
            return self.fail(ctx, exc.error_class, exc.reason, **exc.detail)
        if isinstance(exc, AutomationError):
            return self.fail(
                ctx,
                ErrorClass(exc.classification.value),
                "automation_error",
                message=str(exc)[:300],
            )
        if isinstance(exc, oe.OpenStackError):
            cls = ErrorClass(os_classify(exc).value)
            reason = next((r for t, r in _NH_REASONS if isinstance(exc, t)), None)
            if (
                isinstance(exc, oe.ConflictError)
                and "host" in str(exc).lower()
                and "down" in str(exc).lower()
            ):
                cls, reason = ErrorClass.NEEDS_HUMAN, "compute_host_down"
            return self.fail(
                ctx,
                cls,
                reason or type(exc).__name__,
                message=str(exc)[:300],
                error=type(exc).__name__,
            )
        if isinstance(exc, LookupError):
            return self.fail(
                ctx, ErrorClass.NEEDS_HUMAN, "state_lookup_failed", message=str(exc)[:300]
            )
        return self.fail(ctx, ErrorClass.RETRYABLE, type(exc).__name__, message=str(exc)[:300])


def project_of(resolved: Mapping[str, Any]) -> str:
    return str(resolved["service"]["project_connection_id"])


def read_truth(
    client: GuardedWriteClient, resolved: Mapping[str, Any], green: Mapping[Any, Any] | None
) -> dict[str, Any]:
    """The current-truth panel (renewal-workflow.md 6.1) from a fresh read. Raises when the API is unreachable."""

    def server(sid: str | None) -> dict[str, Any] | None:
        if not sid:
            return None
        try:
            s = client.get_server(sid)
        except oe.NotFoundError as exc:
            if type(exc) is oe.NotFoundError:
                return {"id": sid, "gone": True}
            raise
        return {
            "id": sid,
            "status": s.status,
            "task_state": s.task_state,
            "locked": s.locked,
            "locked_reason": s.locked_reason,
        }

    blue_id = resolved["blue"]["server_id"]
    green_id = (
        green["openstack_id"]
        if green is not None and green["state"] in ("intended", "present")
        else None
    )
    green_port = (green["detail"] or {}).get("port_id") if green is not None else None
    out: dict[str, Any] = {
        "api_reachable": True,
        "blue": server(blue_id),
        "green": server(green_id),
    }
    dv = resolved.get("data_volume")
    if dv:
        v = client.get_volume(dv["volume_id"])
        out["volume"] = {
            "status": v.status,
            "attached_to": sorted(a.server_openstack_id for a in v.attachments),
        }
    fip = client.get_floating_ip(resolved["floating_ip"]["id"])
    on = None
    if fip.port_id == resolved["blue"]["port_id"]:
        on = "blue"
    elif green_port is not None and fip.port_id == green_port:
        on = "green"
    elif fip.port_id is not None:
        on = "other"
    out["fip"] = {"readable": True, "port_id": fip.port_id, "status": fip.status, "on": on}
    return out
