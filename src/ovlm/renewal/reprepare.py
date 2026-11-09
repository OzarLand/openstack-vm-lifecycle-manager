"""``reprepare-automation``: the audited human exit for a run whose verified checkout is lost inside the window.

Inside the downtime window nothing may contact the git host (automation-contract.md section 2), so a run whose B6
checkout is gone (a worker container restart before the checkout cache existed, a lost cache volume) or whose cached
copy no longer matches B6's tree digest parks ``needs_human`` with no way forward: retry-step and every restore step
need that checkout. An approver (not the run's requester), with a consumed password+TOTP step-up and the typed
confirmation of the affected VM, may authorize **one** re-clone of the run's pinned SHA:

* the api records the request as a ``run_signal`` of kind ``reprepare_automation``;
* the worker re-validates it (:meth:`~ovlm.renewal.definition.BlueGreenFipV1.validate_signal`), writes one
  ``automation_reprepare`` row (this module), audits ``automation.reprepare.authorized`` and re-queues the parked step
  as retry-step does;
* the guest port consumes the row atomically before it clones (:func:`take`): the normal verified clone, lint and
  waivers, which must produce the tree digest B6 recorded (when it recorded one). The result is recorded on the row
  and audited ``automation.reprepare.used`` (or ``.refused``). A consumed row is never used again.
* the authorization is bound to the parked step it was given for (review PMR-2): only an attempt of **that** step
  that still holds its lease (running, its attempt number, lease not expired in the database) can consume it, after
  a fence check. Once that step closed without using it (it finished from its probe alone, or was cancelled), the
  authorization is void: it is marked ``expired`` (:func:`expire_stale`) the next time the run's authorizations are
  read by the worker, and no longer counts as pending.

Imported by the api (available actions) and the worker; no adapter import here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.workflow.ids import new_id

#: The parked step's ``error.reason`` that the exit applies to.
CHECKOUT_LOST = "automation_checkout_lost"
CHECKOUT_UNVERIFIABLE = "automation_checkout_unverifiable"
#: The re-clone itself produced another tree than B6 verified: no further authorization applies (a human looks).
REPREPARE_MISMATCH = "automation_reprepare_digest_mismatch"
REASONS = frozenset({CHECKOUT_LOST, CHECKOUT_UNVERIFIABLE})
#: Messages of runs parked by an older worker, before these reasons existed (``automation_error`` + message).
_LEGACY_PREFIXES = (
    "the run's verified checkout is gone",
    "the cached checkout does not match the tree digest",
    "a cached checkout exists but the run has no recorded tree digest",
)

ENTITY = "automation_reprepare"
audit.register_entity(
    ENTITY,
    [
        "run_id",
        "step_key",
        "sha",
        "approver",
        "signal_id",
        "outcome",
        "recorded_tree_digest",
        "tree_digest",
        "quarantined_checkout",
    ],
)
#: A cached checkout copy that did not match B6's tree digest, moved aside (review PMR-6).
CHECKOUT_ENTITY = "automation_checkout"
audit.register_entity(
    CHECKOUT_ENTITY,
    ["run_id", "step_id", "quarantined_checkout", "recorded_tree_digest", "cached_tree_digest"],
)


def record_quarantine(
    c: Connection, *, run_id: str, step_id: str | None, detail: Mapping[str, str]
) -> None:
    """Audit ``automation.checkout.quarantined`` (worker): where the mismatching copy was moved and both digests."""
    with Session(bind=c) as s:
        audit.record(
            s, action="automation.checkout.quarantined", target_type=CHECKOUT_ENTITY, target_id=run_id,
            result="failure", principal_type="worker", auth_method="none", run_id=UUID(run_id),
            step_id=UUID(step_id) if step_id else None,
            after={"run_id": run_id, "step_id": step_id, "quarantined_checkout": detail.get("quarantined_checkout"),
                   "recorded_tree_digest": detail.get("recorded_tree_digest"),
                   "cached_tree_digest": detail.get("cached_tree_digest")},
        )  # fmt: skip


def applies_to(error: Mapping[str, Any] | None) -> bool:
    """Whether a parked step's ``error`` is the lost / unverifiable checkout refusal this exit is for."""
    if not isinstance(error, Mapping):
        return False
    reason = error.get("reason")
    if reason in REASONS:
        return True
    message = str(error.get("message") or "")
    return reason == "automation_error" and message.startswith(_LEGACY_PREFIXES)


@dataclass(frozen=True)
class Authorization:
    id: str
    run_id: str
    signal_id: str
    step_key: str
    sha: str
    approver_id: str


#: Outcome of an authorization whose step closed (finished, cancelled) without using it: void (PMR-2).
EXPIRED = "expired: its step closed without a re-clone"


def pending(c: Connection, run_id: str) -> bool:
    """An authorization of the run not consumed yet whose step is still open (a void one does not count)."""
    return (
        c.execute(
            text(
                "SELECT 1 FROM automation_reprepare a JOIN workflow_step s ON s.id = a.step_id WHERE a.run_id = :r "
                "AND a.consumed_at IS NULL AND s.state IN ('ready', 'running', 'waiting', 'needs_human')"
            ),
            {"r": run_id},
        ).first()
        is not None
    )


def expire_stale(c: Connection, run_id: str) -> list[str]:
    """Void the run's unconsumed authorizations whose step is closed (PMR-2): ``consumed_at`` and ``outcome =
    expired`` in one update (the table's trigger allows that single transition), audited
    ``automation.reprepare.expired``. Worker only. Returns the ids."""
    rows = (
        c.execute(
            text(
                "UPDATE automation_reprepare a SET consumed_at = now(), outcome = :o WHERE a.run_id = :r "
                "AND a.consumed_at IS NULL AND NOT EXISTS (SELECT 1 FROM workflow_step s WHERE s.id = a.step_id "
                "AND s.state IN ('ready', 'running', 'waiting', 'needs_human')) "
                "RETURNING id, run_id, signal_id, step_id, step_key, sha, approver_id"
            ),
            {"r": run_id, "o": EXPIRED},
        )
        .mappings()
        .all()
    )
    if rows:
        with Session(bind=c) as s:
            for row in rows:
                audit.record(
                    s, action="automation.reprepare.expired", target_type=ENTITY, target_id=str(row["id"]),
                    result="failure", principal_type="worker", auth_method="none", run_id=UUID(str(row["run_id"])),
                    step_id=UUID(str(row["step_id"])), authority_ref=f"run_signal:{row['signal_id']}",
                    after={"run_id": str(row["run_id"]), "step_key": row["step_key"], "sha": row["sha"],
                           "approver": str(row["approver_id"]), "signal_id": str(row["signal_id"]),
                           "outcome": EXPIRED},
                )  # fmt: skip
    return [str(r["id"]) for r in rows]


def authorize(
    c: Connection,
    *,
    run_id: str,
    signal_id: str,
    step_id: str,
    step_key: str,
    sha: str,
    approver_id: str,
) -> str:
    """Record the one-shot authorization and its audit row, in the signal's transaction. A void authorization of
    the run (its step closed) is expired first, so it does not block this one."""
    expire_stale(c, run_id)
    aid = new_id()
    c.execute(
        text(
            "INSERT INTO automation_reprepare (id, run_id, signal_id, step_id, step_key, sha, approver_id) "
            "VALUES (:i, :r, :s, :st, :k, :sha, :a)"
        ),
        {
            "i": aid,
            "r": run_id,
            "s": signal_id,
            "st": step_id,
            "k": step_key,
            "sha": sha,
            "a": approver_id,
        },
    )
    with Session(bind=c) as s:
        audit.record(
            s, action="automation.reprepare.authorized", target_type=ENTITY, target_id=aid, actor_id=UUID(approver_id),
            principal_type="human", auth_method="password+totp", run_id=UUID(run_id), step_id=UUID(step_id),
            after={"run_id": run_id, "step_key": step_key, "sha": sha, "approver": approver_id, "signal_id": signal_id},
        )  # fmt: skip
    return aid


def take(c: Connection, run_id: str, *, step_id: str, attempt: int) -> Authorization | None:
    """Consume the run's pending authorization for ``step_id`` (one-shot: the row is marked used before any git
    contact), only while attempt ``attempt`` of that step still holds its lease in the database (``running``, same
    attempt, lease not expired): an attempt that lost its step consumes nothing (PMR-2). Void authorizations of the
    run are expired first."""
    expire_stale(c, run_id)
    row = (
        c.execute(
            text(
                "UPDATE automation_reprepare a SET consumed_at = now() WHERE a.run_id = :r AND a.step_id = :s "
                "AND a.consumed_at IS NULL AND EXISTS (SELECT 1 FROM workflow_step s WHERE s.id = :s "
                "AND s.run_id = :r AND s.state = 'running' AND s.attempt = :a AND s.lease_expires_at > now()) "
                "RETURNING id, run_id, signal_id, step_key, sha, approver_id"
            ),
            {"r": run_id, "s": step_id, "a": attempt},
        )
        .mappings()
        .first()
    )
    if row is None:
        return None
    return Authorization(
        id=str(row["id"]), run_id=str(row["run_id"]), signal_id=str(row["signal_id"]),
        step_key=row["step_key"], sha=row["sha"], approver_id=str(row["approver_id"]),
    )  # fmt: skip


def finish(
    c: Connection,
    auth: Authorization,
    *,
    ok: bool,
    outcome: str,
    recorded_digest: str | None = None,
    tree_digest: str | None = None,
    quarantined: str | None = None,
) -> None:
    """Record what the consumed authorization led to, on its row and in the audit trail (with the cached copy moved
    aside on a digest mismatch, when there was one: PMR-6)."""
    c.execute(
        text("UPDATE automation_reprepare SET outcome = :o WHERE id = :i"),
        {"i": auth.id, "o": outcome[:500]},
    )
    with Session(bind=c) as s:
        audit.record(
            s, action="automation.reprepare." + ("used" if ok else "refused"), target_type=ENTITY,
            target_id=auth.id, result="success" if ok else "failure", principal_type="worker", auth_method="none",
            run_id=UUID(auth.run_id), authority_ref=f"run_signal:{auth.signal_id}",
            after={"run_id": auth.run_id, "step_key": auth.step_key, "sha": auth.sha, "approver": auth.approver_id,
                   "signal_id": auth.signal_id, "outcome": outcome[:200], "recorded_tree_digest": recorded_digest,
                   "tree_digest": tree_digest}
            | ({"quarantined_checkout": quarantined} if quarantined else {}),
        )  # fmt: skip
