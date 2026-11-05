"""Review IS-1 part 4 (docs/reviews/review-inventory-sync-host-keys.md): at the first SSH to blue (W1
``quiesce_old``, before the outage starts) the worker re-reads the live ``managed_vm`` row and refuses unless the
host key is confirmed, its fingerprint is the plan's, and the confirmer is an active user. The run parks
``needs_human`` with nothing done on blue: no quiesce, no ``downtime_started_at``, no restore."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from ovlm.inventory.ids import uuid7
from tests.integration.renewal.conftest import World, explain, to_cutover
from tests.integration.renewal.test_failures import parked

OTHER = "SHA256:" + "B" * 43


def _new_fingerprint(w: World) -> None:
    # the owner rewrites the fingerprint: the trigger clears the confirmation (registry_0002)
    w.x("UPDATE managed_vm SET ssh_host_key_fingerprint = :f WHERE id = :v", f=OTHER, v=w.ids["vm"])


def _forged_and_confirmed(w: World) -> None:
    # a row confirmed for another key than the plan pinned (only the owner can write this now)
    w.x("UPDATE managed_vm SET ssh_host_key_fingerprint = :f WHERE id = :v", f=OTHER, v=w.ids["vm"])
    w.x(
        "UPDATE managed_vm SET host_key_confirmed_by = :u, host_key_confirmed_at = now() WHERE id = :v",
        u=w.users["op"],
        v=w.ids["vm"],
    )


def _confirmer_disabled(w: World) -> None:
    uid = str(uuid7())
    w.x("INSERT INTO app_user (id, username, state, password_hash, created_via, disabled_at) "
        "VALUES (:i, 'user-gone', 'disabled', 'x', 'cli', now())", i=uid)  # fmt: skip
    w.x("UPDATE managed_vm SET host_key_confirmed_by = :u WHERE id = :v", u=uid, v=w.ids["vm"])


def _confirmer_unknown(w: World) -> None:
    w.x(
        "UPDATE managed_vm SET host_key_confirmed_by = :u WHERE id = :v",
        u=str(uuid7()),
        v=w.ids["vm"],
    )


@pytest.mark.parametrize(
    ("tamper", "problem"),
    [
        (_new_fingerprint, "not confirmed"),
        (_forged_and_confirmed, "not the one the plan pinned"),
        (_confirmer_disabled, "is disabled"),
        (_confirmer_unknown, "not confirmed by a known user"),
    ],
)
def test_w1_refuses_blue_when_the_live_host_key_row_is_not_trusted(
    world: World, tamper: Callable[[World], None], problem: str
) -> None:
    w = world
    to_cutover(w)
    tamper(w)
    w.drive()
    r = parked(w, "blue_host_key_untrusted")
    assert r["downtime_started_at"] is None, explain(w)  # refused before the outage
    [w1] = [s for s in w.steps() if s["step_key"] == "quiesce_old"]
    assert any(problem in p for p in w1["error"]["problems"]), w1["error"]
    assert not [c for c in w.guest.calls if c[0] == "quiesce"]  # nothing ran on blue
    step_keys = w.keys()
    assert "stop_old" not in step_keys and "boot_old" not in step_keys


def test_w1_proceeds_when_the_live_row_is_the_plans_confirmed_key(world: World) -> None:
    w = world
    to_cutover(w)
    w.drive(until="stop_old")
    assert w.run()["downtime_started_at"] is not None, explain(w)
    assert [c for c in w.guest.calls if c[0] == "quiesce"]
