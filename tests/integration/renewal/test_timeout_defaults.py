"""Roadmap P1-8 on the worker side: the plan records the renewal values it was created with; a worker whose own values
differ says so at admission, naming the keys (docs/timeouts.md)."""

from __future__ import annotations

import logging

import pytest

from ovlm.renewal.config import RenewalConfig
from tests.integration.renewal.conftest import CFG, World


def _admission_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "differ from the plan's record" in r.getMessage()]


def test_plan_records_the_values_the_worker_enforces(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    w = world
    rec = w.q(
        "SELECT resolved -> 'renewal_settings' AS r FROM renewal_plan WHERE id = :p",
        p=w.ids["plan"],
    )
    assert rec[0]["r"]["values"] == CFG.values()
    with caplog.at_level(logging.WARNING, logger="ovlm.renewal"):
        w.start()
        w.drive(until="claim_resources")
    assert w.run()["state"] == "running"
    assert not _admission_warnings(caplog)


def test_worker_with_other_values_warns_at_admission(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    w = world
    w.make_engine(
        RenewalConfig(**{**CFG.__dict__, "timeouts": {**CFG.timeouts, "fip_status": 45.0}})
    )
    with caplog.at_level(logging.WARNING, logger="ovlm.renewal"):
        w.start()
        w.drive(until="claim_resources")
    (warning,) = _admission_warnings(caplog)
    assert warning.changed_keys == ["renewal.timeouts.fip_status"]  # type: ignore[attr-defined]
    # a warning, not a refusal: the worker enforces its own values
    assert w.run()["state"] == "running"
