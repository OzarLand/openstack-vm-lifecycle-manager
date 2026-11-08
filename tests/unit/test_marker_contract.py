"""Defect AB: the data marker must travel under the contract's name from the playbooks to W1, W6 and W8.

automation-contract 3.7 and the reference roles report ``facts.marker_sha256``; OVLM used to read
``facts.marker_checksum``, so with a real repository W1 recorded no marker and W6/W8 silently skipped the comparison.
The renewal test doubles spoke OVLM's spelling, so CI never saw it. These tests tie OVLM's key to the contract text
and to the roles' own ``ovlm_facts``, and run contract-shaped results through the step code (no database: the W1
evidence read is answered by a fake connection).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml

from ovlm.renewal.ports import PhaseResult
from ovlm.renewal.steps_window import (
    MARKER_FACT,
    DataAttachGreen,
    HealthcheckGreen,
    QuiesceOld,
    w1_marker,
)
from ovlm.workflow.contract import Done, ErrorClass, Fail, StepContext, Wait

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
CONTRACT = ROOT / "docs" / "automation-contract.md"
DOUBLES = ROOT / "tests" / "integration" / "renewal" / "doubles.py"
SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
VOLUME = {"volume_id": "vol-1", "mount_point": "/srv/data", "fs_type": "ext4", "fs_uuid": "u-1"}


# --- static: one name everywhere ---------------------------------------------------------------------------------


def _contract_result_example() -> dict[str, Any]:
    text = CONTRACT.read_text()
    section = text[text.index("### 3.7 Result JSON") :]
    block = re.search(r"```json\n(.*?)```", section, re.S)
    assert block, "no result.json example in contract 3.7"
    return dict(json.loads(block.group(1)))


def _role_fact_keys(role: str) -> set[str]:
    """Keys of every ``ovlm_facts`` the role sets: literal dicts, and ``combine({...})`` expressions."""
    keys: set[str] = set()
    for task in yaml.safe_load((ROLES / role / "tasks" / "main.yml").read_text()):
        facts = (task.get("ansible.builtin.set_fact") or {}).get("ovlm_facts")
        if isinstance(facts, dict):
            keys |= set(facts)
        elif isinstance(facts, str):
            keys |= set(re.findall(r"'([a-z_0-9]+)':", facts))
    return keys


def test_ovlm_reads_the_marker_under_the_contracts_name() -> None:
    assert MARKER_FACT in _contract_result_example()["facts"]


@pytest.mark.parametrize("role", ["quiesce", "data_volume", "healthcheck"])
def test_every_reference_role_reports_the_marker_under_the_key_ovlm_reads(role: str) -> None:
    keys = _role_fact_keys(role)
    assert keys, f"no ovlm_facts found in role {role}"
    assert MARKER_FACT in keys, (role, sorted(keys))


def test_the_renewal_doubles_speak_the_contracts_name() -> None:
    src = DOUBLES.read_text()
    assert f'"{MARKER_FACT}": self.marker' in src
    assert '"marker_checksum":' not in src, (
        "a double with its own field name hides a contract mismatch"
    )


# --- behaviour: contract-shaped results through W1, W6 and W8 ----------------------------------------------------


class _Conn:
    def __init__(self, ctx: _Ctx) -> None:
        self.ctx = ctx

    def execute(self, *_: Any, **__: Any) -> Any:
        return SimpleNamespace(scalar=lambda: self.ctx.w1_evidence)


class _Ctx:
    """Just enough StepContext for ``verify``: W1's stored evidence and the previous attempt's evidence."""

    def __init__(self, w1_evidence: Mapping[str, Any] | None = None) -> None:
        self.w1_evidence = dict(w1_evidence) if w1_evidence is not None else None
        self.run = SimpleNamespace(id="run-1")
        self.previous_evidence: Mapping[str, Any] | None = None

    @contextmanager
    def read(self) -> Iterator[_Conn]:
        yield _Conn(self)


def _w1_marker(ctx: _Ctx) -> str | None:
    return w1_marker(cast(StepContext, ctx))


def _step(
    cls: type, ctx: _Ctx, result: PhaseResult, *, data_volume: Mapping[str, Any] | None = VOLUME
) -> Any:
    cfg = SimpleNamespace(healthcheck_max_attempts=1, healthcheck_interval=0)
    step = cls(SimpleNamespace(cfg=cfg))
    step.safe_truth = lambda ctx: {}  # the closed table's probe is not under test here
    m = step.memo(ctx)
    m["resolved"] = {"data_volume": data_volume}
    m["result"] = result
    return step


def _contract_result(**facts: Any) -> PhaseResult:
    """A result as contract 3.7 shapes it, with the example's facts (placeholders filled in)."""
    example = _contract_result_example()["facts"]
    shaped = {k: (SHA if k == MARKER_FACT else "value") for k in example}
    return PhaseResult("ok", "ok", {**shaped, **facts})


def _w1_evidence(result: PhaseResult) -> Mapping[str, Any]:
    ctx = _Ctx()
    out = _step(QuiesceOld, ctx, result).verify(ctx, {})
    assert isinstance(out, Done), out
    return out.evidence


def test_w1_records_the_marker_a_contract_shaped_quiesce_reports() -> None:
    ev = _w1_evidence(_contract_result())
    assert ev["marker_checksum"] == SHA
    assert _w1_marker(_Ctx(ev)) == SHA


@pytest.mark.parametrize("facts", [{MARKER_FACT: None}, {MARKER_FACT: ""}], ids=["null", "empty"])
def test_w1_refuses_a_quiesce_without_a_marker(facts: dict[str, Any]) -> None:
    ctx = _Ctx()
    out = _step(QuiesceOld, ctx, _contract_result(**facts)).verify(ctx, {})
    assert isinstance(out, Fail), out
    assert (
        out.error_class is ErrorClass.NEEDS_HUMAN and out.needs_human_reason == "quiesce_no_marker"
    )
    assert out.detail["expected_fact"] == MARKER_FACT


def test_w1_refuses_a_repo_that_still_spells_the_marker_its_own_way() -> None:
    res = PhaseResult("ok", "quiesced", {"marker_checksum": SHA, "was_mounted": True})
    ctx = _Ctx()
    out = _step(QuiesceOld, ctx, res).verify(ctx, {})
    assert isinstance(out, Fail) and out.needs_human_reason == "quiesce_no_marker", out


def test_w1_without_a_data_volume_needs_no_marker() -> None:
    ctx = _Ctx()
    out = _step(QuiesceOld, ctx, PhaseResult("ok", "quiesced", {}), data_volume=None).verify(
        ctx, {}
    )
    assert isinstance(out, Done) and out.evidence["marker_checksum"] is None


def test_w1_marker_falls_back_to_the_raw_facts_of_an_older_w1_record() -> None:
    """A run that passed W1 before this fix stored ``marker_checksum: None`` next to the raw facts."""
    assert _w1_marker(_Ctx({"marker_checksum": None, "facts": {MARKER_FACT: SHA}})) == SHA
    assert _w1_marker(_Ctx(None)) is None


def test_w6_passes_on_the_same_marker_and_says_it_compared() -> None:
    ctx = _Ctx(_w1_evidence(_contract_result()))
    out = _step(DataAttachGreen, ctx, _contract_result(fs_uuid="u-1")).verify(ctx, {})
    assert isinstance(out, Done), out
    assert out.evidence["marker_comparison"] == "equal"


def test_w6_fails_on_a_different_marker() -> None:
    ctx = _Ctx(_w1_evidence(_contract_result()))
    out = _step(
        DataAttachGreen, ctx, _contract_result(fs_uuid="u-1", **{MARKER_FACT: "0" * 64})
    ).verify(ctx, {})
    assert isinstance(out, Fail) and out.needs_human_reason == "data_attach_mismatch", out
    assert out.detail["problems"] == ["marker checksum differs from W1"]


def test_w6_fails_when_green_reports_no_marker() -> None:
    ctx = _Ctx(_w1_evidence(_contract_result()))
    out = _step(
        DataAttachGreen, ctx, _contract_result(fs_uuid="u-1", **{MARKER_FACT: None})
    ).verify(ctx, {})
    assert isinstance(out, Fail) and out.needs_human_reason == "data_attach_mismatch", out


def test_w8_passes_on_the_same_marker_and_says_it_compared() -> None:
    ctx = _Ctx(_w1_evidence(_contract_result()))
    out = _step(HealthcheckGreen, ctx, _contract_result()).verify(ctx, {})
    assert isinstance(out, Done), out
    assert out.evidence["marker_checksum"] == SHA and out.evidence["marker_comparison"] == "equal"


def test_w8_never_passes_a_healthy_green_with_a_different_marker() -> None:
    ctx = _Ctx(_w1_evidence(_contract_result()))
    step = _step(HealthcheckGreen, ctx, _contract_result(**{MARKER_FACT: "0" * 64}))
    step.d.cfg.healthcheck_max_attempts = 2
    first = step.verify(ctx, {})
    assert isinstance(first, Wait), first  # retried like an unhealthy answer, never Done
    ctx.previous_evidence = first.evidence
    last = step.verify(ctx, {})
    assert isinstance(last, Fail) and last.needs_human_reason == "healthcheck_exhausted", last
    assert last.detail["marker_comparison"] == "differs"
