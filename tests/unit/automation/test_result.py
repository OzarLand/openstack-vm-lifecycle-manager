"""``ovlm.result/1`` parsing: guest output is untrusted (security-model 6.4)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ovlm.automation.result import ResultError, parse_result
from ovlm.automation.types import Classification, Phase


def doc(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": "ovlm.result/1",
        "phase": "healthcheck",
        "ok": True,
        "changed": False,
        "classification": "ok",
        "facts": {"device": "/dev/disk/by-id/x", "n": 3, "flag": True, "none": None},
        "checks": [{"name": "svc", "ok": True, "detail": "up", "observed": 200, "expected": 200}],
        "message": "fine",
    }
    base.update(over)
    return base


def parse(d: Any, phase: Phase = Phase.HEALTHCHECK, **kw: Any) -> Any:
    raw = d if isinstance(d, bytes) else json.dumps(d).encode()
    return parse_result(raw, phase, **kw)


def test_valid_document() -> None:
    r = parse(doc())
    assert r.ok and r.classification is Classification.OK and r.facts["n"] == 3
    assert r.checks[0].observed == "200"
    assert r.as_json()["reported_by"] == "guest"


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"not json",
        b"[]",
        b'"str"',
        b"\xff\xfe\x00",
        b'{"schema":"ovlm.result/1","schema":"ovlm.result/1"}',  # duplicate key
        b'{"schema":"ovlm.result/1","phase":"healthcheck","ok":NaN,"classification":"ok"}',
        b'{"schema":"ovlm.result/1","phase":"healthcheck","ok":true,"classification":"ok","facts":{"a":Infinity}}',
        b"[" * 200000 + b"]" * 200000,  # recursion bomb
        b"{" * 5000,
    ],
)
def test_malformed_json_is_refused(bad: bytes) -> None:
    with pytest.raises(ResultError):
        parse(bad)


@pytest.mark.parametrize(
    "over",
    [
        {"schema": "ovlm.result/2"},
        {"phase": "configure"},  # a result for another phase
        {"ok": "true"},
        {"ok": 1},
        {"changed": "no"},
        {"classification": "great"},
        {"classification": "retryable"},  # ok=true with a failure class
        {"ok": False},  # ok=false with class ok
        {"facts": []},
        {"facts": {"bad key!": 1}},
        {"facts": {"k": {"nested": 1}}},
        {"facts": {"k": [{"x": 1}]}},
        {"facts": {"k": 2**80}},
        {"facts": {f"k{i}": i for i in range(65)}},
        {"facts": {"k": list(range(65))}},
        {"checks": "x"},
        {"checks": [{"name": "a"}]},
        {"checks": [{"name": "a", "ok": "yes"}]},
        {"checks": [{"name": "a", "ok": True, "extra": 1}]},
        {"checks": [{"name": "", "ok": True}]},
        {"checks": [{"name": "a", "ok": True}] * 65},
        {"checks": [{"name": "a", "ok": True, "observed": {"a": {"b": {"c": {"d": {"e": 1}}}}}}]},
        {"message": ["x"]},
        {"unexpected": "field"},
    ],
)
def test_schema_violations_are_refused(over: dict[str, Any]) -> None:
    with pytest.raises(ResultError):
        parse(doc(**over))


def test_missing_required_field() -> None:
    d = doc()
    del d["classification"]
    with pytest.raises(ResultError):
        parse(d)


def test_size_cap_checked_before_parsing() -> None:
    big = doc(message="x" * 70_000)
    with pytest.raises(ResultError, match="size cap"):
        parse(big)
    assert parse(doc(message="x" * 700), max_bytes=4096).message == "x" * 500  # message is trimmed


def test_control_characters_and_ansi_are_stripped() -> None:
    r = parse(doc(message="a\x1b[31mred\x00\x07 b", facts={"k": "v\x1b]0;title\x07w"}))
    assert "\x1b" not in r.message and "\x00" not in r.message and " " not in r.message
    assert "\x1b" not in r.facts["k"]


def test_long_strings_are_capped() -> None:
    r = parse(doc(facts={"k": "y" * 10_000}))
    assert len(r.facts["k"]) == 2048


def test_template_and_yaml_text_is_data_not_code() -> None:
    r = parse(
        doc(
            message="{{ lookup('pipe','id') }}",
            facts={"k": "!!python/object/apply:os.system ['id']"},
        )
    )
    assert r.message == "{{ lookup('pipe','id') }}"  # stored and shown escaped, never rendered


def test_failed_result_carries_its_class() -> None:
    r = parse(doc(ok=False, classification="needs_human"), phase=Phase.HEALTHCHECK)
    assert not r.ok and r.classification is Classification.NEEDS_HUMAN
