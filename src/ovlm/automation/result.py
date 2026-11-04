"""Strict parsing of ``ovlm.result/1`` (automation-contract.md 3.7, security-model.md 6.4).

The file is written on the controller but its content is derived from guest output, so it is **untrusted**: size
cap, safe JSON parser (no YAML, no eval, never rendered through Jinja), allowlisted fields, bounded depth/counts,
control characters stripped, duplicate keys and non-finite numbers refused, internal consistency enforced.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from ovlm.automation.types import Classification, Phase

SCHEMA = "ovlm.result/1"
DEFAULT_MAX_BYTES = (
    64 * 1024
)  # contract 3.7 (ASSUMPTION); security-model 6.4 allows up to 1 MiB per step
MAX_FACTS = 64
MAX_CHECKS = 64
MAX_STR = 2048
MAX_LIST = 64
MAX_MESSAGE = 500
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")
_TOP_KEYS = {"schema", "phase", "ok", "changed", "classification", "facts", "checks", "message"}
_CHECK_KEYS = {"name", "ok", "detail", "observed", "expected"}


class ResultError(ValueError):
    """The result document is missing or invalid. ``reason`` is a short, secret-free code-like string."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    observed: str | None = None
    expected: str | None = None


@dataclass(frozen=True)
class ValidatedResult:
    phase: Phase
    ok: bool
    changed: bool
    classification: Classification
    facts: dict[str, Any] = field(default_factory=dict)
    checks: tuple[Check, ...] = ()
    message: str = ""

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "phase": self.phase.value,
            "ok": self.ok,
            "changed": self.changed,
            "classification": self.classification.value,
            "facts": self.facts,
            "checks": [
                {k: v for k, v in c.__dict__.items() if v is not None or k in ("detail",)}
                for c in self.checks
            ],
            "message": self.message,
            "reported_by": "guest",  # labelled as such wherever it is displayed (security-model 6.4)
        }


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ResultError("duplicate key")
        out[key] = value
    return out


def _reject_constant(_name: str) -> Any:
    raise ResultError("non-finite number")


def _clean(value: str, limit: int = MAX_STR) -> str:
    return _CONTROL_RE.sub("", value)[:limit]


def _scalar(value: Any, what: str) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise ResultError(f"{what}: integer out of range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ResultError(f"{what}: non-finite number")
        return value
    if isinstance(value, str):
        return _clean(value)
    raise ResultError(f"{what}: unsupported type")


def _fact_value(value: Any, name: str) -> Any:
    if isinstance(value, list):
        if len(value) > MAX_LIST:
            raise ResultError(f"fact {name}: list too long")
        return [_scalar(v, f"fact {name}") for v in value]
    return _scalar(value, f"fact {name}")


def _within_depth(value: Any, limit: int) -> bool:
    stack = [(value, 0)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, dict | list):
            if depth >= limit:
                return False
            stack.extend((v, depth + 1) for v in (cur.values() if isinstance(cur, dict) else cur))
    return True


def _opt_text(value: Any, what: str) -> str | None:
    """``observed``/``expected`` may be any small JSON value; it is kept as (capped) text, never interpreted."""
    if value is None:
        return None
    if isinstance(value, bool | int | float):
        return str(_scalar(value, what))
    if isinstance(value, str):
        return _clean(value)
    if isinstance(value, dict | list) and _within_depth(value, 4):
        return _clean(json.dumps(value, sort_keys=True, ensure_ascii=True, default=str))
    raise ResultError(f"{what}: unsupported type")


def _check(raw: Any) -> Check:
    if not isinstance(raw, dict) or not _CHECK_KEYS.issuperset(raw):
        raise ResultError("check: unexpected shape")
    name, ok, detail = raw.get("name"), raw.get("ok"), raw.get("detail", "")
    if not isinstance(name, str) or not name or not isinstance(ok, bool):
        raise ResultError("check: name/ok invalid")
    if not isinstance(detail, str):
        raise ResultError("check: detail invalid")
    return Check(
        name=_clean(name, 128),
        ok=ok,
        detail=_clean(detail),
        observed=_opt_text(raw.get("observed"), "check observed"),
        expected=_opt_text(raw.get("expected"), "check expected"),
    )


def parse_result(
    raw: bytes, phase: Phase, *, max_bytes: int = DEFAULT_MAX_BYTES
) -> ValidatedResult:
    """Parse and validate ``raw``; raise :class:`ResultError` on anything unexpected."""
    if len(raw) > max_bytes:
        raise ResultError("result larger than the size cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ResultError("result is not UTF-8") from None
    try:
        doc = json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except ResultError:
        raise
    except (ValueError, RecursionError):
        raise ResultError("result is not valid JSON") from None
    if not isinstance(doc, dict):
        raise ResultError("result is not an object")
    if not _TOP_KEYS.issuperset(doc) or not {"schema", "phase", "ok", "classification"} <= set(doc):
        raise ResultError("unexpected or missing top-level fields")
    if doc["schema"] != SCHEMA:
        raise ResultError("unknown schema")
    if doc["phase"] != phase.value:
        raise ResultError("result is for another phase")
    ok, changed = doc["ok"], doc.get("changed", False)
    if not isinstance(ok, bool) or not isinstance(changed, bool):
        raise ResultError("ok/changed must be booleans")
    try:
        classification = Classification(doc["classification"])
    except ValueError:
        raise ResultError("unknown classification") from None
    if ok != (classification is Classification.OK):
        raise ResultError("ok and classification disagree")
    facts_raw = doc.get("facts", {})
    if not isinstance(facts_raw, dict) or len(facts_raw) > MAX_FACTS:
        raise ResultError("facts must be a small object")
    facts: dict[str, Any] = {}
    for key, value in facts_raw.items():
        if not _KEY_RE.match(key):
            raise ResultError("fact name not allowed")
        facts[key] = _fact_value(value, key)
    checks_raw = doc.get("checks", [])
    if not isinstance(checks_raw, list) or len(checks_raw) > MAX_CHECKS:
        raise ResultError("checks must be a short list")
    message = doc.get("message", "")
    if not isinstance(message, str):
        raise ResultError("message must be a string")
    return ValidatedResult(
        phase=phase,
        ok=ok,
        changed=changed,
        classification=classification,
        facts=facts,
        checks=tuple(_check(c) for c in checks_raw),
        message=_clean(message, MAX_MESSAGE),
    )
