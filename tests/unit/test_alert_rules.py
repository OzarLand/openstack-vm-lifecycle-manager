"""The shipped Prometheus rule file stays in step with the code (roadmap P1-2, architecture.md section 6).

* Every ``ovlm_*`` metric an expression references is registered by an OVLM metrics module, under that exact sample
  name (``_total`` for counters), and every label it matches or groups by is one of the metric's labels (or a
  Prometheus target label).
* Every label value a matcher names is one the code can produce.
* Severity is ``page`` or ``ticket``; every alert has a ``runbook_url`` whose anchor is a heading of
  docs/operations.md; the two alerts paging is mandatory for page.
* With ``promtool`` on PATH (or ``OVLM_PROMTOOL``): ``promtool check rules`` and ``promtool test rules``.
"""

from __future__ import annotations

import importlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from prometheus_client import Counter, Histogram

from ovlm.observability.metrics import REGISTRY

ROOT = Path(__file__).parents[2]
RULES = ROOT / "deploy" / "prometheus" / "ovlm-alerts.yml"
RULE_TESTS = ROOT / "deploy" / "prometheus" / "ovlm-alerts.test.yml"
OPERATIONS = ROOT / "docs" / "operations.md"
SRC = ROOT / "src" / "ovlm"
RUNBOOK_BASE = (
    "https://github.com/OzarLand/openstack-vm-lifecycle-manager/blob/main/docs/operations.md#"
)

#: Labels Prometheus adds to every scraped series.
TARGET_LABELS = {"job", "instance"}
#: Non-OVLM series the rules may use.
FOREIGN_METRICS = {"up"}
#: Paging is mandatory for these (architecture.md section 6).
MANDATORY_PAGES = {"OvlmPostStartFailure", "OvlmNeedsHumanInWindow"}

_SELECTOR = re.compile(r"\b([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\{([^}]*)\}")
_MATCHER = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*"([^"]*)"')
_BY = re.compile(r"\b(?:by|without|on|ignoring)\s*\(([^)]*)\)")


def _alerts() -> list[dict[str, Any]]:
    doc = yaml.safe_load(RULES.read_text())
    return [r for g in doc["groups"] for r in g["rules"] if "alert" in r]


def _ovlm_metrics() -> dict[str, set[str]]:
    """Sample name -> label names of every metric registered by an ``ovlm.**.metrics`` module."""
    for path in SRC.rglob("metrics.py"):
        importlib.import_module(".".join(path.relative_to(SRC.parent).with_suffix("").parts))
    out: dict[str, set[str]] = {}
    for collector, names in REGISTRY._collector_to_names.items():
        labels = set(getattr(collector, "_labelnames", ()))
        base = getattr(collector, "_name", None)
        for name in names:
            # a counter or histogram is exposed only under its suffixed names (_total, _bucket, ...)
            if name == base and isinstance(collector, Counter | Histogram):
                continue
            out[name] = labels
    return out


def _known_values() -> dict[str, set[str]]:
    """Label values the code produces, for labels whose values are computed rather than written as literals."""
    from ovlm.connections.validation import EXPIRY_WARN_DAYS
    from ovlm.renewal import downtime
    from ovlm.renewal.definition import ORDER, RESTORE_ORDER, phase_of

    return {
        "phase": {phase_of(k) for k in (*ORDER, *RESTORE_ORDER)},
        "kind": {downtime.WINDOW, downtime.RESTORE},
        "within": {"expired", *(f"{d}d" for d in EXPIRY_WARN_DAYS)},
    }


def _literal_in_source(value: str) -> bool:
    needle = f'"{value}"'
    return any(needle in p.read_text() for p in SRC.rglob("*.py"))


def test_rule_file_is_well_formed() -> None:
    alerts = _alerts()
    names = [a["alert"] for a in alerts]
    assert len(names) == len(set(names)), "duplicate alert names"
    for a in alerts:
        assert a["labels"]["severity"] in ("page", "ticket"), a["alert"]
        assert a["annotations"]["summary"], a["alert"]
        assert a["annotations"]["runbook_url"].startswith(RUNBOOK_BASE), a["alert"]
    pages = {a["alert"] for a in alerts if a["labels"]["severity"] == "page"}
    assert pages >= MANDATORY_PAGES


def test_every_metric_and_label_in_the_rules_exists_in_the_code() -> None:
    registered = _ovlm_metrics()
    known = _known_values()
    problems: list[str] = []
    for a in _alerts():
        expr, name = a["expr"], a["alert"]
        used = set(re.findall(r"\b(ovlm_[a-z0-9_]+)\b", expr))
        assert used or "up{" in expr, f"{name}: no metric"
        for metric in used - registered.keys():
            problems.append(f"{name}: {metric} is not registered by any ovlm metrics module")
        for metric, body in _SELECTOR.findall(expr):
            if metric not in registered:
                if metric not in FOREIGN_METRICS:
                    problems.append(f"{name}: unknown selector {metric}")
                continue
            for label, _op, value in _MATCHER.findall(body):
                if label in TARGET_LABELS:
                    continue
                if label not in registered[metric]:
                    problems.append(f"{name}: {metric} has no label {label}")
                    continue
                for v in value.split("|"):
                    ok = v in known[label] if label in known else _literal_in_source(v)
                    if not ok:
                        problems.append(f"{name}: no code produces {metric}{{{label}={v!r}}}")
        labels_in_expr = set().union(*(registered.get(m, set()) for m in used)) | TARGET_LABELS
        for group in _BY.findall(expr):
            for label in filter(None, (s.strip() for s in group.split(","))):
                if label not in labels_in_expr:
                    problems.append(f"{name}: groups by unknown label {label}")
    assert not problems, "\n".join(problems)


def test_the_checker_catches_drift() -> None:
    """A renamed metric or label would be reported (guards the regexes above)."""
    registered = _ovlm_metrics()
    assert "ovlm_post_start_failures_total" in registered
    assert "ovlm_post_start_failures" not in registered  # counters only as _total
    assert registered["ovlm_runs_needing_attention"] == {"phase", "reason"}
    assert registered["ovlm_renewal_downtime_open_seconds"] == {"kind"}
    assert _MATCHER.findall('phase="window", reason=~"a|b"') == [
        ("phase", "=", "window"),
        ("reason", "=~", "a|b"),
    ]
    assert not _literal_in_source("no_such_needs_human_reason_xyz")


def test_every_runbook_anchor_is_a_heading_of_the_operations_guide() -> None:
    anchors = {
        re.sub(r"[^a-z0-9 -]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
        for line in OPERATIONS.read_text().splitlines()
        if line.startswith("#")
    }
    missing = [
        a["alert"]
        for a in _alerts()
        if a["annotations"]["runbook_url"].removeprefix(RUNBOOK_BASE) not in anchors
    ]
    assert not missing, f"no runbook heading in docs/operations.md for {missing}"


def _promtool() -> str | None:
    return os.environ.get("OVLM_PROMTOOL") or shutil.which("promtool")


@pytest.mark.skipif(_promtool() is None, reason="promtool not on PATH (set OVLM_PROMTOOL)")
@pytest.mark.parametrize(
    "args", [["check", "rules", str(RULES)], ["test", "rules", str(RULE_TESTS)]]
)
def test_promtool(args: list[str]) -> None:
    tool = _promtool()
    assert tool is not None
    out = subprocess.run([tool, *args], capture_output=True, text=True, timeout=120, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
