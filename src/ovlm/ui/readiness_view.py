"""What the VM details page shows about rebuild readiness (E4-1): the latest assessment, any run still in flight,
and a plain rendering of each check's evidence. Reads through ``ovlm.readiness.service``, like the REST API."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from ovlm.readiness import service as readiness
from ovlm.ui.support import templates

CATEGORY_LABELS = {
    "configuration-reproducibility": "Configuration reproducibility",
    "persistent-data-separation": "Persistent data separation",
    "dependencies": "Dependencies",
    "validation-capability": "Validation capability",
    "external-services": "External services",
}
LEVEL_TEXT = {
    "ready": "Ready",
    "partially-ready": "Partially ready",
    "not-ready": "Not ready",
}
OPEN_RUN_STATES = ("requested", "running", "needs_human")


def evidence_lines(evidence: Any) -> list[tuple[str, str]]:
    """Evidence as ``(label, text)`` rows: scalars as text, lists joined, nested objects as compact JSON."""
    if not isinstance(evidence, dict):
        return [("value", str(evidence))] if evidence not in (None, {}) else []
    rows: list[tuple[str, str]] = []
    for key, value in evidence.items():
        if isinstance(value, list) and all(not isinstance(v, (dict, list)) for v in value):
            text = ", ".join(str(v) for v in value) or "none"
        elif isinstance(value, (dict, list)):
            text = json.dumps(value, sort_keys=True, ensure_ascii=False)
        elif value is None:
            text = "none"
        elif isinstance(value, bool):
            text = "yes" if value else "no"
        else:
            text = str(value)
        rows.append((str(key).replace("_", " "), text))
    return rows


templates.env.filters["evidence_lines"] = evidence_lines


def readiness_context(db: Session, managed_vm_id: UUID) -> dict[str, Any]:
    latest = readiness.latest_assessment(db, managed_vm_id)
    runs = readiness.runs_of(db, managed_vm_id, limit=3)
    in_flight = next((r for r in runs if r["state"] in OPEN_RUN_STATES), None)
    # A newer run that ended without an assessment (failed or rejected) is worth saying; an old one is not.
    newest_ended = (
        runs[0] if runs and runs[0]["state"] in ("failed", "rejected", "cancelled") else None
    )
    groups: list[dict[str, Any]] = []
    if latest:
        for cat, label in CATEGORY_LABELS.items():
            checks = [c for c in latest["checks"] if c["category"] == cat]
            if checks:
                groups.append({"label": label, "checks": checks})
    return {
        "latest": latest,
        "groups": groups,
        "in_flight": in_flight,
        "failed_run": newest_ended,
        "level_text": LEVEL_TEXT,
    }
