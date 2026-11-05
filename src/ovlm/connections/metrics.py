"""Credential store metrics (security-model.md 4.4 expiry warnings; review CS-4). Worker only. No ids or names as
labels: the log line of the validation job names the credential."""

from __future__ import annotations

from prometheus_client import Gauge

from ovlm.observability.metrics import REGISTRY

CREDENTIALS_EXPIRING = Gauge(
    "ovlm_credentials_expiring",
    "Active application credentials by remaining validity (effective expiry: the earlier of the uploaded and the "
    "Keystone-reported one): within=expired|7d|30d",
    ["within"],
    registry=REGISTRY,
)
CREDENTIALS_FAILING = Gauge(
    "ovlm_credentials_failing_validation",
    "Active credentials whose last validation failed (no new run uses them)",
    registry=REGISTRY,
)
KEK_UNKNOWN = Gauge(
    "ovlm_credentials_unknown_kek",
    "Pending or active credentials wrapped to a key this worker does not hold (rotation order: worker first)",
    registry=REGISTRY,
)
