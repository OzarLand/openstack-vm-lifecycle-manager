"""Why an inventory sync failed, as a **fixed code** (review IS-4). Api-safe: no OpenStack import.

Viewers read sync records (``GET /projects/{id}/syncs``, ``GET /syncs/{id}``) and why a sync run ended
(``runs[].end_reason``). Exception text from the SDK or keystoneauth carries Keystone URLs, HTTP status lines and
response fragments; redaction removes registered secrets, not those. So:

* ``sync_run.error`` stores ``{"code": <code>}`` only;
* the step's failure ``reason`` (shown as ``end_reason``) is the code;
* the redacted exception text goes to the worker log and to the step error's ``detail`` (``workflow_step.error``,
  not served by the api), nowhere else.

Records written before IS-4 (``{"type": ..., "message": ...}``, reasons ``"Type: message"``) are mapped to a code
when they are read (:func:`public_error`, :func:`public_reason`), so their text is not served either.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CREDENTIAL_UNAVAILABLE = "credential_unavailable"
"""No usable read credential: none, not validated, failed validation, expired, rebound, sealed to an unknown key,
or this worker has no credential store key."""
CLIENT_SETUP_FAILED = "client_setup_failed"
"""The read client could not be built from the credential (configuration, CA file, ...): recorded, not retried."""
AUTH_FAILED = "auth_failed"
"""Keystone refused the read credential or could not be reached for a token."""
PROJECT_MISMATCH = "project_mismatch"
"""The token is scoped to another OpenStack project than the connection's: nothing synced."""
CLOUD_ERROR = "cloud_error"
"""An OpenStack read failed during the sync: nothing in the inventory changed."""
INTERRUPTED = "interrupted"
"""The worker stopped during the sync."""
SYNC_ALREADY_RUNNING = "sync_already_running"
"""Another sync of this project holds the lock (retried)."""
WORKER_ERROR = "worker_error"
"""An unexpected error in the worker (retried)."""
OTHER = "other"
"""A reason this release does not classify (shown instead of its text)."""

CODES = frozenset(
    {
        CREDENTIAL_UNAVAILABLE, CLIENT_SETUP_FAILED, AUTH_FAILED, PROJECT_MISMATCH, CLOUD_ERROR,
        INTERRUPTED, SYNC_ALREADY_RUNNING, WORKER_ERROR, OTHER,
        # admission and engine reasons of a sync run (fixed strings, no exception text)
        "no_project_connection", "project_not_found", "project_disabled",
    }
)  # fmt: skip

#: Error types written before IS-4.
_LEGACY_TYPES = {
    "CredentialUnavailable": CREDENTIAL_UNAVAILABLE,
    "AuthenticationFailed": AUTH_FAILED,
    "ProjectMismatch": PROJECT_MISMATCH,
    "Interrupted": INTERRUPTED,
}
#: Fixed engine and admission reasons of a sync run, written as text.
_FIXED = {
    "the run names no project connection": "no_project_connection",
    "no such project connection": "project_not_found",
    "the project connection is disabled": "project_disabled",
    "another sync of this project is running": SYNC_ALREADY_RUNNING,
    "aborted before admission": "aborted",
}


def public_error(error: Mapping[str, Any] | None) -> dict[str, str] | None:
    """A ``sync_run.error`` as viewers see it: ``{"code": ...}`` and nothing else."""
    if not error:
        return None
    code = error.get("code")
    if code in CODES:
        return {"code": str(code)}
    return {"code": _LEGACY_TYPES.get(str(error.get("type")), CLOUD_ERROR)}


def public_reason(reason: str | None) -> str | None:
    """Why a sync run ended, as viewers see it: a code, never exception text."""
    if reason is None:
        return None
    if reason in CODES or reason in _FIXED.values():
        return reason
    if reason in _FIXED:
        return _FIXED[reason]
    head = reason.split(":", 1)[0].strip()
    if head in _LEGACY_TYPES:
        return _LEGACY_TYPES[head]
    return OTHER
