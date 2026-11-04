"""Map adapter errors to OVLM's retry classes (renewal-workflow.md section 2, "Retry class").

The values equal ``ovlm.workflow.ErrorClass`` (``retryable``, ``needs_human``, ``fatal``) so a step converts with
``ErrorClass(classify(exc).value)``; this module does not import the workflow package.

The table is ordered from the most specific class to the most general one; the first match wins. A step may be
stricter for its own context (W2 turns a 409 ``Instance is locked`` into needs_human at once, which is also the
default here), but should not be looser.

Fence loss (``ovlm.workflow.FenceLost``) is a ``BaseException`` and is deliberately not classified: only the engine
handles it.
"""

from __future__ import annotations

import enum

from ovlm.openstack import errors as e


class RetryClass(enum.StrEnum):
    RETRYABLE = "retryable"
    NEEDS_HUMAN = "needs_human"
    FATAL = "fatal"


R, H, F = RetryClass.RETRYABLE, RetryClass.NEEDS_HUMAN, RetryClass.FATAL

#: (error class, retry class, why). Order matters: subclasses before their bases.
CLASSIFICATION: tuple[tuple[type[Exception], RetryClass, str], ...] = (
    # refused by OVLM before sending: programming error or safety stop
    (
        e.WriteNotAllowedError,
        F,
        "the write allowlist refused the call: a bug, never retried (SEC-R-7)",
    ),
    (e.ReadOnlyViolationError, F, "a write on the read-only session: a bug"),
    (
        e.OwnershipViolationError,
        H,
        "ownership_violation: DB and cloud disagree; a human decides (s.4.3)",
    ),
    (e.ForeignLockError, H, "locked by someone else; OVLM does not touch a foreign lock"),
    (
        e.DuplicateResourceError,
        H,
        "duplicate create detected: never auto-delete, never pick one (ADR-0005)",
    ),
    (e.MarkerLimitError, F, "50 tags / 128 metadata items reached (SEC-R-24 condition 3)"),
    (e.ForeignMarkerLossError, F, "a pre-existing tag or key changed during the claim (SEC-R-24)"),
    (e.UnsupportedCloudError, F, "the cloud lacks a required microversion"),
    # cloud answers with a documented meaning
    (
        e.ServerBuildFailedError,
        F,
        "server ERROR (incl. NoValidHost): fatal, green kept for diagnosis (B4)",
    ),
    (
        e.FloatingIpNoRouterPathError,
        H,
        "misleading 404: no router path; nothing changed (OSI s.6.1)",
    ),
    (
        e.InstanceLockedError,
        H,
        "409 locked: an admin lock or a lock OVLM did not expect (W2, OSI s.7)",
    ),
    (
        e.FloatingIpPortAlreadyAssociatedError,
        H,
        "409: the target port already has a FIP (OSI s.6.1)",
    ),
    (e.VolumeAlreadyAttachedError, H, "400 already attached to another server (OSI s.4)"),
    (e.NoFloatingIpAvailableError, F, "empty FIP pool (EXP-01); OVLM never allocates anyway"),
    (e.QuotaExceededError, F, "OverQuota at create (B3)"),
    (e.AuthenticationError, R, "401: token refresh on the next attempt; exhaustion -> needs_human"),
    (
        e.ForbiddenError,
        H,
        "403: the write credential's role is not enough (e.g. admin lock override)",
    ),
    (e.NotFoundError, H, "404: a registered resource disappeared"),
    (e.ConflictError, R, "409: a task is in progress; re-probe and retry"),
    (e.BadRequestError, F, "400: the request is wrong for this cloud (B3)"),
    (e.ServerError, R, "5xx"),
    (e.OpenStackError, R, "transport error or timeout: the step re-probes before acting again"),
)


def classify(exc: Exception) -> RetryClass:
    """Retry class of an exception raised by the adapter. Unknown exceptions are retryable (the engine's own
    default); the retry budget turns repeated failures into needs_human."""
    for cls, retry_class, _why in CLASSIFICATION:
        if isinstance(exc, cls):
            return retry_class
    return RetryClass.RETRYABLE
