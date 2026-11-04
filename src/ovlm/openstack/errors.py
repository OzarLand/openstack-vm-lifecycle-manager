"""Error vocabulary of the adapter and translation of HTTP errors (openstack-integration.md, sections 4, 6, 7).

The classes are OVLM's own: workflow steps classify on them and never see SDK exceptions. ``translate_http_error``
is the narrow translation layer; the message texts it matches are source-verified (SV) in the integration doc and
are covered by canned-body tests. A lab run may replace the canned bodies with captured ones.
"""

from __future__ import annotations

import re


class OpenStackError(Exception):
    """Base class. ``status`` is the HTTP status when the error came from an HTTP response."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ReadOnlyViolationError(OpenStackError):
    """The read-only hook refused a request before sending it (a programming error, never retried)."""


class UnsupportedCloudError(OpenStackError):
    """The cloud cannot satisfy a documented requirement (for example compute microversion below 2.52)."""


class AuthenticationError(OpenStackError):
    """401: credential invalid, expired or revoked."""


class ForbiddenError(OpenStackError):
    """403: the credential's role is not enough (for example a ``reader`` calling a mutating API)."""


class NotFoundError(OpenStackError):
    """404 for a resource that does not exist (or is not visible to the project)."""


class FloatingIpNoRouterPathError(NotFoundError):
    """404 that does **not** mean "floating IP not found": Neutron's ``ExternalGatewayForFloatingIPNotFound``
    (no router joins the port's subnet and the floating IP's external network). Nothing changed (SV, section 6.1)."""


class BadRequestError(OpenStackError):
    """400."""


class ConflictError(OpenStackError):
    """409."""


class InstanceLockedError(ConflictError):
    """409 ``Instance is locked`` (SV, LAB-OBSERVED): stop, start, attach, detach and delete refused for non-admins."""


class FloatingIpPortAlreadyAssociatedError(ConflictError):
    """409 ``FloatingIPPortAlreadyAssociated``: the target port already has a floating IP on that network."""


class ServerError(OpenStackError):
    """5xx (for example ``volume create`` without a type on a cloud with no default type, LAB-OBSERVED)."""


class QuotaExceededError(ForbiddenError):
    """403 ``OverQuota`` at create (DU/AS: not traced in the source)."""


class ServerBuildFailedError(OpenStackError):
    """A server OVLM created ended in ``ERROR`` (any fault). Not an API error: raised by the build check."""


class NoValidHostError(ServerBuildFailedError):
    """The scheduler found no host: the server ends in ``ERROR`` with a fault. Not an API error as such."""


class NoFloatingIpAvailableError(BadRequestError):
    """400 ``Unable to find any IP address on external network``: the pool is empty although the quota is not
    (LAB-OBSERVED, EXP-01)."""


class VolumeAlreadyAttachedError(BadRequestError):
    """400 ``... is already attached ...`` (SV, LAB-OBSERVED). The write client turns it into success when the
    volume is attached to the requested server and re-raises it otherwise."""


# --- raised by OVLM itself, before any request is sent (E5-2) ------------------------------------------------


class WriteNotAllowedError(OpenStackError):
    """The write allowlist refused a request before sending it (SEC-R-7). A programming error, never retried."""


class OwnershipViolationError(OpenStackError):
    """The ownership guard refused a call before sending it (security-model.md section 4.3).

    ``reason`` is a short machine-readable code (``not_registered``, ``marker_missing``, ``not_deletable``, ...)."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class ForeignLockError(OpenStackError):
    """The server is locked with a reason OVLM did not set: OVLM neither re-locks nor unlocks it."""


class DuplicateResourceError(OpenStackError):
    """An idempotent lookup (tag + exact name) found more than one match, or found one where none may exist
    (ADR-0005 section 4: never auto-delete, never pick one)."""

    def __init__(self, message: str, *, matches: tuple[str, ...]) -> None:
        super().__init__(message)
        self.matches = matches


class MarkerLimitError(OpenStackError):
    """A claim would exceed 50 tags or 128 metadata items (OSI section 2, SV): fatal, with a clear message."""


class ForeignMarkerLossError(OpenStackError):
    """After a claim, a tag or metadata key that existed before is missing or changed (SEC-R-24 condition 2)."""


_NO_ROUTER = re.compile(r"External network .+ is not reachable from subnet", re.IGNORECASE)
_LOCKED = re.compile(r"Instance .*is locked", re.IGNORECASE)
_ALREADY_ASSOC = re.compile(
    r"already (has|associated)|FloatingIPPortAlreadyAssociated", re.IGNORECASE
)
_ALREADY_ATTACHED = re.compile(r"already attached", re.IGNORECASE)
_NO_FIP = re.compile(r"Unable to find any IP address on external network", re.IGNORECASE)
_OVER_QUOTA = re.compile(r"OverQuota|Quota exceeded", re.IGNORECASE)


def translate_http_error(status: int, message: str) -> OpenStackError:
    """Map an HTTP status and error text to an OVLM error class.

    The message is matched, never trusted: an unknown text falls back to the class of the status code.
    """
    if status == 404 and _NO_ROUTER.search(message):
        return FloatingIpNoRouterPathError(message, status=status)
    if status == 409 and _LOCKED.search(message):
        return InstanceLockedError(message, status=status)
    if status == 409 and _ALREADY_ASSOC.search(message):
        return FloatingIpPortAlreadyAssociatedError(message, status=status)
    if status == 400 and _ALREADY_ATTACHED.search(message):
        return VolumeAlreadyAttachedError(message, status=status)
    if status == 400 and _NO_FIP.search(message):
        return NoFloatingIpAvailableError(message, status=status)
    if status == 403 and _OVER_QUOTA.search(message):
        return QuotaExceededError(message, status=status)
    by_status: dict[int, type[OpenStackError]] = {
        400: BadRequestError,
        401: AuthenticationError,
        403: ForbiddenError,
        404: NotFoundError,
        409: ConflictError,
    }
    if status in by_status:
        return by_status[status](message, status=status)
    if status >= 500:
        return ServerError(message, status=status)
    return OpenStackError(message, status=status)
