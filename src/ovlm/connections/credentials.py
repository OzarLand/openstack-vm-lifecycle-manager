"""Worker side of the credential store: load and decrypt a project's credentials **in memory**, when a step needs
them (security-model.md 5.1 "Read path"). Never imported by the api (import-linter contract).

* Only an ``active`` credential whose last validation succeeded is used; an expired one is refused with a reason
  (security-model.md 4.4: an expired write credential blocks new runs). The expiry used is the earlier of the
  uploaded one and the one Keystone reported at validation (review CS-3). Nothing is cached: a rotation or a failed
  re-validation takes effect at the next call.
* **Destination binding (review CS-1, CS-2).** A secret is decrypted only for the endpoint it was uploaded and
  validated for: the AAD context is built from the **live** connection and cloud rows (:meth:`ConnectionInfo.
  destination`); a credential whose recorded destination differs is refused *before* anything is decrypted, and one
  whose row was rebound does not authenticate.
* The plaintext lives in a ``bytearray`` that is wiped after the client object is built. What a client library needs
  as ``str`` (the application credential secret for keystoneauth) or ``bytes`` (the guest key for the runner) is an
  immutable copy that Python cannot wipe; it is released with the client object at the end of the step attempt.
* Every refusal raises :class:`CredentialUnavailableError` whose message is safe to show (no secret, no ciphertext).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Engine, text

from ovlm.config.secrets import register_secret
from ovlm.secrets.keyring import Keyring, KeyringError, UnknownKekError, wipe
from ovlm.secrets.store import Destination, credential_context, endpoint_digest, load_sealed


class CredentialUnavailableError(ValueError):
    """No usable credential; the message says why and is safe to show (no secret material)."""


class CredentialKeyMissingError(CredentialUnavailableError):
    """The secret is wrapped to a key this worker does not hold: an operational state (rotation order), not a
    verdict on the credential (review CS-5)."""


@dataclass(frozen=True)
class ConnectionInfo:
    id: str
    name: str
    enabled: bool
    auth_url: str
    region: str
    interface: str
    openstack_project_id: str
    ca_bundle_pem: str | None = field(default=None, repr=False)
    ca_bundle_sha256: str | None = None
    cloud_id: str = ""

    @property
    def endpoint_sha256(self) -> str:
        return endpoint_digest(self.auth_url, self.region, self.interface, self.ca_bundle_sha256)

    def destination(self, kind: str) -> Destination:
        """Where a secret of ``kind`` of this connection may go **now** (the AAD binding of :mod:`ovlm.secrets.store`)."""
        return Destination(self.id, kind, self.cloud_id, self.endpoint_sha256)


@dataclass(frozen=True)
class AppCredential:
    """An application credential, in memory. ``secret`` is excluded from ``repr``."""

    connection: ConnectionInfo
    credential_id: str
    kind: str
    app_credential_id: str
    secret: str = field(repr=False)
    expires_at: datetime
    user_id: str | None = None


def load_connection(c: Connection, pc_id: str) -> ConnectionInfo | None:
    row = c.execute(
        text(
            "SELECT p.id, p.name, p.enabled, p.openstack_project_id, p.cloud_id, c.auth_url, c.region, c.interface, "
            "c.ca_bundle_pem, c.ca_bundle_sha256 FROM project_connection p JOIN cloud c ON c.id = p.cloud_id "
            "WHERE p.id = CAST(:p AS uuid)"
        ),
        {"p": pc_id},
    ).one_or_none()
    if row is None:
        return None
    return ConnectionInfo(
        str(row.id), row.name, bool(row.enabled), row.auth_url, row.region, row.interface,
        row.openstack_project_id, row.ca_bundle_pem, row.ca_bundle_sha256, str(row.cloud_id),
    )  # fmt: skip


def ca_bundle_path(info: ConnectionInfo, ca_dir: Path) -> Path | None:
    """The cloud's CA bundle as a file (keystoneauth/requests take a path). Not secret; content-addressed, written
    atomically, re-checked against its SHA-256 before use."""
    if not info.ca_bundle_pem or not info.ca_bundle_sha256:
        return None
    data = info.ca_bundle_pem.encode()
    if hashlib.sha256(data).hexdigest() != info.ca_bundle_sha256:
        raise CredentialUnavailableError(
            "the cloud's CA bundle does not match its recorded SHA-256"
        )
    ca_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = ca_dir / f"{info.ca_bundle_sha256}.pem"
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == info.ca_bundle_sha256:
        return path
    tmp = ca_dir / f".{info.ca_bundle_sha256}.{os.getpid()}.tmp"
    tmp.write_bytes(data)
    tmp.chmod(0o644)
    os.replace(tmp, path)
    return path


_KIND_LABEL = {
    "os_write": "write application credential (os_write)",
    "os_read": "read application credential (os_read)",
    "ssh_key": "guest SSH key (ssh_key)",
}


def _active_row(c: Connection, pc_id: str, kind: str) -> Any:
    return c.execute(
        text(
            "SELECT id, kind, secret_id, app_credential_id, ssh_public_key, expires_at, verified_expires_at, "
            "cloud_id, endpoint_sha256, validation_result, last_validated_at, validation_requested_at "
            "FROM credential_ref "
            "WHERE project_connection_id = CAST(:p AS uuid) AND kind = :k AND state = 'active'"
        ),
        {"p": pc_id, "k": kind},
    ).one_or_none()


def effective_expiry(row: Any) -> datetime | None:
    """The earlier of the uploaded expiry and the one Keystone reported at validation (review CS-3)."""
    dates = [
        d for d in (row.expires_at, getattr(row, "verified_expires_at", None)) if d is not None
    ]
    return min(dates) if dates else None


def binding_mismatch(row: Any, info: ConnectionInfo) -> str | None:
    """Why the credential row is not bound to the connection's **current** destination, or ``None``. Checked before
    anything is decrypted (the AAD would refuse it anyway)."""
    if str(row.cloud_id) != info.cloud_id:
        return (
            "the project connection was moved to another cloud since this credential was uploaded"
        )
    if row.endpoint_sha256 != info.endpoint_sha256:
        return (
            "the cloud endpoint (auth_url, region, interface or CA bundle) changed since this credential was "
            "uploaded: a secret is only ever sent to the endpoint it was validated for, so the cloud admin's "
            "credential must be uploaded again for the new endpoint"
        )
    return None


def usable_row(c: Connection, info: ConnectionInfo, kind: str, now: datetime | None = None) -> Any:
    """The active, validated, unexpired credential row of ``kind`` bound to the connection's current endpoint, or
    :class:`CredentialUnavailableError`."""
    now = now or datetime.now(UTC)
    label = _KIND_LABEL[kind]
    pc_id = info.id
    row = _active_row(c, pc_id, kind)
    if row is None:
        raise CredentialUnavailableError(
            f"this project has no validated {label}: an admin uploads one (POST "
            f"/api/v1/project-connections/{pc_id}/credentials) and the worker validates it"
        )
    result = row.validation_result or {}
    if not result.get("ok"):
        raise CredentialUnavailableError(
            f"the {label} of this project failed its last validation: {str(result.get('reason') or 'unknown')[:200]}"
        )
    mismatch = binding_mismatch(row, info)
    if mismatch is not None:
        raise CredentialUnavailableError(f"the {label} of this project is refused: {mismatch}")
    expiry = effective_expiry(row)
    if expiry is not None and expiry <= now:
        raise CredentialUnavailableError(
            f"the {label} of this project expired at {expiry.isoformat()}: the cloud admin creates a new "
            "application credential and an admin uploads it"
        )
    return row


def _connection(c: Connection, pc_id: str) -> ConnectionInfo:
    info = load_connection(c, pc_id)
    if info is None:
        raise CredentialUnavailableError("no such project connection")
    if not info.enabled:
        raise CredentialUnavailableError("the project connection is disabled")
    return info


class CredentialStore:
    """The worker's view of the store: the engine (role ``ovlm_worker``) and the key ring."""

    def __init__(
        self, engine: Engine, keyring: Keyring, ca_dir: Path, *, revalidate_after: float = 86400.0
    ) -> None:
        self.engine = engine
        self.keyring = keyring
        self.ca_dir = ca_dir
        #: Seconds after which an active credential is validated again (review CS-4, ``kek.revalidation_interval``).
        self.revalidate_after = revalidate_after

    def __repr__(self) -> str:
        return f"CredentialStore({self.keyring!r})"

    def unseal_for(
        self, c: Connection, cred_id: Any, secret_id: Any, destination: Destination
    ) -> bytearray:
        """Decrypt for ``destination``, which the caller builds from the **live** connection
        (:meth:`ConnectionInfo.destination`)."""
        sealed = load_sealed(c, secret_id)
        if sealed is None:
            raise CredentialUnavailableError("the credential's sealed secret is missing")
        try:
            return self.keyring.unseal(sealed, credential_context(cred_id, destination))
        except UnknownKekError as exc:
            raise CredentialKeyMissingError(
                f"the credential cannot be decrypted by this worker yet: {exc} (rotate the worker's key first)"
            ) from None
        except KeyringError as exc:
            raise CredentialUnavailableError(
                f"the credential cannot be decrypted by this worker: {exc}"
            ) from None

    def connection(self, pc_id: str) -> ConnectionInfo:
        with self.engine.connect() as c:
            return _connection(c, pc_id)

    def app_credential(self, pc_id: str, kind: str) -> AppCredential:
        """The active ``os_read``/``os_write`` credential of a project, decrypted now."""
        with self.engine.connect() as c:
            info = _connection(c, pc_id)
            row = usable_row(c, info, kind)
            buf = self.unseal_for(c, row.id, row.secret_id, info.destination(kind))
        try:
            secret = buf.decode("ascii")
        except UnicodeDecodeError:
            raise CredentialUnavailableError(
                "the stored application credential secret is not text"
            ) from None
        finally:
            wipe(buf)
        register_secret(secret)  # redaction backstop (security-model.md 5.2)
        expiry = effective_expiry(row)
        assert expiry is not None  # noqa: S101 - os_* rows always carry one (CHECK constraint)
        return AppCredential(
            info, str(row.id), kind, row.app_credential_id, secret, expiry,
            (row.validation_result or {}).get("user_id"),
        )  # fmt: skip

    def guest_key(self, pc_id: str) -> tuple[bytes, str]:
        """``(private OpenSSH key, public line)`` of the project's guest SSH key, decrypted now."""
        with self.engine.connect() as c:
            info = _connection(c, pc_id)
            row = usable_row(c, info, "ssh_key")
            buf = self.unseal_for(c, row.id, row.secret_id, info.destination("ssh_key"))
        try:
            return bytes(buf), row.ssh_public_key
        finally:
            wipe(buf)

    def write_metadata(self, pc_id: str) -> tuple[datetime | None, str | None]:
        """``(expires_at, user_id)`` of the active write credential, without decrypting anything."""
        with self.engine.connect() as c:
            info = _connection(c, pc_id)
            row = usable_row(c, info, "os_write")
        return effective_expiry(row), (row.validation_result or {}).get("user_id")

    def ca_path(self, info: ConnectionInfo) -> Path | None:
        return ca_bundle_path(info, self.ca_dir)


def connect_read_credential(cred: AppCredential, ca: Path | None, *, process_role: str) -> Any:
    """An inventory read client from an in-memory ``os_read`` credential: no ``clouds.yaml``, no environment, TLS
    verification on, the GET/HEAD guard installed before any request (security-model.md 4.1, SEC-C-3, SEC-C-4)."""
    import openstack
    from openstack.config.loader import OpenStackConfig

    from ovlm.openstack.guard import install_read_only_guard
    from ovlm.openstack.sdk_read import SdkReadClient, require_tls_verification

    if process_role != "worker":
        raise CredentialUnavailableError("OpenStack is reached by the worker only")
    if cred.kind != "os_read":
        raise CredentialUnavailableError("the inventory uses the read credential only")
    extra: dict[str, Any] = {"cacert": str(ca)} if ca else {}
    region = OpenStackConfig(load_yaml_config=False, load_envvars=False).get_one(
        auth_type="v3applicationcredential",
        auth={
            "auth_url": cred.connection.auth_url,
            "application_credential_id": cred.app_credential_id,
            "application_credential_secret": cred.secret,
        },
        region_name=cred.connection.region,
        interface=cred.connection.interface,
        verify=True,
        **extra,
    )
    require_tls_verification(region)
    install_read_only_guard(region.get_session())
    return SdkReadClient(openstack.connection.Connection(config=region))


def project_uuid(value: str | UUID) -> str:
    return str(UUID(str(value)))
