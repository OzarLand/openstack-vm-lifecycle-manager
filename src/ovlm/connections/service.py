"""Clouds, project connections and credential references: the api side (data-model.md 2, security-model.md 4.4, 5.1).

This module **seals** secrets with the worker's public key and never decrypts: it does not import
``ovlm.secrets.keyring`` (import-linter contract) and the ``ovlm_api`` role cannot SELECT ciphertext columns.
Nothing returned from here contains a secret: credential rows are described by metadata only (kind, ids, expiry,
state, key id, validation outcome), and write-only fields are reported as ``secret_set: true``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm.registry.errors import DomainError, conflict, not_found
from ovlm.secrets.envelope import EnvelopeError, PublicKek, SealContext
from ovlm.secrets.store import CREDENTIAL_CONTEXT_TABLE, insert_sealed
from ovlm.workflow.ids import new_id as _new_id


def new_id() -> UUID:
    return UUID(_new_id())


SLUG = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
OS_KINDS = ("os_read", "os_write")
CREDENTIAL_KINDS = (
    "os_read",
    "os_write",
    "ssh_key",
)  # uploadable through this API (vault/secret: later)
#: security-model.md 4.4: ``expires_at`` mandatory, at most 180 days ahead.
MAX_CREDENTIAL_DAYS = 180
#: security-model.md 4.4: warn 30 and 7 days before expiry.
EXPIRY_WARN_DAYS = (30, 7)


def _invalid(detail: str, code: str = "invalid") -> DomainError:
    return DomainError(422, code, "Invalid request", detail, "Fix the request and retry.")


# --- normalisation ----------------------------------------------------------------------------------------------


def normalise_slug(value: str, what: str) -> str:
    v = value.strip().lower()
    if not SLUG.match(v):
        raise _invalid(
            f"{what}: 1-64 characters of a-z, 0-9 and '-', not starting or ending with '-'"
        )
    return v


def normalise_project_id(value: str) -> str:
    """Keystone project ids are 32 hex characters; a UUID form with dashes and upper case is normalised."""
    v = value.strip().lower().replace("-", "")
    if not HEX32.match(v):
        raise _invalid("openstack_project_id: a Keystone project id (32 hexadecimal characters)")
    return v


def normalise_app_credential_id(value: str) -> str:
    v = value.strip().lower().replace("-", "")
    if not HEX32.match(v):
        raise _invalid(
            "app_credential_id: a Keystone application credential id (32 hexadecimal characters)"
        )
    return v


def normalise_auth_url(value: str) -> str:
    v = value.strip()
    parts = urlsplit(v)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise _invalid(
            "auth_url: an https:// Keystone URL without credentials (TLS verification is always on)"
        )
    if parts.query or parts.fragment or any(c.isspace() for c in v):
        raise _invalid("auth_url: no query, fragment or whitespace")
    return v.rstrip("/")


def normalise_ca_bundle(pem: str | None) -> tuple[str | None, str | None]:
    """A PEM bundle of one or more X.509 certificates (not secret). Returns (pem, sha256)."""
    if pem is None or not pem.strip():
        return None, None
    from cryptography import x509

    data = pem.strip().encode() + b"\n"
    if len(data) > 256 * 1024:
        raise _invalid("ca_bundle_pem: larger than 256 KiB")
    if b"PRIVATE KEY" in data:
        raise _invalid("ca_bundle_pem: must contain certificates only")
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        raise _invalid("ca_bundle_pem: not a PEM certificate bundle") from None
    if not certs:
        raise _invalid("ca_bundle_pem: no certificate")
    return data.decode(), hashlib.sha256(data).hexdigest()


# --- clouds -----------------------------------------------------------------------------------------------------

_CLOUD_COLS = "id, name, auth_url, region, interface, ca_bundle_sha256, version, created_by, created_at, updated_at"


def _cloud_out(row: Any) -> dict[str, Any]:
    d = dict(row._mapping)
    d["ca_bundle_ref"] = (
        f"sha256:{d.pop('ca_bundle_sha256')}" if d.get("ca_bundle_sha256") else None
    )
    d["tls_verify"] = True  # always (security-model.md 4.5); there is no setting to turn it off
    return d


def list_clouds(db: Session) -> list[dict[str, Any]]:
    rows = db.execute(text(f"SELECT {_CLOUD_COLS} FROM cloud ORDER BY name")).all()  # noqa: S608
    return [_cloud_out(r) for r in rows]


def get_cloud(db: Session, cloud_id: UUID) -> dict[str, Any] | None:
    row = db.execute(
        text(f"SELECT {_CLOUD_COLS} FROM cloud WHERE id = :i"),  # noqa: S608
        {"i": cloud_id},
    ).one_or_none()
    return _cloud_out(row) if row else None


def create_cloud(
    db: Session, *, name: str, auth_url: str, region: str, interface: str, ca_bundle_pem: str | None,
    created_by: UUID | None,
) -> dict[str, Any]:  # fmt: skip
    name = normalise_slug(name, "name")
    region = region.strip()
    if not region:
        raise _invalid("region: required")
    if interface not in ("public", "internal"):
        raise _invalid("interface: 'public' or 'internal'")
    pem, sha = normalise_ca_bundle(ca_bundle_pem)
    if db.execute(text("SELECT 1 FROM cloud WHERE name = :n"), {"n": name}).first():
        raise conflict("cloud-exists", "Cloud exists", f"A cloud named {name!r} exists.")
    cid = new_id()
    db.execute(
        text(
            "INSERT INTO cloud (id, name, auth_url, region, interface, ca_bundle_pem, ca_bundle_sha256, created_by) "
            "VALUES (:i, :n, :u, :r, :f, :p, :s, :by)"
        ),
        {"i": cid, "n": name, "u": normalise_auth_url(auth_url), "r": region, "f": interface,
         "p": pem, "s": sha, "by": created_by},
    )  # fmt: skip
    out = get_cloud(db, cid)
    assert out is not None  # noqa: S101
    return out


def update_cloud(
    db: Session, cloud_id: UUID, *, version: int, auth_url: str | None = None, region: str | None = None,
    interface: str | None = None, ca_bundle_pem: str | None = None, clear_ca_bundle: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    """Returns (before, after). Optimistic concurrency on ``version`` (409 when stale)."""
    before = get_cloud(db, cloud_id)
    if before is None:
        raise not_found("cloud-not-found", "Cloud")
    sets: dict[str, Any] = {}
    if auth_url is not None:
        sets["auth_url"] = normalise_auth_url(auth_url)
    if region is not None:
        if not region.strip():
            raise _invalid("region: required")
        sets["region"] = region.strip()
    if interface is not None:
        if interface not in ("public", "internal"):
            raise _invalid("interface: 'public' or 'internal'")
        sets["interface"] = interface
    if clear_ca_bundle:
        sets["ca_bundle_pem"], sets["ca_bundle_sha256"] = None, None
    elif ca_bundle_pem is not None:
        sets["ca_bundle_pem"], sets["ca_bundle_sha256"] = normalise_ca_bundle(ca_bundle_pem)
    assign = ", ".join(f"{k} = :{k}" for k in sets)
    n = db.execute(
        text(
            f"UPDATE cloud SET {assign}{', ' if assign else ''}version = version + 1, updated_at = now() "  # noqa: S608
            "WHERE id = :id AND version = :v"
        ),
        {**sets, "id": cloud_id, "v": version},
    ).rowcount  # type: ignore[attr-defined]
    if n != 1:
        raise conflict("stale-version", "Stale version", "The cloud changed since you read it.",
                       "Re-read it and retry.")  # fmt: skip
    after = get_cloud(db, cloud_id)
    assert after is not None  # noqa: S101
    return before, after


def delete_cloud(db: Session, cloud_id: UUID) -> dict[str, Any]:
    before = get_cloud(db, cloud_id)
    if before is None:
        raise not_found("cloud-not-found", "Cloud")
    if db.execute(
        text("SELECT 1 FROM project_connection WHERE cloud_id = :c LIMIT 1"), {"c": cloud_id}
    ).first():
        raise conflict("cloud-in-use", "Cloud in use", "Project connections still use this cloud.",
                       "Delete or move them first.")  # fmt: skip
    db.execute(text("DELETE FROM cloud WHERE id = :c"), {"c": cloud_id})
    return before


# --- project connections ----------------------------------------------------------------------------------------

_PC_COLS = (
    "p.id, p.cloud_id, c.name AS cloud_name, c.auth_url, c.region, c.interface, c.ca_bundle_sha256, "
    "p.openstack_project_id, p.openstack_project_name, p.name, p.guest_access, p.enabled, p.version, "
    "p.created_by, p.created_at, p.updated_at"
)


def _pc_out(row: Any) -> dict[str, Any]:
    d = dict(row._mapping)
    d["ca_bundle_ref"] = (
        f"sha256:{d.pop('ca_bundle_sha256')}" if d.get("ca_bundle_sha256") else None
    )
    d["tls_verify"] = True
    return d


def list_connections(db: Session, projects: frozenset[UUID] | None) -> list[dict[str, Any]]:
    """``projects`` is the caller's visible set (``None`` = all, security-model.md 3.3)."""
    where, params = "", {}
    if projects is not None:
        where, params = "WHERE p.id = ANY(:ids)", {"ids": list(projects)}
    rows = db.execute(
        text(f"SELECT {_PC_COLS} FROM project_connection p JOIN cloud c ON c.id = p.cloud_id {where} "  # noqa: S608
             "ORDER BY p.name"), params,
    ).all()  # fmt: skip
    return [_pc_out(r) for r in rows]


def get_connection(db: Session, pc_id: UUID) -> dict[str, Any] | None:
    row = db.execute(
        text(
            f"SELECT {_PC_COLS} FROM project_connection p JOIN cloud c ON c.id = p.cloud_id WHERE p.id = :i"  # noqa: S608
        ),
        {"i": pc_id},
    ).one_or_none()
    return _pc_out(row) if row else None


def _guest_access(value: dict[str, Any] | None) -> dict[str, Any]:
    """``{"mode": "direct"}`` or ``{"mode": "jump_host", "host": ..., "port": 22, "host_key": "<pinned key>"}``."""
    if not value:
        return {"mode": "direct"}
    mode = value.get("mode", "direct")
    if mode == "direct":
        if set(value) - {"mode"}:
            raise _invalid("guest_access: 'direct' takes no other field")
        return {"mode": "direct"}
    if mode != "jump_host":
        raise _invalid("guest_access.mode: 'direct' or 'jump_host'")
    if set(value) - {"mode", "host", "port", "host_key"}:
        raise _invalid("guest_access: unknown field")
    host, port, key = value.get("host"), value.get("port", 22), value.get("host_key")
    if not isinstance(host, str) or not re.match(r"^[A-Za-z0-9.:-]{1,253}$", host):
        raise _invalid("guest_access.host: a host name or address")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise _invalid("guest_access.port: 1-65535")
    if not isinstance(key, str) or not re.match(r"^ssh-(ed25519|rsa) [A-Za-z0-9+/=]{20,}$|^ecdsa-sha2-nistp(256|384|521) [A-Za-z0-9+/=]{20,}$", key.strip()):  # fmt: skip
        raise _invalid(
            "guest_access.host_key: the jump host's pinned public host key (type and base64)"
        )
    return {"mode": "jump_host", "host": host, "port": port, "host_key": key.strip()}


def create_connection(
    db: Session, *, cloud_id: UUID, openstack_project_id: str, openstack_project_name: str, name: str,
    guest_access: dict[str, Any] | None, enabled: bool, created_by: UUID | None,
) -> dict[str, Any]:  # fmt: skip
    if get_cloud(db, cloud_id) is None:
        raise not_found("cloud-not-found", "Cloud")
    name = normalise_slug(name, "name")
    project_id = normalise_project_id(openstack_project_id)
    pname = openstack_project_name.strip()
    if not pname or len(pname) > 255:
        raise _invalid("openstack_project_name: 1-255 characters")
    if db.execute(text("SELECT 1 FROM project_connection WHERE name = :n"), {"n": name}).first():
        raise conflict(
            "connection-exists", "Connection exists", f"A connection named {name!r} exists."
        )
    if db.execute(
        text("SELECT 1 FROM project_connection WHERE cloud_id = :c AND openstack_project_id = :p"),
        {"c": cloud_id, "p": project_id},
    ).first():
        raise conflict("connection-exists", "Connection exists",
                       "This OpenStack project already has a connection on this cloud.")  # fmt: skip
    pc_id = new_id()
    db.execute(
        text(
            "INSERT INTO project_connection (id, cloud_id, openstack_project_id, openstack_project_name, name, "
            "guest_access, enabled, created_by) VALUES (:i, :c, :p, :pn, :n, CAST(:g AS jsonb), :e, :by)"
        ),
        {"i": pc_id, "c": cloud_id, "p": project_id, "pn": pname, "n": name,
         "g": json.dumps(_guest_access(guest_access)), "e": enabled, "by": created_by},
    )  # fmt: skip
    out = get_connection(db, pc_id)
    assert out is not None  # noqa: S101
    return out


def update_connection(
    db: Session, pc_id: UUID, *, version: int, openstack_project_name: str | None = None,
    guest_access: dict[str, Any] | None = None, enabled: bool | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    """The cloud and the OpenStack project id are fixed once created (credentials and inventory are bound to them):
    a different project is a new connection."""
    before = get_connection(db, pc_id)
    if before is None:
        raise not_found("connection-not-found", "Project connection")
    sets: dict[str, Any] = {}
    if openstack_project_name is not None:
        pname = openstack_project_name.strip()
        if not pname or len(pname) > 255:
            raise _invalid("openstack_project_name: 1-255 characters")
        sets["openstack_project_name"] = pname
    if guest_access is not None:
        sets["guest_access"] = json.dumps(_guest_access(guest_access))
    if enabled is not None:
        sets["enabled"] = enabled
    assign = ", ".join(
        f"{k} = CAST(:{k} AS jsonb)" if k == "guest_access" else f"{k} = :{k}" for k in sets
    )
    n = db.execute(
        text(
            f"UPDATE project_connection SET {assign}{', ' if assign else ''}version = version + 1, "  # noqa: S608
            "updated_at = now() WHERE id = :id AND version = :v"
        ),
        {**sets, "id": pc_id, "v": version},
    ).rowcount  # type: ignore[attr-defined]
    if n != 1:
        raise conflict("stale-version", "Stale version", "The connection changed since you read it.",
                       "Re-read it and retry.")  # fmt: skip
    after = get_connection(db, pc_id)
    assert after is not None  # noqa: S101
    return before, after


def delete_connection(db: Session, pc_id: UUID) -> dict[str, Any]:
    """Only an unused connection: no credential, service or active role binding refers to it."""
    before = get_connection(db, pc_id)
    if before is None:
        raise not_found("connection-not-found", "Project connection")
    checks = (
        ("SELECT 1 FROM credential_ref WHERE project_connection_id = :p LIMIT 1", "credentials"),
        ("SELECT 1 FROM service WHERE project_connection_id = :p LIMIT 1", "services"),
        (
            "SELECT 1 FROM role_binding WHERE scope = :s AND revoked_at IS NULL LIMIT 1",
            "role bindings",
        ),
    )
    for sql, what in checks:
        if db.execute(text(sql), {"p": pc_id, "s": f"project:{pc_id}"}).first():
            raise conflict("connection-in-use", "Connection in use", f"Active {what} refer to this connection.",
                           "Disable the connection instead (enabled=false), or remove them first.")  # fmt: skip
    db.execute(text("DELETE FROM project_connection WHERE id = :p"), {"p": pc_id})
    return before


# --- credentials ------------------------------------------------------------------------------------------------

_CRED_COLS = (
    "r.id, r.project_connection_id, r.kind, r.service_id, r.app_credential_id, r.ssh_public_key, r.expires_at, "
    "r.state, r.superseded_by, r.validation_requested_at, r.last_validated_at, r.validation_result, r.rotated_at, "
    "r.cloud_deletion_pending, r.created_by, r.created_at, s.kek_id, s.created_at AS sealed_at, s.rewrapped_at"
)


def credential_out(row: Any, now: datetime | None = None) -> dict[str, Any]:
    """Metadata only. The secret is write-only: ``secret_set`` says it exists, never what it is."""
    d = dict(row._mapping)
    now = now or datetime.now(UTC)
    vr = d.pop("validation_result") or {}
    d["validation"] = {
        "state": "pending" if d["last_validated_at"] is None or (
            d["validation_requested_at"] and d["validation_requested_at"] > d["last_validated_at"]
        ) else ("valid" if vr.get("ok") else "invalid"),
        "ok": vr.get("ok"),
        "reason": vr.get("reason"),
        "roles": vr.get("roles"),
        "checked_at": d["last_validated_at"],
    }  # fmt: skip
    d["secret_set"] = True
    d["ssh_public_key_fingerprint"] = (
        ssh_fingerprint(d["ssh_public_key"]) if d.get("ssh_public_key") else None
    )
    exp = d.get("expires_at")
    d["expires_in_days"] = (exp - now).days if exp else None
    d["expired"] = bool(exp and exp <= now)
    d["expiry_warning"] = next(
        (f"expires in less than {w} days" for w in sorted(EXPIRY_WARN_DAYS) if exp and exp - now < timedelta(days=w)),
        None,
    ) if exp and exp > now else ("expired" if d["expired"] else None)  # fmt: skip
    return d


def list_credentials(
    db: Session, pc_id: UUID, *, include_history: bool = True
) -> list[dict[str, Any]]:
    where = "" if include_history else "AND r.state IN ('pending', 'active')"
    rows = db.execute(
        text(f"SELECT {_CRED_COLS} FROM credential_ref r JOIN sealed_secret s ON s.id = r.secret_id "  # noqa: S608
             f"WHERE r.project_connection_id = :p {where} ORDER BY r.created_at DESC, r.id"), {"p": pc_id},
    ).all()  # fmt: skip
    return [credential_out(r) for r in rows]


def get_credential(db: Session, cred_id: UUID) -> dict[str, Any] | None:
    row = db.execute(
        text(f"SELECT {_CRED_COLS} FROM credential_ref r JOIN sealed_secret s ON s.id = r.secret_id "  # noqa: S608
             "WHERE r.id = :i"), {"i": cred_id},
    ).one_or_none()  # fmt: skip
    return credential_out(row) if row else None


def ssh_fingerprint(public_line: str) -> str:
    import base64

    blob = base64.b64decode(public_line.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def ssh_public_key_of(private_openssh: bytes) -> str:
    """The public line of an unencrypted OpenSSH ed25519/ECDSA/RSA private key (validated, not stored)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    try:
        key = serialization.load_ssh_private_key(private_openssh, password=None)
    except (ValueError, TypeError, AssertionError):
        raise _invalid(
            "secret: an unencrypted OpenSSH private key (ssh-keygen -t ed25519 -N '')"
        ) from None
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 3072:
        raise _invalid("secret: RSA keys must be at least 3072 bits (ed25519 recommended)")
    if not isinstance(
        key, ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
    ):
        raise _invalid("secret: ed25519, ECDSA or RSA keys only")
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )


@dataclass(frozen=True)
class Upload:
    kind: str
    app_credential_id: str | None
    expires_at: datetime | None


def check_upload(
    kind: str,
    app_credential_id: str | None,
    expires_at: datetime | None,
    now: datetime | None = None,
) -> Upload:
    now = now or datetime.now(UTC)
    if kind not in CREDENTIAL_KINDS:
        raise _invalid(f"kind: one of {list(CREDENTIAL_KINDS)}")
    if kind in OS_KINDS:
        if not app_credential_id:
            raise _invalid("app_credential_id: required for an application credential")
        if expires_at is None:
            raise _invalid(
                "expires_at: required for an application credential (security-model.md 4.4)"
            )
        if expires_at.tzinfo is None:
            raise _invalid("expires_at: needs a time zone (e.g. 2027-03-01T00:00:00Z)")
        if expires_at <= now:
            raise DomainError(422, "credential-expired", "Credential expired",
                              "expires_at is in the past: this credential cannot be used.",
                              "Create a new application credential in Keystone and upload it.")  # fmt: skip
        if expires_at > now + timedelta(days=MAX_CREDENTIAL_DAYS):
            raise _invalid(
                f"expires_at: at most {MAX_CREDENTIAL_DAYS} days ahead (security-model.md 4.4)"
            )
        return Upload(kind, normalise_app_credential_id(app_credential_id), expires_at)
    if app_credential_id or expires_at:
        raise _invalid("app_credential_id and expires_at apply to application credentials only")
    return Upload(kind, None, None)


def upload_credential(
    db: Session,
    kek: PublicKek,
    pc_id: UUID,
    upload: Upload,
    secret: bytearray,
    *,
    created_by: UUID | None,
) -> dict[str, Any]:
    """Seal ``secret`` to the worker key and register a **pending** credential; the worker validates it out of band
    and switches it in (security-model.md 4.4). ``secret`` is wiped here, whatever happens."""
    try:
        if get_connection(db, pc_id) is None:
            raise not_found("connection-not-found", "Project connection")
        pending = db.execute(
            text("SELECT 1 FROM credential_ref WHERE project_connection_id = :p AND kind = :k AND state = 'pending'"),
            {"p": pc_id, "k": upload.kind},
        ).first()  # fmt: skip
        if pending:
            raise conflict(
                "credential-pending", "A credential is awaiting validation",
                f"A {upload.kind} credential of this connection is still being validated by the worker.",
                "Wait for its validation, or delete the pending credential, then upload again.",
            )  # fmt: skip
        public_line = None
        if upload.kind == "ssh_key":
            public_line = ssh_public_key_of(bytes(secret))
        elif (
            not bytes(secret).strip()
            or len(secret) > 1024
            or any(c < 0x21 or c > 0x7E for c in bytes(secret))
        ):
            raise _invalid(
                "secret: the application credential secret (printable characters, no spaces)"
            )
        cred_id, secret_id = new_id(), new_id()
        try:
            sealed = kek.seal(secret, SealContext(CREDENTIAL_CONTEXT_TABLE, str(cred_id), "secret"))
        except EnvelopeError as exc:
            raise _invalid(str(exc)) from None
        insert_sealed(db, secret_id, sealed)
        db.execute(
            text(
                "INSERT INTO credential_ref (id, project_connection_id, kind, secret_id, app_credential_id, "
                "ssh_public_key, expires_at, created_by) VALUES (:i, :p, :k, :s, :a, :pk, :e, :by)"
            ),
            {"i": cred_id, "p": pc_id, "k": upload.kind, "s": secret_id, "a": upload.app_credential_id,
             "pk": public_line, "e": upload.expires_at, "by": created_by},
        )  # fmt: skip
    finally:
        secret[:] = b"\0" * len(secret)
    out = get_credential(db, cred_id)
    assert out is not None  # noqa: S101
    return out


def request_validation(db: Session, cred_id: UUID) -> dict[str, Any]:
    """Ask the worker to validate a credential again (e.g. after the cloud admin changed its roles)."""
    n = db.execute(
        text("UPDATE credential_ref SET validation_requested_at = now(), updated_at = now() "
             "WHERE id = :i AND state IN ('pending', 'active')"), {"i": cred_id},
    ).rowcount  # type: ignore[attr-defined]  # fmt: skip
    if n != 1:
        if get_credential(db, cred_id) is None:
            raise not_found("credential-not-found", "Credential")
        raise conflict("credential-not-current", "Credential not current",
                       "Only a pending or active credential is validated.")  # fmt: skip
    out = get_credential(db, cred_id)
    assert out is not None  # noqa: S101
    return out


def credential_in_use(db: Session, pc_id: UUID) -> bool:
    """A non-terminal renewal of a service of this project (security-model.md 7.1: blocked while a run uses it)."""
    return (
        db.execute(
            text(
                "SELECT 1 FROM workflow_run r JOIN service s ON s.id = r.service_id "
                "WHERE r.kind = 'renewal' AND s.project_connection_id = :p "
                "AND r.state NOT IN ('rejected', 'cancelled', 'failed', 'completed', 'rolled_back') LIMIT 1"
            ),
            {"p": pc_id},
        ).first()
        is not None
    )


def delete_credential(db: Session, cred_id: UUID) -> dict[str, Any]:
    """Remove the credential and its sealed secret. An active credential cannot be removed while a renewal of its
    project is running. Deleting the Keystone application credential itself is the cloud admin's job."""
    before = get_credential(db, cred_id)
    if before is None:
        raise not_found("credential-not-found", "Credential")
    if before["state"] == "active" and credential_in_use(db, before["project_connection_id"]):
        raise conflict("credential-in-use", "Credential in use",
                       "A renewal of this project is running and may need this credential.",
                       "Wait until the run ends.")  # fmt: skip
    row = db.execute(
        text("SELECT secret_id FROM credential_ref WHERE id = :i"), {"i": cred_id}
    ).scalar_one()
    db.execute(text("DELETE FROM credential_ref WHERE id = :i"), {"i": cred_id})
    db.execute(text("DELETE FROM sealed_secret WHERE id = :s"), {"s": row})
    return before
