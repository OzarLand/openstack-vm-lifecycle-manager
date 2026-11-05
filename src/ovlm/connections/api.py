"""``/api/v1/clouds``, ``/api/v1/project-connections`` and their credentials (admin; api-design.md 3.8 style).

* Clouds and project connections: **admin**, human session (``credential.manage``); every change is audited.
  Listing project connections is open to every role, filtered by the caller's project scopes (security-model.md 3.3).
* Anything that decides **where a secret goes** takes the same TOTP step-up and typed confirmation as an upload
  (review CS-1): every cloud ``PATCH`` (all its fields are endpoint fields: ``auth_url``, region, interface, CA
  bundle) and ``DELETE``, and a change of a connection's ``guest_access`` (the jump host the guest key is used
  against). A cloud endpoint change also sends every credential of the cloud back to validation, where the worker
  refuses it without decrypting it: secrets are bound to the endpoint they were uploaded for.
* Credentials: **admin**, human session, a **TOTP step-up** bound to the action and target, and a typed confirmation
  (the connection's name). The secret is **write-only**: it is sealed here with the worker's public key and never
  returned, logged or audited (``secret_set: true``; audit records only that it changed). The api cannot decrypt it.
  The worker validates the credential out of band and switches it in (``validation.state``).
"""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.api.routes_common import ProblemRoute, audit_change
from ovlm.auth.authz import Action, visible_projects
from ovlm.auth.deps import current_principal, get_db, get_settings, require_action
from ovlm.auth.principal import GLOBAL, Principal
from ovlm.auth.stepup import consume_stepup
from ovlm.config import Settings
from ovlm.connections import events as _events  # noqa: F401 - registers the audit allowlists
from ovlm.connections import service as svc
from ovlm.registry.errors import DomainError, not_found
from ovlm.secrets.envelope import EnvelopeError, PublicKek, load_public_key

router = APIRouter(prefix="/api/v1", route_class=ProblemRoute)
Db = Annotated[Session, Depends(get_db)]
Cfg = Annotated[Settings, Depends(get_settings)]
Admin = Annotated[Principal, Depends(require_action(Action.CREDENTIAL_MANAGE, GLOBAL))]
Me = Annotated[Principal, Depends(current_principal)]

UPLOAD_STEPUP_ACTION = "credential.upload"
DELETE_STEPUP_ACTION = "credential.delete"
CLOUD_UPDATE_STEPUP_ACTION = "cloud.update"
CLOUD_DELETE_STEPUP_ACTION = "cloud.delete"
CONNECTION_UPDATE_STEPUP_ACTION = "project_connection.update"


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


@lru_cache(maxsize=4)
def _public_kek(path: str, _mtime_ns: int) -> PublicKek:
    return load_public_key(Path(path))


def public_kek(settings: Settings) -> PublicKek:
    """The worker's public key (``kek.public_key_file``). Without it no credential can be accepted (503)."""
    path = settings.kek.public_key_file
    if path is None:
        raise DomainError(503, "credential-store-unconfigured", "Credential store not configured",
                          "The api has no worker public key (kek.public_key_file), so it cannot seal secrets.",
                          "Generate the worker key pair (make secrets) and mount the public key into the api.")  # fmt: skip
    try:
        return _public_kek(str(path), path.stat().st_mtime_ns)
    except (OSError, EnvelopeError) as exc:
        raise DomainError(503, "credential-store-unconfigured", "Credential store not configured",
                          f"The worker public key cannot be loaded: {type(exc).__name__}.",
                          "Check kek.public_key_file.") from None  # fmt: skip


def _audit_cred(
    db: Session, who: Principal, action: str, cred: dict[str, Any], **extra: Any
) -> None:
    after = {
        "kind": cred["kind"], "project_connection_id": cred["project_connection_id"],
        "app_cred_id": cred.get("app_credential_id"), "expires_at": cred.get("expires_at"),
        "state": cred["state"], "kek_id": cred.get("kek_id"),
        "ssh_public_key_fingerprint": cred.get("ssh_public_key_fingerprint"), **extra,
    }  # fmt: skip
    audit.record(
        db, action=action, target_type="credential_ref", target_id=str(cred["id"]), actor_id=who.user_id,
        principal_type=who.principal_type, auth_method=who.auth_method, source_ip=who.source_ip,
        project_scope=f"project:{cred['project_connection_id']}", after=after,
    )  # fmt: skip


# --- clouds -----------------------------------------------------------------------------------------------------


class CloudIn(_Body):
    name: str = Field(min_length=1, max_length=64)
    auth_url: str = Field(min_length=9, max_length=2048)
    region: str = Field(min_length=1, max_length=255)
    interface: Literal["public", "internal"] = "public"
    #: PEM bundle of the CA certificates of the cloud's endpoints (not secret). TLS verification is always on.
    ca_bundle_pem: str | None = Field(default=None, max_length=262144)


class CloudPatch(_Body):
    version: int
    auth_url: str | None = Field(default=None, min_length=9, max_length=2048)
    region: str | None = Field(default=None, min_length=1, max_length=255)
    interface: Literal["public", "internal"] | None = None
    ca_bundle_pem: str | None = Field(default=None, max_length=262144)
    clear_ca_bundle: bool = False
    #: Step-up ``cloud.update`` for this cloud (every field decides where secrets are sent).
    stepup_id: UUID
    #: Must equal the cloud's name.
    typed_confirmation: str = Field(max_length=100)


class StepUpConfirmation(_Body):
    stepup_id: UUID
    typed_confirmation: str = Field(max_length=100)


def _confirm(typed: str, expected: str, what: str = "project connection") -> None:
    if not expected or " ".join(typed.split()).lower() != expected:
        raise DomainError(422, "confirmation-mismatch", "Typed confirmation does not match",
                          f"Type the {what}'s name ({expected!r}) to confirm.")  # fmt: skip


@router.get("/clouds")
def list_clouds(db: Db, _: Admin) -> dict[str, Any]:
    return {"items": svc.list_clouds(db)}


@router.post("/clouds", status_code=201)
def create_cloud(body: CloudIn, response: Response, db: Db, who: Admin) -> dict[str, Any]:
    out = svc.create_cloud(db, name=body.name, auth_url=body.auth_url, region=body.region,
                           interface=body.interface, ca_bundle_pem=body.ca_bundle_pem, created_by=who.user_id)  # fmt: skip
    audit_change(db, who, "cloud.create", "cloud", str(out["id"]), scope=GLOBAL, after=out)
    db.commit()
    response.headers["Location"] = f"/api/v1/clouds/{out['id']}"
    return out


@router.get("/clouds/{cloud_id}")
def get_cloud(cloud_id: UUID, db: Db, _: Admin) -> dict[str, Any]:
    out = svc.get_cloud(db, cloud_id)
    if out is None:
        raise not_found("cloud-not-found", "Cloud")
    return out


def _cloud_or_404(db: Session, cloud_id: UUID) -> dict[str, Any]:
    cloud = svc.get_cloud(db, cloud_id)
    if cloud is None:
        raise not_found("cloud-not-found", "Cloud")
    return cloud


@router.patch("/clouds/{cloud_id}")
def update_cloud(cloud_id: UUID, body: CloudPatch, db: Db, who: Admin) -> dict[str, Any]:
    """Step-up + typed confirmation (CS-1). An endpoint change sends the cloud's credentials back to validation;
    the worker refuses them (bound to the old endpoint) and the cloud admin's credentials must be uploaded again."""
    _confirm(body.typed_confirmation, _cloud_or_404(db, cloud_id)["name"], "cloud")
    stepup_id = consume_stepup(
        db, who, body.stepup_id, action=CLOUD_UPDATE_STEPUP_ACTION, target_id=str(cloud_id)
    )
    before, after = svc.update_cloud(
        db, cloud_id, version=body.version, auth_url=body.auth_url, region=body.region, interface=body.interface,
        ca_bundle_pem=body.ca_bundle_pem, clear_ca_bundle=body.clear_ca_bundle,
    )  # fmt: skip
    invalidated = (
        svc.invalidate_cloud_credentials(db, cloud_id)
        if svc.endpoint_changed(before, after)
        else []
    )
    audit_change(db, who, "cloud.update", "cloud", str(cloud_id), scope=GLOBAL, before=before,
                 after={**after, "stepup_id": stepup_id, "invalidated_count": len(invalidated)})  # fmt: skip
    for cred_id in invalidated:
        cred = svc.get_credential(db, cred_id)
        if cred is not None:
            _audit_cred(db, who, "credential.endpoint_changed", cred, stepup_id=stepup_id,
                        validation_reason="the cloud endpoint changed: re-validation requested")  # fmt: skip
    db.commit()
    return after


@router.delete("/clouds/{cloud_id}", status_code=204)
def delete_cloud(cloud_id: UUID, body: StepUpConfirmation, db: Db, who: Admin) -> Response:
    _confirm(body.typed_confirmation, _cloud_or_404(db, cloud_id)["name"], "cloud")
    stepup_id = consume_stepup(
        db, who, body.stepup_id, action=CLOUD_DELETE_STEPUP_ACTION, target_id=str(cloud_id)
    )
    before = svc.delete_cloud(db, cloud_id)
    audit_change(db, who, "cloud.delete", "cloud", str(cloud_id), scope=GLOBAL, before=before,
                 after={"stepup_id": stepup_id})  # fmt: skip
    db.commit()
    return Response(status_code=204)


# --- project connections ----------------------------------------------------------------------------------------


class ConnectionIn(_Body):
    cloud_id: UUID
    openstack_project_id: str = Field(min_length=32, max_length=36)
    openstack_project_name: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=64)
    guest_access: dict[str, Any] | None = None
    enabled: bool = True


class ConnectionPatch(_Body):
    version: int
    openstack_project_name: str | None = Field(default=None, min_length=1, max_length=255)
    #: Changing it takes a step-up ``project_connection.update`` and the typed connection name (CS-1).
    guest_access: dict[str, Any] | None = None
    enabled: bool | None = None
    stepup_id: UUID | None = None
    typed_confirmation: str | None = Field(default=None, max_length=100)


def _visible_connection(db: Session, who: Principal, pc_id: UUID) -> dict[str, Any]:
    out = svc.get_connection(db, pc_id)
    projects = visible_projects(who)
    if out is None or (projects is not None and pc_id not in projects):
        raise not_found("connection-not-found", "Project connection")  # 404 for out of scope (3.3)
    return out


@router.get("/project-connections")
def list_connections(db: Db, who: Me) -> dict[str, Any]:
    return {"items": svc.list_connections(db, visible_projects(who))}


@router.post("/project-connections", status_code=201)
def create_connection(body: ConnectionIn, response: Response, db: Db, who: Admin) -> dict[str, Any]:
    out = svc.create_connection(
        db, cloud_id=body.cloud_id, openstack_project_id=body.openstack_project_id,
        openstack_project_name=body.openstack_project_name, name=body.name, guest_access=body.guest_access,
        enabled=body.enabled, created_by=who.user_id,
    )  # fmt: skip
    audit_change(db, who, "project_connection.create", "project_connection", str(out["id"]),
                 scope=f"project:{out['id']}", after=out)  # fmt: skip
    db.commit()
    response.headers["Location"] = f"/api/v1/project-connections/{out['id']}"
    return out


@router.get("/project-connections/{pc_id}")
def get_connection(pc_id: UUID, db: Db, who: Me) -> dict[str, Any]:
    return _visible_connection(db, who, pc_id)


@router.patch("/project-connections/{pc_id}")
def update_connection(pc_id: UUID, body: ConnectionPatch, db: Db, who: Admin) -> dict[str, Any]:
    stepup_id: UUID | None = None
    current = svc.get_connection(db, pc_id)
    if current is None:
        raise not_found("connection-not-found", "Project connection")
    if (
        body.guest_access is not None
        and svc.guest_access_of(body.guest_access) != current["guest_access"]
    ):
        if body.stepup_id is None or body.typed_confirmation is None:
            raise DomainError(403, "stepup-required", "Step-up authentication required",
                              "Changing guest_access decides where the guest SSH key is used.",
                              f"POST /api/v1/session/reauth for action {CONNECTION_UPDATE_STEPUP_ACTION!r} and this "
                              "connection, then send stepup_id and typed_confirmation (the connection's name).")  # fmt: skip
        _confirm(body.typed_confirmation, current["name"])
        stepup_id = consume_stepup(
            db, who, body.stepup_id, action=CONNECTION_UPDATE_STEPUP_ACTION, target_id=str(pc_id)
        )
    before, after = svc.update_connection(
        db, pc_id, version=body.version, openstack_project_name=body.openstack_project_name,
        guest_access=body.guest_access, enabled=body.enabled,
    )  # fmt: skip
    audit_change(db, who, "project_connection.update", "project_connection", str(pc_id),
                 scope=f"project:{pc_id}", before=before, after={**after, "stepup_id": stepup_id})  # fmt: skip
    db.commit()
    return after


@router.delete("/project-connections/{pc_id}", status_code=204)
def delete_connection(pc_id: UUID, db: Db, who: Admin) -> Response:
    before = svc.delete_connection(db, pc_id)
    audit_change(db, who, "project_connection.delete", "project_connection", str(pc_id),
                 scope=f"project:{pc_id}", before=before)  # fmt: skip
    db.commit()
    return Response(status_code=204)


# --- credentials ------------------------------------------------------------------------------------------------


class CredentialIn(_Body):
    kind: Literal["os_read", "os_write", "ssh_key"]
    #: The Keystone application credential id (not secret). ``os_*`` only.
    app_credential_id: str | None = Field(default=None, min_length=32, max_length=36)
    #: Write-only: the application credential secret, or the guest's OpenSSH private key. Never returned.
    secret: SecretStr = Field(min_length=1, max_length=16384)
    #: The application credential's expiry as created in Keystone (mandatory for ``os_*``, at most 180 days).
    expires_at: datetime | None = None
    stepup_id: UUID
    #: Must equal the project connection's name.
    typed_confirmation: str = Field(max_length=100)


class CredentialAction(_Body):
    stepup_id: UUID
    typed_confirmation: str = Field(max_length=100)


@router.get("/project-connections/{pc_id}/credentials")
def list_credentials(pc_id: UUID, db: Db, _: Admin) -> dict[str, Any]:
    pc = svc.get_connection(db, pc_id)
    if pc is None:
        raise not_found("connection-not-found", "Project connection")
    return {
        "items": svc.list_credentials(db, pc_id),
        "stepup": {"upload": {"action": UPLOAD_STEPUP_ACTION, "target_id": str(pc_id)},
                   "delete": {"action": DELETE_STEPUP_ACTION, "target_id": "<credential id>"}},
        "typed_confirmation": pc["name"],
    }  # fmt: skip


@router.post("/project-connections/{pc_id}/credentials", status_code=202)
def upload_credential(
    pc_id: UUID, body: CredentialIn, response: Response, db: Db, settings: Cfg, who: Admin
) -> dict[str, Any]:
    """Accepted, not yet usable: the worker validates the credential and switches it in (``validation.state``)."""
    secret = bytearray(body.secret.get_secret_value().encode())
    try:
        kek = public_kek(settings)
        pc = svc.get_connection(db, pc_id)
        if pc is None:
            raise not_found("connection-not-found", "Project connection")
        _confirm(body.typed_confirmation, pc["name"])
        upload = svc.check_upload(body.kind, body.app_credential_id, body.expires_at)
        stepup_id = consume_stepup(
            db, who, body.stepup_id, action=UPLOAD_STEPUP_ACTION, target_id=str(pc_id)
        )
        out = svc.upload_credential(db, kek, pc_id, upload, secret, created_by=who.user_id)
    finally:
        secret[:] = b"\0" * len(secret)
    _audit_cred(
        db, who, "credential.upload", out, stepup_id=stepup_id, secret=f"sealed:{out['kek_id']}"
    )
    db.commit()
    response.headers["Location"] = f"/api/v1/credentials/{out['id']}"
    return out


@router.get("/credentials/{cred_id}")
def get_credential(cred_id: UUID, db: Db, _: Admin) -> dict[str, Any]:
    out = svc.get_credential(db, cred_id)
    if out is None:
        raise not_found("credential-not-found", "Credential")
    return out


@router.post("/credentials/{cred_id}/validate", status_code=202)
def revalidate_credential(cred_id: UUID, db: Db, who: Admin) -> dict[str, Any]:
    """Ask the worker to validate the credential again (no secret involved: no step-up)."""
    out = svc.request_validation(db, cred_id)
    _audit_cred(db, who, "credential.validation_requested", out)
    db.commit()
    return out


@router.delete("/credentials/{cred_id}", status_code=204)
def delete_credential(cred_id: UUID, body: CredentialAction, db: Db, who: Admin) -> Response:
    cred = svc.get_credential(db, cred_id)
    if cred is None:
        raise not_found("credential-not-found", "Credential")
    pc = svc.get_connection(db, cred["project_connection_id"])
    if pc is None:  # CS-8: never compare against an empty expected name
        raise not_found("connection-not-found", "Project connection")
    _confirm(body.typed_confirmation, pc["name"])
    stepup_id = consume_stepup(
        db, who, body.stepup_id, action=DELETE_STEPUP_ACTION, target_id=str(cred_id)
    )
    before = svc.delete_credential(db, cred_id)
    _audit_cred(db, who, "credential.delete", {**before, "state": "deleted"}, stepup_id=stepup_id)
    db.commit()
    return Response(status_code=204)
