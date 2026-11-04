"""The profile ``spec`` (data-model.md section 5, automation-contract.md section 1), validated with pydantic.

Everything is ``extra="forbid"``: an unknown key is an error, so nothing resolved can be smuggled in. In particular
the image is a match rule (``name`` or ``properties``), never an image id or "latest": it is resolved at plan time and
the unique match is recorded in the plan (SEC-R-29). Security groups are names, resolved to ids at plan time.

``spec_hash`` is the SHA-256 of the canonical JSON of the validated spec (defaults included), so two requests that mean
the same thing hash the same, and the plan hash can bind to it (security-model.md section 7.1).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ovlm.profiles.errors import ProfileError

SHA = re.compile(r"^[0-9a-f]{40}$")
_REPO = re.compile(
    r"^(https://[^\s/@]+(:\d+)?/[^\s]+|ssh://[^\s/@]+@[^\s/]+/[^\s]+|[a-z0-9_.-]+@[^\s:/]+:[^\s]+)$"
)
_SECRET_REF = re.compile(r"^ovlm-secret://\S+$")
_NAME = Field(min_length=1, max_length=255)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ImageMatch(_Strict):
    """Exactly one of ``name`` or ``properties``. Never an id, never "newest wins"."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    properties: dict[str, str] | None = None

    @model_validator(mode="after")
    def _one_rule(self) -> ImageMatch:
        if (self.name is None) == (not self.properties):
            raise ValueError("give exactly one of 'name' or a non-empty 'properties'")
        if self.name is not None and self.name.strip().lower() == "latest":
            raise ValueError(
                "'latest' is not an image: the image is resolved to a unique match at plan time"
            )
        return self


class Network(_Strict):
    network_id: UUID
    subnet_id: UUID


class DataVolume(_Strict):
    volume_id: UUID
    fs_type: Literal["ext4", "xfs"]
    fs_uuid: UUID | None = None
    label: str | None = Field(default=None, min_length=1, max_length=16)
    mount_point: str = Field(pattern=r"^/[A-Za-z0-9_./-]*$", max_length=255)
    snapshot_before_handoff: bool = False

    @model_validator(mode="after")
    def _identity(self) -> DataVolume:
        if (self.fs_uuid is None) == (self.label is None):
            raise ValueError("give exactly one of 'fs_uuid' or 'label' to identify the filesystem")
        if ".." in self.mount_point.split("/"):
            raise ValueError("mount_point must not contain '..'")
        return self


class Automation(_Strict):
    repo: str = Field(max_length=500)
    sha: str
    playbook_dir: str = Field(default="playbooks/", max_length=255)
    requirements: str = Field(default="requirements.yml", max_length=255)
    inventory_vars: dict[str, Any] = Field(default_factory=dict)
    secret_refs: dict[str, str] = Field(default_factory=dict)
    store_diffs: bool = False

    @field_validator("repo")
    @classmethod
    def _repo(cls, v: str) -> str:
        if not _REPO.match(v):
            raise ValueError("repo must be an https or ssh URL")
        return v

    @field_validator("sha")
    @classmethod
    def _sha(cls, v: str) -> str:
        if not SHA.match(v):
            raise ValueError(
                "sha must be a full 40-character lowercase commit SHA (no branch, no tag, no short SHA)"
            )
        return v

    @field_validator("playbook_dir", "requirements")
    @classmethod
    def _relative(cls, v: str) -> str:
        if v.startswith("/") or ".." in v.split("/"):
            raise ValueError("must be a relative path inside the repository")
        return v

    @field_validator("secret_refs")
    @classmethod
    def _refs(cls, v: dict[str, str]) -> dict[str, str]:
        for key, ref in v.items():
            if not _SECRET_REF.match(ref):
                raise ValueError(
                    f"secret_refs.{key} must be an ovlm-secret:// reference, never a value"
                )
        return v


class GuestAccess(_Strict):
    ssh_user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    host_key_policy: Literal["injected", "console", "tofu"] = "injected"


class ExternalCheck(_Strict):
    scheme: Literal["http", "https", "tcp"]
    port: int = Field(ge=1, le=65535)
    path: str | None = Field(default=None, max_length=500)
    expected_status: int | None = Field(default=None, ge=100, le=599)


class HealthCheck(_Strict):
    external: ExternalCheck
    accept_degraded: bool = False


class Cutover(_Strict):
    floating_ip_id: UUID
    method: Literal["floating_ip"] = "floating_ip"


class ProfileSpec(_Strict):
    flavor: str = _NAME
    image: ImageMatch
    network: Network
    security_groups: Annotated[list[str], Field(min_length=1, max_length=50)]
    availability_zone: str = Field(default="from_volume", min_length=1, max_length=255)
    data_volume: DataVolume | None = (
        None  # at most one data volume (MVP): a single object, not a list
    )
    stateless_service: bool = False
    automation: Automation
    guest_access: GuestAccess
    health_check: HealthCheck
    cutover: Cutover
    strategy: Literal["bluegreen_fip_v1"] = "bluegreen_fip_v1"

    @model_validator(mode="after")
    def _data_or_stateless(self) -> ProfileSpec:
        if (self.data_volume is None) == (not self.stateless_service):
            raise ValueError("declare exactly one of 'data_volume' or 'stateless_service: true'")
        return self


def validate_spec(raw: Any) -> ProfileSpec:
    """Validate or raise :class:`ProfileError` (422) with ``errors[]`` (field path and message only, no input values)."""
    try:
        return ProfileSpec.model_validate(raw)
    except ValidationError as exc:
        raise ProfileError(
            422, "invalid-profile-spec", "Invalid profile spec",
            f"The spec has {exc.error_count()} problem(s).", "Fix the listed fields and send the spec again.",
            errors=[{"field": ".".join(str(p) for p in e["loc"]), "message": e["msg"]} for e in exc.errors()],
        ) from None  # fmt: skip


def canonical(spec: ProfileSpec) -> dict[str, Any]:
    return spec.model_dump(mode="json", exclude_none=True)


def spec_hash(spec: ProfileSpec) -> str:
    blob = json.dumps(canonical(spec), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode()).hexdigest()
