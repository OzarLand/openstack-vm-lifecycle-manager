"""Unit tests for the audit allowlist (no database)."""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterator

import pytest

from ovlm import audit
from ovlm.audit.allowlist import _ENTITIES, AllowlistError


@pytest.fixture(autouse=True)
def _isolated_registry() -> Iterator[None]:
    before = dict(_ENTITIES)
    yield
    _ENTITIES.clear()
    _ENTITIES.update(before)


@pytest.mark.parametrize(
    "field",
    [
        "password",
        "db_password",
        "api_key",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "private_key",
        "credential",
        "cookie",
        "password_hash",
        "totp_seed",
        "ciphertext",
        "vault_password",
    ],
)
def test_sensitive_looking_fields_cannot_be_allowlisted(field: str) -> None:
    with pytest.raises(AllowlistError, match="sensitive"):
        audit.register_entity("thing", ["name", field])


def test_snapshot_keeps_only_allowlisted_fields() -> None:
    audit.register_entity("profile", ["name", "automation_sha"])
    out = audit.snapshot(
        "profile",
        {"name": "web", "automation_sha": "a" * 40, "ssh_private_key": "-----BEGIN", "vault": "x"},
    )
    assert out == {"name": "web", "automation_sha": "a" * 40}
    assert audit.snapshot("profile", None) is None


def test_secret_fields_only_leave_a_changed_marker() -> None:
    audit.register_entity("credential_ref", ["name", "key_id"], secret_fields=["secret_value"])
    before, after = audit.snapshot_pair(
        "credential_ref",
        {"name": "n", "key_id": "k1", "secret_value": "OLD-CANARY"},
        {"name": "n", "key_id": "k2", "secret_value": "NEW-CANARY"},
    )
    assert before == {"name": "n", "key_id": "k1"}
    assert after == {"name": "n", "key_id": "k2", "changed_fields": ["secret_value"]}
    _, unchanged = audit.snapshot_pair(
        "credential_ref", {"secret_value": "same"}, {"secret_value": "same"}
    )
    assert unchanged == {}
    for blob in (str(before), str(after)):
        assert "CANARY" not in blob


def test_unregistered_entity_is_refused_and_registration_is_stable() -> None:
    with pytest.raises(AllowlistError, match="no audit allowlist"):
        audit.snapshot("nope", {"a": 1})
    audit.register_entity("x", ["a"])
    audit.register_entity("x", ["a"])  # idempotent
    with pytest.raises(AllowlistError, match="different"):
        audit.register_entity("x", ["a", "b"])
    with pytest.raises(AllowlistError, match="both allowed and secret"):
        audit.register_entity("y", ["a"], secret_fields=["a"])


def test_values_are_made_json_safe() -> None:
    audit.register_entity("t", ["when", "id", "tags", "obj"])
    uid = uuid.uuid4()
    out = audit.snapshot(
        "t",
        {
            "when": dt.datetime(2026, 1, 2, tzinfo=dt.UTC),
            "id": uid,
            "tags": {"b", "a"},
            "obj": object,
        },
    )
    assert out is not None
    assert (
        out["when"].startswith("2026-01-02") and out["id"] == str(uid) and out["tags"] == ["a", "b"]
    )
    assert isinstance(out["obj"], str)
