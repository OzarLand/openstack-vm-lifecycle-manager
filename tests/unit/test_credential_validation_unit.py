"""Credential validation rules (security-model.md 4.4), the read-only Keystone token check over a canned transport,
upload checks, and how the renewal's production ports use the store's refusals."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import pytest
import requests
from requests.adapters import BaseAdapter

from ovlm.automation.types import AutomationError
from ovlm.connections.credentials import ConnectionInfo, CredentialUnavailableError
from ovlm.connections.service import check_upload, normalise_auth_url, normalise_project_id
from ovlm.connections.validation import (
    KeystoneRefusedError,
    TokenFacts,
    TransientValidationError,
    evaluate_token,
    keystone_token_check,
)
from ovlm.registry.errors import DomainError
from ovlm.renewal.production import SdkCloudPort, StoreCredentialSource

NOW = datetime(2026, 11, 5, tzinfo=UTC)
PROJECT = "0123456789abcdef0123456789abcdef"
APP = "fedcba9876543210fedcba9876543210"
CONN = ConnectionInfo("pc", "lab", True, "https://keystone.test/v3", "R1", "public", PROJECT)
LATER = NOW + timedelta(days=90)


def facts(**kw: Any) -> TokenFacts:
    base: dict[str, Any] = {"project_id": PROJECT, "roles": ("reader",), "user_id": "u1",
                            "app_credential_id": APP, "restricted": True, "token_expires_at": None,
                            "record_status": 200, "record_expires_at": LATER, "record_unrestricted": False,
                            "record_roles": ()}  # fmt: skip
    return TokenFacts(**{**base, **kw})


def test_valid_read_and_write_credentials() -> None:
    assert evaluate_token("os_read", facts(), CONN, APP, LATER, NOW)[0]
    assert evaluate_token("os_write", facts(roles=("member", "reader")), CONN, APP, LATER, NOW)[0]
    assert evaluate_token("os_write", facts(roles=("member",)), CONN, APP, LATER, NOW)[0]


@pytest.mark.parametrize(
    ("kind", "change", "reason"),
    [
        ("os_read", {"project_id": "ffffffffffffffffffffffffffffffff"}, "not scoped"),
        ("os_read", {"roles": ("reader", "member")}, "other roles"),
        ("os_read", {"roles": ("member",)}, "lacks the role 'reader'"),
        ("os_write", {"roles": ("reader",)}, "lacks the role 'member'"),
        ("os_write", {"roles": ("member", "admin")}, "other roles"),
        ("os_write", {"roles": ("member", "manager")}, "other roles"),
        ("os_read", {"app_credential_id": "00000000000000000000000000000000"}, "not issued"),
        ("os_read", {"restricted": False}, "unrestricted"),
    ],
)
def test_wrong_scope_roles_id_or_unrestricted_are_refused(
    kind: str, change: dict[str, Any], reason: str
) -> None:
    ok, why = evaluate_token(kind, facts(**change), CONN, APP, LATER, NOW)
    assert not ok and reason in why


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"record_expires_at": None}, "never expires"),
        ({"record_expires_at": NOW + timedelta(days=181)}, "more than 180 days"),
        ({"record_expires_at": LATER + timedelta(hours=1)}, "later than the uploaded"),
        ({"record_expires_at": NOW - timedelta(seconds=1)}, "expired (Keystone)"),
        ({"record_status": 403}, "HTTP 403"),
        ({"record_status": None}, "cannot be verified"),
        ({"record_unrestricted": True}, "unrestricted"),
        ({"record_roles": ("reader", "admin")}, "other roles"),
    ],
)
def test_cs3_keystone_record_decides_the_expiry_not_the_form(
    change: dict[str, Any], reason: str
) -> None:
    """Review CS-3: the uploaded expires_at is checked against Keystone's own record of the application credential;
    a never-expiring one, or one later than 180 days or than the uploaded date, is refused whatever the form said."""
    ok, why = evaluate_token("os_read", facts(**change), CONN, APP, LATER, NOW)
    assert not ok and reason in why


def test_cs3_earlier_keystone_expiry_is_accepted_and_reported() -> None:
    ok, why = evaluate_token(
        "os_read", facts(record_expires_at=NOW + timedelta(days=10)), CONN, APP, LATER, NOW
    )
    assert ok and "(Keystone)" in why


def test_expired_credential_is_refused() -> None:
    assert evaluate_token("os_read", facts(), CONN, APP, NOW - timedelta(seconds=1), NOW) == (
        False, "the credential is expired",
    )  # fmt: skip


# --- the Keystone check itself: one token request, nothing else -------------------------------------------------


class CannedKeystone(BaseAdapter):
    def __init__(
        self, status: int = 201, roles: tuple[str, ...] = ("reader",), record_status: int = 200,
        record_expires: str | None = "2026-12-01T00:00:00.000000",
    ) -> None:  # fmt: skip
        super().__init__()
        self.sent: list[tuple[str, str, bytes]] = []
        self.status, self.roles = status, roles
        self.record_status, self.record_expires = record_status, record_expires

    def send(self, request: requests.PreparedRequest, *a: Any, **kw: Any) -> requests.Response:
        body = request.body if isinstance(request.body, bytes) else str(request.body or "").encode()
        self.sent.append((str(request.method), str(request.url), body))
        resp = requests.Response()
        resp.status_code = self.status
        resp.headers["Content-Type"] = "application/json"
        resp.url, resp.request = str(request.url), request
        if request.method == "GET":  # the application credential's own record
            resp.status_code = self.record_status
            rec = {"application_credential": {
                "id": APP, "name": "ovlm", "expires_at": self.record_expires, "unrestricted": False,
                "project_id": PROJECT, "roles": [{"id": r, "name": r} for r in self.roles]}}  # fmt: skip
            resp._content = json.dumps(rec if self.record_status == 200 else {"error": {}}).encode()
            return resp
        if self.status == 201:
            resp.headers["X-Subject-Token"] = "tok"
            payload: Any = {"token": {
                "methods": ["application_credential"], "expires_at": "2099-01-01T00:00:00.000000Z",
                "issued_at": "2026-01-01T00:00:00.000000Z",
                "user": {"id": "svc-user", "name": "svc", "domain": {"id": "d", "name": "d"}},
                "project": {"id": PROJECT, "name": "p", "domain": {"id": "d", "name": "d"}},
                "roles": [{"id": r, "name": r} for r in self.roles], "catalog": [],
                "application_credential": {"id": APP, "name": "ovlm", "restricted": True},
            }}  # fmt: skip
        else:
            payload = {"error": {"code": self.status, "message": "nope"}}
        resp._content = json.dumps(payload).encode()
        return resp

    def close(self) -> None:
        pass


def test_keystone_check_sends_one_token_request_and_reads_the_record() -> None:
    ks = CannedKeystone()
    got = keystone_token_check("https://keystone.test/v3", APP, "s3cret-canary", True, adapter=ks)
    assert [(m, urlparse(u).path) for m, u, _ in ks.sent] == [
        ("POST", "/v3/auth/tokens"), ("GET", f"/v3/users/svc-user/application_credentials/{APP}"),
    ]  # fmt: skip
    assert (
        b"s3cret-canary" in ks.sent[0][2]
    )  # the secret goes to Keystone only, in the token request only
    assert b"s3cret-canary" not in ks.sent[1][2]
    assert got.project_id == PROJECT and got.roles == ("reader",) and got.user_id == "svc-user"
    assert got.app_credential_id == APP and got.restricted is True
    assert got.record_read and got.record_expires_at == datetime(2026, 12, 1, tzinfo=UTC)
    assert got.record_unrestricted is False and got.record_roles == ("reader",)
    assert evaluate_token("os_read", got, CONN, APP, LATER, NOW)[0]


def test_cs3_never_expiring_or_unreadable_record_from_keystone() -> None:
    never = keystone_token_check(
        "https://keystone.test/v3", APP, "s", True, adapter=CannedKeystone(record_expires=None)
    )
    assert never.record_read and never.record_expires_at is None
    assert "never expires" in evaluate_token("os_read", never, CONN, APP, LATER, NOW)[1]
    hidden = keystone_token_check(
        "https://keystone.test/v3", APP, "s", True, adapter=CannedKeystone(record_status=403)
    )
    assert (
        not hidden.record_read and not evaluate_token("os_read", hidden, CONN, APP, LATER, NOW)[0]
    )
    with pytest.raises(TransientValidationError):
        keystone_token_check(
            "https://keystone.test/v3", APP, "s", True, adapter=CannedKeystone(record_status=503)
        )


def test_keystone_refusal_is_a_verdict_and_carries_no_secret() -> None:
    with pytest.raises(KeystoneRefusedError) as exc:
        keystone_token_check(
            "https://keystone.test/v3", APP, "s3cret-canary", True, adapter=CannedKeystone(401)
        )
    assert "s3cret-canary" not in str(exc.value) and "401" in str(exc.value)


# --- upload checks ----------------------------------------------------------------------------------------------


def test_upload_checks() -> None:
    up = check_upload("os_write", APP.upper(), NOW + timedelta(days=30), now=NOW)
    assert up.app_credential_id == APP
    with pytest.raises(DomainError) as e:
        check_upload("os_write", APP, NOW - timedelta(days=1), now=NOW)
    assert e.value.code == "credential-expired"
    bads: list[Callable[[], object]] = [
        lambda: check_upload("os_read", APP, NOW + timedelta(days=181), now=NOW),
        lambda: check_upload("os_read", APP, None, now=NOW),
        lambda: check_upload("os_read", None, LATER, now=NOW),
        lambda: check_upload("os_read", APP, datetime(2027, 1, 1), now=NOW),  # noqa: DTZ001 - naive on purpose
        lambda: check_upload("os_read", "not-hex", LATER, now=NOW),
        lambda: check_upload("ssh_key", APP, None, now=NOW),
        lambda: check_upload("vault_password", None, None, now=NOW),
    ]
    for bad in bads:
        with pytest.raises(DomainError):
            bad()
    assert check_upload("ssh_key", None, None, now=NOW).kind == "ssh_key"


def test_auth_url_and_project_id_normalisation() -> None:
    assert normalise_auth_url("https://keystone.test:5000/v3/") == "https://keystone.test:5000/v3"
    for bad in (
        "http://keystone.test/v3",
        "https://user:pw@keystone.test/v3",
        "https://k.test/v3?x=1",
    ):
        with pytest.raises(DomainError):
            normalise_auth_url(bad)
    assert normalise_project_id("01234567-89AB-CDEF-0123-456789ABCDEF") == PROJECT
    with pytest.raises(DomainError):
        normalise_project_id("default")


# --- production ports and the store's refusals -----------------------------------------------------------------


class _RefusingStore:
    def app_credential(self, pc: str, kind: str) -> Any:
        raise CredentialUnavailableError(
            "the write application credential (os_write) of this project expired at X"
        )

    def guest_key(self, pc: str) -> Any:
        raise AssertionError("not reached")

    def write_metadata(self, pc: str) -> Any:
        raise CredentialUnavailableError(
            "this project has no validated write application credential (os_write)"
        )

    def ca_path(self, info: Any) -> None:
        return None


def test_admission_gets_the_store_reason_and_steps_stop_for_a_human() -> None:
    port = SdkCloudPort(StoreCredentialSource(_RefusingStore()))
    assert (
        port.unavailable_reason("pc")
        == "the write application credential (os_write) of this project expired at X"
    )
    with pytest.raises(AutomationError, match="no validated write"):
        port.write_credential_expires_at("pc")
    with pytest.raises(AutomationError, match="expired at X"):
        port._creds("pc")  # noqa: SLF001


def test_cs8_typed_confirmation_never_matches_an_empty_expected_name() -> None:
    from ovlm.connections.api import _confirm

    with pytest.raises(DomainError):
        _confirm("", "")
    _confirm(" Lab ", "lab")
