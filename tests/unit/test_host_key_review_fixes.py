"""Unit tests for the fixes of docs/reviews/review-inventory-sync-host-keys.md that need no database:
IS-3 (one address rule), IS-4 (reason codes for viewers), IS-8 (a client set-up error is a recorded failure)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from ovlm.inventory import job
from ovlm.inventory import reasons as rc
from ovlm.registry.ssh_target import first_fixed_address

# --- IS-3 ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixed_ips", "expected"),
    [
        (
            [{"ip_address": "2001:db8::5", "subnet_id": "s6"}, {"ip_address": "10.0.0.5"}],
            "2001:db8::5",
        ),
        (
            (("10.0.0.7", "s"), ("10.0.0.5", "s")),
            "10.0.0.7",
        ),  # the adapter's tuples, as blue_ref reads them
        ([], None),
        (None, None),
        ([{"ip_address": "not-an-ip"}], None),
        ([{"ip_address": "10.0.0.5; rm -rf /"}], None),
    ],
)
def test_first_fixed_address_is_fixed_ips_0(fixed_ips: Any, expected: str | None) -> None:
    assert first_fixed_address(fixed_ips) == expected


# --- IS-4 ---------------------------------------------------------------------------------------------------------

KEYSTONE = "https://keystone.example.invalid:5000/v3 401 Unauthorized"


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (None, None),
        ({"code": "auth_failed"}, {"code": "auth_failed"}),
        ({"code": "auth_failed", "message": KEYSTONE}, {"code": "auth_failed"}),
        ({"type": "CredentialUnavailable", "message": "no validated read credential"},
         {"code": "credential_unavailable"}),
        ({"type": "AuthenticationFailed", "message": KEYSTONE}, {"code": "auth_failed"}),
        ({"type": "ProjectMismatch", "message": "scoped to abc"}, {"code": "project_mismatch"}),
        ({"type": "Interrupted", "message": "the worker stopped"}, {"code": "interrupted"}),
        ({"type": "OpenStackError", "message": KEYSTONE}, {"code": "cloud_error"}),
        ({"code": "made-up", "message": KEYSTONE}, {"code": "cloud_error"}),
    ],
)  # fmt: skip
def test_public_error_keeps_a_code_only(error: Any, code: Any) -> None:
    assert rc.public_error(error) == code


@pytest.mark.parametrize(
    ("reason", "public"),
    [
        (None, None),
        ("project_mismatch", "project_mismatch"),
        ("client_setup_failed", "client_setup_failed"),
        ("project_disabled", "project_disabled"),
        ("the project connection is disabled", "project_disabled"),
        ("another sync of this project is running", "sync_already_running"),
        (
            f"AuthenticationFailed: the read credential could not obtain a token: {KEYSTONE}",
            "auth_failed",
        ),
        (f"ConnectFailure: {KEYSTONE}", "other"),
        (KEYSTONE, "other"),
    ],
)
def test_public_reason_is_a_code_never_text(reason: str | None, public: str | None) -> None:
    assert rc.public_reason(reason) == public


def test_every_failure_code_is_snake_case() -> None:
    assert all(c.replace("_", "").isalpha() and c.islower() for c in rc.CODES)


# --- IS-8 ---------------------------------------------------------------------------------------------------------


class _Store:
    def app_credential(self, project: str, kind: str) -> Any:
        return SimpleNamespace(kind=kind, connection=SimpleNamespace(openstack_project_id="p"))

    def ca_path(self, connection: Any) -> None:
        return None


def test_a_client_set_up_error_is_a_refusal_with_its_code() -> None:
    def broken(cred: Any, ca: Any, *, process_role: str) -> Any:
        raise ValueError("cacert /etc/ovlm/ca/missing.pem does not exist")

    with pytest.raises(job.CredentialRefusedError) as exc:
        job.StoreReadAccess(_Store(), connect=broken).open("pc")
    assert exc.value.code == rc.CLIENT_SETUP_FAILED
    assert "could not be set up" in str(exc.value) and "missing.pem" in str(exc.value)


def test_an_unavailable_credential_keeps_its_code() -> None:
    from ovlm.connections.credentials import CredentialUnavailableError

    def unavailable(cred: Any, ca: Any, *, process_role: str) -> Any:
        raise CredentialUnavailableError("OpenStack is reached by the worker only")

    with pytest.raises(job.CredentialRefusedError) as exc:
        job.StoreReadAccess(_Store(), connect=unavailable).open("pc")
    assert exc.value.code == rc.CREDENTIAL_UNAVAILABLE


def test_a_database_error_reading_the_credential_stays_retryable() -> None:
    class _Down(_Store):
        def app_credential(self, project: str, kind: str) -> Any:
            raise ConnectionError("database restarting")

    with pytest.raises(ConnectionError):
        job.StoreReadAccess(_Down(), connect=lambda *a, **k: None).open("pc")
