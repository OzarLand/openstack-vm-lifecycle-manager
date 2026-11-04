"""SEC-C-3 (write credential in memory, nothing ambient read) and SEC-C-4 (TLS verification always on)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from openstack.config import loader

from ovlm.config.secrets import known_secrets
from ovlm.openstack import errors
from ovlm.openstack.ownership import InMemoryOwnershipRegistry
from ovlm.openstack.sdk_read import connect_read_only
from ovlm.openstack.sdk_write import (
    SdkWriteBackend,
    WriteCredential,
    connect_write,
    connect_write_from_clouds_yaml,
)
from tests.unit.test_openstack_allowlist import AUTH_URL, RUN, SID, CannedCloud

SECRET = "app-cred-s3cret-value"
CRED = WriteCredential(
    auth_url=AUTH_URL,
    application_credential_id="cred-id",
    application_credential_secret=SECRET,
    region_name="R1",
)


def _registry() -> InMemoryOwnershipRegistry:
    return InMemoryOwnershipRegistry(RUN)


def _clouds_yaml(tmp_path: Path, **extra: str) -> Path:
    lines = "".join(f"    {k}: {v}\n" for k, v in extra.items())
    path = tmp_path / "clouds.yaml"
    path.write_text(
        "clouds:\n  lab:\n    auth_type: v3applicationcredential\n    auth:\n"
        f"      auth_url: {AUTH_URL}\n      application_credential_id: id\n"
        f"      application_credential_secret: {SECRET}\n    region_name: R1\n{lines}"
    )
    return path


@pytest.fixture
def files_read(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Every file list the SDK's config loader tries to read."""
    seen: list[list[str]] = []
    original = loader.OpenStackConfig._load_yaml_json_file

    def spy(self: Any, filelist: list[str]) -> Any:
        seen.append(list(filelist))
        return original(self, filelist)

    monkeypatch.setattr(loader.OpenStackConfig, "_load_yaml_json_file", spy)
    return seen


# --- SEC-C-3 ------------------------------------------------------------------------------------------------


def test_write_credential_hides_its_secret_and_refuses_empty_fields() -> None:
    assert SECRET not in repr(CRED)
    with pytest.raises(errors.WriteNotAllowedError):
        WriteCredential(AUTH_URL, "id", "", "R1")
    with pytest.raises(errors.WriteNotAllowedError):
        WriteCredential(AUTH_URL, "id", "s", "")


def test_connect_write_exists_only_in_the_worker() -> None:
    for role in ("api", "migrate"):
        with pytest.raises(errors.WriteNotAllowedError, match="worker"):
            connect_write(CRED, registry=_registry(), gate=lambda _a: None, process_role=role)
    assert SECRET not in known_secrets()


def test_connect_write_uses_the_in_memory_credential_and_reads_nothing_ambient(
    monkeypatch: pytest.MonkeyPatch, files_read: list[list[str]]
) -> None:
    for k, v in {"OS_AUTH_URL": "https://ambient.invalid/v3", "OS_CLOUD": "lab",
                 "OS_APPLICATION_CREDENTIAL_SECRET": "ambient", "OS_CLIENT_CONFIG_FILE": "/x.yaml"}.items():  # fmt: skip
        monkeypatch.setenv(k, v)
    client = connect_write(CRED, registry=_registry(), gate=lambda _a: None, process_role="worker")
    assert all(files == [] for files in files_read), files_read  # no clouds/secure/vendor file
    backend = client._backend
    assert isinstance(backend, SdkWriteBackend)
    auth = backend._conn.config.config["auth"]
    assert auth["auth_url"] == AUTH_URL and auth["application_credential_secret"] == SECRET
    assert backend._conn.config.config["region_name"] == "R1"
    assert SECRET in known_secrets()  # the redaction backstop knows it
    # the write guard is on the session before any request; the token request goes out with the credential
    assert getattr(backend._conn.session, "_ovlm_write_guard", False)
    cloud = CannedCloud()
    backend._conn.session.session.mount("http://", cloud)
    with pytest.raises(errors.WriteNotAllowedError):  # no gate bound outside the client's own calls
        backend._conn.compute.delete(f"/servers/{SID}")
    assert cloud.writes() == []
    token = next(b for m, u, _h, b in cloud.sent if u.endswith("/auth/tokens"))
    assert token["auth"]["identity"]["application_credential"]["secret"] == SECRET


def test_clouds_yaml_variant_reads_only_the_named_file(
    tmp_path: Path, files_read: list[list[str]]
) -> None:
    path = _clouds_yaml(tmp_path)
    client = connect_write_from_clouds_yaml(
        "lab", path, registry=_registry(), gate=lambda _a: None, process_role="worker"
    )
    assert [f for f in files_read if f] == [
        [str(path)]
    ]  # no secure.yaml, no vendor file, no search path
    assert getattr(client._backend._conn.session, "_ovlm_write_guard", False)  # type: ignore[attr-defined]
    assert SECRET in known_secrets()
    with pytest.raises(errors.WriteNotAllowedError, match="worker"):
        connect_write_from_clouds_yaml(
            "lab", path, registry=_registry(), gate=lambda _a: None, process_role="api"
        )


# --- SEC-C-4 ------------------------------------------------------------------------------------------------

INSECURE = [{"verify": "false"}, {"insecure": "true"}, {"verify": "'false'"},
            {"insecure": "true", "cacert": "/etc/hostname"}, {"cacert": "/nonexistent/ca.pem"}]  # fmt: skip


@pytest.mark.parametrize("extra", INSECURE)
def test_write_client_refuses_tls_verification_off(tmp_path: Path, extra: dict[str, str]) -> None:
    path = _clouds_yaml(tmp_path, **extra)
    with pytest.raises(errors.UnsupportedCloudError, match="TLS verification"):
        connect_write_from_clouds_yaml(
            "lab", path, registry=_registry(), gate=lambda _a: None, process_role="worker"
        )


@pytest.mark.parametrize("extra", INSECURE)
def test_read_client_refuses_tls_verification_off(tmp_path: Path, extra: dict[str, str]) -> None:
    with pytest.raises(errors.UnsupportedCloudError, match="TLS verification"):
        connect_read_only("lab", _clouds_yaml(tmp_path, **extra))


def test_a_custom_ca_bundle_is_accepted(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    path = _clouds_yaml(tmp_path, cacert=str(ca))
    reader = connect_read_only("lab", path)
    assert reader._conn.session.verify == str(ca)
    writer = connect_write_from_clouds_yaml(
        "lab", path, registry=_registry(), gate=lambda _a: None, process_role="worker"
    )
    assert writer._backend._conn.session.verify == str(ca)  # type: ignore[attr-defined]
    in_memory = connect_write(
        WriteCredential(AUTH_URL, "id", SECRET, "R1", cacert=ca),
        registry=_registry(), gate=lambda _a: None, process_role="worker",
    )  # fmt: skip
    assert in_memory._backend._conn.session.verify == str(ca)  # type: ignore[attr-defined]
    assert connect_read_only("lab", _clouds_yaml(tmp_path))._conn.session.verify is True
