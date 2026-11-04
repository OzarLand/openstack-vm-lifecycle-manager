from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ovlm.config import SecretFileError, Settings, read_secret_file
from ovlm.config.secrets import known_secrets


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in list(__import__("os").environ):
        if key.startswith("OVLM_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(tmp_path / "absent.toml"))
    # Default api settings have no external_url; production checks are tested explicitly below.
    monkeypatch.setenv("OVLM_DEVELOPMENT_MODE", "true")


def test_defaults_and_role_mapping() -> None:
    assert Settings(process_role="api").db_role == "ovlm_api"
    assert Settings(process_role="worker").db_role == "ovlm_worker"
    assert Settings(process_role="migrate").db_role == "ovlm_owner"


def test_toml_file_and_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "ovlm.toml"
    cfg.write_text('[db]\nhost = "from-file"\nname = "filedb"\n[log]\nlevel = "DEBUG"\n')
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("OVLM_DB__HOST", "from-env")
    s = Settings()
    assert s.db.host == "from-env"  # env beats file
    assert s.db.name == "filedb"
    assert s.log.level == "DEBUG"


def test_unknown_key_in_file_is_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "ovlm.toml"
    cfg.write_text('[db]\nhots = "typo"\n')
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(cfg))
    with pytest.raises(ValidationError):
        Settings()


def test_db_role_is_not_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OVLM_DB__USER", "postgres")
    with pytest.raises(ValidationError):
        Settings()


def test_metrics_port_must_be_separate() -> None:
    with pytest.raises(ValidationError):
        Settings(http={"port": 9000, "metrics_port": 9000, "host": "x", "metrics_host": "x"})


def test_password_comes_from_file_and_is_registered(tmp_path: Path) -> None:
    pw = tmp_path / "pw"
    pw.write_text("s3cr3t-value\n")
    url = Settings(process_role="worker", db={"password_file": pw}).db_url()
    assert url.password == "s3cr3t-value"
    assert url.username == "ovlm_worker"
    assert "s3cr3t-value" not in repr(url)  # SQLAlchemy masks it
    assert "s3cr3t-value" in known_secrets()


def test_missing_and_empty_secret_files(tmp_path: Path) -> None:
    with pytest.raises(SecretFileError) as exc:
        read_secret_file(tmp_path / "nope")
    assert "nope" in str(exc.value)
    empty = tmp_path / "empty"
    empty.write_text("\n")
    with pytest.raises(SecretFileError):
        read_secret_file(empty)


# --- production checks (SEC-C-11, SEC-C-2) --------------------------------------------------------------------


def test_production_api_requires_external_url() -> None:
    with pytest.raises(ValidationError, match="external_url is required"):
        Settings(process_role="api", development_mode=False)
    ok = Settings(process_role="api", development_mode=False, external_url="https://ovlm.example.org")
    assert ok.external_url == "https://ovlm.example.org"
    # the worker and migrate processes do not serve the UI and do not need it
    assert Settings(process_role="worker", development_mode=False).external_url is None
    # an explicit development installation may run without it (Host-header fallback, warned once)
    assert Settings(process_role="api", development_mode=True).external_url is None


def test_development_mode_is_off_unless_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OVLM_DEVELOPMENT_MODE")
    assert Settings(process_role="worker").development_mode is False
    with pytest.raises(ValidationError):
        Settings(process_role="api")


def test_openstack_http_debug_is_refused_in_production() -> None:
    with pytest.raises(ValidationError, match="openstack_http_debug"):
        Settings(process_role="worker", development_mode=False, log={"openstack_http_debug": True})
    s = Settings(process_role="worker", development_mode=True, log={"openstack_http_debug": True})
    assert s.log.openstack_http_debug


def test_trusted_proxies_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OVLM_HTTP__TRUSTED_PROXIES", '["172.18.0.0/16"]')
    assert [str(n) for n in Settings().http.trusted_proxies] == ["172.18.0.0/16"]
