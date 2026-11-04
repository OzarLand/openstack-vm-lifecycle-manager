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
