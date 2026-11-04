from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from ovlm.config import Settings, read_secret_file
from ovlm.observability.context import bind_context
from ovlm.observability.logging import configure_logging


@pytest.fixture
def stream() -> Iterator[io.StringIO]:
    buf = io.StringIO()
    configure_logging("test", "DEBUG", stream=buf)
    yield buf
    logging.getLogger().handlers[:] = []


def lines(buf: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in buf.getvalue().splitlines()]


def test_json_line_with_context(stream: io.StringIO) -> None:
    log = logging.getLogger("t")
    with bind_context(run_id="run-1", step_id="step-2", request_id="req-3"):
        log.info("hello %s", "world", extra={"count": 3})
    log.info("outside")
    first, second = lines(stream)
    assert first["event"] == "hello world"
    assert first["level"] == "INFO"
    assert first["process"] == "test"
    assert (first["run_id"], first["step_id"], first["request_id"]) == ("run-1", "step-2", "req-3")
    assert first["count"] == 3
    assert "ts" in first
    assert "run_id" not in second  # context is reset after the block


def test_unknown_context_field_rejected() -> None:
    with pytest.raises(ValueError), bind_context(bogus=1):
        pass


def test_secret_value_never_reaches_log_output(stream: io.StringIO, tmp_path: Path) -> None:
    """E1-2 acceptance: a secret read from a file does not appear in the output, however it is logged."""
    secret = 'Tr0ub4dor&3"quoted\\back'
    pw = tmp_path / "db_password"
    pw.write_text(secret + "\n")
    settings = Settings(process_role="api", development_mode=True, db={"password_file": pw})
    url = settings.db_url()  # reads and registers the secret
    assert read_secret_file(pw) == secret

    log = logging.getLogger("leak")
    log.info("plain: " + secret)
    log.info("arg: %s", secret)
    log.info("dict: %s", {"k": secret})
    log.info("extra", extra={"anything": secret, "nested": {"x": [secret]}})
    log.info("url %s", f"postgresql://ovlm_api:{secret}@db/ovlm")
    log.info("repr %r", secret)
    log.info("settings %r", settings)
    log.info("sqlalchemy url %s", url.render_as_string(hide_password=False))
    try:
        raise RuntimeError(f"connection failed with password {secret}")
    except RuntimeError:
        log.exception("boom")
    log.warning("exc_info string", exc_info=(RuntimeError, RuntimeError(secret), None))

    out = stream.getvalue()
    assert out, "nothing was logged"
    assert secret not in out
    assert json.dumps(secret)[1:-1] not in out
    assert "Tr0ub4dor" not in out
    assert "[REDACTED]" in out


def test_pattern_backstop_for_unregistered_secrets(stream: io.StringIO) -> None:
    log = logging.getLogger("pat")
    log.info("connect postgresql://user:hunter2hunter2@host/db")
    log.info("header Authorization: Bearer abcdefgh12345678")
    log.info("x", extra={"api_token": "zzz", "password": "p"})
    out = stream.getvalue()
    for leaked in ("hunter2hunter2", "abcdefgh12345678", '"zzz"', '"p"'):
        assert leaked not in out
