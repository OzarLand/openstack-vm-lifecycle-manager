from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from sqlalchemy.engine import URL

from tests.integration.conftest import ROOT, settings_for
from tests.integration.test_migrations import migrate


def test_worker_process_heartbeats_and_stops_on_sigterm(
    admin_url: URL, fresh_db: str, secrets_dir: Path
) -> None:
    migrate(admin_url, fresh_db, secrets_dir)
    s = settings_for("worker", admin_url, fresh_db, secrets_dir)
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("OVLM_")},
        "OVLM_CONFIG_FILE": "/nonexistent",
        "OVLM_DB__HOST": str(s.db.host),
        "OVLM_DB__PORT": str(s.db.port),
        "OVLM_DB__NAME": s.db.name,
        "OVLM_DB__SSLMODE": "disable",
        "OVLM_DB__PASSWORD_FILE": str(s.db.password_file),
        "OVLM_MIGRATIONS_DIR": str(ROOT / "migrations"),
        "OVLM_HTTP__METRICS_PORT": "19101",
        "OVLM_WORKER__HEARTBEAT_INTERVAL": "0.2",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "ovlm.cli", "worker"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        body = ""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                body = (
                    urllib.request.urlopen("http://127.0.0.1:19101/metrics", timeout=2)
                    .read()
                    .decode()
                )  # noqa: S310
                if (
                    "ovlm_worker_loop_iterations_total 2.0" in body
                    or "iterations_total 3.0" in body
                ):
                    break
            except OSError:
                pass
            time.sleep(0.2)
        assert "ovlm_worker_db_reachable 1.0" in body, body
        assert urllib.request.urlopen("http://127.0.0.1:19101/healthz", timeout=2).status == 200  # noqa: S310
    finally:
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=20)
    assert proc.returncode == 0, out
    assert "shutdown requested" in out and "worker stopped" in out
    assert "worker-pw-test" not in out


def test_worker_refuses_to_start_when_schema_not_at_head(
    admin_url: URL, fresh_db: str, secrets_dir: Path
) -> None:
    # Migrated nothing: ovlm_worker cannot even connect (CONNECT is granted by the baseline).
    s = settings_for("worker", admin_url, fresh_db, secrets_dir)
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("OVLM_")},
        "OVLM_CONFIG_FILE": "/nonexistent",
        "OVLM_DB__HOST": str(s.db.host),
        "OVLM_DB__PORT": str(s.db.port),
        "OVLM_DB__NAME": s.db.name,
        "OVLM_DB__SSLMODE": "disable",
        "OVLM_DB__PASSWORD_FILE": str(s.db.password_file),
        "OVLM_MIGRATIONS_DIR": str(ROOT / "migrations"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "ovlm.cli", "worker"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1
    assert "worker-pw-test" not in result.stdout + result.stderr
