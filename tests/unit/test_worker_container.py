"""The worker container keeps no root process (review CS-6, security follow-up SF-1).

``make smoke`` checks the running stack (``tests/smoke/worker_root_checks.py``). These tests check the files that
decide it, and run the real entrypoint (as root, when the sandbox allows) with a stand-in for tini, to show that the
init starts only after the drop: uid ovlm, CAP_SETUID/SETGID/KILL only, no DAC_READ_SEARCH.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
ENTRYPOINT = ROOT / "docker" / "worker-entrypoint.sh"
CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_DAC_READ_SEARCH = 5, 6, 7, 2
WANTED = (1 << CAP_SETGID) | (1 << CAP_SETUID) | (1 << CAP_KILL)


def _worker() -> dict[str, object]:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    return compose["services"]["worker"]  # type: ignore[no-any-return]


def test_compose_has_no_root_init_and_the_healthcheck_drops_to_ovlm() -> None:
    worker = _worker()
    assert not worker.get("init"), "init: true keeps docker-init as root PID 1 with DAC_READ_SEARCH"
    test = worker["healthcheck"]["test"]  # type: ignore[index]
    assert test[:4] == ["CMD", "setpriv", "--reuid=10001", "--regid=10001"], test
    assert "--bounding-set=-all" in test and "--no-new-privs" in test
    assert test.index("--") < test.index("python")


def test_the_worker_image_ships_tini_and_the_entrypoint_execs_it_after_the_drop() -> None:
    assert '"tini=${TINI_VERSION}"' in (ROOT / "Dockerfile").read_text()
    script = ENTRYPOINT.read_text()
    assert 'set -- "$TINI" -- ovlm "$@"' in script
    final = script[script.index("exec setpriv --reuid=10001 --regid=10001 --groups=10002") :]
    assert "--bounding-set=-all,+setuid,+setgid,+kill" in final.split('"$@"')[0]
    assert "dac_read_search" not in final.split('"$@"')[0]


@pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("setpriv") is None, reason="needs root and setpriv"
)
def test_entrypoint_starts_the_init_as_ovlm_without_dac_read_search() -> None:
    work = Path(tempfile.mkdtemp(prefix="ovlm-entrypoint-", dir="/tmp"))  # noqa: S108 - must be reachable by 10001
    try:
        work.chmod(0o755)
        stub = work / "tini"
        stub.write_text('#!/bin/sh\ncat /proc/self/status\necho "ARGS $*"\n')
        stub.chmod(0o755)
        script = work / "entrypoint.sh"
        text = ENTRYPOINT.read_text()
        assert "TINI=/usr/bin/tini" in text
        script.write_text(text.replace("TINI=/usr/bin/tini", f"TINI={stub}"))
        script.chmod(0o755)
        proc = subprocess.run(  # noqa: S603
            ["/bin/sh", str(script), "worker"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if proc.returncode != 0 and "Operation not permitted" in proc.stderr:
        pytest.skip(f"the sandbox cannot drop privileges: {proc.stderr.strip()}")
    assert proc.returncode == 0, proc.stderr
    status = dict(
        (k, v.strip())
        for k, v in (ln.split(":", 1) for ln in proc.stdout.splitlines() if ":" in ln)
    )
    assert status["Uid"].split() == ["10001"] * 4 and status["Gid"].split() == ["10001"] * 4
    for key in ("CapPrm", "CapEff", "CapAmb", "CapBnd"):
        assert int(status[key], 16) == WANTED, f"{key} is {status[key]}"
        assert not int(status[key], 16) & (1 << CAP_DAC_READ_SEARCH)
    assert status["NoNewPrivs"] == "1"
    assert "ARGS -- ovlm worker" in proc.stdout
