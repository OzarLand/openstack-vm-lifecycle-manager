"""Run inside the worker container (``python - < worker_checks.py``, by ``make smoke``).

Proves: the worker process is the unprivileged ``ovlm`` user holding exactly CAP_SETUID/SETGID/KILL (ambient); the
image ships ansible and the pinned ansible.posix collection; and ansible really runs as ``ovlm-ansible``."""

import json
import os
import pathlib
import shutil
import subprocess
import sys

CAP_SETGID, CAP_SETUID, CAP_KILL = 6, 7, 5
WANTED = (1 << CAP_SETGID) | (1 << CAP_SETUID) | (1 << CAP_KILL)


def worker_pid() -> int:
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                argv = pathlib.Path(f"/proc/{entry}/cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            if argv[:1] and argv[0].endswith(b"ovlm") and b"worker" in argv[1:2]:
                return int(entry)
            if (
                argv[:2]
                and argv[0].endswith(b"python")
                and argv[1].endswith(b"ovlm")
                and b"worker" in argv[2:3]
            ):
                return int(entry)
    raise SystemExit("worker process not found")


status = dict(
    line.split(":", 1)
    for line in pathlib.Path(f"/proc/{worker_pid()}/status").read_text().splitlines()
    if ":" in line
)
assert status["Uid"].split()[0] == "10001", f"worker is not uid 10001: {status['Uid']}"
for key in ("CapAmb", "CapEff", "CapPrm", "CapBnd"):
    assert int(status[key].strip(), 16) == WANTED, (
        f"{key} is {status[key].strip()}, expected {WANTED:x}"
    )

manifest = json.loads(
    pathlib.Path(
        "/opt/ovlm/collections/ansible_collections/ansible/posix/MANIFEST.json"
    ).read_text()
)
assert manifest["collection_info"]["version"] == "2.2.2", manifest["collection_info"]["version"]

# ssh (ansible's connection, ssh-keyscan/ssh-keygen for host-key pinning) and git (the verified clone) are shipped.
for binary, probe in (
    ("ssh", ["-V"]),
    ("ssh-keyscan", ["-V"]),
    ("ssh-keygen", ["-?"]),
    ("git", ["--version"]),
):
    path = shutil.which(binary)
    assert path, f"{binary} is missing from the worker image"
    # as the ansible user too: it runs ssh, so it must be able to execute these
    proc = subprocess.run(  # noqa: S603
        [path, *probe], user="ovlm-ansible", group="ovlm-ansible", extra_groups=[],
        env={"HOME": "/nonexistent"}, capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    assert proc.returncode in (0, 1) and (proc.stdout + proc.stderr).strip(), (
        f"{binary} does not run: {proc.stderr}"
    )

# The root filesystem is read-only: like the runner, use a directory under the tmpfs run root, shared with the
# runner user through its group (the worker is a member of ovlm-ansible; it owns the directory).
scratch = pathlib.Path("/run/ovlm/smoke")
scratch.mkdir(mode=0o770)
os.chown(scratch, -1, 10002)
os.chmod(scratch, 0o770)  # noqa: S103 - group-shared scratch dir under the 0710 tmpfs run root
try:
    proc = subprocess.run(  # noqa: S603
        ["/opt/venv/bin/ansible", "--version"],
        user="ovlm-ansible", group="ovlm-ansible", extra_groups=[],
        env={"HOME": str(scratch), "ANSIBLE_HOME": str(scratch / "home"), "ANSIBLE_LOCAL_TEMP": str(scratch / "tmp")},
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
finally:
    shutil.rmtree(scratch, ignore_errors=True)
assert proc.returncode == 0 and "ansible [core" in proc.stdout, proc.stderr
who = subprocess.run(  # noqa: S603
    ["/usr/bin/id", "-u"], user="ovlm-ansible", capture_output=True, text=True, check=True
).stdout.strip()
assert who == "10002", who
# Credential store KEK: the worker (uid ovlm) reads its 0600 copy; ovlm-ansible reads neither copy nor original.
kek_copy = pathlib.Path("/run/ovlm-kek/worker_kek")
assert kek_copy.stat().st_uid == 10001 and (kek_copy.stat().st_mode & 0o077) == 0, (
    "KEK copy is not 0600 ovlm"
)
for path in ("/run/ovlm-kek/worker_kek", "/run/secrets/worker_kek"):
    denied = subprocess.run(  # noqa: S603
        ["/usr/bin/cat", path], user="ovlm-ansible", group="ovlm-ansible", extra_groups=[],
        capture_output=True, check=False,
    )  # fmt: skip
    assert denied.returncode != 0, f"ovlm-ansible can read {path}"
sys.stdout.write(f"worker image OK: {proc.stdout.splitlines()[0]}\n")
sys.exit(0)
