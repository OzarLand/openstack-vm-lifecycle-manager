"""Run inside the worker container as ``ovlm`` (``docker compose exec -T -u ovlm worker python - < ...``, by
``make smoke``).

Review CS-6 (SF-1): after start-up no process in the worker runs as uid 0, and none holds ``CAP_DAC_READ_SEARCH``
(the capability that reads the 0400 KEK) in its permitted, effective or ambient set. PID 1 is tini running as
``ovlm``, not docker-init as root.

A process injected from outside by ``docker compose exec`` or by the healthcheck starts as the container user (root)
for the few milliseconds before it drops privileges (the healthcheck runs ``setpriv`` first). Such a process is only
reported if it is still there, still root, after a short wait: a long-lived root process is what this check is for.
"""

import os
import pathlib
import sys
import time

CAP_DAC_READ_SEARCH = 2


def status(pid: str) -> dict[str, str] | None:
    try:
        text = pathlib.Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return None  # gone meanwhile
    return {
        k: v.strip() for k, v in (line.split(":", 1) for line in text.splitlines() if ":" in line)
    }


def cmdline(pid: str) -> str:
    try:
        return (
            pathlib.Path(f"/proc/{pid}/cmdline")
            .read_bytes()
            .replace(b"\0", b" ")
            .decode(errors="replace")
        )
    except OSError:
        return "?"


def offenders() -> dict[str, str]:
    found = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        st = status(pid)
        if st is None:
            continue
        uids = st["Uid"].split()  # real, effective, saved, filesystem
        caps = {k: int(st[k], 16) for k in ("CapPrm", "CapEff", "CapAmb")}
        why = []
        if "0" in uids:
            why.append(f"uid {st['Uid']}")
        held = [k for k, v in caps.items() if v & (1 << CAP_DAC_READ_SEARCH)]
        if held:
            why.append(f"DAC_READ_SEARCH in {held}")
        if why:
            found[pid] = f"{cmdline(pid)!r}: {', '.join(why)}"
    return found


assert os.getuid() == 10001, f"run this check as ovlm, not uid {os.getuid()}"
first = offenders()
if first:
    time.sleep(3)  # let a healthcheck or another exec finish dropping privileges
    still = {pid: why for pid, why in offenders().items() if pid in first}
    if still:
        raise SystemExit(f"privileged processes in the worker after start-up: {still}")

init = status("1")
assert init is not None and init["Uid"].split()[0] == "10001", (
    f"PID 1 is not uid ovlm: {init and init['Uid']}"
)
assert cmdline("1").startswith("/usr/bin/tini "), f"PID 1 is not tini: {cmdline('1')!r}"
sys.stdout.write("worker has no root process and no DAC_READ_SEARCH; PID 1 is tini as ovlm\n")
