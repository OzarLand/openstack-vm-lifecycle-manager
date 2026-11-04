"""A stand-in for the ``ansible-runner`` executable: records how it was invoked and writes whatever result,
events and output the test asks for (through the ``fake`` extra-var). Used to test the runner's handling of
untrusted output without ansible. The real ansible-runner is exercised by tests/integration."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path


def main() -> None:
    args = sys.argv[1:]
    pdd = Path(args[1])
    ident = args[args.index("-i") + 1]
    ev = json.loads((pdd / "env" / "extravars").read_text())
    fake = ev.get("fake", {})
    art = pdd / "artifacts" / ident
    art.mkdir(parents=True, exist_ok=True)

    def mode(p: Path) -> str:
        return oct(stat.S_IMODE(p.stat().st_mode))

    record = fake.get("record")
    if record:
        env_dir = pdd / "env"
        key = next(iter(sorted(env_dir.glob("guest_key"))), None)
        Path(record).write_text(
            json.dumps(
                {
                    "argv": sys.argv,
                    "env": dict(os.environ),
                    "cwd": os.getcwd(),
                    "uid": os.getuid(),
                    "pgid": os.getpgrp(),
                    "pid": os.getpid(),
                    "run_dir_mode": mode(pdd),
                    "env_files": sorted(p.name for p in env_dir.iterdir()),
                    "key_mode": mode(key) if key else None,
                    "key_text": key.read_text() if key else None,
                    "vault_file": os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE"),
                    "vault_mode": mode(Path(os.environ["ANSIBLE_VAULT_PASSWORD_FILE"]))
                    if os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
                    else None,
                    "vault_text": Path(os.environ["ANSIBLE_VAULT_PASSWORD_FILE"]).read_text()
                    if os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE")
                    else None,
                    "inventory": (pdd / "inventory" / "hosts.yml").read_text(),
                    "known_hosts": (pdd / "known_hosts").read_text(),
                    "ansible_cfg": (pdd / "ansible.cfg").read_text(),
                    "extravars": (pdd / "env" / "extravars").read_text(),
                    "settings": (pdd / "env" / "settings").read_text(),
                    "project_files": sorted(p.name for p in (pdd / "project").iterdir()),
                    "playbook_exists": (pdd / "project" / args[args.index("-p") + 1]).is_file(),
                }
            )
        )
    if fake.get("try_read") and record:
        rec = json.loads(Path(record).read_text())
        try:
            Path(fake["try_read"]).read_text()
            rec["read_attempt"] = "allowed"
        except PermissionError:
            rec["read_attempt"] = "denied"
        Path(record).write_text(json.dumps(rec))
    if fake.get("sleep"):
        time.sleep(fake["sleep"])
    (art / "stdout").write_text(fake.get("stdout", "PLAY RECAP\n"))
    if "events" in fake:
        d = art / "job_events"
        d.mkdir(exist_ok=True)
        for i, e in enumerate(fake["events"]):
            (d / f"{i:04d}-x.json").write_text(json.dumps(e) if not isinstance(e, str) else e)
    result = fake.get("result")
    if fake.get("result_symlink"):
        (art / "result.json").symlink_to(fake["result_symlink"])
    elif isinstance(result, str):
        (art / "result.json").write_text(result)
    elif result is not None:
        (art / "result.json").write_text(json.dumps(result))
    if fake.get("stderr"):
        sys.stderr.write(fake["stderr"])
    sys.exit(fake.get("rc", 0))


if __name__ == "__main__":
    main()
