"""``ovlm kek``: the worker key pair of the credential store (docs/credential-store.md).

* ``ovlm kek generate --private-out PATH --public-out PATH``: a new X25519 key pair (private 0400, public 0444).
  Never overwrites. ``make secrets`` does the same with ``openssl``.
* ``ovlm kek public --private-in PATH``: print the public key (PEM) and its key id.
* ``ovlm kek status``: run in the worker (its settings): the key ids it holds, how many sealed secrets in use are
  wrapped to each key id, and the orphan sealed secrets (no credential refers to them; the validation job deletes
  them). Exit 0 only when every secret in use is wrapped to the **current** key: then the old key may be removed.
  Exit 2 while a secret is wrapped to a key the worker does not hold, 3 while one is still wrapped to a previous key.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from ovlm.secrets.envelope import parse_public_key
from ovlm.secrets.keyring import generate_private_pem, public_pem_of


def _write_new(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    path.chmod(mode)


def _generate(args: argparse.Namespace) -> int:
    for p in (args.private_out, args.public_out):
        if p.exists():
            sys.stderr.write(f"{p} exists: refusing to overwrite a key\n")
            return 1
    private = generate_private_pem()
    public = public_pem_of(private)
    _write_new(args.private_out, private, 0o400)
    _write_new(args.public_out, public, 0o444)
    sys.stdout.write(f"kek_id {parse_public_key(public).kek_id}\n")
    return 0


def _public(args: argparse.Namespace) -> int:
    public = public_pem_of(args.private_in.read_bytes())
    sys.stdout.write(public.decode())
    sys.stdout.write(f"# kek_id {parse_public_key(public).kek_id}\n")
    return 0


def _status(_: argparse.Namespace) -> int:
    from ovlm.config import Settings
    from ovlm.db.engine import make_engine
    from ovlm.secrets.keyring import load_keyring
    from ovlm.secrets.store import kek_usage, legacy_count, orphan_count

    settings = Settings(process_role="worker")
    if settings.kek.private_key_file is None:
        sys.stderr.write("kek.private_key_file is not set\n")
        return 1
    ring = load_keyring(
        settings.kek.private_key_file,
        settings.kek.previous_private_key_files,
        process_role="worker",
    )
    engine = make_engine(settings)
    with engine.connect() as c:
        usage = kek_usage(c)
        orphans = orphan_count(c)
        legacy = legacy_count(c)
    sys.stdout.write(f"current kek_id {ring.current_kek_id}; held {sorted(ring.kek_ids)}\n")
    for kid, n in sorted(usage.items()):
        held = (
            "current"
            if kid == ring.current_kek_id
            else ("held" if kid in ring.kek_ids else "NOT HELD")
        )
        sys.stdout.write(f"{kid}\t{n}\t{held}\n")
    sys.stdout.write(f"orphan sealed secrets (deleted by the validation job): {orphans}\n")
    sys.stdout.write(
        f"retired-format (ovlm-env-v1) secrets, never usable, not counted above: {legacy}\n"
    )
    return kek_status_code(usage, ring.current_kek_id, ring.kek_ids)


def kek_status_code(usage: dict[str, int], current: str, held: frozenset[str]) -> int:
    """0: every secret in use is wrapped to the current key (the old one may go); 2: some to a key not held;
    3: some still to a previous key (re-wrap not finished). Review CS-9."""
    in_use = {k for k, n in usage.items() if n}
    if not in_use <= held:
        return 2
    return 0 if in_use <= {current} else 3


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="ovlm kek", description="Credential store key pair")
    sub = parser.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="new worker key pair")
    g.add_argument("--private-out", type=Path, required=True)
    g.add_argument("--public-out", type=Path, required=True)
    p = sub.add_parser("public", help="public key of a private key file")
    p.add_argument("--private-in", type=Path, required=True)
    sub.add_parser("status", help="key ids held and sealed secrets per key id (worker settings)")
    args = parser.parse_args(list(argv))
    return {"generate": _generate, "public": _public, "status": _status}[args.cmd](args)
