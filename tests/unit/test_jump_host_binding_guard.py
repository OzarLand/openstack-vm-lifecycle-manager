"""Guard for roadmap SF-2 (review N-1): the connection's jump host must not reach the guest SSH path unless the
``ssh_key`` binding covers it.

``project_connection.guest_access`` (``direct`` or ``jump_host`` with host, port and pinned host key) is stored and
protected by an API step-up, but the ``ovlm_api`` role can rewrite the column directly and it is **not** part of the
AAD binding of the guest SSH key (:class:`ovlm.secrets.store.Destination`). Today that is harmless because nothing
outside the connections CRUD reads it: every guest SSH call (``ssh_argv``, the Ansible inventory's
``ansible_ssh_common_args``, ``ssh-keyscan``) goes straight to the VM's address. SF-2 is therefore moot until the jump
host is wired in, and this test fails the day it is wired without the binding: it then needs a digest of
``guest_access`` in ``Destination.binding()`` for ``ssh_key`` (or the jump host's key pinned outside what ``ovlm_api``
can write), see security-model.md 6.3.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

from ovlm.automation.hostkeys import HostKeyPolicy, ssh_argv, ssh_common_options
from ovlm.connections.credentials import ConnectionInfo

SRC = Path(__file__).resolve().parents[2] / "src" / "ovlm"

#: The connections CRUD: where ``guest_access`` is validated, stored, audited and changed (with a step-up).
CRUD = {
    SRC / "connections" / "service.py",
    SRC / "connections" / "api.py",
    SRC / "connections" / "events.py",
}
#: What wiring a jump host into the guest SSH path would look like.
JUMP = re.compile(r"jump_host|ProxyJump|ProxyCommand|['\"]-J['\"]|\bguest_access\b[^\n]*\bproject_connection\b"
                  r"|\bproject_connection\b[^\n]*\bguest_access\b|\bp\.guest_access\b")  # fmt: skip
ROUTING_OPTIONS = ("proxyjump", "proxycommand", "-j")


def _source_hits() -> list[str]:
    hits = []
    for path in sorted(SRC.rglob("*.py")):
        if path in CRUD:
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if JUMP.search(line):
                hits.append(f"{path.relative_to(SRC)}:{n}: {line.strip()}")
    return hits


def _routed_options() -> list[str]:
    """Options of every guest SSH command OVLM builds that would send the connection through another host."""
    policy = HostKeyPolicy("pinned", ())
    argv = [
        *ssh_common_options(Path("/run/kh"), policy, None),
        *ssh_common_options(Path("/run/kh"), policy, "/run/cp/%C"),
        *ssh_argv(
            host="192.0.2.10",
            port=22,
            user="ovlm",
            key_path=Path("/run/key"),
            known_hosts=Path("/run/kh"),
            policy=policy,
        ),  # fmt: skip
    ]
    return [
        a
        for a in argv
        if any(a.lower().startswith(o) or f"{o}=" in a.lower() for o in ROUTING_OPTIONS)
    ]


def _info() -> ConnectionInfo:
    return ConnectionInfo("pc-1", "conn", True, "https://keystone.example.test/v3", "RegionOne", "public",
                          "p-1", None, None, "cloud-1")  # fmt: skip


def test_sf2_the_jump_host_is_not_wired_without_the_ssh_key_binding() -> None:
    bound = any(
        "guest_access" in part or "jump" in part
        for part in _info().destination("ssh_key").binding()
    )
    snapshot_fields = [
        f.name for f in dataclasses.fields(ConnectionInfo) if "guest" in f.name or "jump" in f.name
    ]
    wired = _source_hits() + _routed_options() + snapshot_fields
    assert bound or not wired, (
        "the connection's jump host (guest_access) reaches the guest SSH path, but the ssh_key binding does not "
        "cover it (review N-1, roadmap SF-2): add a digest of guest_access to Destination.binding() for ssh_key "
        f"before wiring it. Found: {wired}"
    )


def test_sf2_guard_sees_a_wired_jump_host() -> None:
    """The guard's detectors work: a ProxyJump option and a read of the connection's column are both caught."""
    assert JUMP.search('opts += ["-o", f"ProxyJump={jump}"]')
    assert JUMP.search("SELECT p.guest_access FROM project_connection p")
    assert JUMP.search("SELECT name, guest_access FROM project_connection WHERE id = :p")
    assert not JUMP.search(
        'user = resolved["guest_access"]["ssh_user"]'
    )  # the profile's guest_access, not it
