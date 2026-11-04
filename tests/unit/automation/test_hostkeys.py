from __future__ import annotations

import base64
import struct
from pathlib import Path

import pytest

from ovlm.automation.hostkeys import (
    HostKeyPolicy,
    fingerprint_sha256,
    known_hosts_pattern,
    parse_known_hosts,
    parse_public_key,
    render_known_hosts,
    ssh_argv,
    validate_host,
)
from ovlm.automation.types import AutomationError

# Generated with ssh-keygen; the fingerprint is `ssh-keygen -lf` output.
PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwLM199YxaNqwwlrFbz6zrsuROa7AzsYbaXTnF5qNWB root@vm"
FP = "SHA256:0hpD4131G25lrFZzMUbOAa7dgcCd/9iw2kMK3PsmoPI"


def test_fingerprint_matches_openssh_format() -> None:
    key = parse_public_key(PUB)
    assert fingerprint_sha256(key) == FP == key.fingerprint
    assert key.line == PUB.rsplit(" ", 1)[0]


def _blob(name: bytes, body: bytes = b"x" * 32) -> str:
    return base64.b64encode(
        struct.pack(">I", len(name)) + name + struct.pack(">I", len(body)) + body
    ).decode()


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "ssh-ed25519",
        "ssh-dss AAAA",
        f"ssh-ed25519 {_blob(b'ssh-rsa')}",  # declared type differs from the blob
        "ssh-ed25519 !!!notbase64",
        "ssh-ed25519 AAAA",
        f"-oProxyCommand=x {_blob(b'ssh-ed25519')}",
    ],
)
def test_malformed_keys_are_refused(bad: str) -> None:
    with pytest.raises(AutomationError):
        parse_public_key(bad)


def test_known_hosts_line_format() -> None:
    key = parse_public_key(f"ssh-ed25519 {_blob(b'ssh-ed25519')}")
    assert render_known_hosts("10.0.0.5", 22, [key]) == f"10.0.0.5 {key.line}\n"
    assert render_known_hosts("10.0.0.5", 2222, [key]) == f"[10.0.0.5]:2222 {key.line}\n"
    assert known_hosts_pattern("host.example", 22) == "host.example"


@pytest.mark.parametrize(
    "host", ["", "a b", "a\nb", "-oProxyCommand=x", "a;b", "x" * 300, "bad_host!"]
)
def test_host_validation(host: str) -> None:
    with pytest.raises(AutomationError):
        validate_host(host)
    assert (
        validate_host("10.1.2.3") and validate_host("fe80::1") and validate_host("vm-1.example.org")
    )


def test_policy_rules() -> None:
    key = f"ssh-ed25519 {_blob(b'ssh-ed25519')}"
    assert HostKeyPolicy.pinned([key]).strict_option == "yes"
    with pytest.raises(AutomationError):
        HostKeyPolicy.pinned([])  # checking cannot be disabled: no empty pin
    with pytest.raises(AutomationError):
        HostKeyPolicy.tofu("  ")  # TOFU needs an audited acknowledgement
    assert HostKeyPolicy.tofu("ack-1").strict_option == "accept-new"


def test_parse_known_hosts_reads_ssh_written_files() -> None:
    key = f"ssh-ed25519 {_blob(b'ssh-ed25519')}"
    text = f"# comment\n|1|abc|def {key}\n[h]:22 {key}\nbroken line\n"
    assert [k.line for k in parse_known_hosts(text)] == [key, key]


def test_ssh_argv_is_strict_and_agentless(tmp_path: Path) -> None:
    policy = HostKeyPolicy.pinned([f"ssh-ed25519 {_blob(b'ssh-ed25519')}"])
    argv = ssh_argv(
        host="10.0.0.5", port=22, user="ovlm", key_path=tmp_path / "k", known_hosts=tmp_path / "kh",
        policy=policy, command=["sudo", "true"],
    )  # fmt: skip
    joined = " ".join(argv)
    for needle in ("StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "ForwardAgent=no", "BatchMode=yes",
                   "GlobalKnownHostsFile=/dev/null", "PasswordAuthentication=no"):  # fmt: skip
        assert needle in joined
    assert (
        argv[-3:] == ["ovlm@10.0.0.5", "sudo", "true"] and "StrictHostKeyChecking=no" not in joined
    )
    with pytest.raises(AutomationError):
        ssh_argv(
            host="h",
            port=22,
            user="Bad User",
            key_path=tmp_path,
            known_hosts=tmp_path,
            policy=policy,
        )
