"""Host-key pinning and what the ADR-0006 bootstrap-key step needs (security-model 6.2).

Policies (``profile.guest_access.host_key_policy``): ``pinned`` is what every normal run uses: strict checking
against keys OVLM already holds (the rotated key of B5, or blue's recorded key). ``tofu`` is the audited
per-profile opt-in: first connect trusts what it sees, into a per-run known_hosts that is returned to the caller
for recording; it needs an explicit acknowledgement string. Disabling checking does not exist.

For B3-B5 (bootstrap key injected through user-data, rotated before ``configure``) this module gives the step
what it needs without owning the flow: parse and fingerprint keys, render a pinned known_hosts, and build the
argv of a strictly-checking ``ssh`` call (:func:`ssh_argv`) to run the host-key regeneration over the session
authenticated against the bootstrap key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ovlm.automation.types import AutomationError

ALLOWED_KEY_TYPES = frozenset(
    {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"}
)
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass(frozen=True)
class PublicKey:
    type: str
    blob_b64: str

    @property
    def line(self) -> str:
        return f"{self.type} {self.blob_b64}"

    @property
    def fingerprint(self) -> str:
        return fingerprint_sha256(self)


def parse_public_key(text: str) -> PublicKey:
    """Parse ``"<type> <base64> [comment]"``. The comment is dropped; the blob's inner type must match."""
    parts = text.strip().split()
    if len(parts) < 2 or parts[0] not in ALLOWED_KEY_TYPES:
        raise AutomationError("unsupported or malformed host key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise AutomationError("host key is not valid base64") from None
    if len(blob) < 8 or len(blob) > 8192:
        raise AutomationError("host key has an implausible size")
    (n,) = struct.unpack(">I", blob[:4])
    if n > len(blob) - 4 or blob[4 : 4 + n].decode("ascii", "replace") != parts[0]:
        raise AutomationError("host key type does not match its blob")
    return PublicKey(parts[0], parts[1])


def fingerprint_sha256(key: PublicKey) -> str:
    """OpenSSH style ``SHA256:<base64 without padding>``."""
    digest = hashlib.sha256(base64.b64decode(key.blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def validate_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise AutomationError("invalid guest host")
    return host


def validate_user(user: str) -> str:
    if not _USER_RE.match(user):
        raise AutomationError("invalid guest user name")
    return user


def validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise AutomationError("invalid guest port")
    return port


@dataclass(frozen=True)
class HostKeyPolicy:
    """``pinned`` needs ``keys``; ``tofu`` needs ``tofu_acknowledged_by`` (the audited opt-in) and has no keys."""

    mode: str  # "pinned" | "tofu"
    keys: tuple[PublicKey, ...] = ()
    tofu_acknowledged_by: str | None = None

    @classmethod
    def pinned(cls, keys: Iterable[str | PublicKey]) -> HostKeyPolicy:
        parsed = tuple(k if isinstance(k, PublicKey) else parse_public_key(k) for k in keys)
        if not parsed:
            raise AutomationError("pinned host-key policy needs at least one key")
        return cls("pinned", parsed)

    @classmethod
    def tofu(cls, acknowledged_by: str) -> HostKeyPolicy:
        if not acknowledged_by.strip():
            raise AutomationError("TOFU host-key policy needs an audited acknowledgement")
        return cls("tofu", (), acknowledged_by.strip())

    @property
    def strict_option(self) -> str:
        return "yes" if self.mode == "pinned" else "accept-new"


def known_hosts_pattern(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def render_known_hosts(host: str, port: int, keys: Sequence[PublicKey]) -> str:
    pattern = known_hosts_pattern(validate_host(host), validate_port(port))
    return "".join(f"{pattern} {k.line}\n" for k in keys)


def parse_known_hosts(text: str) -> list[PublicKey]:
    """Keys of a known_hosts file written by ssh (hashed or not): used to read back the TOFU result."""
    keys: list[PublicKey] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            try:
                keys.append(parse_public_key(f"{parts[-2]} {parts[-1]}"))
            except AutomationError:
                continue
    return keys


def ssh_common_options(
    known_hosts: Path, policy: HostKeyPolicy, control_path: str | None
) -> list[str]:
    opts = [
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"StrictHostKeyChecking={policy.strict_option}",
        "-o", "IdentitiesOnly=yes",
        "-o", "ForwardAgent=no",
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "UpdateHostKeys=no",
    ]  # fmt: skip
    if control_path:
        opts += [
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={control_path}",
            "-o",
            "ControlPersist=60",
        ]
    else:
        opts += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
    return opts


def ssh_argv(
    *,
    host: str,
    port: int,
    user: str,
    key_path: Path,
    known_hosts: Path,
    policy: HostKeyPolicy,
    command: Sequence[str] = (),
    connect_timeout: int = 10,
) -> list[str]:
    """argv for a strictly host-key-checked ``ssh`` (no shell, key by file, never an agent). For the B5 step."""
    return [
        "ssh",
        "-p", str(validate_port(port)),
        "-i", str(key_path),
        "-o", f"ConnectTimeout={connect_timeout}",
        *ssh_common_options(known_hosts, policy, None),
        f"{validate_user(user)}@{validate_host(host)}",
        *command,
    ]  # fmt: skip
