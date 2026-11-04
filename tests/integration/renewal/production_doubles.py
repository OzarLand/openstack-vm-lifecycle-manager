"""Doubles **under** the production guest adapter (:class:`ovlm.renewal.production.RunnerGuestPort`): the automation
runner, OpenSSH and HTTP. The adapter itself is the real one, so the worker-loop test exercises its request building,
host-key pinning (blue by registered fingerprint, green by the injected bootstrap key then rotation), the fixed probe
command list and the external identity check. The guest model is :class:`FakeGuest` (state follows the fake cloud).

The fake cloud here advances its clock a little on every call ("time passes while OVLM looks"), so asynchronous
transitions progress with no ticker thread: one renewal runs one step at a time, so the fake is never used from two
threads at once.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ovlm.automation.classify import Decision
from ovlm.automation.hostkeys import PublicKey, parse_public_key
from ovlm.automation.lint import LintResult
from ovlm.automation.model import (
    AutomationSpec,
    PhaseOutcome,
    PhaseRequest,
    PreparedAutomation,
    RunRecord,
)
from ovlm.automation.result import ValidatedResult
from ovlm.automation.types import Classification, Phase, SecretBytes
from ovlm.openstack.sdk_write import WriteCredential
from ovlm.openstack.types import CreateServerSpec, ServerInfo
from ovlm.renewal.ports import FenceLike, GuestRef
from ovlm.renewal.production import ROTATE_HOST_KEYS, HttpAnswer, ProjectCredentials, SshResult
from tests.integration.renewal.doubles import FakeGuest, RenewalFake


def new_key() -> tuple[bytes, PublicKey]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    return private, parse_public_key(public.decode())


class TickingFake(RenewalFake):
    """Every call advances the clock by ``step`` seconds first; creates record their user-data; the volume is
    checked after every call (never attached to two servers)."""

    step = 4.0

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.user_data: dict[str, str] = {}
        self.violations: list[str] = []
        self.on_create: Callable[[str, str], None] | None = None

    @contextmanager
    def _call(self, op: str) -> Iterator[None]:
        self.tick(self.step)
        with super()._call(op):
            yield
        for v in self._volumes.values():
            if len(v.attachments) > 1:
                self.violations.append(f"{op}: volume {v.id} attached to {sorted(v.attachments)}")

    def create_server(self, spec: CreateServerSpec) -> ServerInfo:
        info = super().create_server(spec)
        self.user_data[info.openstack_id] = spec.user_data or ""
        if self.on_create is not None:
            self.on_create(info.openstack_id, spec.user_data or "")
        return info


@dataclass
class GuestKeys:
    """The guest-side SSH world: each server's current host key and the ``ovlm`` user's authorized key."""

    cloud: TickingFake
    guest: FakeGuest
    authorized: PublicKey
    host_keys: dict[str, PublicKey] = field(default_factory=dict)
    calls: list[tuple[str, tuple[str, ...], str]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def learn_bootstrap(self, server_id: str, user_data: str) -> None:
        """What cloud-init does with OVLM's user-data: install the bootstrap host key and the ``ovlm`` user."""
        doc = yaml.safe_load(user_data.split("\n", 1)[1])
        user = next(u for u in doc["users"] if isinstance(u, dict))
        assert user["ssh_authorized_keys"] == [self.authorized.line]
        self.host_keys[server_id] = parse_public_key(doc["ssh_keys"]["ed25519_public"])

    def server_at(self, address: str) -> str | None:
        for p in self.cloud.list_ports():
            if any(ip == address for ip, _ in p.fixed_ips):
                return p.device_id
        return None


class SshDouble:
    def __init__(self, keys: GuestKeys) -> None:
        self.k = keys

    def keyscan(self, host: str, port: int) -> list[PublicKey]:
        sid = self.k.server_at(host)
        if sid is None or not self.k.guest._active(sid):  # noqa: SLF001
            return []
        return [self.k.host_keys[sid]]

    def run(
        self, *, host: str, port: int, user: str, keys: Sequence[PublicKey], private_key: SecretBytes,
        command: Sequence[str], timeout: float,
    ) -> SshResult:  # fmt: skip
        sid = self.k.server_at(host)
        self.k.calls.append((sid or "?", tuple(command), user))
        if sid is None or not self.k.guest._active(sid):  # noqa: SLF001
            return SshResult(255, "", "ssh: connect to host: Connection timed out")
        if self.k.host_keys.get(sid) not in keys:
            return SshResult(255, "", "Host key verification failed.")
        if user != "ovlm" or b"OPENSSH PRIVATE KEY" not in private_key.value:
            return SshResult(255, "", "Permission denied (publickey).")
        self.k.guest.sync()
        st = self.k.guest.g(sid)
        cmd = tuple(command)
        if cmd == ("true",):
            return SshResult(0, "")
        if cmd == ROTATE_HOST_KEYS:
            _private, pub = new_key()
            self.k.host_keys[sid] = pub
            return SshResult(0, pub.line + "\n")
        if cmd == ("systemctl", "is-system-running"):
            return SshResult(0, "running\n")
        if cmd[:3] == ("findmnt", "-n", "--"):
            return SshResult(0 if st.mounted else 1, "")
        if cmd[:3] == ("systemctl", "is-active", "--"):
            return SshResult(0 if st.units else 3, "")
        if cmd == ("cloud-init", "status"):
            return SshResult(0, "status: done\n")
        return SshResult(127, "", f"not in the fixed command list: {cmd}")


class HttpDouble:
    """Answers from whichever server holds the FIP's port, like the reference workload (``hostname`` in JSON)."""

    def __init__(self, cloud: TickingFake, guest: FakeGuest, fip_address: str) -> None:
        self.cloud, self.guest, self.fip_address = cloud, guest, fip_address
        self.urls: list[str] = []

    def get(self, url: str, timeout: float) -> HttpAnswer:
        self.urls.append(url)
        if urlparse(url).hostname != self.fip_address:
            return HttpAnswer(None, {}, b"", "URLError")
        r = self.guest.external_probe(self.fip_address, {}, {})
        if not r.ok or r.identity is None:
            return HttpAnswer(None, {}, b"", "ConnectionRefusedError")
        name = self.cloud.get_server(r.identity).name
        return HttpAnswer(200, {"Content-Type": "application/json"},
                          json.dumps({"hostname": name, "counter": 1}).encode())  # fmt: skip


class RunnerDouble:
    """Stands in for ``AutomationRunner``: a "verified checkout" with the phase playbooks, and phases answered by the
    :class:`FakeGuest` model of the guest the request targets."""

    def __init__(self, guest: FakeGuest, keys: GuestKeys, root: Path) -> None:
        self.guest, self.keys, self.root = guest, keys, root
        self.prepared: list[str] = []
        self.adopted: list[str] = []
        self.requests: list[PhaseRequest] = []

    def prepare_automation(self, spec: AutomationSpec, workflow_id: str) -> PreparedAutomation:
        self.prepared.append(workflow_id)
        checkout = self.root / workflow_id / "_checkout"
        (checkout / spec.playbook_dir).mkdir(parents=True, exist_ok=True)
        optional = {Phase.PREFLIGHT, Phase.ROLLBACK_HOOKS}
        for phase in Phase:
            if phase not in optional or phase.value in self.guest.phases:
                (checkout / spec.playbook_dir / f"{phase.value}.yml").write_text("- hosts: all\n")
        return PreparedAutomation(
            spec, workflow_id, checkout, spec.ref, "none", "2.19.4", LintResult()
        )

    def adopt_checkout(self, spec: AutomationSpec, workflow_id: str) -> PreparedAutomation | None:
        checkout = self.root / workflow_id / "_checkout"
        if not checkout.is_dir():
            return None
        self.adopted.append(workflow_id)
        return PreparedAutomation(
            spec, workflow_id, checkout, spec.ref, "none", "2.19.4", LintResult()
        )

    def run_phase(
        self, prepared: PreparedAutomation, req: PhaseRequest, *, fence: FenceLike | None = None
    ) -> PhaseOutcome:
        assert fence is not None
        self.requests.append(req)
        sid = self.keys.server_at(req.target.host)
        assert sid is not None, req.target.host
        # the adapter pinned exactly the guest's current host key, never accepted anything else
        assert req.target.host_keys.mode == "pinned"
        assert list(req.target.host_keys.keys) == [self.keys.host_keys[sid]], (sid, req.phase)
        assert req.target.user == "ovlm" and b"OPENSSH PRIVATE KEY" in req.ssh_key.value
        dv = req.data_volume
        res = self.guest.run_phase(
            run_id=req.workflow_id, step_id=req.step_id, attempt=req.attempt, phase=req.phase.value,
            target=GuestRef(sid, req.target.host, req.target.role), timeout=60, fence=fence,
            data_volume=None if dv is None else {"id": dv.id, "mount_point": dv.mount_point,
                                                 "fs_type": dv.fs_type, "first_use": dv.first_use},
            expected_marker=req.expected_marker_checksum, expected_fs_uuid=req.expected_fs_uuid,
        )  # fmt: skip
        cls = Classification(res.classification)
        result = ValidatedResult(req.phase, res.ok, False, cls, dict(res.facts), (), res.reason)
        record = RunRecord(
            workflow_id=req.workflow_id, step_id=req.step_id, attempt=req.attempt, phase=req.phase.value,
            target_role=req.target.role, project_scope=req.project_scope, repo=prepared.spec.repo,
            sha=prepared.sha, requirements_hash="none", ansible_core_version="2.19.4", extravars_sha256="0" * 64,
            extravars_keys=["ovlm"], first_use=False if dv else None, exit_code=0 if res.ok else 2,
            classification=cls.value, reported_classification=cls.value, reason=res.reason,
            result={"ok": res.ok}, result_error=None, task_summary=[], log="", events=[], diff=None,
            duration_seconds=0.1, host_key_mode="pinned", lint_digest="0" * 64,
        )  # fmt: skip
        return PhaseOutcome(Decision(cls, res.reason), result, record)


@dataclass
class StaticCredentials:
    """One project's credentials, in memory (what the encrypted store will hand the worker)."""

    creds: ProjectCredentials
    asked: list[str] = field(default_factory=list)

    def for_project(self, project_connection_id: str) -> ProjectCredentials | None:
        self.asked.append(project_connection_id)
        return self.creds


def credentials(user_id: str, private: bytes, public: PublicKey) -> StaticCredentials:
    return StaticCredentials(
        ProjectCredentials(
            write=WriteCredential("https://keystone.invalid/v3", "app-cred-id", "app-cred-secret", "R1"),
            guest_key=SecretBytes(private), guest_public_key=public.line,
            expires_at=datetime.now(UTC) + timedelta(days=30), write_user_id=user_id,
        )
    )  # fmt: skip


__all__ = [
    "GuestKeys", "HttpDouble", "RunnerDouble", "SshDouble", "StaticCredentials", "TickingFake", "credentials",
    "new_key",
]  # fmt: skip
