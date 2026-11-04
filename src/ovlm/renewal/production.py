"""Production adapters of the renewal ports (worker only): OpenStack through the guarded SDK write client, the guest
through the automation runner, OpenSSH and an HTTP probe. :func:`production_deps` wires them from ``Settings``.

Safety argument (for the SRE and security reviews)
---------------------------------------------------

* **Credentials stay in memory.** The write application credential and the guest SSH key come from a
  :class:`CredentialSource` per project connection. They are handed to ``connect_write`` (in-memory
  ``WriteCredential``, never a ``clouds.yaml``) and to the runner as :class:`SecretBytes`; the only files are the
  runner's own 0600 run-dir files and this module's short-lived 0600 SSH key file in a 0700 directory under
  ``automation.run_root`` (tmpfs in the worker container), removed in ``finally``.
* **No credential store yet.** security-model.md 5.1 (sealed secrets in the database, unsealed by the worker's KEK) is
  not implemented in this release. :class:`NoCredentialStore` (the default) makes admission **reject** every renewal
  with that reason, so no run takes a lock it cannot use. :class:`FileCredentialSource` is an explicit, opt-in
  interim (``renewal.credentials_dir``) for the lab: worker-only secret files, refused unless owned by the worker
  user and not group/world readable. It is a reported deviation, not the design.
* **Every OpenStack write** goes through ``GuardedWriteClient`` (ownership guard) over a session carrying the write
  allowlist and the step attempt's fence gate (``sdk_write.connect_write``). The token pre-warm of the W1 claim
  uses a session carrying the read-only guard: it can send only the token request.
* **Guest commands are a fixed list** (SEC-R-36): probe = ``findmnt``, ``systemctl is-active``, ``cloud-init
  status``, ``systemctl is-system-running``; host-key rotation = one fixed command. Arguments are validated
  (mount point, unit names) and shell-quoted. SSH always runs with ``StrictHostKeyChecking=yes`` against keys
  pinned for this connection (``hostkeys.ssh_argv``); blue's keys are accepted only when their SHA-256 fingerprint
  equals the fingerprint confirmed at registration (ADR-0006).
* **A fence check precedes every guest mutation** (the host-key rotation, every Ansible spawn inside the runner).

Not covered by CI: there is no real cloud or guest in CI. The OpenSSH, HTTP and Keystone paths are unit tested with
doubles; the first run against real systems is the lab run (E5-6). Status: "unit tested", never "lab validated".
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, cast

import yaml
from sqlalchemy import Engine, text

from ovlm.automation.hostkeys import (
    HostKeyPolicy,
    PublicKey,
    parse_public_key,
    render_known_hosts,
    ssh_argv,
    validate_host,
    validate_port,
)
from ovlm.automation.model import (
    AutomationSpec,
    DataVolume,
    GuestTarget,
    PhaseOutcome,
    PhaseRequest,
    PreparedAutomation,
)
from ovlm.automation.types import AutomationError, Classification, Phase, SecretBytes
from ovlm.openstack.ownership import OwnershipRegistry
from ovlm.openstack.sdk_write import WriteCredential
from ovlm.openstack.write import GuardedWriteClient
from ovlm.renewal.ledger import plan_resolved
from ovlm.renewal.ports import (
    Bootstrap,
    ExternalResult,
    FenceLike,
    Gate,
    GuestProbe,
    GuestRef,
    HostKeyResult,
    PhaseResult,
)

log = logging.getLogger("ovlm.renewal.production")

# --- credentials --------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectCredentials:
    """What a renewal of one project needs, in memory. ``guest_key`` is the private key of the ``ovlm`` user on the
    guests (security-model.md 6.1); ``guest_public_key`` goes into green's user-data."""

    write: WriteCredential
    guest_key: SecretBytes = field(repr=False)
    guest_public_key: str
    expires_at: datetime | None = None
    write_user_id: str | None = None


class CredentialSource(Protocol):
    def for_project(self, project_connection_id: str) -> ProjectCredentials | None:
        """The project's credentials, read now (no cache: a rotation takes effect at the next call)."""
        ...


NO_STORE_REASON = (
    "no write credential and guest SSH key are available for this project: the encrypted credential store "
    "(security-model.md 5.1) is not implemented in this release"
)


class NoCredentialStore:
    """The default: nothing is available, so admission rejects every renewal with :data:`NO_STORE_REASON`."""

    def for_project(self, project_connection_id: str) -> ProjectCredentials | None:
        return None


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class FileCredentialSource:
    """**Interim, opt-in** (``renewal.credentials_dir``): ``<dir>/<project_connection_id>.json`` (write application
    credential: ``auth_url``, ``application_credential_id``, ``application_credential_secret``, ``region_name``,
    optional ``interface``, ``cacert``, ``expires_at``, ``user_id``) and ``<dir>/<id>.guest_key`` (OpenSSH ed25519
    private key). The directory and files must belong to the worker user and grant nothing to group or others."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _check(self, path: Path) -> None:
        st = path.stat()
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise PermissionError(
                f"{path.name}: must be owned by the worker user and not readable by group or others"
            )

    def for_project(self, project_connection_id: str) -> ProjectCredentials | None:
        if not _UUID.match(project_connection_id):
            return None
        cred_path = self.directory / f"{project_connection_id}.json"
        key_path = self.directory / f"{project_connection_id}.guest_key"
        if not (cred_path.is_file() and key_path.is_file()):
            return None
        for p in (self.directory, cred_path, key_path):
            self._check(p)
        raw = json.loads(cred_path.read_text())
        key = key_path.read_bytes()
        expires = raw.get("expires_at")
        return ProjectCredentials(
            write=WriteCredential(
                auth_url=raw["auth_url"], application_credential_id=raw["application_credential_id"],
                application_credential_secret=raw["application_credential_secret"],
                region_name=raw["region_name"], interface=raw.get("interface", "public"),
                cacert=Path(raw["cacert"]) if raw.get("cacert") else None,
            ),
            guest_key=SecretBytes(key),
            guest_public_key=public_key_of(key),
            expires_at=datetime.fromisoformat(expires) if expires else None,
            write_user_id=raw.get("user_id"),
        )  # fmt: skip


def public_key_of(private_openssh: bytes) -> str:
    """The OpenSSH public line of an OpenSSH private key (no passphrase)."""
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_ssh_private_key(private_openssh, password=None)
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )


# --- cloud --------------------------------------------------------------------------------------------------------


class SdkCloudPort:
    """:class:`~ovlm.renewal.ports.CloudPort` over ``sdk_write.connect_write`` (one guarded client per attempt)."""

    def __init__(self, credentials: CredentialSource, *, process_role: str = "worker") -> None:
        self.credentials = credentials
        self.process_role = process_role

    def _creds(self, project: str) -> ProjectCredentials:
        creds = self.credentials.for_project(project)
        if creds is None:
            raise AutomationError(NO_STORE_REASON, Classification.NEEDS_HUMAN)
        return creds

    def unavailable_reason(self, project: str) -> str | None:
        try:
            return None if self.credentials.for_project(project) is not None else NO_STORE_REASON
        except (OSError, ValueError, KeyError) as exc:
            return f"the credentials of this project are unreadable: {type(exc).__name__}: {exc}"[
                :300
            ]

    def write_client(
        self, registry: OwnershipRegistry, gate: Gate, *, project: str
    ) -> GuardedWriteClient:
        from ovlm.openstack.sdk_write import connect_write

        return connect_write(
            self._creds(project).write, registry=registry, gate=gate, process_role=self.process_role
        )

    def write_credential_expires_at(self, project: str) -> datetime | None:
        return self._creds(project).expires_at

    def write_user_id(self, project: str) -> str | None:
        return self._creds(project).write_user_id

    def token_expires_at(self, project: str) -> datetime | None:
        """A fresh Keystone token's expiry, from a session that can send only the token request. Raises when
        Keystone cannot be reached: W1 is then not claimed (a step failure before any outage)."""
        from keystoneauth1 import session as ks_session
        from keystoneauth1.identity import v3

        from ovlm.openstack.guard import install_read_only_guard
        from ovlm.openstack.sdk_read import translated

        cred = self._creds(project).write
        auth = v3.ApplicationCredential(
            auth_url=cred.auth_url,
            application_credential_id=cred.application_credential_id,
            application_credential_secret=cred.application_credential_secret,
        )
        sess = self._token_session(ks_session, auth, str(cred.cacert) if cred.cacert else True)
        install_read_only_guard(sess)
        with translated():
            expires: datetime | None = auth.get_access(sess).expires
        return expires

    def _token_session(self, ks_session: Any, auth: Any, verify: bool | str) -> Any:
        return ks_session.Session(auth=auth, verify=verify)


# --- SSH ----------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SshResult:
    exit_code: int
    stdout: str
    stderr: str = ""

    @property
    def connected(self) -> bool:
        return self.exit_code != 255  # ssh's own failure (connect, auth, host key) is 255


class SshTransport(Protocol):
    def keyscan(self, host: str, port: int) -> list[PublicKey]: ...

    def run(
        self,
        *,
        host: str,
        port: int,
        user: str,
        keys: Sequence[PublicKey],
        private_key: SecretBytes,
        command: Sequence[str],
        timeout: float,
    ) -> SshResult: ...


class OpenSshTransport:
    """``ssh``/``ssh-keyscan`` subprocesses. The key file lives in a 0700 directory for one call and is removed."""

    def __init__(self, work_root: Path, *, connect_timeout: int = 10) -> None:
        self.work_root = work_root
        self.connect_timeout = connect_timeout

    @contextlib.contextmanager
    def _dir(self) -> Iterator[Path]:
        self.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        d = Path(tempfile.mkdtemp(prefix="ssh-", dir=self.work_root))
        try:
            yield d
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def keyscan(self, host: str, port: int) -> list[PublicKey]:
        try:
            argv = ["ssh-keyscan", "-T", str(self.connect_timeout), "-p", str(validate_port(port)), "--",
                    validate_host(host)]  # fmt: skip
            out = subprocess.run(  # noqa: S603 - fixed argv (PATH lookup, like ssh_argv), validated host
                argv,
                capture_output=True, text=True, timeout=self.connect_timeout + 15, check=False,
            ).stdout  # fmt: skip
        except (OSError, subprocess.SubprocessError):
            return []
        keys = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and not line.startswith("#"):
                with contextlib.suppress(ValueError):
                    keys.append(parse_public_key(" ".join(parts[1:3])))
        return keys

    def run(
        self,
        *,
        host: str,
        port: int,
        user: str,
        keys: Sequence[PublicKey],
        private_key: SecretBytes,
        command: Sequence[str],
        timeout: float,
    ) -> SshResult:
        if not keys:
            return SshResult(255, "", "no pinned host key")
        with self._dir() as d:
            key_path = d / "key"
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                data = private_key.value
                fh.write(data if data.endswith(b"\n") else data + b"\n")
            known = d / "known_hosts"
            known.write_text(render_known_hosts(host, port, list(keys)))
            argv = ssh_argv(
                host=host, port=port, user=user, key_path=key_path, known_hosts=known,
                policy=HostKeyPolicy.pinned(keys), command=[" ".join(shlex.quote(c) for c in command)],
                connect_timeout=self.connect_timeout,
            )  # fmt: skip
            try:
                p = subprocess.run(  # noqa: S603 - argv built by hostkeys.ssh_argv
                    argv, capture_output=True, text=True, timeout=timeout, check=False,
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(d)},
                )  # fmt: skip
            except subprocess.TimeoutExpired:
                return SshResult(255, "", "timeout")
            except OSError as exc:
                return SshResult(255, "", type(exc).__name__)
            return SshResult(p.returncode, p.stdout[:65536], p.stderr[:4096])


# --- HTTP -------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpAnswer:
    status: int | None
    headers: Mapping[str, str]
    body: bytes
    error: str = ""


class HttpGetter(Protocol):
    def get(self, url: str, timeout: float) -> HttpAnswer: ...


class UrllibGetter:
    """GET without redirects or proxies; the body is capped. ``https``: certificate checks stay on."""

    def get(self, url: str, timeout: float) -> HttpAnswer:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                return None

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )  # fmt: skip
        try:
            with opener.open(url, timeout=timeout) as resp:  # noqa: S310 - http/https built from the profile
                return HttpAnswer(resp.status, dict(resp.headers.items()), resp.read(65536))
        except urllib.error.HTTPError as exc:
            return HttpAnswer(exc.code, dict(exc.headers.items()), exc.read(65536))
        except (OSError, ValueError) as exc:
            return HttpAnswer(None, {}, b"", type(exc).__name__)


#: Header a workload may set to prove which server answered (preferred over the body). See :func:`identify`.
IDENTITY_HEADER = "X-OVLM-Server-Id"


def _hostname_of(name: str | None) -> str | None:
    """What Nova/cloud-init make of a server name as the guest hostname (lower case, ``[a-z0-9-]``, 63 chars)."""
    if not name:
        return None
    return re.sub(r"[^a-z0-9-]", "-", name.lower())[:63].strip("-") or None


def identify(answer: HttpAnswer, candidates: Mapping[str, str | None]) -> str | None:
    """Which candidate server answered: the ``X-OVLM-Server-Id`` header or a JSON ``server_id`` equal to a
    candidate id, else a JSON ``hostname`` equal to a candidate's hostname (the reference workload reports its
    hostname). Ambiguous or unknown: ``None`` (never success)."""
    sid = answer.headers.get(IDENTITY_HEADER) or next(
        (v for k, v in answer.headers.items() if k.lower() == IDENTITY_HEADER.lower()), None
    )
    body: Any = None
    with contextlib.suppress(ValueError, UnicodeDecodeError):
        body = json.loads(answer.body.decode())
    if not sid and isinstance(body, dict) and isinstance(body.get("server_id"), str):
        sid = body["server_id"]
    if sid:
        return sid if sid in candidates else None
    host = body.get("hostname") if isinstance(body, dict) else None
    if isinstance(host, str):
        short = host.split(".")[0].lower()
        matches = [cid for cid, name in candidates.items() if _hostname_of(name) == short]
        return matches[0] if len(matches) == 1 else None
    return None


# --- the automation runner, as the guest port uses it ---------------------------------------------------------------


class RunnerLike(Protocol):
    def prepare_automation(self, spec: AutomationSpec, workflow_id: str) -> PreparedAutomation: ...

    def run_phase(
        self, prepared: PreparedAutomation, req: PhaseRequest, *, fence: FenceLike | None = None
    ) -> PhaseOutcome: ...


class RecordStore(Protocol):
    def save(self, conn: Any, record: Any, *, store_diffs: bool) -> str: ...


_MOUNT = re.compile(r"^/[A-Za-z0-9._/-]{0,250}$")
_UNIT = re.compile(r"^[A-Za-z0-9:_.@-]{1,200}\.(service|socket|timer|target|mount)$")
#: B5 rotation (ADR-0006 D'): new host keys, printed back over the same authenticated session, sshd reloaded.
ROTATE_HOST_KEYS = (
    "sudo", "-n", "sh", "-c",
    "set -e; rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub; ssh-keygen -A >/dev/null; "
    "cat /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub; "
    "(systemctl reload ssh || systemctl reload sshd) >/dev/null 2>&1",
)  # fmt: skip
_CONSOLE_FP = re.compile(r"^\S*\s*(\d+)\s+(SHA256:[A-Za-z0-9+/=]+)\s.*\((ED25519|ECDSA|RSA)\)\s*$")


class RunnerGuestPort:
    """:class:`~ovlm.renewal.ports.GuestPort` over the automation runner, OpenSSH and an HTTP getter."""

    def __init__(
        self,
        engine: Engine,
        runner: RunnerLike,
        credentials: CredentialSource,
        *,
        ssh: SshTransport,
        http: HttpGetter,
        store: RecordStore | None = None,
        ssh_timeout: float = 60.0,
        http_timeout: float = 10.0,
    ) -> None:
        self.engine = engine
        self.runner = runner
        self.credentials = credentials
        self.ssh = ssh
        self.http = http
        self.store = store
        self.ssh_timeout = ssh_timeout
        self.http_timeout = http_timeout
        self._prepared: dict[str, PreparedAutomation] = {}
        self._lock = threading.Lock()

    # -- run context ------------------------------------------------------------------------------------

    def _resolved(self, run_id: str) -> Mapping[str, Any]:
        with self.engine.connect() as c:
            return plan_resolved(c, run_id)

    def _creds(self, resolved: Mapping[str, Any]) -> ProjectCredentials:
        creds = self.credentials.for_project(str(resolved["service"]["project_connection_id"]))
        if creds is None:
            raise AutomationError(NO_STORE_REASON, Classification.NEEDS_HUMAN)
        return creds

    def _spec(self, run_id: str, resolved: Mapping[str, Any]) -> AutomationSpec:
        """The profile version's automation block (bound by the plan hash through ``spec_hash``)."""
        with self.engine.connect() as c:
            spec = c.execute(
                text("SELECT spec FROM profile_version WHERE id = :i"),
                {"i": resolved["profile_version"]["id"]},
            ).scalar()
        a = dict((spec or {}).get("automation") or {})
        if (
            a.get("sha") != resolved["automation"]["sha"]
            or a.get("repo") != resolved["automation"]["repo"]
        ):
            raise AutomationError(
                "the profile's automation differs from the plan", Classification.NEEDS_HUMAN
            )
        hc = (spec or {}).get("health_check") or {}
        return AutomationSpec(
            repo=a["repo"], ref=a["sha"], playbook_dir=a.get("playbook_dir") or "playbooks",
            requirements=a.get("requirements") or "requirements.yml",
            inventory_vars=dict(a.get("inventory_vars") or {}),
            timeouts={k: int(v) for k, v in (a.get("timeouts") or {}).items()},
            store_diffs=bool(a.get("store_diffs")), accept_degraded=bool(hc.get("accept_degraded")),
        )  # fmt: skip

    def _prepared_for(self, run_id: str) -> PreparedAutomation:
        with self._lock:
            prepared = self._prepared.get(run_id)
        if (
            prepared is None
        ):  # another worker process prepared it (restart): one more verified clone, same SHA
            resolved = self._resolved(run_id)
            prepared = self.runner.prepare_automation(self._spec(run_id, resolved), run_id)
            with self._lock:
                self._prepared[run_id] = prepared
        return prepared

    # -- GuestPort ---------------------------------------------------------------------------------------

    def prepare(
        self, run_id: str, automation: Mapping[str, Any], fence: FenceLike
    ) -> Mapping[str, Any]:
        resolved = self._resolved(run_id)
        fence.check("automation:prepare")
        prepared = self.runner.prepare_automation(self._spec(run_id, resolved), run_id)
        with self._lock:
            self._prepared[run_id] = prepared
        return prepared.evidence()

    def has_phase(self, run_id: str, phase: str) -> bool:
        prepared = self._prepared_for(run_id)
        return (
            prepared.checkout / prepared.spec.playbook_dir.strip("/") / f"{phase}.yml"
        ).is_file()

    def run_phase(
        self, *, run_id: str, step_id: str, attempt: int, phase: str, target: GuestRef, timeout: float,
        fence: FenceLike, data_volume: Mapping[str, Any] | None = None, expected_marker: str | None = None,
        expected_fs_uuid: str | None = None,
    ) -> PhaseResult:  # fmt: skip
        resolved = self._resolved(run_id)
        creds = self._creds(resolved)
        prepared = self._prepared_for(run_id)
        keys = self._target_keys(target, creds)
        if not keys:
            return PhaseResult("needs_human", "host key unverifiable")
        dv = (
            DataVolume(
                id=data_volume["id"], mount_point=data_volume["mount_point"], fs_type=data_volume["fs_type"],
                expected_serial=data_volume.get("expected_serial"), first_use=False,
            )
            if data_volume
            else None
        )  # fmt: skip
        req = PhaseRequest(
            workflow_id=run_id, step_id=step_id, attempt=attempt, phase=Phase(phase),
            target=GuestTarget(host=target.address, host_keys=HostKeyPolicy.pinned(keys), role=target.role,
                               user=resolved["guest_access"]["ssh_user"]),
            ssh_key=creds.guest_key, service_name=resolved["service"]["slug"], project_scope=resolved["scope"],
            data_volume=dv, expected_marker_checksum=expected_marker, expected_fs_uuid=expected_fs_uuid,
        )  # fmt: skip
        outcome = self.runner.run_phase(prepared, req, fence=fence)
        record_id = None
        if self.store is not None:
            try:
                with self.engine.begin() as c:
                    record_id = self.store.save(
                        c, outcome.record, store_diffs=prepared.spec.store_diffs
                    )
            except Exception:  # noqa: BLE001 - losing the artefact row must not change what the phase decided
                log.exception("could not store the automation run record")
        facts = dict(outcome.result.facts) if outcome.result is not None else {}
        return PhaseResult(
            cast(Any, outcome.decision.classification.value),
            outcome.decision.reason,
            facts,
            {
                "automation_run_id": record_id,
                "sha": prepared.sha,
                "exit_code": outcome.record.exit_code,
            },
        )

    def bootstrap(self, run_id: str, policy: str) -> Bootstrap:
        """cloud-init user-data for green: the ``ovlm`` user with the project's guest public key (sudo for Ansible
        ``become``), and under ``injected`` a fresh ed25519 bootstrap host key (ADR-0006 D'), private part only
        here and in Nova's user-data, rotated at B5."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        resolved = self._resolved(run_id)
        creds = self._creds(resolved)
        doc: dict[str, Any] = {
            "users": ["default", {
                "name": resolved["guest_access"]["ssh_user"], "shell": "/bin/bash", "lock_passwd": True,
                "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [creds.guest_public_key],
            }],
        }  # fmt: skip
        public = key_id = None
        if policy == "injected":
            key = Ed25519PrivateKey.generate()
            private = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            ).decode()
            public = (
                key.public_key()
                .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
                .decode()
            )
            key_id = parse_public_key(public).fingerprint
            doc |= {"ssh_deletekeys": True, "ssh_genkeytypes": [],
                    "ssh_keys": {"ed25519_private": private, "ed25519_public": public}}  # fmt: skip
        user_data = "#cloud-config\n" + yaml.safe_dump(doc, sort_keys=False)
        return Bootstrap(user_data, public, key_id)

    def pin_host_key(
        self, *, run_id: str, target: GuestRef, policy: str, bootstrap_public: str | None,
        accept: tuple[str, ...], console: str | None, fence: FenceLike,
    ) -> HostKeyResult:  # fmt: skip
        resolved = self._resolved(run_id)
        creds, user = self._creds(resolved), resolved["guest_access"]["ssh_user"]
        if accept:  # a re-run: only what the evidence already pinned
            keys = [parse_public_key(k) for k in accept]
            res = self._ssh(target, user, keys, creds, ("true",))
            if res.exit_code == 0:
                return HostKeyResult(True, "ok", tuple(k.line for k in keys), "rotated")
            if not res.connected and bootstrap_public is None:
                return HostKeyResult(False, _ssh_reason(res))
        if policy == "injected":
            if not bootstrap_public:
                return HostKeyResult(False, "no bootstrap key")
            boot = [parse_public_key(bootstrap_public)]
            reach = self._ssh(target, user, boot, creds, ("true",))
            if reach.exit_code != 0:
                return HostKeyResult(False, _ssh_reason(reach))
            fence.check("guest:rotate_host_keys")
            rot = self._ssh(target, user, boot, creds, ROTATE_HOST_KEYS)
            new = _parse_keys(rot.stdout) if rot.exit_code == 0 else []
            if not new:
                return HostKeyResult(False, "host key rotation failed")
            mode = "rotated"
        elif policy in ("console", "tofu"):
            scanned = self.ssh.keyscan(target.address, 22)
            if not scanned:
                return HostKeyResult(False, "unreachable")
            if policy == "console":
                fps = _console_fingerprints(console or "")
                new = [k for k in scanned if k.fingerprint in fps]
                if not new:
                    return HostKeyResult(False, "no console fingerprint matches the scanned keys")
            else:
                new = scanned
            mode = policy
        else:
            return HostKeyResult(False, f"unknown host key policy {policy!r}")
        verify = self._ssh(target, user, new, creds, ("true",))
        if verify.exit_code != 0:
            return HostKeyResult(False, _ssh_reason(verify))
        return HostKeyResult(True, "ok", tuple(k.line for k in new), mode)

    def probe(
        self, run_id: str, target: GuestRef, *, mount_point: str | None, units: tuple[str, ...]
    ) -> GuestProbe:
        resolved = self._resolved(run_id)
        creds, user = self._creds(resolved), resolved["guest_access"]["ssh_user"]
        keys = self._target_keys(target, creds)
        if not keys:
            return GuestProbe(False)
        if mount_point is not None and not _MOUNT.match(mount_point):
            raise AutomationError("mount point not allowed in a probe", Classification.FATAL)
        if any(not _UNIT.match(u) for u in units):
            raise AutomationError("unit name not allowed in a probe", Classification.FATAL)
        state = self._ssh(target, user, keys, creds, ("systemctl", "is-system-running"))
        if not state.connected:
            return GuestProbe(False)
        mounted = None
        if mount_point is not None:
            mounted = (
                self._ssh(target, user, keys, creds, ("findmnt", "-n", "--", mount_point)).exit_code
                == 0
            )
        active = None
        if units:
            active = (
                self._ssh(
                    target, user, keys, creds, ("systemctl", "is-active", "--", *units)
                ).exit_code
                == 0
            )
        ci = self._ssh(target, user, keys, creds, ("cloud-init", "status"))
        return GuestProbe(
            True,
            mounted,
            active,
            ci.exit_code == 0 and "status: done" in ci.stdout,
            next(iter(state.stdout.strip().splitlines()), None),
        )

    def external_probe(
        self, address: str, check: Mapping[str, Any], candidates: Mapping[str, str | None]
    ) -> ExternalResult:
        scheme = check.get("scheme")
        if scheme not in ("http", "https"):
            return ExternalResult(
                False, None, f"{scheme} checks cannot prove which server answered"
            )
        host = f"[{address}]" if ":" in address else address
        path = check.get("path") or "/"
        url = (
            f"{scheme}://{host}:{int(check['port'])}{path if path.startswith('/') else '/' + path}"
        )
        answer = self.http.get(url, self.http_timeout)
        expected = check.get("expected_status")
        ok = answer.status is not None and (
            answer.status == expected if expected is not None else 200 <= answer.status < 400
        )
        return ExternalResult(
            ok, identify(answer, candidates), answer.error or f"HTTP {answer.status}"
        )

    # -- helpers -----------------------------------------------------------------------------------------

    def _target_keys(self, target: GuestRef, creds: ProjectCredentials) -> list[PublicKey]:
        if target.host_keys:
            return [parse_public_key(k) for k in target.host_keys]
        if (
            target.fingerprint
        ):  # blue: keys whose fingerprint equals the one confirmed at registration
            return [
                k
                for k in self.ssh.keyscan(target.address, 22)
                if k.fingerprint == target.fingerprint
            ]
        return []

    def _ssh(
        self, target: GuestRef, user: str, keys: Sequence[PublicKey], creds: ProjectCredentials,
        command: Sequence[str],
    ) -> SshResult:  # fmt: skip
        return self.ssh.run(
            host=target.address, port=22, user=user, keys=keys, private_key=creds.guest_key,
            command=command, timeout=self.ssh_timeout,
        )  # fmt: skip


def _ssh_reason(res: SshResult) -> str:
    if res.connected:
        return f"remote command failed ({res.exit_code})"
    if "host key" in res.stderr.lower() or "REMOTE HOST IDENTIFICATION" in res.stderr:
        return "host key mismatch"
    return "unreachable"


def _parse_keys(text_: str) -> list[PublicKey]:
    out = []
    for line in text_.splitlines():
        with contextlib.suppress(ValueError):
            out.append(parse_public_key(" ".join(line.split()[:2])))
    return out


def _console_fingerprints(console: str) -> set[str]:
    """SHA-256 fingerprints from cloud-init's console block (untrusted text: strict pattern, size cap)."""
    out = set()
    inside = False
    for line in console[-65536:].splitlines():
        if "BEGIN SSH HOST KEY FINGERPRINTS" in line:
            inside = True
        elif "END SSH HOST KEY FINGERPRINTS" in line:
            inside = False
        elif inside and (m := _CONSOLE_FP.match(line.strip())):
            out.add(m.group(2))
    return out


# --- wiring -------------------------------------------------------------------------------------------------------


def credential_source(settings: Any) -> CredentialSource:
    directory = settings.renewal.credentials_dir
    return FileCredentialSource(directory) if directory is not None else NoCredentialStore()


def production_deps(settings: Any, engine: Engine) -> Any:
    """``Deps`` of ``bluegreen_fip_v1`` for this worker: the guarded SDK cloud port, the automation runner from
    ``Settings.automation`` (its run user, timeouts, repo allowlist), OpenSSH and HTTP probes. Nothing connects
    here: the runner, the cloud and the guests are reached only inside step attempts."""
    from ovlm.automation.config import runner_config
    from ovlm.automation.runner import AutomationRunner
    from ovlm.automation.store import ArtifactStore
    from ovlm.renewal.base import Deps
    from ovlm.renewal.config import RenewalConfig

    creds = credential_source(settings)
    rc = runner_config(settings)
    runner = _LazyRunner(lambda: AutomationRunner(rc))
    guest = RunnerGuestPort(
        engine, runner, creds,
        ssh=OpenSshTransport(rc.run_root / f".ssh-{uuid.uuid4().hex[:8]}"),
        http=UrllibGetter(), store=ArtifactStore(rc),
    )  # fmt: skip
    return Deps(engine, RenewalConfig.from_settings(settings), SdkCloudPort(creds), guest)


class _LazyRunner:
    """Builds the runner at first use: its constructor resolves the run user, which only the worker image has."""

    def __init__(self, factory: Callable[[], Any]) -> None:
        self._factory = factory
        self._runner: Any = None
        self._lock = threading.Lock()

    def _get(self) -> Any:
        with self._lock:
            if self._runner is None:
                self._runner = self._factory()
            return self._runner

    def prepare_automation(self, spec: AutomationSpec, workflow_id: str) -> PreparedAutomation:
        prepared: PreparedAutomation = self._get().prepare_automation(spec, workflow_id)
        return prepared

    def run_phase(
        self, prepared: PreparedAutomation, req: PhaseRequest, *, fence: FenceLike | None = None
    ) -> PhaseOutcome:
        outcome: PhaseOutcome = self._get().run_phase(prepared, req, fence=fence)
        return outcome
