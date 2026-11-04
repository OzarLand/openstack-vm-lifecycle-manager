"""Production adapters of the renewal ports (``ovlm.renewal.production``) without a cloud or a guest: credentials
(interim file source and its permission checks), the guarded SDK cloud port, the Keystone token pre-warm through a
read-only session, the external identity check, cloud-init user-data, the fixed probe command list and OpenSSH argv.
"Unit tested" only: the real Keystone, sshd and HTTP paths are lab items (E5-6)."""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ovlm.automation.hostkeys import PublicKey, parse_public_key
from ovlm.automation.types import AutomationError, SecretBytes
from ovlm.openstack.errors import ReadOnlyViolationError, WriteNotAllowedError
from ovlm.openstack.ownership import InMemoryOwnershipRegistry
from ovlm.openstack.sdk_write import WriteCredential
from ovlm.renewal.ports import GuestRef
from ovlm.renewal.production import (
    NO_STORE_REASON,
    ROTATE_HOST_KEYS,
    FileCredentialSource,
    HttpAnswer,
    NoCredentialStore,
    OpenSshTransport,
    ProjectCredentials,
    RunnerGuestPort,
    SdkCloudPort,
    SshResult,
    _console_fingerprints,
    identify,
    public_key_of,
)
from tests.unit.test_openstack_allowlist import CannedCloud

PC = "0b0b0b0b-0000-4000-8000-000000000001"


def _key() -> tuple[bytes, str]:
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    pub = k.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    return priv, pub.decode()


# --- credentials ---------------------------------------------------------------------------------------------------


def _cred_dir(tmp_path: Path, *, mode: int = 0o600) -> Path:
    d = tmp_path / "creds"
    d.mkdir(mode=0o700)
    priv, _pub = _key()
    (d / f"{PC}.json").write_text(json.dumps({
        "auth_url": "https://keystone.invalid/v3", "application_credential_id": "id",
        "application_credential_secret": "s3cret-value", "region_name": "R1",
        "expires_at": "2027-01-01T00:00:00+00:00", "user_id": "u-1",
    }))  # fmt: skip
    (d / f"{PC}.guest_key").write_bytes(priv)
    for f in d.iterdir():
        f.chmod(mode)
    return d


def test_no_store_means_admission_rejects_with_the_reason() -> None:
    port = SdkCloudPort(NoCredentialStore())
    assert port.unavailable_reason(PC) == NO_STORE_REASON
    with pytest.raises(AutomationError):
        port.write_credential_expires_at(PC)


def test_file_source_reads_credentials_in_memory(tmp_path: Path) -> None:
    src = FileCredentialSource(_cred_dir(tmp_path))
    creds = src.for_project(PC)
    assert creds is not None
    assert creds.write.application_credential_secret == "s3cret-value"
    assert "s3cret" not in repr(creds) and "PRIVATE" not in repr(creds)
    assert creds.expires_at == datetime(2027, 1, 1, tzinfo=UTC) and creds.write_user_id == "u-1"
    assert creds.guest_public_key.startswith("ssh-ed25519 ")
    port = SdkCloudPort(src)
    assert port.unavailable_reason(PC) is None
    assert port.write_user_id(PC) == "u-1"


@pytest.mark.skipif(
    os.getuid() == 0, reason="root reads any file; the check is about the worker user"
)
def test_file_source_permission_check_runs_as_the_worker_user(tmp_path: Path) -> None:
    src = FileCredentialSource(_cred_dir(tmp_path, mode=0o640))
    assert "not readable by group or others" in (SdkCloudPort(src).unavailable_reason(PC) or "")


def test_file_source_refuses_loose_permissions(tmp_path: Path) -> None:
    d = _cred_dir(tmp_path)
    (d / f"{PC}.guest_key").chmod(0o644)
    reason = SdkCloudPort(FileCredentialSource(d)).unavailable_reason(PC)
    assert reason is not None and "not readable by group or others" in reason
    assert "s3cret" not in reason


def test_file_source_ignores_ids_that_are_not_uuids(tmp_path: Path) -> None:
    src = FileCredentialSource(_cred_dir(tmp_path))
    assert src.for_project("../creds/" + PC) is None
    assert (
        src.for_project("00000000-0000-0000-0000-000000000000") is None
    )  # no files: not available


def test_public_key_of_matches_the_private_key() -> None:
    priv, pub = _key()
    assert public_key_of(priv) == pub


# --- cloud port ----------------------------------------------------------------------------------------------------


def _creds() -> ProjectCredentials:
    priv, pub = _key()
    return ProjectCredentials(
        WriteCredential("http://keystone.invalid/v3", "id", "s3cret", "R1"), SecretBytes(priv), pub
    )


class _Static:
    creds: ProjectCredentials | None = None

    def for_project(self, pc: str) -> ProjectCredentials | None:
        if _Static.creds is None:
            _Static.creds = _creds()
        return _Static.creds


def test_write_client_exists_only_in_the_worker() -> None:
    port = SdkCloudPort(_Static(), process_role="api")
    with pytest.raises(WriteNotAllowedError):
        port.write_client(InMemoryOwnershipRegistry("r"), lambda a: None, project=PC)


def test_write_client_is_guarded_and_needs_a_gate() -> None:
    client = SdkCloudPort(_Static()).write_client(
        InMemoryOwnershipRegistry("r"), lambda a: None, project=PC
    )
    assert type(client).__name__ == "GuardedWriteClient"


class _CannedTokenPort(SdkCloudPort):
    def __init__(self, cloud: CannedCloud) -> None:
        super().__init__(_Static())
        self.cloud = cloud
        self.session: Any = None

    def _token_session(self, ks_session: Any, auth: Any, verify: bool | str) -> Any:
        self.session = ks_session.Session(auth=auth, verify=verify)
        self.session.session.mount("http://", self.cloud)
        return self.session


def test_token_prewarm_sends_only_the_token_request() -> None:
    cloud = CannedCloud()
    port = _CannedTokenPort(cloud)
    expires = port.token_expires_at(PC)
    assert expires is not None and expires.year == 2099
    assert [(m, u.rsplit("/", 2)[-2:]) for m, u, _h, _b in cloud.sent] == [
        ("POST", ["auth", "tokens"])
    ]
    with pytest.raises(ReadOnlyViolationError):  # the session carries the read-only guard
        port.session.post(
            "http://nova.invalid/v2.1/servers", json={}, endpoint_filter={"service_type": "compute"}
        )


# --- external identity ---------------------------------------------------------------------------------------------

BLUE, GREEN = "b1b1b1b1-0000-4000-8000-000000000001", "a2a2a2a2-0000-4000-8000-000000000002"
CANDIDATES: Mapping[str, str | None] = {BLUE: "app01-prod", GREEN: "app01-ovlm-0123456789ab"}


@pytest.mark.parametrize(
    ("answer", "who"),
    [
        (HttpAnswer(200, {"X-OVLM-Server-Id": GREEN}, b""), GREEN),
        (HttpAnswer(200, {"x-ovlm-server-id": BLUE}, b""), BLUE),
        (HttpAnswer(200, {}, json.dumps({"server_id": GREEN}).encode()), GREEN),
        (HttpAnswer(200, {}, json.dumps({"hostname": "app01-prod"}).encode()), BLUE),
        (
            HttpAnswer(
                200, {}, json.dumps({"hostname": "APP01-OVLM-0123456789AB.novalocal"}).encode()
            ),
            GREEN,
        ),
        (HttpAnswer(200, {"X-OVLM-Server-Id": "someone-else"}, b""), None),
        (HttpAnswer(200, {}, json.dumps({"hostname": "intruder"}).encode()), None),
        (HttpAnswer(200, {}, b"<html>ok</html>"), None),
        (HttpAnswer(None, {}, b"", "ConnectionRefusedError"), None),
    ],
)
def test_identity_must_name_one_candidate(answer: HttpAnswer, who: str | None) -> None:
    assert identify(answer, CANDIDATES) == who


def test_identity_is_never_guessed_between_two_equal_hostnames() -> None:
    body = json.dumps({"hostname": "app"}).encode()
    assert identify(HttpAnswer(200, {}, body), {BLUE: "app", GREEN: "APP"}) is None


# --- guest port pieces that need no guest --------------------------------------------------------------------------


class _Http:
    def __init__(self, answer: HttpAnswer) -> None:
        self.answer, self.urls = answer, []  # type: ignore[var-annotated]

    def get(self, url: str, timeout: float) -> HttpAnswer:
        self.urls.append(url)
        return self.answer


def _port(http: Any = None, ssh: Any = None) -> RunnerGuestPort:
    return RunnerGuestPort(None, None, _Static(), ssh=ssh, http=http)  # type: ignore[arg-type]


def test_external_probe_builds_the_url_and_checks_status_and_identity() -> None:
    http = _Http(HttpAnswer(200, {"X-OVLM-Server-Id": GREEN}, b""))
    res = _port(http).external_probe(
        "192.0.2.10",
        {"scheme": "http", "port": 8080, "path": "/healthz", "expected_status": 200},
        CANDIDATES,
    )
    assert res.ok and res.identity == GREEN and http.urls == ["http://192.0.2.10:8080/healthz"]
    bad = _port(_Http(HttpAnswer(503, {"X-OVLM-Server-Id": GREEN}, b""))).external_probe(
        "2001:db8::1",
        {"scheme": "https", "port": 443, "path": "health", "expected_status": 200},
        CANDIDATES,
    )
    assert not bad.ok


def test_a_tcp_check_cannot_prove_identity() -> None:
    res = _port(_Http(HttpAnswer(200, {}, b""))).external_probe(
        "192.0.2.10", {"scheme": "tcp", "port": 22}, CANDIDATES
    )
    assert not res.ok and res.identity is None


def test_console_fingerprints_are_parsed_strictly() -> None:
    console = (
        "noise\nci-info: -----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
        "ci-info: 256 SHA256:abcDEF123+/= root@g (ED25519)\n"
        "ci-info: evil SHA256:zzz (ED25519) trailing\n"
        "ci-info: -----END SSH HOST KEY FINGERPRINTS-----\n"
        "256 SHA256:outside root@g (ED25519)\n"
    )
    assert _console_fingerprints(console) == {"SHA256:abcDEF123+/="}


# --- OpenSSH transport, with a stand-in ssh on PATH ------------------------------------------------------------------

_FAKE_SSH = """#!{py}
import json, os, stat, sys
args = sys.argv[1:]
key = args[args.index("-i") + 1]
kh = [a.split("=", 1)[1] for a in args if a.startswith("UserKnownHostsFile=")][0]
json.dump({{"argv": args, "key_mode": oct(stat.S_IMODE(os.stat(key).st_mode)),
           "dir_mode": oct(stat.S_IMODE(os.stat(os.path.dirname(key)).st_mode)),
           "known_hosts": open(kh).read(), "env": sorted(os.environ)}}, open({out!r}, "w"))
print("running")
"""


def test_openssh_transport_pins_the_key_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    out = tmp_path / "record.json"
    ssh = bindir / "ssh"
    ssh.write_text(_FAKE_SSH.format(py=sys.executable, out=str(out)))
    ssh.chmod(ssh.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    priv, pub = _key()
    t = OpenSshTransport(tmp_path / "work")
    res = t.run(host="10.0.0.5", port=22, user="ovlm", keys=[parse_public_key(pub)], private_key=SecretBytes(priv),
                command=("findmnt", "-n", "--", "/srv/data dir"), timeout=10)  # fmt: skip
    assert res == SshResult(0, "running\n", "")
    rec = json.loads(out.read_text())
    assert "StrictHostKeyChecking=yes" in rec["argv"] and "BatchMode=yes" in rec["argv"]
    assert rec["argv"][-1] == "findmnt -n -- '/srv/data dir'"  # one quoted remote command line
    assert rec["key_mode"] == "0o600" and rec["dir_mode"] == "0o700"
    assert rec["known_hosts"].strip() == f"10.0.0.5 {pub}"
    assert set(rec["env"]) <= {
        "PATH",
        "HOME",
        "LC_CTYPE",
        "PWD",
        "SHLVL",
        "_",
    }  # no inherited secrets
    assert list((tmp_path / "work").iterdir()) == []  # the key file is gone
    assert t.run(host="10.0.0.5", port=22, user="ovlm", keys=[], private_key=SecretBytes(priv), command=("true",),
                 timeout=5).exit_code == 255  # fmt: skip


# --- probe and pinning logic over an SSH double ------------------------------------------------------------------


class _Ssh:
    def __init__(
        self, host_key: PublicKey, answers: dict[tuple[str, ...], SshResult] | None = None
    ) -> None:
        self.host_key, self.answers = host_key, answers or {}
        self.commands: list[tuple[str, ...]] = []

    def keyscan(self, host: str, port: int) -> list[PublicKey]:
        return [self.host_key]

    def run(self, *, host: str, port: int, user: str, keys: Sequence[PublicKey], private_key: SecretBytes,
            command: Sequence[str], timeout: float) -> SshResult:  # fmt: skip
        self.commands.append(tuple(command))
        if self.host_key not in keys:
            return SshResult(255, "", "Host key verification failed.")
        if tuple(command) == ROTATE_HOST_KEYS:
            _p, new = _key()
            self.host_key = parse_public_key(new)
            return SshResult(0, new + "\n")
        return self.answers.get(tuple(command), SshResult(0, ""))


class _ResolvedPort(RunnerGuestPort):
    def _resolved(self, run_id: str) -> Mapping[str, Any]:
        return {"service": {"project_connection_id": PC}, "guest_access": {"ssh_user": "ovlm"}}


class _Fence:
    def __init__(self) -> None:
        self.checks: list[str] = []

    def check(self, action: str) -> None:
        self.checks.append(action)

    def add_revoke_callback(self, cb: Any) -> Any:
        return lambda: None


def _guest(ssh: _Ssh) -> _ResolvedPort:
    return _ResolvedPort(None, None, _Static(), ssh=ssh, http=None)  # type: ignore[arg-type]


def test_probe_runs_only_the_fixed_list_and_refuses_odd_arguments() -> None:
    _p, pub = _key()
    ssh = _Ssh(parse_public_key(pub), {("cloud-init", "status"): SshResult(0, "status: done\n"),
                                       ("systemctl", "is-system-running"): SshResult(0, "degraded\n")})  # fmt: skip
    g = _guest(ssh)
    target = GuestRef(GREEN, "10.0.0.9", "new", (pub,))
    res = g.probe("run", target, mount_point="/srv/data", units=("app.service",))
    assert (
        res.reachable
        and res.mounted
        and res.units_active
        and res.cloud_init_done
        and res.system_state == "degraded"
    )
    assert ssh.commands == [("systemctl", "is-system-running"), ("findmnt", "-n", "--", "/srv/data"),
                            ("systemctl", "is-active", "--", "app.service"), ("cloud-init", "status")]  # fmt: skip
    for bad in (
        {"mount_point": "/srv; rm -rf /", "units": ()},
        {"mount_point": None, "units": ("x; reboot",)},
    ):
        with pytest.raises(AutomationError):
            g.probe("run", target, **bad)


def test_blue_is_reached_only_with_the_registered_fingerprint() -> None:
    _p, pub = _key()
    key = parse_public_key(pub)
    g = _guest(_Ssh(key))
    assert g.probe("run", GuestRef(BLUE, "10.0.0.5", "old", fingerprint=key.fingerprint), mount_point=None,
                   units=()).reachable  # fmt: skip
    assert not g.probe("run", GuestRef(BLUE, "10.0.0.5", "old", fingerprint="SHA256:other"), mount_point=None,
                       units=()).reachable  # fmt: skip


def test_injected_policy_rotates_once_behind_the_fence_and_pins_the_new_key() -> None:
    _p, boot = _key()
    ssh = _Ssh(parse_public_key(boot))
    fence = _Fence()
    res = _guest(ssh).pin_host_key(run_id="r", target=GuestRef(GREEN, "10.0.0.9", "new"), policy="injected",
                                   bootstrap_public=boot, accept=(), console=None, fence=fence)  # fmt: skip
    assert (
        res.ok
        and res.mode == "rotated"
        and res.pinned == (ssh.host_key.line,)
        and boot not in res.pinned
    )
    assert fence.checks == ["guest:rotate_host_keys"]
    assert ssh.commands.count(ROTATE_HOST_KEYS) == 1


def test_injected_policy_never_trusts_another_key() -> None:
    _p, boot = _key()
    _p2, actual = _key()
    res = _guest(_Ssh(parse_public_key(actual))).pin_host_key(
        run_id="r", target=GuestRef(GREEN, "10.0.0.9", "new"), policy="injected", bootstrap_public=boot,
        accept=(), console=None, fence=_Fence(),
    )  # fmt: skip
    assert not res.ok and res.reason == "host key mismatch"


def test_rerun_accepts_only_the_keys_already_pinned() -> None:
    _p, pinned = _key()
    ssh = _Ssh(parse_public_key(pinned))
    res = _guest(ssh).pin_host_key(run_id="r", target=GuestRef(GREEN, "10.0.0.9", "new"), policy="injected",
                                   bootstrap_public=None, accept=(pinned,), console=None, fence=_Fence())  # fmt: skip
    assert (
        res.ok
        and res.pinned == (parse_public_key(pinned).line,)
        and ROTATE_HOST_KEYS not in ssh.commands
    )


@pytest.mark.parametrize("policy", ["injected", "console", "tofu"])
def test_rerun_after_a_recorded_pin_never_falls_back_to_the_bootstrap_key(policy: str) -> None:
    """REN-2 (reviewer probe 2): green's keys were rotated and pinned; a later B5 re-run finds a host at green's
    address that presents the **bootstrap** key (the impostor holds the user-data copy). The pinned connection fails
    with a host-key mismatch: needs_human, never a connection with the bootstrap key, never a rotation, never a
    re-pin. Holds even if a caller still passes the bootstrap key along."""
    _p, boot = _key()
    _p2, pinned = _key()
    ssh = _Ssh(parse_public_key(boot))  # the answering host presents the bootstrap key
    fence = _Fence()
    res = _guest(ssh).pin_host_key(run_id="r", target=GuestRef(GREEN, "10.0.0.9", "new"), policy=policy,
                                   bootstrap_public=boot, accept=(pinned,), console=None, fence=fence)  # fmt: skip
    assert not res.ok and res.reason == "host key unverifiable" and res.pinned == ()
    assert ROTATE_HOST_KEYS not in ssh.commands and fence.checks == []
    assert ssh.commands == [("true",)]  # one attempt, with the pinned key only


def test_rerun_after_a_recorded_pin_waits_when_green_is_unreachable() -> None:
    """A network blip on a re-run is still "unreachable" (B5 waits on the pinned key), not a fallback."""
    _p, boot = _key()
    _p2, pinned = _key()

    class _Down(_Ssh):
        def run(self, **kw: Any) -> SshResult:
            self.commands.append(tuple(kw["command"]))
            return SshResult(255, "", "ssh: connect to host 10.0.0.9 port 22: Connection timed out")

    ssh = _Down(parse_public_key(boot))
    res = _guest(ssh).pin_host_key(run_id="r", target=GuestRef(GREEN, "10.0.0.9", "new"), policy="injected",
                                   bootstrap_public=boot, accept=(pinned,), console=None, fence=_Fence())  # fmt: skip
    assert not res.ok and res.reason == "unreachable" and ssh.commands == [("true",)]


def test_console_policy_pins_only_keys_the_console_vouches_for() -> None:
    _p, pub = _key()
    key = parse_public_key(pub)
    console = (f"-----BEGIN SSH HOST KEY FINGERPRINTS-----\n256 {key.fingerprint} root@g (ED25519)\n"
               "-----END SSH HOST KEY FINGERPRINTS-----\n")  # fmt: skip
    g = _guest(_Ssh(key))
    ok = g.pin_host_key(run_id="r", target=GuestRef(GREEN, "10.0.0.9", "new"), policy="console",
                        bootstrap_public=None, accept=(), console=console, fence=_Fence())  # fmt: skip
    assert ok.ok and ok.mode == "console"
    bad = g.pin_host_key(run_id="r", target=GuestRef(GREEN, "10.0.0.9", "new"), policy="console",
                         bootstrap_public=None, accept=(), console="", fence=_Fence())  # fmt: skip
    assert not bad.ok


def test_bootstrap_user_data_holds_the_guest_key_and_a_fresh_host_key() -> None:
    g = _guest(_Ssh(parse_public_key(_key()[1])))
    boot = g.bootstrap("run", "injected")
    assert boot.user_data.startswith("#cloud-config\n")
    doc = yaml.safe_load(boot.user_data)
    user = doc["users"][1]
    creds = _Static().for_project(PC)
    assert creds is not None
    assert user["name"] == "ovlm" and user["ssh_authorized_keys"] == [creds.guest_public_key]
    assert user["sudo"] == "ALL=(ALL) NOPASSWD:ALL" and user["lock_passwd"] is True
    assert doc["ssh_keys"]["ed25519_public"] == boot.public_key and doc["ssh_deletekeys"] is True
    assert boot.key_id == parse_public_key(boot.public_key or "").fingerprint
    assert "PRIVATE" not in repr(boot)
    other = g.bootstrap("run", "injected")
    assert other.public_key != boot.public_key  # one key per call (per run)
    assert "ssh_keys" not in yaml.safe_load(g.bootstrap("run", "console").user_data)


# --- the run-level checkout after a worker restart -----------------------------------------------------------------


class _Runner:
    def __init__(self, on_disk: bool) -> None:
        self.on_disk, self.cloned, self.adopted = on_disk, 0, 0

    def prepare_automation(self, spec: Any, workflow_id: str) -> Any:
        self.cloned += 1
        return object()

    def adopt_checkout(self, spec: Any, workflow_id: str) -> Any:
        self.adopted += 1
        return object() if self.on_disk else None


class _CheckoutPort(RunnerGuestPort):
    def __init__(self, runner: _Runner, outage: bool) -> None:
        super().__init__(None, runner, _Static(), ssh=None, http=None)  # type: ignore[arg-type]
        self.outage = outage

    def _resolved(self, run_id: str) -> Mapping[str, Any]:
        return {}

    def _spec(self, run_id: str, resolved: Mapping[str, Any]) -> Any:
        return object()

    def _in_outage(self, run_id: str) -> bool:
        return self.outage


@pytest.mark.parametrize(
    ("on_disk", "outage", "cloned"), [(True, True, 0), (True, False, 0), (False, False, 1)]
)
def test_a_restarted_worker_reuses_the_checkout_and_clones_only_outside_the_outage(
    on_disk: bool, outage: bool, cloned: int
) -> None:
    runner = _Runner(on_disk)
    port = _CheckoutPort(runner, outage)
    first = port._prepared_for("run")  # noqa: SLF001
    assert port._prepared_for("run") is first and runner.cloned == cloned and runner.adopted == 1  # noqa: SLF001


def test_no_git_host_contact_inside_the_downtime_window() -> None:
    runner = _Runner(on_disk=False)
    with pytest.raises(AutomationError, match="inside the downtime window") as exc:
        _CheckoutPort(runner, outage=True)._prepared_for("run")  # noqa: SLF001
    assert exc.value.classification.value == "needs_human" and runner.cloned == 0


def test_lazy_runner_adopts_the_checkout_through_the_public_reverify() -> None:
    """The worker's runner wrapper uses the automation module's public ``reverify_checkout`` (no private helpers)."""
    from ovlm.renewal.production import _LazyRunner

    seen: list[tuple[Any, str]] = []
    prepared: Any = object()

    class _Automation:
        def reverify_checkout(self, spec: Any, workflow_id: str) -> Any:
            seen.append((spec, workflow_id))
            return None if workflow_id == "gone" else prepared

    lazy = _LazyRunner(_Automation)
    spec = object()
    assert lazy.adopt_checkout(spec, "run") is prepared  # type: ignore[arg-type]
    assert lazy.adopt_checkout(spec, "gone") is None  # type: ignore[arg-type]
    assert seen == [(spec, "run"), (spec, "gone")]
