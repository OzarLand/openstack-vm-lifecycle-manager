"""AutomationRunner with a stand-in ansible-runner: everything the runner does around the subprocess."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ovlm.automation.checkout import CloneOptions
from ovlm.automation.hostkeys import HostKeyPolicy
from ovlm.automation.model import (
    AutomationSpec,
    DataVolume,
    GuestTarget,
    PhaseRequest,
    PreparedAutomation,
    RunnerConfig,
)
from ovlm.automation.runner import AutomationRunner, lease_needed
from ovlm.automation.types import AutomationError, Classification, Phase, SecretBytes
from ovlm.workflow.clock import FakeClock
from ovlm.workflow.fence import Fence, FenceLost
from tests.unit.automation.test_checkout import make_repo

KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\n-----END OPENSSH PRIVATE KEY-----"
VAULT = b"vault-pass-0123456789"
HOSTKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwLM199YxaNqwwlrFbz6zrsuROa7AzsYbaXTnF5qNWB"
PLAYBOOK = "- hosts: ovlm_target\n  tasks:\n    - ansible.builtin.ping:\n"
FILES = {
    f"playbooks/{p}.yml": PLAYBOOK
    for p in (
        "preflight",
        "configure",
        "quiesce",
        "data_attach",
        "start_service",
        "healthcheck",
        "rollback_hooks",
    )
}  # noqa: E501


def good(phase: str, **over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"schema": "ovlm.result/1", "phase": phase, "ok": True, "changed": False,
                         "classification": "ok", "facts": {}, "checks": [], "message": "ok"}  # fmt: skip
    d.update(over)
    return d


@pytest.fixture
def env(tmp_path: Path) -> tuple[AutomationRunner, PreparedAutomation, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    runner_bin = bin_dir / "ansible-runner"
    runner_bin.write_text(
        f"#!{sys.executable}\nimport runpy,sys\nsys.path.insert(0, {str(Path(__file__).parent.parent.parent.parent)!r})\nfrom tests.unit.automation.fake_runner import main\nmain()\n"
    )  # noqa: E501
    runner_bin.chmod(0o755)
    (bin_dir / "ansible").write_text("#!/bin/sh\necho 'ansible [core 2.99.1]'\n")
    (bin_dir / "ansible").chmod(0o755)
    url, sha = make_repo(tmp_path / "src", FILES)
    cfg = RunnerConfig(
        run_root=tmp_path / "run", ansible_bin_dir=bin_dir, run_user=None,
        clone=CloneOptions(allowed_repos=[url], allow_file=True), allow_test_extravars=True,
        max_timeout={p: 100 for p in Phase}, default_timeout={p: 50 for p in Phase}, supervisor_slack=0.5,
    )  # fmt: skip
    runner = AutomationRunner(cfg)
    prepared = runner.prepare_automation(
        AutomationSpec(repo=url, ref=sha, inventory_vars={"app_port": 8080}), "wf1"
    )
    return runner, prepared, tmp_path


def request(
    phase: Phase = Phase.CONFIGURE, *, fake: dict[str, Any] | None = None, **over: Any
) -> PhaseRequest:
    kw: dict[str, Any] = dict(
        workflow_id="wf1", step_id="step1", attempt=1, phase=phase,
        target=GuestTarget(host="10.0.0.5", host_keys=HostKeyPolicy.pinned([HOSTKEY]), role="new"),
        ssh_key=SecretBytes(KEY), service_name="svc", test_extravars={"fake": fake or {}},
    )  # fmt: skip
    kw.update(over)
    return PhaseRequest(**kw)


def run(
    env: Any, phase: Phase = Phase.CONFIGURE, fake: dict[str, Any] | None = None, **over: Any
) -> Any:
    runner, prepared, tmp = env
    fake = {"record": str(tmp / f"rec-{phase.value}.json"), **(fake or {})}
    fence = over.pop("fence", None)
    return runner.run_phase(prepared, request(phase, fake=fake, **over), fence=fence)


def recorded(tmp: Path, phase: Phase = Phase.CONFIGURE) -> dict[str, Any]:
    return json.loads((tmp / f"rec-{phase.value}.json").read_text())  # type: ignore[no-any-return]


def test_success_path_and_evidence(env: Any) -> None:
    out = run(env, fake={"result": good("configure", changed=True), "events": [
        {"event": "runner_on_ok", "counter": 1, "event_data": {"task": "pkg", "host": "ovlm-target", "res": {"changed": True}}},
        {"event": "runner_on_ok", "counter": 2, "event_data": {"task": "cfg", "host": "ovlm-target", "res": {}}},
        {"event": "runner_on_skipped", "counter": 3, "event_data": {"task": "skip", "host": "ovlm-target", "res": {}}},
    ]})  # fmt: skip
    assert out.decision.classification is Classification.OK and out.result.changed
    assert [t["status"] for t in out.record.task_summary] == ["changed", "ok", "skipped"]
    r = out.record
    assert (
        r.sha == env[1].sha and r.ansible_core_version == "2.99.1" and len(r.extravars_sha256) == 64
    )
    assert r.requirements_hash == "none" and r.exit_code == 0 and r.host_key_mode == "pinned"
    assert "ovlm.vars" in r.extravars_keys and "ovlm_result_path" in r.extravars_keys
    assert r.result and r.result["reported_by"] == "guest"


def test_invocation_shape_no_secrets_on_argv_or_env(
    env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OS_PASSWORD", "cloud-secret")
    monkeypatch.setenv("OVLM_DB_PASSWORD_FILE", "/run/secrets/db")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")  # noqa: S108
    out = run(env, fake={"result": good("configure")}, vault_password=SecretBytes(VAULT))
    rec = recorded(env[2])
    argv = " ".join(rec["argv"])
    assert out.decision.classification is Classification.OK
    for forbidden in ("PRIVATE KEY", VAULT.decode(), "QUJDREVG"):
        assert forbidden not in argv
        assert forbidden not in json.dumps(rec["env"])
    assert (
        "OS_PASSWORD" not in rec["env"]
        and "OVLM_DB_PASSWORD_FILE" not in rec["env"]
        and "SSH_AUTH_SOCK" not in rec["env"]
    )
    assert (
        rec["env"]["ANSIBLE_CONFIG"].endswith("/ansible.cfg")
        and rec["env"]["ANSIBLE_COLLECTIONS_SCAN_SYS_PATH"] == "false"
    )
    assert rec["env"]["HOME"].endswith("/home") and rec["env"]["HOME"].startswith(
        str(env[2] / "run")
    )
    # files: 0600, run dir 0700, key by file (not env/ssh_key, which ansible-runner would load into an agent)
    assert (
        rec["run_dir_mode"] == "0o700"
        and rec["key_mode"] == "0o600"
        and rec["vault_mode"] == "0o600"
    )
    assert "ssh_key" not in rec["env_files"] and "guest_key" in rec["env_files"]
    assert rec["key_text"].startswith("-----BEGIN") and rec["key_text"].endswith("\n")
    assert rec["vault_text"].strip() == VAULT.decode()
    assert not (env[2] / "run" / "wf1" / "step1").exists(), (
        "run dir (with the secrets) wiped at the end"
    )
    assert (
        "--omit-env-files" in argv
        and "-p playbooks/configure.yml" in argv
        and "-i configure-1" in argv
    )


def test_inventory_known_hosts_cfg_and_extravars(env: Any) -> None:
    run(env, fake={"result": good("configure")}, project_scope="p1")
    rec = recorded(env[2])
    inv = json.loads(rec["inventory"])
    assert list(inv["all"]["children"]) == ["ovlm_target"] and list(
        inv["all"]["children"]["ovlm_target"]["hosts"]
    ) == ["ovlm-target"]
    hv = inv["all"]["children"]["ovlm_target"]["hosts"]["ovlm-target"]
    assert (
        hv["ansible_host"] == "10.0.0.5"
        and hv["ansible_user"] == "ovlm"
        and hv["ovlm_role"] == "new"
    )
    assert hv["ansible_ssh_private_key_file"].endswith("/env/guest_key")
    common = hv["ansible_ssh_common_args"]
    for needle in (
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "IdentitiesOnly=yes",
        "ForwardAgent=no",
        "BatchMode=yes",
    ):
        assert needle in common
    assert "StrictHostKeyChecking=no" not in common and "accept-new" not in common
    # the long pytest run root does not fit a unix socket path: multiplexing is off, not broken
    assert "ControlMaster=no" in common and "ControlPath=none" in common
    assert rec["known_hosts"] == f"10.0.0.5 {HOSTKEY}\n"
    cfg = rec["ansible_cfg"]
    assert (
        "host_key_checking = True" in cfg
        and "display_args_to_stdout = False" in cfg
        and "no_target_syslog = True" in cfg
    )
    assert "fact_caching = memory" in cfg and "nocolor = True" in cfg
    ev = json.loads(rec["extravars"])
    assert (
        ev["ovlm"]["workflow_id"] == "wf1"
        and ev["ovlm"]["role"] == "new"
        and ev["ovlm"]["vars"] == {"app_port": 8080}
    )
    assert ev["ovlm"]["check_mode"] is False and ev["ovlm_result_path"].endswith(
        "/artifacts/configure-1/result.json"
    )
    # connection variables must NOT be extra-vars: they would also redirect `delegate_to: localhost` tasks
    assert not any(k.startswith("ansible_") for k in ev)
    assert "PRIVATE KEY" not in rec["extravars"]
    assert json.loads(rec["settings"]) == {
        "job_timeout": 50,
        "idle_timeout": 50,
        "suppress_ansible_output": True,
    }


def test_data_volume_vars_and_first_use_is_always_false_for_renewals(env: Any) -> None:
    vol = DataVolume(id="vol-1", mount_point="/srv/data", fs_type="ext4")
    run(env, Phase.DATA_ATTACH, fake={"result": good("data_attach")}, data_volume=vol,
        expected_marker_checksum="abc", expected_fs_uuid="u-1")  # fmt: skip
    ev = json.loads(recorded(env[2], Phase.DATA_ATTACH)["extravars"])["ovlm"]
    assert ev["data_volume"] == {
        "id": "vol-1",
        "expected_serial": "vol-1",
        "mount_point": "/srv/data",
        "fs_type": "ext4",
        "first_use": False,
    }  # noqa: E501
    assert ev["expected_marker_checksum"] == "abc" and ev["expected_fs_uuid"] == "u-1"
    with pytest.raises(AutomationError, match="first_use"):
        run(
            env,
            Phase.DATA_ATTACH,
            data_volume=DataVolume(id="v", mount_point="/m", fs_type="ext4", first_use=True),
        )


def test_rollback_hooks_need_the_failed_phase(env: Any) -> None:
    with pytest.raises(AutomationError, match="phase that failed"):
        run(env, Phase.ROLLBACK_HOOKS)
    run(
        env,
        Phase.ROLLBACK_HOOKS,
        fake={"result": good("rollback_hooks")},
        rollback_phase=Phase.QUIESCE,
    )
    assert json.loads(recorded(env[2], Phase.ROLLBACK_HOOKS)["extravars"])["ovlm"]["rollback"] == {
        "phase": "quiesce"
    }


def test_test_extravars_cannot_override_ovlm_or_connection_vars(tmp_path: Path, env: Any) -> None:
    runner, prepared, _ = env
    with pytest.raises(AutomationError, match="override"):
        runner.run_phase(prepared, request(test_extravars={"ovlm": {}}))
    with pytest.raises(AutomationError, match="override"):
        runner.run_phase(prepared, request(test_extravars={"ovlm_result_path": "/etc/x"}))
    strict = AutomationRunner(
        RunnerConfig(**{**runner.cfg.__dict__, "allow_test_extravars": False})
    )
    with pytest.raises(AutomationError, match="not allowed"):
        strict.run_phase(prepared, request())


def test_check_mode_and_diff_flags(env: Any) -> None:
    run(env, Phase.HEALTHCHECK, fake={"result": good("healthcheck")}, check_mode=True)
    argv = recorded(env[2], Phase.HEALTHCHECK)["argv"]
    assert "--cmdline=--check" in argv  # no --diff: diffs are stored only when the profile opted in
    runner, prepared, _ = env
    prepared.spec = AutomationSpec(**{**prepared.spec.__dict__, "store_diffs": True})
    run(env, Phase.HEALTHCHECK, fake={"result": good("healthcheck")}, check_mode=True)
    assert "--cmdline=--check --diff" in recorded(env[2], Phase.HEALTHCHECK)["argv"]


def test_timeouts_are_bounded_by_the_ovlm_maximum(env: Any) -> None:
    runner, prepared, _ = env
    prepared.spec = AutomationSpec(
        **{**prepared.spec.__dict__, "timeouts": {"configure": 99999, "quiesce": 7}}
    )
    assert runner.timeout_for(Phase.CONFIGURE, prepared.spec) == 100
    assert runner.timeout_for(Phase.QUIESCE, prepared.spec) == 7
    assert runner.timeout_for(Phase.HEALTHCHECK, prepared.spec) == 50
    prepared.spec = AutomationSpec(**{**prepared.spec.__dict__, "timeouts": {"configure": 0}})
    with pytest.raises(AutomationError):
        runner.timeout_for(Phase.CONFIGURE, prepared.spec)
    assert lease_needed(60) == 60 + 30 + 30


def test_missing_playbook_is_fatal_before_anything_is_created(env: Any) -> None:
    runner, prepared, tmp = env
    # The checkout is read-only by design: a non-root user must restore write permission before removing it.
    os.chmod(prepared.checkout, 0o700)
    for path in [prepared.checkout / "playbooks", *(prepared.checkout / "playbooks").rglob("*")]:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    shutil.rmtree(prepared.checkout / "playbooks")
    with pytest.raises(AutomationError, match="missing") as exc:
        runner.run_phase(prepared, request())
    assert (
        exc.value.classification is Classification.FATAL
        and not (tmp / "run" / "wf1" / "step1").exists()
    )


# ---- hostile / broken output -> classification ------------------------------------------------------------


@pytest.mark.parametrize(
    ("phase", "fake", "expected"),
    [
        (Phase.CONFIGURE, {"result": "not json", "rc": 0}, Classification.RETRYABLE),
        (
            Phase.CONFIGURE,
            {"result": good("healthcheck"), "rc": 0},
            Classification.RETRYABLE,
        ),  # wrong phase
        (Phase.CONFIGURE, {"rc": 0}, Classification.RETRYABLE),  # no result at all
        (Phase.CONFIGURE, {"result": "[" * 100000, "rc": 0}, Classification.RETRYABLE),
        (
            Phase.CONFIGURE,
            {"result": good("configure", message="x" * 100000), "rc": 0},
            Classification.RETRYABLE,
        ),
        (
            Phase.QUIESCE,
            {"result": good("quiesce", extra="field"), "rc": 0},
            Classification.NEEDS_HUMAN,
        ),
        (Phase.DATA_ATTACH, {"rc": 0}, Classification.NEEDS_HUMAN),
        (
            Phase.DATA_ATTACH,
            {"result": good("data_attach", ok=False, classification="retryable"), "rc": 2},
            Classification.NEEDS_HUMAN,
        ),  # noqa: E501
        (Phase.QUIESCE, {"result": good("quiesce"), "rc": 2}, Classification.NEEDS_HUMAN),
        (
            Phase.CONFIGURE,
            {"result": good("configure", ok=False, classification="fatal"), "rc": 2},
            Classification.FATAL,
        ),
        (Phase.CONFIGURE, {"rc": 4}, Classification.FATAL),
        (Phase.CONFIGURE, {"rc": 3}, Classification.RETRYABLE),
        (Phase.CONFIGURE, {"result": "tmp-symlink", "rc": 0}, Classification.RETRYABLE),
    ],
)
def test_classification_of_untrusted_outputs(
    env: Any, phase: Phase, fake: dict[str, Any], expected: Classification
) -> None:
    if fake.get("result") == "tmp-symlink":
        secret = env[2] / "outside.json"
        secret.write_text(json.dumps(good("configure")))
        fake = {"result_symlink": str(secret), "rc": 0}
    out = run(
        env, phase, fake=fake, data_volume=DataVolume(id="v", mount_point="/m", fs_type="ext4")
    )
    assert out.decision.classification is expected, (out.decision, out.record.result_error)
    if expected is not Classification.OK and out.result is None:
        assert out.record.result_error


def test_symlinked_result_is_never_followed(env: Any) -> None:
    secret = env[2] / "outside.json"
    secret.write_text(json.dumps(good("configure")))
    out = run(env, fake={"result_symlink": str(secret), "rc": 0})
    assert out.result is None and out.record.result_error == "result.json missing"


def test_guest_text_is_data_and_redacted(env: Any) -> None:
    out = run(
        env,
        fake={
            "result": good("configure", message="password=hunter2 and {{ lookup('pipe','id') }}"),
            "stdout": f"x\n{KEY.decode()}\nvault {VAULT.decode()}\ntoken=abcdef12345\n",
            "events": [{"event": "runner_on_ok", "counter": 1, "event_data": {"task": "t\x1b[31m", "host": "h", "res": {"msg": "secret: hunter2", "diff": {"before": "a", "after": "b"}}}}],
        },
        vault_password=SecretBytes(VAULT),
    )  # fmt: skip
    blob = json.dumps(out.record.__dict__, default=str)
    for leak in ("hunter2", "BEGIN OPENSSH", "QUJDREVG", VAULT.decode(), "abcdef12345"):
        assert leak not in blob, leak
    assert "\x1b" not in out.record.task_summary[0]["task"]
    assert out.record.diff is None and '"diff"' not in json.dumps(out.record.events)


def test_diff_kept_only_with_store_diffs(env: Any) -> None:
    runner, prepared, _ = env
    prepared.spec = AutomationSpec(**{**prepared.spec.__dict__, "store_diffs": True})
    out = run(
        env,
        fake={
            "result": good("configure"),
            "events": [
                {
                    "event": "runner_on_ok",
                    "counter": 1,
                    "event_data": {
                        "task": "t",
                        "host": "h",
                        "res": {"changed": True, "diff": {"before": "a", "after": "b"}},
                    },
                }
            ],
        },
    )  # noqa: E501
    assert out.record.diff and '"after": "b"' in out.record.diff


def test_event_log_is_capped_and_hostile_events_ignored(env: Any) -> None:
    big = {
        "event": "runner_on_ok",
        "counter": 1,
        "event_data": {"task": "t", "host": "h", "res": {"stdout": "y" * 200_000}},
    }
    events = [
        big,
        "not json",
        "[]",
        '{"event": 5}',
        {"event": "runner_on_ok", "event_data": "string"},
        {"event": "runner_on_failed", "event_data": {"task": "ok", "res": []}},
    ]  # noqa: E501
    out = run(env, fake={"result": good("configure"), "events": events})
    assert out.decision.classification is Classification.OK
    statuses = [t["status"] for t in out.record.task_summary]
    assert "failed" in statuses  # the well-formed event after the garbage still counts


def test_log_is_capped_with_head_and_tail(env: Any) -> None:
    runner, prepared, tmp = env
    runner.cfg = RunnerConfig(**{**runner.cfg.__dict__, "log_max_bytes": 2000})
    out = run(env, fake={"result": good("configure"), "stdout": "HEAD" + "m" * 50_000 + "TAIL"})
    assert len(out.record.log.encode()) <= 2000 and "truncated" in out.record.log


def test_unreachable_event_is_a_retry_hint(env: Any) -> None:
    out = run(
        env,
        fake={
            "rc": 2,
            "events": [
                {
                    "event": "runner_on_unreachable",
                    "counter": 1,
                    "event_data": {"task": "ping", "host": "h", "res": {"msg": "no route"}},
                }
            ],
        },
    )  # noqa: E501
    assert (
        out.decision.classification is Classification.RETRYABLE
        and "unreachable" in out.decision.reason
    )


def test_timeout_is_classified_by_phase(env: Any) -> None:
    runner, prepared, tmp = env
    runner.cfg = RunnerConfig(
        **{
            **runner.cfg.__dict__,
            "max_timeout": {p: 1 for p in Phase},
            "idle_timeout": {p: 1 for p in Phase},
        }
    )  # noqa: E501
    out = run(env, Phase.CONFIGURE, fake={"sleep": 60})
    assert out.record.reason.endswith("[timeout]") or "[idle]" in out.record.reason
    assert out.decision.classification is Classification.RETRYABLE
    out = run(
        env,
        Phase.QUIESCE,
        fake={"sleep": 60},
        data_volume=DataVolume(id="v", mount_point="/m", fs_type="ext4"),
    )
    assert out.decision.classification is Classification.NEEDS_HUMAN


# ---- the fence gate -----------------------------------------------------------------------------------------


def make_fence(clock: FakeClock, lease: float = 60, margin: float = 10) -> Fence:
    return Fence(clock=clock, lease_duration=lease, fence_margin=margin, t_send=clock.monotonic())


def test_fence_deadline_stops_the_spawn(env: Any) -> None:
    runner, prepared, tmp = env
    clock = FakeClock()
    fence = make_fence(clock)
    clock.advance(51)  # past t_send + lease - margin
    spawned = tmp / "spawned"
    with pytest.raises(FenceLost):
        runner.run_phase(
            prepared,
            request(fake={"record": str(spawned), "result": good("configure")}),
            fence=fence,
        )
    assert not spawned.exists(), "no subprocess was started"
    assert not (tmp / "run" / "wf1" / "step1").exists(), (
        "the run dir (with secrets) was wiped on refusal"
    )


def test_fence_checked_right_before_spawn_with_the_phase_in_the_action(env: Any) -> None:
    runner, prepared, tmp = env
    seen: list[str] = []

    class F:
        def check(self, action: str) -> None:
            seen.append(action)
            assert (tmp / "run" / "wf1" / "step1" / "1" / "env" / "guest_key").exists(), (
                "secrets are in place when the gate runs"
            )  # noqa: E501
            assert not (tmp / "rec-configure.json").exists(), "and nothing has been spawned yet"

        def add_revoke_callback(self, cb: Any) -> Any:
            seen.append("registered")
            return lambda: seen.append("unregistered")

    run(env, fake={"result": good("configure")}, fence=F())
    assert seen == ["automation:spawn:configure", "registered", "unregistered"]


def test_revoked_fence_kills_a_running_phase(env: Any) -> None:
    import threading

    runner, prepared, tmp = env
    fence = make_fence(FakeClock())
    threading.Timer(1.0, lambda: fence.revoke("lease lost")).start()
    out = runner.run_phase(
        prepared,
        request(
            Phase.QUIESCE,
            fake={"sleep": 60},
            data_volume=DataVolume(id="v", mount_point="/m", fs_type="ext4"),
        ),
        fence=fence,
    )  # noqa: E501
    assert (
        out.decision.classification is Classification.NEEDS_HUMAN and "revoked" in out.record.reason
    )


# ---- prepare_automation ------------------------------------------------------------------------------------


def test_prepare_blocks_on_lint_unpinned_requirements_and_missing_collections(
    tmp_path: Path,
) -> None:
    def prep(files: dict[str, str], **cfg: Any) -> Any:
        url, sha = make_repo(tmp_path / f"r{len(list(tmp_path.iterdir()))}", files)
        r = AutomationRunner(
            RunnerConfig(
                run_root=tmp_path / "run",
                run_user=None,
                clone=CloneOptions(allowed_repos=[url], allow_file=True),
                **cfg,
            )
        )  # noqa: E501
        return r.prepare_automation(AutomationSpec(repo=url, ref=sha), "wf")

    bad_lint = {"playbooks/configure.yml": "- hosts: all\n  tasks: []\n"}
    with pytest.raises(AutomationError, match="hosts_pattern") as exc:
        prep(bad_lint)
    assert exc.value.classification is Classification.FATAL
    assert not (tmp_path / "run" / "wf" / "_checkout").exists(), "a refused checkout is removed"
    with pytest.raises(AutomationError, match="unpinned"):
        prep({**FILES, "requirements.yml": "collections:\n  - name: ansible.posix\n"})
    with pytest.raises(AutomationError, match="not vendored or shipped"):
        prep(
            {
                **FILES,
                "requirements.yml": "collections:\n  - name: ansible.posix\n    version: 2.2.2\n",
            }
        )
    with pytest.raises(AutomationError, match="not vendored or shipped"):  # wrong version shipped
        coll = tmp_path / "coll" / "ansible_collections" / "ansible" / "posix"
        coll.mkdir(parents=True)
        (coll / "MANIFEST.json").write_text(json.dumps({"collection_info": {"version": "1.0.0"}}))
        prep(
            {
                **FILES,
                "requirements.yml": "collections:\n  - name: ansible.posix\n    version: 2.2.2\n",
            },
            collections_paths=[tmp_path / "coll"],
        )  # noqa: E501
    (coll / "MANIFEST.json").write_text(json.dumps({"collection_info": {"version": "2.2.2"}}))
    ok = prep(
        {
            **FILES,
            "requirements.yml": "collections:\n  - name: ansible.posix\n    version: 2.2.2\n",
        },
        collections_paths=[tmp_path / "coll"],
    )  # noqa: E501
    assert len(ok.requirements_hash) == 64


def test_vendored_collections_in_the_repo_satisfy_the_pin(tmp_path: Path) -> None:
    files = {
        **FILES,
        "requirements.yml": "collections:\n  - name: ansible.posix\n    version: 2.2.2\n",
        "collections/ansible_collections/ansible/posix/MANIFEST.json": json.dumps(
            {"collection_info": {"version": "2.2.2"}}
        ),
    }
    url, sha = make_repo(tmp_path / "r", files)
    r = AutomationRunner(
        RunnerConfig(
            run_root=tmp_path / "run",
            run_user=None,
            clone=CloneOptions(allowed_repos=[url], allow_file=True),
        )
    )  # noqa: E501
    assert r.prepare_automation(AutomationSpec(repo=url, ref=sha), "wf").sha == sha


def test_release_removes_the_checkout(env: Any) -> None:
    runner, prepared, tmp = env
    assert prepared.checkout.exists()
    runner.release(prepared)
    assert not prepared.checkout.exists()
    assert stat.S_IMODE(os.stat(tmp).st_mode)  # sanity: tmp untouched


def test_requirement_not_in_the_checkout_directory_is_refused(env: Any) -> None:
    runner, _, tmp = env
    url, sha = make_repo(tmp / "r2", FILES)
    runner.cfg = RunnerConfig(
        **{**runner.cfg.__dict__, "clone": CloneOptions(allowed_repos=[url], allow_file=True)}
    )
    with pytest.raises(AutomationError, match="escapes"):
        runner.prepare_automation(
            AutomationSpec(repo=url, ref=sha, requirements="../../etc/passwd"), "wf2"
        )


def test_ansible_binary_must_exist(tmp_path: Path) -> None:
    r = AutomationRunner(
        RunnerConfig(run_root=tmp_path, ansible_bin_dir=tmp_path / "nope", run_user=None)
    )
    with pytest.raises(AutomationError, match="not found"):
        r.ansible_core_version()
    assert subprocess.run(["true"], check=False).returncode == 0  # noqa: S607


def test_ssh_control_path_is_per_run_short_and_removed(env: Any, tmp_path: Path) -> None:
    import tempfile

    runner, prepared, _ = env
    short = Path(tempfile.mkdtemp(prefix="o", dir="/tmp"))  # noqa: S108 - short: unix socket path limit
    try:
        runner.cfg = RunnerConfig(**{**runner.cfg.__dict__, "run_root": short / "r"})
        out = run(env, fake={"result": good("configure")})
        assert out.decision.classification is Classification.OK
        rec = json.loads((tmp_path / "rec-configure.json").read_text())
        common = json.loads(rec["inventory"])["all"]["children"]["ovlm_target"]["hosts"][
            "ovlm-target"
        ]["ansible_ssh_common_args"]  # noqa: E501
        assert "ControlMaster=auto" in common
        cp = next(x for x in common.split() if x.startswith("ControlPath="))[len("ControlPath=") :]
        assert len(cp.replace("%C", "x" * 40)) + 17 <= 100 and cp.startswith(
            str(short / "r" / ".cp")
        )
        assert not list((short / "r" / ".cp").iterdir()), "removed with the run"
    finally:
        shutil.rmtree(short, ignore_errors=True)


# ---- reverify_checkout (public API used by the renewal code) ------------------------------------------------


def test_reverify_checkout_adopts_the_checkout_left_by_prepare(env: Any) -> None:
    runner, prepared, _ = env
    again = runner.reverify_checkout(prepared.spec, "wf1")
    assert again is not None
    assert (again.sha, again.checkout, again.requirements_hash) == (
        prepared.sha,
        prepared.checkout,
        prepared.requirements_hash,
    )
    assert again.ansible_core_version == prepared.ansible_core_version


def test_reverify_checkout_returns_none_without_a_checkout(env: Any) -> None:
    runner, prepared, _ = env
    assert runner.reverify_checkout(prepared.spec, "other-run") is None


def test_reverify_checkout_refuses_a_checkout_at_another_sha(env: Any) -> None:
    runner, prepared, _ = env
    other = AutomationSpec(repo=prepared.spec.repo, ref="0" * 40)
    with pytest.raises(AutomationError) as exc:
        runner.reverify_checkout(other, "wf1")
    assert exc.value.classification is Classification.NEEDS_HUMAN


def test_reverify_checkout_rejects_an_unsafe_workflow_id(env: Any) -> None:
    runner, prepared, _ = env
    with pytest.raises(AutomationError):
        runner.reverify_checkout(prepared.spec, "../etc")
