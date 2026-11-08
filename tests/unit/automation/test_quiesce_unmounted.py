"""Lab finding AA (2026-11-08): the reference ``quiesce`` role on a VM that never mounted the data volume.

The worker died after W5 (volume attached to green) and before W6 (mounted on green); the operator rolled back and
S2 quiesced green. ``mountpoint`` was false and green had no ``last-quiesce.json``, so the role refused "state is
unknown" and the restore parked. For green in S2 that state is safe (nothing to stop or unmount), so OVLM passes
``ovlm.quiesce_allow_unmounted`` there, and only there; W1 on blue must keep refusing.

Three layers: the extra-vars OVLM renders (only quiesce on the new VM may carry the flag), the role's own decision
expressions evaluated with Jinja (needs nothing), and the real playbook run on localhost against a plain directory
that is not a mount point (needs ``ansible-playbook`` and ``mountpoint``; skipped otherwise).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml

from ovlm.automation.hostkeys import HostKeyPolicy
from ovlm.automation.model import DataVolume, GuestTarget, PhaseRequest
from ovlm.automation.render import build_extravars
from ovlm.automation.types import AutomationError, Phase, SecretBytes

ANSIBLE = Path(__file__).resolve().parents[3] / "ansible"
ROLE = ANSIBLE / "roles" / "quiesce" / "tasks" / "main.yml"
GROUP_VARS = ANSIBLE / "playbooks" / "group_vars" / "all.yml"
HOSTKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwLM199YxaNqwwlrFbz6zrsuROa7AzsYbaXTnF5qNWB"


# --- what OVLM renders --------------------------------------------------------------------------------------------


def _req(phase: Phase, role: str, allow: bool) -> PhaseRequest:
    return PhaseRequest(
        workflow_id="wf", step_id="s", attempt=1, phase=phase,
        target=GuestTarget(host="guest", host_keys=HostKeyPolicy.pinned([HOSTKEY]), role=role),  # type: ignore[arg-type]
        ssh_key=SecretBytes(b"k"), service_name="svc",
        data_volume=DataVolume(id="vol-1", mount_point="/srv/data", fs_type="ext4"),
        quiesce_allow_unmounted=allow,
    )  # fmt: skip


def _ovlm(req: PhaseRequest) -> dict[str, Any]:
    doc = build_extravars(
        req, Path("/r.json"), inventory_vars={}, allow_first_use=False, allow_test_extravars=False
    )
    ovlm: dict[str, Any] = doc["ovlm"]
    return ovlm


def test_the_flag_reaches_the_quiesce_of_the_new_vm() -> None:
    assert _ovlm(_req(Phase.QUIESCE, "new", True))["quiesce_allow_unmounted"] is True


def test_the_flag_is_absent_by_default() -> None:
    assert "quiesce_allow_unmounted" not in _ovlm(_req(Phase.QUIESCE, "old", False))
    assert "quiesce_allow_unmounted" not in _ovlm(_req(Phase.QUIESCE, "new", False))


@pytest.mark.parametrize(
    ("phase", "role"),
    [(Phase.QUIESCE, "old"), (Phase.DATA_ATTACH, "new"), (Phase.HEALTHCHECK, "old")],
)
def test_the_flag_is_refused_for_the_old_vm_and_other_phases(phase: Phase, role: str) -> None:
    with pytest.raises(AutomationError, match="quiesce_allow_unmounted"):
        _ovlm(_req(phase, role, True))


# --- the role's decision, evaluated without Ansible ---------------------------------------------------------------


def _jinja() -> jinja2.Environment:
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)  # noqa: S701 - expressions only, no HTML
    env.filters["bool"] = lambda v: (
        v if isinstance(v, bool) else str(v).strip().lower() in ("true", "yes", "1")
    )
    return env


def _task(tasks: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    return next(t for t in tasks if str(t.get("name", "")).startswith(prefix))


def _refuses(*, role: str, allow: bool, record: bool) -> bool:
    """Whether the role's "not mounted, no record" stop fires, with the volume NOT mounted, real (non-test) mode."""
    tasks = yaml.safe_load(ROLE.read_text())
    group = yaml.safe_load(GROUP_VARS.read_text())
    env = _jinja()
    ovlm = {"role": role, **({"quiesce_allow_unmounted": True} if allow else {})}
    ctx: dict[str, Any] = {
        "ovlm": ovlm, "ovlm_test_mode": False, "q_mp_before": {"rc": 1},
        "q_prev": {"content": "e30="} if record else {"changed": False, "failed": False},
    }  # fmt: skip
    ctx["ovlm_role"] = env.from_string(group["ovlm_role"]).render(ctx)
    ctx["ovlm_quiesce_allow_unmounted"] = env.from_string(
        group.get("ovlm_quiesce_allow_unmounted", "{{ false }}")
    ).render(ctx)
    gate = next(
        (t for t in tasks if "q_never_mounted_ok" in t.get("ansible.builtin.set_fact", {})), None
    )
    if gate is not None:
        ctx["q_never_mounted_ok"] = env.from_string(
            gate["ansible.builtin.set_fact"]["q_never_mounted_ok"]
        ).render(ctx)
    stop = _task(tasks, "Stop - the volume is not mounted")
    fail = _task(tasks, "Fail - nothing to compare against")
    assert stop["ansible.builtin.set_fact"] == {"ovlm_class": "needs_human"}
    fired = [env.compile_expression(t["when"])(**ctx) for t in (stop, fail)]
    assert fired[0] == fired[1], fired  # the class and the failure always go together
    return bool(fired[0])


def test_w1_on_the_old_vm_still_refuses_an_unmounted_volume_without_record() -> None:
    assert _refuses(role="old", allow=False, record=False)


def test_the_old_vm_refuses_even_if_the_flag_were_passed() -> None:
    assert _refuses(role="old", allow=True, record=False)


def test_the_new_vm_without_the_flag_refuses() -> None:
    assert _refuses(role="new", allow=False, record=False)


def test_s2_on_the_new_vm_with_the_flag_accepts_never_mounted() -> None:
    assert not _refuses(role="new", allow=True, record=False)


def test_an_earlier_record_is_never_a_refusal() -> None:
    assert not _refuses(role="old", allow=False, record=True)


# --- the real playbook, on localhost, against a directory that is not a mount point --------------------------------


def _collections() -> Path | None:
    """ansible.posix (the role's unmount task), pinned and never fetched here: the CI work dir of
    ``ansible/tests/run.sh`` or ``OVLM_CI_COLLECTIONS_PATH``."""
    for base in (
        os.environ.get("OVLM_CI_COLLECTIONS_PATH"),
        str(ANSIBLE / "tests" / "work" / "collections"),
    ):
        if base and (Path(base) / "ansible_collections/ansible/posix/MANIFEST.json").is_file():
            return Path(base)
    return None


def _ansible_playbook() -> str | None:
    found = shutil.which("ansible-playbook")
    local = Path(sys.executable).parent / "ansible-playbook"
    return found or (str(local) if local.exists() else None)


@pytest.fixture
def play(tmp_path: Path) -> Any:
    binary = _ansible_playbook()
    collections = _collections()
    if binary is None or shutil.which("mountpoint") is None or collections is None:
        pytest.skip(
            "needs ansible-playbook, mountpoint (util-linux) and the pinned ansible.posix collection"
        )
    mnt = tmp_path / "srv-data"
    mnt.mkdir()
    state = tmp_path / "state"
    inventory = tmp_path / "inventory.ini"
    inventory.write_text(
        f"[ovlm_target]\nlocal ansible_connection=local ansible_python_interpreter={sys.executable}\n"
    )

    def run(*, role: str, allow: bool) -> tuple[int, dict[str, Any]]:
        result = tmp_path / f"result-{role}-{allow}.json"
        result.unlink(missing_ok=True)
        ovlm: dict[str, Any] = {
            "workflow_id": "wf", "step": "s", "attempt": 1, "role": role, "check_mode": False, "service_name": "svc",
            "data_volume": {"id": "vol-1", "expected_serial": "vol-1", "mount_point": str(mnt), "fs_type": "ext4",
                            "first_use": False},
            "vars": {"service_units": []},  # nothing to stop: no systemd here
        }  # fmt: skip
        if allow:
            ovlm["quiesce_allow_unmounted"] = True
        extra = tmp_path / "extravars.json"
        extra.write_text(json.dumps({"ovlm": ovlm, "ovlm_result_path": str(result),
                                     "counter_state_dir": str(state), "ansible_become": False}))  # fmt: skip
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(tmp_path), "ANSIBLE_NOCOLOR": "1",
               "ANSIBLE_ROLES_PATH": str(ANSIBLE / "roles"), "ANSIBLE_LOCAL_TEMP": str(tmp_path / "tmp"),
               "ANSIBLE_REMOTE_TEMP": str(tmp_path / "rtmp"), "ANSIBLE_HOST_KEY_CHECKING": "False",
               "ANSIBLE_COLLECTIONS_PATH": str(collections)}  # fmt: skip
        proc = subprocess.run(  # noqa: S603
            [binary, "-i", str(inventory), str(ANSIBLE / "playbooks" / "quiesce.yml"), "-e", f"@{extra}"],
            capture_output=True, text=True, check=False, env=env, timeout=180,
        )  # fmt: skip
        if not result.is_file():
            pytest.fail(
                f"no result written (rc {proc.returncode}): {proc.stdout[-2000:]} {proc.stderr[-2000:]}"
            )
        doc: dict[str, Any] = json.loads(result.read_text())
        return proc.returncode, doc

    return run, state


def test_playbook_s2_on_a_never_mounted_new_vm_succeeds_without_marker(play: Any) -> None:
    run, state = play
    rc, doc = run(role="new", allow=True)
    assert rc == 0 and doc["ok"] is True and doc["classification"] == "ok", doc
    assert doc["facts"]["was_mounted"] is False and doc["facts"]["marker_sha256"] is None, doc[
        "facts"
    ]
    assert not (state / "last-quiesce.json").exists()  # no record invented for a volume never seen


def test_playbook_w1_on_an_unmounted_old_vm_without_record_is_needs_human(play: Any) -> None:
    run, _ = play
    rc, doc = run(role="old", allow=False)
    assert rc != 0 and doc["ok"] is False and doc["classification"] == "needs_human", doc
    assert "state is unknown" in doc["message"], doc


def test_playbook_new_vm_without_the_flag_is_needs_human(play: Any) -> None:
    run, _ = play
    rc, doc = run(role="new", allow=False)
    assert rc != 0 and doc["classification"] == "needs_human", doc
