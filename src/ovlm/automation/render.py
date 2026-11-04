"""Files OVLM writes for a run: one-host inventory, OVLM-owned ansible.cfg, runner settings, extra-vars."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ovlm.automation.hostkeys import (
    HostKeyPolicy,
    ssh_common_options,
    validate_host,
    validate_port,
    validate_user,
)
from ovlm.automation.model import DataVolume, PhaseRequest
from ovlm.automation.types import AutomationError, Phase

HOST_ALIAS = "ovlm-target"
_SOCKET_PATH_LIMIT = 100  # sun_path is 108 bytes; ssh appends a 17-char random suffix


def control_path(directory: Path) -> str | None:
    """Per-run ControlPath, or ``None`` (ControlMaster off) when it would not fit in a unix socket path."""
    candidate = f"{directory}/%C"
    return candidate if len(str(directory)) + 1 + 40 + 17 <= _SOCKET_PATH_LIMIT else None


def connection_vars(
    req: PhaseRequest, key_path: Path, known_hosts: Path, cp: str | None
) -> dict[str, Any]:
    t = req.target
    common = " ".join(ssh_common_options(known_hosts, t.host_keys, cp))
    return {
        "ansible_host": validate_host(t.host),
        "ansible_port": validate_port(t.port),
        "ansible_user": validate_user(t.user),
        "ansible_connection": "ssh",
        "ansible_ssh_private_key_file": str(key_path),
        "ansible_ssh_common_args": common,
        "ansible_ssh_extra_args": "",
        "ansible_ssh_args": "",
        "ansible_ssh_pipelining": True,
    }


def render_inventory(req: PhaseRequest, conn: Mapping[str, Any]) -> str:
    """Exactly one host in the group ``ovlm_target`` (never ``all``, never a group from the repo). JSON is valid
    YAML, so no quoting bugs are possible whatever the values contain."""
    host_vars = {**conn, "ovlm_role": req.target.role}
    doc = {"all": {"children": {"ovlm_target": {"hosts": {HOST_ALIAS: host_vars}}}}}
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def render_ansible_cfg(run: Path, collections: str, roles: str) -> str:
    """OVLM's own configuration (contract section 2); the repo's ansible.cfg is never honoured."""
    return (
        "[defaults]\n"
        f"local_tmp = {run}/tmp\n"  # noqa: S108
        f"collections_path = {collections}\n"
        f"roles_path = {roles}\n"
        "host_key_checking = True\n"
        "retry_files_enabled = False\n"
        "gathering = implicit\n"
        "fact_caching = memory\n"
        "remote_tmp = $HOME/.ansible/tmp\n"  # shell-expanded: HOME is the run dir on the controller, the guest home there
        "display_args_to_stdout = False\n"
        "no_target_syslog = True\n"
        "interpreter_python = auto_silent\n"
        "timeout = 30\n"
        "forks = 1\n"
        "nocolor = True\n"
        "[ssh_connection]\n"
        "pipelining = True\n"
        "ssh_args =\n"
    )


def build_extravars(
    req: PhaseRequest,
    result_path: Path,
    *,
    inventory_vars: Mapping[str, Any],
    allow_first_use: bool,
    allow_test_extravars: bool,
) -> dict[str, Any]:
    ovlm: dict[str, Any] = {
        "workflow_id": req.workflow_id,
        "step": req.step_id,
        "attempt": req.attempt,
        "role": req.target.role,
        "check_mode": req.check_mode,
        "service_name": req.service_name,
        "vars": dict(inventory_vars),
    }
    if req.data_volume is not None:
        ovlm["data_volume"] = _volume(req.data_volume, allow_first_use)
    if req.expected_marker_checksum:
        ovlm["expected_marker_checksum"] = req.expected_marker_checksum
    if req.expected_fs_uuid:
        ovlm["expected_fs_uuid"] = req.expected_fs_uuid
    if req.phase is Phase.ROLLBACK_HOOKS:
        if req.rollback_phase is None:
            raise AutomationError("rollback_hooks needs the phase that failed")
        ovlm["rollback"] = {"phase": req.rollback_phase.value}
    # Connection variables are inventory host vars only. As extra-vars they would also apply to
    # ``delegate_to: localhost`` tasks (the result writer) and send them to the guest.
    doc: dict[str, Any] = {"ovlm": ovlm, "ovlm_result_path": str(result_path)}
    if req.test_extravars:
        if not allow_test_extravars:
            raise AutomationError("test extra-vars are not allowed in this configuration")
        for k, v in req.test_extravars.items():
            if k in doc or k == "ovlm":
                raise AutomationError("test extra-vars may not override OVLM variables")
            doc[k] = v
    return doc


def _volume(v: DataVolume, allow_first_use: bool) -> dict[str, Any]:
    if v.first_use and not allow_first_use:
        raise AutomationError("first_use=true is not available to the renewal strategy")
    return {
        "id": v.id,
        "expected_serial": v.expected_serial or v.id,
        "mount_point": v.mount_point,
        "fs_type": v.fs_type,
        "first_use": v.first_use,
    }


def extravars_digest(doc: Mapping[str, Any]) -> tuple[str, bytes, list[str]]:
    """(sha256, serialised bytes, sorted key list): the run record stores only the first and the last."""
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    keys = sorted({*doc.keys(), *(f"ovlm.{k}" for k in doc.get("ovlm", {}))})
    return hashlib.sha256(raw).hexdigest(), raw, keys


def policy_summary(policy: HostKeyPolicy) -> str:
    return policy.mode
