"""Architecture rule: the api process never imports OpenStack/automation/worker code (architecture.md s.3)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

SRC = Path(__file__).parents[2] / "src" / "ovlm"
FORBIDDEN = (
    "openstack",
    "openstacksdk",
    "keystoneauth1",
    "ansible_runner",
    "ovlm.openstack",
    "ovlm.automation",
    "ovlm.worker",
)


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            found.update(f"{node.module}.{a.name}" for a in node.names)
    return found


def _violations(package: str) -> list[str]:
    bad = []
    for path in (SRC / package).rglob("*.py"):
        for name in _imports(path):
            if any(name == f or name.startswith(f + ".") for f in FORBIDDEN):
                bad.append(f"{path.relative_to(SRC)} imports {name}")
    return bad


def test_api_and_ui_do_not_import_outbound_code() -> None:
    assert _violations("api") == []
    assert _violations("ui") == []


def test_config_imports_no_other_ovlm_module() -> None:
    for path in (SRC / "config").rglob("*.py"):
        others = {
            n for n in _imports(path) if n.startswith("ovlm.") and not n.startswith("ovlm.config")
        }
        assert not others, f"{path.name} imports {others}"


def test_importing_the_api_app_loads_no_outbound_module() -> None:
    import subprocess

    code = (
        "import sys; import ovlm.api.app; "
        "bad=[m for m in sys.modules if m.split('.')[0] in ('openstack','ansible_runner','keystoneauth1') "
        "or m in ('ovlm.openstack','ovlm.automation','ovlm.worker')]; "
        "print(bad); sys.exit(1 if bad else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_api_loads_no_sync_job_scan_job_or_unsealing_code() -> None:
    """The api only queues inventory syncs and host-key scans: the worker-side jobs (OpenStack read client, the
    credential store's unsealing, ssh-keyscan) never load in the api process."""
    import subprocess

    worker_only = (
        "ovlm.inventory.job", "ovlm.inventory.sync", "ovlm.registry.host_key_scan", "ovlm.connections.credentials",
        "ovlm.connections.validation", "ovlm.secrets.keyring", "ovlm.renewal.production",
    )  # fmt: skip
    code = (
        "import sys; import ovlm.api.app; "
        f"bad=[m for m in {worker_only!r} if m in sys.modules]; print(bad); sys.exit(1 if bad else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
