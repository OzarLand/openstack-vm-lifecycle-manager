"""``ovlm inventory sync`` dry run (no database, no cloud: the fake stands in for the SDK client)."""

from __future__ import annotations

import json
import uuid

import pytest

from ovlm import cli
from ovlm.inventory.cli import project_connection_id_for, sync_command
from ovlm.openstack.fake import FakeOpenStack


def test_dry_run_reads_everything_and_reports_counts_only() -> None:
    fake = FakeOpenStack()
    fake.add_server("secret-looking-name")
    fake.add_image()
    code, out = sync_command(fake, cloud="lab", engine=None)
    assert code == 0 and out["dry_run"] is True and out["status"] == "read_ok"
    assert out["counts"] == {
        "server": 1, "volume": 0, "volume_attachment": 0, "port": 0, "floating_ip": 0,
        "network": 0, "image": 1, "flavor": 0,
    }  # fmt: skip
    assert out["versions"]["compute_used"] == "2.100"  # type: ignore[index]
    assert "secret-looking-name" not in json.dumps(out)  # counts only


def test_dry_run_issues_no_write() -> None:
    fake = FakeOpenStack(role="reader")  # a reader credential: any mutating call would raise
    sync_command(fake, cloud="lab", engine=None)
    assert set(fake.calls) <= {
        "list_servers", "list_volumes", "list_ports", "list_floating_ips", "list_networks", "list_images",
        "list_flavors",
    }  # fmt: skip


def test_project_connection_id_is_stable_and_cloud_specific() -> None:
    a = project_connection_id_for("lab", "p1")
    assert a == project_connection_id_for("lab", "p1") and isinstance(a, uuid.UUID)
    assert a != project_connection_id_for("other", "p1") != project_connection_id_for("lab", "p2")


def test_main_dispatches_inventory_and_reports_a_bad_cloud(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["inventory", "sync", "--cloud", "no-such-cloud-xyz", "--dry-run"]) == 1
    capsys.readouterr()
