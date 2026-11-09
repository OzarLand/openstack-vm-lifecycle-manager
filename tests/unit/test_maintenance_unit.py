"""``ovlm upgrade preflight``: the migration direction check against this release's real migration scripts."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic.script import ScriptDirectory

from ovlm.cli import main
from ovlm.db.schema import alembic_config
from ovlm.maintenance.checks import Finding, exit_code, migration_findings

ROOT = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def script() -> ScriptDirectory:
    return ScriptDirectory.from_config(alembic_config(ROOT / "migrations"))


def _codes(findings: list[Finding]) -> list[tuple[str, str]]:
    return [(f.level, f.code) for f in findings]


def test_empty_database_and_database_at_head_pass(script: ScriptDirectory) -> None:
    assert _codes(migration_findings(None, script)) == [("info", "fresh-database")]
    head = script.get_current_head()
    assert _codes(migration_findings(head, script)) == [("info", "schema-at-head")]


def test_an_older_revision_lists_the_pending_migrations_in_order(script: ScriptDirectory) -> None:
    (f,) = migration_findings("renewal_0003", script)
    assert (f.level, f.code) == ("info", "migrations-pending")
    assert f.message.endswith("renewal_0004, renewal_0005")
    assert exit_code([f]) == 0


@pytest.mark.parametrize("revision", ["zz_from_a_newer_release", "renewal_9999"])
def test_a_database_ahead_of_this_release_is_refused(
    script: ScriptDirectory, revision: str
) -> None:
    findings = migration_findings(revision, script)
    assert _codes(findings) == [("block", "database-ahead")]
    assert "Downgrades are not supported" in findings[0].message
    assert exit_code(findings) == 2


def test_finding_line_is_tab_separated() -> None:
    assert Finding("warn", "runs-active", "1 run").line() == "WARN\truns-active\t1 run"


@pytest.mark.parametrize(
    "argv",
    [
        ["upgrade"],
        ["upgrade", "downgrade"],
        ["backup"],
        ["upgrade", "preflight", "--role", "worker"],
    ],
)
def test_cli_refuses_unknown_actions_and_roles(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_cli_check_that_cannot_run_exits_1_never_0(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(tmp_path / "absent.toml"))
    monkeypatch.setenv("OVLM_DEVELOPMENT_MODE", "true")
    monkeypatch.setenv("OVLM_DB__HOST", "127.0.0.1")
    monkeypatch.setenv("OVLM_DB__PORT", "1")  # nothing listens
    monkeypatch.setenv("OVLM_MIGRATIONS_DIR", str(ROOT / "migrations"))
    assert main(["upgrade", "preflight"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error:") and "port 1 failed" in err
