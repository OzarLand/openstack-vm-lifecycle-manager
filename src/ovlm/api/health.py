"""Readiness probing for the api: DB reachable and schema at head."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sqlalchemy import Engine, text

from ovlm.db.schema import SchemaNotAtHeadError, check_schema_at_head


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


class ReadinessProbe(Protocol):
    def check(self) -> list[CheckResult]: ...


class DbReadinessProbe:
    def __init__(self, engine: Engine, migrations_dir: Path) -> None:
        self._engine = engine
        self._migrations_dir = migrations_dir

    def check(self) -> list[CheckResult]:
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001 - report, never raise from a probe
            return [CheckResult("database", False, "database unreachable")]
        results = [CheckResult("database", True)]
        try:
            check_schema_at_head(self._engine, self._migrations_dir)
            results.append(CheckResult("schema", True))
        except SchemaNotAtHeadError as exc:
            results.append(CheckResult("schema", False, str(exc)))
        except Exception:  # noqa: BLE001
            results.append(CheckResult("schema", False, "schema check failed"))
        return results
