"""Readiness probing for the api: DB reachable, schema at head and, when the api holds the worker's public key, the
key the api seals to is one the worker announced (review CS-10, roadmap SF-6)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sqlalchemy import Connection, Engine, text

from ovlm.db.schema import SchemaNotAtHeadError, check_schema_at_head
from ovlm.secrets.envelope import EnvelopeError, load_public_key

log = logging.getLogger(__name__)

#: The readiness detail of a KEK mismatch. It names no key id: ``/readyz`` is unauthenticated, and the ids are
#: in the api's log and in ``ovlm kek status``.
KEK_MISMATCH = (
    "kek mismatch: the api seals to a public key the worker has not announced; credential uploads are refused "
    "(see the api log and ovlm kek status)"
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str = ""


class ReadinessProbe(Protocol):
    def check(self) -> list[CheckResult]: ...


@dataclass(frozen=True)
class KekState:
    """The outcome of :func:`kek_check`: the readiness result, and what the api logs about it (ids included)."""

    result: CheckResult
    note: str = ""
    api_kek_id: str | None = None
    worker_kek_ids: tuple[str, ...] = ()


def kek_check(conn: Connection, public_key_file: Path) -> KekState:
    """Compare the api's public key with the key ids the worker announced (``kek_key``).

    Only fingerprints are compared: the key id is the first 16 hex characters of SHA-256 over the **public** key, and
    the api holds no private key. Outcomes:

    * the api's key is announced: ready (a key the worker holds but no longer uses as current is the middle of a
      "worker first" rotation: ready, noted);
    * the worker announced keys and the api's is not among them: **not ready** (every upload would be refused with
      ``credential-store-key-unknown``, and a secret sealed to that key could not be opened by the worker);
    * the worker has not announced any key yet (not started, or no KEK configured): ready, noted; nothing can be
      sealed until it does, and the upload route says so;
    * the public key file cannot be read or parsed: not ready.
    """
    try:
        api_kek = load_public_key(public_key_file).kek_id
    except EnvelopeError:
        return KekState(CheckResult("kek", False, "kek: the api's public key cannot be read"),
                        "the api's public key cannot be read")  # fmt: skip
    rows = conn.execute(text("SELECT kek_id, is_current FROM kek_key")).all()
    announced = {str(r.kek_id): bool(r.is_current) for r in rows}
    held = tuple(sorted(announced))
    if not announced:
        return KekState(
            CheckResult("kek", True), "the worker has not announced its key ids yet", api_kek
        )
    if api_kek not in announced:
        return KekState(CheckResult("kek", False, KEK_MISMATCH),
                        "kek mismatch: the api's public key is not one the worker holds", api_kek, held)  # fmt: skip
    if not announced[api_kek]:
        return KekState(CheckResult("kek", True),
                        "the api seals to a key the worker holds but no longer uses as current: finish the rotation",
                        api_kek, held)  # fmt: skip
    return KekState(CheckResult("kek", True), "", api_kek, held)


class DbReadinessProbe:
    def __init__(
        self, engine: Engine, migrations_dir: Path, *, public_key_file: Path | None = None
    ) -> None:
        self._engine = engine
        self._migrations_dir = migrations_dir
        self._public_key_file = public_key_file
        self._last_note: str | None = (
            None  # log a KEK note once per change, not at every health check
        )

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
            return results  # the key table may not exist yet
        except Exception:  # noqa: BLE001
            results.append(CheckResult("schema", False, "schema check failed"))
            return results
        if self._public_key_file is not None:
            try:
                with self._engine.connect() as conn:
                    state = kek_check(conn, self._public_key_file)
            except Exception:  # noqa: BLE001
                results.append(CheckResult("kek", False, "kek check failed"))
                return results
            if state.note != self._last_note:
                self._last_note = state.note
                if state.note:
                    log.log(logging.WARNING if state.result.ok else logging.ERROR, state.note,
                            extra={"api_kek_id": state.api_kek_id, "worker_kek_ids": list(state.worker_kek_ids)})  # fmt: skip
            results.append(state.result)
        return results
