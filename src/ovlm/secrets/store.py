"""The ``sealed_secret`` table (security-model.md 5.1). Holds only ciphertext and wrapped data keys.

* :func:`insert_sealed`: the api's only access to ciphertext columns (``INSERT``; it has no ``SELECT`` on them, so no
  ``RETURNING`` either).
* :func:`load_sealed`, :func:`store_rewrap`, :func:`rows_wrapped_to_other_keys`, :func:`delete_orphans`,
  :func:`announce_keys`: worker only (the ``ovlm_api`` role is refused by PostgreSQL).

**Binding (review CS-1, CS-2).** The AAD context of a credential's secret binds the ``credential_ref`` row **and** its
:class:`Destination`: the project connection id, the kind, the cloud id and :func:`endpoint_digest` of the cloud
endpoint (``auth_url``, region, interface, CA bundle) the secret was uploaded for. When the worker *uses* a secret it
builds the destination from the **live** connection and cloud rows, never from columns stored next to the
ciphertext; so a secret whose row was moved to another connection, or whose cloud now points elsewhere, does not
authenticate and is never sent anywhere. The api stores the same destination in ``credential_ref`` (immutable
columns) only to explain a refusal and to re-wrap during a KEK rotation (which sends nothing).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm.secrets.envelope import SealContext, Sealed

CREDENTIAL_CONTEXT_TABLE = "credential_ref"


def endpoint_digest(
    auth_url: str, region: str, interface: str, ca_bundle_sha256: str | None
) -> str:
    """SHA-256 (hex) of everything that decides **where** a credential's secret is sent: the Keystone URL (the token
    request), the region and interface (which catalog endpoints a token is then used against), and the CA bundle
    (whom TLS trusts). Canonical JSON, so the api and the worker compute the same value."""
    canon = json.dumps(
        {"v": 1, "auth_url": auth_url, "region": region, "interface": interface,
         "ca_bundle_sha256": ca_bundle_sha256},
        sort_keys=True, separators=(",", ":"),
    )  # fmt: skip
    return hashlib.sha256(canon.encode()).hexdigest()


@dataclass(frozen=True)
class Destination:
    """What a credential's secret is bound to (AAD binding)."""

    project_connection_id: str
    kind: str
    cloud_id: str
    endpoint_sha256: str

    def binding(self) -> tuple[str, ...]:
        return (
            f"pc={self.project_connection_id}",
            f"kind={self.kind}",
            f"cloud={self.cloud_id}",
            f"endpoint={self.endpoint_sha256}",
        )


def credential_context(credential_id: UUID | str, destination: Destination) -> SealContext:
    return SealContext(
        CREDENTIAL_CONTEXT_TABLE, str(credential_id), "secret", destination.binding()
    )


def insert_sealed(db: Session | Connection, secret_id: UUID, sealed: Sealed) -> None:
    db.execute(
        text(
            "INSERT INTO sealed_secret (id, alg, kek_id, wrapped_dek, nonce, ciphertext) "
            "VALUES (:i, :a, :k, :w, :n, :c)"
        ),
        {"i": secret_id, "a": sealed.alg, "k": sealed.kek_id, "w": sealed.wrapped_dek,
         "n": sealed.nonce, "c": sealed.ciphertext},
    )  # fmt: skip


def _sealed(row: Any) -> Sealed:
    return Sealed(
        row.kek_id, bytes(row.wrapped_dek), bytes(row.nonce), bytes(row.ciphertext), row.alg
    )


def load_sealed(db: Session | Connection, secret_id: UUID) -> Sealed | None:
    row = db.execute(
        text("SELECT alg, kek_id, wrapped_dek, nonce, ciphertext FROM sealed_secret WHERE id = :i"),
        {"i": secret_id},
    ).one_or_none()
    return _sealed(row) if row else None


def rows_wrapped_to_other_keys(
    db: Session | Connection, current_kek_id: str, limit: int = 100
) -> list[tuple[UUID, Destination, UUID, Sealed]]:
    """``(credential id, stored destination, secret id, sealed)`` of credentials whose DEK is not wrapped to the
    current key. The stored destination is right here: a re-wrap decrypts nothing out of the worker and sends
    nothing; it keeps the binding unchanged."""
    rows = db.execute(
        text(
            "SELECT r.id AS cred_id, r.project_connection_id, r.kind, r.cloud_id, r.endpoint_sha256, "
            "s.id AS secret_id, s.alg, s.kek_id, s.wrapped_dek, s.nonce, s.ciphertext "
            "FROM sealed_secret s JOIN credential_ref r ON r.secret_id = s.id "
            "WHERE s.kek_id <> :k ORDER BY s.created_at, s.id LIMIT :l FOR UPDATE OF s SKIP LOCKED"
        ),
        {"k": current_kek_id, "l": limit},
    ).all()
    return [
        (
            r.cred_id,
            Destination(str(r.project_connection_id), r.kind, str(r.cloud_id), r.endpoint_sha256),
            r.secret_id,
            _sealed(r),
        )
        for r in rows
    ]


def store_rewrap(
    db: Session | Connection, secret_id: UUID, old_kek_id: str, sealed: Sealed
) -> bool:
    """Replace the wrapped DEK (the ciphertext is unchanged). Compare-and-set on the old key id."""
    n = db.execute(
        text(
            "UPDATE sealed_secret SET kek_id = :k, wrapped_dek = :w, rewrapped_at = now() "
            "WHERE id = :i AND kek_id = :old"
        ),
        {"k": sealed.kek_id, "w": sealed.wrapped_dek, "i": secret_id, "old": old_kek_id},
    ).rowcount  # type: ignore[attr-defined]
    return bool(n == 1)


def kek_usage(db: Session | Connection) -> dict[str, int]:
    """Number of sealed secrets **in use** (referenced by a credential) per key id: tells when an old key may be
    removed. Orphans (review CS-9) are counted by :func:`orphan_count` and removed by :func:`delete_orphans`."""
    return {
        r.kek_id: int(r.n)
        for r in db.execute(
            text(
                "SELECT s.kek_id, count(*) AS n FROM sealed_secret s "
                "WHERE EXISTS (SELECT 1 FROM credential_ref r WHERE r.secret_id = s.id) GROUP BY s.kek_id"
            )
        )
    }


_ORPHANS = (
    "FROM sealed_secret s WHERE NOT EXISTS (SELECT 1 FROM credential_ref r WHERE r.secret_id = s.id) "
    "AND s.created_at < now() - interval '10 minutes'"
)


def orphan_count(db: Session | Connection) -> int:
    return int(db.execute(text(f"SELECT count(*) {_ORPHANS}")).scalar_one())  # noqa: S608


def delete_orphans(db: Session | Connection) -> int:
    """Delete sealed secrets no credential refers to (left by a database actor; the api deletes both rows). The api
    inserts both rows in one transaction, and the 10-minute margin leaves any in-flight insert alone."""
    return int(
        db.execute(text(f"DELETE {_ORPHANS}")).rowcount  # type: ignore[attr-defined]  # noqa: S608
    )


# --- key announcement (review CS-5, CS-10) ---------------------------------------------------------------------


def announce_keys(db: Session | Connection, current: str, held: Iterable[str]) -> None:
    """The worker publishes the key ids it holds (``kek_key``), so the api seals only to a key the worker can open
    ("worker first" rotation, enforced)."""
    ids = sorted(set(held) | {current})
    db.execute(text("DELETE FROM kek_key WHERE NOT (kek_id = ANY(:ids))"), {"ids": ids})
    for kid in ids:
        db.execute(
            text(
                "INSERT INTO kek_key (kek_id, is_current, announced_at) VALUES (:k, :c, now()) "
                "ON CONFLICT (kek_id) DO UPDATE SET is_current = EXCLUDED.is_current, announced_at = now()"
            ),
            {"k": kid, "c": kid == current},
        )


def announced_keys(db: Session | Connection) -> frozenset[str]:
    return frozenset(db.execute(text("SELECT kek_id FROM kek_key")).scalars())
