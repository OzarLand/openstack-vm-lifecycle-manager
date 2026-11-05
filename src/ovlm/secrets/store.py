"""The ``sealed_secret`` table (security-model.md 5.1). Holds only ciphertext and wrapped data keys.

* :func:`insert_sealed`: the api's only access to ciphertext columns (``INSERT``; it has no ``SELECT`` on them, so no
  ``RETURNING`` either).
* :func:`load_sealed`, :func:`store_rewrap`, :func:`rows_wrapped_to_other_keys`: worker only (the ``ovlm_api`` role
  is refused by PostgreSQL).

The AAD context of a credential's secret is always derived from the **referencing** ``credential_ref`` row
(:func:`credential_context`), never from anything stored next to the ciphertext: a sealed value moved to another
row does not authenticate.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import Connection, text
from sqlalchemy.orm import Session

from ovlm.secrets.envelope import SealContext, Sealed

CREDENTIAL_CONTEXT_TABLE = "credential_ref"


def credential_context(credential_id: UUID | str) -> SealContext:
    return SealContext(CREDENTIAL_CONTEXT_TABLE, str(credential_id), "secret")


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
) -> list[tuple[UUID, UUID, Sealed]]:
    """``(credential id, secret id, sealed)`` of credentials whose DEK is not wrapped to the current key."""
    rows = db.execute(
        text(
            "SELECT r.id AS cred_id, s.id AS secret_id, s.alg, s.kek_id, s.wrapped_dek, s.nonce, s.ciphertext "
            "FROM sealed_secret s JOIN credential_ref r ON r.secret_id = s.id "
            "WHERE s.kek_id <> :k ORDER BY s.created_at, s.id LIMIT :l FOR UPDATE OF s SKIP LOCKED"
        ),
        {"k": current_kek_id, "l": limit},
    ).all()
    return [(r.cred_id, r.secret_id, _sealed(r)) for r in rows]


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
    """Number of sealed secrets per key id (to tell when an old key may be removed)."""
    return {
        r.kek_id: int(r.n)
        for r in db.execute(text("SELECT kek_id, count(*) AS n FROM sealed_secret GROUP BY kek_id"))
    }
