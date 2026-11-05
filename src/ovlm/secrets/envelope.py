"""Envelope encryption, sealing side (security-model.md 5.1). Safe to import in the api: it holds **no private key**
and has no function that decrypts.

Format (``ALG`` = ``ovlm-env-v2``)
---------------------------------

* **Data key (DEK)**: 32 random bytes per secret. The secret is encrypted with AES-256-GCM under the DEK, 12-byte
  random nonce, AAD = ``data_aad(context)`` = ``b"ovlm-data-v2|" + context.aad()`` where ``context.aad()`` is
  ``table|row_id|column`` followed by the context's **binding** (``|b1|b2...``). For a credential the binding is the
  project connection id, the kind, the cloud id and the SHA-256 of the endpoint the secret may be sent to
  (:mod:`ovlm.secrets.store`), so the ciphertext cannot be moved to another row, column, connection, cloud or
  endpoint (review CS-1, CS-2).
* **Key wrapping**: the DEK is sealed to the worker's X25519 public key (the KEK pair): an ephemeral X25519 key pair,
  ECDH with the worker public key, HKDF-SHA256 (salt = ephemeral public || worker public, info = ``wrap_info``) to a
  32-byte wrapping key, then AES-256-GCM of the DEK with AAD = ``wrap_aad(context, kek_id)`` =
  ``b"ovlm-wrap-v2|" + context.aad() + b"|" + kek_id``. ``wrapped_dek`` = ephemeral public (32) || nonce (12) ||
  ciphertext+tag (48).

Why the ``kek_id`` sits in the wrap AAD and not in the data AAD: security-model.md 5.1 lists ``kek_id`` in the AAD and
also says that KEK rotation re-wraps the DEKs while "secrets themselves [stay] unchanged". Both hold only if the
``kek_id`` binds the wrapping, so it is there; the DEK opens only for the full context *and* that key id, and the
data AAD binds the full context again (reported reading).

``ovlm-env-v1`` (no binding beyond the row) is no longer produced and is refused by the worker: such a secret must be
uploaded again (migration ``connections_0002`` rejects the credentials that still use it).

``kek_id`` = first 16 hex characters of SHA-256 over the raw 32-byte public key: it names the key pair and is not
secret. The api only ever needs the public key (:func:`load_public_key`).
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALG = "ovlm-env-v2"
#: The previous format (AAD bound to the row only, review CS-1/CS-2): refused when unsealing.
LEGACY_ALGS = frozenset({"ovlm-env-v1"})
DEK_BYTES = 32
NONCE_BYTES = 12
PUB_BYTES = 32
WRAPPED_DEK_BYTES = PUB_BYTES + NONCE_BYTES + DEK_BYTES + 16
#: Largest secret accepted (an application credential secret is ~86 characters; an SSH private key a few KiB).
MAX_PLAINTEXT_BYTES = 16 * 1024

_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class EnvelopeError(ValueError):
    """Malformed key, context or sealed value. Messages never contain secret material."""


@dataclass(frozen=True)
class SealContext:
    """Where the sealed value belongs and what it is bound to: ``table|row_id|column|binding...`` (security-model.md
    5.1 AAD). ``binding`` is a tuple of plain values (ids, kinds, digests) a sealed value only authenticates with."""

    table: str
    row_id: str
    column: str
    binding: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not (_IDENT.match(self.table) and _IDENT.match(self.column)):
            raise EnvelopeError("seal context: table and column must be identifiers")
        if not self.row_id or "|" in self.row_id or len(self.row_id) > 64:
            raise EnvelopeError("seal context: invalid row id")
        if any(not b or "|" in b or len(b) > 128 for b in self.binding):
            raise EnvelopeError("seal context: invalid binding value")

    def aad(self) -> bytes:
        return "|".join((self.table, self.row_id, self.column, *self.binding)).encode()


def data_aad(context: SealContext) -> bytes:
    return b"ovlm-data-v2|" + context.aad()


def wrap_aad(context: SealContext, kek_id: str) -> bytes:
    return b"ovlm-wrap-v2|" + context.aad() + b"|" + kek_id.encode()


def wrap_info(kek_id: str) -> bytes:
    return b"ovlm-kek-wrap-v1|" + kek_id.encode()


def raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kek_id_of(key: X25519PublicKey) -> str:
    return hashlib.sha256(raw_public(key)).hexdigest()[:16]


def wrapping_key(shared: bytes, eph_pub: bytes, kek_pub: bytes, kek_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=eph_pub + kek_pub, info=wrap_info(kek_id)
    ).derive(shared)


@dataclass(frozen=True)
class Sealed:
    """A sealed secret as stored (table ``sealed_secret``). Nothing here is secret without the KEK private key."""

    kek_id: str
    wrapped_dek: bytes
    nonce: bytes
    ciphertext: bytes
    alg: str = ALG

    def __repr__(self) -> str:  # short, and never the bytes
        return (
            f"Sealed(alg={self.alg}, kek_id={self.kek_id}, ciphertext={len(self.ciphertext)} bytes)"
        )


@dataclass(frozen=True)
class PublicKek:
    """The worker's public key: what the api holds to seal."""

    key: X25519PublicKey

    @property
    def kek_id(self) -> str:
        return kek_id_of(self.key)

    def wrap_dek(self, dek: bytes, context: SealContext) -> bytes:
        kek_pub = raw_public(self.key)
        eph = X25519PrivateKey.generate()
        eph_pub = raw_public(eph.public_key())
        wkey = wrapping_key(eph.exchange(self.key), eph_pub, kek_pub, self.kek_id)
        nonce = os.urandom(NONCE_BYTES)
        return eph_pub + nonce + AESGCM(wkey).encrypt(nonce, dek, wrap_aad(context, self.kek_id))

    def seal(self, plaintext: bytes | bytearray, context: SealContext) -> Sealed:
        """Encrypt ``plaintext`` under a fresh DEK and wrap the DEK to this key. The DEK is dropped afterwards."""
        if not plaintext:
            raise EnvelopeError("refusing to seal an empty secret")
        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise EnvelopeError(f"secret larger than {MAX_PLAINTEXT_BYTES} bytes")
        dek = bytearray(os.urandom(DEK_BYTES))
        try:
            nonce = os.urandom(NONCE_BYTES)
            ciphertext = AESGCM(bytes(dek)).encrypt(nonce, bytes(plaintext), data_aad(context))
            wrapped = self.wrap_dek(bytes(dek), context)
        finally:
            dek[:] = b"\0" * DEK_BYTES
        return Sealed(self.kek_id, wrapped, nonce, ciphertext)


def parse_public_key(data: bytes) -> PublicKek:
    """An X25519 public key in PEM (SubjectPublicKeyInfo, ``openssl pkey -pubout``)."""
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        raise EnvelopeError("KEK public key: not a PEM public key") from None
    if not isinstance(key, X25519PublicKey):
        raise EnvelopeError("KEK public key: must be an X25519 key")
    return PublicKek(key)


def load_public_key(path: Path) -> PublicKek:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise EnvelopeError(
            f"cannot read KEK public key {path}: {exc.strerror or type(exc).__name__}"
        ) from None
    return parse_public_key(data)
