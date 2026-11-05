"""The worker's key ring: the KEK private key(s) and the only code that unwraps a DEK (security-model.md 5.1).

**Worker only.** :func:`load_keyring` refuses in any other process role, and the import-linter contract "the api
cannot decrypt" forbids ``ovlm.api``, ``ovlm.ui`` and the api side of ``ovlm.connections`` from importing this
module. The compose stack mounts the private key into the worker container only.

* The **current** key is the one new seals use (its public key is what the api is given); **previous** keys are
  kept during a rotation only to unwrap and re-wrap (:meth:`Keyring.rewrap`).
* A key file must be a PEM PKCS#8 X25519 private key, owned by the process user, without any group or other
  permission (``0400``/``0600``). It is read once at start; the key object stays in memory.
* :meth:`Keyring.unseal` returns a :class:`bytearray`: the caller converts what a client library needs and then
  calls :func:`wipe`. Python strings cannot be wiped; the residual is documented in ``docs/credential-store.md``.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ovlm.secrets.envelope import (
    ALG,
    DEK_BYTES,
    NONCE_BYTES,
    PUB_BYTES,
    WRAPPED_DEK_BYTES,
    EnvelopeError,
    PublicKek,
    SealContext,
    Sealed,
    data_aad,
    kek_id_of,
    raw_public,
    wrap_aad,
    wrapping_key,
)


class KeyringError(RuntimeError):
    """The key ring cannot be loaded or a value cannot be unsealed. Messages carry no secret material."""


class UnknownKekError(KeyringError):
    """The value was wrapped to a key this worker does not hold."""


def wipe(buf: bytearray | None) -> None:
    """Overwrite a buffer in place (best effort: copies made by libraries are out of reach)."""
    if buf is not None:
        buf[:] = b"\0" * len(buf)


@dataclass
class _Key:
    private: X25519PrivateKey = field(repr=False)
    public: X25519PublicKey = field(repr=False)
    kek_id: str


class Keyring:
    def __init__(
        self, current: X25519PrivateKey, previous: Sequence[X25519PrivateKey] = ()
    ) -> None:
        self._keys: dict[str, _Key] = {}
        self.current_kek_id = self._add(current)
        for key in previous:
            self._add(key)

    def __repr__(self) -> str:
        return f"Keyring(current={self.current_kek_id}, keys={sorted(self._keys)})"

    def _add(self, key: X25519PrivateKey) -> str:
        pub = key.public_key()
        kid = kek_id_of(pub)
        self._keys.setdefault(kid, _Key(key, pub, kid))
        return kid

    @property
    def kek_ids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def public(self) -> PublicKek:
        """The current public key (what the api must hold, and what re-wraps use)."""
        return PublicKek(self._keys[self.current_kek_id].public)

    def _unwrap(self, sealed: Sealed, context: SealContext) -> bytearray:
        if sealed.alg != ALG:
            raise KeyringError(f"unsupported sealed-secret format {sealed.alg!r}")
        key = self._keys.get(sealed.kek_id)
        if key is None:
            raise UnknownKekError(
                f"secret is wrapped to key {sealed.kek_id}, which this worker does not hold"
            )
        w = sealed.wrapped_dek
        if len(w) != WRAPPED_DEK_BYTES:
            raise KeyringError("malformed wrapped data key")
        eph_pub, nonce, body = (
            w[:PUB_BYTES],
            w[PUB_BYTES : PUB_BYTES + NONCE_BYTES],
            w[PUB_BYTES + NONCE_BYTES :],
        )
        try:
            shared = key.private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
            wkey = wrapping_key(shared, eph_pub, raw_public(key.public), key.kek_id)
            dek = bytearray(AESGCM(wkey).decrypt(nonce, body, wrap_aad(context, key.kek_id)))
        except (InvalidTag, ValueError):
            # wrong row/column/key, or tampered: deliberately one answer
            raise KeyringError("sealed secret does not authenticate for this row") from None
        if len(dek) != DEK_BYTES:
            wipe(dek)
            raise KeyringError("malformed data key")
        return dek

    def unseal(self, sealed: Sealed, context: SealContext) -> bytearray:
        """Decrypt in memory. The caller wipes the result (:func:`wipe`) after use."""
        dek = self._unwrap(sealed, context)
        try:
            if len(sealed.nonce) != NONCE_BYTES:
                raise KeyringError("malformed nonce")
            try:
                return bytearray(
                    AESGCM(bytes(dek)).decrypt(sealed.nonce, sealed.ciphertext, data_aad(context))
                )
            except InvalidTag:
                raise KeyringError("sealed secret does not authenticate for this row") from None
        finally:
            wipe(dek)

    def rewrap(self, sealed: Sealed, context: SealContext) -> Sealed:
        """The same secret, its DEK wrapped to the current key (KEK rotation). The secret ciphertext is unchanged;
        the DEK is checked against it before the new wrap is returned (a value that does not decrypt is refused)."""
        dek = self._unwrap(sealed, context)
        try:
            try:
                plain = bytearray(
                    AESGCM(bytes(dek)).decrypt(sealed.nonce, sealed.ciphertext, data_aad(context))
                )
            except InvalidTag:
                raise KeyringError("sealed secret does not authenticate for this row") from None
            wipe(plain)
            pub = self.public()
            return Sealed(
                pub.kek_id, pub.wrap_dek(bytes(dek), context), sealed.nonce, sealed.ciphertext
            )
        finally:
            wipe(dek)


def _read_private(path: Path, *, check_owner: bool = True) -> X25519PrivateKey:
    try:
        st = path.stat()
    except OSError as exc:
        raise KeyringError(
            f"cannot read KEK file {path}: {exc.strerror or type(exc).__name__}"
        ) from None
    if not stat.S_ISREG(st.st_mode):
        raise KeyringError(f"KEK file {path} is not a regular file")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise KeyringError(
            f"KEK file {path} must not grant any permission to group or others (mode 0400 or 0600)"
        )
    if check_owner and st.st_uid != os.geteuid():
        raise KeyringError(f"KEK file {path} must be owned by the worker user")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise KeyringError(
            f"cannot read KEK file {path}: {exc.strerror or type(exc).__name__}"
        ) from None
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        raise KeyringError(f"KEK file {path}: not an unencrypted PEM private key") from None
    finally:
        data = b""
    if not isinstance(key, X25519PrivateKey):
        raise KeyringError(f"KEK file {path}: must be an X25519 key")
    return key


def load_keyring(
    current: Path,
    previous: Sequence[Path] = (),
    *,
    process_role: str,
    check_owner: bool = True,
) -> Keyring:
    """The worker's key ring from its key files. Refused in any process but the worker."""
    if process_role != "worker":
        raise KeyringError(
            "the KEK private key is loaded only by the worker (security-model.md 5.1)"
        )
    return Keyring(
        _read_private(current, check_owner=check_owner),
        [_read_private(p, check_owner=check_owner) for p in previous],
    )


def generate_private_pem() -> bytes:
    """A new X25519 private key (PEM PKCS#8), for ``ovlm kek generate`` and tests."""
    return X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def public_pem_of(private_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, X25519PrivateKey):
        raise EnvelopeError("not an X25519 private key")
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
