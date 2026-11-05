"""Envelope encryption of the credential store (security-model.md 5.1, 10 item 13): round trip, AAD binding,
tampering, key rotation, the worker-only key ring, and the api's inability to decrypt."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ovlm.config import Settings
from ovlm.secrets.cli import kek_status_code
from ovlm.secrets.envelope import (
    ALG,
    WRAPPED_DEK_BYTES,
    EnvelopeError,
    PublicKek,
    SealContext,
    load_public_key,
    parse_public_key,
)
from ovlm.secrets.keyring import (
    Keyring,
    KeyringError,
    UnknownKekError,
    generate_private_pem,
    load_keyring,
    public_pem_of,
    wipe,
)
from ovlm.secrets.store import Destination, credential_context, endpoint_digest

ROOT = Path(__file__).parents[2]
CANARY = b"ovlm-canary-3f9a1c7e-app-credential-secret"
PC, CLOUD = "0190f1e2-0000-7000-8000-0000000000aa", "0190f1e2-0000-7000-8000-0000000000bb"
ENDPOINT = endpoint_digest("https://keystone.test/v3", "R1", "public", None)
DEST = Destination(PC, "os_write", CLOUD, ENDPOINT)
CTX = credential_context("0190f1e2-0000-7000-8000-000000000001", DEST)


def _ring() -> Keyring:
    return Keyring(X25519PrivateKey.generate())


def test_round_trip_and_format() -> None:
    ring = _ring()
    sealed = ring.public().seal(CANARY, CTX)
    assert sealed.alg == ALG and sealed.kek_id == ring.current_kek_id and len(sealed.kek_id) == 16
    assert len(sealed.wrapped_dek) == WRAPPED_DEK_BYTES and len(sealed.nonce) == 12
    assert CANARY not in sealed.ciphertext and CANARY not in sealed.wrapped_dek
    assert "canary" not in repr(sealed) and str(len(sealed.ciphertext)) in repr(sealed)
    out = ring.unseal(sealed, CTX)
    assert isinstance(out, bytearray) and bytes(out) == CANARY
    wipe(out)
    assert out == bytearray(len(CANARY))


def test_each_secret_has_its_own_data_key() -> None:
    pub = _ring().public()
    a, b = pub.seal(CANARY, CTX), pub.seal(CANARY, CTX)
    assert a.ciphertext != b.ciphertext and a.wrapped_dek != b.wrapped_dek and a.nonce != b.nonce


@pytest.mark.parametrize(
    "other",
    [
        credential_context("0190f1e2-0000-7000-8000-000000000002", DEST),  # another row
        SealContext(
            "credential_ref", "0190f1e2-0000-7000-8000-000000000001", "other"
        ),  # another column
        SealContext(
            "other_table", "0190f1e2-0000-7000-8000-000000000001", "secret"
        ),  # another table
    ],
)
def test_ciphertext_cannot_move_to_another_row_column_or_table(other: SealContext) -> None:
    ring = _ring()
    sealed = ring.public().seal(CANARY, CTX)
    with pytest.raises(KeyringError, match="does not authenticate"):
        ring.unseal(sealed, other)


_ROW = "0190f1e2-0000-7000-8000-000000000001"


@pytest.mark.parametrize(
    "other",
    [
        Destination(
            "0190f1e2-0000-7000-8000-0000000000cc", "os_write", CLOUD, ENDPOINT
        ),  # rebound (CS-2)
        Destination(PC, "os_read", CLOUD, ENDPOINT),  # another kind
        Destination(
            PC, "os_write", "0190f1e2-0000-7000-8000-0000000000dd", ENDPOINT
        ),  # moved to another cloud
        Destination(
            PC,
            "os_write",
            CLOUD,
            endpoint_digest("https://attacker.example/v3", "R1", "public", None),
        ),
        Destination(
            PC, "os_write", CLOUD, endpoint_digest("https://keystone.test/v3", "R2", "public", None)
        ),
        Destination(
            PC,
            "os_write",
            CLOUD,
            endpoint_digest("https://keystone.test/v3", "R1", "internal", None),
        ),
        Destination(
            PC,
            "os_write",
            CLOUD,
            endpoint_digest("https://keystone.test/v3", "R1", "public", "a" * 64),
        ),
    ],
)
def test_cs1_cs2_ciphertext_is_bound_to_connection_kind_cloud_and_endpoint(
    other: Destination,
) -> None:
    """Review CS-1/CS-2: the same row id under another connection, kind, cloud or endpoint does not decrypt (neither
    the wrapped data key nor the data), so the worker can never be made to send the secret elsewhere."""
    ring = _ring()
    sealed = ring.public().seal(CANARY, CTX)
    with pytest.raises(KeyringError, match="does not authenticate"):
        ring.unseal(sealed, credential_context(_ROW, other))
    with pytest.raises(KeyringError):
        ring.rewrap(sealed, credential_context(_ROW, other))
    assert bytes(ring.unseal(sealed, credential_context(_ROW, DEST))) == CANARY


def test_endpoint_digest_is_canonical_and_covers_every_endpoint_field() -> None:
    base = ("https://keystone.test/v3", "R1", "public", None)
    assert endpoint_digest(*base) == ENDPOINT and len(ENDPOINT) == 64
    variants = {endpoint_digest(*v) for v in [
        base, ("https://keystone.test/v3/", "R1", "public", None), ("https://keystone.test/v3", "R1 ", "public", None),
        ("https://keystone.test/v3", "R1", "internal", None), ("https://keystone.test/v3", "R1", "public", "0" * 64),
    ]}  # fmt: skip
    assert len(variants) == 5
    with pytest.raises(EnvelopeError):
        SealContext("credential_ref", _ROW, "secret", ("a|b",))


def test_retired_unbound_format_is_refused() -> None:
    sealed = _ring().public().seal(CANARY, CTX)
    with pytest.raises(KeyringError, match="retired format"):
        _ring().unseal(replace(sealed, alg="ovlm-env-v1"), CTX)


def test_cs9_kek_status_is_zero_only_when_everything_is_on_the_current_key() -> None:
    held = frozenset({"cur", "old"})
    assert kek_status_code({"cur": 3}, "cur", held) == 0
    assert kek_status_code({"cur": 3, "old": 0}, "cur", held) == 0
    assert (
        kek_status_code({"cur": 3, "old": 1}, "cur", held) == 3
    )  # re-wrap not finished: keep the old key
    assert kek_status_code({"gone": 1}, "cur", held) == 2


@pytest.mark.parametrize("field", ["wrapped_dek", "nonce", "ciphertext"])
def test_tampering_is_detected(field: str) -> None:
    ring = _ring()
    sealed = ring.public().seal(CANARY, CTX)
    raw = bytearray(getattr(sealed, field))
    raw[-1] ^= 1
    with pytest.raises(KeyringError):
        ring.unseal(replace(sealed, **{field: bytes(raw)}), CTX)  # type: ignore[arg-type]


def test_kek_id_is_bound_to_the_wrap() -> None:
    """Relabelling a wrapped key with another key id fails (the key id is in the wrap AAD)."""
    ring_a = _ring()
    ring_b = Keyring(X25519PrivateKey.generate(), [ring_a._keys[ring_a.current_kek_id].private])  # noqa: SLF001
    sealed = ring_a.public().seal(CANARY, CTX)
    with pytest.raises(KeyringError):
        ring_b.unseal(replace(sealed, kek_id=ring_b.current_kek_id), CTX)
    assert bytes(ring_b.unseal(sealed, CTX)) == CANARY


def test_unknown_key_and_format_are_refused() -> None:
    sealed = _ring().public().seal(CANARY, CTX)
    with pytest.raises(UnknownKekError):
        _ring().unseal(sealed, CTX)
    with pytest.raises(KeyringError, match="format"):
        _ring().unseal(replace(sealed, alg="other"), CTX)


def test_seal_refuses_empty_and_oversized() -> None:
    pub = _ring().public()
    with pytest.raises(EnvelopeError):
        pub.seal(b"", CTX)
    with pytest.raises(EnvelopeError):
        pub.seal(b"x" * 20000, CTX)
    with pytest.raises(EnvelopeError):
        SealContext("credential_ref", "a|b", "secret")


def test_kek_rotation_rewraps_without_touching_the_ciphertext() -> None:
    old = X25519PrivateKey.generate()
    sealed = Keyring(old).public().seal(CANARY, CTX)
    rotating = Keyring(X25519PrivateKey.generate(), [old])
    new = rotating.rewrap(sealed, CTX)
    assert new.kek_id == rotating.current_kek_id != sealed.kek_id
    assert new.ciphertext == sealed.ciphertext and new.nonce == sealed.nonce
    # the old key removed after the verified pass: everything still decrypts with the new key alone
    after = Keyring(rotating._keys[rotating.current_kek_id].private)  # noqa: SLF001
    assert bytes(after.unseal(new, CTX)) == CANARY
    with pytest.raises(UnknownKekError):
        after.unseal(sealed, CTX)


def test_rewrap_refuses_a_value_that_does_not_decrypt() -> None:
    old = X25519PrivateKey.generate()
    sealed = Keyring(old).public().seal(CANARY, CTX)
    bad = replace(sealed, ciphertext=sealed.ciphertext[:-1] + bytes([sealed.ciphertext[-1] ^ 1]))
    with pytest.raises(KeyringError):
        Keyring(X25519PrivateKey.generate(), [old]).rewrap(bad, CTX)


# --- key files ----------------------------------------------------------------------------------------------------


def _key_files(tmp_path: Path, mode: int = 0o400) -> tuple[Path, Path]:
    priv, pub = tmp_path / "kek", tmp_path / "kek.pub"
    pem = generate_private_pem()
    priv.write_bytes(pem)
    priv.chmod(mode)
    pub.write_bytes(public_pem_of(pem))
    return priv, pub


def test_worker_loads_its_key_and_the_api_public_key_matches(tmp_path: Path) -> None:
    priv, pub = _key_files(tmp_path)
    ring = load_keyring(priv, process_role="worker")
    api_side = load_public_key(pub)
    assert api_side.kek_id == ring.current_kek_id
    assert bytes(ring.unseal(api_side.seal(CANARY, CTX), CTX)) == CANARY
    assert "PRIVATE" not in repr(ring)


@pytest.mark.parametrize("role", ["api", "migrate"])
def test_only_the_worker_may_load_the_private_key(tmp_path: Path, role: str) -> None:
    priv, _ = _key_files(tmp_path)
    with pytest.raises(KeyringError, match="only by the worker"):
        load_keyring(priv, process_role=role)


@pytest.mark.parametrize("mode", [0o440, 0o404, 0o644])
def test_key_file_readable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    priv, _ = _key_files(tmp_path, mode)
    with pytest.raises(KeyringError, match="group or others"):
        load_keyring(priv, process_role="worker")


def test_key_file_must_be_x25519_and_owned_by_the_worker(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other = tmp_path / "ed"
    other.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    other.chmod(0o400)
    with pytest.raises(KeyringError, match="X25519"):
        load_keyring(other, process_role="worker")
    if os.geteuid() == 0:  # only root can hand the file to another owner
        priv, _ = _key_files(tmp_path)
        os.chown(priv, 12345, -1)
        with pytest.raises(KeyringError, match="owned by the worker"):
            load_keyring(priv, process_role="worker")


def test_public_key_must_be_x25519(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pem = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(EnvelopeError):
        parse_public_key(pem)
    with pytest.raises(EnvelopeError):
        load_public_key(tmp_path / "missing.pub")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_keys_from_make_secrets_openssl_commands_interoperate(tmp_path: Path) -> None:
    """``make secrets`` generates the pair with openssl: the worker and the api must load it."""
    priv, pub = tmp_path / "worker_kek", tmp_path / "worker_kek.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-out", str(priv)], check=True)  # noqa: S603, S607
    subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True)  # noqa: S603, S607
    priv.chmod(0o400)
    ring = load_keyring(priv, process_role="worker")
    assert load_public_key(pub).kek_id == ring.current_kek_id


def test_kek_cli_generate_never_overwrites(tmp_path: Path) -> None:
    from ovlm.secrets.cli import main

    priv, pub = tmp_path / "k", tmp_path / "k.pub"
    assert main(["generate", "--private-out", str(priv), "--public-out", str(pub)]) == 0
    assert oct(priv.stat().st_mode & 0o777) == "0o400"
    first = priv.read_bytes()
    assert main(["generate", "--private-out", str(priv), "--public-out", str(pub)]) == 1
    assert priv.read_bytes() == first
    assert load_public_key(pub).kek_id == load_keyring(priv, process_role="worker").current_kek_id


# --- settings -----------------------------------------------------------------------------------------------------


def test_settings_refuse_a_private_key_outside_the_worker(tmp_path: Path) -> None:
    priv, pub = _key_files(tmp_path)
    for role in ("api", "migrate"):
        with pytest.raises(ValueError, match="only the worker"):
            Settings(process_role=role, development_mode=True, kek={"private_key_file": priv})
    api = Settings(process_role="api", development_mode=True, kek={"public_key_file": pub})
    assert api.kek.public_key_file == pub
    worker = Settings(
        process_role="worker", development_mode=True,
        kek={"private_key_file": priv, "previous_private_key_files": [priv]},
    )  # fmt: skip
    assert worker.kek.previous_private_key_files == (priv,)
    with pytest.raises(ValueError, match="absolute"):
        Settings(process_role="worker", development_mode=True, kek={"private_key_file": "rel/kek"})


def test_credentials_dir_is_development_only(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="development_mode only"):
        Settings(
            process_role="worker",
            external_url="https://x.test",
            renewal={"credentials_dir": tmp_path},
        )
    dev = Settings(
        process_role="worker", development_mode=True, renewal={"credentials_dir": tmp_path}
    )
    assert dev.renewal.credentials_dir == tmp_path


# --- the api cannot decrypt ---------------------------------------------------------------------------------------


def test_api_process_never_imports_the_key_ring() -> None:
    """Importing the whole api (app factory and every router) loads no decryption code."""
    code = (
        "import sys, ovlm.api.app, ovlm.connections.api, ovlm.ui.routes\n"
        "bad = [m for m in ('ovlm.secrets.keyring', 'ovlm.connections.credentials', 'ovlm.connections.validation')"
        " if m in sys.modules]\n"
        "assert not bad, bad\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=ROOT)  # noqa: S603


def test_import_linter_forbids_the_key_ring_in_the_api() -> None:
    text = (ROOT / "pyproject.toml").read_text()
    assert "the api cannot decrypt" in text
    block = text.split("the api cannot decrypt", 1)[1].split("[[tool.importlinter.contracts]]", 1)[
        0
    ]
    assert '"ovlm.api"' in block and '"ovlm.secrets.keyring"' in block
    assert "allow_indirect_imports = false" in block


def test_public_key_alone_cannot_open_a_sealed_value() -> None:
    """The api's object has no decrypting method at all."""
    pub: PublicKek = _ring().public()
    assert not any(hasattr(pub, n) for n in ("unseal", "decrypt", "unwrap", "private"))
