"""Pure-logic unit tests for ovlm.auth (no database)."""

from __future__ import annotations

import base64
import uuid
from types import SimpleNamespace
from typing import Any

import pyotp
import pytest
from cryptography.fernet import Fernet

from ovlm.auth import csrf, passwords, tokens, totp
from ovlm.auth.authz import authorize, scope_covers, scopes_for
from ovlm.auth.errors import ProblemError
from ovlm.auth.ids import new_id
from ovlm.auth.principal import Principal
from ovlm.auth.users import UserError, check_scope, normalise_username
from ovlm.config import Settings


def principal(*grants: tuple[str, str], kind: str = "human") -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        username="u",
        principal_type=kind,  # type: ignore[arg-type]
        auth_method="password+totp",
        grants=frozenset(grants),
    )


# --- passwords (security-model 10.1) -----------------------------------------------------------------------


def test_default_hash_is_argon2id_with_documented_parameters() -> None:
    h = passwords.hash_password(passwords.make_hasher(), "a long enough passphrase")
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


@pytest.mark.parametrize(
    ("m", "t", "p"),
    [(32768, 3, 4), (65536, 2, 4), (65536, 3, 2)],
    ids=["memory", "time", "parallel"],
)
def test_argon2_floor_is_enforced(m: int, t: int, p: int) -> None:
    with pytest.raises(ValueError, match="floor"):
        passwords.make_hasher(m, t, p)


def test_verify_and_rehash_when_parameters_rise() -> None:
    h = passwords.hash_password(passwords.make_hasher(), "a long enough passphrase")
    ok, rehash = passwords.verify_password(passwords.make_hasher(), h, "a long enough passphrase")
    assert (ok, rehash) == (True, False)
    stronger = passwords.make_hasher(memory_kib=65536 + 1024)
    assert passwords.verify_password(stronger, h, "a long enough passphrase") == (True, True)
    assert passwords.verify_password(stronger, h, "wrong") == (False, False)
    assert passwords.verify_password(stronger, "not-a-hash", "x") == (False, False)


@pytest.mark.parametrize(
    ("password", "fragment"),
    [
        ("short", "at least 12"),
        ("passwordpassword", "too common"),
        ("PasswordPassword", "too common"),
        ("aaaaaaaaaaaaaaaa", "repetitive"),
        ("my-alice-secret-ok", "username"),
        ("x" * 300, "at most"),
    ],
)
def test_password_policy_rejects(password: str, fragment: str) -> None:
    with pytest.raises(passwords.PasswordPolicyError, match=fragment):
        passwords.check_policy(password, username="alice")


def test_password_policy_accepts_a_good_passphrase() -> None:
    passwords.check_policy("correct horse battery staple 7", username="alice")


# --- TOTP ----------------------------------------------------------------------------------------------------


def test_totp_accepts_window_and_refuses_replay() -> None:
    secret = totp.new_secret()
    gen = pyotp.TOTP(secret)
    now = 1_700_000_000.0
    step = int(now // 30)
    assert totp.verify_code(secret, gen.at(int(now)), now=now) == step
    assert totp.verify_code(secret, gen.at(int(now - 30)), now=now) == step - 1  # skew tolerance
    assert totp.verify_code(secret, gen.at(int(now + 30)), now=now) == step + 1
    assert totp.verify_code(secret, gen.at(int(now - 90)), now=now) is None  # outside the window
    assert totp.verify_code(secret, gen.at(int(now)), now=now, last_step=step) is None  # replay
    assert totp.verify_code(secret, gen.at(int(now)), now=now, last_step=step - 1) == step


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 5x"])
def test_totp_rejects_malformed_codes(bad: str) -> None:
    assert totp.verify_code(totp.new_secret(), bad, now=1_700_000_000.0) is None


def test_totp_vault_roundtrip_and_fail_closed(tmp_path: Any) -> None:
    key = Fernet.generate_key().decode()
    vault = totp.TotpVault(key)
    blob = vault.encrypt("JBSWY3DPEHPK3PXP")
    assert b"JBSWY3DPEHPK3PXP" not in blob
    assert vault.decrypt(blob) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(totp.TotpUnavailableError):
        totp.TotpVault.from_file(None)
    with pytest.raises(totp.TotpUnavailableError):
        totp.TotpVault("not a key")
    with pytest.raises(totp.TotpUnavailableError):
        totp.TotpVault(Fernet.generate_key().decode()).decrypt(blob)  # other key


def test_provisioning_uri_names_issuer_and_account() -> None:
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "alice")
    assert uri.startswith("otpauth://totp/OVLM:alice?") and "issuer=OVLM" in uri


# --- API tokens (10.3) -----------------------------------------------------------------------------------------


def test_token_format_parse_and_no_secret_in_hash_input() -> None:
    tid = new_id()
    secret = base64.b32encode(b"\x07" * 32).decode().rstrip("=")
    assert len(secret) == 52
    assert tokens.parse_token(f"ovlm_{tid.hex}_{secret}") == (tid, secret)
    for bad in (
        "",
        "ovlm_x_y",
        f"ovlm_{tid.hex}_{secret.lower()}",
        f"xvlm_{tid.hex}_{secret}",
        f"ovlm_{tid.hex}_{secret}A",
    ):
        assert tokens.parse_token(bad) is None


def test_token_grants_are_a_subset_of_the_owner_and_never_privileged() -> None:
    owner = [("admin", "global"), ("approver", "global"), ("operator", "project:a")]
    # read: viewer through the admin/approver/operator lattice, never approver or admin themselves
    g = tokens.token_grants(owner, {"read"}, "global")
    assert {r for r, _ in g} == {"viewer"}
    # operate: operator only where the owner holds it
    g = tokens.token_grants(owner, {"operate"}, "global")
    assert ("operator", "project:a") in g and ("operator", "global") not in g
    assert not any(r in ("approver", "admin") for r, _ in g)
    # project-scoped token cannot reach other projects
    g = tokens.token_grants(owner, {"operate"}, "project:b")
    assert ("operator", "project:b") not in g and ("operator", "project:a") not in g


def test_token_request_validation() -> None:
    held = [("viewer", "global")]
    tokens.validate_request(held, ["read"], "global", 90)
    with pytest.raises(tokens.TokenRequestError, match="operator"):
        tokens.validate_request(held, ["operate"], "global", 30)
    with pytest.raises(tokens.TokenRequestError, match="between 1 and 90"):
        tokens.validate_request(held, ["read"], "global", 91)
    with pytest.raises(tokens.TokenRequestError):
        tokens.validate_request(held, ["admin"], "global", 30)  # not a token scope
    with pytest.raises(tokens.TokenRequestError):
        tokens.validate_request([("viewer", "project:a")], ["read"], "global", 30)  # exceeds scope
    tokens.validate_request([("viewer", "project:a")], ["read"], "project:a", 30)


# --- authorization lattice ------------------------------------------------------------------------------------


def test_role_lattice() -> None:
    op = principal(("operator", "global"))
    assert authorize(op, "viewer") and authorize(op, "operator")
    assert not authorize(op, "approver") and not authorize(op, "admin")
    ap = principal(("approver", "global"))
    assert authorize(ap, "viewer") and not authorize(ap, "operator")  # approver != operator
    ad = principal(("admin", "global"))
    assert authorize(ad, "admin") and authorize(ad, "viewer")
    assert not authorize(ad, "operator") and not authorize(ad, "approver")  # admin does not inherit


def test_scope_matching() -> None:
    assert scope_covers("global", "project:a") and scope_covers("project:a", "project:a")
    assert not scope_covers("project:a", "project:b") and not scope_covers("project:a", "global")
    p = principal(("operator", "project:a"))
    assert authorize(p, "operator", "project:a") and not authorize(p, "operator", "project:b")
    assert authorize(p, "operator")  # any scope held
    assert scopes_for(p, "viewer") == {"project:a"}
    assert scopes_for(principal(("operator", "global"), ("operator", "project:a")), "operator") == {
        "global"
    }


# --- users / links input handling -----------------------------------------------------------------------------


def test_username_and_scope_validation() -> None:
    assert normalise_username("  Alice.Smith ") == "alice.smith"
    for bad in ("ab", "-alice", "a b c", "x" * 65, "alice/../x"):
        with pytest.raises(UserError):
            normalise_username(bad)
    pid = "0f0e0d0c-0b0a-4908-8706-050403020100"
    assert check_scope("global") == "global"
    assert check_scope(f"project:{pid}") == f"project:{pid}"
    assert (
        check_scope(f"project:{pid.upper()}") == f"project:{pid}"
    )  # canonical lower case (SEC-C-8)
    for bad in ("project:", "project:a/b", "Global", "project:abc-1", "project:" + "x" * 65,
                f"project: {pid}", f"PROJECT:{pid}"):  # fmt: skip
        with pytest.raises(UserError):
            check_scope(bad)


def test_link_split_rejects_garbage() -> None:
    from ovlm.auth.users import _split

    assert (
        _split("nodot") is None
        and _split("short.secret") is None
        and _split("z" * 32 + ".s") is None
    )
    assert _split(uuid.uuid4().hex + ".secret") is not None


def test_uuid7_is_time_ordered_and_versioned() -> None:
    ids = [new_id() for _ in range(50)]
    assert all(i.version == 7 for i in ids)
    assert len({*ids}) == 50
    assert [i.int >> 80 for i in ids] == sorted(i.int >> 80 for i in ids)


# --- CSRF origin check (10.2) ---------------------------------------------------------------------------------


def req(headers: dict[str, str]) -> Any:
    return SimpleNamespace(headers={k.lower(): v for k, v in headers.items()})


def test_origin_check_with_external_url() -> None:
    s = Settings(external_url="https://ovlm.example.org")
    assert csrf.origin_allowed(req({"Origin": "https://ovlm.example.org"}), s)
    assert csrf.origin_allowed(req({"Referer": "https://ovlm.example.org/some/page?x=1"}), s)
    for headers in (
        {},  # neither header: refused
        {"Origin": "null"},
        {"Origin": "https://evil.example.net"},
        {"Origin": "http://ovlm.example.org"},  # scheme matters
        {"Origin": "https://ovlm.example.org:8443"},
        {"Origin": "https://ovlm.example.org.evil.net"},
        {"Referer": "https://evil.example.net/ovlm.example.org"},
    ):
        assert not csrf.origin_allowed(req(headers), s), headers


def test_origin_check_without_external_url_compares_host() -> None:
    s = Settings(
        development_mode=True
    )  # production refuses to start without external_url (SEC-C-11)
    assert csrf.origin_allowed(req({"Origin": "https://ovlm.local", "Host": "ovlm.local"}), s)
    assert not csrf.origin_allowed(req({"Origin": "https://evil.net", "Host": "ovlm.local"}), s)
    assert not csrf.origin_allowed(req({"Host": "ovlm.local"}), s)


def test_token_comparison() -> None:
    assert csrf.tokens_equal("abc", "abc")
    assert not csrf.tokens_equal("abc", "abd") and not csrf.tokens_equal(None, "abc")
    assert not csrf.tokens_equal("", "") and not csrf.tokens_equal("abc", None)


def test_problem_error_body_has_no_internals() -> None:
    body = ProblemError(403, "forbidden", "Forbidden", "nope", next_action="ask").body("/x")
    assert body == {
        "type": "https://ovlm.dev/problems/forbidden",
        "title": "Forbidden",
        "status": 403,
        "code": "forbidden",
        "detail": "nope",
        "instance": "/x",
        "next_action": "ask",
    }


def test_scope_comparison_is_canonical() -> None:
    """SEC-C-8: an upper-case project binding (stored before normalisation) covers the same project."""
    from ovlm.auth.authz import scope_covers
    from ovlm.auth.principal import canonical_scope
    from ovlm.auth.sod import binding_conflicts
    from ovlm.auth.tokens import token_grants

    pid = "0f0e0d0c-0b0a-4908-8706-050403020100"
    upper, lower = f"project:{pid.upper()}", f"project:{pid}"
    assert canonical_scope(upper) == lower and canonical_scope("project:a") == "project:a"
    assert scope_covers(upper, lower) and scope_covers(lower, upper)
    assert not scope_covers(upper, "project:0f0e0d0c-0b0a-4908-8706-050403020101")
    assert binding_conflicts([("approver", upper)], "operator", lower) == [upper]
    assert token_grants([("operator", upper)], ["operate"], lower) >= {("operator", lower)}


def test_cli_invoker_names_the_os_user_and_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review IS-6 (SF-10): ``ovlm admin create --reissue`` records who ran it and where. ``SUDO_USER`` wins (the
    human behind sudo); without any variable, the uid's passwd name, or ``uid:N`` when there is none."""
    import os
    import socket

    from ovlm.auth import cli

    for k in ("SUDO_USER", "USER", "LOGNAME"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("USER", "alice")
    monkeypatch.setenv("SUDO_USER", "bob")
    assert cli.invoker() == {"os_user": "bob", "hostname": socket.gethostname()}
    monkeypatch.delenv("SUDO_USER")
    assert cli.invoker()["os_user"] == "alice"
    monkeypatch.delenv("USER")

    def no_entry(uid: int) -> object:
        raise KeyError(uid)

    monkeypatch.setattr("pwd.getpwuid", no_entry)
    assert cli.invoker()["os_user"] == f"uid:{os.getuid()}"
