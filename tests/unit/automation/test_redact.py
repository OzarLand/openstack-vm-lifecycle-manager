from __future__ import annotations

from ovlm.automation.redact import REDACTED, Redactor, truncate_head_tail

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\nAAAAB3NzaC1lZDI1NTE5AAAA\n-----END OPENSSH PRIVATE KEY-----\n"


def test_known_values_are_replaced_everywhere() -> None:
    r = Redactor(["s3cr3t-value", KEY], include_registry=False)
    out = r.text("login with s3cr3t-value ok; again s3cr3t-value")
    assert "s3cr3t-value" not in out and out.count(REDACTED) == 2


def test_private_key_block_and_single_lines() -> None:
    r = Redactor([KEY], include_registry=False)
    out = r.text("key:\n" + KEY + "\nline only: b3BlbnNzaC1rZXktdjEAAAAABG5vbmU")
    assert "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU" not in out and "BEGIN OPENSSH" not in out


def test_generic_patterns() -> None:
    r = Redactor(include_registry=False)
    for raw in (
        "password=hunter2",
        'db_password: "hunter2"',
        "api_key = hunter2",
        "Authorization: Bearer abcdef0123456789",
        "token=hunter2&x=1",
        '{"secret": "hunter2"}',
    ):
        assert "hunter2" not in r.text(raw) and "abcdef0123456789" not in r.text(raw), raw


def test_ordinary_text_survives() -> None:
    r = Redactor(["abcd"], include_registry=False)
    assert (
        r.text("TASK [Install packages] ok: [ovlm-target]")
        == "TASK [Install packages] ok: [ovlm-target]"
    )


def test_registry_secrets_are_included() -> None:
    from ovlm.config.secrets import register_secret

    register_secret("registered-secret-1")
    assert "registered-secret-1" not in Redactor().text("x registered-secret-1 y")


def test_obj_redacts_keys_and_values() -> None:
    r = Redactor(["topsecret1"], include_registry=False)
    assert r.obj({"a": ["topsecret1", {"topsecret1": 3}], "n": 4}) == {
        "a": [REDACTED, {REDACTED: 3}],
        "n": 4,
    }


def test_truncate_keeps_head_and_tail_with_marker() -> None:
    text = "H" * 1000 + "M" * 5000 + "T" * 1000
    out, cut = truncate_head_tail(text, 2000)
    assert cut and len(out.encode()) <= 2000 and out.startswith("H") and out.endswith("T")
    assert "truncated" in out
    assert truncate_head_tail("short", 100) == ("short", False)
