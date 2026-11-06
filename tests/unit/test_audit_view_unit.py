"""Cursor and admin-only rule of the audit view (no database)."""

from __future__ import annotations

import base64
from typing import Literal
from uuid import uuid4

import pytest

from ovlm.audit import view
from ovlm.auth.principal import Principal


def test_cursor_round_trip_and_garbage() -> None:
    assert view.decode_cursor(view.encode_cursor(42)) == 42
    for bad in ("", "garbage", "e30", base64.urlsafe_b64encode(b'{"id": "x"}').decode(),
                base64.urlsafe_b64encode(b'{"id": 0}').decode(), base64.urlsafe_b64encode(b"[1]").decode(),
                base64.urlsafe_b64encode(b'{"id": true}').decode()):  # fmt: skip
        with pytest.raises(view.InvalidCursorError):
            view.decode_cursor(bad)


def test_admin_only_prefixes_cover_auth_token_and_user_management() -> None:
    for action in ("auth.login.success", "auth.totp.enrol_begin", "authz.denied", "token.revoke",
                   "user.create", "user.enrolment_link.issue", "role_binding.create"):  # fmt: skip
        assert action.startswith(view.ADMIN_ONLY_PREFIXES), action
    for action in ("service.create", "run.start", "approval.decide", "automation_artefact.view"):
        assert not action.startswith(view.ADMIN_ONLY_PREFIXES), action


def test_only_a_human_global_admin_sees_admin_only_events() -> None:
    def who(role: str, scope: str, ptype: Literal["human", "token"] = "human") -> Principal:
        return Principal(
            user_id=uuid4(), username="u", principal_type=ptype, auth_method="session",
            grants=frozenset({(role, scope)}),
        )  # fmt: skip

    assert view.sees_admin_only(who("admin", "global"))
    assert not view.sees_admin_only(who("admin", "project:x"))
    assert not view.sees_admin_only(who("operator", "global"))
    assert not view.sees_admin_only(who("admin", "global", "token"))
