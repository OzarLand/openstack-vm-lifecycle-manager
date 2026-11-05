"""``ovlm admin create --username NAME --enrol-link [--reissue]``: bootstrap the first admin (or recover one).

There is no password option and no default account. The command creates the user without a password and prints a
single-use enrolment link on **stdout** (logs go to stderr); the person opens it and chooses their own password,
then enrols TOTP (mandatory for admin). Runs with the api's database role, so it works inside the api container.
Every use is audited with ``principal_type=system``, ``auth_method=cli``.

``--reissue``: the link expired or was lost before the admin used it. Only for an existing admin who **never
finished enrolment** (still ``pending_enrolment``: no password was ever set). Every earlier unused link of that user
is revoked in the same transaction, so only the new link works, once; audited as ``user.enrolment_link.reissue``
with the number of links revoked. An enrolled admin who lost their credentials is reset by another admin instead.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from typing import Any

from ovlm import audit
from ovlm.auth import events as _events  # noqa: F401  (registers the audit allowlists)
from ovlm.auth import users
from ovlm.config import Settings
from ovlm.db.engine import make_engine, make_session_factory
from ovlm.observability.logging import configure_logging

log = logging.getLogger("ovlm.cli")


def admin_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="ovlm admin", description="Administrator bootstrap")
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser(
        "create", help="create an admin user and print a one-time enrolment link"
    )
    create.add_argument("--username", required=True)
    create.add_argument("--display-name", default="")
    create.add_argument(
        "--enrol-link",
        action="store_true",
        required=True,
        help="required: the only way to set up an admin is a single-use enrolment link (no passwords here)",
    )
    create.add_argument(
        "--reissue",
        action="store_true",
        help="the admin already exists but never finished enrolment: revoke their unused links and print a new one",
    )
    args = parser.parse_args(list(argv))

    settings = Settings(process_role="api")
    configure_logging("admin-cli", settings.log.level, stream=sys.stderr)
    engine = make_engine(settings)
    if args.reissue:
        try:
            raw = _reissue(engine, settings, args.username)
        except users.UserError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 2
        finally:
            engine.dispose()
        return _print_link(settings, raw)
    try:
        with make_session_factory(engine)() as db:
            try:
                user_id = users.create_user(
                    db,
                    username=args.username,
                    display_name=args.display_name,
                    created_by=None,
                    created_via="cli",
                    bindings=[("admin", "global")],
                )
            except users.UserError as exc:
                sys.stderr.write(f"error: {exc}\n")
                return 2
            link_id, raw = users.issue_link(
                db, settings, user_id=user_id, purpose="enrol", created_by=None
            )
            common = {"principal_type": "system", "auth_method": "cli"}
            audit.record(
                db,
                action="user.create",
                target_type="user",
                target_id=str(user_id),
                after={
                    "username": users.normalise_username(args.username),
                    "display_name": args.display_name,
                    "state": "pending_enrolment",
                    "created_via": "cli",
                    "roles": ["admin@global"],
                },
                **common,  # type: ignore[arg-type]
            )
            audit.record(
                db,
                action="user.enrolment_link.issue",
                target_type="enrolment_link",
                target_id=str(link_id),
                after={"purpose": "enrol", "user_id": str(user_id)},
                **common,  # type: ignore[arg-type]
            )
            db.commit()
    finally:
        engine.dispose()
    return _print_link(settings, raw)


def _reissue(engine: Any, settings: Settings, username: str) -> str:
    with make_session_factory(engine)() as db:
        user_id, link_id, raw, revoked = users.reissue_enrolment_link(
            db, settings, username=username
        )
        audit.record(
            db, action="user.enrolment_link.reissue", target_type="enrolment_link", target_id=str(link_id),
            principal_type="system", auth_method="cli",
            after={"purpose": "enrol", "user_id": str(user_id), "revoked_links": revoked},
        )  # fmt: skip
        db.commit()
    return raw


def _print_link(settings: Settings, raw: str) -> int:
    base = (settings.external_url or "").rstrip("/")
    sys.stdout.write(f"{base}/enrol/{raw}\n")
    sys.stderr.write(
        f"single-use link, valid {settings.auth.enrolment_link_hours} h; "
        "the admin chooses their own password and then enrols TOTP\n"
    )
    return 0
