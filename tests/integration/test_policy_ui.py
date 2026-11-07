# ruff: noqa: F811
"""HTTP-level tests of the policy pages (UI-2): real app, real PostgreSQL, real login sessions.

The edit form is driven like a browser: the test scrapes the form from the page (so what the page pre-fills is what
gets posted back), changes one field and posts it. The same service code and audit as ``PUT /api/v1/policies/{id}``
run behind it.
"""

from __future__ import annotations

import json
from html.parser import HTMLParser
from typing import Any

from fastapi.testclient import TestClient

from tests.integration.auth_support import ORIGIN, Env
from tests.integration.auth_support import env as env  # noqa: F401 - fixture
from tests.integration.renewal.test_api import configure
from tests.integration.test_renewal_ui import World


class _Form(HTMLParser):
    """The values a browser would submit for the first form that posts to ``/edit``."""

    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, list[str]] = {}
        self._in = False
        self._select: str | None = None
        self._first_option: str | None = None
        self._selected = False

    def handle_starttag(self, tag: str, attrs_: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs_}
        if tag == "form" and a.get("action", "").endswith("/edit"):
            self._in = True
        elif not self._in:
            return
        elif tag == "input" and a.get("name"):
            kind = a.get("type", "text")
            if kind in ("checkbox", "radio") and "checked" not in a:
                return
            self.values.setdefault(a["name"], []).append(
                a.get("value", "on" if kind == "checkbox" else "")
            )
        elif tag == "select":
            self._select, self._first_option, self._selected = a["name"], None, False
        elif tag == "option" and self._select:
            if self._first_option is None:
                self._first_option = a.get("value", "")
            if "selected" in a:
                self.values[self._select] = [a.get("value", "")]
                self._selected = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "select" and self._select:
            if not self._selected:
                self.values[self._select] = [self._first_option or ""]
            self._select = None
        elif tag == "form":
            self._in = False


def scrape(html: str) -> dict[str, list[str]]:
    p = _Form()
    p.feed(html)
    return p.values


class Pol:
    def __init__(self, env: Env) -> None:
        configure(env)
        self.w = World(env)
        self.env = env
        self.id = str(self.w.ids["policy"])
        self.admin, _ = env.user_client("adm1", [("admin", "global")])

    def csrf(self, c: TestClient) -> str:
        return self.w.csrf(c)

    def edit(self, c: TestClient) -> Any:
        return c.get(f"/policies/{self.id}/edit")

    def post(self, c: TestClient, data: dict[str, Any], *, token: str | None = None) -> Any:
        body = {**data, "csrf_token": token if token is not None else self.csrf(c)}
        return c.post(
            f"/policies/{self.id}/edit",
            data=body,
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )

    def row(self) -> dict[str, Any]:
        r = self.env.sql("SELECT * FROM policy WHERE id = :i", i=self.id)[0]
        return dict(r._mapping)

    def submit(self, c: TestClient, **changes: Any) -> Any:
        """Scrape the page, change fields, post it back."""
        data = scrape(self.edit(c).text)
        for k, v in changes.items():
            if v is None:
                data.pop(k, None)
            else:
                data[k] = v if isinstance(v, list) else [v]
        return self.post(c, data)


def set_non_defaults(p: Pol) -> None:
    p.env.sql(
        "UPDATE policy SET require_distinct_approvers = false, auto_restore_in_window = false, "
        "snapshot_retain_after_restore = 'P7D', retention_period_seconds = 2592000, "
        "approvals = '{\"plan\": false, \"cutover\": true}'::jsonb WHERE id = :i", i=p.id,
    )  # fmt: skip


# --- pages ------------------------------------------------------------------------------------------------------


def test_list_and_detail_show_version_bindings_and_effective_windows(env: Env) -> None:
    p = Pol(env)
    lst = p.w.op.get("/policies")
    assert (
        lst.status_code == 200 and f"/policies/{p.id}" in lst.text and ">Policies</a>" in lst.text
    )
    assert 'aria-current="page"' in lst.text
    d = p.w.op.get(f"/policies/{p.id}")
    assert d.status_code == 200 and "version 1" in d.text and "Effective windows" in d.text
    assert (
        "Bindings" in d.text and "App" in d.text
    )  # the seeded policy is bound to the service "App"
    assert "mon, tue, wed, thu, fri, sat, sun" in d.text and "UTC" in d.text
    assert "Next window opens" in d.text
    assert (
        "Edit (creates version 2)" not in d.text and "Only an admin" in d.text
    )  # operator: no edit link
    assert "Edit (creates version 2)" in p.admin.get(f"/policies/{p.id}").text
    assert p.w.op.get("/policies/not-a-uuid").status_code == 404
    assert p.w.other.get("/policies").status_code == 200  # reading needs viewer only


# --- admin edit -------------------------------------------------------------------------------------------------


def test_admin_edit_creates_a_new_version_and_keeps_every_unchanged_field(env: Env) -> None:
    p = Pol(env)
    set_non_defaults(p)  # the trap: a full replace must not reset these
    before = p.row()
    page = p.edit(p.admin)
    assert page.status_code == 200 and "Saving creates version 2" in page.text
    r = p.submit(p.admin, max_age="P2D", renewal_interval="PT12H")
    assert r.status_code == 303 and r.headers["location"] == f"/policies/{p.id}?notice=updated", (
        r.text
    )
    after = p.row()
    assert after["version"] == before["version"] + 1
    assert (after["max_age_seconds"], after["renewal_interval_seconds"]) == (172800, 43200)
    for col in ("name", "windows", "approvals", "require_distinct_approvers", "auto_restore_in_window",
                "snapshot_retain_after_restore", "max_window_duration_seconds", "retention_period_seconds"):  # fmt: skip
        assert after[col] == before[col], col
    assert after["require_distinct_approvers"] is False and after["approvals"] == {
        "plan": False,
        "cutover": True,
    }
    assert after["last_edited_by"] is not None
    follow = p.admin.get(f"/policies/{p.id}?notice=updated")
    assert "Policy saved as a new version." in follow.text and "version 2" in follow.text
    rows = env.sql(
        "SELECT actor_id, project_scope, before, after FROM audit_event WHERE action = 'policy.update'"
    )
    assert len(rows) == 1 and rows[0].project_scope == "global"
    assert rows[0].before["version"] == 1 and rows[0].after["version"] == 2
    assert (
        rows[0].after["require_distinct_approvers"] is False and rows[0].after["max_age"] == "P2D"
    )


def test_admin_adds_a_weekend_window_and_removes_one(env: Env) -> None:
    p = Pol(env)
    p.env.sql(
        "UPDATE policy SET windows = CAST(:w AS jsonb) WHERE id = :i", i=p.id,
        w=json.dumps([{"weekdays": ["mon"], "start": "01:00", "end": "05:00", "timezone": "UTC"}]),
    )  # fmt: skip
    p.env.sql("UPDATE policy SET max_window_duration_seconds = 7200 WHERE id = :i", i=p.id)
    data = scrape(p.edit(p.admin).text)
    assert data["win_start"][0] == "01:00" and data["win_days"] == ["0:mon"]
    data["win_days"] += ["1:sat", "1:sun"]  # the first spare row
    data["win_start"][1], data["win_end"][1] = "02:00", "04:00"
    r = p.post(p.admin, data)
    assert r.status_code == 303, r.text
    assert p.row()["windows"] == [
        {"weekdays": ["mon"], "start": "01:00", "end": "05:00", "timezone": "UTC"},
        {"weekdays": ["sat", "sun"], "start": "02:00", "end": "04:00", "timezone": "UTC"},
    ]
    data = scrape(p.edit(p.admin).text)  # now remove the Monday window
    data["win_remove"] = ["0"]
    assert p.post(p.admin, data).status_code == 303
    assert [w["weekdays"] for w in p.row()["windows"]] == [["sat", "sun"]]
    assert p.row()["version"] == 3


def test_windows_are_validated_and_nothing_is_saved(env: Env) -> None:
    p = Pol(env)
    before = p.row()

    def win0(**kw: Any) -> Any:
        def mutate(d: dict[str, list[str]]) -> None:
            for key, val in kw.items():
                if key == "win_days":
                    d["win_days"] = val
                elif key in ("win_start", "win_end", "win_tz"):
                    d[key][0] = val
                else:
                    d[key] = [val]

        return mutate

    bad = [
        (win0(win_start="22:00", win_end="02:00"), "same day"),  # crosses midnight
        (win0(win_start="10:00", win_end="25:00"), "HH:MM"),
        (win0(win_tz="Mars/Base"), "time zone"),
        (win0(win_days=[]), "weekdays"),
        (win0(max_window_duration="PT5H", win_start="10:00", win_end="12:00"), "does not fit"),
        (win0(renewal_interval="P9D", max_age="P2D"), "renewal_interval"),
        (win0(max_age="tomorrow"), "max_age"),
    ]
    for mutate, expect in bad:
        data = scrape(p.edit(p.admin).text)
        mutate(data)
        r = p.post(p.admin, data)
        assert r.status_code == 422 and expect in r.text, (expect, r.status_code, r.text[:300])
    assert p.row() == before


def test_a_missing_field_is_refused_never_reset_to_a_default(env: Env) -> None:
    p = Pol(env)
    set_non_defaults(p)
    before = p.row()
    for field in (
        "require_distinct_approvers",
        "auto_restore_in_window",
        "approval_plan",
        "max_window_duration",
    ):
        r = p.submit(p.admin, **{field: None})
        assert r.status_code == 422, field
    assert p.row() == before and p.row()["require_distinct_approvers"] is False


# --- authorization, CSRF, locking -------------------------------------------------------------------------------


def test_non_admins_get_403_and_nothing_changes(env: Env) -> None:
    p = Pol(env)
    before = p.row()
    data = scrape(p.edit(p.admin).text)
    data["max_age"] = ["P3D"]
    viewer, _ = env.user_client("viewer1", [("viewer", "global")])
    approver, _ = env.user_client("appr1", [("approver", "global")])
    for c in (p.w.op, viewer, approver, p.w.other):
        assert p.edit(c).status_code == 403
        r = p.post(c, data)
        assert r.status_code == 403, r.text
        assert "needs the admin role" in r.text
    assert p.row() == before
    anon = env.client()
    assert anon.get(f"/policies/{p.id}/edit", follow_redirects=False).status_code == 303


def test_csrf_is_enforced_and_the_form_carries_the_token(env: Env) -> None:
    p = Pol(env)
    page = p.edit(p.admin)
    assert f'name="csrf_token" value="{p.csrf(p.admin)}"' in page.text and "style=" not in page.text
    data = scrape(page.text)
    assert data.pop("csrf_token") == [p.csrf(p.admin)]  # the page carried it; now post without it
    data["max_age"] = ["P3D"]
    before = p.row()
    no_token = p.admin.post(f"/policies/{p.id}/edit", data=data, headers={"Origin": ORIGIN})
    assert no_token.status_code == 403
    assert p.post(p.admin, data, token="forged").status_code == 403
    wrong_origin = p.admin.post(
        f"/policies/{p.id}/edit", data={**data, "csrf_token": p.csrf(p.admin)},
        headers={"Origin": "https://evil.example"},
    )  # fmt: skip
    assert wrong_origin.status_code == 403
    assert p.row() == before
    assert p.post(p.admin, data).status_code == 303  # with the token it works


def test_a_stale_version_gets_409_and_nothing_is_saved(env: Env) -> None:
    p = Pol(env)
    data = scrape(p.edit(p.admin).text)  # version 1
    assert data["if_match"] == ['"1"']
    # someone else saves version 2 through the API meanwhile
    body = {
        "name": "pol", "max_age": "P5D", "renewal_interval": "P1D", "max_window_duration": "PT1H",
        "windows": [{"weekdays": ["mon"], "start": "01:00", "end": "05:00", "timezone": "UTC"}],
    }  # fmt: skip
    api = p.admin.put(
        f"/api/v1/policies/{p.id}", json=body, headers=env.headers(p.admin, **{"If-Match": '"1"'})
    )
    assert api.status_code == 200, api.text
    mine = dict(data, max_age=["P3D"])
    r = p.post(p.admin, mine)
    assert r.status_code == 409 and "version 1" in r.text and "now version 2" in r.text
    assert p.row()["max_age_seconds"] == 5 * 86400 and p.row()["version"] == 2
    forged = dict(data, if_match=["abc"])  # not an ETag
    assert p.post(p.admin, forged).status_code in (412, 409)
    gone = dict(data)
    gone.pop("if_match")
    assert p.post(p.admin, gone).status_code == 428  # missing If-Match is refused, like the API
    assert p.row()["version"] == 2


# --- voided approvals -------------------------------------------------------------------------------------------


def test_open_plans_are_counted_and_the_policy_name_must_be_typed(env: Env) -> None:
    p = Pol(env)
    quiet = p.edit(p.admin)
    assert "No open plan uses this policy" in quiet.text and 'name="confirm_name"' not in quiet.text
    assert "changes the plan hash" in quiet.text
    plan = p.w.make_plan()
    approval = p.w.request_g1(plan)
    page = p.edit(p.admin)
    assert "1 open plan and 1 live approval would be affected." in page.text
    assert 'name="confirm_name"' in page.text and "Approvals already given" in page.text
    before = p.row()
    # no confirmation, a wrong one, a different case: refused, nothing saved
    for typed in (None, "", "wrong", "POL", "pol x"):
        extra = {} if typed is None else {"confirm_name": typed}
        r = p.post(p.admin, {**scrape(page.text), "max_age": ["P3D"], **extra})
        assert r.status_code == 422 and "Type the policy name" in r.text, typed
    assert p.row() == before and env.sql("SELECT void_reason FROM approval")[0][0] is None
    ok = p.post(p.admin, {**scrape(page.text), "max_age": ["P3D"], "confirm_name": "pol"})
    assert ok.status_code == 303 and p.row()["version"] == 2
    # the warning is true: the approval no longer matches and cannot be approved
    decision = p.w.approve(approval)
    assert decision.status_code == 409 and "voided" in decision.text.lower()
    assert env.sql("SELECT void_reason FROM approval")[0][0] == "bound hash changed"
    # a finished plan is not counted
    env.sql("UPDATE renewal_plan SET state = 'cancelled' WHERE id = :p", p=plan)
    assert "No open plan uses this policy" in p.edit(p.admin).text
