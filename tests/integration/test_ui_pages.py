# ruff: noqa: F811
"""HTTP-level tests of the operator UI (E6-1, E6-2): real app, real PostgreSQL, real login sessions.

The pages are rendered for logged-in users of each role. They check content, the CSRF token on forms and on HTMX
requests, role-based visibility, and that changes go through the same service layer as the API (audit rows,
conflicts).
"""

from __future__ import annotations

import json
import re
from html import unescape
from typing import Any
from uuid import uuid4

from tests.integration.auth_support import ORIGIN, PASSWORD
from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.test_registry_api import Env, Session
from tests.integration.test_registry_api import env as env  # noqa: F401

HX_HEADERS = re.compile(r"hx-headers='([^']*)'")


def csrf_of(s: Session) -> str:
    return str(s.client.get("/api/v1/session").json()["csrf_token"])


def form_post(
    s: Session, url: str, data: dict[str, str], *, token: str | None = None, **kw: Any
) -> Any:
    """A browser form post: the hidden ``csrf_token`` field and the Origin header."""
    body = dict(data)
    body["csrf_token"] = token if token is not None else csrf_of(s)
    return s.client.post(url, data=body, headers={"Origin": ORIGIN}, follow_redirects=False, **kw)


def page(s: Session, url: str, **kw: Any) -> Any:
    return s.client.get(url, **kw)


# --- layout, navigation, CSRF -----------------------------------------------------------------------------------------


def test_anonymous_is_sent_to_login_and_htmx_gets_hx_redirect(env: Env) -> None:
    anon = env.auth.client()
    for path in ("/", "/inventory", "/services", f"/inventory/servers/{uuid4()}"):
        r = anon.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login", path
    r = anon.get("/inventory", headers={"HX-Request": "true"}, follow_redirects=False)
    assert r.status_code == 200 and r.headers["HX-Redirect"] == "/login"
    assert (
        anon.post(
            "/services", data={}, headers={"Origin": ORIGIN}, follow_redirects=False
        ).status_code
        == 303
    )


def test_layout_has_navigation_identity_logout_and_csrf_header_for_htmx(env: Env) -> None:
    s = env.users["operator"]
    r = page(s, "/")
    assert r.status_code == 200
    for label in ("Dashboard", "Inventory", "Services", "Renewals", "Audit"):
        assert f">{label}</a>" in r.text
    assert 'aria-current="page"' in r.text and 'href="#main"' in r.text  # skip link, current page
    assert "operator (global)" in r.text and "Sign out / switch account" in r.text
    assert 'action="/logout"' in r.text
    m = HX_HEADERS.search(r.text)
    assert m and json.loads(unescape(m.group(1))) == {"X-CSRF-Token": csrf_of(s)}
    assert (
        f'name="csrf_token" value="{csrf_of(s)}"' in r.text
    )  # the logout form works without JavaScript
    assert 'src="/static/htmx.min.js"' in r.text
    assert not re.search(r'(src|href)="https?://(?!github\.com/OzarLand)', r.text)  # no CDN
    assert "style=" not in r.text  # the CSP forbids inline styles
    assert page(s, "/renewals").status_code == 200 and page(s, "/audit").status_code == 200


def test_dashboard_counts_and_fragment(env: Env) -> None:
    r = page(env.users["viewer"], "/")
    assert r.status_code == 200 and "Servers" in r.text and "Managed VMs" in r.text
    frag = page(env.users["viewer"], "/ui/fragments/summary")
    assert frag.status_code == 200 and "<html" not in frag.text
    assert re.search(r"Servers</dt>\s*<dd><a href=\"/inventory\">2</a>", frag.text)


def test_logout_form_ends_the_session(env: Env) -> None:
    s = env.users["viewer"]
    r = form_post(s, "/logout", {})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert s.client.get("/inventory", follow_redirects=False).status_code == 303


# --- inventory list ---------------------------------------------------------------------------------------------------


def test_inventory_list_shows_age_volumes_floating_ips_and_marks_gone(env: Env) -> None:
    s = env.users["viewer"]
    r = page(s, "/inventory")
    assert r.status_code == 200
    assert ">blue<" in r.text and ">green<" in r.text
    assert env.ids["vol"][:8] in r.text  # attached volume
    assert re.search(r"\d+[dhm]", r.text)  # age
    assert re.search(r"\b\d+\.\d+\.\d+\.\d+\b", r.text)  # floating IP of blue
    assert "Next page" not in r.text

    env.fake.keep_tombstones = False
    env.fake.delete_server(env.ids["green"])
    env.sync(kind="full")
    gone = page(s, "/inventory", params={"status": "gone"})
    assert ">green<" in gone.text and ">blue<" not in gone.text
    assert 'class="badge gone"' in gone.text and 'class="gone"' in gone.text
    assert ">green<" in page(s, "/inventory").text  # still listed, but marked


def test_inventory_filters_and_pagination_and_bad_input(env: Env) -> None:
    s = env.users["viewer"]
    assert ">blue<" not in page(s, "/inventory", params={"project": str(uuid4())}).text
    assert ">green<" in page(s, "/inventory", params={"project": str(env.project)}).text
    bad = page(s, "/inventory", params={"project": "not-a-uuid"})
    assert bad.status_code == 422 and 'role="alert"' in bad.text
    assert page(s, "/inventory", params={"status": "bogus"}).status_code == 422
    assert page(s, "/inventory", params={"cursor": "garbage"}).status_code == 200
    # the filter form enhances with HTMX but is a plain GET form first
    assert 'method="get" action="/inventory"' in page(s, "/inventory").text


def test_registered_filter(env: Env) -> None:
    op = env.users["operator"]
    svc = env.make_service()
    blue = env.observed_id(env.ids["blue"])
    assert (
        form_post(op, f"/inventory/servers/{blue}/register", {"service_id": svc["id"]}).status_code
        == 303
    )
    assert ">blue<" in page(op, "/inventory", params={"registered": "yes"}).text
    assert ">green<" not in page(op, "/inventory", params={"registered": "yes"}).text
    assert ">blue<" not in page(op, "/inventory", params={"registered": "no"}).text
    assert 'class="badge managed"' in page(op, "/inventory").text


# --- VM details: observed vs desired, register ------------------------------------------------------------------------


def test_detail_shows_observed_next_to_not_managed(env: Env) -> None:
    sid = env.observed_id(env.ids["green"])
    r = page(env.users["viewer"], f"/inventory/servers/{sid}")
    assert r.status_code == 200
    assert r.text.index("Desired state") < r.text.index("Observed state")
    assert "Not managed" in r.text
    assert "Register as managed VM" not in r.text  # a viewer cannot register
    assert env.ids["green"] in r.text
    assert page(env.users["viewer"], f"/inventory/servers/{uuid4()}").status_code == 404
    assert page(env.users["viewer"], "/inventory/servers/nonsense").status_code == 404


def test_operator_registers_a_vm_and_detail_shows_desired_state(env: Env) -> None:
    op = env.users["operator"]
    blue = env.observed_id(env.ids["blue"])
    r = page(op, f"/inventory/servers/{blue}")
    assert (
        "Register as managed VM" in r.text and f'name="csrf_token" value="{csrf_of(op)}"' in r.text
    )
    assert "No service exists" in r.text  # nothing to register to yet
    svc = env.make_service()
    r = page(op, f"/inventory/servers/{blue}")
    assert f'value="{svc["id"]}"' in r.text

    done = form_post(op, f"/inventory/servers/{blue}/register", {"service_id": svc["id"]})
    assert (
        done.status_code == 303
        and done.headers["location"] == f"/inventory/servers/{blue}?notice=registered"
    )
    after = page(op, done.headers["location"])
    assert "The server is now a managed VM." in after.text and "App 01" in after.text
    assert "no profile assigned" in after.text and "Not managed" not in after.text
    # the same state through the REST API: the UI used the same service layer
    vms = op.get("/api/v1/managed-vms").json()["items"]
    assert [v["openstack_server_id"] for v in vms] == [env.ids["blue"]]
    rows = env.auth.sql(
        "SELECT actor_id, project_scope FROM audit_event WHERE action = 'managed_vm.register'"
    )
    assert len(rows) == 1 and str(rows[0][0]) == str(env.operator_id)

    again = form_post(op, f"/inventory/servers/{blue}/register", {"service_id": svc["id"]})
    assert (
        again.status_code == 409
        and "already" in again.text.lower()
        and 'role="alert"' in again.text
    )


def test_register_is_refused_without_role_csrf_or_valid_input(env: Env) -> None:
    viewer, op = env.users["viewer"], env.users["operator"]
    svc = env.make_service()
    green = env.observed_id(env.ids["green"])
    url = f"/inventory/servers/{green}/register"
    assert form_post(viewer, url, {"service_id": svc["id"]}).status_code == 403
    assert form_post(op, url, {"service_id": svc["id"]}, token="wrong").status_code == 403
    no_origin = op.client.post(
        url, data={"service_id": svc["id"], "csrf_token": csrf_of(op)}, follow_redirects=False
    )
    assert no_origin.status_code == 403
    blank = form_post(op, url, {"service_id": ""})
    assert blank.status_code == 422 and 'role="alert"' in blank.text
    other = env.make_service("app02", project=uuid4())
    mismatch = form_post(op, url, {"service_id": other["id"]})
    assert mismatch.status_code == 409 and "project" in mismatch.text.lower()
    assert op.get("/api/v1/managed-vms").json()["items"] == []
    denied = env.auth.sql("SELECT count(*) FROM audit_event WHERE action = 'authz.denied'")
    assert denied[0][0] >= 1  # the viewer's attempt is audited like an API denial


def test_gone_server_cannot_be_registered(env: Env) -> None:
    env.fake.keep_tombstones = False
    env.fake.delete_server(env.ids["green"])
    env.sync(kind="full")
    env.make_service()
    green = env.observed_id(env.ids["green"])
    r = page(env.users["operator"], f"/inventory/servers/{green}")
    assert "Register as managed VM" not in r.text and "Showing its last known state" in r.text


# --- services ---------------------------------------------------------------------------------------------------------


def test_services_list_and_create_by_form(env: Env) -> None:
    op, viewer = env.users["operator"], env.users["viewer"]
    assert "No services yet." in page(op, "/services").text
    assert "Create a service" in page(op, "/services").text
    assert "Create a service" not in page(viewer, "/services").text
    r = form_post(
        op,
        "/services",
        {
            "name": "Billing",
            "slug": "billing",
            "project_connection_id": str(env.project),
            "owner_contact": "",
        },
    )
    assert r.status_code == 303
    listing = page(op, "/services?notice=service-created")
    assert "Billing" in listing.text and "Service created." in listing.text
    assert [s["slug"] for s in op.get("/api/v1/services").json()["items"]] == ["billing"]
    dup = form_post(
        op,
        "/services",
        {"name": "Billing 2", "slug": "billing", "project_connection_id": str(env.project)},
    )
    assert (
        dup.status_code == 409
        and "Slug already in use" in dup.text
        and 'value="Billing 2"' in dup.text
    )
    bad = form_post(
        op,
        "/services",
        {"name": "X", "slug": "Bad Slug", "project_connection_id": str(env.project)},
    )
    assert bad.status_code == 422
    assert (
        form_post(
            op, "/services", {"name": "X", "slug": "x", "project_connection_id": "nope"}
        ).status_code
        == 422
    )
    assert (
        form_post(
            viewer,
            "/services",
            {"name": "X", "slug": "x", "project_connection_id": str(env.project)},
        ).status_code
        == 403
    )
    assert (
        env.auth.sql("SELECT count(*) FROM audit_event WHERE action = 'service.create'")[0][0] == 1
    )


# --- auth pages and step-up -------------------------------------------------------------------------------------------


def test_login_totp_and_enrol_pages_are_labelled_forms(env: Env) -> None:
    anon = env.auth.client()
    r = anon.get("/login")
    assert r.status_code == 200
    for field in ("username", "password", "totp_code"):
        assert f'<label for="{field}">' in r.text and f'id="{field}"' in r.text
    assert 'name="csrf_token"' in r.text and "<nav" not in r.text  # bare layout, no navigation
    link = env.auth.create_user("newbie", [("operator", "global")])
    enrol = anon.get(f"/enrol/{link}")
    assert 'for="password_confirm"' in enrol.text and "Welcome, newbie" in enrol.text
    c, _ = env.auth.user_client("totpuser", [("approver", "global")], totp=False)
    # an approver without TOTP is held on the enrolment page: no navigation, enrolment form
    t = c.get("/account/totp")
    assert t.status_code == 200 and "Generate a key" in t.text and "<nav" not in t.text
    assert c.get("/inventory", follow_redirects=False).headers["location"] == "/account/totp"


def test_stepup_page_issues_a_confirmation_for_one_action_and_target(env: Env) -> None:
    c, secret = env.auth.user_client("boss", [("admin", "global")])
    assert secret
    anon_view = c.get("/account/stepup")
    assert anon_view.status_code == 200 and "Nothing to confirm" in anon_view.text
    form = c.get("/account/stepup", params={"action": "approval.decide", "target_id": "t1"})
    assert 'name="totp_code"' in form.text and 'name="action" value="approval.decide"' in form.text
    token = csrf_of(Session(c, uuid4()))
    h = {"Origin": ORIGIN}
    bad = c.post(
        "/account/stepup",
        headers=h,
        data={
            "csrf_token": token,
            "action": "approval.decide",
            "target_id": "t1",
            "password": "wrong password!",
            "totp_code": env.auth.code(secret),
        },
    )
    assert bad.status_code == 401 and "Invalid password or code." in bad.text
    env.auth.clock.advance()
    ok = c.post(
        "/account/stepup",
        headers=h,
        data={
            "csrf_token": token,
            "action": "approval.decide",
            "target_id": "t1",
            "password": PASSWORD,
            "totp_code": env.auth.code(secret),
        },
    )
    assert ok.status_code == 200 and "Confirmation id" in ok.text and "5 minutes" in ok.text
    forged = c.post(
        "/account/stepup",
        headers=h,
        data={"csrf_token": "x", "action": "a", "target_id": "b", "password": PASSWORD},
    )
    assert forged.status_code == 403
