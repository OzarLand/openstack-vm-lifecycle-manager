# ruff: noqa: F811
"""The readiness section of the VM details page (E4-1): content, role-based controls, CSRF, escaping, audit."""

from __future__ import annotations

from uuid import uuid4

from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.test_readiness_api import good_spec, run_worker, setup_vm
from tests.integration.test_registry_api import Env
from tests.integration.test_registry_api import env as env  # noqa: F401
from tests.integration.test_ui_pages import form_post, page


def detail_url(env: Env, server: str = "blue") -> str:
    return f"/inventory/servers/{env.observed_id(env.ids[server])}"


def test_unassessed_managed_vm_shows_the_prompt_and_the_button_for_operators_only(env: Env) -> None:
    setup_vm(env)
    html = page(env.client, detail_url(env)).text
    assert 'id="readiness"' in html and "Not assessed yet" in html and "Assess readiness" in html
    assert (
        'action="/inventory/servers/' in html
        and "/assess" in html
        and "No code runs on the VM" in html
    )
    env.as_("viewer")
    seen = page(env.client, detail_url(env)).text
    assert "Not assessed yet" in seen and "Assess readiness" not in seen and "/assess" not in seen


def test_not_managed_servers_have_no_readiness_section(env: Env) -> None:
    html = page(env.client, detail_url(env, "green")).text
    assert 'id="readiness"' not in html


def test_request_then_result_is_shown_with_evidence_and_recommendations(env: Env) -> None:
    vm = setup_vm(env)
    url = detail_url(env)
    server_id = url.rsplit("/", 1)[1]
    r = form_post(env.client, f"{url}/assess", {})
    assert r.status_code == 303 and r.headers["location"].startswith(
        f"{url}?notice=assessment-requested"
    )
    waiting = page(env.client, url, params={"notice": "assessment-requested"}).text
    assert "Readiness assessment requested" in waiting and "waiting for the worker" in waiting
    again = form_post(
        env.client, f"{url}/assess", {}
    )  # a second click does not pile up a second run
    assert again.status_code == 303
    assert env.auth.sql("SELECT count(*) FROM workflow_run WHERE kind='readiness'")[0][0] == 1

    run_worker(env)
    html = page(env.client, url).text
    assert '<span class="badge ok">Ready</span>' in html and "Assess again" in html
    assert "no blocker failed and none is unknown" in html and "applicable checks pass" in html
    for key in (
        "data.separate_volume",
        "network.floating_ip",
        "automation.pinned_sha",
        "validation.health_check_defined",
    ):
        assert key in html
    assert (
        "Persistent data separation" in html
        and "External services" in html
        and "Validation capability" in html
    )
    assert "Do this:" in html  # the unknown attestation check says what to do
    assert (
        "<summary>Evidence</summary>" in html and env.ids["vol"] in html
    )  # evidence names the volume
    assert "ovlm-secret" not in html
    rows = env.auth.sql(
        "SELECT actor_id, result FROM audit_event WHERE action = 'readiness.request' ORDER BY id"
    )
    assert len(rows) == 2 and all(r[0] == env.operator_id for r in rows)
    assert server_id in url and vm["id"]


def test_not_ready_names_the_failed_blockers_and_escapes_evidence(env: Env) -> None:
    setup_vm(env, good_spec(env, flavor="<script>alert(1)</script>"))
    url = detail_url(env)
    form_post(env.client, f"{url}/assess", {})
    run_worker(env)
    html = page(env.client, url).text
    assert '<span class="badge err">Not ready</span>' in html
    assert "at least one blocker failed" in html and "platform.flavor_resolvable" in html
    assert (
        "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    )


def test_post_needs_csrf_and_the_operator_role(env: Env) -> None:
    setup_vm(env)
    url = detail_url(env)
    assert form_post(env.client, f"{url}/assess", {}, token="wrong").status_code in (400, 403)
    env.as_("viewer")
    assert form_post(env.client, f"{url}/assess", {}).status_code == 403
    assert env.auth.sql("SELECT count(*) FROM workflow_run WHERE kind='readiness'")[0][0] == 0
    env.as_("operator")
    assert form_post(env.client, f"/inventory/servers/{uuid4()}/assess", {}).status_code == 404
    assert (
        form_post(env.client, f"{detail_url(env, 'green')}/assess", {}).status_code == 404
    )  # not a managed VM
    assert form_post(env.client, "/inventory/servers/not-a-uuid/assess", {}).status_code == 404


def test_a_run_that_did_not_finish_is_said_so(env: Env) -> None:
    setup_vm(env)
    url = detail_url(env)
    form_post(env.client, f"{url}/assess", {})
    with env.worker.begin() as c:
        from sqlalchemy import text

        c.execute(
            text(
                "UPDATE workflow_run SET state = 'failed', finished_at = now() WHERE kind = 'readiness'"
            )
        )
    html = page(env.client, url).text
    assert "did not finish (failed)" in html and "Not assessed yet" in html
