# ruff: noqa: F811
"""Blue's SSH host key (ADR-0006 "Blue", api-design.md 3.3) against PostgreSQL: registration queues a
``host_key_scan`` run (api as ``ovlm_api``), the worker's definition (as ``ovlm_worker``) scans the VM's fixed
address from the inventory (``ssh-keyscan`` replaced by a double) and records the fingerprint, an operator confirms
it in a human session, and a plan is refused until then."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from ovlm.automation.hostkeys import PublicKey, parse_public_key
from ovlm.registry.host_key_scan import HostKeyScanDefinition, preferred
from ovlm.workflow.engine import WorkflowEngine
from ovlm.workflow.registry import Registry
from tests.integration.auth_support import env as auth_env  # noqa: F401
from tests.integration.test_auth_authz import bearer, mint_token
from tests.integration.test_registry_api import Env, env  # noqa: F401
from tests.integration.test_ui_pages import form_post, page
from tests.integration.workflow.conftest import TEST_CONFIG


def _key(kind: str = "ed25519") -> PublicKey:
    priv: Any = (
        ed25519.Ed25519PrivateKey.generate()
        if kind == "ed25519"
        else ec.generate_private_key(ec.SECP256R1())
    )
    line = priv.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    return parse_public_key(line.decode())


class Guest:
    """``ssh-keyscan`` double: what answers at each address."""

    def __init__(self) -> None:
        self.keys: dict[str, list[PublicKey]] = {}
        self.scanned: list[tuple[str, int]] = []

    def keyscan(self, host: str, port: int) -> list[PublicKey]:
        self.scanned.append((host, port))
        return list(self.keys.get(host, []))


def _drive(env: Env, guest: Guest) -> None:
    eng = WorkflowEngine(
        env.worker, Registry([HostKeyScanDefinition(env.worker, guest.keyscan)]), TEST_CONFIG
    )
    for _ in range(20):
        eng.run_once()
        if (
            env.auth.sql(
                "SELECT count(*) FROM workflow_run WHERE kind = 'host_key_scan' AND finished_at IS NULL"
            )[0][0]
            == 0
        ):
            return
    raise AssertionError("scan runs did not finish")


def _register(env: Env) -> dict[str, Any]:
    svc = env.make_service()
    r = env.client.post(
        f"/api/v1/services/{svc['id']}/managed-vms",
        json={"observed_server_id": env.observed_id(env.ids["blue"])},
    )
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def _confirm(env: Env, vm_id: str, fingerprint: str) -> Any:
    return env.client.post(
        f"/api/v1/managed-vms/{vm_id}/host-key/confirm", json={"fingerprint": fingerprint}
    )


def test_registration_scans_and_the_operator_confirms(env: Env) -> None:
    guest = Guest()
    ed, ecdsa = _key("ed25519"), _key("ecdsa")
    guest.keys["10.0.0.5"] = [ecdsa, ed]
    vm = _register(env)
    run = vm["host_key_scan_run"]
    assert run["state"] == "requested" and vm["ssh_host_key_fingerprint"] is None
    assert _confirm(env, vm["id"], ed.fingerprint).json()["code"] == "host-key-not-scanned"

    _drive(env, guest)
    assert guest.scanned == [("10.0.0.5", 22)]  # the fixed address of the port carrying the FIP
    got = env.client.get(f"/api/v1/managed-vms/{vm['id']}").json()
    assert got["ssh_host_key_fingerprint"] == ed.fingerprint  # ed25519 preferred
    assert got["host_key_confirmed_at"] is None
    [state] = env.auth.sql("SELECT state FROM workflow_run WHERE id = :i", i=run["id"])
    assert state[0] == "completed"

    wrong = _confirm(env, vm["id"], ecdsa.fingerprint)
    assert wrong.status_code == 409 and wrong.json()["code"] == "host-key-mismatch"
    assert _confirm(env, vm["id"], "not-a-fingerprint").status_code == 422
    ok = _confirm(env, vm["id"], ed.fingerprint)
    assert ok.status_code == 200, ok.text
    assert (
        ok.json()["host_key_confirmed_by"] == str(env.operator_id)
        and ok.json()["already_confirmed"] is False
    )
    assert _confirm(env, vm["id"], ed.fingerprint).json()["already_confirmed"] is True

    rows = env.auth.sql(
        "SELECT action, result, principal_type, after FROM audit_event WHERE target_type = 'managed_vm_host_key' "
        "ORDER BY id"
    )
    assert [(r.action, r.result, r.principal_type) for r in rows] == [
        ("managed_vm.host_key_scan", "success", "worker"),
        ("managed_vm.host_key_confirm", "success", "human"),
    ]
    assert rows[1].after["fingerprint"] == ed.fingerprint


def test_a_rescan_never_replaces_a_confirmed_key(env: Env) -> None:
    guest = Guest()
    first = _key()
    guest.keys["10.0.0.5"] = [first]
    vm = _register(env)
    _drive(env, guest)
    assert _confirm(env, vm["id"], first.fingerprint).status_code == 200

    guest.keys["10.0.0.5"] = [first]  # same key: the re-scan succeeds and keeps the confirmation
    r = env.client.post(f"/api/v1/managed-vms/{vm['id']}/host-key-scans")
    assert r.status_code == 202 and r.json()["already_pending"] is False
    _drive(env, guest)
    assert env.client.get(f"/api/v1/managed-vms/{vm['id']}").json()["host_key_confirmed_at"]

    other = _key()  # something else answers now
    guest.keys["10.0.0.5"] = [other]
    run = env.client.post(f"/api/v1/managed-vms/{vm['id']}/host-key-scans").json()["run"]
    _drive(env, guest)
    got = env.client.get(f"/api/v1/managed-vms/{vm['id']}").json()
    assert got["ssh_host_key_fingerprint"] == first.fingerprint and got["host_key_confirmed_at"]
    [r2] = env.auth.sql(
        "SELECT r.state, s.error->>'reason' AS reason FROM workflow_run r JOIN workflow_step s ON s.run_id = r.id "
        "WHERE r.id = :i", i=run["id"],
    )  # fmt: skip
    assert r2.state == "failed" and "host key changed" in r2.reason
    failed = env.auth.sql(
        "SELECT result FROM audit_event WHERE action = 'managed_vm.host_key_scan' ORDER BY id"
    )
    assert [f.result for f in failed][-1] == "failure"


def test_an_unreachable_vm_fails_the_scan_with_a_reason(env: Env) -> None:
    vm = _register(env)
    _drive(env, Guest())
    [r] = env.auth.sql(
        "SELECT r.state, s.error->>'reason' AS reason FROM workflow_run r JOIN workflow_step s ON s.run_id = r.id "
        "WHERE r.id = :i", i=vm["host_key_scan_run"]["id"],
    )  # fmt: skip
    assert r.state == "failed" and r.reason.startswith("unreachable")


def test_confirmation_needs_an_operator_in_a_human_session(env: Env) -> None:
    guest = Guest()
    key = _key()
    guest.keys["10.0.0.5"] = [key]
    vm = _register(env)
    _drive(env, guest)

    env.as_("viewer")
    assert _confirm(env, vm["id"], key.fingerprint).status_code == 403
    assert env.client.post(f"/api/v1/managed-vms/{vm['id']}/host-key-scans").status_code == 403
    env.as_("operator")
    raw = mint_token(env.auth, env.client.client, "operate")
    anon = env.auth.client()
    r = anon.post(
        f"/api/v1/managed-vms/{vm['id']}/host-key/confirm",
        json={"fingerprint": key.fingerprint},
        headers=bearer(raw),
    )
    assert r.status_code == 403  # a token can never vouch for a host key
    assert _confirm(env, str(uuid4()), key.fingerprint).status_code == 404
    assert env.client.get(f"/api/v1/managed-vms/{vm['id']}").json()["host_key_confirmed_at"] is None


def test_the_preferred_key_is_ed25519() -> None:
    ed, ecdsa = _key("ed25519"), _key("ecdsa")
    assert preferred([ecdsa, ed]) == ed and preferred([ecdsa]) == ecdsa and preferred([]) is None


@pytest.mark.parametrize("confirmed", [False, True])
def test_a_plan_needs_a_confirmed_host_key(env: Env, confirmed: bool) -> None:
    from sqlalchemy import text

    from ovlm.registry.errors import DomainError
    from ovlm.renewal.config import RenewalConfig
    from ovlm.renewal.plans import resolve_plan

    guest = Guest()
    key = _key()
    guest.keys["10.0.0.5"] = [key]
    vm = _register(env)
    _drive(env, guest)
    if confirmed:
        assert _confirm(env, vm["id"], key.fingerprint).status_code == 200
    with env.api.connect() as c:
        with pytest.raises(DomainError) as exc:
            resolve_plan(c, vm["id"], RenewalConfig(), policy_row={})
        c.execute(text("SELECT 1"))
    # unconfirmed: refused for the host key; confirmed: it gets past it (and stops at the missing profile)
    assert exc.value.code == ("no-profile" if confirmed else "host-key-unconfirmed")


# --- review IS-3: one address rule for the scan and the renewal ---------------------------------------------------


def _second_fip_port(env: Env, ip: str = "10.0.0.9") -> tuple[str, str]:
    """Blue gets a second port with its own floating IP. Returns ``(port, fip)``."""
    net = env.fake.get_port(env.ids["port"]).network_id
    ext = env.fake.get_floating_ip(env.ids["fip"]).floating_network_id
    assert net is not None and ext is not None
    port = env.fake.add_port(net, device_id=env.ids["blue"], ip=ip)
    fip = env.fake.add_floating_ip(ext, address="192.0.2.20")
    env.fake.update_floating_ip(fip, port)
    env.sync(kind="full")
    return port, fip


def _profile(env: Env, service_id: str, floating_ip_id: str) -> None:
    import json

    profile, version = str(uuid4()), str(uuid4())
    env.auth.sql(
        "INSERT INTO profile (id, service_id, name, latest_version) VALUES (CAST(:i AS uuid), CAST(:s AS uuid), "
        "'p', 1)", i=profile, s=service_id,
    )  # fmt: skip
    env.auth.sql(
        "INSERT INTO profile_version (id, profile_id, number, spec, spec_hash) VALUES (CAST(:i AS uuid), "
        "CAST(:p AS uuid), 1, CAST(:s AS jsonb), :h)",
        i=version, p=profile, s=json.dumps({"cutover": {"floating_ip_id": floating_ip_id}}), h="0" * 64,
    )  # fmt: skip


def _scan_evidence(env: Env, run_id: str) -> Any:
    [row] = env.auth.sql(
        "SELECT evidence, error FROM workflow_step WHERE run_id = CAST(:r AS uuid)", r=run_id
    )
    return row


def test_is3_the_scan_targets_the_service_fip_port_as_the_renewal_does(env: Env) -> None:
    port2, fip2 = _second_fip_port(env)
    # the profile's service FIP is on the port that sorts last by id: before IS-3 the scan took the first one
    service_port, service_fip, address = max(
        (env.ids["port"], env.ids["fip"], "10.0.0.5"), (port2, fip2, "10.0.0.9")
    )
    guest = Guest()
    key = _key()
    guest.keys[address] = [key]
    svc = env.make_service()
    _profile(env, svc["id"], service_fip)
    r = env.client.post(
        f"/api/v1/services/{svc['id']}/managed-vms",
        json={"observed_server_id": env.observed_id(env.ids["blue"])},
    )
    assert r.status_code == 201, r.text
    vm = r.json()
    _drive(env, guest)
    assert guest.scanned == [(address, 22)]
    ev = _scan_evidence(env, vm["host_key_scan_run"]["id"]).evidence
    assert (ev["port_id"], ev["floating_ip_id"], ev["address"], ev["target_source"]) == (
        service_port, service_fip, address, "profile",
    )  # fmt: skip
    [audit] = env.auth.sql(
        "SELECT after FROM audit_event WHERE action = 'managed_vm.host_key_scan' ORDER BY id DESC LIMIT 1"
    )
    assert audit.after["port_id"] == service_port and audit.after["address"] == address


def test_is3_without_a_profile_several_fip_ports_are_ambiguous(env: Env) -> None:
    _second_fip_port(env)
    guest = Guest()
    guest.keys["10.0.0.5"] = guest.keys["10.0.0.9"] = [_key()]
    vm = _register(env)
    _drive(env, guest)
    assert guest.scanned == []  # nothing was contacted
    err = _scan_evidence(env, vm["host_key_scan_run"]["id"]).error
    assert "several ports of this VM carry a floating IP" in err["reason"]


def test_is3_the_scan_uses_fixed_ips_0_not_the_first_ipv4(env: Env) -> None:
    from dataclasses import replace

    pid = env.ids["port"]
    env.fake._ports[pid] = replace(  # noqa: SLF001 - a dual-stack port, IPv6 listed first
        env.fake._ports[pid],  # noqa: SLF001
        fixed_ips=(("2001:db8::5", "sub-6"), ("10.0.0.5", "sub-1")),
    )
    env.sync(kind="full")
    guest = Guest()
    guest.keys["2001:db8::5"] = [_key()]
    vm = _register(env)
    _drive(env, guest)
    assert guest.scanned == [("2001:db8::5", 22)]  # what the renewal's blue_ref uses: fixed_ips[0]
    ev = _scan_evidence(env, vm["host_key_scan_run"]["id"]).evidence
    assert ev["port_id"] == pid and ev["target_source"] == "only_fip_port"


def test_ui_confirm_makes_the_operator_paste_the_fingerprint(env: Env) -> None:
    """Review IS-2 (SF-10): the confirm form never shows or prefills the scanned fingerprint. The operator pastes the
    one read on the VM and says where; a mismatch is refused, the source is audited, and a viewer cannot confirm."""
    guest = Guest()
    ed, other = _key(), _key()
    guest.keys["10.0.0.5"] = [ed]
    vm = _register(env)
    _drive(env, guest)
    op, viewer = env.users["operator"], env.users["viewer"]
    server = env.observed_id(env.ids["blue"])
    detail = page(op, f"/inventory/servers/{server}")
    assert detail.status_code == 200 and "Confirm the SSH host key" in detail.text
    assert ed.fingerprint not in detail.text  # neither shown nor prefilled while unconfirmed
    [field] = [line for line in detail.text.splitlines() if 'name="fingerprint"' in line]
    assert "value=" not in field
    assert "Confirm the SSH host key" not in page(viewer, f"/inventory/servers/{server}").text

    url = f"/inventory/servers/{server}/host-key/confirm"
    assert (
        form_post(viewer, url, {"fingerprint": ed.fingerprint, "source": "console"}).status_code
        == 403
    )
    no_source = form_post(op, url, {"fingerprint": ed.fingerprint})
    assert no_source.status_code == 422 and "never copied from OVLM" in no_source.text
    wrong = form_post(op, url, {"fingerprint": other.fingerprint, "source": "console"})
    assert wrong.status_code == 409 and "does not match" in wrong.text
    assert ed.fingerprint not in wrong.text
    assert env.client.get(f"/api/v1/managed-vms/{vm['id']}").json()["host_key_confirmed_at"] is None

    done = form_post(op, url, {"fingerprint": f"  {ed.fingerprint} ", "source": "ssh-keygen"})
    assert done.status_code == 303 and done.headers["location"].endswith(
        "notice=host-key-confirmed"
    )
    after = page(op, done.headers["location"])
    assert ed.fingerprint in after.text and "Confirm the SSH host key" not in after.text
    [row] = env.auth.sql(
        "SELECT actor_id, project_scope, after FROM audit_event WHERE action = 'managed_vm.host_key_confirm'"
    )
    assert str(row.actor_id) == str(env.operator_id) and row.project_scope
    assert row.after["source"] == "ssh-keygen" and row.after["via"] == "ui"
    assert row.after["fingerprint"] == ed.fingerprint
