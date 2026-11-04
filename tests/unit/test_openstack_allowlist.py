"""Write allowlist and fence hook (SEC-R-7, ADR-0003) and the SDK write backend over a canned transport.

Three levels: the pure rule function; a real keystoneauth session whose transport records what is actually sent;
the openstacksdk connection used by ``sdk_write`` (its proxies are Adapters on that same session). No real cloud:
"unit tested" only."""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import pytest
import requests
from keystoneauth1 import adapter, session
from keystoneauth1.identity import v3
from openstack import connection
from requests.adapters import BaseAdapter

from ovlm.openstack import errors
from ovlm.openstack.allowlist import (
    RULES,
    SERVER_ACTIONS,
    TAG_MANAGED,
    WRITE_OPERATIONS,
    GateBinding,
    classify_write,
    install_write_guard,
)
from ovlm.openstack.guard import install_read_only_guard
from ovlm.openstack.ownership import InMemoryOwnershipRegistry, ResourceKind, run_tag
from ovlm.openstack.sdk_write import SdkWriteBackend, error_message
from ovlm.openstack.types import CreateServerSpec
from ovlm.openstack.write import GuardedWriteClient
from ovlm.workflow import FenceLost

AUTH_URL = "http://keystone.invalid/v3"
NOVA = "http://nova.invalid/v2.1"
CINDER = "http://cinder.invalid/v3/p1"
NEUTRON = "http://neutron.invalid"
RUN = str(uuid.UUID(int=0xBEEF))
SID = "11111111-1111-1111-1111-111111111111"
VID = "22222222-2222-2222-2222-222222222222"
FID = "33333333-3333-3333-3333-333333333333"
PID = "44444444-4444-4444-4444-444444444444"

C = {"endpoint_filter": {"service_type": "compute"}}
N = {"endpoint_filter": {"service_type": "network"}}
B = {"endpoint_filter": {"service_type": "block-storage"}}


def kw(base: dict[str, Any], body: Any = None) -> dict[str, Any]:
    return {**base, "json": body} if body is not None else dict(base)


CREATE_BODY = {
    "server": {"name": "g", "imageRef": "i", "flavorRef": "f", "networks": [{"uuid": "n"}],
               "tags": [TAG_MANAGED, run_tag(RUN)]}
}  # fmt: skip

# --- level 1: the rule function -----------------------------------------------------------------------------

ALLOWED = [
    ("POST", "/servers", kw(C, CREATE_BODY), "create_server"),
    ("DELETE", f"/servers/{SID}", C, "delete_server"),
    ("POST", f"servers/{SID}/action", kw(C, {"os-stop": None}), "stop_server"),
    ("POST", f"/servers/{SID}/action", kw(C, {"os-start": None}), "start_server"),
    ("POST", f"/servers/{SID}/action", kw(C, {"lock": {"locked_reason": "ovlm:x"}}), "lock_server"),
    ("POST", f"/servers/{SID}/action", kw(C, {"unlock": None}), "unlock_server"),
    ("POST", f"/servers/{SID}/action", kw(C, {"os-getConsoleOutput": {}}), "get_console_output"),
    ("PUT", f"/servers/{SID}/tags/ovlm%3Amanaged", C, "add_server_tag"),
    ("POST", f"/servers/{SID}/os-volume_attachments", kw(C, {"volumeAttachment": {"volumeId": VID}}),
     "attach_volume"),
    ("DELETE", f"/servers/{SID}/os-volume_attachments/{VID}", C, "detach_volume"),
    ("PUT", f"/floatingips/{FID}", kw(N, {"floatingip": {"port_id": PID}}), "update_floating_ip"),
    ("PUT", f"/floatingips/{FID}", kw(N, {"floatingip": {"port_id": PID, "fixed_ip_address": "10.0.0.6"}}),
     "update_floating_ip"),
    ("PUT", f"/floatingips/{FID}/tags/ovlm%3Amanaged", N, "add_floating_ip_tag"),
    ("POST", f"/volumes/{VID}/metadata", kw(B, {"metadata": {"ovlm.managed": "true"}}), "merge_volume_metadata"),
    ("POST", f"/volumes/{VID}/metadata", kw({"endpoint_filter": {"service_type": "volumev3"}},
                                            {"metadata": {"ovlm.managed": "true"}}), "merge_volume_metadata"),
]  # fmt: skip


@pytest.mark.parametrize(("method", "url", "kwargs", "op"), ALLOWED)
def test_allowed_writes_are_classified(
    method: str, url: str, kwargs: dict[str, Any], op: str
) -> None:
    assert classify_write(method, url, kwargs) == op
    assert op in WRITE_OPERATIONS


def test_reads_and_the_token_request_pass_without_an_operation() -> None:
    assert classify_write("GET", f"/servers/{SID}", C) is None
    assert classify_write("HEAD", "/", {}) is None
    assert classify_write("POST", f"{AUTH_URL}/auth/tokens", {"authenticated": False}) is None


REFUSED = {
    # SEC-R-7 explicit list
    "delete volume": ("DELETE", f"/volumes/{VID}", B),
    "create volume": ("POST", "/volumes", kw(B, {"volume": {"size": 1}})),
    "volume action (force delete/detach, reset)": ("POST", f"/volumes/{VID}/action", kw(B, {"os-force_detach": {}})),
    "delete snapshot": ("DELETE", f"/snapshots/{VID}", B),
    "allocate fip": ("POST", "/floatingips", kw(N, {"floatingip": {"floating_network_id": "x"}})),
    "release fip": ("DELETE", f"/floatingips/{FID}", N),
    "security group create": ("POST", "/security-groups", kw(N, {"security_group": {}})),
    "security group update": ("PUT", f"/security-groups/{SID}", kw(N, {"security_group": {}})),
    "security group rule": ("POST", "/security-group-rules", kw(N, {"security_group_rule": {}})),
    "security group rule delete": ("DELETE", f"/security-group-rules/{SID}", N),
    "port create": ("POST", "/ports", kw(N, {"port": {}})),
    "port delete": ("DELETE", f"/ports/{PID}", N),
    "port update": ("PUT", f"/ports/{PID}", kw(N, {"port": {"port_security_enabled": False}})),
    # server actions not listed
    "forceDelete": ("POST", f"/servers/{SID}/action", kw(C, {"forceDelete": None})),
    "rebuild": ("POST", f"/servers/{SID}/action", kw(C, {"rebuild": {"imageRef": "x"}})),
    "createImage": ("POST", f"/servers/{SID}/action", kw(C, {"createImage": {"name": "x"}})),
    "reboot": ("POST", f"/servers/{SID}/action", kw(C, {"reboot": {"type": "HARD"}})),
    "two actions in one body": ("POST", f"/servers/{SID}/action", kw(C, {"os-stop": None, "forceDelete": None})),
    "action without body": ("POST", f"/servers/{SID}/action", C),
    # replace-all and delete forms of markers (SEC-R-24)
    "server tags replace-all": ("PUT", f"/servers/{SID}/tags", kw(C, {"tags": []})),
    "server tag delete": ("DELETE", f"/servers/{SID}/tags/ovlm%3Amanaged", C),
    "server tags delete-all": ("DELETE", f"/servers/{SID}/tags", C),
    "foreign server tag": ("PUT", f"/servers/{SID}/tags/team%3Aweb", C),
    "server metadata replace": ("PUT", f"/servers/{SID}/metadata", kw(C, {"metadata": {}})),
    "server metadata merge": ("POST", f"/servers/{SID}/metadata", kw(C, {"metadata": {"a": "b"}})),
    "volume metadata replace": ("PUT", f"/volumes/{VID}/metadata", kw(B, {"metadata": {"ovlm.managed": "true"}})),
    "volume metadata foreign key": ("POST", f"/volumes/{VID}/metadata", kw(B, {"metadata": {"owner": "x"}})),
    "volume metadata key delete": ("DELETE", f"/volumes/{VID}/metadata/owner", B),
    "fip tags replace-all": ("PUT", f"/floatingips/{FID}/tags", kw(N, {"tags": []})),
    # body predicates
    "create without tags": ("POST", "/servers", kw(C, {"server": {"name": "g", "networks": [{"uuid": "n"}]}})),
    "create without run tag": ("POST", "/servers", kw(C, {"server": {"tags": [TAG_MANAGED], "networks": [{}]}})),
    "create with block devices": ("POST", "/servers", kw(C, {"server": {
        **CREATE_BODY["server"], "block_device_mapping_v2": [{"source_type": "blank"}]}})),
    "create several": ("POST", "/servers", kw(C, {"server": {**CREATE_BODY["server"], "max_count": 3}})),
    # SEC-C-5: only allow-listed create keys
    **{f"create with {k}": ("POST", "/servers", kw(C, {"server": {**CREATE_BODY["server"], k: v}}))
       for k, v in (("adminPass", "chosen"), ("config_drive", True), ("OS-DCF:diskConfig", "MANUAL"),
                    ("return_reservation_id", True), ("trusted_image_certificates", ["x"]),
                    ("min_count", 1), ("block_device_mapping", []), ("personality", []),
                    ("hostname", "h"), ("host", "compute-1"), ("hypervisor_hostname", "h"))},
    "create with an unknown top-level key": ("POST", "/servers", kw(C, {**CREATE_BODY, "extra": {}})),
    "create with auto network": ("POST", "/servers", kw(C, {"server": {**CREATE_BODY["server"], "networks": "auto"}})),
    "attach with delete_on_termination": ("POST", f"/servers/{SID}/os-volume_attachments",
        kw(C, {"volumeAttachment": {"volumeId": VID, "delete_on_termination": True}})),
    "attachment update (swap, d_o_t)": ("PUT", f"/servers/{SID}/os-volume_attachments/{VID}",
        kw(C, {"volumeAttachment": {"volumeId": VID}})),
    "fip disassociate": ("PUT", f"/floatingips/{FID}", kw(N, {"floatingip": {"port_id": None}})),
    "fip other field": ("PUT", f"/floatingips/{FID}", kw(N, {"floatingip": {"port_id": PID, "description": "x"}})),
    # transport shape
    "absolute url": ("DELETE", f"{NOVA}/servers/{SID}", C),
    "query string": ("DELETE", f"/servers/{SID}?force=1", C),
    "path traversal": ("DELETE", f"/servers/{SID}/../../volumes/{VID}", C),
    "encoded traversal": ("PUT", f"/servers/{SID}/tags/ovlm%3A..%2F..%2Fx", C),
    "wrong service for path": ("DELETE", f"/servers/{SID}", B),
    "no endpoint filter": ("DELETE", f"/servers/{SID}", {}),
    "raw data body": ("POST", f"/servers/{SID}/action", {**C, "data": '{"os-stop": null}'}),
    "non-uuid id": ("DELETE", "/servers/detail", C),
    "patch": ("PATCH", f"/servers/{SID}", kw(C, {})),
    "identity write": ("POST", "/users", {"endpoint_filter": {"service_type": "identity"}}),
    "token request via a proxy": ("POST", f"{AUTH_URL}/auth/tokens",
                                  {"authenticated": False, "endpoint_filter": {"service_type": "identity"}}),
}  # fmt: skip


def test_create_accepts_every_allow_listed_key() -> None:
    full = {**CREATE_BODY["server"], "metadata": {"ovlm.role": "green"}, "availability_zone": "az1",
            "security_groups": [{"name": "sg"}], "key_name": "k", "user_data": "I2Nsb3Vk"}  # fmt: skip
    assert classify_write("POST", "/servers", kw(C, {"server": full})) == "create_server"
    hints = {"server": CREATE_BODY["server"], "os:scheduler_hints": {"group": SID}}
    assert classify_write("POST", "/servers", kw(C, hints)) == "create_server"


@pytest.mark.parametrize("case", list(REFUSED), ids=list(REFUSED))
def test_everything_else_is_refused(case: str) -> None:
    method, url, kwargs = REFUSED[case]
    with pytest.raises(errors.WriteNotAllowedError):
        classify_write(method, url, kwargs)


def test_the_allowlist_is_exactly_the_strategy_operations() -> None:
    """A change of this set is a security-relevant change: this test makes it visible in review."""
    assert {
        "create_server", "delete_server", "stop_server", "start_server", "lock_server", "unlock_server",
        "get_console_output", "add_server_tag", "attach_volume", "detach_volume", "update_floating_ip",
        "add_floating_ip_tag", "merge_volume_metadata",
    } == WRITE_OPERATIONS  # fmt: skip
    assert set(SERVER_ACTIONS) == {"os-stop", "os-start", "lock", "unlock", "os-getConsoleOutput"}
    assert len(RULES) == 9
    for rule in RULES:  # no rule ever deletes or creates a volume or a FIP
        if rule.method in {"DELETE", "POST"}:
            assert "volumes/" not in rule.path.pattern or rule.path.pattern.endswith("/metadata$")
            assert "floatingips" not in rule.path.pattern


# --- level 2: a real keystoneauth session ---------------------------------------------------------------------

_CATALOG = [
    {"type": t, "id": t, "name": t, "endpoints": [{"id": t + "e", "interface": "public", "region": "R1", "url": u}]}
    for t, u in (("compute", NOVA), ("block-storage", CINDER), ("volumev3", CINDER), ("network", NEUTRON))
]  # fmt: skip

NOVA_SERVER = {
    "id": SID, "name": "blue", "status": "ACTIVE", "OS-EXT-STS:vm_state": "active", "OS-EXT-STS:task_state": None,
    "tags": [TAG_MANAGED], "metadata": {}, "locked": False, "flavor": {"original_name": "m1"},
    "image": {"id": "img"}, "os-extended-volumes:volumes_attached": [],
}  # fmt: skip


class CannedCloud(BaseAdapter):
    """Stands in for the network: records what is actually sent and answers like the services would."""

    def __init__(self, compute_max: str = "2.100") -> None:
        super().__init__()
        self.sent: list[tuple[str, str, dict[str, str], Any]] = []
        self.compute_max = compute_max
        self.errors: dict[tuple[str, str], tuple[int, Any]] = {}

    def send(
        self, request: requests.PreparedRequest, *args: Any, **kwargs: Any
    ) -> requests.Response:
        method, url = str(request.method), str(request.url)
        raw = request.body
        body: Any = json.loads(raw) if isinstance(raw, (str, bytes)) and raw else None
        headers = {str(k): str(v) for k, v in request.headers.items()}
        self.sent.append((method, url, headers, body))
        path = urlparse(url).path
        resp = requests.Response()
        resp.status_code, resp.url, resp.request = 200, url, request
        resp.headers["Content-Type"] = "application/json"
        out: Any = {}
        if (method, path) in self.errors:
            resp.status_code, out = self.errors[(method, path)]
        elif method == "POST" and path.endswith("/auth/tokens"):
            resp.status_code = 201
            resp.headers["X-Subject-Token"] = "tok"
            out = {"token": {
                "methods": ["application_credential"], "expires_at": "2099-01-01T00:00:00.000000Z",
                "issued_at": "2026-01-01T00:00:00.000000Z",
                "user": {"id": "u", "name": "u", "domain": {"id": "d", "name": "d"}},
                "project": {"id": "p1", "name": "p", "domain": {"id": "d", "name": "d"}},
                "roles": [{"id": "r", "name": "member"}], "catalog": _CATALOG,
            }}  # fmt: skip
        elif path in ("/v2.1", "/v2.1/"):
            out = {"version": {"id": "v2.1", "status": "CURRENT", "version": self.compute_max,
                               "min_version": "2.1", "links": [{"rel": "self", "href": NOVA + "/"}]}}  # fmt: skip
        elif path in ("/v3/p1", "/v3/p1/", "/v3", "/v3/"):
            out = {"version": {"id": "v3.0", "status": "CURRENT", "version": "3.71", "min_version": "3.0",
                               "links": [{"rel": "self", "href": CINDER + "/"}]}}  # fmt: skip
        elif path in ("", "/"):
            out = {"versions": [{"id": "v2.0", "status": "CURRENT",
                                 "links": [{"rel": "self", "href": NEUTRON + "/v2.0/"}]}]}  # fmt: skip
        elif method == "POST" and path.endswith("/servers"):
            resp.status_code = 202
            out = {"server": {"id": SID, "adminPass": "not-logged", "links": []}}
        elif method == "GET" and path.endswith(f"/servers/{SID}"):
            out = {"server": NOVA_SERVER}
        elif method == "POST" and path.endswith("/action"):
            resp.status_code = 202
            if body and "os-getConsoleOutput" in body:
                resp.status_code, out = 200, {"output": "line1\nline2"}
        elif method == "PUT" and "/floatingips/" in path and "/tags/" not in path:
            port = (body or {}).get("floatingip", {}).get("port_id")
            out = {"floatingip": {"id": FID, "floating_ip_address": "192.0.2.10", "port_id": port,
                                  "floating_network_id": "ext", "status": "DOWN", "tags": [TAG_MANAGED]}}  # fmt: skip
        elif method in ("PUT", "DELETE") or (
            method == "POST" and path.endswith("/os-volume_attachments")
        ):
            resp.status_code = 202 if method != "PUT" else 201
        resp._content = json.dumps(out).encode()
        return resp

    def close(self) -> None:
        pass

    def writes(self) -> list[tuple[str, str]]:
        return [(m, urlparse(u).path) for m, u, _h, _b in self.sent if m not in ("GET", "HEAD")
                and not urlparse(u).path.endswith("/auth/tokens")]  # fmt: skip


class Gate:
    def __init__(self, cloud: CannedCloud) -> None:
        self.cloud = cloud
        self.checks: list[tuple[str, int]] = []
        self.refuse = False

    def __call__(self, action: str) -> None:
        self.checks.append((action, len(self.cloud.writes())))
        if self.refuse:
            raise FenceLost(action, "test")


def _session(cloud: CannedCloud) -> tuple[session.Session, GateBinding]:
    auth = v3.ApplicationCredential(
        auth_url=AUTH_URL, application_credential_id="id", application_credential_secret="s3cret"
    )
    sess = session.Session(auth=auth)
    sess.session.mount("http://", cloud)
    binding = GateBinding()
    install_write_guard(sess, binding)
    return sess, binding


def test_session_sends_an_allowed_write_after_the_gate() -> None:
    cloud = CannedCloud()
    sess, binding = _session(cloud)
    gate = Gate(cloud)
    compute = adapter.Adapter(session=sess, service_type="compute", interface="public")
    with binding.bind(gate):
        compute.post(f"/servers/{SID}/action", json={"os-stop": None})
    assert gate.checks == [("openstack:stop_server", 0)]  # checked while nothing had been sent yet
    assert cloud.writes() == [("POST", f"/v2.1/servers/{SID}/action")]


def test_session_refuses_without_sending() -> None:
    cloud = CannedCloud()
    sess, binding = _session(cloud)
    gate = Gate(cloud)
    compute = adapter.Adapter(session=sess, service_type="compute", interface="public")
    with binding.bind(gate):
        compute.get("/servers")  # authenticate
        with pytest.raises(errors.WriteNotAllowedError):
            compute.post(f"/servers/{SID}/action", json={"forceDelete": None})
    assert cloud.writes() == [] and gate.checks == []


def test_session_without_a_bound_gate_refuses_writes_but_reads() -> None:
    cloud = CannedCloud()
    sess, _binding = _session(cloud)
    compute = adapter.Adapter(session=sess, service_type="compute", interface="public")
    compute.get("/servers")
    with pytest.raises(errors.WriteNotAllowedError, match="no fence gate"):
        compute.post(f"/servers/{SID}/action", json={"os-stop": None})
    assert cloud.writes() == []


def test_session_lost_fence_sends_nothing() -> None:
    cloud = CannedCloud()
    sess, binding = _session(cloud)
    gate = Gate(cloud)
    gate.refuse = True
    compute = adapter.Adapter(session=sess, service_type="compute", interface="public")
    with binding.bind(gate), pytest.raises(FenceLost):
        compute.delete(f"/servers/{SID}")
    assert cloud.writes() == []


def test_one_gate_check_covers_exactly_one_send() -> None:
    seen: list[dict[str, Any]] = []

    class Stub:
        def request(self, url: str, method: str, **kwargs: Any) -> str:
            seen.append(kwargs)
            return "sent"

    stub = Stub()
    binding = GateBinding()
    install_write_guard(stub, binding)
    with binding.bind(lambda _a: None):
        stub.request(f"/servers/{SID}", "DELETE", **C, connect_retries=5, allow_reauth=True)
    stub.request("/servers", "GET", **C, connect_retries=5)
    assert seen[0]["connect_retries"] == 0 and seen[0]["status_code_retries"] == 0
    assert seen[0]["redirect"] is False and seen[0]["allow_reauth"] is False
    assert seen[1]["connect_retries"] == 5  # reads untouched


def test_guards_do_not_stack() -> None:
    cloud = CannedCloud()
    sess, binding = _session(cloud)
    with pytest.raises(errors.WriteNotAllowedError):
        install_write_guard(sess, binding)
    ro = session.Session()
    install_read_only_guard(ro)
    with pytest.raises(errors.WriteNotAllowedError):
        install_write_guard(ro, GateBinding())


def test_gate_binding_is_per_thread() -> None:
    import threading

    binding = GateBinding()
    seen: list[bool] = []
    with binding.bind(lambda _a: None):
        t = threading.Thread(target=lambda: seen.append(binding.bound))
        t.start()
        t.join()
        assert binding.bound
    assert seen == [False] and not binding.bound


# --- level 3: the SDK connection and the write backend ------------------------------------------------------


def _conn(cloud: CannedCloud) -> tuple[Any, GateBinding]:
    sess, binding = _session(cloud)
    return connection.Connection(session=sess, region_name="R1"), binding


def test_sdk_proxies_cannot_delete_or_create_volumes_or_fips() -> None:
    cloud = CannedCloud()
    conn, binding = _conn(cloud)
    with binding.bind(Gate(cloud)):
        calls: list[Callable[[], object]] = [
            lambda: conn.block_storage.delete_volume(VID),
            lambda: conn.block_storage.create_volume(size=1),
            lambda: conn.network.delete_ip(FID),
            lambda: conn.network.create_ip(floating_network_id="ext"),
            lambda: conn.network.delete_security_group(SID),
            lambda: conn.network.delete_port(PID),
            lambda: conn.compute.rebuild_server(SID, image="img"),
            lambda: conn.compute.set_server_metadata(SID, a="b"),
        ]
        for call in calls:
            with pytest.raises(errors.WriteNotAllowedError):
                call()
    assert cloud.writes() == []


def _backend(cloud: CannedCloud) -> tuple[SdkWriteBackend, Gate]:
    conn, binding = _conn(cloud)
    return SdkWriteBackend(conn, binding), Gate(cloud)


def test_backend_create_sends_tags_user_data_and_the_pinned_microversion() -> None:
    cloud = CannedCloud()
    backend, gate = _backend(cloud)
    spec = CreateServerSpec(
        name="ovlm-web-1", image_id="img", flavor_id="fl", network_id="net",
        tags=(TAG_MANAGED, run_tag(RUN)), metadata={"ovlm.role": "green"}, user_data="#cloud-config\n",
        security_group_names=("sg-1",), availability_zone="az1",
    )  # fmt: skip
    with backend.gate_binding.bind(gate):
        info = backend.create_server(spec)
    assert info.openstack_id == SID and info.status == "BUILD"
    method, url, headers, body = next(
        s for s in cloud.sent if s[0] == "POST" and s[1].endswith("/servers")
    )
    assert body["server"]["tags"] == [TAG_MANAGED, run_tag(RUN)]
    assert base64.b64decode(body["server"]["user_data"]) == b"#cloud-config\n"
    assert body["server"]["networks"] == [{"uuid": "net"}]
    assert "block_device_mapping_v2" not in body["server"]
    assert headers.get("OpenStack-API-Version") == "compute 2.79"
    assert gate.checks == [("openstack:create_server", 0)]
    assert "user_data" not in repr(spec) and "cloud-config" not in repr(spec)


def test_backend_operations_send_exactly_the_allowlisted_requests() -> None:
    cloud = CannedCloud()
    backend, gate = _backend(cloud)
    with backend.gate_binding.bind(gate):
        backend.stop_server(SID)
        backend.start_server(SID)
        backend.lock_server(SID, "ovlm:retained:r")
        backend.unlock_server(SID)
        backend.add_server_tag(SID, TAG_MANAGED)
        backend.attach_volume(SID, VID)
        backend.detach_volume(SID, VID)
        fip = backend.update_floating_ip(FID, PID)
        backend.add_floating_ip_tag(FID, TAG_MANAGED)
        backend.merge_volume_metadata(VID, {"ovlm.managed": "true"})
        out = backend.get_console_output(SID, 10)
        backend.delete_server(SID)
    assert fip.port_id == PID and out == "line1\nline2"
    assert cloud.writes() == [
        ("POST", f"/v2.1/servers/{SID}/action"),
        ("POST", f"/v2.1/servers/{SID}/action"),
        ("POST", f"/v2.1/servers/{SID}/action"),
        ("POST", f"/v2.1/servers/{SID}/action"),
        ("PUT", f"/v2.1/servers/{SID}/tags/ovlm%3Amanaged"),
        ("POST", f"/v2.1/servers/{SID}/os-volume_attachments"),
        ("DELETE", f"/v2.1/servers/{SID}/os-volume_attachments/{VID}"),
        ("PUT", f"/v2.0/floatingips/{FID}"),
        ("PUT", f"/v2.0/floatingips/{FID}/tags/ovlm%3Amanaged"),
        ("POST", f"/v3/p1/volumes/{VID}/metadata"),
        ("POST", f"/v2.1/servers/{SID}/action"),
        ("DELETE", f"/v2.1/servers/{SID}"),
    ]
    actions = [b for m, u, _h, b in cloud.sent if u.endswith("/action")]
    assert actions == [{"os-stop": None}, {"os-start": None}, {"lock": {"locked_reason": "ovlm:retained:r"}},
                       {"unlock": None}, {"os-getConsoleOutput": {"length": 10}}]  # fmt: skip
    assert [a for a, _ in gate.checks] == [
        "openstack:stop_server", "openstack:start_server", "openstack:lock_server", "openstack:unlock_server",
        "openstack:add_server_tag", "openstack:attach_volume", "openstack:detach_volume",
        "openstack:update_floating_ip", "openstack:add_floating_ip_tag", "openstack:merge_volume_metadata",
        "openstack:get_console_output", "openstack:delete_server",
    ]  # fmt: skip
    assert [n for _, n in gate.checks] == list(range(12))  # each check before its own send


@pytest.mark.parametrize(
    ("method", "path_suffix", "status", "body", "call", "cls"),
    [
        ("POST", "/action", 409, {"conflictingRequest": {"message": f"Instance {SID} is locked", "code": 409}},
         lambda b: b.stop_server(SID), errors.InstanceLockedError),
        ("PUT", f"/floatingips/{FID}", 404, {"NeutronError": {"type": "ExternalGatewayForFloatingIPNotFound",
         "message": "External network ext is not reachable from subnet sn. Therefore, cannot associate Port p "
                    "with a Floating IP.", "detail": ""}},
         lambda b: b.update_floating_ip(FID, PID), errors.FloatingIpNoRouterPathError),
        ("POST", "/os-volume_attachments", 400, {"badRequest": {"message": f"Invalid volume: volume {VID} "
         "already attached", "code": 400}}, lambda b: b.attach_volume(SID, VID), errors.VolumeAlreadyAttachedError),
        ("POST", "/servers", 403, {"forbidden": {"message": "Quota exceeded for instances", "code": 403}},
         lambda b: b.create_server(CreateServerSpec("g", "i", "f", network_id="n",
                                                    tags=(TAG_MANAGED, run_tag(RUN)))),
         errors.QuotaExceededError),
        ("DELETE", f"/servers/{SID}", 503, "Service Unavailable", lambda b: b.delete_server(SID), errors.ServerError),
    ],
)  # fmt: skip
def test_backend_translates_error_bodies(
    method: str, path_suffix: str, status: int, body: Any, call: Any, cls: type[Exception]
) -> None:
    cloud = CannedCloud()
    backend, gate = _backend(cloud)
    prefix = "/v2.0" if "floatingips" in path_suffix else "/v2.1"
    path = prefix + (path_suffix if path_suffix.startswith(("/servers", "/floatingips")) else f"/servers/{SID}"
                     + path_suffix)  # fmt: skip
    cloud.errors[(method, path)] = (status, body)
    with backend.gate_binding.bind(gate), pytest.raises(cls) as exc:
        call(backend)
    assert type(exc.value) is cls
    assert exc.value.status == status  # type: ignore[attr-defined]


def test_error_message_extraction() -> None:
    class R:
        def __init__(self, body: Any, text: str = "") -> None:
            self._b, self.text = body, text

        def json(self) -> Any:
            if self._b is None:
                raise ValueError("no json")
            return self._b

    assert error_message(R({"itemNotFound": {"message": "gone", "code": 404}})) == "gone"
    assert error_message(R({"NeutronError": {"message": "nope"}})) == "nope"
    assert error_message(R({"message": "flat"})) == "flat"
    assert error_message(R(None, "x" * 900)) == "x" * 500


def test_backend_refuses_a_cloud_below_the_pinned_microversion_before_any_write() -> None:
    cloud = CannedCloud(compute_max="2.72")
    backend, gate = _backend(cloud)
    with backend.gate_binding.bind(gate), pytest.raises(errors.UnsupportedCloudError):
        backend.stop_server(SID)
    assert cloud.writes() == [] and gate.checks == []


def test_backend_records_write_microversions() -> None:
    backend, _gate = _backend(CannedCloud())
    v = backend.write_microversions()
    assert v["compute_write"] == "2.79" and v["compute_max"] == "2.100"


def test_create_needs_exactly_one_network_choice() -> None:
    cloud = CannedCloud()
    backend, gate = _backend(cloud)
    with backend.gate_binding.bind(gate), pytest.raises(errors.WriteNotAllowedError):
        backend.create_server(CreateServerSpec("g", "i", "f", tags=(TAG_MANAGED, run_tag(RUN))))
    assert cloud.writes() == []


def test_guarded_client_over_the_sdk_refuses_an_unregistered_target_before_any_request() -> None:
    cloud = CannedCloud()
    backend, gate = _backend(cloud)
    reg = InMemoryOwnershipRegistry(RUN)
    client = GuardedWriteClient(backend, reg, gate)
    with pytest.raises(errors.OwnershipViolationError):
        client.stop_server(SID)
    assert cloud.writes() == [] and gate.checks == []
    reg.register(ResourceKind.SERVER, SID)
    client.stop_server(SID)  # registered and tagged (canned body): one gated send
    assert cloud.writes() == [("POST", f"/v2.1/servers/{SID}/action")]
    assert gate.checks == [("openstack:stop_server", 0)]


# connect_write / connect_write_from_clouds_yaml: see test_openstack_credentials.py (SEC-C-3, SEC-C-4).
