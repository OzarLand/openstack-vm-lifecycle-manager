"""SDK read client: mapping from Nova/Cinder/Neutron-shaped bodies, error translation, microversions, and an
end-to-end pass over a guarded session with a canned transport. No real cloud: this is "unit tested" only."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from keystoneauth1 import session
from keystoneauth1.identity import v3
from openstack import connection
from openstack.block_storage.v3.volume import Volume
from openstack.compute.v2.flavor import Flavor
from openstack.compute.v2.server import Server
from openstack.image.v2.image import Image
from openstack.network.v2.floating_ip import FloatingIP
from openstack.network.v2.network import Network
from openstack.network.v2.port import Port
from requests.adapters import BaseAdapter

from ovlm.openstack import errors
from ovlm.openstack.errors import (
    ReadOnlyViolationError,
    UnsupportedCloudError,
    translate_http_error,
)
from ovlm.openstack.guard import install_read_only_guard
from ovlm.openstack.interface import ReadClient
from ovlm.openstack.sdk_read import (
    SdkReadClient,
    map_flavor,
    map_floating_ip,
    map_image,
    map_network,
    map_port,
    map_server,
    map_volume,
    parse_time,
    parse_version,
)
from ovlm.openstack.types import payload_hash, to_payload

NOVA_SERVER = {
    "id": "11111111-1111-1111-1111-111111111111",
    "name": "app01",
    "status": "ACTIVE",
    "OS-EXT-STS:vm_state": "active",
    "OS-EXT-STS:task_state": None,
    "OS-EXT-STS:power_state": 1,
    "created": "2026-01-01T00:00:00Z",
    "updated": "2026-01-02T00:00:00Z",
    "OS-SRV-USG:launched_at": "2026-01-01T00:01:00.000000",
    "flavor": {
        "original_name": "m1.small",
        "vcpus": 1,
        "ram": 2048,
        "disk": 20,
        "ephemeral": 0,
        "swap": 0,
    },
    "image": {"id": "img-1", "links": []},
    "tags": ["ovlm:managed"],
    "metadata": {"ovlm.service": "app01"},
    "locked": True,
    "locked_reason": "retention",
    "hostId": "hash",
    "OS-EXT-AZ:availability_zone": "az1",
    "os-extended-volumes:volumes_attached": [{"id": "vol-1", "delete_on_termination": False}],
}


def _mk(cls: Any, body: dict[str, Any]) -> Any:
    return cls.existing(**body)


def test_map_server_full() -> None:
    s = map_server(_mk(Server, NOVA_SERVER))
    assert s.openstack_id == NOVA_SERVER["id"]
    assert (s.status, s.vm_state, s.task_state, s.power_state) == ("ACTIVE", "active", None, 1)
    assert s.flavor_original_name == "m1.small"
    assert (s.flavor_vcpus, s.flavor_ram, s.flavor_disk) == (1, 2048, 20)
    assert s.image_id == "img-1"
    assert s.tags == ("ovlm:managed",) and s.metadata == {"ovlm.service": "app01"}
    assert s.locked is True and s.locked_reason == "retention"
    assert s.launched_at == datetime(2026, 1, 1, 0, 1, tzinfo=UTC)  # naive Nova time read as UTC
    assert s.created == datetime(2026, 1, 1, tzinfo=UTC)
    assert [(v.volume_id, v.delete_on_termination) for v in s.attached_volumes] == [
        ("vol-1", False)
    ]
    assert not s.is_minimal_construct and not s.is_deleted
    assert s.host_id == "hash"


def test_map_server_boot_from_volume_has_no_image_and_launched_at_may_be_null() -> None:
    body = {**NOVA_SERVER, "image": "", "OS-SRV-USG:launched_at": None}
    s = map_server(_mk(Server, body))
    assert s.image_id is None
    assert s.launched_at is None


def test_map_server_minimal_construct_is_flagged() -> None:
    s = map_server(Server.existing(id="x", status="UNKNOWN", created="2026-01-01T00:00:00Z"))
    assert s.is_minimal_construct
    assert s.flavor_original_name is None and s.tags == ()


def test_map_server_tombstone() -> None:
    s = map_server(Server.existing(id="x", status="DELETED", updated="2026-01-03T00:00:00Z"))
    assert s.is_deleted


def test_map_volume_attachments_and_types() -> None:
    v = map_volume(
        Volume.existing(
            id="vol-1", name="data", status="in-use", size=10, bootable="false", multiattach=False,
            availability_zone="az1", volume_type="ssd", metadata={"k": "v"},
            attachments=[{"server_id": "srv-1", "device": "/dev/vdb", "attachment_id": "att-1"}],
        )
    )  # fmt: skip
    assert (v.status, v.size, v.bootable, v.multiattach, v.volume_type) == (
        "in-use",
        10,
        False,
        False,
        "ssd",
    )
    assert [(a.server_openstack_id, a.volume_openstack_id, a.device) for a in v.attachments] == [
        ("srv-1", "vol-1", "/dev/vdb")
    ]
    assert v.attachments[0].openstack_id == "srv-1:vol-1"


def test_map_network_objects() -> None:
    p = map_port(
        Port.existing(
            id="p", name="", network_id="n", device_id="d", device_owner="compute:az1",
            fixed_ips=[{"ip_address": "10.0.0.2", "subnet_id": "sn"}], mac_address="fa:16", security_group_ids=["sg"],
            status="ACTIVE",
        )
    )  # fmt: skip
    assert (
        p.fixed_ips == (("10.0.0.2", "sn"),)
        and p.mac == "fa:16"
        and p.security_group_ids == ("sg",)
    )
    f = map_floating_ip(
        FloatingIP.existing(
            id="f",
            floating_ip_address="192.0.2.1",
            port_id=None,
            floating_network_id="n",
            status="DOWN",
        )
    )
    assert f.floating_ip_address == "192.0.2.1" and f.port_id is None
    n = map_network(
        Network.existing(
            id="n", name="ext", status="ACTIVE", is_router_external=True, is_shared=False
        )
    )
    assert n.is_external and not n.is_shared


def test_map_image_and_flavor() -> None:
    i = map_image(
        Image.existing(id="i", name="ubuntu", status="active", visibility="public", owner="o")
    )
    assert (i.visibility, i.owner_id) == ("public", "o")
    fl = map_flavor(Flavor.existing(id="f", name="m1", vcpus=1, ram=1, disk=1, ephemeral=0))
    assert fl.name == "m1" and fl.vcpus == 1


def test_payload_hash_is_stable_and_sensitive() -> None:
    a = map_server(_mk(Server, NOVA_SERVER))
    b = map_server(_mk(Server, NOVA_SERVER))
    assert payload_hash(to_payload(a)) == payload_hash(to_payload(b))
    c = map_server(_mk(Server, {**NOVA_SERVER, "tags": ["other"]}))
    assert payload_hash(to_payload(a)) != payload_hash(to_payload(c))
    json.dumps(to_payload(a))  # JSON safe (datetimes are strings)


def test_parse_helpers() -> None:
    assert (
        parse_version("2.100") == (2, 100)
        and parse_version((2, 52)) == (2, 52)
        and parse_version(None) is None
    )
    assert parse_time("2026-01-01T00:00:00Z") == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_time(None) is None and parse_time("") is None


# --- error translation: canned bodies copied from source-verified code paths / lab observations ---------------


@pytest.mark.parametrize(
    ("status", "text", "cls"),
    [
        (404, "External network 5f1a is not reachable from subnet 9c2b. Therefore, cannot associate Port 77 with a Floating IP.",
         errors.FloatingIpNoRouterPathError),
        (404, "Floating IP abc could not be found", errors.NotFoundError),
        (409, "Instance 1234 is locked", errors.InstanceLockedError),
        (409, "Cannot associate floating IP: FloatingIPPortAlreadyAssociated", errors.FloatingIpPortAlreadyAssociatedError),
        (409, "Something else", errors.ConflictError),
        (400, "Unable to find any IP address on external network abc.", errors.NoFloatingIpAvailableError),
        (400, "Invalid volume: volume X already attached", errors.BadRequestError),
        (403, "Quota exceeded for instances", errors.QuotaExceededError),
        (403, "Policy doesn't allow this", errors.ForbiddenError),
        (401, "expired", errors.AuthenticationError),
        (500, "Volume type with name __DEFAULT__ could not be found.", errors.ServerError),
    ],
)  # fmt: skip
def test_translate_http_error(status: int, text: str, cls: type[Exception]) -> None:
    err = translate_http_error(status, text)
    assert type(err) is cls and err.status == status


def test_no_router_404_is_a_not_found_subclass_so_naive_handlers_misread_it() -> None:
    # documented trap: a caller that only catches NotFoundError for "FIP gone" would misclassify; code must check
    # FloatingIpNoRouterPathError first.
    assert issubclass(errors.FloatingIpNoRouterPathError, errors.NotFoundError)


# --- end to end over a guarded session with a canned transport ------------------------------------------------

AUTH_URL = "http://keystone.invalid/v3"
NOVA = "http://nova.invalid/v2.1"
CINDER = "http://cinder.invalid/v3/p1"
_CATALOG = [
    {
        "type": t,
        "id": t,
        "name": t,
        "endpoints": [{"id": t + "e", "interface": "public", "region": "R1", "url": u}],
    }
    for t, u in (("compute", NOVA), ("block-storage", CINDER), ("volumev3", CINDER))
]


class CannedCloud(BaseAdapter):
    def __init__(self, compute_max: str = "2.100") -> None:
        super().__init__()
        self.requests: list[tuple[str, str]] = []
        self.compute_max = compute_max

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        method, url = str(request.method), str(request.url)
        self.requests.append((method, url))
        path = urlparse(url).path
        resp = requests.Response()
        resp.status_code = 200
        resp.headers["Content-Type"] = "application/json"
        resp.url, resp.request = url, request
        body: Any = {}
        if method == "POST" and path.endswith("/auth/tokens"):
            resp.status_code = 201
            resp.headers["X-Subject-Token"] = "tok"
            body = {"token": {
                "methods": ["password"], "expires_at": "2099-01-01T00:00:00.000000Z",
                "issued_at": "2026-01-01T00:00:00.000000Z",
                "user": {"id": "u", "name": "u", "domain": {"id": "d", "name": "d"}},
                "project": {"id": "p1", "name": "p", "domain": {"id": "d", "name": "d"}},
                "roles": [{"id": "r", "name": "reader"}], "catalog": _CATALOG,
            }}  # fmt: skip
        elif path in ("/v2.1", "/v2.1/"):
            body = {"version": {"id": "v2.1", "status": "CURRENT", "version": self.compute_max,
                                "min_version": "2.1", "links": [{"rel": "self", "href": NOVA + "/"}]}}  # fmt: skip
        elif path in ("/v3/p1", "/v3/p1/", "/v3", "/v3/"):
            body = {"version": {"id": "v3.0", "status": "CURRENT", "version": "3.71", "min_version": "3.0",
                                "links": [{"rel": "self", "href": CINDER + "/"}]}}  # fmt: skip
        elif path.endswith("/servers/detail"):
            body = {"servers": [NOVA_SERVER]}
        resp._content = json.dumps(body).encode()
        return resp

    def close(self) -> None:
        pass


def _client(cloud: CannedCloud) -> SdkReadClient:
    auth = v3.Password(
        auth_url=AUTH_URL, username="u", password="pw", user_domain_id="d", project_id="p1"
    )
    sess = session.Session(auth=auth)
    sess.session.mount("http://", cloud)
    install_read_only_guard(sess)
    conn = connection.Connection(session=sess, region_name="R1")
    return SdkReadClient(conn)


def test_sdk_client_satisfies_the_read_protocol() -> None:
    assert isinstance(_client(CannedCloud()), ReadClient)


def test_list_servers_end_to_end_query_and_only_reads() -> None:
    cloud = CannedCloud()
    client = _client(cloud)
    servers = client.list_servers(
        changes_since=datetime(2026, 1, 1, 12, 0, tzinfo=UTC), tags=["ovlm:managed"], name="app01"
    )
    assert [s.name for s in servers] == ["app01"]
    q = next(
        parse_qs(urlparse(u).query)
        for m, u in cloud.requests
        if u.startswith(NOVA) and "/servers/detail" in u
    )
    assert q["changes-since"] == ["2026-01-01T12:00:00Z"]
    assert q["tags"] == ["ovlm:managed"]
    assert q["name"] == ["^app01$"]  # anchored: Nova's name filter is a regex
    assert "metadata" not in q  # never a filter (ignored for non-admins)
    assert {m for m, _ in cloud.requests} <= {"GET", "HEAD", "POST"}
    assert [u for m, u in cloud.requests if m == "POST"] == [f"{AUTH_URL}/auth/tokens"]


def test_name_filter_is_rechecked_client_side() -> None:
    client = _client(CannedCloud())
    assert client.list_servers(name="app0") == []  # the canned cloud returns app01 for any regex


def test_negotiated_versions_recorded() -> None:
    v = _client(CannedCloud("2.100")).negotiated_versions()
    assert v.compute_max == (2, 100) and v.compute_used == (2, 100)
    assert v.as_json()["compute_used"] == "2.100"
    assert v.block_storage_max == (3, 71)


def test_cloud_below_2_52_is_refused() -> None:
    with pytest.raises(UnsupportedCloudError, match="2.52"):
        _client(CannedCloud("2.40")).negotiated_versions()


def test_compute_used_is_capped_at_the_sdk_pin() -> None:
    v = _client(CannedCloud("2.104")).negotiated_versions()
    assert v.compute_max == (2, 104) and v.compute_used == (
        2,
        100,
    )  # SDK pins Server at 2.100 (osdk 4.22.0)


def test_project_id_from_token() -> None:
    assert _client(CannedCloud()).project_id() == "p1"


def test_write_through_the_sdk_connection_is_refused() -> None:
    client = _client(CannedCloud())
    with pytest.raises(ReadOnlyViolationError):
        client._conn.compute.stop_server("abc")
