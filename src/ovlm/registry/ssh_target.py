"""Which address OVLM reaches blue at over SSH: one rule for the host-key scan and the renewal (review IS-3).

The renewal reaches blue at ``fixed_ips[0]`` of the port the **service floating IP** is attached to (the plan's
``blue.port_id``, read live from OpenStack). The host-key scan uses the same rule, from the inventory:

1. the service floating IP is the one the service's latest profile version names (``cutover.floating_ip_id``),
   when there is a profile; its port must be one of blue's present ports;
2. before a profile exists (registration comes first, lab scenario A2): the **only** present port of blue that
   carries a present floating IP. Several such ports are ambiguous and refused; the operator creates the profile
   and scans again.

On that port, the address is :func:`first_fixed_address`: ``fixed_ips[0]`` in the order OpenStack lists them, as
the renewal does. Before IS-3 the scan took the first port by id and preferred IPv4, so it could reach another
interface than the renewal.

No OpenStack import: the api may import this module. Pure reads; transactions belong to the caller.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text


@dataclass(frozen=True)
class SshTarget:
    port_id: str
    address: str
    floating_ip_id: str
    #: ``profile`` (the profile's service floating IP) or ``only_fip_port`` (no profile yet).
    source: str


class NoSshTargetError(Exception):
    """No address can be chosen; the message is safe to show and says what to do."""


def first_fixed_address(fixed_ips: Sequence[Any] | None) -> str | None:
    """``fixed_ips[0]`` of a port, as an IP address string. Accepts the inventory's ``{"ip_address": ...}`` dicts
    and the adapter's ``(ip_address, subnet_id)`` tuples. ``None`` when the port has none or it is not an IP."""
    if not fixed_ips:
        return None
    first = fixed_ips[0]
    raw = first.get("ip_address") if isinstance(first, Mapping) else first[0]
    try:
        return str(ipaddress.ip_address(str(raw)))
    except ValueError:
        return None


def blue_ssh_target(conn: Any, managed_vm_id: str) -> SshTarget:
    """The scan's target for a managed VM, from the inventory. Raises :class:`NoSshTargetError` with a reason."""
    vm = conn.execute(
        text(
            "SELECT m.openstack_server_id, s.project_connection_id AS pc, "
            "(SELECT v.spec->'cutover'->>'floating_ip_id' FROM profile p JOIN profile_version v "
            "   ON v.profile_id = p.id AND v.number = p.latest_version WHERE p.service_id = s.id) AS fip_id "
            "FROM managed_vm m JOIN service s ON s.id = m.service_id WHERE m.id = :v"
        ),
        {"v": managed_vm_id},
    ).first()
    if vm is None:
        raise NoSshTargetError("the managed VM no longer exists")
    rows = conn.execute(
        text(
            "SELECT p.openstack_id AS port_id, p.fixed_ips, f.openstack_id AS fip_id "
            "FROM observed_port p JOIN observed_floating_ip f ON f.port_id = p.openstack_id "
            "  AND f.project_connection_id = p.project_connection_id AND f.status = 'present' "
            "WHERE p.project_connection_id = :pc AND p.device_id = :srv AND p.status = 'present' "
            "ORDER BY p.openstack_id, f.openstack_id"
        ),
        {"pc": vm.pc, "srv": vm.openstack_server_id},
    ).all()
    if vm.fip_id:
        source = "profile"
        chosen = [r for r in rows if r.fip_id == vm.fip_id]
        if not chosen:
            raise NoSshTargetError(
                "the service floating IP named by the profile is not on a port of this VM in the inventory: "
                "sync the project, check the profile's cutover.floating_ip_id, and scan again"
            )
    else:
        source = "only_fip_port"
        chosen = rows
        if len({r.port_id for r in rows}) > 1:
            raise NoSshTargetError(
                "several ports of this VM carry a floating IP: create the service's profile (its "
                "cutover.floating_ip_id names the service floating IP), then scan again"
            )
        if not chosen:
            raise NoSshTargetError(
                "the inventory shows no port of this VM with a floating IP (the renewal reaches blue through the "
                "service floating IP's port): sync the project and scan again"
            )
    row = chosen[0]
    address = first_fixed_address(row.fixed_ips)
    if address is None:
        raise NoSshTargetError(
            "the service floating IP's port has no fixed address in the inventory: sync the project and scan again"
        )
    return SshTarget(str(row.port_id), address, str(row.fip_id), source)
