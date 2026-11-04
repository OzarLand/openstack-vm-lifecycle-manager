"""Who is the client? The source address behind the TLS proxy (SEC-C-1, security-model.md section 9).

The api listens behind an operator-provided TLS reverse proxy, so the TCP peer of every request is the proxy. The
real client is named in ``X-Forwarded-For``, but that header is only believable when the peer is one of the
configured ``http.trusted_proxies``; anyone else could write anything there.

Rules (pure function :func:`resolve_client`):

* Peer not a trusted proxy: the peer is the client, ``X-Forwarded-For`` is ignored. ``attributable``.
* Peer is a trusted proxy: walk ``X-Forwarded-For`` from the right (the entry the proxy itself appended) and skip
  further trusted proxies; the first other valid address is the client. ``attributable``.
* Peer is a trusted proxy but names no valid client (header absent or garbage): the client is unknown. The
  address recorded is the proxy's, and it is **not attributable**: it must not key a per-source rate limit,
  because it stands for every user at once.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class ClientAddress:
    #: Best known address of the client, for audit and session rows (``None``: no peer at all).
    address: str | None
    #: True when ``address`` really is one client's (not a proxy standing for everyone).
    attributable: bool

    @property
    def rate_limit_key(self) -> str | None:
        """The address to key the per-source limiter on, or ``None`` to skip that limiter."""
        return self.address if self.attributable else None


def _parse(value: str) -> IPAddress | None:
    value = value.strip()
    if value.startswith("[") and "]" in value:  # "[2001:db8::1]:443"
        value = value[1 : value.index("]")]
    elif value.count(":") == 1:  # "192.0.2.1:443"
        value = value.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _trusted(addr: IPAddress, networks: Iterable[IPNetwork]) -> bool:
    return any(addr.version == n.version and addr in n for n in networks)


def resolve_client(
    peer: str | None, forwarded_for: Iterable[str], trusted_proxies: Iterable[IPNetwork]
) -> ClientAddress:
    """Resolve the client from the TCP ``peer`` and every ``X-Forwarded-For`` header value (in order)."""
    networks = tuple(trusted_proxies)
    peer_addr = _parse(peer) if peer else None
    if peer_addr is None:
        return ClientAddress(peer, attributable=peer is not None)
    if not _trusted(peer_addr, networks):
        return ClientAddress(str(peer_addr), attributable=True)
    hops = [h for value in forwarded_for for h in value.split(",") if h.strip()]
    for hop in reversed(hops):
        addr = _parse(hop)
        if addr is None:
            break  # garbage: nothing to the left of it can be trusted either
        if not _trusted(addr, networks):
            return ClientAddress(str(addr), attributable=True)
    return ClientAddress(str(peer_addr), attributable=False)
