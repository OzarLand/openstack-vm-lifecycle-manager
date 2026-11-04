"""Idempotent lookups (ADR-0005 section 4, OSI section 3): by tag **and** exact name, never by metadata.

Nova's ``name`` filter is a regex; the read client anchors it (``^name$``) and this module re-checks equality and
the tag client side. Metadata is never a filter (silently ignored for non-admins, LAB-OBSERVED EXP-01 Q5).
"""

from __future__ import annotations

from ovlm.openstack.errors import DuplicateResourceError
from ovlm.openstack.interface import ReadClient
from ovlm.openstack.types import ServerInfo


def find_server_by_tag_and_name(reader: ReadClient, *, tag: str, name: str) -> ServerInfo | None:
    """0 matches -> None; 1 -> that server; more than 1 -> :class:`DuplicateResourceError` (needs_human: a lost
    response plus a retry happened; never pick one, never delete one). A minimal construct (unreachable cell) in
    the tag-filtered result means a duplicate cannot be excluded: also :class:`DuplicateResourceError`."""
    listed = reader.list_servers(tags=[tag], name=name)
    unverifiable = [s.openstack_id for s in listed if s.is_minimal_construct]
    if unverifiable:
        raise DuplicateResourceError(
            f"lookup tag={tag} name={name}: servers in an unreachable cell, a duplicate cannot be excluded",
            matches=tuple(unverifiable),
        )
    matches = [s for s in listed if s.name == name and tag in s.tags and not s.is_deleted]
    if len(matches) > 1:
        raise DuplicateResourceError(
            f"duplicate create detected: {len(matches)} servers with tag {tag} and name {name}",
            matches=tuple(s.openstack_id for s in matches),
        )
    return matches[0] if matches else None
