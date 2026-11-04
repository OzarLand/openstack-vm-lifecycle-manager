"""Effective-policy resolution (FR-POL-2, FR-POL-4): the most specific binding wins; no binding, no policy.

Specificity: a binding on the service beats a binding on its service group. There is **no global default**: a service
with no binding at all has no policy and is never due. Pure functions, no database.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

# Higher is more specific. Extend here when another scope type is added.
SPECIFICITY: dict[str, int] = {"service_group": 1, "service": 2}


@dataclass(frozen=True)
class BindingRef:
    id: UUID
    policy_id: UUID
    scope_type: str
    scope_id: UUID


@dataclass(frozen=True)
class Resolution:
    winner: BindingRef | None
    shadowed: tuple[BindingRef, ...]
    reason: str


def resolve(service_id: UUID, group_id: UUID | None, bindings: list[BindingRef]) -> Resolution:
    """``bindings`` may hold any bindings; only those on this service or its group are considered."""
    applicable = [
        b
        for b in bindings
        if (b.scope_type == "service" and b.scope_id == service_id)
        or (b.scope_type == "service_group" and group_id is not None and b.scope_id == group_id)
    ]
    if not applicable:
        return Resolution(
            None, (), "no policy is bound to this service or its group: the service is never due"
        )
    ranked = sorted(applicable, key=lambda b: SPECIFICITY[b.scope_type], reverse=True)
    winner, rest = ranked[0], tuple(ranked[1:])
    why = f"the binding on the {winner.scope_type.replace('_', ' ')} is the most specific"
    if rest:
        why += "; less specific bindings are shadowed"
    return Resolution(winner, rest, why)
