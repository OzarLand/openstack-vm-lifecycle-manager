"""Write allowlist and fence hook of the write session (security-model.md section 4.3, SEC-R-7; ADR-0003).

Safety argument
---------------
Every HTTP request of the write session goes through ``keystoneauth1.session.Session.request``: the SDK proxies
and the raw calls of ``sdk_write`` are keystoneauth Adapters on that session, and the auth plugin sends its token
request through it too. :func:`install_write_guard` wraps that one method, so a request that is not checked here
cannot be sent. For each request, in this order:

1. ``GET`` and ``HEAD`` pass (the write client must probe). Nothing else is a read.
2. The auth plugin's token request passes: the same narrow rule as the read-only hook (``guard``): ``POST`` to
   ``.../auth/tokens``, ``authenticated=False``, no ``endpoint_filter``.
3. Any other request must match exactly one :data:`RULES` entry: the **service type** of its ``endpoint_filter``,
   the **method**, the **relative path** (fully anchored; ids are UUID-shaped; no query string, no absolute URL,
   no ``..``) and a **body predicate** (for example the ``/action`` endpoint only accepts the action names listed
   for it, a create must carry the OVLM tags and no block-device mapping). No match: :class:`WriteNotAllowedError`.
4. Then the **fence gate** bound for this thread is called with ``openstack:<operation>``. With no gate bound (no
   active step attempt), the request is refused. The gate raises ``FenceLost`` (a ``BaseException``) past the
   deadline.
5. The request is sent with ``connect_retries=0``, ``status_code_retries=0``, ``redirect=False`` and
   ``allow_reauth=False``: one gate check covers exactly one send. A failed send surfaces to the step, which
   re-probes before acting again (the step contract), instead of keystoneauth re-sending it later.

What the rules make impossible by construction (refused even if a caller tried): any ``DELETE`` on
``volumes``/``snapshots``/``floatingips``/``ports`` (so OVLM can never delete a snapshot, its own included), ``POST /volumes`` (create), ``POST``/``DELETE /floatingips``
(allocate/release), any ``security-groups``/``security-group-rules`` write, server ``forceDelete``/``rebuild``/
``resize``/``createImage`` and every other action not listed, the replace-all forms ``PUT .../tags`` and
``PUT .../metadata``, tag deletion, ``PUT .../os-volume_attachments`` (swap, ``delete_on_termination`` change), a
create carrying ``block_device_mapping_v2`` (Nova could create a volume that dies with the server), an attach with
``delete_on_termination: true``, and a floating IP disassociation (``port_id: null``). **OVLM never deletes a
volume or a floating IP, and never creates one.**

The allowlist and the ownership guard (``ownership``) are independent: a call must pass both.

This module imports nothing from the SDK; the rules are unit-tested alone and through a real keystoneauth session.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

from ovlm.openstack.errors import WriteNotAllowedError
from ovlm.openstack.guard import READ_METHODS, _is_token_request

#: Marker tag on every resource OVLM manages (ADR-0005).
TAG_MANAGED = "ovlm:managed"
#: Prefix of the per-run tag on resources OVLM created: ``ovlm:run:<run uuid>``.
TAG_RUN_PREFIX = "ovlm:run:"
#: Cinder volumes carry metadata, not tags (ADR-0005 section 5).
VOLUME_MARKER_KEY = "ovlm.managed"
VOLUME_MARKER_VALUE = "true"
#: Every lock OVLM sets carries a reason with this prefix (``ovlm:retained:<run>``, ``ovlm:restored:<run>``).
LOCK_REASON_PREFIX = "ovlm:"

Gate = Callable[[str], None]

_ID = r"[0-9A-Fa-f-]{1,64}"  # UUID-shaped ids only
# A tag segment, percent-encoded by the client; only OVLM's own tags may be added.
_OVLM_TAG = r"ovlm(?::|%3[Aa])[A-Za-z0-9._%:-]{1,200}"

COMPUTE = frozenset({"compute"})
NETWORK = frozenset({"network"})
BLOCK_STORAGE = frozenset({"block-storage", "volumev3", "volume", "block-store"})

#: The server actions OVLM may send (``POST /servers/{id}/action``), each mapped to its operation name.
SERVER_ACTIONS: Mapping[str, str] = {
    "os-stop": "stop_server",
    "os-start": "start_server",
    "lock": "lock_server",
    "unlock": "unlock_server",
    "os-getConsoleOutput": "get_console_output",
}


def _single_key(body: Any) -> str | None:
    if isinstance(body, dict) and len(body) == 1:
        (key,) = body
        return str(key)
    return None


#: The only keys a server-create body may carry (SEC-C-5). An allow-list, not a deny-list: ``adminPass``,
#: ``config_drive``, ``OS-DCF:diskConfig``, ``return_reservation_id``, ``trusted_image_certificates``, block device
#: mappings, ``min_count``/``max_count`` and anything Nova adds later are refused, whoever builds the body.
CREATE_SERVER_KEYS = frozenset(
    {
        "name",
        "imageRef",
        "flavorRef",
        "networks",
        "tags",
        "metadata",
        "availability_zone",
        "security_groups",
        "key_name",
        "user_data",
    }
)
#: Top-level siblings of ``server`` in the create body.
CREATE_BODY_KEYS = frozenset({"server", "os:scheduler_hints"})


def _create_ok(body: Any) -> bool:
    if not isinstance(body, dict) or "server" not in body or not set(body) <= CREATE_BODY_KEYS:
        return False
    server = body.get("server")
    if not isinstance(server, dict) or not set(server) <= CREATE_SERVER_KEYS:
        return False
    tags = server.get("tags")
    if not isinstance(tags, list) or TAG_MANAGED not in tags:
        return False
    if not any(isinstance(t, str) and t.startswith(TAG_RUN_PREFIX) for t in tags):
        return False
    networks = server.get("networks")
    return isinstance(networks, list) and len(networks) >= 1  # never "auto"/"none"


def _attach_ok(body: Any) -> bool:
    att = body.get("volumeAttachment") if isinstance(body, dict) and len(body) == 1 else None
    if not isinstance(att, dict) or not att.get("volumeId"):
        return False
    return set(att) <= {
        "volumeId",
        "device",
    }  # no delete_on_termination, no tag, no multiattach tricks


def _fip_update_ok(body: Any) -> bool:
    fip = body.get("floatingip") if isinstance(body, dict) and len(body) == 1 else None
    if not isinstance(fip, dict) or not set(fip) <= {"port_id", "fixed_ip_address"}:
        return False
    return isinstance(fip.get("port_id"), str) and bool(fip["port_id"])  # never a disassociation


def _volume_metadata_ok(body: Any) -> bool:
    md = body.get("metadata") if isinstance(body, dict) and len(body) == 1 else None
    return (
        isinstance(md, dict)
        and len(md) >= 1
        and all(isinstance(k, str) and k.startswith("ovlm.") for k in md)
    )


#: Prefix of the only snapshot name OVLM creates: ``ovlm-prehandoff-<run uuid>`` (W4).
SNAPSHOT_NAME_PREFIX = "ovlm-prehandoff-"
_SNAPSHOT_KEYS = frozenset({"volume_id", "name", "metadata", "force", "description"})


def _snapshot_create_ok(body: Any) -> bool:
    snap = body.get("snapshot") if isinstance(body, dict) and len(body) == 1 else None
    if not isinstance(snap, dict) or not set(snap) <= _SNAPSHOT_KEYS:
        return False
    if snap.get("force", False) is not False:  # never a snapshot of an attached (in-use) volume
        return False
    if not isinstance(snap.get("volume_id"), str) or not re.fullmatch(_ID, snap["volume_id"]):
        return False
    name = snap.get("name")
    if not isinstance(name, str) or not name.startswith(SNAPSHOT_NAME_PREFIX) or len(name) > 255:
        return False
    md = snap.get("metadata")
    return (
        isinstance(md, dict)
        and md.get(VOLUME_MARKER_KEY) == VOLUME_MARKER_VALUE
        and all(
            isinstance(k, str) and k.startswith("ovlm.") and isinstance(v, str)
            for k, v in md.items()
        )
    )


def _no_body(body: Any) -> bool:
    return body is None


@dataclass(frozen=True)
class Rule:
    """One allowed mutating request: ``method`` on ``path`` (anchored regex over the relative path) of a service."""

    operation: str
    services: frozenset[str]
    method: str
    path: re.Pattern[str]
    body_ok: Callable[[Any], bool]


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(rf"^{pattern}$")


#: THE write allowlist. Adding a line here is a security-relevant change (review by the Security reviewer).
RULES: tuple[Rule, ...] = (
    Rule("create_server", COMPUTE, "POST", _p("servers"), _create_ok),
    Rule("delete_server", COMPUTE, "DELETE", _p(f"servers/{_ID}"), _no_body),
    # stop, start, lock, unlock, console: the action name is checked separately (SERVER_ACTIONS)
    Rule("server_action", COMPUTE, "POST", _p(f"servers/{_ID}/action"), lambda b: True),
    Rule("add_server_tag", COMPUTE, "PUT", _p(f"servers/{_ID}/tags/{_OVLM_TAG}"), _no_body),
    Rule("attach_volume", COMPUTE, "POST", _p(f"servers/{_ID}/os-volume_attachments"), _attach_ok),
    Rule(
        "detach_volume",
        COMPUTE,
        "DELETE",
        _p(f"servers/{_ID}/os-volume_attachments/{_ID}"),
        _no_body,
    ),
    Rule("update_floating_ip", NETWORK, "PUT", _p(f"floatingips/{_ID}"), _fip_update_ok),
    Rule(
        "add_floating_ip_tag", NETWORK, "PUT", _p(f"floatingips/{_ID}/tags/{_OVLM_TAG}"), _no_body
    ),
    Rule(
        "merge_volume_metadata",
        BLOCK_STORAGE,
        "POST",
        _p(f"volumes/{_ID}/metadata"),
        _volume_metadata_ok,
    ),
    # W4 pre-handoff snapshot (renewal-workflow.md 2.2): create only; there is no snapshot DELETE rule.
    Rule("create_volume_snapshot", BLOCK_STORAGE, "POST", _p("snapshots"), _snapshot_create_ok),
)

#: The operation names a write can be classified as (used by the fake to model the same boundary).
WRITE_OPERATIONS: frozenset[str] = frozenset(
    {r.operation for r in RULES if r.operation != "server_action"} | set(SERVER_ACTIONS.values())
)


def _relative_path(url: str) -> str:
    parsed = urlparse(str(url))
    if parsed.scheme or parsed.netloc:
        raise WriteNotAllowedError("a write must use a path relative to the service endpoint")
    if parsed.query or parsed.fragment or parsed.params:
        raise WriteNotAllowedError("a write may not carry a query string")
    path = parsed.path
    decoded = unquote(path)
    if ".." in decoded.split("/") or "//" in path or "\\" in decoded:
        raise WriteNotAllowedError("path traversal in a write path")
    return path.lstrip("/")


def classify_write(method: str, url: str, kwargs: Mapping[str, Any]) -> str | None:
    """Return ``None`` for a read or the token request, the operation name for an allowed write, and raise
    :class:`WriteNotAllowedError` for anything else. Sends nothing; pure function of the request."""
    verb = str(method).upper()
    if verb in READ_METHODS:
        return None
    if _is_token_request(verb, str(url), dict(kwargs)):
        return None
    endpoint_filter = kwargs.get("endpoint_filter") or {}
    service = str(endpoint_filter.get("service_type") or "")
    if not service:
        raise WriteNotAllowedError(f"refused {verb} {url}: not a service request")
    path = _relative_path(url)
    body = kwargs.get("json")
    if kwargs.get("data") is not None:
        raise WriteNotAllowedError(f"refused {verb} {path}: raw request bodies are not checkable")
    for rule in RULES:
        if service in rule.services and verb == rule.method and rule.path.match(path):
            if not rule.body_ok(body):
                raise WriteNotAllowedError(f"refused {verb} {service}/{path}: body not allowed")
            if rule.operation != "server_action":
                return rule.operation
            action = _single_key(body)
            if action is None or action not in SERVER_ACTIONS:
                raise WriteNotAllowedError(f"refused server action {action!r}: not allowlisted")
            return SERVER_ACTIONS[action]
    raise WriteNotAllowedError(f"refused {verb} {service}/{path}: not in the write allowlist")


class GateBinding:
    """The fence gate of the step attempt running on this thread (thread-local).

    The write client binds its step's gate around each call; a mutating request with no gate bound is refused,
    so the write session cannot mutate outside an active step attempt."""

    def __init__(self) -> None:
        self._local = threading.local()

    @contextmanager
    def bind(self, gate: Gate) -> Iterator[None]:
        previous = getattr(self._local, "gate", None)
        self._local.gate = gate
        try:
            yield
        finally:
            self._local.gate = previous

    @property
    def bound(self) -> bool:
        return getattr(self._local, "gate", None) is not None

    def check(self, operation: str) -> None:
        gate: Gate | None = getattr(self._local, "gate", None)
        if gate is None:
            raise WriteNotAllowedError(
                f"refused {operation}: no active step attempt (no fence gate bound)"
            )
        gate(f"openstack:{operation}")


_MARK = "_ovlm_write_guard"
_ONE_SEND = {
    "connect_retries": 0,
    "status_code_retries": 0,
    "redirect": False,
    "allow_reauth": False,
}


def install_write_guard(session: Any, binding: GateBinding) -> None:
    """Wrap ``session.request`` (a keystoneauth1 ``Session``) with the allowlist and the fence gate. Refuses a
    session that already carries a guard (read-only or write): one session, one purpose."""
    if getattr(session, _MARK, False) or getattr(session, "_ovlm_read_only_guard", False):
        raise WriteNotAllowedError("this session already carries a guard")
    original: Callable[..., Any] = session.request

    def guarded(url: str, method: str, *args: Any, **kwargs: Any) -> Any:
        operation = classify_write(method, url, kwargs)
        if operation is not None:
            binding.check(operation)  # FenceLost propagates: nothing is sent
            kwargs.update(_ONE_SEND)
        return original(url, method, *args, **kwargs)

    session.request = guarded
    setattr(session, _MARK, True)
