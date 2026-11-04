"""Read-only request hook for the inventory session (security-model.md section 4.1, SEC-R-5; architecture.md s. 3).

The hook sits on ``keystoneauth1.session.Session.request``: every service call of the SDK (its proxies are
keystoneauth Adapters) and every discovery call goes through that one method, so a hook there sees them all.

Rule: only ``GET`` and ``HEAD`` may be sent, with exactly **one** exemption: the auth plugin's own token request,
``POST <auth_url>/auth/tokens`` sent with ``authenticated=False`` and **no** ``endpoint_filter``. A service call
always carries an ``endpoint_filter`` (the Adapter sets it), so a ``POST /v3/auth/tokens`` made through the
identity proxy is still refused. The exemption is narrow on purpose and covered by tests.

This file imports nothing from the SDK (the session is passed in), so the rule can be unit-tested alone.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from ovlm.openstack.errors import ReadOnlyViolationError

READ_METHODS = frozenset({"GET", "HEAD"})
_MARK = "_ovlm_read_only_guard"


def _is_token_request(method: str, url: str, kwargs: dict[str, Any]) -> bool:
    if method != "POST":
        return False
    if kwargs.get("endpoint_filter"):  # a service call, not the auth plugin
        return False
    if kwargs.get("authenticated") is not False:  # the plugin sends authenticated=False
        return False
    return urlparse(url).path.rstrip("/").endswith("/auth/tokens")


def check_request(method: str, url: str, kwargs: dict[str, Any]) -> None:
    """Raise ``ReadOnlyViolationError`` unless the request is a read or the token request."""
    verb = str(method).upper()
    if verb in READ_METHODS:
        return
    if _is_token_request(verb, str(url), kwargs):
        return
    raise ReadOnlyViolationError(
        f"read-only session refused {verb} {urlparse(str(url)).path or url}"
    )


def install_read_only_guard(session: Any) -> None:
    """Wrap ``session.request`` in place. Idempotent. ``session`` is a keystoneauth1 ``Session``."""
    if getattr(session, _MARK, False):
        return
    original: Callable[..., Any] = session.request

    def guarded(url: str, method: str, *args: Any, **kwargs: Any) -> Any:
        check_request(method, url, kwargs)
        return original(url, method, *args, **kwargs)

    session.request = guarded
    setattr(session, _MARK, True)
