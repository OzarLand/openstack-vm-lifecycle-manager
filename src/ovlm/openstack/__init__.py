"""OpenStack adapter: OVLM's own typed vocabulary, a `ReadClient` (GET/HEAD only) and a `WriteClient` interface.

Layout:

* ``types``      frozen dataclasses (OVLM vocabulary; no SDK objects leave the adapter)
* ``errors``     error classes and the HTTP-error translation (openstack-integration.md)
* ``interface``  ``ReadClient`` / ``WriteClient`` protocols
* ``guard``      GET/HEAD-only request hook with the one tested Keystone token exemption (SEC-R-5)
* ``sdk_read``   the openstacksdk-backed ``ReadClient`` and microversion negotiation
* ``allowlist``  the write allowlist and fence hook of the write session (SEC-R-7, ADR-0003)
* ``ownership``  the ownership guard and the registry protocol it consults (security-model.md s.4.3, ADR-0005)
* ``write``      ``GuardedWriteClient``: the write client steps receive (guard + idempotency over a backend)
* ``sdk_write``  the openstacksdk write backend and ``connect_write`` (write credential, worker only)
* ``lookup``     idempotent lookup by tag + exact name, never by metadata
* ``retry``      adapter errors -> retry classes (retryable / needs_human / fatal)
* ``fake``       hand-written in-memory fake implementing both protocols (tests, E5-4)

Worker process only: never imported by the api (import-linter contract and test). Importing this package is
cheap; ``sdk_read`` and ``sdk_write`` are the only modules that import ``openstack``.
"""
