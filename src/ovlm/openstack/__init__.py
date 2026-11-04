"""OpenStack adapter: OVLM's own typed vocabulary, a `ReadClient` (GET/HEAD only) and a `WriteClient` interface.

Layout:

* ``types``      frozen dataclasses (OVLM vocabulary; no SDK objects leave the adapter)
* ``errors``     error classes and the HTTP-error translation (openstack-integration.md)
* ``interface``  ``ReadClient`` / ``WriteClient`` protocols (``WriteClient`` is a stub until E5-2)
* ``guard``      GET/HEAD-only request hook with the one tested Keystone token exemption (SEC-R-5)
* ``sdk_read``   the openstacksdk-backed ``ReadClient`` and microversion negotiation
* ``fake``       hand-written in-memory fake implementing both protocols (tests, E5-4)

Worker process only: never imported by the api (import-linter contract and test). Importing this package is
cheap; ``sdk_read`` is the only module that imports ``openstack``.
"""
