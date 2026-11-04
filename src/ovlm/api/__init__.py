"""HTTP adapter for the REST API (``/api/v1`` arrives with the domain modules) and the health endpoints.

Architecture rule: the api process never imports ``openstack``, ``automation`` or ``worker`` code. Enforced by
the import-linter contract and ``tests/unit/test_import_boundaries.py``.
"""
