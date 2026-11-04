"""OVLM - OpenStack VM Lifecycle Manager.

Modular monolith (docs/architecture.md): one package, one sub-package per module, process roles ``api``,
``worker`` and the one-shot ``migrate``. Module boundaries are enforced by import-linter contracts
(``pyproject.toml``) and ``tests/unit/test_import_boundaries.py``.
"""

__version__ = "0.0.1"
