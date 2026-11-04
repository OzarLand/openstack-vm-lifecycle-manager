from __future__ import annotations

import pytest

from ovlm.config import secrets


@pytest.fixture(autouse=True)
def _clean_secret_registry() -> None:
    secrets.clear_known_secrets()
