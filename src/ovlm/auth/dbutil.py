"""Small SQLAlchemy typing helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy.engine import Result


def rowcount(result: Result[Any]) -> int:
    """Rows affected by an INSERT/UPDATE/DELETE executed through ``Session.execute(text(...))``."""
    return int(getattr(result, "rowcount", 0))
