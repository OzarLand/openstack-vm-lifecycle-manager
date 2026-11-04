"""UUIDv7 (time-ordered) identifiers, data-model.md conventions. Python 3.12 has no ``uuid.uuid7``."""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    ms = time.time_ns() // 1_000_000  # identifier ordering only; never used for leases or timers
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= ((rand >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return uuid.UUID(int=value)


def new_id() -> str:
    return str(uuid7())
