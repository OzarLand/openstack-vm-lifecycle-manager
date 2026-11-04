"""UUIDv7 (time-ordered) primary keys (data-model.md conventions). ``uuid.uuid7`` exists only from Python 3.14."""

from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    millis = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")  # 80 random bits, 74 used
    value = (
        ((millis & ((1 << 48) - 1)) << 80)
        | (0x7 << 76)
        | (((rand >> 62) & 0xFFF) << 64)
        | (0b10 << 62)
        | (rand & ((1 << 62) - 1))
    )
    return uuid.UUID(int=value)
