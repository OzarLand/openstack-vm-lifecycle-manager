"""Time-ordered UUIDs (UUIDv7, RFC 9562) for primary keys (data-model.md conventions)."""

from __future__ import annotations

import os
import time
from uuid import UUID


def new_id() -> UUID:
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76  # version 7
    value |= ((rand >> 62) & 0xFFF) << 64
    value |= 0b10 << 62  # RFC 4122 variant
    value |= rand & ((1 << 62) - 1)
    return UUID(int=value)
