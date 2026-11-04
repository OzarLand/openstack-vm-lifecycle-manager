"""Redaction of captured output: a backstop, not the control (automation-contract.md section 5).

Known secret values (exact match, built from the run's secret refs plus the process-wide registry) and generic
patterns are replaced. Workload secrets that OVLM does not know (vault-decrypted values a task prints) cannot be
redacted: that is why the artefacts are restricted (:mod:`ovlm.automation.store`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from ovlm.config import secrets as secret_registry

REDACTED = "[REDACTED]"
_MIN_SECRET_LEN = (
    4  # shorter values would shred ordinary text; they are covered by the patterns where it matters
)

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|\Z)", re.DOTALL),
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
    re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)[^\s\"']+"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)(\b[\w.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key)[\w.-]*"
        r"[\"']?\s*[=:]\s*[\"']?)[^\s\"',;}{]+"
    ),
)


class Redactor:
    def __init__(
        self, secrets: Iterable[str | bytes] = (), *, include_registry: bool = True
    ) -> None:
        values: set[str] = set()
        sources: list[Iterable[str | bytes]] = [secrets]
        if include_registry:
            sources.append(secret_registry.known_secrets())
        for source in sources:
            for item in source:
                text = item.decode("utf-8", "replace") if isinstance(item, bytes) else item
                self._add(values, text)
        # Longest first so a secret containing another one is replaced whole.
        self._values = sorted(values, key=len, reverse=True)

    @staticmethod
    def _add(values: set[str], text: str) -> None:
        text = text.strip("\r\n")
        if len(text) >= _MIN_SECRET_LEN:
            values.add(text)
        # A multi-line secret (a private key) shows up line by line in logs.
        for line in text.splitlines():
            line = line.strip()
            if len(line) >= 8:
                values.add(line)

    def text(self, value: str) -> str:
        for secret in self._values:
            if secret in value:
                value = value.replace(secret, REDACTED)
        for pattern in _PATTERNS:
            value = pattern.sub(
                lambda m: (m.group(1) + REDACTED) if m.lastindex else REDACTED, value
            )
        return value

    def data(self, value: bytes) -> str:
        return self.text(value.decode("utf-8", "replace"))

    def obj(self, value: Any) -> Any:
        """Redact every string (keys and values) of a JSON-like structure."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.text(str(k)): self.obj(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self.obj(v) for v in value]
        return value


def truncate_head_tail(value: str, max_bytes: int) -> tuple[str, bool]:
    """Cap ``value`` at ``max_bytes`` UTF-8 bytes, keeping head and tail with a marker (contract section 7)."""
    raw = value.encode("utf-8")
    if len(raw) <= max_bytes:
        return value, False
    marker = f"\n[... truncated {len(raw) - max_bytes} bytes ...]\n".encode()
    keep = max(max_bytes - len(marker), 0)
    head, tail = keep * 2 // 3, keep - keep * 2 // 3
    out = raw[:head] + marker + (raw[len(raw) - tail :] if tail else b"")
    return out.decode("utf-8", "ignore"), True
