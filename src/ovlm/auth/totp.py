"""TOTP (RFC 6238) enrolment and verification (security-model.md section 2.1; mandatory for approver/admin).

Library: ``pyotp`` (pinned). Secrets are stored encrypted at rest (Fernet, key from a file that only the api
mounts), so a database dump alone does not yield the second factor. A code is accepted at most once: the caller
persists the accepted time step and passes it back as ``last_step``.
"""

from __future__ import annotations

import hmac
import time
from pathlib import Path

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from ovlm.config import read_secret_file

ISSUER = "OVLM"
PERIOD = 30
WINDOW = 1  # accept the previous and next step to absorb clock skew
DIGITS = 6


class TotpUnavailableError(RuntimeError):
    """No usable TOTP key is configured; TOTP operations fail closed."""


class TotpVault:
    def __init__(self, key: str) -> None:
        try:
            self._fernet = Fernet(key.encode())
        except ValueError as exc:
            raise TotpUnavailableError(
                "the TOTP key file does not hold a valid Fernet key"
            ) from exc

    @classmethod
    def from_file(cls, path: Path | None) -> TotpVault:
        if path is None:
            raise TotpUnavailableError("auth.totp_key_file is not configured")
        return cls(read_secret_file(path))

    def encrypt(self, secret: str) -> bytes:
        return self._fernet.encrypt(secret.encode())

    def decrypt(self, blob: bytes) -> str:
        try:
            return self._fernet.decrypt(bytes(blob)).decode()
        except InvalidToken as exc:
            raise TotpUnavailableError(
                "cannot decrypt the stored TOTP secret with the configured key"
            ) from exc


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD).provisioning_uri(
        name=username, issuer_name=ISSUER
    )


def verify_code(
    secret: str, code: str, *, last_step: int | None = None, now: float | None = None
) -> int | None:
    """Return the matched time step, or ``None``. Steps at or before ``last_step`` are refused (no replay)."""
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret, digits=DIGITS, interval=PERIOD)
    current = int((time.time() if now is None else now) // PERIOD)
    matched: int | None = None
    for step in range(current - WINDOW, current + WINDOW + 1):
        # no early exit: constant work whichever step matches
        if hmac.compare_digest(totp.generate_otp(step), code):
            matched = step
    if matched is None or (last_step is not None and matched <= last_step):
        return None
    return matched
