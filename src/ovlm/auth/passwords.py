"""Password hashing and policy (security-model.md section 2.1).

argon2id with at least m=64 MiB, t=3, p=4 (RFC 9106 second recommendation); re-hash on login when the parameters
rise. Minimum length 12, checked against an offline list of known-weak passwords.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
MAX_LENGTH = 256  # bounds hashing cost (DoS)
MEMORY_KIB, TIME_COST, PARALLELISM = 64 * 1024, 3, 4
_BREACHED_FILE = Path(__file__).parent / "data" / "common_passwords.txt"


class PasswordPolicyError(ValueError):
    pass


def make_hasher(
    memory_kib: int = MEMORY_KIB, time_cost: int = TIME_COST, parallelism: int = PARALLELISM
) -> PasswordHasher:
    if memory_kib < MEMORY_KIB or time_cost < TIME_COST or parallelism < PARALLELISM:
        raise ValueError("argon2id parameters below the security-model floor (m=64MiB, t=3, p=4)")
    return PasswordHasher(
        memory_cost=memory_kib, time_cost=time_cost, parallelism=parallelism, type=Type.ID
    )


@lru_cache(maxsize=1)
def _breached() -> frozenset[str]:
    return frozenset(
        line.strip().lower()
        for line in _BREACHED_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )


def check_policy(password: str, *, username: str | None = None) -> None:
    """Raise :class:`PasswordPolicyError` (message safe to show) if ``password`` is not acceptable."""
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"The password must be at least {MIN_LENGTH} characters long.")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"The password must be at most {MAX_LENGTH} characters long.")
    low = password.lower()
    if low in _breached():
        raise PasswordPolicyError("This password is too common. Choose another one.")
    if len(set(password)) < 5:
        raise PasswordPolicyError("The password is too repetitive. Choose another one.")
    if username and username.lower() in low:
        raise PasswordPolicyError("The password must not contain the username.")


def hash_password(hasher: PasswordHasher, password: str) -> str:
    return hasher.hash(password)


def verify_password(hasher: PasswordHasher, stored: str, password: str) -> tuple[bool, bool]:
    """``(matches, needs_rehash)``. Never raises for a wrong password or a malformed stored hash."""
    try:
        hasher.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return False, False
    return True, hasher.check_needs_rehash(stored)


@lru_cache(maxsize=1)
def dummy_hash() -> str:
    """A valid hash to verify against when the user is unknown, so timing does not reveal existence."""
    return make_hasher().hash("ovlm-timing-equaliser")
