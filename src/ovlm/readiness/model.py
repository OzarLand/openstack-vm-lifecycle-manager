"""Vocabulary of a readiness check (FR-RDY-1, FR-RDY-2). Plain data and enums; no I/O, safe everywhere."""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class Result(enum.StrEnum):
    PASS = "pass"  # noqa: S105 - a check result, not a password
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not-applicable"


class Severity(enum.StrEnum):
    BLOCKER = "blocker"
    WARNING = "warning"
    INFO = "info"


class Category(enum.StrEnum):
    """The five categories of FR-RDY-1."""

    CONFIGURATION = "configuration-reproducibility"
    DATA = "persistent-data-separation"
    DEPENDENCIES = "dependencies"
    VALIDATION = "validation-capability"
    EXTERNAL = "external-services"


class Level(enum.StrEnum):
    NOT_READY = "not-ready"
    PARTIALLY_READY = "partially-ready"
    READY = "ready"


@dataclass(frozen=True)
class Outcome:
    """What one check says about one snapshot. ``evidence`` is JSON-safe facts read from the snapshot (never
    secrets); ``recommendation`` says what to do, or is ``None`` when nothing is needed."""

    result: Result
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str | None = None


@dataclass(frozen=True)
class Check:
    """A named, versioned check. Bump ``version`` whenever the rule or its thresholds change: a stored assessment
    names the versions it ran, so it stays interpretable (FR-RDY-4)."""

    key: str
    version: int
    category: Category
    severity: Severity
    title: str
    description: str
    run: Callable[[dict[str, Any]], Outcome]

    def catalogue_entry(self) -> dict[str, Any]:
        return {
            "key": self.key, "version": self.version, "category": self.category.value,
            "severity": self.severity.value, "title": self.title, "description": self.description,
        }  # fmt: skip


@dataclass(frozen=True)
class CheckResult:
    """One check's outcome with the identity of the check that produced it (a ``check_result`` row)."""

    key: str
    version: int
    category: Category
    severity: Severity
    result: Result
    evidence: dict[str, Any]
    recommendation: str | None
