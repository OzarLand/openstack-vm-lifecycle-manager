"""Shared vocabulary of the automation contract (docs/automation-contract.md sections 3, 6)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Phase(StrEnum):
    PREFLIGHT = "preflight"
    CONFIGURE = "configure"
    QUIESCE = "quiesce"
    DATA_ATTACH = "data_attach"
    START_SERVICE = "start_service"
    HEALTHCHECK = "healthcheck"
    ROLLBACK_HOOKS = "rollback_hooks"


class Classification(StrEnum):
    """What the workflow engine does next (contract section 6). ``ok`` means proceed."""

    OK = "ok"
    RETRYABLE = "retryable"
    NEEDS_HUMAN = "needs_human"
    FATAL = "fatal"


#: Phases that touch the data volume or its mount: any anomaly stops for a human (contract section 6).
#: ``rollback_hooks`` is included: it acts on the data path of the OLD VM after a failure.
DATA_PHASES: frozenset[Phase] = frozenset({Phase.QUIESCE, Phase.DATA_ATTACH, Phase.ROLLBACK_HOOKS})

#: Contract section 6 defaults (ASSUMPTION: tuned in the lab): (total timeout, idle timeout) in seconds.
DEFAULT_TIMEOUTS: dict[Phase, tuple[int, int]] = {
    Phase.PREFLIGHT: (120, 60),
    Phase.CONFIGURE: (1800, 300),
    Phase.DATA_ATTACH: (300, 120),
    Phase.QUIESCE: (300, 120),
    Phase.START_SERVICE: (300, 120),
    Phase.HEALTHCHECK: (60, 30),
    Phase.ROLLBACK_HOOKS: (300, 120),
}

#: Seconds between SIGTERM and SIGKILL of the process group (contract section 6).
KILL_GRACE_SECONDS = 30.0


class AutomationError(Exception):
    """A run could not be started or verified. Carries the class the engine should act on.

    Raised *before* any guest is touched (bad SHA, lint failure, missing playbook, ...), so ``fatal`` here means
    "do not retry, the input is wrong". The message never contains secret values.
    """

    def __init__(self, message: str, classification: Classification = Classification.FATAL) -> None:
        super().__init__(message)
        self.classification = classification


class CheckoutUnverifiable(AutomationError):  # noqa: N818 - a classified refusal, like its base
    """The run's checkout (on ``run_root`` or in the checkout cache) cannot be shown to be the tree B6 verified: its
    tree digest differs from the recorded one, or none was recorded. Always ``NEEDS_HUMAN``; never resolved by a git
    contact unless an approver authorizes one re-clone (``reprepare-automation``).

    ``detail``: evidence for the step's refusal, e.g. where a mismatching cached copy was moved aside and both
    digests (``quarantined_checkout``, ``recorded_tree_digest``, ``cached_tree_digest``; review PMR-6)."""

    def __init__(self, message: str, detail: dict[str, str] | None = None) -> None:
        super().__init__(message, Classification.NEEDS_HUMAN)
        self.detail: dict[str, str] = dict(detail or {})


@dataclass(frozen=True)
class SecretBytes:
    """A secret handed to the runner. ``repr`` hides the value so a stray log line cannot leak it."""

    value: bytes

    def __repr__(self) -> str:
        return "SecretBytes(<redacted>)"

    __str__ = __repr__
