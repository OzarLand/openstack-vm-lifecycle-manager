"""Deterministic crash-point injection (testing-strategy.md section 4.1).

The engine calls :func:`crashpoint` at every named point: ``<step_key>.after_claim``, ``.after_probe``,
``.after_intent``, ``.after_act``, ``.after_verify_before_commit``, ``.after_commit`` and the engine points
``lease.heartbeat``, ``lease.release``, ``run.create`` (locks acquired, admission not yet committed) and
``signal.apply`` (signal effect written, consumption not yet committed).

In production the call is a no-op: no plan is installed and the environment variable is ignored unless the
process opted in. The worker entry point refuses to start when ``OVLM_TEST_CRASHPOINT`` is set (see
``ovlm.worker.main``), so a release deployment cannot activate a plan by accident.

Modes:

* ``raise``: raise :class:`SimulatedCrash` (a ``BaseException``; the engine never catches ``BaseException`` and no
  ``finally`` block commits state, so this behaves like the thread vanishing).
* ``exit``: ``os._exit(137)``, the real thing for subprocess tests (no cleanup, no flush of anything).
* ``stop``: ``SIGSTOP`` to the own process (all threads, the heartbeat included, freeze as under a VM pause);
  the test sends ``SIGCONT``.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

ENV_VAR = "OVLM_TEST_CRASHPOINT"

Mode = Literal["raise", "exit", "stop"]


class SimulatedCrash(BaseException):  # noqa: N818 - name fixed by testing-strategy.md
    """In-process stand-in for SIGKILL. Deliberately not an ``Exception``."""


@dataclass
class CrashPlan:
    target: str
    occurrence: int = 1
    mode: Mode = "raise"
    hits: int = 0
    fired: bool = False
    action: Callable[[str], None] | None = None

    def hit(self, name: str) -> None:
        if self.fired or name != self.target:
            return
        self.hits += 1
        if self.hits < self.occurrence:
            return
        self.fired = True
        if self.action is not None:
            self.action(name)
            return
        _fire(self.mode, name)

    @classmethod
    def parse(cls, spec: str) -> CrashPlan:
        """``name[@occurrence][:mode]``, e.g. ``dummy.after_act@2:exit``."""
        name, _, mode = spec.partition(":")
        name, _, occ = name.partition("@")
        if mode not in ("", "raise", "exit", "stop"):
            raise ValueError(f"unknown crash mode {mode!r}")
        return cls(target=name, occurrence=int(occ or 1), mode=(mode or "exit"))  # type: ignore[arg-type]


def _fire(mode: Mode, name: str) -> None:
    if mode == "raise":
        raise SimulatedCrash(name)
    sys.stderr.write(f"crashpoint {name}: {mode}\n")
    sys.stderr.flush()
    if mode == "exit":
        os._exit(137)
    # Directed at the calling thread so the stop takes effect before this thread runs any further code
    # (``os.kill(getpid())`` lets the kernel pick a thread, and this one could race past its next check).
    signal.pthread_kill(threading.get_ident(), signal.SIGSTOP)


@dataclass
class _State:
    plan: CrashPlan | None = None
    recorder: list[str] | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


_state = _State()


def crashpoint(name: str) -> None:
    """Named crash point. No-op unless a plan is installed or the opt-in env plan applies."""
    rec = _state.recorder
    if rec is not None:
        with _state.lock:
            rec.append(name)
    plan = _state.plan
    if plan is not None:
        plan.hit(name)


def install(plan: CrashPlan | None) -> None:
    _state.plan = plan


def install_from_env() -> CrashPlan | None:
    """Used only by test worker processes (the production entry point refuses the variable)."""
    spec = os.environ.get(ENV_VAR)
    plan = CrashPlan.parse(spec) if spec else None
    install(plan)
    return plan


def record(recorder: list[str] | None) -> None:
    """Start (list) or stop (None) recording every crash point hit, in order (enumeration run)."""
    _state.recorder = recorder
