"""Registry of workflow definitions, startup sweepers and periodic jobs known to this worker process."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ovlm.workflow.contract import StartupSweeper, WorkflowDefinition


@dataclass(frozen=True)
class PeriodicJob:
    """A single-step run created by the scheduler leader every ``interval`` seconds (ADR-0003 "Scheduler")."""

    kind: str
    strategy: str
    version: str
    interval: float
    subject: dict[str, Any] = field(default_factory=dict)


class Registry:
    def __init__(self, definitions: Iterable[WorkflowDefinition] = ()) -> None:
        self._defs: dict[tuple[str, str, str], WorkflowDefinition] = {}
        self._current: dict[tuple[str, str], WorkflowDefinition] = {}
        self.sweepers: list[StartupSweeper] = []
        self.periodic: list[PeriodicJob] = []
        #: Strategy gauges refreshed with the engine's (``refresh_metrics``), on its read connection; a failing
        #: refresher is logged and never stops the others.
        self.metric_refreshers: list[Callable[[Any], None]] = []
        for d in definitions:
            self.register(d)

    def register(self, defn: WorkflowDefinition) -> None:
        for version in {defn.version, *defn.resumes_versions}:
            key = (defn.kind, defn.strategy, version)
            if key in self._defs and self._defs[key] is not defn:
                raise ValueError(f"duplicate workflow definition for {key}")
            self._defs[key] = defn
        self._current[(defn.kind, defn.strategy)] = defn

    def resolve(self, kind: str, strategy: str, version: str) -> WorkflowDefinition | None:
        return self._defs.get((kind, strategy, version))

    def is_current(self, kind: str, strategy: str, version: str) -> bool:
        d = self._current.get((kind, strategy))
        return d is not None and d.version == version

    def known(self) -> list[tuple[str, str, str]]:
        return sorted(self._defs)

    def current_versions(self, kind: str, strategy: str) -> list[str]:
        d = self._current.get((kind, strategy))
        return [d.version] if d else []
