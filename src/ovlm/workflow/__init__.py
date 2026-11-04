"""Generic durable step executor: run admission, resource locks, signals, timers, scheduler (ADR-0003).

May depend on ``db``, ``audit``, ``observability``, ``config``; knows no strategy. Strategies implement
:class:`~ovlm.workflow.contract.WorkflowDefinition` and :class:`~ovlm.workflow.contract.Step` and are registered
in a :class:`~ovlm.workflow.registry.Registry` given to the worker.

Modules: ``contract`` (interfaces), ``engine`` (claims, leases, fenced commits, admission, signals),
``fence`` (local self-fencing), ``clock``, ``crashpoint`` (test harness), ``requests`` (api-side inserts),
``registry``, ``metrics``, ``audit`` (hook until E3-4).
"""

from ovlm.workflow.contract import (
    Act,
    Admission,
    Defer,
    Done,
    ErrorClass,
    Fail,
    LockSpec,
    Reject,
    Step,
    StepContext,
    StepSpec,
    Transition,
    TxContext,
    Wait,
    Wake,
    WorkflowDefinition,
)
from ovlm.workflow.fence import Fence, FencedCommitRejected, FenceLost, OwnershipLost

__all__ = [
    "Act",
    "Admission",
    "Defer",
    "Done",
    "ErrorClass",
    "Fail",
    "Fence",
    "FenceLost",
    "FencedCommitRejected",
    "LockSpec",
    "OwnershipLost",
    "Reject",
    "Step",
    "StepContext",
    "StepSpec",
    "Transition",
    "TxContext",
    "Wait",
    "Wake",
    "WorkflowDefinition",
]
