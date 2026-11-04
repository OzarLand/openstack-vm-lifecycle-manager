"""Request bodies of the policy endpoints. Durations are ISO 8601 (``P90D``, ``PT6H``), windows are explicit."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from ovlm.policies.durations import parse_duration
from ovlm.policies.windows import WEEKDAYS, Weekday, load_zone, parse_hhmm


def _duration(value: str) -> str:
    parse_duration(value)
    return value


Duration = Annotated[str, AfterValidator(_duration), Field(max_length=40)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WindowIn(_Strict):
    weekdays: Annotated[list[Weekday], Field(min_length=1, max_length=7)]
    start: str
    end: str
    timezone: str = Field(max_length=64)

    @model_validator(mode="after")
    def _valid(self) -> WindowIn:
        if len(set(self.weekdays)) != len(self.weekdays):
            raise ValueError("weekdays must not repeat")
        if parse_hhmm(self.end) <= parse_hhmm(self.start):
            raise ValueError(
                "a window ends later than it starts on the same day; write a night window as two"
            )
        load_zone(self.timezone)
        return self

    def canonical(self) -> dict[str, object]:
        return {
            "weekdays": sorted(self.weekdays, key=WEEKDAYS.index), "start": self.start, "end": self.end,
            "timezone": self.timezone,
        }  # fmt: skip

    @property
    def length_seconds(self) -> int:
        a, b = parse_hhmm(self.start), parse_hhmm(self.end)
        return (b.hour * 60 + b.minute - a.hour * 60 - a.minute) * 60


class ApprovalsIn(_Strict):
    plan: bool = True
    cutover: bool = True  # retirement approval is always required and not configurable


class PolicyIn(_Strict):
    name: str = Field(min_length=1, max_length=200)
    max_age: Duration
    renewal_interval: Duration
    windows: Annotated[list[WindowIn], Field(min_length=1, max_length=50)]
    approvals: ApprovalsIn = Field(default_factory=ApprovalsIn)
    require_distinct_approvers: bool = True
    snapshot_retain_after_restore: Literal["until_next_renewal"] | Duration = "until_next_renewal"
    auto_restore_in_window: bool = True
    max_window_duration: Duration  # required (SRE-R-6)
    retention_period: Duration | None = None

    @model_validator(mode="after")
    def _consistent(self) -> PolicyIn:
        if parse_duration(self.renewal_interval) > parse_duration(self.max_age):
            raise ValueError("renewal_interval must not be longer than max_age")
        budget = parse_duration(self.max_window_duration)
        shortest = min(w.length_seconds for w in self.windows)
        if budget > shortest:
            raise ValueError(
                "max_window_duration does not fit in the shortest window: the downtime could not finish in it"
            )
        return self


class BindingIn(_Strict):
    policy_id: UUID
    scope_type: Literal["service_group", "service"]
    scope_id: UUID


class ExceptionIn(_Strict):
    service_id: UUID
    reason: str = Field(min_length=1, max_length=2000)
    owner: str = Field(min_length=1, max_length=200)
    starts_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def _times(self) -> ExceptionIn:
        if self.starts_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError(
                "starts_at and expires_at need a time zone offset, for example 2027-01-31T00:00:00Z"
            )
        if self.expires_at <= self.starts_at:
            raise ValueError("expires_at must be later than starts_at")
        return self


class ApproveIn(_Strict):
    stepup_id: UUID
