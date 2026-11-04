"""Settings model."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)
from sqlalchemy.engine import URL

from ovlm.config.secrets import read_secret_file

ProcessRole = Literal["api", "worker", "migrate"]

#: Fixed DB role per process (data-model.md section 12). Not configurable on purpose.
DB_ROLE_FOR_PROCESS: dict[str, str] = {
    "api": "ovlm_api",
    "worker": "ovlm_worker",
    "migrate": "ovlm_owner",
}

DEFAULT_CONFIG_FILE = "/etc/ovlm/ovlm.toml"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DatabaseSettings(_Section):
    host: str = "localhost"
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = "ovlm"
    sslmode: Literal["disable", "allow", "prefer", "require", "verify-ca", "verify-full"] = "prefer"
    #: Path of the file holding this process's DB role password (Docker secret).
    password_file: Path | None = None


class HttpSettings(_Section):
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    #: Internal listener for /metrics (SEC-R-17). Never published by the Compose file.
    metrics_host: str = "127.0.0.1"
    metrics_port: int = Field(default=9100, ge=1, le=65535)
    #: Addresses or networks of the TLS reverse proxies in front of the api (security-model.md section 9). Only a
    #: request whose peer is in this list may name the client with ``X-Forwarded-For``; from anyone else the header
    #: is ignored and the peer address is the client. The default trusts a proxy on the same host (loopback).
    #: A containerised proxy on the Compose network must be listed here, or every client looks like the proxy.
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
        ipaddress.IPv4Network("127.0.0.1/32"),
        ipaddress.IPv6Network("::1/128"),
    )

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _parse_networks(cls, value: object) -> object:
        if isinstance(value, str):
            value = [v for v in (p.strip() for p in value.split(",")) if v]
        if isinstance(value, list | tuple):
            return tuple(ipaddress.ip_network(str(v), strict=False) for v in value)
        return value


class LogSettings(_Section):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    #: Let the openstacksdk / keystoneauth / HTTP client loggers follow ``level`` (curl lines with request and
    #: response bodies at DEBUG). Off: they are pinned to WARNING whatever ``level`` says (security-model.md 4.5,
    #: SEC-C-2). Refused unless ``development_mode`` is on, so it can never be switched on in production by a
    #: config key alone. Even when on, the server-create request (``user_data``) is sent with logging disabled.
    openstack_http_debug: bool = False


class WorkerSettings(_Section):
    #: Seconds between worker loop iterations / heartbeat updates. Default TBD in lab.
    heartbeat_interval: float = Field(default=5.0, gt=0)
    #: Seconds allowed for a graceful stop before the loop gives up waiting.
    shutdown_grace: float = Field(default=30.0, gt=0)
    #: Concurrent steps per worker process (ADR-0003).
    slots: int = Field(default=4, ge=1, le=64)
    #: Seconds a claim or heartbeat extends a step lease (DB time). Must exceed several heartbeats.
    lease_duration: float = Field(default=60.0, gt=0)
    #: Seconds subtracted from the lease to form the local fence deadline (ADR-0003, SRE-R-2).
    fence_margin: float = Field(default=10.0, gt=0)
    #: Seconds a takeover of a destructive / window / restore step waits before probing (SRE-R-27).
    #: Must be >= the SDK request timeout + fence_margin; the SDK timeout is checked by the openstack module.
    takeover_delay: float = Field(default=45.0, ge=0)

    @model_validator(mode="after")
    def _check_lease(self) -> WorkerSettings:
        if self.lease_duration < 3 * self.heartbeat_interval:
            raise ValueError("worker.lease_duration must be >= 3 x worker.heartbeat_interval")
        if self.fence_margin + self.heartbeat_interval >= self.lease_duration:
            raise ValueError(
                "worker.fence_margin + worker.heartbeat_interval must be < worker.lease_duration"
            )
        if self.takeover_delay < self.fence_margin:
            raise ValueError("worker.takeover_delay must be >= worker.fence_margin")
        return self


class PollSettings(_Section):
    #: Backoff of WAIT re-claims and of signal polling (ADR-0003 "timers").
    initial_interval: float = Field(default=5.0, gt=0)
    max_interval: float = Field(default=300.0, gt=0)


class RetrySettings(_Section):
    #: Default bound on retryable failures of one step; ``max_attempts_per_step`` overrides by step_key.
    max_attempts: int = Field(default=3, ge=1)
    max_attempts_per_step: dict[str, int] = Field(default_factory=dict)
    #: Backoff before re-running a step after a retryable failure.
    backoff_initial: float = Field(default=10.0, gt=0)
    backoff_max: float = Field(default=300.0, gt=0)


class AlertSettings(_Section):
    #: Seconds before an unadmitted run (SRE-R-25) or an unconsumed signal (SRE-R-24) is flagged in metrics.
    after: float = Field(default=300.0, gt=0)


class RenewalGreenReady(_Section):
    #: ``green_ready.max_age``: B9 success must be younger than this when W1 is claimed. Default TBD in lab.
    max_age: float | None = Field(default=None, gt=0)


class RenewalHealthcheck(_Section):
    #: ``healthcheck.max_attempts`` / ``healthcheck.interval`` (W8). Defaults TBD in lab.
    max_attempts: int | None = Field(default=None, ge=1)
    interval: float | None = Field(default=None, ge=0)


class RenewalExternalVerify(_Section):
    #: ``external_verify.required_successes`` / ``external_probe.interval`` (W10, S9). Defaults TBD in lab.
    required_successes: int | None = Field(default=None, ge=1)
    interval: float | None = Field(default=None, ge=0)


class RenewalRetire(_Section):
    #: ``retire.health_max_age``: X1 needs a green healthcheck younger than this. Default TBD in lab.
    health_max_age: float | None = Field(default=None, gt=0)


class RenewalApprovalValidity(_Section):
    #: ``approval.validity.*`` in seconds. Plan 24 h and cutover 4 h are the security-model.md 7.1 defaults; the
    #: retirement validity has no documented default and must be configured.
    plan: float = Field(default=24 * 3600, gt=0)
    cutover: float = Field(default=4 * 3600, gt=0)
    retirement: float | None = Field(default=None, gt=0)


class RenewalSettings(_Section):
    #: Global cap on admitted (non-terminal, non-requested) renewal runs (NFR-9). Checked at admission.
    max_concurrent_runs: int = Field(default=5, ge=1)
    #: ``timeouts.<key>`` of renewal-workflow.md (seconds). **No defaults** (TBD in lab): a run whose strategy
    #: needs a key that is not configured is rejected at admission with the list of missing keys.
    timeouts: dict[str, float] = Field(default_factory=dict)
    #: ``automation.timeout.<phase>`` (seconds) as the renewal uses them for step deadlines, leases and the
    #: worst-case window shown at G2. No defaults (renewal-workflow.md section 8 item 11: TBD in lab).
    automation_timeouts: dict[str, float] = Field(default_factory=dict)
    green_ready: RenewalGreenReady = RenewalGreenReady()
    healthcheck: RenewalHealthcheck = RenewalHealthcheck()
    external_verify: RenewalExternalVerify = RenewalExternalVerify()
    retire: RenewalRetire = RenewalRetire()
    approval_validity: RenewalApprovalValidity = RenewalApprovalValidity()


class AuthSettings(_Section):
    """Authentication knobs (security-model.md section 2). Defaults are the documented values."""

    #: File holding the Fernet key that encrypts TOTP secrets at rest (Docker secret, api only).
    #: Without it TOTP enrolment and verification refuse to work (fail closed).
    totp_key_file: Path | None = None
    session_idle_minutes: int = Field(default=30, ge=1, le=24 * 60)
    session_absolute_hours: int = Field(default=12, ge=1, le=24 * 7)
    enrolment_link_hours: int = Field(default=72, ge=1, le=24 * 14)
    #: Failed attempts per account / per source address in the window before backoff applies.
    login_failure_threshold: int = Field(default=5, ge=1)
    login_ip_failure_threshold: int = Field(default=20, ge=1)
    login_window_minutes: int = Field(default=15, ge=1)
    #: Delay applied per source address once ``login_ip_failure_threshold`` is reached. It is fixed and never
    #: escalates: only the per-account backoff doubles (up to 15 minutes), so a shared or misattributed source
    #: address can slow other users for seconds, never lock them out (SEC-C-1).
    login_ip_delay_seconds: int = Field(default=10, ge=1, le=60)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OVLM_",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
    )

    process_role: ProcessRole = "api"
    #: Development / test installation. Off (the default) means production: the api refuses to start without
    #: ``external_url`` and ``log.openstack_http_debug`` is refused. Never set it on a real installation.
    development_mode: bool = False
    #: Public origin of the UI/API behind the TLS proxy (``https://ovlm.example.org``). Required in production for
    #: the api: the CSRF Origin check and the enrolment links use it (SEC-C-11).
    external_url: str | None = None
    migrations_dir: Path = Path("migrations")
    db: DatabaseSettings = DatabaseSettings()
    http: HttpSettings = HttpSettings()
    log: LogSettings = LogSettings()
    worker: WorkerSettings = WorkerSettings()
    poll: PollSettings = PollSettings()
    retry: RetrySettings = RetrySettings()
    admission: AlertSettings = AlertSettings()
    signal: AlertSettings = AlertSettings()
    renewal: RenewalSettings = RenewalSettings()
    auth: AuthSettings = AuthSettings()

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if self.http.port == self.http.metrics_port and self.http.host == self.http.metrics_host:
            raise ValueError(
                "http.port and http.metrics_port must differ (metrics use a separate port)"
            )
        if not self.development_mode:
            if self.process_role == "api" and not self.external_url:
                raise ValueError(
                    "external_url is required for the api (CSRF Origin check, enrolment links); "
                    "set development_mode = true only on a development installation"
                )
            if self.log.openstack_http_debug:
                raise ValueError(
                    "log.openstack_http_debug logs OpenStack request and response bodies (credentials, "
                    "bootstrap keys) and is refused unless development_mode is on"
                )
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        toml_path = os.environ.get("OVLM_CONFIG_FILE", DEFAULT_CONFIG_FILE)
        return (
            init_settings,
            env_settings,
            TomlConfigSettingsSource(settings_cls, toml_file=toml_path),
        )

    @property
    def db_role(self) -> str:
        return DB_ROLE_FOR_PROCESS[self.process_role]

    def db_url(self) -> URL:
        """SQLAlchemy URL for this process's DB role. The password is read from its file now and is never
        stringified into a URL string by this code (``URL`` objects mask it in ``repr``)."""
        password = read_secret_file(self.db.password_file) if self.db.password_file else None
        return URL.create(
            "postgresql+psycopg",
            username=self.db_role,
            password=password,
            host=self.db.host,
            port=self.db.port,
            database=self.db.name,
            query={"sslmode": self.db.sslmode},
        )
