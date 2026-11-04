"""Settings model."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
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


class LogSettings(_Section):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"


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


class RenewalSettings(_Section):
    #: Global cap on admitted (non-terminal, non-requested) renewal runs (NFR-9). Checked at admission.
    max_concurrent_runs: int = Field(default=5, ge=1)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OVLM_",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
    )

    process_role: ProcessRole = "api"
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

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if self.http.port == self.http.metrics_port and self.http.host == self.http.metrics_host:
            raise ValueError(
                "http.port and http.metrics_port must differ (metrics use a separate port)"
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
