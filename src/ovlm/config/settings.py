"""Settings model."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    NoDecode,
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


class RenewalSettings(_Section):
    #: Global cap on admitted (non-terminal, non-requested) renewal runs (NFR-9). Checked at admission.
    max_concurrent_runs: int = Field(default=5, ge=1)


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


AUTOMATION_PHASES: tuple[str, ...] = (
    "preflight",
    "configure",
    "quiesce",
    "data_attach",
    "start_service",
    "healthcheck",
    "rollback_hooks",
)
_OS_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class AutomationSettings(_Section):
    """``automation.*`` (architecture.md section 5, automation-contract.md section 11). Worker only: the api never
    reads it. Secrets are files (``*_file``); nothing here holds a secret value."""

    #: Parent of the per-attempt run directories. tmpfs in the worker container (secrets touch only memory).
    run_root: Path = Path("/run/ovlm")
    require_tmpfs: bool = False
    #: Directory holding ``ansible`` and ``ansible-runner`` (the worker image's venv). ``None``: the running
    #: interpreter's directory.
    ansible_bin_dir: Path | None = None
    #: Pre-provisioned, pinned collections (the worker image ships ``ansible.posix`` at this path). Never filled at
    #: run time: Galaxy is not contacted (SEC-R-12).
    collections_paths: Annotated[tuple[Path, ...], NoDecode] = (Path("/opt/ovlm/collections"),)
    #: OS user ansible runs as. ``None`` runs it as the worker user: refused outside development mode.
    run_user: str | None = "ovlm-ansible"
    #: Command prepended to ``kill`` when a direct signal to the runner user's processes is refused (e.g.
    #: ``["sudo", "-n", "-u", "ovlm-ansible"]``). Unneeded when the worker holds CAP_KILL (the container image does).
    signal_prefix: Annotated[tuple[str, ...], NoDecode] = ()
    #: Per-phase overrides, seconds. A phase absent keeps the contract default (section 6).
    timeout: dict[str, int] = Field(default_factory=dict)
    idle_timeout: dict[str, int] = Field(default_factory=dict)
    #: Hard ceiling per phase: the effective timeout is min(profile value, this). Absent: 4 x the default.
    max_timeout: dict[str, int] = Field(default_factory=dict)
    result_max_bytes: int = Field(default=1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    log_max_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)
    #: Days restricted artefacts (log, events, diff) are kept; separate from the audit retention.
    artifact_retention_days: int = Field(default=30, ge=1, le=3650)
    #: Allowlisted automation repository URL prefixes (https or ssh). Empty refuses every repository.
    allowed_repos: Annotated[tuple[str, ...], NoDecode] = ()
    #: Optional deploy key (ssh URLs): files, mode 0600, and the git host's known_hosts.
    git_ssh_key_file: Path | None = None
    git_ssh_known_hosts_file: Path | None = None

    @field_validator("allowed_repos", "collections_paths", mode="before")
    @classmethod
    def _split(cls, value: object) -> object:
        # an environment variable carries the list as comma separated text (TOML: a real list)
        if isinstance(value, str):
            return tuple(v for v in (p.strip() for p in value.split(",")) if v)
        return value

    @field_validator("signal_prefix", mode="before")
    @classmethod
    def _split_words(cls, value: object) -> object:
        return (
            tuple(value.split()) if isinstance(value, str) else value
        )  # "sudo -n -u ovlm-ansible"

    @model_validator(mode="after")
    def _check(self) -> AutomationSettings:
        for name in ("timeout", "idle_timeout", "max_timeout"):
            table: dict[str, int] = getattr(self, name)
            for phase, seconds in table.items():
                if phase not in AUTOMATION_PHASES:
                    raise ValueError(f"automation.{name}: unknown phase {phase!r}")
                if seconds <= 0:
                    raise ValueError(f"automation.{name}.{phase} must be positive")
        if self.run_user is not None and not _OS_USER.match(self.run_user):
            raise ValueError("automation.run_user is not a valid OS user name")
        if not self.run_root.is_absolute():
            raise ValueError("automation.run_root must be an absolute path")
        if self.ansible_bin_dir is not None and not self.ansible_bin_dir.is_absolute():
            raise ValueError("automation.ansible_bin_dir must be an absolute path")
        if any(not p.is_absolute() for p in self.collections_paths):
            raise ValueError("automation.collections_paths must be absolute paths")
        for url in self.allowed_repos:
            parts = urlsplit(url)
            if (
                parts.scheme not in {"https", "ssh"}
                or not parts.hostname
                or parts.password
                or (parts.username and parts.scheme == "https")
            ):
                raise ValueError(
                    "automation.allowed_repos entries must be https:// or ssh:// URL prefixes without credentials"
                )
        if (self.git_ssh_key_file is None) != (self.git_ssh_known_hosts_file is None):
            raise ValueError(
                "automation.git_ssh_key_file and automation.git_ssh_known_hosts_file go together"
            )
        return self


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
    automation: AutomationSettings = AutomationSettings()

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
            if self.process_role == "worker" and self.automation.run_user is None:
                raise ValueError(
                    "automation.run_user must name the separate OS user (security-model.md 6.5); "
                    "null (ansible as the worker user) is for development_mode only"
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
