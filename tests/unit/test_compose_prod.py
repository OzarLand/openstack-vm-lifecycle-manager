"""The production Compose file and ``make secrets`` (roadmap P1-9).

* ``compose.prod.yaml`` never turns development mode on, loads the TOML configuration from a read-only mount, takes
  pinned images from required variables instead of building, restarts the long-running services, and keeps the
  secret split and the worker's privilege model of ``compose.yaml`` (the file ``make smoke`` checks in CI).
* ``make secrets`` creates missing files with their modes and never changes an existing file or its mode.

The structure is checked on the YAML itself (no Docker needed); when the ``docker compose`` plugin is installed, the
file is also resolved with ``docker compose config``, which needs no daemon (CI runs it in ``make compose-check``).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parents[2]
PROD = ROOT / "compose.prod.yaml"
DEV = ROOT / "compose.yaml"
MAKEFILE = ROOT / "Makefile"

API_SECRETS = {"db_api_password", "worker_kek_pub", "totp_key"}
WORKER_SECRETS = {"db_worker_password", "worker_kek"}
WORKER_ONLY = {"worker_kek", "db_worker_password"}
ENV_FOR_CONFIG = {
    "OVLM_IMAGE": "registry.example.org/ovlm@sha256:" + "a" * 64,
    "OVLM_WORKER_IMAGE": "registry.example.org/ovlm-worker@sha256:" + "b" * 64,
    "OVLM_EXTERNAL_URL": "https://ovlm.example.org",
}


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)
    return data


def _services(path: Path) -> dict[str, dict[str, Any]]:
    return _load(path)["services"]  # type: ignore[no-any-return]


def _env(service: dict[str, Any]) -> dict[str, str]:
    env = service.get("environment") or {}
    assert isinstance(env, dict), "environment must be a mapping"
    return {str(k): str(v) for k, v in env.items()}


def _secret_names(service: dict[str, Any]) -> set[str]:
    return {s if isinstance(s, str) else s["source"] for s in service.get("secrets", [])}


def _mount_targets(service: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for v in service.get("volumes", []):
        if isinstance(v, str):
            parts = v.split(":")
            out[parts[1]] = {"source": parts[0], "read_only": parts[2:] == ["ro"]}
        else:
            out[v["target"]] = v
    return out


# --- compose.prod.yaml: structure -------------------------------------------------------------------------------


def test_no_service_runs_in_development_mode() -> None:
    for name, svc in _services(PROD).items():
        env = _env(svc)
        assert env.get("OVLM_DEVELOPMENT_MODE", "false").lower() == "false", name
        assert env.get("OVLM_CONFIG_FILE") != "/nonexistent", name
    assert "DEVELOPMENT_MODE" not in PROD.read_text().replace("development mode", "")


def test_every_ovlm_service_loads_the_config_file_from_a_read_only_mount() -> None:
    services = _services(PROD)
    for name in ("migrate", "api", "worker"):
        svc = services[name]
        assert _env(svc)["OVLM_CONFIG_FILE"] == "/etc/ovlm/ovlm.toml", name
        mount = _mount_targets(svc)["/etc/ovlm/ovlm.toml"]
        assert mount["read_only"] is True, name
        assert mount.get("bind", {}).get("create_host_path") is False, (
            f"{name}: a missing config file must fail, not become an empty directory"
        )


def test_images_are_required_parameters_and_nothing_is_built() -> None:
    services = _services(PROD)
    for name, svc in services.items():
        assert "build" not in svc, f"{name} builds from source: production runs pinned images"
    for name in ("migrate", "api"):
        assert services[name]["image"].startswith("${OVLM_IMAGE:?"), name
    assert services["worker"]["image"].startswith("${OVLM_WORKER_IMAGE:?")
    assert "@sha256:" in services["postgres"]["image"]


def test_restart_policies_and_healthchecks() -> None:
    services = _services(PROD)
    for name in ("postgres", "api", "worker"):
        assert services[name]["restart"] == "unless-stopped", name
        assert services[name]["healthcheck"]["test"], name
    assert services["migrate"]["restart"] == "no"
    for name in ("api", "worker"):
        assert (
            services[name]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
        )


def test_the_api_runs_in_production_mode_behind_a_loopback_port() -> None:
    api = _services(PROD)["api"]
    env = _env(api)
    assert env["OVLM_EXTERNAL_URL"].startswith("${OVLM_EXTERNAL_URL:?"), (
        "external_url must be required"
    )
    assert "OVLM_HTTP__TRUSTED_PROXIES" in env
    assert all(str(p).startswith("127.0.0.1:") for p in api["ports"]), api["ports"]
    for name, svc in _services(PROD).items():
        if name != "api":
            assert "ports" not in svc, f"{name} must not publish a port"


def test_secrets_are_split_as_in_the_development_file() -> None:
    prod, dev = _services(PROD), _services(DEV)
    assert _secret_names(prod["api"]) == API_SECRETS == _secret_names(dev["api"])
    assert _secret_names(prod["worker"]) == WORKER_SECRETS == _secret_names(dev["worker"])
    assert _secret_names(prod["migrate"]) == {"db_owner_password"}
    assert not WORKER_ONLY & _secret_names(prod["api"]), "worker-only secrets reach the api"
    assert "totp_key" not in _secret_names(prod["worker"])
    api_env = _env(prod["api"])
    assert "OVLM_KEK__PRIVATE_KEY_FILE" not in api_env
    assert "OVLM_RENEWAL__CREDENTIALS_DIR" not in api_env
    assert "OVLM_LOG__OPENSTACK_HTTP_DEBUG" not in api_env
    assert _load(PROD)["secrets"] == _load(DEV)["secrets"], "the same files under ./secrets"


def test_hardening_and_worker_privilege_model_match_the_development_file() -> None:
    prod, dev = _services(PROD), _services(DEV)
    for name in ("migrate", "api", "worker"):
        assert prod[name]["read_only"] is True, name
        assert prod[name]["cap_drop"] == ["ALL"], name
        assert prod[name]["security_opt"] == ["no-new-privileges:true"], name
    for key in ("user", "cap_add", "tmpfs", "healthcheck"):
        if key == "healthcheck":
            assert prod["worker"][key]["test"] == dev["worker"][key]["test"]
        else:
            assert prod["worker"][key] == dev["worker"][key], key
    assert not prod["worker"].get("init")
    assert _mount_targets(prod["worker"])["/var/lib/ovlm/checkouts"]["source"] == "checkouts"
    worker_env, dev_worker_env = _env(prod["worker"]), _env(dev["worker"])
    for key in (
        "OVLM_AUTOMATION__RUN_ROOT",
        "OVLM_AUTOMATION__REQUIRE_TMPFS",
        "OVLM_AUTOMATION__RUN_USER",
        "OVLM_AUTOMATION__CHECKOUT_CACHE",
        "OVLM_KEK__PRIVATE_KEY_FILE",
    ):
        assert worker_env[key] == dev_worker_env[key], key


def test_the_project_name_differs_from_the_development_stack() -> None:
    """``make down`` (``docker compose -f compose.yaml down -v``) must never delete the production volumes."""
    assert _load(DEV)["name"] == "ovlm"
    assert "ovlm-prod" in str(_load(PROD)["name"])
    make = MAKEFILE.read_text()
    assert "DEV_COMPOSE := docker compose -f compose.yaml$(if " in make
    assert "\t$(DEV_COMPOSE) down -v" in make


@pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(["docker", "compose", "version"], capture_output=True).returncode != 0,
    reason="the docker compose plugin is not installed (CI runs make compose-check)",
)
def test_docker_compose_resolves_the_file() -> None:
    env = {**os.environ, **ENV_FOR_CONFIG}
    for var in ("COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "OVLM_TRUSTED_PROXIES", "OVLM_CONFIG"):
        env.pop(var, None)
    out = subprocess.run(
        ["docker", "compose", "-f", str(PROD), "config", "--format", "json"],
        capture_output=True, text=True, env=env, cwd=ROOT, check=True,
    )  # fmt: skip
    model = json.loads(out.stdout)
    assert model["name"] == "ovlm-prod"
    services = model["services"]
    assert services["api"]["image"] == ENV_FOR_CONFIG["OVLM_IMAGE"]
    assert services["worker"]["image"] == ENV_FOR_CONFIG["OVLM_WORKER_IMAGE"]
    assert services["api"]["environment"]["OVLM_HTTP__TRUSTED_PROXIES"] == "172.30.240.1/32"
    assert model["networks"]["default"]["ipam"]["config"][0]["gateway"] == "172.30.240.1"
    assert {s["source"] for s in services["api"]["secrets"]} == API_SECRETS
    missing = {k: v for k, v in env.items() if k != "OVLM_EXTERNAL_URL"}
    refused = subprocess.run(
        ["docker", "compose", "-f", str(PROD), "config", "-q"],
        capture_output=True, text=True, env=missing, cwd=ROOT,
    )  # fmt: skip
    assert refused.returncode != 0 and "OVLM_EXTERNAL_URL" in refused.stderr


# --- make secrets ------------------------------------------------------------------------------------------------

needs_make = pytest.mark.skipif(
    shutil.which("make") is None or shutil.which("openssl") is None, reason="needs make and openssl"
)


def _make_secrets(cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "-s", "-f", str(MAKEFILE), "secrets"],
        cwd=cwd, capture_output=True, text=True, check=True,
    )  # fmt: skip


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@needs_make
def test_make_secrets_creates_every_file_with_its_mode(tmp_path: Path) -> None:
    _make_secrets(tmp_path)
    d = tmp_path / "secrets"
    assert _mode(d) == 0o700
    expected = {
        "db_superuser_password": 0o444,
        "db_owner_password": 0o444,
        "db_api_password": 0o444,
        "db_worker_password": 0o444,
        "worker_kek": 0o400,
        "worker_kek.pub": 0o444,
        "totp_key": 0o444,
    }
    assert {p.name: _mode(p) for p in d.iterdir()} == expected
    assert "PRIVATE KEY" in (d / "worker_kek").read_text()
    assert "PUBLIC KEY" in (d / "worker_kek.pub").read_text()


@needs_make
def test_make_secrets_never_changes_an_existing_file_or_its_mode(tmp_path: Path) -> None:
    _make_secrets(tmp_path)
    d = tmp_path / "secrets"
    # the operator tightens the TOTP key (install-guide-real-cloud.md 5.2) and one password file
    (d / "totp_key").chmod(0o400)
    (d / "db_api_password").chmod(0o440)
    before = {p.name: (p.read_bytes(), _mode(p)) for p in d.iterdir()}
    out = _make_secrets(tmp_path)
    after = {p.name: (p.read_bytes(), _mode(p)) for p in d.iterdir()}
    assert after == before
    assert "created" not in out.stdout
    assert _mode(d / "totp_key") == 0o400


@needs_make
def test_make_secrets_fills_in_only_what_is_missing(tmp_path: Path) -> None:
    _make_secrets(tmp_path)
    d = tmp_path / "secrets"
    kek = (d / "worker_kek").read_bytes()
    (d / "worker_kek.pub").unlink()
    (d / "db_owner_password").unlink()
    out = _make_secrets(tmp_path)
    assert "created secrets/worker_kek.pub" in out.stdout
    assert "created secrets/db_owner_password" in out.stdout
    assert (d / "worker_kek").read_bytes() == kek, "an existing KEK is never replaced"
    assert _mode(d / "worker_kek.pub") == 0o444
    assert _mode(d / "db_owner_password") == 0o444


@needs_make
def test_make_secrets_warns_about_a_loose_kek_without_changing_it(tmp_path: Path) -> None:
    _make_secrets(tmp_path)
    kek = tmp_path / "secrets" / "worker_kek"
    kek.chmod(0o644)
    out = _make_secrets(tmp_path)
    assert "WARNING: secrets/worker_kek" in out.stderr
    assert _mode(kek) == 0o644
