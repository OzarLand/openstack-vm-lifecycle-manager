"""Renewal timeout defaults (roadmap P1-8, docs/timeouts.md): named, documented, overridable key by key, checked."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from ovlm.automation.types import DEFAULT_TIMEOUTS, Phase
from ovlm.config import Settings
from ovlm.config.renewal_defaults import (
    AUTOMATION_PHASE_DEFAULTS,
    DEFAULTS_ID,
    KEYSTONE_DEFAULT_TOKEN_LIFETIME,
    SCALAR_DEFAULTS,
    TIMEOUT_DEFAULTS,
)
from ovlm.renewal.config import STEP_TIMEOUT_KEYS, RenewalConfig, log_effective

DOC = Path(__file__).parents[2] / "docs" / "timeouts.md"


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in list(os.environ):
        if key.startswith("OVLM_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(tmp_path / "absent.toml"))


def _settings(**renewal: object) -> Settings:
    return Settings(process_role="worker", renewal=renewal)


def test_fresh_settings_need_no_renewal_key_and_say_which_are_defaults() -> None:
    cfg = RenewalConfig.from_settings(_settings())
    assert cfg.missing(snapshot=True) == []
    assert set(cfg.defaulted) == set(cfg.values())  # all 30 keys, by their settings path
    assert (
        len(cfg.defaulted)
        == len(TIMEOUT_DEFAULTS) + len(AUTOMATION_PHASE_DEFAULTS) + len(SCALAR_DEFAULTS)
        == 30
    )
    assert cfg.timeouts["green_build"] == 900.0 and cfg.validity_retirement == 4 * 3600.0
    record = cfg.record()
    assert (
        record["defaults"] == DEFAULTS_ID
        and record["values"]["renewal.timeouts.fip_status"] == 30.0
    )


def test_every_step_key_has_a_default() -> None:
    assert set(STEP_TIMEOUT_KEYS.values()) | {"green_host_key"} == set(TIMEOUT_DEFAULTS)


def test_an_override_wins_and_only_that_key_leaves_the_defaults() -> None:
    cfg = RenewalConfig.from_settings(
        _settings(timeouts={"green_build": 1200}, healthcheck={"max_attempts": 3})
    )
    assert cfg.timeouts["green_build"] == 1200.0 and cfg.healthcheck_max_attempts == 3
    assert "renewal.timeouts.green_build" not in cfg.defaulted
    assert "renewal.healthcheck.max_attempts" not in cfg.defaulted
    assert len(cfg.defaulted) == 28
    assert cfg.timeouts["server_stop"] == TIMEOUT_DEFAULTS["server_stop"]


def test_override_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OVLM_RENEWAL__TIMEOUTS__VOLUME_DETACH", "75")
    cfg = RenewalConfig.from_settings(Settings(process_role="worker"))
    assert cfg.timeouts["volume_detach"] == 75.0
    assert "renewal.timeouts.volume_detach" not in cfg.defaulted


def test_ansible_step_bounds_follow_the_runner_timeout() -> None:
    assert {p.value: v for p, v in DEFAULT_TIMEOUTS.items()} == dict(AUTOMATION_PHASE_DEFAULTS)
    cfg = RenewalConfig.from_settings(_settings())
    assert cfg.automation == {p: float(t) for p, (t, _i) in AUTOMATION_PHASE_DEFAULTS.items()}
    raised = Settings(process_role="worker", automation={"timeout": {"quiesce": 200}})
    cfg = RenewalConfig.from_settings(raised)
    # still "defaulted": the renewal key itself is not set
    assert cfg.automation["quiesce"] == 200.0
    assert "renewal.automation_timeouts.quiesce" in cfg.defaulted
    assert DEFAULT_TIMEOUTS[Phase.QUIESCE] == (120, 90)


def test_default_worst_cases_stay_under_the_keystone_token_lifetime() -> None:
    cfg = RenewalConfig.from_settings(_settings())
    assert cfg.worst_case_window(snapshot=False, stateless=True) == 2180.0
    assert cfg.worst_case_window(snapshot=False, stateless=False) == 2660.0
    assert cfg.worst_case_window(snapshot=True, stateless=False) == 2960.0
    assert KEYSTONE_DEFAULT_TOKEN_LIFETIME - 600 >= 2960.0  # at least 10 minutes of margin


@pytest.mark.parametrize(
    ("renewal", "automation", "message"),
    [
        ({"timeouts": {"green_bulid": 10}}, {}, "unknown key 'green_bulid'"),
        ({"automation_timeouts": {"cofnigure": 10}}, {}, "unknown key 'cofnigure'"),
        ({"timeouts": {"server_stop": 0}}, {}, "server_stop must be positive"),
        ({"automation_timeouts": {"quiesce": 60}}, {}, "below the runner's timeout"),
        ({}, {"timeout": {"healthcheck": 90}}, None),  # runner raised: the bound follows, no error
        (
            {"automation_timeouts": {"healthcheck": 60}},
            {"timeout": {"healthcheck": 90}},
            "healthcheck",
        ),
        ({"green_ready": {"max_age": 60}}, {}, "B9 step deadline"),
        ({"external_verify": {"required_successes": 7, "interval": 10}}, {}, "never collect"),
        ({"timeouts": {"server_delete": 100}}, {}, "X1"),
    ],
)
def test_relations_between_keys_are_checked(
    renewal: dict[str, object], automation: dict[str, object], message: str | None
) -> None:
    def build() -> Settings:
        return Settings(
            process_role="api", development_mode=True, renewal=renewal, automation=automation
        )

    if message is None:
        build()
        return
    with pytest.raises(ValidationError, match=re.escape(message)):
        build()


def test_start_up_notice_names_the_defaults_and_warns_past_the_token_lifetime(
    caplog: pytest.LogCaptureFixture,
) -> None:
    log = logging.getLogger("test.renewal")
    with caplog.at_level(logging.INFO, logger="test.renewal"):
        log_effective(RenewalConfig.from_settings(_settings()), log)
    (rec,) = caplog.records
    assert (
        "30 key(s) use the built-in defaults" in rec.getMessage()
        and DEFAULTS_ID in rec.getMessage()
    )
    assert rec.renewal_defaulted_keys == sorted(RenewalConfig.from_settings(_settings()).values())  # type: ignore[attr-defined]
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="test.renewal"):
        log_effective(RenewalConfig.from_settings(_settings(timeouts={"snapshot": 1500})), log)
    assert [r.levelno for r in caplog.records] == [logging.INFO, logging.WARNING]
    assert "Keystone" in caplog.records[1].getMessage()


def test_the_doc_lists_every_default_with_its_value() -> None:
    """docs/timeouts.md is the reviewable source: each key appears in its tables with the value the code uses."""
    text = DOC.read_text()
    assert DEFAULTS_ID in text
    for key, value in TIMEOUT_DEFAULTS.items():
        assert re.search(rf"^\| `{key}` \| {value:g} \|", text, re.MULTILINE), key
    for phase, (timeout, idle) in AUTOMATION_PHASE_DEFAULTS.items():
        assert re.search(rf"^\| `{phase}` \| {timeout} / {idle}\b", text, re.MULTILINE), phase
    for key, value in SCALAR_DEFAULTS.items():
        section, name = key.split(".")
        assert re.search(
            rf"^\| `\[renewal\.{section}\] {name}` \| {value:g}\b", text, re.MULTILINE
        ), key
