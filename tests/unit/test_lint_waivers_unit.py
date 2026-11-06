"""Lint waivers (SF-13): the api's copy of the rule names matches the lint, the data-safety rules are never waivable,
and the plan hash changes only when a waiver exists."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ovlm.automation import lint
from ovlm.profiles.waivers import PATH_GLOB, WAIVABLE_RULES, hash_binding
from ovlm.renewal.plans import compute_plan_hash

LINT_SRC = Path(lint.__file__).read_text()
NEVER = {"formatting", "quiesce_state", "ssh_override", "hosts_pattern", "parse_error"}


def test_waivable_rules_are_blocking_lint_rules_and_exclude_the_data_safety_ones() -> None:
    documented = set(re.findall(r"^\* ``([a-z_]+)``", lint.__doc__ or "", re.M))
    for rule in (*WAIVABLE_RULES, *NEVER):
        assert rule in documented, rule
        assert (
            re.search(rf'"{rule}",?\s*\n?\s*"error"', LINT_SRC) or f'"{rule}", "error"' in LINT_SRC
        ), rule
    assert not NEVER & set(WAIVABLE_RULES)
    assert "templated_task_name" not in WAIVABLE_RULES  # warnings never need one


def test_path_glob_shape() -> None:
    assert PATH_GLOB.match("roles/*/tasks/*.yml") and PATH_GLOB.match("*")
    assert not PATH_GLOB.match("roles/x y") and not PATH_GLOB.match("")


def test_plan_hash_binds_waivers_only_when_there_are_some() -> None:
    base: dict[str, Any] = {"resolved": {"blue": {"server_id": "s"}}, "profile_version_id": "pv", "spec_hash": "h",
            "automation_sha": "a" * 40, "policy": {"id": "p", "version": 1}}  # fmt: skip
    plain = compute_plan_hash(**base)
    assert compute_plan_hash(**base, lint_waivers=[]) == plain  # existing plans keep their hash
    w = {
        "id": "w1",
        "rule": "check_mode_forced",
        "path_glob": "*",
        "granted_by": "u",
        "reason": "r" * 10,
    }
    one = compute_plan_hash(**base, lint_waivers=hash_binding([w]))
    assert one != plain
    other = compute_plan_hash(**base, lint_waivers=hash_binding([{**w, "path_glob": "roles/*"}]))
    assert other not in (plain, one)
