"""Readiness framework and MVP checks (E4-1, E4-2): level rules, every check's outcomes, catalogue invariants.

The checks are pure functions of the snapshot, so these tests build snapshots by hand: no database, no OpenStack."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest

from ovlm.readiness.checks import ATTESTATIONS, BY_KEY, CHECKS, catalogue
from ovlm.readiness.levels import derive_level, summarize
from ovlm.readiness.model import Category, Check, CheckResult, Level, Outcome, Result, Severity
from ovlm.readiness.runner import run_check, run_checks
from tests.unit.test_profile_spec_unit import FIP, SHA, SPEC, VOL

P, F, U, N = Result.PASS, Result.FAIL, Result.UNKNOWN, Result.NOT_APPLICABLE
B, W, I = Severity.BLOCKER, Severity.WARNING, Severity.INFO  # noqa: E741

PROFILE_VERSION = "pv-1"
NOW = "2026-11-04T12:00:00+00:00"


def good() -> dict[str, Any]:
    """A VM that passes every check except the attestations (nobody attested yet)."""
    return {
        "schema": 1, "taken_at": NOW, "now": NOW, "live_code_run": False,
        "managed_vm": {"id": "vm-1", "service_id": "svc-1", "openstack_server_id": "srv-1", "role": "current"},
        "profile": {"id": "prof-1", "version_id": PROFILE_VERSION, "number": 1, "spec_hash": "0" * 64,
                    "spec": copy.deepcopy(SPEC)},
        "server": {"id": "obs-1", "openstack_id": "srv-1", "name": "blue", "observation_status": "present",
                   "synced_at": NOW, "payload_hash": "h", "revision_id": "rev-1",
                   "data": {"status": "ACTIVE", "image_id": "img-1", "locked": False, "is_minimal_construct": False}},
        "attachments": [{"volume_openstack_id": VOL, "device": "/dev/vdb", "delete_on_termination": False}],
        "volumes": {VOL: {"status": "in-use", "size": 10, "bootable": False, "multiattach": False,
                          "volume_type": "ssd", "observation_status": "present"}},
        "ports": [{"openstack_id": "port-1", "network_id": "net-1"}],
        "networks": {"net-1": {"name": "tenant", "is_external": False}},
        "floating_ips": [{"openstack_id": FIP, "floating_ip_address": "192.0.2.10", "port_id": "port-1"}],
        "flavor_candidates": [{"openstack_id": "fl-1", "name": "m1.small", "vcpus": 1, "ram": 1024, "disk": 10}],
        "image_candidates": [{"openstack_id": "img-9", "name": "ubuntu-24.04", "status": "active", "visibility": "public"}],
        "quota": None, "attestations": [],
    }  # fmt: skip


def result_of(key: str, snap: dict[str, Any]) -> Outcome:
    return BY_KEY[key].run(snap)


def edit(fn: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    snap = good()
    fn(snap)
    return snap


def attested(
    snap: dict[str, Any],
    *,
    expires: str | None = "2027-01-01T00:00:00+00:00",
    version: str = PROFILE_VERSION,
) -> None:
    snap["attestations"] = [
        {"check_key": k, "attested_by": "u-1", "attested_at": NOW, "expires_at": expires, "profile_version_id": version}
        for k in ATTESTATIONS
    ]  # fmt: skip


# --- level rules (FR-RDY-3) ---------------------------------------------------------------------------------------------


def cr(result: Result, severity: Severity, key: str = "k") -> CheckResult:
    return CheckResult(key, 1, Category.DATA, severity, result, {}, None)


@pytest.mark.parametrize(
    ("results", "level"),
    [
        ([], Level.READY),
        ([cr(P, B), cr(P, W), cr(P, I)], Level.READY),
        ([cr(F, B), cr(P, B)], Level.NOT_READY),
        ([cr(U, B), cr(P, B)], Level.PARTIALLY_READY),
        ([cr(F, B), cr(U, B)], Level.NOT_READY),  # a failed blocker outranks an unknown one
        ([cr(F, W), cr(U, W), cr(F, I)], Level.READY),  # warnings and info never move the level
        ([cr(N, B), cr(N, B)], Level.READY),  # not-applicable is neither pass nor fail
        ([cr(U, W), cr(P, B)], Level.READY),
    ],
)
def test_level_rules_are_explicit(results: list[CheckResult], level: Level) -> None:
    assert derive_level(results) is level


def test_level_does_not_depend_on_how_many_checks_pass() -> None:
    nine_pass_one_fail = [cr(P, B, f"p{i}") for i in range(9)] + [cr(F, B, "bad")]
    assert derive_level(nine_pass_one_fail) is Level.NOT_READY
    assert summarize(nine_pass_one_fail)["text"] == "9/10 applicable checks pass"


def test_summary_is_orientation_only_and_names_what_decided() -> None:
    s = summarize([cr(P, B, "a"), cr(F, B, "b"), cr(U, B, "c"), cr(N, B, "d"), cr(F, W, "e")])
    assert s["counts"] == {"pass": 1, "fail": 2, "unknown": 1, "not-applicable": 1}
    assert s["failed_blockers"] == ["b"] and s["unknown_blockers"] == ["c"]
    assert s["orientation_only"] is True and s["applicable"] == 4 and s["total"] == 5


# --- catalogue invariants -----------------------------------------------------------------------------------------------


def test_catalogue_is_named_versioned_and_covers_the_five_categories() -> None:
    assert len({c.key for c in CHECKS}) == len(CHECKS)
    assert all(c.version >= 1 and c.title and c.description for c in CHECKS)
    assert {c.category for c in CHECKS} == set(Category)
    entry = catalogue()[0]
    assert set(entry) == {"key", "version", "category", "severity", "title", "description"}


def test_a_good_vm_passes_everything_but_the_unattested_hook() -> None:
    level, summary, results = run_checks(good())
    by = {r.key: r.result for r in results}
    assert by["external.human_attestations"] is U and by["automation.drift_unchecked"] is U
    assert by["platform.quota_headroom"] is U  # no quota reading yet
    assert all(v is P for k, v in by.items() if k not in {
        "external.human_attestations", "automation.drift_unchecked", "platform.quota_headroom"})  # fmt: skip
    assert level is Level.READY  # every unknown one is a warning


def test_every_result_carries_evidence_or_a_recommendation() -> None:
    for r in run_checks(good())[2]:
        assert r.evidence or r.recommendation, r.key
    broken = good()
    broken["attachments"] = []
    for r in run_checks(broken)[2]:
        if r.result in (F, U):
            assert r.recommendation, r.key


def test_a_crashing_check_is_unknown_and_does_not_stop_the_others() -> None:
    def boom(_: dict[str, Any]) -> Outcome:
        raise KeyError("secret-ish detail")

    c = Check("x.boom", 1, Category.DATA, B, "t", "d", boom)
    r = run_check(c, good())
    assert (
        r.result is U and "KeyError" in r.evidence["error"] and "secret-ish" not in str(r.evidence)
    )
    level, _, results = run_checks(good(), (c, *CHECKS))
    assert (
        level is Level.PARTIALLY_READY and len(results) == len(CHECKS) + 1
    )  # unknown blocker holds it back


def test_checks_are_deterministic_and_do_not_mutate_the_snapshot() -> None:
    snap = good()
    before = copy.deepcopy(snap)
    first = [(r.key, r.result, r.evidence, r.recommendation) for r in run_checks(snap)[2]]
    second = [(r.key, r.result, r.evidence, r.recommendation) for r in run_checks(snap)[2]]
    assert first == second and snap == before


def test_evidence_never_carries_secret_references() -> None:
    text = str([r.evidence for r in run_checks(good())[2]])
    assert "ovlm-secret" not in text


# --- automation -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("sha", ["main", "v1.2", "a" * 7, "A" * 40, "a" * 39, ""])
def test_automation_must_be_a_full_lowercase_sha(sha: str) -> None:
    out = result_of(
        "automation.pinned_sha", edit(lambda s: s["profile"]["spec"]["automation"].update(sha=sha))
    )
    assert out.result is F and out.recommendation


def test_automation_pinned_passes_with_a_full_sha() -> None:
    out = result_of("automation.pinned_sha", good())
    assert out.result is P and out.evidence["sha"] == SHA


def test_drift_check_is_unknown_because_no_repo_code_runs_on_the_live_vm() -> None:
    out = result_of("automation.drift_unchecked", good())
    assert (
        out.result is U
        and out.evidence["live_code_run"] is False
        and "SEC-R-28" in out.evidence["reason"]
    )
    assert BY_KEY["automation.drift_unchecked"].severity is W


def test_no_profile_is_unknown_for_every_profile_dependent_check() -> None:
    snap = edit(lambda s: s.update(profile=None))
    needing = ["automation.pinned_sha", "data.separate_volume", "data.volume_type_explicit", "network.floating_ip",
               "platform.flavor_resolvable", "platform.image_resolvable", "validation.health_check_defined",
               "external.human_attestations"]  # fmt: skip
    for key in needing:
        assert result_of(key, snap).result is U, key
    assert derive_level(run_checks(snap)[2]) is Level.PARTIALLY_READY


# --- data separation ------------------------------------------------------------------------------------------------------

SEP = "data.separate_volume"


def test_data_volume_passes_when_exactly_one_matching_volume() -> None:
    out = result_of(SEP, good())
    assert out.result is P and out.evidence["attached_data_volumes"] == [VOL]


def test_stateless_service_has_no_data_volume_to_check() -> None:
    def stateless(s: dict[str, Any]) -> None:
        spec = s["profile"]["spec"]
        spec.pop("data_volume")
        spec["stateless_service"] = True
        s["attachments"] = []

    snap = edit(stateless)
    assert (
        result_of(SEP, snap).result is N
        and result_of("data.volume_type_explicit", snap).result is N
    )


def test_no_data_volume_attached_fails() -> None:
    out = result_of(SEP, edit(lambda s: s.update(attachments=[])))
    assert out.result is F and "no data volume" in out.evidence["problems"][0]


def test_two_data_volumes_fail() -> None:
    def two(s: dict[str, Any]) -> None:
        s["attachments"].append(
            {"volume_openstack_id": "vol-2", "device": "/dev/vdc", "delete_on_termination": False}
        )

    out = result_of(SEP, edit(two))
    assert out.result is F and "2 data volumes" in out.evidence["problems"][0]


def test_wrong_volume_fails() -> None:
    out = result_of(
        SEP, edit(lambda s: s["attachments"][0].update(volume_openstack_id="vol-other"))
    )
    assert out.result is F and any("profile names" in p for p in out.evidence["problems"])


def test_multiattach_volume_fails() -> None:
    out = result_of(SEP, edit(lambda s: s["volumes"][VOL].update(multiattach=True)))
    assert out.result is F and any("multiattach" in p for p in out.evidence["problems"])


def test_delete_on_termination_true_fails() -> None:
    out = result_of(SEP, edit(lambda s: s["attachments"][0].update(delete_on_termination=True)))
    assert out.result is F and any("deleted with the server" in p for p in out.evidence["problems"])


def test_unreported_delete_on_termination_is_unknown_not_pass() -> None:
    out = result_of(SEP, edit(lambda s: s["attachments"][0].update(delete_on_termination=None)))
    assert out.result is U and out.evidence["delete_on_termination"] is None


def test_unreported_multiattach_is_unknown() -> None:
    assert result_of(SEP, edit(lambda s: s["volumes"][VOL].update(multiattach=None))).result is U


def test_a_failure_outranks_an_unknown_in_the_same_check() -> None:
    def both(s: dict[str, Any]) -> None:
        s["attachments"][0].update(delete_on_termination=True)
        s["volumes"][VOL].update(multiattach=None)

    assert result_of(SEP, edit(both)).result is F


def test_volume_missing_from_the_inventory_is_unknown() -> None:
    assert result_of(SEP, edit(lambda s: s["volumes"].clear())).result is U


def test_boot_from_volume_root_is_not_counted_as_the_data_volume() -> None:
    def bfv(s: dict[str, Any]) -> None:
        s["server"]["data"]["image_id"] = None
        s["attachments"].insert(
            0,
            {
                "volume_openstack_id": "root-vol",
                "device": "/dev/vda",
                "delete_on_termination": True,
            },
        )
        s["volumes"]["root-vol"] = {
            "status": "in-use",
            "bootable": True,
            "multiattach": False,
            "volume_type": "ssd",
        }

    assert (
        result_of(SEP, edit(bfv)).result is P
    )  # the root volume's delete_on_termination does not matter here


def test_a_server_gone_from_the_inventory_is_unknown_not_pass() -> None:
    snap = edit(lambda s: s["server"].update(observation_status="gone"))
    for key in (SEP, "vm.state_supported", "vm.root_disk_image_booted", "network.floating_ip"):
        assert result_of(key, snap).result is U, key


@pytest.mark.parametrize(("vtype", "expected"), [("ssd", P), (None, F), ("", F)])
def test_volume_type_must_be_explicit(vtype: str | None, expected: Result) -> None:
    out = result_of(
        "data.volume_type_explicit", edit(lambda s: s["volumes"][VOL].update(volume_type=vtype))
    )
    assert out.result is expected


# --- dependencies ---------------------------------------------------------------------------------------------------------


def test_image_booted_root_passes_and_boot_from_volume_is_not_applicable() -> None:
    assert result_of("vm.root_disk_image_booted", good()).result is P
    out = result_of(
        "vm.root_disk_image_booted", edit(lambda s: s["server"]["data"].update(image_id=None))
    )
    assert out.result is N and out.evidence["boot_from_volume"] is True


@pytest.mark.parametrize(
    ("changes", "expected"),
    [({}, P), ({"status": "ERROR"}, F), ({"status": "SHELVED"}, F), ({"status": "SHUTOFF"}, F),
     ({"locked": True}, F), ({"status": "UNKNOWN"}, U), ({"is_minimal_construct": True}, U)],
)  # fmt: skip
def test_vm_state(changes: dict[str, Any], expected: Result) -> None:
    out = result_of("vm.state_supported", edit(lambda s: s["server"]["data"].update(changes)))
    assert out.result is expected


def test_floating_ip_passes_when_it_is_the_profiles_cutover_address() -> None:
    out = result_of("network.floating_ip", good())
    assert out.result is P and out.evidence["floating_ips"] == ["192.0.2.10"]


def test_floating_ip_missing_fails() -> None:
    assert result_of("network.floating_ip", edit(lambda s: s.update(floating_ips=[]))).result is F


def test_other_floating_ip_than_the_profiles_fails() -> None:
    out = result_of(
        "network.floating_ip", edit(lambda s: s["floating_ips"][0].update(openstack_id="fip-other"))
    )
    assert out.result is F and "profile" in (out.recommendation or "")


def test_floating_ip_of_another_server_does_not_count() -> None:
    assert (
        result_of(
            "network.floating_ip",
            edit(lambda s: s["floating_ips"][0].update(port_id="port-elsewhere")),
        ).result
        is F
    )


def test_provider_network_vm_is_not_applicable_and_says_renewal_must_refuse_it() -> None:
    def provider(s: dict[str, Any]) -> None:
        s["floating_ips"] = []
        s["networks"]["net-1"]["is_external"] = True

    out = result_of("network.floating_ip", edit(provider))
    assert (
        out.result is N
        and out.evidence["provider_network"] is True
        and "refuse" in (out.recommendation or "")
    )


@pytest.mark.parametrize(("candidates", "expected"), [(1, P), (0, F), (2, F)])
def test_flavor_must_resolve_to_exactly_one(candidates: int, expected: Result) -> None:
    out = result_of(
        "platform.flavor_resolvable",
        edit(
            lambda s: s.update(
                flavor_candidates=[
                    {"openstack_id": f"f{i}", "name": "m1.small"} for i in range(candidates)
                ]
            )
        ),
    )
    assert out.result is expected


@pytest.mark.parametrize(
    ("images", "expected"),
    [([("i1", "active")], P), ([], F), ([("i1", "active"), ("i2", "active")], F), ([("i1", "deactivated")], F),
     ([("i1", "active"), ("i2", "queued")], P)],
)  # fmt: skip
def test_image_must_resolve_to_one_active_image(
    images: list[tuple[str, str]], expected: Result
) -> None:
    out = result_of(
        "platform.image_resolvable",
        edit(
            lambda s: s.update(
                image_candidates=[
                    {"openstack_id": i, "name": "ubuntu-24.04", "status": st} for i, st in images
                ]
            )
        ),
    )
    assert out.result is expected


def test_image_by_properties_cannot_be_resolved_from_the_inventory() -> None:
    out = result_of(
        "platform.image_resolvable",
        edit(lambda s: s["profile"]["spec"].update(image={"properties": {"os_distro": "ubuntu"}})),
    )
    assert out.result is U and "properties" in out.evidence["reason"]


def test_quota_is_unknown_until_a_reading_exists_and_advisory_afterwards() -> None:
    assert result_of("platform.quota_headroom", good()).result is U
    assert BY_KEY["platform.quota_headroom"].severity is W

    def quota(
        instances: tuple[int, int],
        cores: tuple[int, int] = (20, 2),
        ram: tuple[int, int] = (50000, 1024),
    ) -> dict[str, Any]:
        return edit(lambda s: s.update(quota={
            "instances": {"limit": instances[0], "in_use": instances[1]},
            "cores": {"limit": cores[0], "in_use": cores[1]}, "ram": {"limit": ram[0], "in_use": ram[1]}}))  # fmt: skip

    assert result_of("platform.quota_headroom", quota((10, 3))).result is P
    short = result_of("platform.quota_headroom", quota((3, 3)))
    assert short.result is F and short.evidence["short"]["instances"] == {
        "limit": 3,
        "in_use": 3,
        "needed": 1,
    }
    assert result_of("platform.quota_headroom", quota((-1, 99))).result is P  # -1: unlimited
    assert (
        result_of("platform.quota_headroom", quota((10, 3), cores=(2, 2))).result is F
    )  # flavor needs 1 vCPU
    # an advisory failure never changes the level
    snap = quota((3, 3))
    attested(snap)
    assert derive_level(run_checks(snap)[2]) is Level.READY


# --- validation, attestations ---------------------------------------------------------------------------------------------


def test_health_check_defined() -> None:
    out = result_of("validation.health_check_defined", good())
    assert out.result is P and out.evidence["port"] == 443 and out.evidence["scheme"] == "https"
    bad = edit(lambda s: s["profile"]["spec"].update(health_check={}))
    assert result_of("validation.health_check_defined", bad).result is F
    assert BY_KEY["validation.health_check_defined"].severity is B


def test_attestations_are_unknown_until_every_statement_is_attested() -> None:
    out = result_of("external.human_attestations", good())
    assert out.result is U and set(out.evidence["statements"]) == set(ATTESTATIONS)
    assert all(v["state"] == "missing" for v in out.evidence["statements"].values())
    snap = good()
    attested(snap)
    ok = result_of("external.human_attestations", snap)
    assert (
        ok.result is P and ok.evidence["statements"]["state_outside_volume"]["attested_by"] == "u-1"
    )
    partial = good()
    attested(partial)
    partial["attestations"].pop()
    assert result_of("external.human_attestations", partial).result is U


def test_attestations_expire_and_end_with_a_profile_change() -> None:
    expired = good()
    attested(expired, expires="2026-01-01T00:00:00+00:00")
    assert result_of("external.human_attestations", expired).result is U
    other_version = good()
    attested(other_version, version="pv-0")
    assert result_of("external.human_attestations", other_version).result is U
    no_expiry = good()
    attested(no_expiry, expires=None)
    assert result_of("external.human_attestations", no_expiry).result is P


def test_attestation_check_is_a_warning_so_it_never_blocks_the_level() -> None:
    assert BY_KEY["external.human_attestations"].severity is W
    assert derive_level(run_checks(good())[2]) is Level.READY
