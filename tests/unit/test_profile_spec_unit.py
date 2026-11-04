"""Profile spec validation and hashing (data-model.md section 5)."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from ovlm.profiles.errors import ProfileError
from ovlm.profiles.spec import spec_hash, validate_spec

NET, SUBNET, VOL, FIP = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
)
SHA = "a" * 40

SPEC: dict[str, Any] = {
    "flavor": "m1.small",
    "image": {"name": "ubuntu-24.04"},
    "network": {"network_id": NET, "subnet_id": SUBNET},
    "security_groups": ["web"],
    "data_volume": {"volume_id": VOL, "fs_type": "ext4", "label": "data", "mount_point": "/srv/data"},
    "automation": {"repo": "https://git.example.invalid/team/app.git", "sha": SHA,
                   "secret_refs": {"vault": "ovlm-secret://app/vault"}},
    "guest_access": {"ssh_user": "ovlm"},
    "health_check": {"external": {"scheme": "https", "port": 443, "path": "/health", "expected_status": 200}},
    "cutover": {"floating_ip_id": FIP},
}  # fmt: skip


def spec_with(**changes: Any) -> dict[str, Any]:
    out = copy.deepcopy(SPEC)
    for key, value in changes.items():
        if value is None:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def fields(raw: Any) -> list[str]:
    with pytest.raises(ProfileError) as exc:
        validate_spec(raw)
    assert exc.value.status == 422 and exc.value.errors
    return [e["field"] for e in exc.value.errors]


def test_a_good_spec_validates_with_defaults_filled() -> None:
    s = validate_spec(SPEC)
    assert s.strategy == "bluegreen_fip_v1" and s.guest_access.host_key_policy == "injected"
    assert (
        s.automation.store_diffs is False
        and s.availability_zone == "from_volume"
        and s.cutover.method == "floating_ip"
    )


def test_hash_is_stable_and_changes_with_content() -> None:
    a, b = validate_spec(SPEC), validate_spec(dict(reversed(list(SPEC.items()))))
    assert spec_hash(a) == spec_hash(b) and len(spec_hash(a)) == 64
    assert spec_hash(validate_spec(spec_with(flavor="m1.large"))) != spec_hash(a)


def test_the_image_is_a_rule_never_an_id_or_latest() -> None:
    assert "image.id" in fields(spec_with(image={"id": "55555555-5555-4555-8555-555555555555"}))
    assert any(f.startswith("image") for f in fields(spec_with(image={"id": "x"})))
    assert any(f.startswith("image") for f in fields(spec_with(image={"name": "latest"})))
    assert any(f.startswith("image") for f in fields(spec_with(image={})))
    assert any(
        f.startswith("image")
        for f in fields(spec_with(image={"name": "a", "properties": {"k": "v"}}))
    )
    assert validate_spec(
        spec_with(image={"properties": {"os_distro": "ubuntu", "os_version": "24.04"}})
    ).image.properties


@pytest.mark.parametrize("sha", ["main", "v1.2.3", "abc1234", "A" * 40, "a" * 39, "g" * 40, ""])
def test_the_automation_must_be_pinned_to_a_full_sha(sha: str) -> None:
    raw = spec_with()
    raw["automation"]["sha"] = sha
    assert "automation.sha" in fields(raw)


def test_secret_refs_are_references_and_values_are_never_echoed() -> None:
    raw = spec_with()
    raw["automation"]["secret_refs"] = {"vault": "hunter2-the-actual-password"}
    with pytest.raises(ProfileError) as exc:
        validate_spec(raw)
    assert "hunter2" not in str(exc.value.errors) and "hunter2" not in exc.value.detail
    assert exc.value.errors and exc.value.errors[0]["field"] == "automation.secret_refs"


def test_exactly_one_of_data_volume_or_stateless() -> None:
    assert fields(spec_with(data_volume=None))  # neither
    assert fields(spec_with(stateless_service=True))  # both
    assert validate_spec(spec_with(data_volume=None, stateless_service=True)).stateless_service
    assert fields(
        spec_with(data_volume=[SPEC["data_volume"], SPEC["data_volume"]])
    )  # more than one volume


@pytest.mark.parametrize("mount", ["srv/data", "/srv/../etc", "/srv/da ta", "/srv/$HOME"])
def test_mount_point_is_a_clean_absolute_path(mount: str) -> None:
    raw = spec_with()
    raw["data_volume"]["mount_point"] = mount
    assert any(f.startswith("data_volume") for f in fields(raw))


def test_unknown_keys_and_other_strategies_are_errors() -> None:
    assert "surprise" in fields(spec_with(surprise=1))
    assert "strategy" in fields(spec_with(strategy="inplace"))
    assert "cutover.method" in fields(spec_with(cutover={"floating_ip_id": FIP, "method": "dns"}))
    assert "guest_access.host_key_policy" in fields(
        spec_with(guest_access={"ssh_user": "ovlm", "host_key_policy": "ignore"})
    )


def test_repo_and_paths() -> None:
    for repo in ("file:///etc", "ftp://x/y", "git.example.invalid/x", "https://user:pw@h/x.git"):
        raw = spec_with()
        raw["automation"]["repo"] = repo
        assert "automation.repo" in fields(raw)
    raw = spec_with()
    raw["automation"]["playbook_dir"] = "../../etc"
    assert "automation.playbook_dir" in fields(raw)


def test_not_an_object_is_a_clean_422() -> None:
    assert fields("nope") == [""]
