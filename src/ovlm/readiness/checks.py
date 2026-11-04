"""The MVP checks (backlog E4-2). Each check is a pure function of the input snapshot (``snapshot.py`` documents its
shape): read-only, from the DB inventory and the profile, **no repository code and no OpenStack call**.

Rules of thumb used throughout:

* ``pass`` only when the snapshot proves it; a missing observation is ``unknown``, never a pass.
* ``fail`` says what is wrong in ``evidence`` and what to do in ``recommendation``.
* ``not-applicable`` is for the cases the strategy does not depend on (a stateless service has no data volume; a
  boot-from-volume VM has no image to rebuild from). Its evidence says why, so the reader can disagree.
* Severity is fixed per check. ``blocker`` checks decide the level (levels.py); ``warning`` and ``info`` do not.

Bump a check's ``version`` when its rule changes. Evidence holds identifiers and facts, never secret values: the
profile's ``secret_refs`` are never copied (only the automation repository URL and SHA are).
"""

from __future__ import annotations

from typing import Any

from ovlm.readiness.model import Category, Check, Outcome, Result, Severity

SHA_LEN = 40

#: Human statements OVLM cannot verify (automation-contract.md section 9, FR-RDY-5). A valid attestation names the
#: current profile version and has not expired. Keys are what ``attestation.check_key`` holds.
ATTESTATIONS: dict[str, str] = {
    "state_outside_volume": "No data is written outside the data volume; the rest of the VM is reproducible.",
    "healthcheck_representative": "The health check represents real, user-facing function of the service.",
    "external_dependencies": "External dependencies (DNS, other hosts' cron jobs, secret stores) are documented and unaffected by a replacement VM.",
}


def _spec(snap: dict[str, Any]) -> dict[str, Any] | None:
    profile = snap.get("profile")
    return profile.get("spec") if profile else None


def _no_profile() -> Outcome:
    return Outcome(
        Result.UNKNOWN,
        {"profile": "none"},
        "Assign a profile to the service: readiness is assessed against the desired state.",
    )


def _server(snap: dict[str, Any]) -> dict[str, Any] | None:
    server = snap.get("server")
    return server if server and server.get("observation_status") == "present" else None


def _stale() -> Outcome:
    return Outcome(
        Result.UNKNOWN,
        {"observation": "the server is not present in the last inventory sync"},
        "Run an inventory sync and assess again.",
    )


def _data_attachments(snap: dict[str, Any]) -> list[dict[str, Any]]:
    """Attached volumes that are not the root disk. A boot-from-volume VM's root volume is a bootable volume."""
    boot_from_volume = not snap["server"]["data"].get("image_id")
    out = []
    for att in snap.get("attachments", []):
        vol = snap.get("volumes", {}).get(att["volume_openstack_id"], {})
        if boot_from_volume and vol.get("bootable"):
            continue
        out.append(att)
    return out


# --- configuration reproducibility ---------------------------------------------------------------------------------


def automation_pinned(snap: dict[str, Any]) -> Outcome:
    spec = _spec(snap)
    if spec is None:
        return _no_profile()
    auto = spec.get("automation") or {}
    sha = auto.get("sha") or ""
    evidence = {"repo": auto.get("repo"), "sha": sha or None}
    if len(sha) == SHA_LEN and all(c in "0123456789abcdef" for c in sha):
        return Outcome(Result.PASS, evidence)
    return Outcome(
        Result.FAIL, evidence,
        "Pin the automation to a full 40-character commit SHA (not a branch, tag or short SHA), so a rebuild runs "
        "exactly the reviewed code.",
    )  # fmt: skip


def automation_drift_unchecked(snap: dict[str, Any]) -> Outcome:
    """``configure --check --diff`` on the live VM needs repository code on it. An assessment runs none by default
    (SEC-R-28), so this stays ``unknown`` (warning) until a human-confirmed live run exists (not in this release)."""
    if snap.get("live_code_run"):
        return Outcome(
            Result.UNKNOWN, {"live_code_run": True, "note": "live code execution is not available in this release"},
            "Not available yet.",
        )  # fmt: skip
    return Outcome(
        Result.UNKNOWN,
        {"live_code_run": False, "reason": "no repository code runs on the live VM during an assessment (SEC-R-28)"},
        "To learn whether the running VM matches its automation, run the playbook in check mode yourself, or accept "
        "that drift is only discovered when the replacement VM is built.",
    )  # fmt: skip


# --- persistent data separation ------------------------------------------------------------------------------------


def data_separate_volume(snap: dict[str, Any]) -> Outcome:
    spec = _spec(snap)
    if spec is None:
        return _no_profile()
    if spec.get("stateless_service"):
        return Outcome(Result.NOT_APPLICABLE, {"stateless_service": True})
    if _server(snap) is None:
        return _stale()
    atts = _data_attachments(snap)
    ids = [a["volume_openstack_id"] for a in atts]
    declared = (spec.get("data_volume") or {}).get("volume_id")
    evidence: dict[str, Any] = {"attached_data_volumes": ids, "profile_volume_id": declared}
    problems: list[str] = []
    advice: list[str] = []
    unknown: list[str] = []
    if len(atts) == 0:
        problems.append("no data volume is attached")
        advice.append(
            "Attach the data volume, or declare the service stateless in the profile if it keeps no data."
        )
    elif len(atts) > 1:
        problems.append(
            f"{len(atts)} data volumes are attached; the MVP strategy hands over exactly one"
        )
        advice.append("Keep exactly one data volume (several volumes are a later strategy).")
    else:
        att = atts[0]
        vol_id = att["volume_openstack_id"]
        vol = snap.get("volumes", {}).get(vol_id)
        if declared and declared != vol_id:
            problems.append("the attached volume is not the volume the profile names")
            advice.append("Correct the profile's data volume, or attach the declared volume.")
        if vol is None:
            unknown.append("the volume is not in the inventory")
        else:
            evidence["volume"] = {
                k: vol.get(k) for k in ("status", "size", "bootable", "multiattach", "volume_type")
            }
            if vol.get("multiattach") is True:
                problems.append("the data volume is multiattach")
                advice.append(
                    "Use a normal (single-attach) volume: a multiattach handoff can corrupt a single-writer filesystem."
                )
            elif vol.get("multiattach") is None:
                unknown.append("the inventory does not say whether the volume is multiattach")
        dot = att.get("delete_on_termination")
        evidence["delete_on_termination"] = dot
        if dot is True:
            problems.append(
                "the data volume would be deleted with the server (delete_on_termination)"
            )
            advice.append(
                "Detach it from deletion: set delete_on_termination to false for this attachment."
            )
        elif dot is None:
            unknown.append("the cloud does not report delete_on_termination for this attachment")
    if problems:
        evidence["problems"] = problems
        return Outcome(Result.FAIL, evidence, " ".join(advice))
    if unknown:
        evidence["unknown"] = unknown
        return Outcome(
            Result.UNKNOWN, evidence, "Check these facts in the cloud, then assess again."
        )
    return Outcome(Result.PASS, evidence)


def data_volume_type_explicit(snap: dict[str, Any]) -> Outcome:
    spec = _spec(snap)
    if spec is None:
        return _no_profile()
    if spec.get("stateless_service"):
        return Outcome(Result.NOT_APPLICABLE, {"stateless_service": True})
    declared = (spec.get("data_volume") or {}).get("volume_id")
    vol = snap.get("volumes", {}).get(declared) if declared else None
    if vol is None:
        return Outcome(
            Result.UNKNOWN,
            {"profile_volume_id": declared, "volume": "not in the inventory"},
            "Run an inventory sync and assess again.",
        )
    vtype = vol.get("volume_type")
    if vtype:
        return Outcome(Result.PASS, {"volume_type": vtype})
    return Outcome(
        Result.FAIL, {"volume_type": None},
        "Give the volume an explicit volume type: a cloud may have no working default type, so a later volume "
        "(for example a snapshot restore) could fail.",
    )  # fmt: skip


# --- dependencies (what the strategy needs from the platform) ------------------------------------------------------


def vm_state_supported(snap: dict[str, Any]) -> Outcome:
    server = snap.get("server")
    if server is None or server.get("observation_status") != "present":
        return _stale()
    data = server["data"]
    status = data.get("status")
    evidence = {
        "status": status,
        "locked": data.get("locked"),
        "locked_reason": data.get("locked_reason"),
    }
    if data.get("is_minimal_construct") or status == "UNKNOWN":
        return Outcome(
            Result.UNKNOWN,
            evidence,
            "The compute cell is unreachable; assess again when it is back.",
        )
    if status != "ACTIVE":
        return Outcome(
            Result.FAIL,
            evidence,
            f"The VM is {status}; the MVP strategy renews VMs that are ACTIVE. Bring it to ACTIVE first.",
        )
    if data.get("locked"):
        return Outcome(
            Result.FAIL, evidence,
            "The VM is locked. A lock set by an administrator cannot be removed by OVLM and blocks stop, detach "
            "and delete: ask the lock's owner to remove it.",
        )  # fmt: skip
    return Outcome(Result.PASS, evidence)


def root_disk_image_booted(snap: dict[str, Any]) -> Outcome:
    server = _server(snap)
    if server is None:
        return _stale()
    image_id = server["data"].get("image_id")
    if image_id:
        return Outcome(Result.PASS, {"image_id": image_id})
    return Outcome(
        Result.NOT_APPLICABLE,
        {"boot_from_volume": True, "reason": "the VM boots from a volume: its root volume is never touched by a renewal"},
    )  # fmt: skip


def floating_ip_served(snap: dict[str, Any]) -> Outcome:
    spec = _spec(snap)
    if spec is None:
        return _no_profile()
    server = _server(snap)
    if server is None:
        return _stale()
    fips = snap.get("floating_ips", [])
    port_ids = {p["openstack_id"] for p in snap.get("ports", [])}
    networks = snap.get("networks", {})
    external = [
        p for p in snap.get("ports", []) if networks.get(p.get("network_id"), {}).get("is_external")
    ]
    declared = (spec.get("cutover") or {}).get("floating_ip_id")
    mine = [f for f in fips if f.get("port_id") in port_ids]
    evidence = {
        "floating_ips": [f["floating_ip_address"] for f in mine],
        "profile_floating_ip_id": declared,
    }
    if not mine and external:
        return Outcome(
            Result.NOT_APPLICABLE,
            {**evidence, "provider_network": True,
             "reason": "the VM is attached to an external (provider) network and has no floating IP"},
            "The floating-IP strategy bluegreen_fip_v1 cannot cut over this VM: renewal planning must refuse it.",
        )  # fmt: skip
    if not mine:
        return Outcome(
            Result.FAIL, evidence,
            "Associate a floating IP with the VM: the service must be reached through one so a replacement can take it over.",
        )  # fmt: skip
    if declared and declared not in {f["openstack_id"] for f in mine}:
        return Outcome(
            Result.FAIL, evidence,
            "The profile's cutover floating IP is not the one associated with this VM; correct the profile.",
        )  # fmt: skip
    return Outcome(Result.PASS, evidence)


def flavor_resolvable(snap: dict[str, Any]) -> Outcome:
    spec = _spec(snap)
    if spec is None:
        return _no_profile()
    name = spec.get("flavor")
    found = snap.get("flavor_candidates", [])
    evidence = {"flavor": name, "matches": [f["openstack_id"] for f in found]}
    if len(found) == 1:
        return Outcome(Result.PASS, evidence)
    if not found:
        return Outcome(
            Result.FAIL,
            evidence,
            "No flavor with that name is visible to the project; correct the profile or ask for the flavor.",
        )
    return Outcome(
        Result.FAIL,
        evidence,
        "More than one flavor has that name; the replacement VM cannot be built from an ambiguous name.",
    )


def image_resolvable(snap: dict[str, Any]) -> Outcome:
    spec = _spec(snap)
    if spec is None:
        return _no_profile()
    match = spec.get("image") or {}
    if not match.get("name"):
        return Outcome(
            Result.UNKNOWN,
            {"image_match": "properties", "reason": "the inventory does not hold image properties"},
            "Resolve the image by name, or confirm at plan time that the properties match exactly one image.",
        )  # fmt: skip
    found = [i for i in snap.get("image_candidates", []) if i.get("status") == "active"]
    evidence = {"image_name": match["name"], "matches": [i["openstack_id"] for i in found]}
    if len(found) == 1:
        return Outcome(Result.PASS, evidence)
    if not found:
        return Outcome(
            Result.FAIL,
            evidence,
            "No active image has that name in the project's view; correct the profile.",
        )
    return Outcome(
        Result.FAIL,
        evidence,
        "More than one active image has that name: the image must resolve to a unique match.",
    )


def quota_headroom(snap: dict[str, Any]) -> Outcome:
    """Advisory (members cannot see host capacity: quota is not schedulable capacity). Needs a quota reading the
    inventory does not collect yet; until then ``unknown``."""
    quota = snap.get("quota")
    if not quota:
        return Outcome(
            Result.UNKNOWN, {"quota": "not collected"},
            "OVLM does not read project quotas yet. Make sure the project can hold one more server of this "
            "flavor (instances, cores, RAM) while the old and the new VM coexist.",
        )  # fmt: skip
    flavor = (snap.get("flavor_candidates") or [{}])[0]
    need = {"instances": 1, "cores": flavor.get("vcpus") or 0, "ram": flavor.get("ram") or 0}
    short = {}
    for key, wanted in need.items():
        q = quota.get(key) or {}
        limit, used = q.get("limit"), q.get("in_use")
        if limit is None or limit < 0 or used is None:  # -1 = unlimited in Nova
            continue
        if limit - used < wanted:
            short[key] = {"limit": limit, "in_use": used, "needed": wanted}
    if short:
        return Outcome(
            Result.FAIL,
            {"short": short},
            "Raise the quota, or free capacity, before renewing: the new VM must exist next to the old one.",
        )
    return Outcome(Result.PASS, {"checked": sorted(need)})


# --- validation capability -------------------------------------------------------------------------------------------


def health_check_defined(snap: dict[str, Any]) -> Outcome:
    spec = _spec(snap)
    if spec is None:
        return _no_profile()
    ext = (spec.get("health_check") or {}).get("external")
    if ext and ext.get("scheme") and ext.get("port"):
        return Outcome(
            Result.PASS,
            {k: ext.get(k) for k in ("scheme", "port", "path", "expected_status")}
            | {"accept_degraded": (spec["health_check"]).get("accept_degraded", False)},
        )  # fmt: skip
    return Outcome(
        Result.FAIL, {"health_check": None},
        "Define an external health check (scheme, port, path, expected status): without it OVLM cannot tell that "
        "the replacement serves the service before moving the floating IP.",
    )  # fmt: skip


# --- external services / human attestations --------------------------------------------------------------------------


def human_attestations(snap: dict[str, Any]) -> Outcome:
    """The hook for FR-RDY-5: ``unknown`` until every statement is attested for the current profile version and
    has not expired. Recording an attestation is V1; until then this check always reports what is missing."""
    profile = snap.get("profile")
    if profile is None:
        return _no_profile()
    now = snap.get("now") or ""
    by_key: dict[str, dict[str, Any]] = {}
    for a in snap.get("attestations", []):
        if a.get("profile_version_id") != profile.get("version_id"):
            continue
        if a.get("expires_at") and a["expires_at"] <= now:
            continue
        by_key[a["check_key"]] = a
    states = {
        key: ({"state": "attested", "attested_by": by_key[key].get("attested_by"), "attested_at": by_key[key].get("attested_at"),
               "expires_at": by_key[key].get("expires_at")} if key in by_key else {"state": "missing"})
        for key in ATTESTATIONS
    }  # fmt: skip
    missing = [k for k, v in states.items() if v["state"] == "missing"]
    evidence = {"statements": {k: {"text": ATTESTATIONS[k], **v} for k, v in states.items()}}
    if missing:
        return Outcome(
            Result.UNKNOWN, evidence,
            "A person who knows the service must attest these statements (who and when are recorded, and they "
            "expire when the profile changes): " + ", ".join(missing) + ".",
        )  # fmt: skip
    return Outcome(Result.PASS, evidence)


C, S = Category, Severity

#: Order is the order shown to people: by category, blockers first within the list as written.
CHECKS: tuple[Check, ...] = (
    Check("automation.pinned_sha", 1, C.CONFIGURATION, S.BLOCKER, "Automation pinned to a commit",
          "The profile's automation points at a full 40-character commit SHA.", automation_pinned),
    Check("automation.drift_unchecked", 1, C.CONFIGURATION, S.WARNING, "Running VM compared with its automation",
          "Whether the running VM matches its automation needs repository code on the live VM, which an assessment "
          "does not run by default (SEC-R-28).", automation_drift_unchecked),
    Check("data.separate_volume", 1, C.DATA, S.BLOCKER, "Data on one separate volume",
          "Exactly one attached data volume, the one the profile names, not multiattach, not deleted with the server; "
          "not applicable to a stateless service.", data_separate_volume),
    Check("data.volume_type_explicit", 1, C.DATA, S.WARNING, "Data volume type is explicit",
          "The data volume has an explicit volume type (a cloud may have no working default).", data_volume_type_explicit),
    Check("vm.state_supported", 1, C.DEPENDENCIES, S.BLOCKER, "VM is ACTIVE and not locked",
          "The VM is ACTIVE and not locked; an administrator's lock cannot be removed by OVLM.", vm_state_supported),
    Check("vm.root_disk_image_booted", 1, C.DEPENDENCIES, S.INFO, "Root disk booted from an image",
          "The VM boots from an image; boot-from-volume VMs are not applicable to this check.", root_disk_image_booted),
    Check("network.floating_ip", 1, C.DEPENDENCIES, S.BLOCKER, "Service reached through a floating IP",
          "A floating IP is associated with the VM, and it is the profile's cutover address; a VM on a provider "
          "network is not applicable.", floating_ip_served),
    Check("platform.flavor_resolvable", 1, C.DEPENDENCIES, S.BLOCKER, "Flavor resolves to one flavor",
          "The profile's flavor name matches exactly one flavor in the inventory.", flavor_resolvable),
    Check("platform.image_resolvable", 1, C.DEPENDENCIES, S.BLOCKER, "Image resolves to one image",
          "The profile's image rule matches exactly one active image in the inventory.", image_resolvable),
    Check("platform.quota_headroom", 1, C.DEPENDENCIES, S.WARNING, "Quota headroom for one more VM",
          "Advisory: the project's quota leaves room for one extra server while old and new coexist.", quota_headroom),
    Check("validation.health_check_defined", 1, C.VALIDATION, S.BLOCKER, "Health check defined",
          "The profile defines an external health check.", health_check_defined),
    Check("external.human_attestations", 1, C.EXTERNAL, S.WARNING, "Human attestations",
          "People attest what OVLM cannot verify; unknown until attested for the current profile version.", human_attestations),
)  # fmt: skip

BY_KEY: dict[str, Check] = {c.key: c for c in CHECKS}
if len(BY_KEY) != len(CHECKS):
    raise RuntimeError("duplicate check key")


def catalogue() -> list[dict[str, Any]]:
    return [c.catalogue_entry() for c in CHECKS]
