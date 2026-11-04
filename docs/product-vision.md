# Product vision

| Field | Value |
|---|---|
| Owner | Agent 1 — Product Manager / Engineering Manager |
| Status | **Designed** (Phase 1 proposal, awaiting maintainer approval) |
| Last updated | 2026-11-04 |

## The problem

Organizations that move from VMware to OpenStack usually move their habits too. Virtual machines stay in production
for years, are configured by hand and are rarely documented. Nobody has ever rebuilt them. The OpenStack platform then
has to protect each instance like a pet: live migrations before every host patch, evacuations after every host failure,
and long maintenance campaigns spent preserving instances instead of improving the platform.

OpenStack was designed for a different model, where an instance can be replaced. Most organizations cannot use that
model because they lack three things for each VM:

1. A **reproducible configuration**: the VM can be rebuilt from code, not from memory.
2. **Persistent data that lives outside the VM**: the data is on a volume or an external service, not on the root disk.
3. A **tested and controlled way to replace it**: someone has actually done it, with health checks, approval and a way
   back.

## The principle

> **A virtual machine should be replaceable. The service and its persistent data should outlive the virtual machine.**

## What OVLM is

OVLM (OpenStack VM Lifecycle Manager) is an OpenStack-native tool that helps operators move workloads from "preserved
forever" to "renewed on a plan". It does four things:

| | Capability | Question it answers |
|---|---|---|
| 🔍 | **Inventory** (read-only) | What VMs do we have, how old are they, what volumes, ports and IPs do they use? |
| 🧭 | **Readiness assessment** | Could this VM be rebuilt safely today? If not, what exactly is missing? |
| 📅 | **Lifecycle policies and planning** | When should each VM be renewed, under which rules, and who must approve? |
| 🔁 | **Controlled renewal** | Replace the VM step by step, observably, with health checks, approval, cutover and a way back. |

## What OVLM is not

- Not another OpenStack dashboard. Horizon and Skyline already show resources.
- Not a VMware migration tool. VMware is the business context, not a V1 integration.
- Not a configuration management system. OVLM calls the operator's Ansible content. It does not replace it.
- Not a patch or vulnerability manager. Renewal can carry a newer image, but OVLM does not decide what to patch.
- Not a promise that every application can be rebuilt. OVLM **assesses** and **explains** readiness. It refuses to
  renew what is not ready.

## Who it is for

| Persona | Context | What they need from OVLM |
|---|---|---|
| **Platform operator** (primary) | Runs the OpenStack cloud. Spends maintenance windows live-migrating long-lived VMs. | Know which VMs are replaceable, and replace them instead of preserving them. |
| **Workload owner / application team** | Owns the service on the VMs. Usually wrote (or inherited) the configuration. | A clear list of what blocks rebuildability, and a renewal they approve and can trust. |
| **Change approver / team lead** | Accepts operational risk. | Who approved what, when, what happened, and evidence the service came back. |
| **Security / audit** | Reviews credentials and destructive actions. | Least privilege, no secrets in logs, a complete audit trail. |

## The two scenarios

- **Scenario A — existing VMs (brownfield).** Discover existing instances, register the ones worth managing, describe
  their desired state in a profile, assess readiness, fix the blockers, then renew them on a plan.
- **Scenario B — new managed VMs (greenfield).** The first VM of a service is created from a profile that already has
  its automation, data volume and renewal policy. In V1, this is the same renewal engine with no previous VM: the
  workflow "provision → configure → attach data → health check". It is planned after the brownfield MVP.

## Success measures (to be measured, not assumed)

| Measure | Why it matters |
|---|---|
| Share of registered VMs with a readiness level of "rebuildable" | Shows progress from pets to replaceable workloads |
| Renewals completed / attempted / rolled back | Shows whether renewal works and is trusted |
| Median age of managed VMs compared with their policy maximum | Shows that renewal actually happens |
| Service interruption per renewal (measured by the health check) | Shows the real cost of renewing |
| Renewals that needed human recovery | Shows how reliable the engine is |

## Guiding principles for the team

1. **Read-only first.** Inventory and assessment work without any destructive OpenStack permission.
2. **Explain, do not score blindly.** Every readiness result names its evidence, blockers and recommendations.
3. **Refuse unsafe work.** A renewal that cannot prove its prerequisites does not start. A step that cannot prove its
   result stops and asks a human.
4. **Every step is observable, auditable and recoverable.** A worker or database restart resumes the workflow; it
   never repeats a destructive step blindly.
5. **Simple before clever.** One process type, one database, one renewal strategy in the MVP.
6. **Honest status.** Designed, implemented, unit tested, integration tested, lab validated and production validated
   are different states. They are never mixed up.
