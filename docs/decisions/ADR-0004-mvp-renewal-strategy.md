# ADR-0004 — MVP renewal strategy: blue/green with data-volume handoff and floating-IP cutover

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 2 (Chief Architect); maintainer approval required |

## Context

FR-REN-2 fixes one MVP strategy. Tags below are Agent 3's (openstack-integration.md). Hard facts that shape it:

| Fact | Section | Tag |
|---|---|---|
| A non-multiattach volume can be attached to one server only; a second attach is rejected (400) | §4 | SOURCE-VERIFIED |
| Hot-detach of a mounted volume can be refused by the guest; volume rolls back to `in-use` after ~`device_detach_timeout × attempts` | §4 | SOURCE-VERIFIED |
| A locked server rejects attach, detach, stop, start, delete for a non-admin (409) | §4, §7 | SOURCE-VERIFIED |
| A lock set by an admin cannot be removed by the project member | §7 | SOURCE-VERIFIED |
| Attach/detach allowed in `ACTIVE` and `STOPPED` (no task in progress) | §4 | SOURCE-VERIFIED |
| Detach needs the server's compute host up; force-detach / reset-state are admin only | §4, §9 | SOURCE-VERIFIED |
| FIP re-association is one PUT, atomic in the DB, applied asynchronously by the L3 agent | §6.1 | SOURCE-VERIFIED (API) / DOCUMENTED-UNVERIFIED (data plane) |
| Missing router path gives a misleading 404 `ExternalGatewayForFloatingIPNotFound` | §6.1 | SOURCE-VERIFIED |
| `delete_on_termination` default false for attach-after-create; true for Nova-created boot volumes | §4 | SOURCE-VERIFIED |
| Blue and green cannot hold the same fixed IP at once | §9 | SOURCE-VERIFIED |
| Members cannot see host capacity; quota ≠ schedulable | §7 | SOURCE-VERIFIED |

## Options

| Option | Verdict |
|---|---|
| A. Blue/green, exclusive volume handoff, FIP cutover | **Chosen.** Works with `member` role, keeps the old VM as the way back. |
| B. Stop-and-rebuild in place (Nova rebuild) | Rejected: destroys the way back; rebuild semantics vary. Later strategy. |
| C. Multiattach handoff | Rejected: needs admin volume type, corrupts single-writer filesystems (§5). Opt-in later for cluster-aware data. |
| D. Octavia member swap / Designate | Rejected for MVP: services may not exist; later cutover methods (§6.2). |
| E. Fixed-IP preservation via pre-created port | Rejected for MVP: needs net-owner role and a port move inside the downtime window (§9). |

## Decision

### Shape: two phases separated by a gate

1. **Build phase (no service impact, old VM serves):** preflight → claim resources (ownership markers, ADR-0005) → create green (image boot, no data) → wait ACTIVE →
   SSH ready (pinned host key, ADR-0006) → Ansible `preflight` + `configure` on green → verify cutover preconditions
   (router path for green's port, FIP still on blue, volume attached only to blue).
2. **Gate G2 — downtime/cutover approval** (when the policy requires it) **plus policy window check.**
3. **Downtime window:** quiesce blue (Ansible) → **stop blue** → detach → (optional snapshot) → attach to green →
   `data_attach` → `start_service` → `healthcheck` (internal, with marker checksum) → **move FIP** → external verify.
4. **Retention:** lock blue (stopped) → wait retention period (revert available) → gate G3 → unlock → delete blue.

### Decisions on the open points

| Point | Decision | Reason |
|---|---|---|
| Where is the "before cutover" approval | **G2 sits before `quiesce_old`**, not before the FIP move. One approval covers the whole downtime window. No human gate inside the window. | Downtime starts at quiesce. A gate before the FIP move would approve after the damage (service already down) and extend downtime while waiting for a human. |
| G1 (plan) and G3 (retirement) | G1 before run start; G3 before deleting blue. G1/G2 required or not per policy (FR-POL-1); G3 always needs a distinct human approver (security-model.md §3.2). G2 also re-checks the policy window when the window opens. Approvals are bound to the plan hash (security-model.md §7.1). | FR-REN-4 |
| Stop blue before detach | **Always** in MVP. No hot-detach option. | Removes the guest-refusal failure mode; the guest is already quiesced. |
| Attach to green | Hot attach to running green (needed for `data_attach` playbook). | Attach is the less risky direction. |
| Lock blue | **Only after** external verify succeeded (`retain_old`). OVLM's project credential sets the lock (`locked_by=owner`). Unlock is the first step of revert and of retirement. A blue VM locked by an admin is a readiness **blocker**. | Locked servers reject attach/stop/start/delete for non-admin; an admin lock cannot be undone by OVLM. |
| Blue's fstab | Quiesce stops units and unmounts but **does not remove** the fstab entry (must be by UUID/LABEL with `nofail`). | Revert = attach to stopped blue, start blue; boot remounts and restarts enabled units. |
| Rollback / revert | One **convergent restore sequence** (renewal-workflow.md §4): each step probes and skips if already satisfied, target = "volume on blue, blue ACTIVE and healthy, FIP on blue's port, green stopped". Used for in-window rollback and post-cutover revert until retirement. | One code path, testable from every intermediate state. |
| Automatic vs human rollback | Build-phase failure: run stops `failed` with green kept for diagnosis; operator rollback (typed confirmation) deletes green (security-model.md §7.1). In-window failure with unambiguous state: automatic restore (`renewal.auto_rollback_in_window`, default true). Ambiguous state (quiesce failure, `data_attach` needs_human, stuck volume, unknown FIP state): stop, `needs_human`. After cutover: revert only on operator request. | Contract §6 classes; data safety beats speed. |
| Number of data volumes | **Exactly one** data volume, or **zero** for profiles declaring `stateless_service: true` (handoff steps skipped). N volumes = V1. | Sequential multi-volume handoff multiplies partial states (2 of 3 moved) for no MVP value. |
| Root disk | Green boots **from image** (local root disk). Blue may be boot-from-volume: its root volume is never touched by handoff; at retirement OVLM reports a leftover root volume (`delete_on_termination=false`) and does not delete it. Boot-from-volume **green** = V1. | Simplest; but see risk below (clouds with only zero-disk flavors). |
| Network | Green gets a **new port** on blue's network/subnet (same router path); new fixed IP and MAC; FIP is the stable address. FIP required: VMs without FIP are not renewable in MVP (readiness blocker). | §6.1, §9 |
| AZ | Green is created in the data volume's AZ. | §4 same-AZ rule |
| Snapshot before handoff | Optional per profile (`data_volume.snapshot_before_handoff`, default false), taken while the volume is `available` between detach and attach; deleted at retirement. | Backup is the workload owner's job; adds downtime. |
| Anti-affinity | Best effort `different_host` hint only if configured per project; plan states "same host possible". | §7 (AS on filter availability) |
| Guest access | Worker reaches green's fixed IP **directly** (routed) or through a per-project **jump host**. No temporary FIP. | OVLM never creates FIPs in MVP (§6.1); avoids public-IP leftovers. |

### Out of MVP scope (refused by readiness, not silently handled)

VMs without FIP (provider networks), more than one data volume, multiattach volumes, boot-from-volume green,
fixed-IP or MAC preservation, Octavia/Designate cutover, hot-detach, blue locked by admin, blue in `ERROR`/`SHELVED`.

## Consequences

- Downtime = quiesce + stop + detach + attach + data_attach + start + healthcheck + FIP propagation. It is **measured**,
  not promised (renewal-workflow.md §3). The lab gives first numbers (TCG timings are not representative, ADR-0001).
- Quota must cover one extra server (cores, RAM, instances, port) during the build phase and retention.
- Old VM stays stopped and locked (FR-REN-7), consuming instance quota (cores/RAM accounting of stopped servers is
  cloud-dependent, ASSUMPTION) until retirement.
- Revert carries the data **forward**: green's writes stay on the volume; application-level schema compatibility of
  blue's software with data written by green is the workload owner's responsibility (profile attestation, V1).
- Risk: clouds whose member-visible flavors all have `disk=0` force boot-from-volume (booting zero-disk flavors from
  image is admin-only, §7 SOURCE-VERIFIED); MVP cannot renew there. Maintainer to confirm acceptable.

## Maintainer decisions (2026-11-04)

The maintainer accepted the three points raised by Agent 2:

1. **MVP scope limits:** one data volume at most (or a stateless service), the replacement boots from an image, a
   floating IP is required, and no temporary floating IPs are used.
2. **Pre-handoff snapshot:** off by default. This remains subject to the independent SRE review (Agent 7 holds a veto
   on unsafe lifecycle operations). If the SRE review rejects this default, the question goes back to the maintainer.
3. **After a revert:** the new VM stays stopped until an operator discards it.
