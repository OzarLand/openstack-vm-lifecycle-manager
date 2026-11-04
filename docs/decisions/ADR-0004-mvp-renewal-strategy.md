# ADR-0004 — MVP renewal strategy: blue/green with data-volume handoff and floating-IP cutover

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 2 (Chief Architect); maintainer approval required |

> **Revision 2026-11-04**: restore converges from "quiesced but ACTIVE" (SRE-R-1); `first_use` always false (SRE-R-3);
> automatic restore is a policy field with a closed trigger table and one attempt (SEC-R-30, SRE Q5); snapshot failure
> restores (SRE-R-7); window budget enforced (SRE-R-6); EXP-01 results (lab-observed tags, no volume creation, no
> temporary FIP confirmed). Maintainer decision **D-1: B** (below).
>
> **Revision 2026-11-04 (round 2)**: green proven ready before T0 (step B9, EXP-01b); no settle delay after the FIP
> move (EXP-01b, LAB-OBSERVED 1.1–1.3 s); snapshot described as a manual way back and kept after a restore (SRE-R-30,
> -31); evidence-invalid and `api_unreachable` rows (SRE-R-23, SEC-R-34, SRE-R-26). One deliberate deviation:
> SEC-R-34 item (2) asks that self-resolution never moves forward; renewal-workflow.md §5.1 rule 1 lets a run continue
> when the failed call is proven to have landed (exact expected post-state), inside the approved budget, and never for
> W9/W10, because SRE-R-26 shows that restoring there would undo a completed step for no safety gain.

## Context

FR-REN-2 fixes one MVP strategy. Tags below are Agent 3's (openstack-integration.md). Hard facts that shape it:

| Fact | Section | Tag |
|---|---|---|
| A non-multiattach volume can be attached to one server only; a second attach is rejected (400) | §4 | SOURCE-VERIFIED; **LAB-OBSERVED** (EXP-01 Q6) |
| Hot-detach of a mounted volume can be refused by the guest; volume rolls back to `in-use` after ~`device_detach_timeout × attempts` | §4 | SOURCE-VERIFIED |
| A locked server rejects attach, detach, stop, start, delete for a non-admin (409) | §4, §7 | SOURCE-VERIFIED; stop and detach refusal and own-unlock **LAB-OBSERVED** (EXP-01 Q6) |
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
| Blue's fstab and units | Quiesce stops units and unmounts but **does not remove** the fstab entry (must be by UUID/LABEL with `nofail`) and **never disables** units; readiness requires `service_units` enabled. Restore step S6 ensures blue has **booted since quiesce**: if blue is still ACTIVE with the volume unmounted or units inactive, it stops and starts blue (SRE-R-1). Nova stop + start was chosen over `reboot HARD` because both are already in the write credential's operation set. | Revert = attach to stopped blue, boot blue; boot remounts and restarts enabled units. Converges without `rollback_hooks`. |
| Data volume formatting | The strategy always passes `first_use = false`; a blank volume in a renewal is needs_human. `first_use = true` is reserved for a future initial-provisioning strategy with its own gate (SRE-R-3). | Closes the only `mkfs` path for renewals. |
| Rollback / revert | One **convergent restore sequence** (renewal-workflow.md §4): each step probes and skips if already satisfied, target = "volume on blue, blue ACTIVE and healthy, FIP on blue's port, green stopped". Used for in-window rollback and post-cutover revert until retirement. | One code path, testable from every intermediate state. |
| Automatic vs human rollback | Build-phase failure (incl. `NoValidHost`): run stops `failed` with green kept for diagnosis; operator rollback (typed confirmation) deletes green (security-model.md §7.1). In-window failure: automatic restore only for the rows of the **closed table** (renewal-workflow.md §4.1), controlled by the **policy** field `auto_restore_in_window` (default true; bound through the policy version in the plan hash, copied into the plan, shown at G2). One automatic restore per run; a restore failure is `needs_human`; never re-enter the window automatically. Ambiguous state (quiesce failure, `data_attach` needs_human, stuck volume, unknown FIP state, API unreachable): stop, `needs_human`. Failures after the service started on green (W7–W10): `needs_human` with paging, unless a W4 pre-handoff snapshot was taken, then automatic restore (**D-1 = B**). After cutover: revert only on operator request. | Contract §6 classes; data safety beats speed; an automatic destructive sequence must be bound to what the approver saw (SEC-R-30). |
| Window budget | Policy field `max_window_duration`, required; enforced before W2–W8 (state known → restore); from W9 the run finishes forward. G2 shows the worst-case window (Σ step deadlines W1–W10 + S1–S10) (SRE-R-6). | A threshold that only alerts is not a stop condition. |
| Number of data volumes | **Exactly one** data volume, or **zero** for profiles declaring `stateless_service: true` (handoff steps skipped). N volumes = V1. | Sequential multi-volume handoff multiplies partial states (2 of 3 moved) for no MVP value. |
| Root disk | Green boots **from image** (local root disk). Blue may be boot-from-volume: its root volume is never touched by handoff; at retirement OVLM reports a leftover root volume (`delete_on_termination=false`) and does not delete it. Boot-from-volume **green** = V1. | Simplest; but see risk below (clouds with only zero-disk flavors). |
| Network | Green gets a **new port** on blue's network/subnet (same router path); new fixed IP and MAC; FIP is the stable address. FIP required: VMs without FIP are not renewable in MVP (readiness blocker). | §6.1, §9 |
| AZ | Green is created in the data volume's AZ. | §4 same-AZ rule |
| Snapshot before handoff | Optional per profile (`data_volume.snapshot_before_handoff`, default false), taken while the volume is `available` between detach and attach; kept at retirement and after a restore (OVLM never deletes snapshots; revised 2026-11-04, see renewal-workflow.md §4) (policy `snapshot_retain_after_restore`). It is a **manual** way back for a human with Cinder rights; OVLM never restores from it (SRE-R-30). When on: B1 checks Cinder `snapshots`/`gigabytes` quota; W4 failure or deadline → automatic restore, never an open-ended outage (SRE-R-7). When off: G2 states "revert carries green's writes forward". A policy-level mandate is V1 (SRE-R-19). | Backup is the workload owner's job; adds downtime. |
| Anti-affinity | Best effort `different_host` hint only if configured per project; plan states "same host possible". | §7 (AS on filter availability) |
| Green readiness before the outage | Step B9 proves green reachable over SSH on the pinned key and healthy without data (cloud-init done, `preflight.yml`) after G2 and immediately before T0; W1 is not claimed otherwise. | EXP-01b: Nova ACTIVE came ~85 s before SSH answered; starting the window then added ~55 s of outage (R3, LAB-OBSERVED). |
| FIP move | One PUT, then W10 starts at once; no settle delay. | EXP-01b: 1.1–1.3 s API time, effective at once (LAB-OBSERVED, hairpin probe path). Documentation, not a default. |
| Guest access | Worker reaches green's fixed IP **directly** (routed) or through a per-project **jump host**. No temporary FIP. | OVLM never creates FIPs in MVP (§6.1); avoids public-IP leftovers. **Confirmed by EXP-01**: the FIP pool was empty while the FIP quota was unlimited (allocation → 400), so a design that allocated FIPs would fail on quota-green clouds; direct SSH to a fixed IP worked (LAB-OBSERVED). The write-session allowlist excludes FIP create/delete (SEC-R-7). |
| Volume creation | OVLM creates **no Cinder volume** in MVP (green boots from image; the data volume pre-exists). Any future strategy that creates one (boot-from-volume green, V1) passes an explicit `volume_type` resolved to an ID at plan time and in the plan hash, and preflight checks it exists. | EXP-01: `volume create` without a type → HTTP 500 (`__DEFAULT__` not found) on Felcloud; a working default type cannot be assumed (LAB-OBSERVED). |

### Out of MVP scope (refused by readiness, not silently handled)

VMs without FIP (provider networks), more than one data volume, multiattach volumes, boot-from-volume green,
fixed-IP or MAC preservation, Octavia/Designate cutover, hot-detach, blue locked by admin, blue in `ERROR`/`SHELVED`.

## Consequences

- Downtime = quiesce + stop + detach + attach + data_attach + start + healthcheck + FIP propagation. It is **measured**,
  not promised (renewal-workflow.md §3). First real-cloud observation (EXP-01, one run, 1 vCPU): ~45 s from unmount
  to green serving, excluding the FIP move; EXP-01b measured 40.6 s and 46.1 s total outage through the FIP when green
  was ready at T0. This informs documentation only; it is not a default and not a promise (renewal-workflow.md §10).
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

## Maintainer decision D-1 (2026-11-04): automatic restore after the service ran on green

**Decided by the maintainer, 2026-11-04: B** (relayed by Agent 1). Applied in renewal-workflow.md §4.1, §7 and
architecture.md §6 (paging mandatory for this state).

**Question.** When a failure happens at W7 `start_service_green`, W8 `healthcheck_green`, W9 `move_fip` or W10
`verify_external` (the service has run on the data volume on green), should OVLM restore to blue automatically?
(Raised by the security review, ruling (a) condition 7, for W7/W8; W9/W10 carry the same data exposure, so the answer
should cover W7–W10.)

| Option | Behaviour | Consequence |
|---|---|---|
| A. Keep default `true` | Auto restore for W7–W10 as for earlier rows; policy help text and G2 state that blue restarts on data green may have changed | Shortest outage at 3 a.m.; risk: blue's software meets data written or migrated by a half-working green, with no snapshot to go back to |
| **B. needs_human unless snapshot (recommended)** | W7–W10 failures → `needs_human`, unless `snapshot_before_handoff` is on, in which case auto restore runs | No automatic restart of blue on possibly changed data without a copy of the pre-handoff data; cost: an outage that lasts until a human acts (paging via the alert rules becomes mandatory), and profiles that want unattended recovery must turn the snapshot on (adds snapshot time to the window and needs Cinder quota) |
| C. Per-profile attestation | Auto restore for W7–W10 only if the profile carries an attestation "blue's software accepts data written by green's version" (V1 attestation mechanism pulled into MVP) | Puts the judgement with the workload owner; more MVP scope (attestation storage, expiry with profile changes) |

**Recommendation: B.** The rows before W7 move only metadata (attachments, power state), so an automatic restore
there cannot meet changed data. From W7 on it can, and only a snapshot makes that case recoverable. The consequence to
accept is a longer outage for profiles without a snapshot. The switch stays a policy field bound into the plan hash.
Option A no longer applies.

## Backlog (V1) from the reviews

SRE-R-19 policy may mandate the snapshot; SRE-R-21 stateless profiles move the FIP before stopping blue; SRE-R-22 pause
refused inside the window except at step boundaries with known state; SRE-R-20 notification channel.
