# SRE / reliability review — Phase 1 design (independent)

| Field | Value |
|---|---|
| Reviewer | Agent 7 — SRE / Reliability Engineer, **independent review** (did not read `docs/team-log.md`) |
| Date | 2026-11-04 |
| Artefacts reviewed (git commit `7a7ea43`) | `docs/renewal-workflow.md`, `docs/decisions/ADR-0003-workflow-engine.md`, `docs/decisions/ADR-0004-mvp-renewal-strategy.md`, `docs/decisions/ADR-0005-ownership-and-idempotency.md`, `docs/architecture.md`, `docs/data-model.md` (§8–§9) |
| Evidence base (not re-derived) | `docs/openstack-integration.md` ("OSI", tags SV / DU / AS as defined there), `docs/automation-contract.md` ("AC"), `docs/test-environment.md`, `docs/api-design.md` §3.7/§4, `docs/functional-requirements.md` FR-REN |
| Method | OzarLand `openstack-automation-review` SKILL.md v0.2.0 (delegated judgement, blast radius, safeguards, failure/interruption, observability) applied to a **design only**: nothing was executed, no dry run happened |
| Tagging of OpenStack claims | SV / DU / AS exactly as OSI; my own unverified claims about non-OpenStack behaviour (PostgreSQL, Linux, Ansible) are tagged **AS**. I invent no OpenStack behaviour. |

## 1. Verdict

**Accept with required changes.** No veto. No lifecycle operation is rejected as unsafe in principle; the
design's core safety argument holds: the data volume is non-multiattach so Nova and Cinder refuse a second attach
(OSI §4 SV), the old VM is stopped before detach, every step is probe-first, OVLM never deletes the data volume,
and no `force` flag exists anywhere. I found **no state in which two VMs can write the same data volume** and
**no step that can repeat a destructive action blindly** after a crash.

The acceptance is conditional on the **required-before-implementation** findings in §5.1. Three of them are
high: the restore sequence does not converge from the "quiesced but still ACTIVE" states (SRE-R-1), the fencing
design only reacts to heartbeat failure and so lets a paused worker issue a mutating call after takeover
(SRE-R-2), and the only `mkfs` path in the system is not closed for renewals (SRE-R-3). Each has a small fix.
Implementation of the **window phase (W1–W10) and restore (S1–S9)** should not start until SRE-R-1, -2, -3 are
resolved in the design documents; build-phase and engine work can proceed in parallel.

Counts: critical 0 · high 3 · medium 9 · low 6 · V1 items 4.

## 2. What the automation does (as understood)

One strategy, `bluegreen_fip_v1`: build a replacement VM (green) next to the current one (blue) with no service
impact; after a human gate (G2, typed confirmation of blue) enter a downtime window in which blue is quiesced and
stopped, the single data volume is detached from blue and attached to green, green mounts it by UUID, starts the
service, passes an internal health check with a marker checksum, and the floating IP is moved; an external probe
ends the window. Blue is kept stopped and locked for a retention period (revert available), then deleted after a
two-person gate. A PostgreSQL-backed step executor with leases, fencing tokens and run-held resource locks runs
it; failures inside the window with known state run a convergent restore automatically; ambiguous states stop in
`needs_human` with locks held.

## 3. Answers to the mission questions

### Q1. Worker death before / during / after the OpenStack call, per step

Legend: "before" = after claim, before the call; "during" = call sent, response not recorded; "after" = call done,
commit lost (fenced commit rejected or DB lost it). Resume = takeover attempt with new token, probe first.

| Step | Before | During | After | Can resume repeat a destructive act / lose data / create two writers? |
|---|---|---|---|---|
| B1 preflight | rerun | rerun | rerun | No (read-only). |
| B2 claim_resources | rerun | tag may exist → set semantics no-op | rerun | No. See SRE-R-15 (volume metadata must merge). |
| B3 create_green | ledger `intended` already committed → lookup by `tags=ovlm:run:<id>` + `^name$` (OSI §3 SV) → 0 → create | create may have landed → lookup finds 1 → adopt; if the stale call lands after the new worker created → 2 → `needs_human`, never auto-delete (ADR-0005 §4) | lookup → adopt | No data involved. Residual: whether a server in `BUILD` is returned by a `tags=` listing is OSI open question 6 → lab item already listed (§9). Quota only. |
| B4 wait_green_active | poll | poll | poll | No. Auto-delete of an `ERROR` green + retry: OVLM's own resource, never had data; classification must be an allowlist (SRE-R-11). |
| B5 wait_green_ssh | reread console | same | same | No. |
| B6/B7 preflight/configure | lease covers subprocess timeout + grace + margin; rerun (idempotent, AC §4) | same | same | No: green is disposable. Assumes the orphan subprocess dies by itself (SRE-R-5). |
| B8 verify_cutover_preconditions | rerun | rerun | rerun | No. |
| G2 await_cutover | waiting, no lease | — | — | No. Validity re-checked at W1 claim: good. |
| W1 quiesce_old | `needs_human` + read-only probe (AC §6) | same; orphan quiesce may still be running on blue → lease arithmetic must hold (SRE-R-5) | retry-step reruns quiesce (idempotent) | No writers: volume still on blue, units stopped or being stopped. **Rollback from here does not converge** (SRE-R-1). |
| W2 stop_old | probe: ACTIVE → stop | probe: `powering-off` task → wait; SHUTOFF → skip | skip | Repeating "stop" on a SHUTOFF server is a no-op by the step's own skip rule. Outage already intended. |
| W3 detach_volume | probe `in-use` on blue → DELETE (202, OSI §4 SV) | probe `detaching` → wait; `available` → skip; a second DELETE on `detaching` is refused with 400 "must be in-use" (OSI §4 SV, `begin_detaching` conditional) → retryable → re-probe | skip | No second writer possible: blue is SHUTOFF. Volume data untouched by detach. |
| W4 snapshot | ledger + name lookup | same | same | No. Failure handling inside the outage: SRE-R-7. |
| W5 attach_volume_green | probe `available` → POST | probe attachment to green exists / `reserved` / `attaching` → wait (OSI §4 SV states) | skip | A stale duplicate POST is rejected 400 (OSI §4 SV `_check_volume_already_attached`). Both calls target green, so the end state is "attached to green once". |
| W6 data_attach_green | `needs_human` + probe | same | retry-step reruns; decision table never formats an existing fs (AC §3.3) | Only data-destructive path = `mkfs` when `first_use == true` → must be impossible in a renewal (SRE-R-3). |
| W7 start_service_green | rerun (idempotent) | rerun | rerun | Green is the only VM with the volume attached and ACTIVE; blue SHUTOFF. One writer. |
| W8 healthcheck_green | rerun (read-only) | rerun | rerun | No. |
| W9 move_fip | probe FIP on blue → PUT (pure state set, OSI §3 SV) | probe FIP `port_id` → green → verify; still blue → PUT again (repeat-safe) | verify | Not data. Stale PUT landing after a restore's S8 → FIP on stopped green → S9 fails → `needs_human` (visible, not data-destructive) — this is the window SRE-R-2 narrows. |
| W10 verify_external | rerun | rerun | one transaction, rerun recommits | No. |
| R1 retain_old (lock) | probe `locked` → skip | same | same | No. |
| X1 retire_old | probe: locked by OVLM → unlock; attachments re-read (only root; `delete_on_termination` known, mv ≥ 2.79 SV) → DELETE | probe 404 → done | 404 → done | Irreversible but **not repeatable** (404 = done). Data volume is never attached to blue here by precondition. The `intent` row is committed before the call, so the audit trail survives a lost result. Add "green demonstrably holds the data" to the probe (SRE-R-10). |
| S1–S9 restore | each probes, skips if satisfied | same | same | S5 attach-to-stopped-blue is allowed in STOPPED (OSI §4 SV). Order S2→S3→S4 before S5 guarantees the volume leaves green before it reaches blue. A stale W5 landing between S4 and S5 → S5 sees "attached to green" → unexpected → `needs_human` (correct, retry restarts at S2). |

Conclusion Q1: no step can repeat a destructive act, lose the only copy of the data, or produce two writers,
provided SRE-R-3 (no `mkfs`) and SRE-R-5 (orphan subprocess really dies within its lease) hold. The data volume
is never created, formatted (for renewals), or deleted by OVLM.

### Q2. Fencing and lease design

Sound in structure (claim with `FOR UPDATE SKIP LOCKED`, monotonic `fencing_seq`, every write guarded by
`id AND fencing_token AND state='running'`, intent persisted before act, lease covering subprocess timeouts). Gaps:

- **Clock skew.** Claiming and heartbeat use DB `now()`; self-fencing compares against `lease_expires_at`, a DB
  timestamp. If the worker computes "lease_expires_at − fence_margin reached" with its own wall clock, a worker
  clock behind the DB clock fences late, after a takeover. The fence deadline must be a **local monotonic** value
  derived from the moment the claim/heartbeat response arrived (`t_response + lease_duration − margin`), never a
  wall-clock comparison against a DB timestamp (SRE-R-2).
- **Long pause (SIGSTOP, VM freeze, swap, debugger).** ADR-0003 self-fences "if a heartbeat fails … and
  lease_expires_at − fence_margin is reached". A paused worker fails no heartbeat; when it resumes, the next thing
  it does may be the OpenStack call it was about to send. The fence must be checked **before every mutating
  call and every subprocess spawn**, and `0 rows` on heartbeat must stop the step at once, not at lease end.
  The runtime guard "WriteClient needs a step context with a valid token" (architecture.md §3) is the natural
  place: a request hook that refuses to send when the local fence deadline has passed (SRE-R-2).
- **DB failover with lost commits.** Probe-first makes lost commits harmless for every step (the next attempt
  re-derives state from OpenStack; `intent` rows are committed before acting). One hole: if an async replica is
  promoted without the last transactions, `fencing_seq` may hand out a value a stale worker still holds
  (AS, PostgreSQL sequence/WAL behaviour, not verified here); the stale commit guard would then pass. Adding
  `lease_owner = <per-process uuid>` to the guard closes it; the HA posture (single instance with backups, or
  synchronous replication) should be stated (SRE-R-4).
- **Lost commit after a successful OpenStack call.** Covered by probe-first. I checked each destructive step for
  state that cannot be re-derived from OpenStack: W1's marker checksum (re-derived by rerunning the idempotent
  quiesce), B5's fingerprint (reread from console), `downtime_started_at` (under-measured if lost → write it in the
  W1 claim transaction, SRE-R-14). Nothing destructive depends on lost local state.
- **Limit acknowledged in ADR-0003** (OpenStack does not know the token): with the gate in SRE-R-2 the residual
  window is one network round trip. I walked the stale-call outcomes per step in Q1; all are observable and none
  reach the volume's data.

### Q3. Rollback and revert convergence

Target state "volume on blue, blue ACTIVE and healthy, FIP on blue, green SHUTOFF". Per reachable state:

| State reached | Restore path | Converges? |
|---|---|---|
| Build phase (any) | delete green on operator rollback | Yes (blue never touched). |
| W1 done, W2 not (blue ACTIVE, units stopped, volume unmounted) — also: W2 refused, abort right after W1 | S1–S5 skip, **S6 skipped because blue is ACTIVE**, S7 = `rollback_hooks` *if present* + healthcheck | **No** without `rollback_hooks.yml`: nothing remounts or restarts; S7 fails → `needs_human` with the service down and no OVLM action left except retrying S7. **SRE-R-1.** |
| W2 done (blue SHUTOFF, volume on blue) | S6 start → fstab (UUID, `nofail`) remounts, enabled units start | Yes, if units are *enabled* (quiesce stops, must not disable) — add to B1 probe (SRE-R-1). Lab item already listed. |
| W3 done (volume `available`) | S5 attach to stopped blue (OSI §4 SV), S6 | Yes. |
| W5 done (on green, not mounted) | S2 quiesce green (idempotent "already unmounted"), S3, S4, S5, S6 | Yes. |
| W6–W8 done (mounted/serving on green, FIP on blue) | S2–S6 | Yes. |
| W9 done / W10 failed | + S8 move FIP back, S9 | Yes. |
| Retained (locked) | S1 unlock own lock (OSI §7 SV) then as above | Yes. Admin lock → `needs_human` (OSI §7 SV, unlock override is admin). |
| Green deleted/gone mid-restore | S2/S3 skip; Nova delete detaches volumes (OSI §4 SV) → S4 skip | Yes. |

Where a human or OpenStack admin is needed (§6 of the workflow): stuck `detaching`/`reserved`/`attaching`,
`error_attaching`, blue's compute host down (detach refused; OSI §9 SV), admin lock, `ERROR` with task state, FIP
`DOWN`. All are correctly out of a `member`'s reach (OSI §8 SV). Are those states safe to sit in? **For data,
yes**: in every one of them at most one VM has the volume and either it is SHUTOFF or the volume is not mounted
for writing by a second party. **For availability, no**: the service is down until a human acts, so paging is
part of safety (SRE-R-9). The design surfaces the stuck resource, status, request IDs and the admin action; that is
the right content. What is missing is a single run-level "current truth" view and a read-only re-probe action
(SRE-R-9).

### Q4. Downtime window

Bounded per pass: every W step has a deadline key, W8 is bounded by `max_attempts`, failures go to restore, and
restore steps have deadlines. Measured: yes, `downtime_started_at` → `downtime_ended_at` (or S9 success), exported.
Stop condition that *goes back*: present for failures, **absent for time**: `renewal.max_window_duration` "only
triggers an alert, never an automatic action". Per the method's stop-condition criterion that is "continue on
threshold breach". Required: enforce the budget at each W-step start while state is known (W1–W8) → restore; from
W9 on, finish forward (going back is no shorter). Show the worst-case window (Σ W deadlines + Σ S deadlines) in
the G2 preview so the approver knows what they approve (SRE-R-6). Unbounded waits remain only in `needs_human`,
which is correct (human judgement), provided it pages (SRE-R-9). A policy window closing while the run is inside
the downtime window should be stated as "run continues; restore may run outside the window" (SRE-R-14).

### Q5. `renewal.auto_rollback_in_window` default `true`

**Safe default, accept**, under these conditions, which the design mostly states and should make explicit:
(1) it runs only when every resource state is known from a **fresh** probe (not cached evidence) — stated;
(2) the trigger list is **closed**: W7 failure, W8 exhausted, W9 4xx with FIP verified unchanged by GET, W10
exhausted, W4 failure (SRE-R-7), window budget exceeded (SRE-R-6); anything else → `needs_human`; (3) restore is
bounded and is **never retried automatically** (restore failure → `needs_human`); (4) SRE-R-1 is fixed, otherwise
the auto-restore from early-window states ends in `needs_human` anyway. The alternative default (`false`) leaves
the service down at 3 a.m. waiting for a human in states where the way back is known and safe; that is worse.
Flapping risk: W10 failing on FIP propagation lag (DU, OSI §6.1) triggers a restore that then faces the same lag at
S9 — the lab must size `external_verify` deadlines above observed propagation (already a lab item).

### Q6. Optional pre-handoff snapshot default `off`

**Acceptable for MVP, with changes.** A failed handoff that leaves the volume in `reserved`/`attaching`/
`error_attaching` is an attachment **metadata** state (OSI §4 SV); the bytes are untouched and an admin reset
returns the volume. A snapshot does not help there. What the snapshot protects against is **application-level**
damage by green and schema-forward writes that blue cannot read after a revert (ADR-0004 "data carried forward").
That is a real risk the owner must see. Required: (a) the plan/G2 preview states "no pre-handoff snapshot: revert
carries green's writes forward" when off (SRE-R-6 preview); (b) when on, W4 failure inside the outage must
restore, not `needs_human` (SRE-R-7); (c) B1 pre-checks Cinder snapshot/gigabytes quota when on (SRE-R-7).
V1: let a **policy** mandate it (SRE-R-19).

### Q7. Mission failure scenarios → designed behaviour → judgement

| Scenario | Designed behaviour (renewal-workflow §5, §7) | Judgement |
|---|---|---|
| Interrupted workflow | Lease expiry → takeover with probe; data phases → `needs_human` + read-only probe; no duplicate green (ledger + tag), no duplicate attach (Nova refuses, SV) | Sound. Conditions: SRE-R-2 (fence gate), SRE-R-5 (orphan subprocess). |
| Insufficient compute capacity | Quota pre-check advisory (host capacity invisible to member, OSI §7 SV); `OverQuota` fatal; `NoValidHost` → delete ERROR green, bounded retry; blue untouched | Sound. Classification must be an allowlist and retries backed off (SRE-R-11). |
| Failed provisioning | BuildFailed, green kept for diagnosis, operator rollback deletes only `ovlm:run:<this run>` | Sound. Note the run holds all locks while failed — intended, visible via `409 resource-locked`. |
| Failed Ansible configuration | AC §6 classes; fatal → BuildFailed; volume never left blue | Sound. |
| Failed health check | W8 exhausted → auto restore S2–S9, FIP never moved; downtime includes restore | Sound (blue is SHUTOFF here, so S6 starts it). |
| Failed cutover | W9 error → FIP unchanged (single transaction, OSI §6.1 SV) → restore; W10 failure → restore incl. S8; FIP unknown → `needs_human` | Sound. Add "no FIP already on green's port" to B8 (SRE-R-13). FIP `DOWN` past deadline → `needs_human` is right: a PUT back faces the same agent. |
| DB or worker restart | Self-fence at lease end − margin; fenced commit decides; waits are timers | Sound with SRE-R-2 and SRE-R-4. |
| Detach refused / stuck (extra) | `needs_human`, blue stopped; operator may roll back (S6) or call admin | Sound. |
| Blank or wrong fs on green (extra) | W6 `needs_human`, no `mkfs` | Sound **only if** `first_use` is hard-wired `false` (SRE-R-3). |

### Q8. Observability at 3 a.m.

Present and good: run state + phase + current step, per-step evidence with before/after states and OpenStack
request IDs, `downtime_*` timestamps, locks held, `next_action` on errors, `blast_radius` on pre-confirmation
GETs, §6 table of admin actions, JSON logs with run/step/token correlation, metrics including
`ovlm_runs_needing_attention`, `ovlm_lease_takeovers_total`, `ovlm_fenced_commit_rejected_total`, worker heartbeat in
`/readyz`. Audit is append-only at DB level.

Gaps for an operator who did not design the system: no single answer to "where is the data, who can write to
it, who is reachable, right now" (it is spread over step evidence); no read-only re-probe action (the only
actions mutate); running steps whose worker is dead look "running" for up to the full lease (minutes for Ansible
steps) with no lease owner / heartbeat age shown; no documented alert rules; the dashboard "runs needing
attention" is V1 (FR-UI-1), so in MVP the run page and `GET /runs?state=needs_human` must stand alone; no
notification channel at all (SRE-R-9, SRE-R-20).

## 4. Method checklist (openstack-automation-review)

**Decisions the automation takes (execution vs judgement).**

| Decision | Kind | Delegated explicitly? | Verdict |
|---|---|---|---|
| Start the outage (quiesce + stop blue) | judgement | Yes: G2 approval or operator TC of blue, human session, bound to plan hash | Correct |
| Move the FIP | execution (inside approved window) | Yes (G2 covers the window) | Correct: a gate here would extend the outage |
| Restore automatically inside the window | execution when state known | Yes: `auto_rollback_in_window` (policy), closed triggers required (SRE-R-6/7) | Correct |
| Delete an `ERROR` green and retry create | execution on OVLM-owned, data-less resource | Implicit | Make the trigger an allowlist (SRE-R-11) |
| Delete blue | judgement | Yes: two-person G3 + TC | Correct; add "green holds the data" probe (SRE-R-10) |
| Decide a blank volume is "fine" | judgement | Never delegated (`needs_human`) | Correct, close `first_use` (SRE-R-3) |
| Force-detach / reset-state / unlock override / evacuate | judgement + admin | Not delegated; OVLM has no admin credential | Correct |
| Delete orphans | judgement | Manual, typed confirmation | Correct |

**Scope and blast radius.** One service, one blue, one green, one volume, one FIP per run; locks per resource
held by the run; ≤ 5 runs; ownership guard (DB ledger AND marker) before every mutating call; write credential
`member` on one project; no admin credential. Target set is explicit (plan IDs), never "all". Good.

**Safeguards.**

| Safeguard | Present (evidence) | Gap |
|---|---|---|
| Preview / dry run | Plan with resolved IDs; `blast_radius`; B1 re-validates live; `--check` for configure | Worst-case window and "no snapshot" consequence missing from the G2 preview (SRE-R-6) |
| Explicit scope | plan IDs; one-host Ansible inventory (AC §2) | — |
| Confirmation | G1/G2/G3; TC = name + last 6 ID chars; human session + step-up; no `force` anywhere | — |
| Monitoring while running | W8/W10 probes; metrics; evidence | Run-level truth view, alerts (SRE-R-9) |
| Stop conditions | Deadlines per step; failure → restore / `needs_human`; API-unreachable → no auto restore | Time budget is alert-only (SRE-R-6); W4 failure halts inside outage (SRE-R-7) |
| Pre-checks | §1 preconditions, B1, B8 | Units enabled (SRE-R-1); credential expiry vs window (SRE-R-8); green port has no FIP (SRE-R-13) |
| Post-checks | Capability-based: marker checksum, fs UUID, external identity probe | S9 identity not stated (SRE-R-13) |
| Idempotency | probe→decide→act→verify; ledger + tags; set-semantics everywhere | `owned_resource` uniqueness vs retried green (SRE-R-11) |
| Concurrency lock | `resource_lock` run-held; one running step per run; Ansible lease rule | Port lock timing (SRE-R-16) |

**Production-software discipline.** Pinned SHA automation, pinned requirements, versioned strategy, crash tests
in CI listed (ADR-0003 consequences), evidence per attempt, upgrade drain rule. Good. Control-debt check: can an
operator other than the author explain and recover it? Yes for the state machine (the tables are explicit); the
engine's lease/fence semantics need the operator-facing fields in SRE-R-9 to be explainable at 3 a.m.

## 5. Findings

Severity: critical / high / medium / low. "Artefact" cites document and section.

### 5.1 Required before implementation

| ID | Sev | Artefact + section | Failure scenario | Why it matters | Required change (minimum) |
|---|---|---|---|---|---|
| SRE-R-1 | **high** | renewal-workflow.md §4 (S6, S7), §5 "Operator abort", §1 preconditions; AC §3.4 | W1 `quiesce_old` succeeds (units stopped, volume unmounted) and then W2 fails/is refused, the operator aborts, or the worker dies and the operator chooses rollback. Restore: S5 skipped (volume on blue), **S6 skipped because blue is ACTIVE**, S7 runs `rollback_hooks.yml` only if the profile has one, then healthcheck fails → `needs_human`. Service stays down; OVLM has no remaining action but retrying S7. | The design promises one convergent restore "testable from every intermediate state" (ADR-0004). It does not converge from the first state the window can fail in, and relies on an optional profile hook. | (a) S6 becomes "ensure blue has booted since quiesce": if blue is ACTIVE and a read-only probe (`findmnt` on the mount point, `systemctl is-active` on `service_units`) shows the volume unmounted or units inactive → Nova stop, wait `SHUTOFF`, Nova start (primitives already used; stop/start are `member`, OSI §7 SV; Nova stop's guest-shutdown behaviour against a busy mount is AS → lab item). (b) B1 precondition: `service_units` are **enabled** (`systemctl is-enabled`, read-only) so a boot restarts them; quiesce must stop, never disable. (c) `rollback_hooks` stays optional defence in depth in S7. (d) Update AC §3.4 ("remove the fstab line only after OVLM confirms handover") to match renewal-workflow §8 row 7 (fstab never edited); the two documents currently contradict each other. |
| SRE-R-2 | **high** | ADR-0003 "Self-fencing", "Limit of fencing"; architecture.md §3 runtime guard | Worker is paused (SIGSTOP, hypervisor freeze, swap storm) past its lease; another worker takes over W9 and, on failure, restores (S8 FIP → blue). The paused worker resumes and sends the PUT it had prepared (`port_id = green`) — green is now SHUTOFF → FIP on a stopped VM, outage until S9 fails and a human acts. Same shape for any mutating call. Separately: fence computed by comparing worker wall-clock to DB `lease_expires_at` fences late when the worker clock lags. | Self-fencing is defined reactively ("if a heartbeat fails and … is reached"); a paused process fails no heartbeat before it acts. The ADR's own mitigation list assumes fencing happens before lease expiry. | (a) Fence deadline is a **local monotonic** timestamp set from the claim/heartbeat *response* time (`t_resp + lease_duration − fence_margin`), never a wall-clock comparison with DB timestamps. (b) The deadline is checked **immediately before every mutating OpenStack call and every subprocess spawn** (WriteClient request hook; automation module before `exec`), and before each fenced commit. (c) A heartbeat returning 0 rows stops the step at once (ownership already lost), not at lease end. (d) Add "paused worker (SIGSTOP longer than the lease)" to the CI crash-test list. |
| SRE-R-3 | **high** | renewal-workflow.md §2.2 W6; AC §3 common extra-vars `ovlm.data_volume.first_use`, §3.3 decision table | `first_use` is "set by OVLM from its own records". A renewal of a VM OVLM has never handed off before has no record; if the strategy derives `first_use` from "no prior data_attach recorded", the first renewal of every existing VM passes `true`, and a blank device that matched the serial (wrong volume, AS) would be formatted with no human in the loop. | This is the **only** `mkfs` path in the whole system; AC §3.3 row "no fs and `first_use == true` → mkfs" is the single data-destructive branch. Closing it costs one line. | The renewal strategy passes `first_use = false` unconditionally; W6 evidence records the value passed; a blank volume in a renewal is always `needs_human`. `first_use = true` is reserved for a future, separate "initial provisioning" strategy with its own gate. Static lint: the strategy must not be able to set it. |
| SRE-R-4 | medium | ADR-0003 "Fenced commit", "DB outage"; data-model.md §8 `fencing_seq`; architecture.md §11 "DB HA is the operator's choice" | PostgreSQL failover to an async replica that lost the last transactions: a claim with token N is lost; the promoted DB re-issues N (AS: sequence values are WAL-logged ahead in batches; a lost tail can still regress). A new worker claims the same step with token N; the stale worker's commit `WHERE fencing_token = N AND state='running'` **succeeds** and overwrites the live attempt's evidence/state. | The whole correctness story rests on "a stale worker can never commit". Probe-first limits damage on OpenStack, but a successful stale commit can advance the run on stale evidence. | (a) Guard every fenced commit and heartbeat with `AND lease_owner = :worker_instance_id` (uuid per process start) in addition to the token. (b) State the DB HA posture in architecture.md: single instance with backups (MVP) **or** synchronous replication (`synchronous_commit = on`, sync standby); asynchronous failover is explicitly unsupported for the workflow tables. (c) After any lost DB connection the worker treats its in-memory ownership as unknown until a heartbeat with both predicates returns 1 row. |
| SRE-R-5 | medium | ADR-0003 "Lease + heartbeat" (subprocess lease rule); renewal-workflow.md §5 "Worker crash" ("a killed container kills its children; the startup sweeper removes run dirs"); AC §8 | The worker *process* dies (OOM-kill of the Python process, `kill -9`) but the container lives; `ansible-runner` is re-parented to the container's PID 1 and keeps running `quiesce` on blue (or `configure` on green). The lease arithmetic (timeout + grace + margin) assumes the orphan stops by itself; nothing in the design guarantees it. "Sweeper removes run dirs" does not kill a process. | The "no second Ansible run on the same VM" guarantee for data phases depends on the orphan being dead when the lease expires. | (a) Spawn `ansible-runner` in its own process group with ansible-runner's own `--timeout` (DU, AC §2) **and** a kernel-level tie to the parent (`PR_SET_PDEATHSIG`, AS Linux) so parent death kills it. (b) The startup sweeper kills any process group recorded in a run-dir marker **before** the restarted worker claims any step. (c) Run the worker as PID 1 (or with a minimal init that forwards signals and reaps) so "container killed ⇒ children killed" is actually true. (d) CI crash test: kill only the worker process mid-`configure`, assert the subprocess is gone before takeover. |
| SRE-R-6 | medium | renewal-workflow.md §3 "window budget … only triggers an alert, never an automatic action"; api-design.md §4 `blast_radius` | Slow Cinder backend: W3 uses its whole detach deadline, W5 its attach deadline, W8 all attempts, W10 its deadline; the pass is "bounded" at the sum of defaults nobody has summed, far past what the approver imagined at G2. The budget fires an alert and the run continues. | A threshold breach that only alerts is "continue", not a stop condition (method §4). Q4 asks for a stop condition that goes back. The G2 approver cannot see what they are approving in time. | (a) `renewal.max_window_duration` is enforced: before starting each of W1–W8, if `now − downtime_started_at > budget` and state is known → restore; from W9 on, finish forward. Default must exist (lab-derived), not "optional". (b) `blast_radius` / G2 preview shows worst-case window = Σ deadlines(W1–W10) + Σ deadlines(S1–S9), and whether a pre-handoff snapshot is taken ("no: revert carries green's writes forward"). |
| SRE-R-7 | medium | renewal-workflow.md §2.2 W4 (`retryable → needs_human`); ADR-0004 "Snapshot before handoff" | Profile opts into the snapshot; Cinder snapshot fails or stalls (quota, backend). The run stops in `needs_human` with blue SHUTOFF, volume `available`, service down, waiting for a human — in a state that is fully known and trivially reversible. | A safety option must not convert a known, reversible state into an unbounded outage. The snapshot is a safety net, not a precondition for serving. | W4 failure or deadline → **auto restore** (state known: volume `available`, blue SHUTOFF) with reason "snapshot failed"; the operator re-runs later. B1 pre-checks Cinder `snapshots`/`gigabytes` quota when the option is on (OSI §9 SV: snapshots count). A stuck snapshot (`creating` past deadline) is reported as an orphan candidate, never deleted automatically. |
| SRE-R-8 | medium | AC §2 isolation rules ("fresh `git clone` … per run, per phase attempt", requirements install per run dir); renewal-workflow.md §2.2 W1, W6, W7, W8; §1 preconditions | Inside the downtime window each Ansible phase (W1, W6, W7, W8 ×N) performs a fresh clone from the git host and a collections install. Git host or Galaxy mirror unavailable, or slow, during the outage → W1 fails before it starts (`needs_human` with service up — acceptable) or **W6/W7 fail after the volume moved** → restore; outage extended by an external dependency that has nothing to do with the cloud. Likewise: write application credential or G2 approval expiring mid-window → `needs_human` mid-outage. | The window must depend only on OpenStack and the two guests. Every external dependency inside it is an outage multiplier. | (a) Clone and verify (`rev-parse HEAD == SHA`, requirements installed) **once per run** in the build phase (B6) into a read-only run-level directory; window phases copy from it (local, no network); per-attempt isolation is kept by copying. (b) B1 and the W1 claim check: write-credential `expires_at` and G2 validity exceed `now + worst-case window` (SRE-R-6 value). (c) Keystone token refresh is pre-warmed at the W1 claim. |
| SRE-R-9 | medium | architecture.md §6; api-design.md §3.7; renewal-workflow.md §6; FR-UI-1 (dashboard is V1) | 3 a.m., run in `needs_human` at W5. The operator opens the run: step list, evidence per step. To answer "is the volume on blue or green, is anything mounted, where is the FIP, is blue locked, is the worker alive, and what does `rollback` do *from here*" they must read several steps' evidence and the design document. A step whose worker died shows `running` for up to the Ansible lease with no sign the worker is gone. No alert reaches anyone unless the operator wrote rules themselves. | Method §6: the organisation must know what state things are in and how to stop or recover, from the tool alone. Safety of `needs_human` states depends on a human arriving. | (a) Run-level **current-truth panel** stored on the run and refreshed on every phase change, on entering `needs_human`, and on demand: blue/green status + task + lock, volume status + attachment target, mount state (last `findmnt`), service units state, FIP `port_id`/`status`, probe timestamp, OpenStack request IDs. (b) `POST /runs/{id}/actions/probe`: read-only re-probe (read credential, SSH read-only), no TC. (c) Run body carries `available_actions[]` with the concrete effect from the current state ("rollback will: stop green, attach volume to blue, start blue, keep FIP on blue"). (d) Running steps expose `lease_owner`, `lease_expires_at`, `heartbeat_at`, and the worker's `last_seen_at`; the UI flags "worker not seen for X, takeover at T". (e) Ship a sample Prometheus alert file: `needs_human` while `phase=window`, window budget breach, worker heartbeat age, `ovlm_fenced_commit_rejected_total` increase, `ovlm_lease_takeovers_total` increase, runs in `needs_human` > 15 min in any phase. |
| SRE-R-10 | medium | renewal-workflow.md §2.3 X1 probe ("blue SHUTOFF, locked by OVLM, no data volume attached") | During retention green crashes or an admin moves the volume; nobody notices; retirement is requested and approved on schedule (two humans, but acting on the calendar, not on evidence). X1's probe passes (blue has no data volume) and deletes the only VM proven to serve the data. | Never delete the way back while the forward path is not demonstrably live. The check is cheap and uses reads OVLM already does. | X1 probe adds: volume `in-use` attached to the service's `current` managed VM (green), green `ACTIVE`, and a fresh `healthcheck.yml` (role `new`) ok within the last `retire.health_max_age`; otherwise `needs_human`, never delete. Show this evidence in the G3 approval `blast_radius`. |
| SRE-R-11 | medium | renewal-workflow.md §2.1 B4 ("ERROR → fatal for this attempt"), §7 rows "Insufficient capacity" (delete + retry) vs "Failed provisioning" (keep); ADR-0005 / data-model.md §9 `UNIQUE(run_id, role)` | B4 cannot tell "capacity" from "bad image" except by `fault.message` text (OSI §7 SV: `NoValidHost` is visible as a fault message for a member). A broad match auto-deletes greens that should have been kept for diagnosis; a narrow miss retries a non-capacity failure. Also: a retried green needs a second `owned_resource` row with role `green` for the same run, which the unique constraint forbids. | Automatic deletion, even of an OVLM-owned data-less VM, must be on a closed, documented trigger. The data-model constraint will block the designed retry at implementation time. | (a) Auto-delete + retry only on an explicit allowlist of fault codes/messages (initially `NoValidHost`), with backoff ≥ `poll.max_interval` between attempts and `retry.max_attempts.create_green` bound; everything else: keep green, BuildFailed. (b) `owned_resource`: partial unique `UNIQUE(run_id, role) WHERE state IN ('intended','present')`, keeping deleted rows as history. |
| SRE-R-12 | medium | ADR-0003 "Step contract" (`WAIT`, lease released); renewal-workflow.md §5 "OpenStack API outage" | API outage lasting longer than a step's deadline during the window → `needs_human` ("state unknown"), sticky. The API returns ten minutes later; the run still waits for a human although a probe would now resolve the state and restore could run. | The outage is unbounded by a condition (human presence) unrelated to the actual state, which OVLM can re-derive by itself as soon as the API answers. | Distinguish `needs_human(reason=api_unreachable)` from other reasons: the scheduler re-probes it automatically every `poll.max_interval`; when a probe succeeds and the state is known and auto-restore conditions hold → continue the designed handling (restore or resume) and record that it self-resolved. Other `needs_human` reasons stay manual. |

### 5.2 Low (fix during implementation; no design re-approval needed)

| ID | Sev | Artefact + section | Failure scenario | Required change |
|---|---|---|---|---|
| SRE-R-13 | low | renewal-workflow.md §2.1 B8, §4 S9 | Green's port already carries a FIP on the same external network → W9 gets 409 `FloatingIPPortAlreadyAssociated` (OSI §6.1 SV) only inside the window. S9 does not state that the response must come from **blue** (W10 states "from green"); a stale W9 landing late would pass a naive S9. | B8 asserts no FIP on green's port. S9 verifies the identity/marker field equals blue, mirroring W10. |
| SRE-R-14 | low | renewal-workflow.md §3, §5 | `downtime_started_at` written outside the W1 claim transaction is lost on a lost commit → under-measured downtime, budget (SRE-R-6) computed late. Policy window closes mid-window: behaviour unstated. | Write `downtime_started_at` in the W1 **claim** transaction (first claim only). State: "a policy window closing during the downtime window does not stop the run; restore may run outside the window". |
| SRE-R-15 | low | renewal-workflow.md §2.1 B2; ADR-0005 §5 (volume metadata `ovlm.managed`) | Cinder has two metadata write semantics (replace-all vs merge; **AS**, not covered by OSI). Replace-all would erase the owner's existing volume metadata (e.g. backup tags) on every run. | Implement B2 with merge semantics; OSI to add the fact with a tag; test in lab with pre-existing metadata. |
| SRE-R-16 | low | ADR-0003 "Resource locks" (acquired in the run-creation transaction); data-model.md §9 (`port` type) | Green's port does not exist when the run is created, so it cannot be locked then; the design does not say when it is. | Either lock green's port in the B3 success transaction, or drop `port` from the MVP lock types. |
| SRE-R-17 | low | renewal-workflow.md §4 ("green stays SHUTOFF for diagnosis") | After restore, a project member starts green by hand; its enabled units start without the volume (`nofail`) and write into the mount-point directory on green's root disk; later diagnosis is confused, and if someone later re-attaches the volume by hand the data is split. | R-step after restore: lock green with `locked_reason='ovlm:restored:<run>'` (own lock, OSI §7 SV); unlock in Discarding. State the expectation that green is discarded promptly. |
| SRE-R-18 | low | renewal-workflow.md §2 diagram (`NeedsHuman --> Window: retry-step`) | `needs_human` raised in Restoring; the diagram sends `retry-step` back to Window. | State "`retry-step` retries the current step in the current phase; the overlay never changes phase" and redraw. |

### 5.3 V1 (not required for MVP)

| ID | Artefact | Change |
|---|---|---|
| SRE-R-19 | ADR-0004 snapshot option | Allow a **policy** to mandate `snapshot_before_handoff` (organisation-level), not only per profile. |
| SRE-R-20 | architecture.md §6 | Notification channel (webhook/e-mail) for `needs_human` and window-budget breach; MVP relies on Prometheus alerting (SRE-R-9 e). |
| SRE-R-21 | ADR-0004 `stateless_service` | For stateless profiles move the FIP **before** stopping blue (green already configured and serving on its fixed IP): near-zero downtime, no quiesce. |
| SRE-R-22 | FR-REN-8 pause | Pause is V1 already; when added, pause must be refused inside the window except at step boundaries with known state, same rule as abort. |

## 6. Questions for the authors

1. SRE-R-1: is Nova `stop` acceptable as the "reboot blue after quiesce" primitive, or do you prefer Nova
   `reboot HARD` (also `member`, OSI §7 SV, but a new primitive in the write credential's access rules)?
2. SRE-R-2: where exactly will the fence check live — SDK session hook, or the `WriteClient` wrapper? The
   architecture's runtime guard suggests the wrapper; the hook catches raw `session.post` paths too.
3. SRE-R-8: does AC's "no reuse of a checkout" intend to forbid a per-run verified copy, or only cross-run reuse?
4. SRE-R-10: what maximum age of a green health check is acceptable before retirement (`retire.health_max_age`)?
5. Q5/Q6: confirm the closed trigger list for auto restore (W4, W7, W8, W9-4xx-verified, W10, budget) and that
   restore is never auto-retried.

## 7. Lab items this review adds (to test-environment.md §5)

- Rollback from "quiesced, blue ACTIVE" (kill the worker right after W1 success; then operator rollback) → blue
  serving again without `rollback_hooks.yml` (SRE-R-1).
- Paused worker: `kill -STOP` the worker mid-W9 for longer than the lease; takeover; `kill -CONT`; assert no
  second PUT is sent (SRE-R-2).
- Worker process (not container) `kill -9` mid-`configure` and mid-`quiesce`; assert the `ansible-runner`
  process group is gone before the takeover claims (SRE-R-5).
- Snapshot option on, Cinder snapshot quota 0 → W4 fails → automatic restore, downtime recorded (SRE-R-7).
- Git host unreachable during the window (block egress after B8) → window must still complete (SRE-R-8).
- Window budget set below the observed detach time → restore triggered at the W4/W5 boundary (SRE-R-6).

## 8. Maintainer decisions needed

1. Approve the three high findings as design changes before window-phase implementation (SRE-R-1, -2, -3).
2. Decide the DB HA posture statement (SRE-R-4): single instance + backups for MVP, synchronous replication
   otherwise; asynchronous failover unsupported.
3. Confirm that `renewal.max_window_duration` becomes a stop condition with a mandatory, lab-derived default
   (SRE-R-6), and accept that auto-restore triggers are a closed list.
4. Confirm the MVP observability minimum (SRE-R-9 a–e) given that the dashboard is V1.

> Decision support only. State-changing steps above require approval by the
> accountable owner and should be executed under your change process.
