# ADR-0008 — Exit when a step's own pinned playbook refuses a state verified safe (roadmap P0-2)

| Field | Value |
|---|---|
| Status | **Accepted by the maintainer, 2026-11-09** (decisions at the end). Implementation: roadmap P0-2. |
| Date | 2026-11-09 |
| Deciders | Maintainer (decision); Agent 2 (Chief Architect, workflow and API); Agent 7 (SRE) and Agent 8 (Security) review, as for every state-changing operation |
| Evidence | D-8 and D-8b ([mvp-report.md](../mvp-report.md) §4), LAB-01 first attempt, run `01a1b9e7`, Felcloud, 2026-11-08 (**LAB-OBSERVED**). Behaviour of the existing signals: `src/ovlm/workflow/engine.py` (retry-step, mark-resolved, reprepare-automation all re-queue the step) and `src/ovlm/renewal/definition.py` (**SOURCE-VERIFIED**) |

## Context

A run pins its automation repository to one commit SHA. The SHA is part of the plan hash approved at G1, and B6 clones
and verifies it once. Nothing contacts the git host inside the downtime window, except one authorized re-clone of the
**same** SHA (`reprepare-automation`, [automation-contract.md](../automation-contract.md) §2). This is on purpose: the
code that runs during the outage is the code the approver approved.

LAB-01 showed the cost of that rule when the pinned code itself is wrong.

1. The worker died after W5 (volume attached to green) and before W6 (mount). Green held the data volume but had never
   mounted it.
2. The operator rolled back. The restore reached S2 (`quiesce_green`, AC `quiesce.yml` on green).
3. S2 parked first on defect Z (checkout lost). `reprepare-automation` re-cloned the pinned SHA (digest equal).
4. S2 then parked on defect AA: the pinned `quiesce.yml` treats "not mounted, no earlier quiesce record" as unknown and
   refuses. The fix (`ovlm.quiesce_allow_unmounted`, AC §3.4) existed later, but the run's pin predated it.
5. `retry-step` re-runs the same playbook. `mark-resolved` re-queues the step, which must reach Done from its own probe
   and act, so it re-runs the same playbook too (by design, SRE-C-2). `reprepare-automation` re-clones the same SHA.
   The pin cannot change during a run. **No OVLM path was left.**
6. Agent 1 decided a manual guest action: after read-only checks, the volume was mounted on green (no fsck, no write,
   service not started), only so that the old playbook would see a state it accepts. Then `retry-step` on S2; S2–S10
   ran on their own. Data was safe (volume never attached twice, marker and fs UUID equal).

The lab service was down about 13 h, mostly waiting for fixes Z and AA. The state the playbook refused was safe: a
volume that is not mounted can be detached. The operator changed the guest to fit the playbook, by hand, outside OVLM's
audit. That is the wrong way round.

Question: **what audited exit should OVLM offer when a step's own pinned playbook refuses a state that a human has
verified safe?**

### Facts that shape the answer

| Fact | Source |
|---|---|
| Restore cannot be aborted or rolled back: it is the last way home. In the window, the exit from a refusal is rollback (restore). In restore, there is none. | renewal-workflow.md §2, §4; `validate_signal` |
| Only two restore steps run repository code: S2 (`quiesce.yml` on green) and S7 (`rollback_hooks.yml`, `start_service.yml`, `healthcheck.yml` on blue). S1, S3–S6, S8–S10 are OVLM code against OpenStack; a pinned playbook cannot refuse them. | renewal-workflow.md §4 |
| S3 stops green (Nova stop) **before** S4 detaches the volume. A detach never targets a running green. | renewal-workflow.md §4 |
| OVLM already has a fixed, OVLM-owned, read-only guest probe (`findmnt <mount_point>`, `systemctl is-active <units>`, `cloud-init status`, `systemctl is-system-running`). It runs no repository code. | SEC-R-36; `production.py` `probe()` |
| Guest output is untrusted (security-model.md §6.4). The playbook's own result is guest output too, so S2 today already lets guest output decide that S4 may detach. | security-model.md §6.4; `QuiesceGreen.verify` |
| S2 compares no marker in restore (restore carries data forward; W1's checksum from blue stands). | AC §3.4; renewal-workflow.md §4 |

## Options

### A. `accept-step` signal (approver, restore only, OVLM re-verifies the postcondition)

An approver who is not the run's requester accepts the parked step as done **without running its playbook**. Allowed
only for an allowlist of restore steps that change no cloud resource, and only when OVLM's own read-only probe, taken
just before, shows the step's postcondition.

Can OVLM verify S2's postcondition ("service stopped, volume unmounted on green") without the playbook? **Mostly yes,
with two additions:**

- `findmnt <mount_point>` only proves nothing is mounted at that path. The volume could be mounted elsewhere. The probe
  needs one more fixed command: `findmnt --source /dev/disk/by-id/virtio-<serial20>` (or `lsblk -no MOUNTPOINTS` on
  the by-id device), so "the data device is mounted nowhere" is checked. This changes the SEC-R-36 list (security review).
- `systemctl is-active a b` reports through its exit code in a way that does not mean "all active" or "none active"
  reliably across systemd versions. The accept check must read the per-unit output lines and require each unit to be
  `inactive` or `failed`.

What OVLM cannot verify: that no process holds the raw block device, and anything the guest lies about. Both limits
already apply to the playbook's result today.

### B. Pin bump for restore phases only

An approver authorizes the run to use a newer SHA for the remaining restore steps. The worker clones it inside the
window and runs the full B6 verification (SHA check, lint, waivers, collection pins).

### C. Guest-side override flag

OVLM passes a documented "operator attests state X" extra-var and the playbook may honour it. This is what
`ovlm.quiesce_allow_unmounted` already is. It only helps pins that already know the flag.

### D. Status quo plus a runbook

No OVLM change. Document the D-8b manual guest action (read-only checks, then change the guest so the old playbook
passes, then `retry-step`).

### E. Automatic skip in S2 from OVLM's probe

S2's probe adds a skip rule: volume on an ACTIVE green, data device mounted nowhere, units inactive → Done, no playbook.
No human involved.

## Analysis

| Criterion | A. accept-step | B. pin bump (restore) | C. guest flag | D. runbook | E. auto-skip |
|---|---|---|---|---|---|
| Data-loss risk | Low. Accept is refused unless OVLM sees the device mounted nowhere. S3 still stops green before S4 detaches. Residual: a lying guest, the same trust as the playbook result | Medium. New code, never run against this run's green, runs during the outage on both VMs (S2 green, S7 blue) | None added (playbook decides) | Medium. A human changes guest state by hand under pressure (D-8b mounted a data volume) | Low, same probe as A, but no human sees the refusal |
| Could it detach a mounted volume? | Only if the guest lies and the graceful stop in S3 fails and Nova hard-powers green off (power-cut class: journal recovers, in-flight writes lost). Same as today if the playbook lies | Same as today | Same as today | Yes, if the manual action is done wrong | As A |
| Separation of duties | Approver, never the requester; human session, step-up, TC, attestation | Approver; but approving a code diff during an outage is a weak control | None needed | None in OVLM | None |
| Auditability | Full: signal, refusal, probe, attestation, outcome in `audit_event`; step evidence says "not run" | Full, but the run's reproducibility evidence splits across two SHAs | Playbook result only | Lab notes only; OVLM sees a normal retry | Step evidence only; no human decision |
| Blast radius | One step of one run; allowlisted steps only | All remaining Ansible steps of the run, on both VMs | Repo-wide | One run, unbounded actions | Every run, every S2 |
| Complexity | Small: one signal kind, one table, one probe command, UI action | Large: clone in window, profile/plan hash change mid-run, waivers bound to a profile version, evidence of which SHA ran which step | Small per flag, repo work | None | Small |
| Would it have resolved D-8b? | **Yes**, once AA was diagnosed, without the manual mount | Yes, but only after the AA fix was merged in the repo (the hours of waiting stay) | **No** (old pin) | No (that is what happened) | Yes, silently |
| Fencing and leases | No running attempt (step parked). Close by compare-and-set on state and attempt; late results of the old attempt are refused by the fence | Clone inside the step attempt, fence-checked, as reprepare | Unchanged | Human acts outside fencing | Inside the step attempt |
| "No git contact in the window" | None | Needs a clone of **a different SHA** in the window. reprepare only allows the **same** SHA, with a digest that must equal B6's; B breaks that property | None | None | None |

Notes:

- **B** fixes the right thing in the wrong place. The pin is the approval boundary (T13). Bumping it mid-outage turns an
  approver into a code reviewer at 3 a.m. It also needs the fix to exist, which is where most of the 13 h went. It
  would need the plan hash, waivers and profile version to be re-bound inside a running run. Rejected for now.
- **C** is the normal way to teach the repository a new safe state, and it should keep being used (AA was fixed this
  way). It is not an exit for a run that already runs an old pin.
- **D** keeps the worst property of D-8b: the human edits the guest to satisfy code, and OVLM does not record why.
- **E** is tempting, but a playbook refusal is a signal. A silent skip hides it, and a guest that lies would pass with no
  human in the loop. E is A without the human; A keeps the human and the same checks.
- **A** does not let a human override OVLM's own checks. It lets OVLM's own read-only checks, confirmed by an approver,
  replace a repository playbook that refused. The human attests; OVLM verifies; neither alone is enough.

## Decision

**A, `accept-step`, for restore steps only, plus C as the normal repository fix and D only for steps outside the
allowlist.** B and E are rejected. The allowlist is **S2 only**, one approver, playbook refusals only (maintainer
decisions below).

### Guard rails

| Rule | Detail |
|---|---|
| Who | `approver` in the run's scope, interactive human session (API tokens and service principals: 403). Never the run's requester (run starter, plan creator), whatever `auth.allow_operator_approver` says (same rule as reprepare-automation) |
| Step-up | Password + TOTP, single use, 5 min, bound to action `run.accept_step` and the run |
| Typed confirmation | Name + last 6 characters of the ID of the VM the step targets: green for S2, blue for S7 |
| Attestation | Free text, 20 to 2,000 characters, required: what the human checked and why the refusal is wrong. Stored as data, displayed escaped |
| Phase | `restore` (effective phase) only. Never in build, window, retained or retire: there the exit is rollback or revert |
| Steps | Allowlist in code: **S2 `quiesce_green`**; S7 is **not** in the allowlist (maintainer decision Q2; may be revisited with lab evidence). Never W1, W6 (marker proof of the data), any step that moves the volume or the FIP (S4, S5, S8), any OpenStack step (S1, S3, S6, S10) |
| Parked reason | The step is in `needs_human` because **its playbook ran and refused** (phase result `needs_human` / `fatal`, or exhausted retries on the playbook's failure). Refused for `automation_checkout_lost` / `_unverifiable` (use reprepare-automation), `data_phase_interrupted` (maintainer decision Q3: retry-step is the exit), `approval_evidence_invalid`, ownership violations, lock or fence errors, `api_unreachable` |
| OVLM postcondition, S2 | Cloud (write client, read calls): green `ACTIVE`, no `task_state`; data volume `in-use` with exactly one attachment, on green. Guest (fixed read-only probe on green): reachable, data device (by-id, 20-char serial prefix) mounted nowhere, `<mount_point>` not a mount, every unit in `service_units` `inactive` or `failed` |
| Freshness | The worker runs the probe in `prepare_signal` (outside the transaction, as the `probe` signal does) and refuses if it is older than 60 s at commit or differs from the probe shown to the approver (the request carries its `probe_id`) |
| Once | At most one accept per (run, step). Unique row in `step_acceptance`. One pending accept per run |
| Effect | The step is closed `done` with `resolution = accepted`, the playbook is **not run**. Compare-and-set on `(state = needs_human, attempt)`; the fencing token of the parked attempt is retired, so a late outcome from it is discarded. The run continues with the next restore step (S3 after S2), which probes as usual |
| Not changed | The pin, the plan hash, approvals, locks, leases. No git contact. No guest mutation by OVLM. mark-resolved and retry-step keep their meaning |

### Evidence and audit rows

| Where | Content |
|---|---|
| `run_signal` (api) | kind `accept_step`, step key, attestation, TC, step-up id, probe id; audited `run.accept_step.requested` |
| `step_acceptance` (worker, append-only) | run, step key, attempt, approver, signal id, pinned SHA, parked reason and a sha256 of the refused phase result, probe JSON and time, attestation, outcome (`accepted` / `refused` + code) |
| `audit_event` (worker) | `run.accept_step.accepted` or `run.accept_step.refused` (refusal code), with run, step, attempt, approver, auth method, pinned SHA, probe summary |
| Step evidence | `accepted: {by, at, attestation, probe, playbook_not_run: true, refused_result_sha256}`; for S2 also `marker_comparison: "skipped: step accepted, playbook not run"` |
| Run summary and UI | Badge "S2 accepted by X at T, playbook not run" on the run, the step list and the final summary |
| Metric | `ovlm_step_accepted_total{step}`; sample alert rule: any increase notifies (it should be rare) |

### API and UI

- `POST /runs/{id}/actions/accept-step` `{step_id, probe_id, attestation, typed_confirmation, stepup_id}`. Approver,
  human session + step-up + TC. 403 `sod-violation` for a requester; 409 `not-applicable` when the step, phase or parked
  reason is outside the rules; 409 `postcondition-not-met` with the failing check when the probe disagrees.
- `available_actions[]` shows it only when the last probe meets the postcondition, with its concrete effect:
  "Accept S2 without running `quiesce.yml`. OVLM checked at T: volume `<id>` attached to green only, mounted nowhere on
  green, units inactive. Next: S3 stops green, S4 detaches the volume, S5 attaches it to blue." Otherwise it shows why
  not ("data device mounted at /srv/data on green").
- The form shows the refused playbook result (escaped, "reported by guest"), the fresh probe with its time, and a
  "Re-probe" button. Submitting with a stale probe is refused.

### Interaction with existing rules

- **mark-resolved** stays "re-probe and re-run". accept-step is a separate kind so its weaker semantics is never
  reached by accident and its role rule differs (approver only).
- **reprepare-automation** stays the exit for a lost checkout. In D-8 the order would have been: reprepare (Z), then
  accept-step (AA).
- **Fencing**: no attempt runs while the step is parked. The accept transaction is the engine's signal transaction; it
  does not take a lease. A worker that took over earlier and still holds an old token cannot commit afterwards.
- **REN-1 outage seal**: unchanged; accept-step only moves forward inside restore.
- **Downtime**: unchanged; the outage still ends at S9.

## Tests that would prove it

| # | Level | Test |
|---|---|---|
| T1 | unit (`validate_signal`) | Refused: operator; viewer; API token; approver who started the run; approver who created the plan; wrong or reused step-up; wrong TC; empty or short attestation; step W1, W6, S4, S5, S8; phase window; parked reason `automation_checkout_lost`; second accept on the same step; probe older than 60 s; probe id mismatch. Each with its refusal code audited |
| T2 | unit (postcondition) | S2 refused when: data device mounted at the mount point; mounted elsewhere (by-id source check); one unit `active`; volume has two attachments; volume on blue; green `SHUTOFF`; green has a `task_state`; guest unreachable |
| T3 | engine | Accept closes the parked step with compare-and-set; a late outcome of the old attempt (old fencing token) is discarded; the run moves to S3; locks unchanged |
| T4 | integration, **D-8 reproduction** | Worker killed after W5 (volume attached to green, never mounted). Automation fixture pinned at a commit whose `quiesce.yml` refuses the never-mounted state (the reference role before the AA fix). Operator rollback → S2 parks on the playbook refusal. `retry-step` → parks again. `mark-resolved` → parks again (current semantics kept). `accept-step` by an approver who is not the requester → S3–S10 run, run `rolled_back`, 0 locks. Asserts: no guest mount or other mutation outside the playbooks (the guest double records commands), volume never attached to two servers, marker on blue equal to W1's, audit rows `requested` + `accepted`, step evidence `playbook_not_run: true`, downtime ends at S9 |
| T5 | integration, negative | Same, but the worker died after W6 (green mounted the volume) and the pinned playbook refuses for another reason: accept-step refused `postcondition-not-met` (mounted), run stays parked |
| T6 | API/UI | Endpoint status codes; action hidden when the probe disagrees; badge on run page and summary; attestation rendered escaped |
| T7 | security acceptance | New criterion in security-model.md §10: "accept-step needs an approver who is not the requester, a step-up bound to `run.accept_step`, the TC and a fresh OVLM probe meeting the postcondition; never applies outside restore or to a step that moves the volume or the FIP" |
| T8 | lab (optional) | LAB-01 failure injection on Felcloud with the pre-AA pin; S2 accepted; converges without a manual guest action |

## Consequences

- A refusal by an old pinned playbook in restore no longer forces a human to change the guest by hand. The decision is
  made in OVLM, by an approver, on facts OVLM measured, and it is audited.
- The approved code is never replaced during a run. No git contact is added to the window.
- A step can now end `done` without running the repository code meant for it. Every view and the run summary must say
  so. Reviewers of a run must treat an accepted step as a weaker proof than a run step.
- The fixed guest command list grows by one read-only command (mount source check). Security review needed (SEC-R-36).
- Doc changes on implementation: renewal-workflow.md §2 (operator actions table) and §4, api-design.md (actions),
  security-model.md §3.1 (RBAC row) and §10 (criterion), data-model.md (`step_acceptance`), automation-contract.md §3.4
  (the S2 refusal has an OVLM exit).
- Roadmap P0-2 acceptance stays as written: ADR accepted by SRE and security reviewers; T4 converges without a manual
  guest action.

## Maintainer decisions (2026-11-09)

The questions as asked, then the answers:

1. **Choice**: accept A (accept-step) with C and D as complements, and reject B and E for now?
2. **S7**: include `recover_old_service` in the allowlist (S9's external probe still checks blue afterwards), or S2 only
   at first?
3. **Interrupted data phase**: may accept-step also apply to S2 parked on `data_phase_interrupted` (worker died during
   S2) when the probe meets the postcondition, or only to a playbook refusal?
4. **Two people**: is one approver (not the requester) enough, or must an operator attest and a different approver
   accept (two-person rule, as G3)? On a solo installation the second rule needs a second account.
5. **B later**: keep a pin bump for restore phases as a V1 option (with a re-bound plan hash and a G2-like approval),
   or close it?
6. **Window steps**: confirm that no window step (W1, W6, W7, W8) ever gets accept-step, since rollback is the exit
   there.
7. **Probe trust**: accept that a guest-reported "not mounted" (OVLM's own command) unblocks S3/S4, at the same trust
   level as the playbook result today?

Answers:

1. **A accepted**, with C (the normal repository fix) and D (runbook for steps outside the allowlist) as complements.
   B and E rejected.
2. **S2 only.** S7 stays out; it can be revisited with lab evidence.
3. **Playbook refusals only.** An S2 parked on `data_phase_interrupted` keeps retry-step as its exit.
4. **One approver** (not the requester), with step-up, typed confirmation and attestation; same level as
   reprepare-automation.
5. B is not pursued (not on the V1 list).
6. Confirmed: no window step ever gets accept-step; rollback is the exit there.
7. Accepted: OVLM's own read-only guest probe is trusted at the same level as a playbook result today.
