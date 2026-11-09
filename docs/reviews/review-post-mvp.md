# Independent security and SRE review — post-MVP code (#31–#49, roadmap P1-6)

| Field | Value |
|---|---|
| Reviewer | Independent reviewer (security and SRE lenses) |
| Date | 2026-11-09 |
| Scope | Code merged after the MVP lab work, PRs #31–#49: quiesce busy check and S7 `start_service` (#31), lab kit (#32), checkout cache and tree digest re-adoption (#34), `reprepare-automation` (#35, `renewal_0002`), restore quiesce flag AA (#37), marker field AB (#38), run_root checkout sweep (#43), downtime intervals (#44, `renewal_0003`), result contract and AD (#46), `accept-step` with `step_acceptance` and the approver `probe` (#47, `renewal_0004`, ADR-0008), heartbeat and fence fix (#48), W6 filesystem label (#49). Read per PR with `git diff <merge>^1 <merge>`. |
| Specification | `docs/security-model.md`, `docs/renewal-workflow.md`, `docs/automation-contract.md` (AC), `docs/architecture.md`, ADR-0008, the earlier reviews in `docs/reviews/` |
| Method | Code reading against the specification. The full unit suite run locally (`tests/unit`: 1497 passed, 4 skipped). The integration suites were **not** run here (no PostgreSQL usable in this environment); claims that depend on the database were checked by reading the SQL and the migrations. One probe script for PMR-3 (§4). `docs/team-log.md` was not read. |

## 1. Verdict

**Fit for a production pilot after PMR-1 is fixed; PMR-2 to PMR-6 can follow during the pilot.** No vetoed operation.

I found no path by which the new code lets anyone bypass separation of duties, reuse a step-up for another action
or run, accept a step outside S2 in restore, attach the data volume to two servers, or contact the git host inside
the window without an approver's authorization. accept-step is narrower than the ADR in one place only (an S2 parked
on anything but a failed `result.json` is refused), and the worker re-checks every condition the api checks, with a
probe of its own, under the run and step row locks.

The one finding I would fix before a pilot is an SRE one:

* **PMR-1**: the accept-step probe runs up to five SSH commands with a 60 s timeout each **inside the worker's
  main loop** (signal preparation). A green whose sshd accepts connections but whose commands hang (the kind of green
  that ends in an S2 refusal) stalls signal processing and step claims for every run on that worker for up to 5 min
  per probe request, and any operator or approver can queue several.

Everything else is defence in depth, binding precision or evidence quality. Findings by severity in §2.

## 2. Findings

Severity (as in the earlier reviews): **High** = defeats a stated control or leaves the service down with no OVLM
way out; **Medium** = a wrong state or a trap an operator can still leave; **Low** = defence in depth, labelling,
coverage; **Info** = judgement recorded, no change asked.

| # | Sev | Where | Failure or attack scenario | Required change |
|---|---|---|---|---|
| PMR-1 | **Medium** (SRE) | `src/ovlm/renewal/definition.py:735-758` (`prepare_signal`: `probe` and `accept_step` both call `accept_probe`), `:673-733` (`accept_probe` → `guest.probe`), `src/ovlm/renewal/production.py:986-1037` (five sequential SSH commands: `is-system-running`, `findmnt`, `is-active`, `lsblk`, `cloud-init status`), `:580` (`ssh_timeout = 60.0` per command), `src/ovlm/workflow/engine.py:1307-1353` (`process_signals` applies signals one by one, `prepare_signal` before each), `:1320-1353` (`_apply_signal`), `src/ovlm/worker/main.py:268-300` (signals, admission, scheduler and claims share one loop) | Before #47 a `probe` signal did cloud reads only. Now, for a run parked on an S2 refusal, every `probe` and every `accept_step` signal opens up to five SSH sessions to green, in the worker's main loop. Green answers TCP but a command hangs (systemd busy, a hung block device: plausible for the green that made S2 refuse): each command waits 60 s, so one probe takes up to 300 s; an unreachable green still costs the connect timeout per probe. During that time this worker processes no other signal (another run's `rollback` or `abort` inside its window waits) and claims no step (another run's next window or restore step waits; running steps keep their leases, they heartbeat on their own threads). The approver is told to press Re-probe, the page does not show progress, and probe requests are not de-duplicated (`send_signal` inserts one row per click), so a few clicks queue several such probes. #47 also lets approvers (not only operators) send `probe` in any run state (`definition.py:489-492`, `service.py:740-742`). No data effect. | (a) Give the accept probe a total deadline well under `accept.FRESH_SECONDS` (e.g. 20 s) and a per-command SSH timeout of a few seconds; better, run the fixed read-only commands in **one** SSH session (one quoted script of the same commands). (b) Take the probe out of the main loop: a bounded thread pool for `prepare_signal` network I/O, or a per-run probe job. (c) Collapse duplicate probe requests: the api refuses a `probe` while one of the same run is pending (409), as it does for `accept_step`. (d) Optionally limit the approver's `probe` to runs where accept-step applies. Add a test with a guest double whose commands sleep. |
| PMR-2 | Low | `src/ovlm/renewal/production.py:629-676` (`_prepared_for`, no fence parameter), `:677-736` (`_reprepare` consumes the authorization and clones, no `fence.check`), `:834-836` (`has_phase` reaches the same path), `src/ovlm/renewal/reprepare.py:129-150` (`take`: `WHERE run_id = :r AND consumed_at IS NULL`, ignores `step_id`, no expiry) | (a) **Not bound to the step.** An approver authorizes a re-clone for a step parked `automation_checkout_lost`, e.g. S2. The re-queued S2 then reaches Done from its probe alone (green already stopped or the volume no longer on green: `QuiesceGreen.probe` returns skip, `run_phase` is never called). The authorization stays pending, with no expiry. Hours later S7 finds the checkout gone (a second container restart) and `_reprepare` consumes the old authorization for S7: a git contact inside the window that no human authorized for that step. While it is pending, a new authorization is refused (`reprepare.pending`), so the approver cannot even re-decide. (b) **Not fenced.** An attempt that lost its lease (stuck in its probe past the lease) still calls `_prepared_for` → `take` → clone: it consumes the one-shot authorization and contacts the git host although it no longer owns the step; the attempt that took over then finds no authorization and parks again, and the approver must start over. `prepare()` (B6) does `fence.check("automation:prepare")`; the re-clone path does not. Same SHA and digest-checked, so no code-integrity effect. | Pass the attempt's fence (and step id) into `_prepared_for`; `fence.check("automation:reprepare")` before `take` and again before the clone; `take` only the row whose `step_id` is the current step, and treat an authorization as void once its step closed (or after a short validity, e.g. 1 h): mark it `outcome = 'expired'` in the step's success commit. Test: S2 skipped after an authorization → S7 with a lost checkout parks `automation_checkout_lost`. |
| PMR-3 | Low | `src/ovlm/automation/runner.py:777-823` (`_sweepable` / `sweep_checkout_cache`: any entry not in `keep`, older than `max_age`, is removed; no name filter, unlike `sweep_run_root_checkouts`), `src/ovlm/worker/main.py:234-262` (`keep` = non-terminal run ids only), `src/ovlm/config/settings.py:337-343` (only "absolute, outside `run_root`"), `runner.py:201-222` (`_cache_root` also chmods the directory to 0700) | An operator writing the real-cloud install (P1-7) sets `automation.checkout_cache = /var/lib/ovlm` instead of `/var/lib/ovlm/checkouts`, next to other worker state (for example the interim `renewal.credentials_dir`). Within the first hour (start-up sweep, then hourly) every subdirectory there that is not a run id and is older than the orphan max age is deleted with `rmtree`, and the directory is made 0700. Reproduced with a probe script (§4): a `credentials/` directory is removed together with a stale run entry. | Apply the same rule as on `run_root`: only entries whose name is a canonical run UUID are candidates (the worker already computes `_as_uuid`), never anything else. Refuse at start-up a cache directory that contains entries other than run UUIDs (or require a marker file OVLM writes on first use), and reject in the settings validator a cache path that equals or contains `credentials_dir`, `kek.private_key_file`'s directory or `run_root`. |
| PMR-4 | Low (SRE, evidence) | `src/ovlm/renewal/definition.py:778-782` (the shown probe's `at` is the commit time of the `probe` signal, not when the probe was taken), `:642-646` and `src/ovlm/renewal/service.py:846-848` (60 s freshness checked at api submit and again at worker commit), `src/ovlm/ui/templates/renewals/action.html:39-44` (Re-probe posts a separate form; success redirects to the run page, `routes_renewal.py:859`) | (a) `prepare_signal` for `probe` does the cloud reads and then up to five SSH calls (PMR-1); `at` is stamped afterwards in `on_signal`. The probe the approver reads can be older than its `at` by the probe's duration, so "taken at T, at most 60 s old" is not what the evidence says. The worker's own fresh probe (elapsed measured from its start, facts compared) is what protects the decision, so this is evidence precision, not a bypass. (b) The 60 s budget for the shown probe is spent between the worker's commit of the probe and the worker's validation of the accept: worker tick, page reload, password + TOTP + typed confirmation + a 20-character attestation, api submit, then the worker's next tick and its own probe (seconds on a real cloud) before the age is read again. Re-probe leaves the action page, so the attestation typed so far is lost. At 3 a.m. this gives repeated `probe-stale` refusals, each spending a step-up. | Stamp `at` with the DB time read **before** the probe starts (as `t0` does for the worker's own probe) and store the probe duration. Judge the shown probe's freshness once, at api submit (e.g. 120 s), and let the worker's commit rest on its own probe (≤ 60 s, facts equal to the shown one), which is the stronger check. Make Re-probe return to the action page with the attestation kept (or poll the probe in place). |
| PMR-5 | Low (SRE) | `src/ovlm/renewal/steps_window.py:240-251` (W1 `verify`: an ok quiesce without `facts.marker_sha256` parks `quiesce_no_marker`) | AB is correct as a data-safety rule, but it is detected only **after** W1 stopped the units and unmounted the volume on blue: the outage has started. An automation repository that never reports `marker_sha256` (an older role using `marker_checksum`, defect AD) costs a full outage plus a restore on every run until it is fixed, and nothing before the window says so. | Detect it before G2: e.g. B6 lint rule "the quiesce phase sets `marker_sha256` in its result facts" (static check of the role, or a result-contract fixture run in check mode), or require the profile onboarding check to have seen a quiesce result with the field. Keep the W1 refusal as the backstop. |
| PMR-6 | Low (forensics, defence in depth) | `src/ovlm/automation/runner.py:164-190` and `:228-256` (`prepare_automation` → `_store_in_cache` removes the existing cache entry before writing the new clone), `src/ovlm/renewal/production.py:677-732` (`_reprepare` runs that path after `CheckoutUnverifiable`), `migrations/versions/renewal_0002_reprepare_automation.py` (no trigger on `automation_reprepare`) | (a) A cached checkout whose tree digest differs from B6's record is the one sign that something wrote to the worker-only cache (or the disk corrupted it). The approver's `reprepare-automation` then re-clones, and `_store_in_cache` deletes the mismatching copy before anyone looked at it; the refusal evidence holds only the message. (b) `automation_reprepare` relies on grants alone: the worker holds `UPDATE (consumed_at, outcome)` and could reset `consumed_at` to NULL, re-arming a one-shot authorization. `run_downtime` and `step_acceptance` got triggers for the same property; this table did not. | (a) On a digest mismatch, move the copy aside (`<cache>/<run>/_checkout.mismatch-<time>`, kept until the run is terminal) and record both digests in the step's refusal evidence. (b) Add a trigger that allows `consumed_at` and `outcome` to go from NULL to a value once each and refuses every other UPDATE, DELETE and TRUNCATE. |
| PMR-7 | Info | `src/ovlm/renewal/production.py:878-885` (`reported` = the result's classification for any valid failed `result.json`), `src/ovlm/renewal/steps_build.py:425-426`, `src/ovlm/renewal/accept.py:88-95`, `ansible/README.md` (the reference roles write `result.json` in `always`, with the phase default `needs_human` and `facts.error_kind = automation_error` for an unplanned failure) | accept-step's gate "the playbook ran and **refused**" accepts any failed `result.json`, including the rescue path of an unplanned error (a task crash, the guest dropping the SSH connection mid-play). ADR-0008 Q3 meant planned refusals. Safety does not depend on it: OVLM's own probe must still show the postcondition. But the UI calls it "the playbook refused" and the approver may not see that the play was cut short. | Record `facts.error_kind` (and the failing task name if the result carries one) in `step_acceptance` and show it on the accept form; consider excluding `error_kind = automation_error` from the gate after lab evidence. |
| PMR-8 | Info (accepted residual, inherited) | `src/ovlm/renewal/definition.py:1077-1105` (`_check_confirmation`) | REN-10 applies to the two new kinds: the worker accepts any consumed `run.accept_step` / `run.reprepare_automation` step-up of the actor on this run within its validity, not one bound to this signal. Only a compromised api could replay one (the api's `consume_stepup` is single-use). | As REN-10: record `consumed_by` (signal id) on the step-up and check it in the worker. |
| PMR-9 | Info | `src/ovlm/renewal/production.py:1019-1025` (`lsblk -n -o MOUNTPOINT -- /dev/disk/by-id/virtio-<20>`), ADR-0008 "What OVLM cannot verify" | Two residuals of the S2 postcondition worth writing down next to the ADR's: (a) `lsblk` and `findmnt` see the mount namespace of the probe's SSH session; a filesystem mounted only inside a unit's private namespace, or lazily unmounted (`umount -l`) while a process still writes through it, reads "mounted nowhere". (b) Between the worker's probe and S3's Nova stop (seconds to a minute), something on green may mount the device again; S3's graceful stop then unmounts it cleanly, a hard power-off after Nova's shutdown timeout loses in-flight writes. Both are the "guest lies / power-cut" class the ADR accepted. | Add both to ADR-0008's consequences and security-model.md §6.4. Later, optionally extend the fixed read-only list with a check of `/sys/block/<dev>/holders` (device-mapper or other holders of the disk). No change required for the pilot. |
| PMR-10 | Info | `migrations/versions/renewal_0004_step_acceptance.py:101-109`, `migrations/versions/renewal_0003_run_downtime.py:85-87` | Downgrading `renewal_0004` drops `step_acceptance` and `workflow_step.resolution` and deletes every `accept_step` signal; downgrading `renewal_0003` drops every downtime interval. After a downgrade an accepted S2 looks like a step that ran (only its JSON evidence still says otherwise) and restore intervals are gone. architecture.md §9 already says the supported path is "restore backup", so this matters only if someone downgrades a production database. | Make both downgrades refuse when the tables hold rows (or export them first), consistent with the append-only intent. |

### 2.1 Answers to the questions of the brief

**Authorization and separation of duties.** accept-step: api `_check_accept` (`service.py:794-855`) and worker
`_accept_refusal` (`definition.py:589-671`) both require the approver role in the run's scope, refuse the run starter
and the plan creator whatever `auth.allow_operator_approver` says, require a human session with a consumed step-up
bound to `run.accept_step` and the run, and the typed confirmation of **green** (`tc_target`, `plans.py:512`). The
worker re-reads the role at its own time, the parked step's id and attempt from the payload against the locked step
row, the probe id against `current_truth`, and refuses with a `step_acceptance` row and an audit row in the same
transaction. `reprepare-automation` has the same role and requester rules on both sides. Role widening: approvers may
now send `probe` (read-only, refreshes the truth panel; the self-resolution rules run only for the system probe,
`definition.py:784-785`) and nothing else new; `retry-step`, `rollback`, `abort` still need the operator role.

**TOCTOU between probe and accept.** The worker's own probe is taken in `prepare_signal` outside the transaction and
must be at most 60 s old (monotonic, from its start) and equal in facts to the probe the approver saw; the step row
is locked `FOR UPDATE` in the signal transaction and the close is a compare-and-set on `(needs_human, attempt)` that
retires the fencing token. The remaining window (probe → S3 stop) is PMR-9 (b). PMR-4 is about evidence precision.

**Fencing and leases.** #48: `_Heartbeater.stop` closes the fence before joining both threads, and a beat whose
UPDATE was in flight when the fence closed rolls back (`_LateBeat`); the outcome commit happens before `stop`, so the
close cannot refuse a legitimate commit. A beat that passes the `fence.revoked` check and commits a moment after
`close` can still extend an ended attempt's lease once; that only delays a takeover (fencing tokens still refuse any
late write), so I record it here rather than as a finding. accept-step takes no lease. The re-clone path is not
fenced (PMR-2).

**Crash safety of the new commits.** W1 writes `downtime_started_at` and opens the window interval in one fenced
transaction; S2 opens the restore interval in a fenced transaction before its play (re-entry is a no-op: `INSERT ...
WHERE NOT EXISTS` plus the partial unique index); W10 and S9 close inside their success commits (`UPDATE ... WHERE
ended_at IS NULL`). The accept row, its audit row, the step close and the S3 transition commit together with the
signal consumption. Sweeps are idempotent and never fatal. The reprepare authorization is consumed before the clone
(a crash between them wastes it, documented); PMR-2 covers its binding.

**Checkout cache, digest and sweep.** No path traversal: run ids pass `_safe_component` (runner) or a canonical
UUID check (worker) before any path is built. `tree_digest` uses `lstat`, records symlinks as their target text and
opens files with `O_NOFOLLOW`; it refuses devices, FIFOs and sockets. Adoption copies the cache into `run_root`
first and digests **the copy that will be used**, then `check_tree` (no escaping symlinks) and the B6 lint, pins and
waivers run again; the expected digest comes from B6's step evidence in the database, not from the cache. The cache
root must be a real directory (not a symlink) owned by the worker's euid, mode forced to 0700. The sweep never
removes a non-terminal run's entries (keep set read from the database in the same pass; unknown entries only after
the orphan max age; per-step sweep only when the database reads the run terminal); `_sweepable` skips symlinked
entries, `sweep_run_root_checkouts` removes only `_checkout*` parts and leaves step run directories to the orphan
sweeper. `remove_tree` uses `os.walk` without following links. The one gap is PMR-3 (entries that are not run ids).

**SQL grants and triggers.** `step_acceptance`: worker `SELECT, INSERT`, api `SELECT`, triggers refuse UPDATE,
DELETE, TRUNCATE, partial unique index "one accepted row per (run, step key)", check constraints on outcome, refusal
code and accepted-row completeness. `run_downtime`: worker may only close an open interval once (trigger), no DELETE,
one open interval per run. `workflow_step.resolution` is covered by the existing table-level worker UPDATE and a
check (`accepted` only with `succeeded`). `automation_reprepare`: grants only (PMR-6 b). The `run_signal` kind check is
widened in both migrations; the api's insert guard still forbids consumed rows.

**Audit completeness.** accept-step: `run.accept_step.requested` (api, same transaction as the signal),
`run.accept_step.refused` for every api refusal (`record_independent`, survives the rollback) and every worker
refusal, `run.accept_step.accepted`; a wrong step-up is audited by `consume_stepup` as `auth.stepup.refused` with
action `run.accept_step`. reprepare: `authorized`, `used` / `refused`. Downtime: `renewal.downtime.started` /
`.ended` per interval. The only unaudited moment is a reprepare authorization consumed by `take` whose clone never
finished (crash): the row shows `consumed_at` with no `outcome`.

**Guest probe command.** The volume id is checked against `^[0-9A-Za-z-]{20,64}$`, mount points and unit names
against the existing patterns, and the command is passed as an argv that `SshClient.run` quotes with `shlex.quote`;
`--` precedes every operand. No injection path. `lsblk` failing (device absent, e.g. a non-virtio bus) reads as
"unknown", never "mounted nowhere". Unit states are read per line; a missing line is `unknown`, not stopped.

**UI escaping.** The attestation, the refused result, the probe details and the guest-reported mount points are
rendered through autoescaped Jinja templates (`Jinja2Templates`, no `| safe` or `Markup` in `src/ovlm/ui`); the typed
confirmation target is shown split, never echoed.

**Metrics.** `ovlm_step_accepted_total{step}` can only carry allowlisted step keys (one value today);
`ovlm_renewal_downtime_seconds{kind}` has two values. No user-supplied label. The counter is incremented in
`_accept` before the compare-and-set; since the step row is locked `FOR UPDATE` in the signal transaction the CAS
cannot fail in practice, so no over-count.

**Migrations.** `renewal_0003`'s backfill copies only consistent first intervals and names the closing step from
the run's history; restore intervals before the migration are not invented (documented). An in-flight run in the
window at upgrade time gets an open window row that W10 or S9 closes. Downgrades: PMR-10.

## 3. Checked and found sound

| Area | What I checked |
|---|---|
| AA (#37) | `quiesce_allow_unmounted` is passed only by S2 and refused by `build_extravars` for any phase other than `quiesce` on role `new`; the role still stops units first and only skips the unmount when the path is not a mount and no earlier record exists; W1 keeps refusing that state. S2's Done for "never mounted" records `marker_comparison: skipped` and no marker. |
| AB / AD (#38, #46) | W1 refuses an ok quiesce without `marker_sha256` when the run has a data volume; W6 and W8 compare against W1's value read from OVLM's own evidence (with the raw-fact fallback for runs that passed W1 earlier) and record `marker_comparison`; another spelling is not read as a marker. |
| W6 label (#49) | The profile's one identity (`fs_uuid` or `label`) is compared; a missing fact is a problem, never a pass; a plan with neither is refused. The reference role reports `fs_label`. |
| Busy check (#31) | `fuser -m` without `-v` (rc 0 = a process holds the mount); the message carries PIDs only. S7 runs `start_service` (idempotent, refuses an unmounted data path) before the healthcheck for stateful profiles; lease sized for it. |
| Checkout re-adoption (#34) | On `run_root`: digest compared when B6 recorded one; in the cache: adopted only with a recorded digest equal to the copy's; neither: re-clone only outside the outage (`_in_outage` also covers phase `restore`, so a revert after the cutover is inside it). |
| reprepare (#35) | Approver, never the requester, step-up `run.reprepare_automation`, TC, only for `automation_checkout_lost` / `_unverifiable` (and the legacy messages); one pending per run (unique index); consumed before the clone; the re-clone must reproduce B6's digest or it is discarded and the step parks `automation_reprepare_digest_mismatch`. |
| accept-step scope (#47) | S2 only, effective phase `restore` only, parked `quiesce_green_failed` with a playbook classification of `needs_human` or `fatal`; `data_phase_interrupted`, lost checkout, ownership, lock and API reasons are refused; once per (run, step) by index and by check; the transition is `next()` for S2 (restore interval opened, S3 next), and the step evidence and every view say "playbook not run". |
| Engine (#47, #48) | `accept_step` never reaches the generic strategy path (an `AcceptStep` there is "unsupported"); `reprepare_automation` re-queues exactly as retry-step after the strategy recorded its row; fence `close` clears callbacks without firing them, after the attempt's actions ended. |
| Downtime (#44) | One open interval per run; REN-1 seal, budget and retention still read the first-interval columns; UI and API never show "0s" for a measured value; terminal runs with an open row show "end not measured". |
| Lab kit (#32) | Lab host only; no secret is printed; `ssh -n` and the key file option. |

## 4. Reproduction

PMR-3, probe script (kept out of the tree):

```python
# python -I probe_sweep.py <repo>/src
import os, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from ovlm.automation.runner import sweep_checkout_cache

d = Path(tempfile.mkdtemp())
(d / "credentials").mkdir(); (d / "credentials" / "secret.json").write_text("x")
(d / "3f0c2b1e-0000-4000-8000-000000000001").mkdir()
old = time.time() - 10 * 3600
for p in d.iterdir():
    os.utime(p, (old, old))
print(sweep_checkout_cache(d, 3600, keep=set()))
```

Output: both `3f0c2b1e-…` and `credentials` are removed. The worker passes `keep` = the non-terminal run ids, so a
non-UUID directory is never in it.

PMR-1, by reading: `RunnerGuestPort.probe` issues its commands one after another through `_ssh(..., timeout =
self.ssh_timeout)` (60 s default, `production.py:580`, not overridden by `production_deps` at `:1185-1189`), and
`WorkflowEngine._apply_signal` calls `prepare_signal` synchronously from `process_signals`, which `Worker._workflow_tick`
calls before `claim`.

PMR-2, by reading: `QuiesceGreen.probe` (`steps_after.py:296-308`) returns `skip` from cloud reads alone, so a
re-queued S2 can finish without calling `run_phase` and without consuming the authorization; `reprepare.take` selects by
`run_id` only.
