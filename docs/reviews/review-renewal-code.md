# Independent review — renewal strategy `bluegreen_fip_v1` (code)

| Field | Value |
|---|---|
| Reviewer | Agent 7 — independent reviewer (SRE veto on lifecycle operations) with the security lens |
| Date | 2026-11-04 |
| Scope | `src/ovlm/renewal/` (B1–B9, G1–G3, W1–W10, S1–S10, X1, Discarding, closed table, self-resolution, production adapters, W4 snapshot path), `src/ovlm/api/routes_renewal.py`, the snapshot additions in `src/ovlm/openstack/` (`write.py`, `sdk_write.py`, `allowlist.py`). Engine, auth, RBAC, write client and runner were reviewed earlier; only their use by the renewal code is judged here. |
| Specification | `docs/renewal-workflow.md`, ADR-0004 (D-1 = B), ADR-0005, ADR-0006, `docs/security-model.md` §3–§7 |
| Method | Code reading against the specification; the renewal test suites on a local PostgreSQL 16; four reviewer probe tests written to confirm or refute suspected findings (kept out of the tree, reproduced in §4). `docs/team-log.md` was not read. |

## 1. Verdict

**Accept with required changes.** No vetoed operation.

I found no path by which the code attaches the data volume to two servers, starts blue while green holds the data
without a human choosing it, formats a volume, deletes a volume, a floating IP or a snapshot, runs a destructive
call twice without a probe in between, or restores automatically after W7–W10 without a W4 snapshot (D-1 = B).
The ownership guard, the write allowlist, the ledger and the closed table are used as the design says, and the
engine crash points in the window and in the restore are tested.

Two findings must be fixed before the lab campaign, because each one defeats a control the design relies on:

* **REN-1** — a run whose outage has started can be sent back to the build phase (G2 expired while W1 was parked),
  where the only offered operator actions delete green and never restore blue. Confirmed by a probe test.
* **REN-2** — after a completed host-key rotation, a re-run of B5 falls back to the bootstrap host key, so whoever
  holds the user-data copy of that key and the network position is re-pinned as green. Confirmed by a probe test.

Neither is a data-loss path on its own (REN-1 keeps the volume on blue; REN-2 never hands over the volume, which is
attached by Nova to the real green and verified by W6), which is why this is not a rejection. Everything else is
listed by severity in §2.

## 2. Findings

Severity: **High** = defeats a stated control or leaves the service down with no OVLM way out; **Medium** = a
wrong state or a trap an operator can still leave; **Low** = defence in depth, labelling, coverage; **Info** =
judgement recorded, no change asked.

| # | Sev | Where | Failure or attack scenario | Required change |
|---|---|---|---|---|
| REN-1 | **High** | `src/ovlm/renewal/steps_window.py:115-146` (W1 probe re-runs every claim check), `:160-175` (claim transaction requires `expires_at > now()`), `src/ovlm/renewal/definition.py:300-302` (`w1_claim_refused` → back to `await_cutover`/`verify_green_ready`, phase `build`), `:496-497` (rollback in phase `build` → `discard_green`), `src/ovlm/renewal/service.py:464-478` (build-phase actions) | W1 claims (`downtime_started_at` written, blue quiesced: units stopped, volume unmounted), the quiesce playbook fails → `needs_human(quiesce_old_failed)` in phase `window` (correct, tested). G2 expires while the run waits for a human (4 h default validity; a 3 a.m. page). The operator sends `retry-step` (TC): W1's probe re-runs the claim checks, G2 is expired → `w1_claim_refused` → the run transitions to `await_cutover`, **phase `build`**, with `downtime_started_at` set and no `downtime_ended_at`. The run page now offers *rollback: delete green; blue keeps serving* and *abort*. `rollback` runs `discard_green` and finishes `rolled_back`: green deleted, **blue still quiesced, service down, no OVLM action left** (the restore S6 boot-cycle is never offered; `revert` is refused outside retention). The same path is taken for a stale B9 (`back_to = verify_green_ready`, less harmful: W1 is re-claimed afterwards) and for a Keystone/credential expiry refusal. Reproduced: §4, probe 1. | Once `downtime_started_at` is set, W1 is a re-run inside the outage: (a) in `QuiesceOld.probe` and in the claim transaction skip the checks that can refuse (G2 expiry, policy window, B9 age, credential/token horizon) and only re-validate G2 evidence integrity (section 2.2: "an approval never expires mid-outage"); (b) in `on_failure`, a `w1_claim_refused` with `downtime_started_at` set must park `needs_human` in phase `window`, never transition to `build`; (c) in `on_signal`/`on_abort`, a `rollback`/`abort` while `downtime_started_at IS NOT NULL AND downtime_ended_at IS NULL` must go through `_restore`, whatever `run.phase` says; (d) `available_actions` must describe the restore in that state. Add the probe-1 scenario as a test (expected end state: `await_discard` with blue ACTIVE, mounted, units active). |
| REN-2 | **High** (security) | `src/ovlm/renewal/production.py:650-669` (`pin_host_key`: when `accept` is non-empty and the pinned connection fails, the `injected` branch is entered whenever `bootstrap_public` is set) | B5 rotated and pinned green's new keys (`ledger_detail` records `pinned` only after the verify succeeded, so a recorded pin means the real green no longer accepts the bootstrap key). A later B5 re-run (retry-step after a network blip, a takeover during B5) finds the pinned connection failing (`exit 255`, e.g. "host key mismatch" because something else now answers at green's fixed IP). Because `bootstrap_public` is still in the ledger detail, the code connects with the **bootstrap** key, and if the answering host presents it, runs `ROTATE_HOST_KEYS` there and **pins the impostor's keys**, overwriting the recorded pin. ADR-0006 rule "interrupted rotation: accept only what the evidence pinned; anything else → needs_human" is not implemented for this branch. The attacker needs the user-data copy of the bootstrap private key (cloud admin, or the guest itself) and a network position; the data volume is still never handed over (Nova attaches it to the real green; W6 checks the W1 marker checksum). What they do receive: the `configure` run, the project's vault-decrypted secrets templated by it, and the chance to answer W7/W8/W10 as "green". Reproduced: §4, probe 2. `console` and `tofu` re-runs are not affected (`bootstrap_public is None` returns the failure). | In `pin_host_key`: when `accept` is non-empty, never enter the bootstrap branch; return `HostKeyResult(False, "host key unverifiable")` (or the ssh reason) so B5 parks `host_key_unverifiable`. Additionally clear `bootstrap_public` from the ledger detail (or ignore it) once `pinned` is recorded. Add probe 2 as a unit test (expected: `not res.ok`, `ROTATE_HOST_KEYS` never sent). |
| REN-3 | Low | `src/ovlm/renewal/definition.py:322` (`reason = ... or "api_unreachable"` when a deadline failure carries no `truth`), `src/ovlm/workflow/engine.py:836-853` (`_normalise` builds the deadline `Fail` from the step's last `Wait` evidence) | A window step's deadline passes right after `act` (its `verify` returns `Wait(poll_after=None)` with no evidence) or before `act` ("deadline passed before acting; nothing was sent"). The failure carries no fresh probe, so `_window_failure` labels it `api_unreachable` although the API answered. The run then belongs to the re-probe job (`reprobe.py`) and the section 5.1 rules: for W2 this ends in rule 2 → automatic restore (the same outcome the closed table would give, but reached through `resume.auto` with the wrong story), and the 3 a.m. panel says "API unreachable" when it was not. Reproduced: §4, probe 3. | Label a deadline failure without `truth` as `deadline_exceeded` (park, no self-resolution) unless the step's own error was a connectivity class; or make `WindowStep` steps attach `safe_truth` to every `Wait` they return after `act` (they already do for the probe-side waits). Later; no data effect. |
| REN-4 | Medium | `src/ovlm/renewal/definition.py:439-440` (`revert` allowed in phase `retire`), `src/ovlm/renewal/steps_after.py:202-219` (X1 sends unlock + delete, then waits for the 404) | `revert` is accepted while X1 is `waiting` for blue's 404 after the delete was sent, or `needs_human` after the delete landed. `_restore` starts S1 on a deleted blue: `get_server` 404 → `RestoreStep.classify` → `needs_human`, phase `restore`, with no terminal path (green is the current VM, nothing to restore to; `discard` is refused outside `await_discard`). The run can never finish. No data effect. | Refuse `revert` once X1 has persisted an intent (`workflow_step.retire_old` has an intent / blue answers 404): "revert impossible: the old VM was deleted". Later. |
| REN-5 | Low | `src/ovlm/renewal/definition.py:448-455` (`mark_resolved` needs `approver` when the **following** step is destructive) | The engine re-queues the **current** step on `mark_resolved` (`engine.py:1421-1454`), so the next destructive call after a `mark-resolved` is the current step's own `act` (W2 stop, S6 start/stop, X1 delete, Discarding delete), not the following step's. The role rule therefore looks one step too far. All of these acts are inside the approved G2/G3 scope and `mark_resolved` always needs TC + step-up, so this is a role nuance, not an authority gap. | Require `approver` when the current step is destructive **or** the following one is. Later. |
| REN-6 | Low | `src/ovlm/renewal/steps_after.py:443-463` (S6 `boot_old` decides from blue's power state and the guest probe only) | S6 starts blue without probing that the data volume is attached to blue (or the profile is stateless). In the sequence this is guaranteed by S5 (`Done` only with `in-use` on blue), and `mark_resolved` re-queues S5 rather than skipping it, so I could not reach S6 with the volume elsewhere through OVLM; a human detaching the volume by hand between S5 and S6 would. Blue would then boot without data (`nofail`), S7 fails, no second writer. | Add the precondition to S6's probe (volume `in-use` on blue, or stateless) → `needs_human("volume not on blue")`. Cheap defence in depth; later. |
| REN-7 | Low | `src/ovlm/renewal/steps_after.py:612-624` (Discarding with a ledger row `intended` and no `openstack_id` answers "absent") | A worker dies between the Nova create and `ledger_present`; the operator rolls back from `BuildFailed`/B3 before any retry; `discard_green` sees no id, finishes `rolled_back`, and the run-tagged server stays in the project. It is caught by the orphan report (report-only), never adopted by another run (adoption needs this run's ledger row), so no safety effect; it is a leak the run could have found itself. | In `DiscardGreen.probe`, when the ledger has no id, run `find_run_server(intended_name)` and park `needs_human("green exists but is not recorded")` if one is found. Later. |
| REN-8 | Medium (interim) | `src/ovlm/renewal/production.py:129-168` (`FileCredentialSource`), `src/ovlm/config/settings.py:175-186` (`renewal.credentials_dir`) | Judgement on the interim option while the credential store is built. What it is: plaintext JSON with the write application-credential secret, plus the guest `ovlm` private key, as files owned by the worker uid, mode checked (`0o077` bits refused) on every read, UUID-only file names, never cached, never logged, `None` by default (admission then rejects every renewal: fail-closed, tested). What it is not: encrypted at rest; audited per read; role-gated (the api process accepts the setting too, though nothing in the api reads it); protected from root in the container or from a host backup/image; expiry-warned (30/7 days) outside the B1/W1 checks. The `cacert` path from the JSON is trusted as given. The directory check demands 0700 ownership by the worker uid, which a default Docker secret mount (root, 0444) does not satisfy, so the lab will use a tmpfs mount. Note that the test for the permission check is skipped when CI runs as root. | **Acceptable for the lab only**, under these conditions: a dedicated lab project; application credential `unrestricted=false`, `member` only, `expires_at` ≤ 30 days, created for the lab and deleted after it; files on a tmpfs or secret mount of the worker container only, never in the image, the repo, or a host directory that is backed up; `renewal.credentials_dir` refused (validator) when `process_role != worker`; a startup log line stating that the interim source is active. Not a production default. The credential store (security-model.md §5.1) remains required before any production use. |
| REN-9 | Info (accepted) | `src/ovlm/renewal/production.py:619-624` (`sudo: ALL=(ALL) NOPASSWD:ALL` for the cloud user), `:442-447` (`ROTATE_HOST_KEYS` via `sudo -n`) | The `ovlm` guest key is root on every green (and, by the registration contract, on blue). Needed by Ansible `become` and by the B5 rotation. Security-model.md §1.1 already states this asset's impact; the key is per project, in memory, 0600 for one call. The rotation command is fixed, quoted, and behind a fence check. | No change for MVP. Later hardening (image-level): a sudoers rule limited to the rotation command and the automation's `become` needs; a dedicated rotation helper on the image. |
| REN-10 | Low | `src/ovlm/renewal/definition.py:685-713` (`_check_confirmation`) | The worker re-validates an operator signal's step-up (user, action `run.<kind>`, target = run, interactive, consumed within validity) but not that **this** signal consumed it: a second `run_signal` carrying the same consumed `stepup_id` passes. Only the api writes signals and its `consume_stepup` is single-use, so this is the compromised-api residual that section 3.1 already accepts. | Record `consumed_by` (signal id) on the step-up when the api sends the signal and check it in the worker. Later. |
| REN-11 | Info | `src/ovlm/renewal/steps_after.py:136-191` (X1 probe runs the fresh green healthcheck playbook inside `probe`), `src/ovlm/renewal/config.py:105` (`retire.health_max_age` required, never read) | X1 is stricter than the design (always a fresh healthcheck, never one younger than `max_age`), which is fine. The step deadline is `timeouts.server_delete`, which may be shorter than the healthcheck run; a deadline during the probe parks `deadline_exceeded` with nothing sent. Operational only. | Either read `retire.health_max_age` or drop it from the required keys; size the X1 deadline from the healthcheck timeout. Later. |
| REN-12 | Info | `src/ovlm/renewal/evidence.py:80-97` (`_voided_by_run`), `src/ovlm/renewal/service.py` | A revert voids G3 by derivation (restore steps after `decided_at`); the `approval` row stays `approved` and the API/UI show it so. The worker is right (it has no `UPDATE` on `approval`), and X1 can never run after a restore (`unlock_old` present → mismatch). | Have the api mark `void_reason` when it records the `revert` signal, for the audit reader. Later. |

### 2.1 Answers to the five questions

**1. Data safety.** Two-server attach: W5/S5 act only when the volume is `available` with no attachment; Nova refuses
a second attach anyway (ADR-0004, LO), and the guard's `attach_volume` is check-then-act. Blue started on green's
data: S6 runs only after S5 proved `in-use` on blue (REN-6 adds the belt); no automatic restore after W7–W10
without a W4 snapshot (`closed_table.d1`, tested for W7, W8, W10, budget before W7, and `auto_restore_disabled`);
the operator rollback in that state is TC-gated and its consequence text names the snapshot or its absence. Twice:
W3 detach `detach_try ≤ 2`, W5/S5 attach re-sent once and only on a takeover, W9 one PUT and repeat-safe; every
window/restore step starts at `probe`; the 16 OpenStack crash points assert "each mutating call sent once". mkfs:
`first_use` is hard-wired `False` in `_dv` (W1/W6), in `QuiesceGreen.act` (S2), and again in `RunnerGuestPort.run_phase`. Deletions: the
allowlist has no `DELETE` for volumes, snapshots or floating IPs and no `POST /volumes`; `update_floating_ip` refuses
an empty port (so a missing green port cannot disassociate the FIP); the guard's `check_delete` re-reads attachments
and refuses any registered volume or any `delete_on_termination` that is not exactly `False`. API outage: every
window/restore failure carries `safe_truth`; `api_reachable=False` always parks (`closed_table.decide` first
branch), and the re-probe job only inserts a system `probe` signal. Operator signals: TC + consumed step-up
re-validated by the worker, `rollback`/`abort` refused in restore, `revert` only after cutover (REN-4). Takeovers:
data phases W1/W6/S2 park with the read-only guest probe attached (tested for W1, W6; S2 by reading).

**2. Restore convergence and `needs_human` states.** S1–S10 each probe and skip; tested from W2 (quiesced-but-ACTIVE,
boot-cycle), W3, W4, W5, W7/W10-with-snapshot, budget, evidence-invalid, data-phase crashes, operator rollback,
revert, and a crash after the act of six restore steps. A restore failure is `needs_human` and never re-enters the
window (tested). Every `needs_human` keeps all locks and the current truth; the API's `available_actions` names the
effect of each action, and the W7–W10 text states the data consequence. The one state that is **not** safe to sit in
is REN-1's (run back in `build` with the outage open): its actions are wrong and one of them deletes the only
alternative to blue. REN-4 is a dead end but harmless.

**3. Approvals.** Bound to the recomputed plan hash (profile version, spec hash, automation SHA, target ids, policy
binding): the api voids on mismatch, admission rejects a changed hash, and the worker recomputes it at B1 (G1 with
expiry), at the W1 claim (G2 expiry + the seven checks, and `expires_at > now()` again inside the claim transaction),
before W2, W3, W5, W9 (integrity only, by design), at `await_retirement` and X1 (G3 with check 7: distinct from G1
and G2 deciders, never `self_approved`, no restore since, not expired — `check_expiry=False` there is right because
check 7 carries the expiry itself). Human-only: the decision route requires `approver` with `human_only=True`;
operator cutover without an approval needs a human session, a `run.cutover` step-up and the TC; every confirmed run
action needs the same. Typed confirmation is compared server-side with `hmac.compare_digest` on whitespace-normalised
text, in the api and again in the worker. Requester set is recomputed (profile author, plan creator, run starter,
policy editor, approval requester) and G3 excludes the G1/G2 deciders (tested, UI and worker). Self-approval of G2 by
the run starter is refused by the worker even when the stored requester set was forged (tested).

**4. Guest path.** Bootstrap key: generated in memory, private part only in user-data, public key and fingerprint
in the ledger; cloud-init `ssh_deletekeys` and `ssh_genkeytypes: [ed25519]` (an empty list fails the cloud-init schema, lab bug M) so the guest boots with exactly that key;
rotation behind a fence check, new keys read back over the authenticated session and verified before pinning; the
re-run gap is REN-2. Pinning: `StrictHostKeyChecking=yes`, `BatchMode=yes`, a per-call `known_hosts` in a 0700
directory, key file 0600 removed in `finally`, scrubbed environment (unit-tested through a fake `ssh`). Blue: keys
scanned and accepted only when their SHA-256 fingerprint equals the registration one. Probe: fixed command list,
mount point and unit names validated by pattern and shell-quoted. `sudo NOPASSWD`: REN-9. External probe: no
redirects, no proxy, body capped, identity from the `X-OVLM-Server-Id` header or JSON `server_id`, hostname fallback
only when exactly one candidate matches; TCP checks are refused as proof of identity. Interim credentials: REN-8.

**5. Tested versus claimed.** See §3.

## 3. Coverage of renewal-workflow.md §7–§8 and the crash points

Legend: **T** = an automated test exercises the row against the fake cloud/guest on PostgreSQL (I ran it); **R** = I
confirmed the behaviour by reading the code only; **—** = neither.

| Row (§7 / §4.1 / §5) | Status | Test |
|---|---|---|
| Interrupted workflow: no duplicate green, no duplicate attach, data phases → needs_human | T | `test_crash_window.py` (W2/W3/W5/W9 × 4 points; W7/W8 × 2; W1/W6 × 3; 6 restore steps after act), `test_worker_loop.py`, `test_failures.py::test_lost_create_response_adopts_never_duplicates` |
| Insufficient capacity: `OverQuota` fatal; `NoValidHost` fatal, green kept, rollback deletes it | T | `test_overquota_at_create_is_fatal_build_failed_then_rollback`, `test_no_valid_host_green_kept_until_operator_rollback` |
| Failed provisioning / adoption refused for another user's server | T | `test_adoption_refused_for_a_server_of_another_user` |
| Failed Ansible configuration: BuildFailed, volume never left blue | T | `test_configure_fatal_build_failed_volume_never_left_blue` |
| Green ACTIVE but not reachable: B5/B9 wait on SSH | T | `test_green_active_but_ssh_late_waits_on_reachability` |
| Console empty under `console` policy → needs_human before any outage | T (unit) | `test_console_policy_pins_only_keys_the_console_vouches_for` |
| Failed health check W8: needs_human + page; restore only with a snapshot | T | `test_w8_healthcheck_exhausted_pages`, `test_w7_failure_with_snapshot_restores_and_keeps_snapshot` |
| Failed cutover W9 (no router path 404) / W10 with and without snapshot | T | `test_w9_no_router_path_pages`, `test_w10_external_verify_exhausted_*` |
| W9 generic 4xx with FIP unchanged; FIP on an unknown port (`fip_state_unknown`) | R | — |
| Quiesced but still ACTIVE → S6 boot-cycle (SRE-R-1) | T | `test_w2_stop_exhausted_quiesced_but_active_restore_boot_cycles_blue`, data-phase crash tests |
| DB or worker restart | T (engine suite, earlier review) + T here | `test_worker_loop.py` |
| Detach refused / stuck (W3 rolled back once then restore; stuck `detaching`) | T | `test_w3_detach_rolled_back_retried_once_then_auto_restore_converges`, `test_w3_stuck_detaching_is_needs_human` |
| Detach refused because the compute host is down (`compute_host_down` classification) | R | — |
| Blank or wrong filesystem on green: W6 needs_human, no mkfs | T | `test_w6_data_attach_failure_needs_human_no_restore` (+ `first_use=False` asserted by the fake guest) |
| W2 admin lock → needs_human directly | T | `test_w2_admin_lock_is_needs_human_directly` |
| W4 snapshot: refused create, `error`, stuck `creating`, kept after restore, adoption by name, squatted name, duplicate | T | `test_snapshot.py` (12 tests) |
| W5 attach not done → restore; stuck `attaching` → needs_human | T | `test_w5_attach_not_done_auto_restores`, `test_w5_stuck_attaching_is_needs_human` |
| Budget before W5 → restore; before W7 → page | T | `test_budget_exceeded_before_w5_restores`, `test_budget_exceeded_before_w7_pages` |
| Budget before W2/W3/W4/W6/W8 individually | R | — |
| `approval_evidence_invalid` inside the window (pre-start) → restore of a known state; later role revocation does not trip it | T | `test_evidence_invalid_inside_window_restores_known_state`, `test_legitimate_later_role_revocation_does_not_trip_the_check` |
| `approval_evidence_invalid` before W9 (D-1 row) | R | — |
| `auto_restore_in_window = false` parks | T | `test_auto_restore_disabled_by_policy_parks` |
| One restore per run; restore failure never re-enters the window | T | `test_restore_failure_is_needs_human_and_never_reenters_window` |
| G2 expired never claims W1; forged G2; self-approved G2; window closed; B9 stale; credential horizon | T | `test_g2_*`, `test_w1_claim_*` |
| W1 re-claim after a failed quiesce with G2 expired (REN-1) | T (probe, fails the design) | §4 probe 1 |
| §5.1 rule 0 (budget) and rule 1 (exact post-state → forward); operator probe refreshes only | T | `test_self_resolution.py` |
| §5.1 rule 2 (unchanged state → restore) and rule 3 (differs → stays) | R | — |
| Abort in build → Discarding; abort after cutover refused; revert restores and voids G3 | T | `test_abort_in_build_discards_green`, `test_abort_after_cutover_is_refused_revert_restores_and_voids_g3` |
| Abort inside the window (step finishes, then restore) | R | — |
| G3 by the G2 approver refused; X1 precondition mismatch voids G3 | T | `test_g3_by_the_g2_approver_is_refused`, `test_x1_mismatch_needs_human_and_voids_g3` |
| retry-step / mark-resolved semantics; wrong TC and foreign step-up refused | T | `test_retry_step_after_needs_human_runs_the_step_again`, `test_operator_rollback_from_needs_human_window_converges` |
| Stateless profile skips the handoff | T | `test_stateless_profile_skips_handoff_steps` |
| Takeover during S2 `quiesce_green`, S7, S9, S10, Discarding | R | — |
| Worker paused past the lease during W9 (no second PUT); `kill -9` mid-quiesce process-group sweep | — (engine/runner scope, lab items) | — |
| Host keys: injected rotation once behind the fence; another key never trusted; re-run accepts pinned keys; console strictness; user-data content | T (unit) | `test_renewal_production.py` |
| Host keys: re-run after rotation must not fall back to the bootstrap key (REN-2) | T (probe, fails the design) | §4 probe 2 |
| API human-only approvals and actions, CSRF, step-up, TC, SoD shown and enforced, G3 provenance | T | `test_renewal_ui.py` (17), `test_api.py` (2), `test_ui_renewal.py` (10) |

Nothing in this list is lab-validated: all cloud and guest behaviour is the fake's (`RenewalFake`, `FakeGuest`),
and the production adapters are unit-tested with doubles, as their module docstring states.

## 4. Tests run

Environment: local PostgreSQL 16.15 on this host (`OVLM_TEST_DATABASE_URL`), `make install` (uv, frozen lock),
Python 3.13.

| Suite | Result |
|---|---|
| `tests/unit -k "renewal or closed_table or adoption or allowlist or snapshot or ownership or write"` | 314 passed, 1 skipped (the file-permission check skips as root), 813 deselected |
| `tests/integration/renewal` + `tests/integration/test_renewal_ui.py` (with the two integration probes below collected) | 113 passed |
| Clean re-run without the probes: `tests/integration/renewal`, `tests/integration/test_renewal_ui.py`, `tests/unit/test_renewal_production.py`, `tests/unit/test_ui_renewal.py` | 156 passed, 1 skipped |

Reviewer probes (written to confirm or refute a reading; **not** committed; each assertion states the *observed*
behaviour, so a passing probe is a confirmed finding):

1. **REN-1** (`tests/integration/renewal/`, `World` fixture): quiesce fails after the claim → `needs_human
   (quiesce_old_failed)`; G2 `expires_at` set in the past; `retry_step` with TC → open step `await_cutover`, phase
   `build`, `downtime_started_at` set, `downtime_ended_at` null; `rollback` with green's TC → `rolled_back`,
   `start_server` never called. **Passed (finding confirmed).**
2. **REN-2** (unit, `_Ssh` double from `test_renewal_production.py`): `pin_host_key(policy="injected",
   accept=(pinned,), bootstrap_public=boot)` against a host presenting the bootstrap key → `ok=True`,
   `mode="rotated"`, `ROTATE_HOST_KEYS` sent, the recorded pin replaced. **Passed (finding confirmed).** The same
   call with `policy="tofu"` and `bootstrap_public=None` → `ok=False, "host key mismatch"` (refuted for tofu).
3. **REN-3**: W2 deadline set in the past before its act → `needs_human_reason == "api_unreachable"` with error
   "step deadline passed before acting; nothing was sent". **Passed (finding confirmed).**

## 5. Required before the lab, and later

**Required before the lab campaign (E5-6):**

1. REN-1 with its test (W1 re-claim inside the outage never leaves phase `window`; rollback/abort with an open
   outage always restore).
2. REN-2 with its test (B5 re-run never falls back to the bootstrap key once a pin is recorded).
3. REN-8 operating conditions for the interim credential files (dedicated lab project, short-lived `member`
   application credential, tmpfs/secret mount, `credentials_dir` refused outside the worker role, startup log line).

**Later (before production, in this order):** REN-4 (revert after X1 acted), REN-6 (S6 precondition), REN-3
(deadline labelling), REN-5 (mark-resolved role on the current step), REN-7 (Discarding looks up an unrecorded
green), REN-10 (step-up bound to the signal), REN-11, REN-12; close the **R** rows of §3 with tests, in particular
§5.1 rules 2 and 3, abort inside the window, the per-step budget rows, `approval_evidence_invalid` before W9, and a
takeover during S2; the credential store of security-model.md §5.1 replaces REN-8.

## 6. What I did not review

The engine, auth/SoD, RBAC, the write client's transport allowlist and the automation runner beyond how the renewal
code calls them (reviewed and fixed earlier); the UI templates beyond the renewal route tests; `docs/team-log.md`.
