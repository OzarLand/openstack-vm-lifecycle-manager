# Verification — renewal review fixes (REN-1..8)

| Field | Value |
|---|---|
| Verifier | Independent verifier (did not write the fixes) |
| Date | 2026-11-04 |
| Input | `docs/reviews/review-renewal-code.md`, findings REN-1..8 |
| Fixes checked | `260ee2f` (REN-2), `4364ebf` (REN-1, REN-3..7), merged in `ac2fe29` "Merge renewal review fixes (REN-1..8)" |
| Scope | For each finding only: does its failure scenario still happen? I did not re-review the renewal code. |
| Environment | `make install` (uv, frozen lock), Python 3.13, PostgreSQL 16.15 running locally (`OVLM_TEST_DATABASE_URL`). The tests ran as root; the one test that skips as root was also run as a non-root user (see REN-8). |

## 1. Verdicts

| Finding | Sev | Verdict | Evidence (code) | Regression test(s) | Ran |
|---|---|---|---|---|---|
| REN-1 | High | **fixed** | `src/ovlm/renewal/steps_window.py:116` (W1 probe switches to `reclaim_probe` once `downtime_started_at` is set), `:153-178` (re-claim checks G2 integrity only, with `check_expiry=False`, plus blue's state; any problem → needs_human), `:201` (the claim SQL accepts an expired G2 only when the outage has already started), `:205` (a failed re-claim → `approval_evidence_invalid`, needs_human, never `w1_claim_refused`); `src/ovlm/renewal/definition.py:325` (on_failure: `w1_claim_refused` with the outage started parks `w1_reclaim_refused` in phase `window`); `:563-580` (`_seal`, applied to `next` :239, `on_failure` :308, `on_abort` :414, `on_signal` :524: while the outage is open, any transition to a build step, to `discard_green`, to phase `build` or to a terminal state is turned into a park in phase `window`); `:419-424` (abort from a build step during an open outage → `_restore`); `:468`, `:552` (rollback/abort judged on the effective phase); `src/ovlm/renewal/plans.py:478`, `:493-500` (`effective_phase`; the TC target is blue's); `src/ovlm/renewal/service.py:454` (the page offers the restore, not "delete green") | `tests/integration/renewal/test_review_fixes.py::test_ren1_w1_rerun_with_expired_g2_stale_b9_and_short_credential_finishes_forward`, `::test_ren1_w1_rerun_failing_again_stays_in_window_and_rollback_restores_blue` (the review's probe 1 word for word; ends `await_discard` with blue ACTIVE, mounted, units active, green not deleted), `::test_ren1_w1_rerun_with_voided_g2_is_needs_human_in_the_window`, `::test_ren1_open_outage_with_a_stored_build_phase_restores_never_discards` | yes |
| REN-2 | High (sec) | **fixed** | `src/ovlm/renewal/production.py:650-662` (when `accept` is non-empty, it connects with the pinned keys only and returns before the `injected` branch; only `unreachable` can lead to a wait, every other result → `host key unverifiable`); `src/ovlm/renewal/steps_build.py:376` (once `pinned` is in the ledger detail, B5 never passes `bootstrap_public` to the guest port: a second barrier) | `tests/unit/test_renewal_production.py::test_rerun_after_a_recorded_pin_never_falls_back_to_the_bootstrap_key[injected,console,tofu]` (the review's probe 2: `not ok`, `ROTATE_HOST_KEYS` never sent, no fence check, one connection attempt, pinned key only), `::test_rerun_after_a_recorded_pin_waits_when_green_is_unreachable`, `::test_rerun_accepts_only_the_keys_already_pinned` | yes |
| REN-3 | Low | **fixed** | `src/ovlm/renewal/definition.py:340-344` (a deadline with no `truth` → park `deadline_exceeded`; the reason is no longer rewritten to `api_unreachable` at :350) | `test_review_fixes.py::test_ren3_w2_deadline_before_acting_parks_deadline_exceeded` (no automatic restore, `stop_server` never called) | yes |
| REN-4 | Medium | **fixed** | `src/ovlm/renewal/definition.py:479-482` (`revert` refused once `retire_old` has a persisted intent, `_retire_intent` :668); `src/ovlm/renewal/service.py:516` (the page shows revert as unavailable) | `test_review_fixes.py::test_ren4_revert_refused_after_x1_sent_the_delete_run_still_completes` | yes |
| REN-5 | Low | **fixed** | `src/ovlm/renewal/definition.py:490-506` (needs the approver when the current step or the next one is destructive) | `test_review_fixes.py::test_ren5_mark_resolved_on_a_destructive_current_step_needs_the_approver` | yes |
| REN-6 | Low | **fixed** | `src/ovlm/renewal/steps_after.py:436-457` (S6 probe: the volume must be `in-use` on blue only, or the profile stateless; otherwise needs_human `volume_not_on_blue` with no start or stop) | `test_review_fixes.py::test_ren6_boot_old_refuses_when_the_volume_is_not_on_blue` | yes |
| REN-7 | Low | **fixed** | `src/ovlm/renewal/steps_after.py:630-652` (Discarding looks up the server by run tag and exact name when the ledger row has no id; one or more matches → needs_human `green_unrecorded`, never "absent") | `test_review_fixes.py::test_ren7_discard_finds_an_unrecorded_green_by_tag_and_name` | yes |
| REN-8 | Medium (interim) | **fixed (as scoped: off by default, fails closed)** | `src/ovlm/config/settings.py:179` (`credentials_dir` defaults to `None`); `src/ovlm/renewal/production.py:813-815` (`None` → `NoCredentialStore` → admission rejects every renewal); `:137-142`, `:151-152` (owner uid and `0o077` checked on the directory and on both files at every read: `PermissionError`, which becomes the unavailable reason); `:146-150` (an id that is not a UUID, or a missing file → no credentials) | `tests/unit/test_renewal_production.py::test_no_store_means_admission_rejects_with_the_reason`, `::test_file_source_refuses_loose_permissions`, `::test_file_source_permission_check_runs_as_the_worker_user` (skips as root; **run here as the non-root `postgres` user: passed**), `::test_file_source_ignores_ids_that_are_not_uuids` | yes |

### 1.1 REN-1: every path from W1 onward (special care)

The question: can any path reach `discard_green`, or leave the outage through the build phase, while blue is
quiesced or stopped? `downtime_started_at` is written in the claim transaction, before the quiesce play runs. It is
cleared only by `_end_downtime`, which runs at W10 success (`definition.py:292`) or at S10 success (`:275`). Inside
that window `_seal` filters every transition the definition returns. The paths:

| Path | What happens now | How verified |
|---|---|---|
| Claim refused on a re-run (G2 expired, window closed, B9 stale, credential horizon) | The refusing checks are skipped and W1 goes forward. If the integrity check fails, it parks in `window` | Committed tests (forward, voided G2) |
| Re-claim transaction loses (G2 voided between probe and act) | `approval_evidence_invalid`, needs_human; `on_failure` → `_window_failure`, never `w1_claim_refused` | Code reading (`steps_window.py:205`) |
| `w1_claim_refused` reaching `on_failure` with the outage started | Parks `w1_reclaim_refused` in phase `window` (a second barrier) | Code reading (`definition.py:325`) |
| Crash after the quiesce (takeover) + G2 expired + retry-step | `data_phase_interrupted` in `window`; the retry re-claims and the run finishes forward; never a build step | Verifier probe P1 (after_act, after_verify_before_commit): passed |
| Operator rollback | Uses the effective phase: restore (S1–S10), TC = blue's | Committed test |
| Operator abort, with a stored `build` phase and the outage open | `_on_abort` → `_restore`; ends at `await_discard`, green not deleted | Verifier probe P2: passed |
| Operator `discard` while the outage is open | Refused (`step != await_discard`); the seal would also block the transition | Verifier probe P4: passed (no delete) |
| Deadline on the re-queued W1 (G2 expired) | Parks `deadline_exceeded` in phase `window` (REN-3); rollback then restores blue | Verifier probe P3: passed |
| `discard_green` reaching Done with the outage open | `next` → the seal → park (no `rolled_back`) | Code reading (`definition.py:239-241`) |

Residual (not blocking): `_seal` lets a `None` transition through, and for a FATAL failure the engine turns `None`
into `run_state="failed"` (`engine.py:739-743`). `_on_failure` returns `None` only for `preflight` and
`claim_resources`. These are build steps the seal makes unreachable while the outage is open, so no path exists
today. Making the seal map `None` to a park when the outage is open would close this by construction.

### 1.2 REN-2: the bootstrap key after a pin, including on a takeover (special care)

`pinned` is written to the ledger only when `res.ok` (`steps_build.py:382-388`), so a recorded pin is durable.
From then on, every B5 attempt (retry-step, mark-resolved or takeover, since all of them re-enter at `probe` →
`act`) reads `det["pinned"]` and sets `bootstrap=None`. `pin_host_key` also returns from the `accept` branch
without ever reaching the bootstrap code. That makes two independent barriers, both covered by the unit test,
which passes `bootstrap_public` on purpose.

Residual (not blocking, matches ADR-0006 `Interrupted rotation`): if a worker dies after `ROTATE_HOST_KEYS` but
before the pin is recorded, the re-run has no pin and uses the bootstrap key again. The real green no longer
presents that key, so it parks `host_key_unverifiable`. ADR-0006 allows the bootstrap key before a pin is
recorded, and testing-strategy WF-25 (L2) is where the lab checks this.

### 1.3 REN-8 note

Judged only as asked (off by default, fails closed): yes. The review's lab conditions are **not** in the code:
`credentials_dir` is not refused when `process_role != worker`, and nothing logs at startup that the interim
source is active. The credential store being built on another branch replaces this setting.

## 2. Overall verdict

**Ready to merge.** REN-1..8 are fixed. Each High finding has a regression test that reproduces the review's
probe, and four extra verifier probes on the remaining REN-1 paths passed. The two residuals in §1.1 and §1.2 are
hardening, not open findings.

## 3. Tests run

| Run | Result |
|---|---|
| `pytest tests/integration/renewal/test_review_fixes.py` | 9 passed |
| `pytest tests/unit/test_renewal_production.py::test_rerun_after_a_recorded_pin_never_falls_back_to_the_bootstrap_key` (3 params), `::test_rerun_after_a_recorded_pin_waits_when_green_is_unreachable`, `::test_rerun_accepts_only_the_keys_already_pinned` | 5 passed |
| `pytest tests/unit/test_renewal_production.py -k "no_store or file_source"` (root) | 4 passed, 1 skipped |
| `::test_file_source_permission_check_runs_as_the_worker_user` as non-root uid `postgres` | 1 passed |
| Verifier probes P1 (×2), P2, P3, P4 (`tests/integration/renewal/`, not committed) | 5 passed |
| `tests/integration/renewal` + `tests/integration/test_renewal_ui.py` + `tests/unit/test_renewal_production.py` + `tests/unit/test_ui_renewal.py` | 170 passed, 1 skipped (the root-only skip above) |
| `tests/unit -k "renewal or closed_table or adoption or allowlist or snapshot or ownership or write"` | 319 passed, 1 skipped, 817 deselected |

Commands: `uv run --frozen --group automation pytest <path>::<test> -q`, with
`OVLM_TEST_DATABASE_URL=postgresql+psycopg://postgres@127.0.0.1:55432/postgres` for the integration tests.
