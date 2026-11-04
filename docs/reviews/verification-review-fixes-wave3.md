# Verification of the review fixes — engine (SRE-C) and wave-3 security (SEC-C)

| Field | Value |
|---|---|
| Verifier | Independent verifier (did not write the fixes or the reviews) |
| Date | 2026-11-04 |
| Tree verified | `claude/ovlm-verify-fixes` at `8d616e1` (merges of `claude/ovlm-fix-engine` and `claude/ovlm-fix-security`) |
| Fix commits | engine `6cb79a4`, `ba872eb`; security `47da539`, `2ae92a4`, `f00f862`, `889f323`, `c2b96b8`, `d300492`, `5209798`, `6f85fd9` |
| Inputs | `docs/reviews/sre-review-engine-e5-1.md` (SRE-C-1..10), `docs/reviews/security-review-code-wave3.md` (SEC-C-1..11) |
| Method | For each finding: re-read the failure scenario, read the fixing diff and its regression test, decide whether the scenario is still possible; ran the regression tests, the full unit and integration suites and `make lint`; an independent DEBUG log probe for SEC-C-2 (below). Not a re-review of the modules. |

## Overall verdict

**Ready to merge.** Every finding is fixed or, for two lows, addressed as far as the current code base allows;
no blocking item. Both High findings are fixed: SEC-C-1's scenario is impossible in the documented deployment
(proxy on loopback, trusted by default), and SEC-C-2 was checked by an independent probe: no request or response
body reaches the log output with `log.level = DEBUG`. Three non-blocking follow-ups are listed at the end.

## Results

Line numbers refer to the verified tree. "Ran" = the named regression test was executed in this session (all
passed).

### Security review (SEC-C)

| Finding | Sev | Verdict | Evidence (fix · test) | Ran |
|---|---|---|---|---|
| SEC-C-1 login limit keyed on the proxy IP | High | **fixed** (residual on misconfiguration, see F-1) | `src/ovlm/auth/clientaddr.py:59` `resolve_client` (XFF only from `http.trusted_proxies`, right-to-left, trusted proxy without XFF → not attributable → no per-source key); `src/ovlm/auth/deps.py:99-126`; `src/ovlm/auth/login.py:71-110` (per-source delay fixed at `login_ip_delay_seconds`, default 10 s, never escalates); `src/ovlm/config/settings.py` `trusted_proxies` default loopback; `src/ovlm/cli.py` uvicorn `proxy_headers=False`. Tests: `tests/integration/test_auth_client_address.py::test_a_trusted_proxy_naming_no_client_never_locks_out_another_account` (the review's exact case: 25 failures on one user via the proxy, correct login of another succeeds, no `login_attempt` row carries the proxy address), `::test_forwarded_client_from_a_trusted_proxy_is_the_rate_limit_key`, `::test_forwarded_header_from_an_untrusted_peer_is_ignored`, `::test_only_the_per_account_limit_escalates`; `tests/unit/test_client_address.py` | yes |
| SEC-C-2 request bodies logged at DEBUG | High | **fixed** | `src/ovlm/observability/logging.py:49-107` (SDK/HTTP loggers pinned to WARNING plus a handler filter that drops their lower records even if a library lowers the level later); `log.openstack_http_debug` refused outside `development_mode` (`settings.py:185-196`); `src/ovlm/openstack/sdk_write.py:234` create sent with `log=False`; `src/ovlm/observability/redaction.py:29` JSON-quoted keys and `user_data`. Tests: `tests/unit/test_sdk_debug_logging.py` (4 tests) and the independent probe below | yes |
| SEC-C-3 write credential only from a file / ambient config | Medium | **fixed** | `sdk_write.py:316` `WriteCredential` (secret out of `repr`), `:353-382` `connect_write` with `OpenStackConfig(load_yaml_config=False, load_envvars=False)` (checked in the pinned openstacksdk: no config, secure or vendor file, and `OS_CLIENT_*_FILE` overrides are read through `_get_envvar`, which honours `load_envvars=False`), secret registered with the redaction backstop; `connect_write_from_clouds_yaml` reads only the named file. Tests: `tests/unit/test_openstack_credentials.py::test_connect_write_uses_the_in_memory_credential_and_reads_nothing_ambient`, `::test_clouds_yaml_variant_reads_only_the_named_file`. Nothing calls either constructor yet; E5-4 must use `connect_write` | yes |
| SEC-C-4 TLS verification not enforced | Medium | **fixed** | `src/ovlm/openstack/sdk_read.py:379` `require_tls_verification` on what the SDK hands to `requests`; called by both clients (`sdk_read.py:404`, `sdk_write.py` `_write_client`). Tests: `test_openstack_credentials.py::test_write_client_refuses_tls_verification_off`, `::test_read_client_refuses_tls_verification_off` (5 cases each, incl. `insecure` winning over `cacert`, missing bundle), `::test_a_custom_ca_bundle_is_accepted` | yes |
| SEC-C-5 create-body deny-list | Low | **fixed** | `src/ovlm/openstack/allowlist.py:91-120` `CREATE_SERVER_KEYS` / `CREATE_BODY_KEYS` allow-list. Test: `tests/unit/test_openstack_allowlist.py::test_everything_else_is_refused` (adds `adminPass`, `config_drive`, `OS-DCF:diskConfig`, …) | yes |
| SEC-C-6 own lock decided by `ovlm:` prefix | Low | **fixed** | `src/ovlm/openstack/write.py:92` `own_lock_reasons`, exact match at every use, `ForeignLockError.locked_reason`. Tests: `tests/unit/test_openstack_write.py::test_an_ovlm_prefixed_lock_of_another_run_or_unknown_form_is_foreign`, `::test_own_locks_are_recognised_and_can_change_kind` | yes |
| SEC-C-7 fake not strict by default | Low | **fixed** | `src/ovlm/openstack/fake.py:184` `strict_gate: bool = True`. Test: `tests/unit/test_openstack_fake.py::test_the_fake_is_strict_by_default` | yes |
| SEC-C-8 free-form project scopes | Low | **partial** | Canonical lower-case UUID enforced on creation and compared canonically on both sides (`src/ovlm/auth/users.py:50`, `principal.py` `canonical_scope`): the upper-case inconsistency is gone. **Remaining:** the existence check (`users.py:66` `check_project_exists`) silently does nothing while the `project_connection` table does not exist, which is the case on this tree (no migration creates it), so a well-formed but unknown UUID still binds and grants nothing. It switches on by itself when the table arrives. Tests: `tests/integration/test_auth_authz.py::test_project_scopes_are_uuids_stored_lower_case`, `::test_project_scope_must_name_an_existing_project_connection` (creates the table itself), `tests/unit/test_auth_unit.py::test_scope_comparison_is_canonical` | yes |
| SEC-C-9 duplicate binding returns a fake id and audits | Low | **fixed** | `users.py:262-291` (`add_binding`) `ON CONFLICT (…) WHERE revoked_at IS NULL DO NOTHING RETURNING id`, else the existing id; `routes_auth.py` answers 200 `{created: false}`, no audit row. Test: `test_auth_authz.py::test_duplicate_binding_returns_the_existing_id_without_a_false_audit_row` | yes |
| SEC-C-10 adoption checks left to the step | Low | **fixed** (as asked: pure function + documented registry rule; enforcement belongs to E5-4) | `write.py:123` `adopt_checks` (readable, tags, image, flavor, created after ledger commit, no volume from both sources, `user_id`); `ownership.py` docstring. Tests: `tests/unit/test_openstack_adoption.py` (6 tests) | yes |
| SEC-C-11 production without `external_url` | Low | **fixed** | `settings.py:163, 185-190`: the api refuses to start without `external_url` unless `development_mode`; Compose sets development mode explicitly. Tests: `tests/unit/test_config.py::test_production_api_requires_external_url`, `::test_development_mode_is_off_unless_set` | yes |

### SRE engine review (SRE-C)

| Finding | Sev | Verdict | Evidence (fix · test) | Ran |
|---|---|---|---|---|
| SRE-C-1 signal transition lock conflict leaves no open step | Medium | **fixed** | `src/ovlm/workflow/engine.py:936` `_close_and_transition` (close step + transition in one savepoint; conflict → step kept open in `needs_human`, run parked), `:978` `_park_on_conflict`; locks are acquired before any audit record in `_apply_transition`, so the savepoint rollback leaves no stray audit line. Invariant "needs_human ⇒ exactly one open needs_human step" asserted after every workflow integration test (`tests/integration/workflow/conftest.py` `assert_open_step_invariant`). Tests: `tests/integration/workflow/test_sre_review_engine.py::test_sre_c1_signal_transition_lock_conflict_keeps_the_step_open` (×2), `::test_sre_c1_retry_step_works_after_a_signal_lock_conflict` | yes |
| SRE-C-2 `mark_resolved` without re-probe | Medium | **fixed** | `engine.py:1421-1454`: `mark_resolved` re-queues the step like `retry_step` (fresh budget and deadline, attestation kept in `evidence.mark_resolved`); the step is never closed on attestation. Tests: `::test_sre_c2_mark_resolved_re_probes_and_never_completes_on_attestation_alone`, `::test_sre_c2_mark_resolved_resets_budget_and_deadline` | yes |
| SRE-C-3 late claim still acts | Medium | **fixed** | Claim returns `late`/`deadline_in` (`engine.py:457`); `_StepContext.deadline_passed` (claim-time DB view, then local monotonic, never later than the DB deadline); `src/ovlm/workflow/contract.py:318` turns `Act` into `needs_human(deadline_exceeded)` before the intent is persisted; `Done` allowed. Tests: `::test_sre_c3_step_claimed_after_its_deadline_does_not_act`, `::test_sre_c3_late_step_whose_goal_is_already_reached_completes`, `::test_sre_c3_deadline_passing_locally_between_claim_and_act_stops_the_act`; `tests/unit/workflow/test_sre_review_unit.py::test_sre_c3_contract_never_acts_past_the_deadline`, `::test_sre_c3_contract_late_but_goal_reached_is_done` | yes |
| SRE-C-4 pool too small, slow pool timeout | Low | **fixed** (see F-3) | `src/ovlm/db/engine.py:11` `pool_options`: worker pool `2×slots+4` + `slots` overflow, `pool_timeout = max(1, fence_margin/2)`; `StepContext.read` documented. Test: `test_sre_review_unit.py::test_sre_c4_worker_pool_is_sized_from_slots_and_fails_fast` | yes |
| SRE-C-5 poll backoff by attempt counter | Low | **fixed** | `engine.py:872` `_poll_delay` by consecutive waits (`:883`, takeovers transparent, reset after an act), all timers clamped to the remaining deadline (`_clamp`). Test: `::test_sre_c5_backoff_counts_consecutive_waits_only_and_is_clamped_to_the_deadline` | yes |
| SRE-C-6 audit logged before commit | Low | **fixed** | `src/ovlm/workflow/audit.py:46` emits on the connection's `commit` event only. Test: `test_sre_review_unit.py::test_sre_c6_log_audit_is_emitted_only_after_commit` | yes |
| SRE-C-7 parked step shows a succeeded attempt | Low | **fixed** | `_park_on_conflict` sets the attempt `outcome = 'parked'` and records `step.parked` with lock and holder. Test: `::test_sre_c7_outcome_lock_conflict_marks_the_attempt_parked` | yes |
| SRE-C-8 untested paths | Low | **fixed** | New crash point `outcome.before_commit` (`crashpoint.py:5`, pinned enumeration updated); `set_lease` stops unless the guarded heartbeat returns True. Tests: `::test_sre_c8_commit_fails_on_a_terminated_backend_next_attempt_re_probes`, `::test_sre_c8_commit_acknowledgement_lost_after_commit_is_harmless`, `::test_sre_c8_two_workers_racing_one_signal_apply_it_once`, `::test_sre_c8_set_lease_heartbeat_failure_stops_before_probe`, plus the SRE-C-1 regressions | yes |
| SRE-C-9 watchdog at 20 Hz per step | Low | **fixed** | `engine.py:358-365`: `min(watchdog_interval (1 s), max(remaining/2, 50 ms))`. Test: `test_sre_review_unit.py::test_sre_c9_watchdog_interval_is_configurable_and_bounded_by_default` | yes |
| SRE-C-10 worker rows never deleted | Low | **fixed** | `engine.py:410` `sweep_worker_rows` (never its own row), upsert in `beat_worker`, sweeper in `worker/main.py`; `src/ovlm/workflow/workers.py` liveness on recent non-draining rows only. Test: `::test_sre_c10_stale_worker_rows_are_swept_and_live_count_uses_recent_rows` | yes |

## SEC-C-2: independent DEBUG log check

Probe written for this verification (scratch file, not committed), run as its own process with real stdout:

1. `OVLM_LOG__LEVEL=DEBUG`, `Settings(process_role="worker")`, then `configure_logging("worker", settings.log.level)`
   exactly as `worker/main.py:184` does.
2. A plain keystoneauth `Session` (default `log=True`, not the write backend) POSTs a JSON body carrying a request
   marker and a `password` field; the canned transport answers with a response marker and an `adminPass`.
3. The write backend creates a server whose `user_data` carries a host-key marker, then stops it.
4. The `keystoneauth.session`, `openstack` and `urllib3` loggers are then set to DEBUG (as a library or
   `openstack.enable_logging` would) and step 2 is repeated.
5. stdout is searched for the request marker, the response marker, the host-key marker and its base64 form, and
   for `REQ: curl` / `RESP BODY`.

| Run | Lines | Request marker | Response marker | Host key (plain or base64) | `REQ: curl` lines |
|---|---|---|---|---|---|
| As shipped (pin on) | 4 | 0 | 0 | 0 | 0 |
| Positive control (`openstack_http_debug=True`, pin lifted) | 28 | 2 | 2 | 0 | 5 |

The positive control shows the probe detects body logging when it happens; with the shipped configuration nothing
of a body reaches the output, even after the SDK loggers are lowered to DEBUG. The control also shows the server
create is never logged even with the development flag (`log=False`). Incoming API request bodies are not logged by
OVLM either: no code reads `request.body()`/`request.json()` for logging, and request logs carry route templates
(security review "main context").

## No new problem found in the touched lines, with three non-blocking follow-ups

- **F-1 (SEC-C-1, misconfiguration residual).** If the TLS proxy's address is *not* in `http.trusted_proxies`
  (for example a proxy on the host reaching the Compose-published port, whose peer inside the container is the
  bridge gateway, not loopback), every client is the proxy and is attributable; one client failing a login every
  ≤ 10 s keeps everyone at 429 (rolling fixed delay). The escalation to 900 s is gone, so this is a 10 s rolling
  window, not the original lockout, and it requires a misconfiguration; the Compose stack is now development-only.
  Suggested: a startup or first-request warning when the peer is a private address outside `trusted_proxies` and
  `external_url` is set, and a line in the deployment docs.
- **F-2 (SEC-C-8).** The `project_connection` existence check is dormant until that table is migrated; make the
  cloud-connection module's migration ticket mention it, so binding creation is re-tested then.
- **F-3 (SRE-C-4).** At the maximum `worker.slots = 64` the worker pool may open `2×64+4+64 = 196` connections,
  above PostgreSQL's default `max_connections = 100`. Document the required `max_connections` (or cap the pool) in
  the deployment guide. Default `slots = 4` gives 16 connections and is fine.

Minor observations, no action required: a legacy binding stored with an upper-case UUID is not caught by the
active-binding unique index when the same scope is added in canonical form (no such rows exist outside tests);
`charset_normalizer` still logs encoding-detection lines at DEBUG (no body content).

## Tests run

| Suite | Command | Result |
|---|---|---|
| Setup | `make install` | ok (`uv sync --frozen`) |
| Targeted regressions | `uv run --frozen pytest tests/integration/workflow/test_sre_review_engine.py tests/integration/test_auth_client_address.py tests/unit/workflow/test_sre_review_unit.py -q` | **26 passed** |
| Targeted regressions | `uv run --frozen pytest tests/unit/test_sdk_debug_logging.py tests/unit/test_client_address.py tests/unit/test_config.py -q` | **31 passed** |
| SEC-C-2 probe | scratch script, two runs (shipped, positive control) | as tabulated above |
| Unit, full | `uv run --frozen pytest tests/unit -q` | **1035 passed** |
| Integration, full | `uv run --frozen pytest tests/integration -q` | **295 passed, 11 skipped** (4 min 20 s); the 11 skips are `tests/integration/test_automation_container.py` cases that need a Docker daemon, unrelated to these findings |
| Static | `make lint` (ruff, ruff format, mypy strict, import-linter) | pass; 2 contracts kept, 0 broken |

Environment: Python 3.13, no Docker daemon in this session (so the container path of the integration fixtures and
the automation-container tests could not run); integration suites ran against a local PostgreSQL 16 cluster through
`OVLM_TEST_DATABASE_URL`. No real cloud: the OpenStack paths were exercised over the canned transport and the fake.
