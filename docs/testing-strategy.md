# Testing strategy

| Field | Value |
|---|---|
| Owner | Agent 9 — QA / Test Automation Engineer |
| Status | **Designed** (Phase 1 proposal; no test code exists, nothing has been run) |
| Last updated | 2026-11-04 |

Inputs: [functional-requirements.md](functional-requirements.md), [automation-contract.md](automation-contract.md),
[test-environment.md](test-environment.md), [security-model.md](security-model.md) §10,
[openstack-integration.md](openstack-integration.md), [ADR-0001](decisions/ADR-0001-test-environment.md).
Aligned with [architecture.md](architecture.md), [renewal-workflow.md](renewal-workflow.md) (step keys B1–X1, W1–W10, S1–S9,
gates G1–G3), [ADR-0003](decisions/ADR-0003-workflow-engine.md) (leases, fencing token, resource locks),
[ADR-0005](decisions/ADR-0005-ownership-and-idempotency.md) and [data-model.md](data-model.md). **[ALIGN]** = still open
against a document that has not fixed the detail (list in §10). **ASSUMPTION** = mine, unverified.

> **Revision 2026-11-04**: synced to the architecture revision. Addressed: SEC-R-1 (DB roles `ovlm_api` / `ovlm_worker`, §5, §6 row 14),
> SEC-R-30 (policy field `auto_restore_in_window`, §4.2 WF-17), SRE-R-11 (`NoValidHost` fatal everywhere; §10 item 2 closed).
>
> **Revision 2026-11-04 (round 2)**: synced to architecture round 2. Added: B9 `verify_green_ready` before T0 (§7.1), WF-21 to WF-24
> (SRE-R-23, -24, -26, bounded self-resolution), injected host key and its rotation at B5 (§4.2, §6 row 18, §7.1), security tests S-24 to S-27.

## 1. Principles

1. A test proves only what its level can prove. A pass at one level never earns the label of a higher one.
2. Every claim in a document carries the status of the **highest level whose gate passed**, using the vocabulary of
   [agent-team.md](agent-team.md). Levels are not blended ("mostly tested" does not exist).
3. Tests assert **outcomes and invariants** (no data lost, one volume attachment, ownership guard held), not call
   sequences.
4. No test touches a real cloud unless it is in the lab suite (§7). CI never holds OpenStack credentials. A failure we cannot reproduce deterministically is a bug in the test or the design (§9.4).

## 2. Test pyramid and status mapping
| Level | Runs where | Real components | Faked | Proves | Does NOT prove | Status granted |
|---|---|---|---|---|---|---|
| L0 Static | CI, every push | none | — | Lint, types, schema/format, `ansible-lint`, `yamllint`, `--syntax-check`, lock-file hashes, SAST/dep scan | Behaviour | none (gate only) |
| L1 Unit | CI, every push, < 2 min | none | OpenStack (fake adapter), clock, subprocess | State machine, decision logic, error classification, redaction, validation, RBAC, ownership guard, engine invariants under injected crashes (in-process) | Real SQL locking, real Ansible, real OpenStack behaviour | **Unit tested** |
| L2 Integration | CI, every PR, < 15 min | PostgreSQL (container), Alembic, ansible-runner, Ubuntu container target, `ovlm-counter` role, real worker subprocesses | OpenStack (same fake) | Migrations, row locks/leases/fencing under real concurrency, real kill -9 recovery, DB restart, real Ansible run and result.json handling, role idempotency | Any OpenStack, Cinder, Neutron, guest kernel behaviour, systemd/udev | **Integration tested** |
| L3 Lab | Quick-lab (OpenStack 2026.1 + Cinder LVM, ADR-0001), manual-triggered, nightly later | Everything incl. OpenStack | nothing (failures injected in the cloud) | End-to-end renewal and the failure scenarios of §7 on one specific release | Other releases/backends, scale, production IAM/policy, real-KVM timing (TCG) | **Lab validated** (release + date stated) |
| L4 Production | Operator's own platform | Everything | nothing | Works on a real platform | — | **Production validated** only when confirmed by a human other than the author |

Rules: "Unit tested" requires L1 green **and** no skipped tests for that feature. "Integration tested" requires L2
green in CI at the commit. "Lab validated" requires an evidence bundle (§7.3) committed or attached to the release
record. No agent, test or script may write "validated" for L3/L4; only a human reviewing the bundle does (see §7.3).

## 3. Unit tests with OpenStack faked

### 3.1 Options
| Option | Fidelity | Maintenance | Models async/failure | Verdict |
|---|---|---|---|---|
| (a) Hand-written fake of **OVLM's own OpenStack adapter interface** | As good as we encode; documented gotchas become code | Low: interface is ours and small; fake in `tests/fakes/` | Native: states, delays, faults are fake features | **Recommended** |
| (b) Recorded HTTP fixtures (VCR-style) against openstacksdk | Real payloads once, but frozen at one release; no state | High: re-record on every SDK/cloud change; cannot be recorded without a cloud (we have none now); secrets in cassettes | Poor: each failure needs a recording; asynchronous sequences need hand-edited cassettes | Reject as the main approach |
| (c) Mock `openstacksdk` objects (`Mock`/`MagicMock`) | Lowest: tests assert calls and pass whatever the mock returns | Medium; couples tests to SDK internals, breaks on SDK upgrades | Poor | Reject |

### 3.2 Recommendation: one fake, one contract suite

- OVLM code (workflow steps, inventory sync, readiness) depends only on an OVLM-owned **adapter interface** (`Protocol`;
  architecture.md §10 already calls for a fake OpenStack adapter; method names **[ALIGN]** with the code). Nothing outside the adapter imports `openstack`. A lint (import-linter)
  enforces this in L0.
- `FakeOpenStack` implements the interface as an in-memory state machine (servers, volumes, attachments, ports, FIPs,
  routers, quotas, tags). It is a **test double owned by QA**, versioned with the adapter.
- A **contract test suite** (`tests/contract/`) is written against the interface and runs against (i) the fake in CI and
  (ii) the real SDK adapter in the lab (§7). A behaviour counts as "modelled" only if the contract suite passes on both.
  This is how we keep the fake honest: until a lab run exists, every fake behaviour is marked `UNCONFIRMED` in the
  fake's docstring and in `tests/fakes/FIDELITY.md` (a table: behaviour, source in openstack-integration.md, SV/DU/AS tag,
  lab-confirmed yes/no/date).
- The thin SDK adapter (translation, microversion pins, error-text mapping) gets a small number of **canned-error-body**
  tests (§3.4) with a mocked transport. This is a narrow supplement for the translation layer, not a second strategy.

### 3.3 What the fake must model
| Area | Fake behaviour | Source |
|---|---|---|
| Async volume states | Detach: `in-use`→`detaching`→`available`; attach: `available`→`reserved`→`attaching`→`in-use`; transitions advance by a fake clock (`tick(n)`), so tests control timing and can freeze mid-transition; attachment `attach_status` incl. `error_attaching`/`error_detaching` | OSI §4 |
| Detach refused | Guest refuses → after the fake timeout volume returns to `in-use` (not an error state) | OSI §4 |
| Server states/locks | Attach/detach/stop/start/delete → 409 on `locked` (non-admin), on `task_state` set, on `ERROR`/`BUILD`; unlock override only if `locked_by` matches | OSI §4, §7 |
| Attach rules | Second attach of in-use volume → 400; attach already attached to same server is detectable; 202-without-device variant | OSI §4 |
| Host down | Detach refused when blue's compute host is flagged down | OSI §4, §9 |
| `delete_on_termination` | Per attachment; deleting a server deletes flagged volumes | OSI §4 |
| Metadata filter gotcha | `list_servers(metadata=...)` as non-admin **ignores the filter and returns everything**; tags filter works | OSI §2 |
| Non-unique names | Two servers with the same name coexist; name lookup returns both | OSI §3 |
| Create idempotency | No client token; `create` with tags is atomic; a created server in `BUILD`/`ERROR` is listable by tag | OSI §3 |
| FIP without router | `update_floatingip` with no router path → **404** whose text is `External network … is not reachable from subnet…`; port with another FIP on same ext net → 409 | OSI §6.1 |
| FIP async | Association is immediate in API, `status` DOWN→ACTIVE after fake delay; data-plane probe lags | OSI §6.1 |
| Quota | `OverQuota` 403 at create; Neutron quota readable only with a `manager` flag; `NoValidHost` → server `ERROR` with fault although quota is fine | OSI §7 |
| Microversions | Calls below the pinned microversion (2.26/2.52/2.73/2.79) fail like Nova | OSI rec. 10 |
| Roles | Credentials carry role (`reader`, `member`); any mutating call with `reader` → 403 (security test 9 reuses this) | OSI §8 |

### 3.4 Fault-injection API of the fake

`fake.fail(op, when="before"|"after_apply", error=…, nth=1, times=1)`.
`after_apply` = the cloud applied the change but the response is lost (timeout): the key case for idempotency (create
succeeded, worker never learned the id). Also `fake.freeze(resource)`, `fake.set_host_down()`, `fake.admin_reset()` (simulates the
operator fixing a stuck state), `fake.snapshot()` for invariant checks.

Canned-error tests (translation layer): the real error bodies quoted in OSI for FIP-no-router 404, attach 400, lock
409, `OverQuota`, `NoValidHost` fault map to OVLM error classes; each body is copied from a source-verified code path
and tagged so a lab run can replace it with a captured one.

### 3.5 Unit-test scope (non-exhaustive)

State machine transitions and illegal transitions; step idempotency ("observe, act, verify" for every mutating step,
called twice → second call no-op); error classification (retryable/fatal/needs_human, automation-contract §6);
readiness rules (FR-RDY-3 table-driven: failed blocker→`not-ready`, unknown blocker→≤`partially-ready`); policy
resolution and renewal deadline (FR-POL-2/5, time zones, DST edge, window rollover); approval hash binding and expiry;
ownership guard; redaction; profile validation (pinned SHA, allowlisted repo); capacity pre-check advisory outcomes;
drift detection. Property-based tests (Hypothesis) for the state machine (any event sequence never reaches an illegal
state) and for redaction (no secret substring in output).

## 4. Workflow-engine tests

Applies FR-REN-3, NFR-2/3, ADR-0003 and renewal-workflow.md §5. Every handler is `probe → decide → act → verify`, so the
tests target exactly those seams.

### 4.1 Crash-point injection harness

Deterministic, no sleeps, no random kills.

1. **Named crash points** are inserted by the engine through one call: `crashpoint("<step_key>.<phase>")`, with the real
   step keys (`create_green`, `detach_volume`, `move_fip`, …). Phases follow the ADR-0003 contract: `after_claim`
   (claim committed, nothing done), `after_probe`, `after_intent` (intent/ledger row persisted), `after_act` (OpenStack or
   Ansible changed, nothing recorded), `after_verify_before_commit`, `after_commit` (next step not yet claimed); plus
   engine points `lease.heartbeat`, `lease.release`, `run.create` (locks acquired). In production the call is a no-op
   unless `OVLM_TEST_CRASHPOINT` is set; a unit test rejects that variable in release builds.
2. **Enumeration run:** one uninterrupted renewal on the fake records the ordered list of crash points hit (N points,
   with occurrence index; restore steps S1–S9 are enumerated by a second run that forces a restore). A new step adds
   scenarios automatically; a step lacking `after_intent` and `after_act` fails a coverage test.
3. **Matrix run:** for each point *i* of N, kill at *i*, restart, run to completion. One `pytest` parameter per point.
4. **Two kill modes:** (L1) in-process: `SimulatedCrash(BaseException)`; the engine must not catch `BaseException` and no
   `finally` may commit state. (L2) real: `os._exit(137)` in a worker subprocess, plus an external `SIGKILL` smoke test
   with no cooperating hook (mid-step).
5. **Mid-step = response lost:** combine with `fake.fail(…, when="after_apply")` on every mutating adapter call.
6. **Oracle after every resumed run:**

| Invariant | Check |
|---|---|
| Same final state as the uninterrupted run | `fake.snapshot()` equal modulo ids/timestamps |
| No duplicate green / port / attachment | count by tag `ovlm:run:<id>` and `owned_resource` ledger; data volume has ≤ 1 attachment at every instant (fake records history) |
| No double-applied step | one committed success per step; `attempt` increments, none lost |
| Data safe | volume never on two servers; no `mkfs` on `first_use=false`; **crash in a data phase (W1, W6, S2) → `needs_human` with probe evidence** unless the probe proves state (AC §6) |
| Resume follows probed state | DB and fake disagree in both directions → the fake wins |
| Resource locks | held by the run across crash, `NeedsHuman` and restart; released only in the terminal transaction |
| Audit complete | every attempt, takeover and decision has an audit event |
| Defined end state | `Completed`, `RolledBack`, `Restored`/`NeedsHuman` awaiting an operator; never stuck `running` |

### 4.2 Scenario list
| ID | Scenario | Level | Assertion |
|---|---|---|---|
| WF-01 | Crash at every crash point (matrix) | L1 + L2 | Oracle |
| WF-02 | Response lost after every mutating call | L1 | Oracle; `create_green` adopts by ledger + tag (0→create, 1→adopt, >1→`needs_human`, never auto-delete) |
| WF-03 | `kill -9` worker during real `ansible-runner` | L2 | Orphan process group and run dir swept; secret files gone; non-data phases rerun; data phases `needs_human` |
| WF-04 | Lease expiry and takeover: heartbeat stops, injectable clock passes `lease_expires_at` | L1 + L2 | New claim with attempt+1 and a new `fencing_token`; resumes once |
| WF-05 | **Fencing:** A paused at `after_act`, lease expires, B claims and commits, A resumes and commits | L2 (real DB) | A's fenced write matches 0 rows and A discards its result; DB holds B's state |
| WF-06 | **Limit of fencing** (ADR-0003): A's in-flight OpenStack call lands after B's takeover | L1 (fake delays the call) | B's probe sees the effect and skips or verifies; no duplicate effect; duplicate attach is rejected by the fake as in Nova |
| WF-07 | **Self-fencing:** heartbeat fails (0 rows / DB down) until `lease_expires_at − fence_margin` | L2 | Worker makes no further adapter call, kills its Ansible process group; data-phase subprocess runs to its timeout instead (renewal-workflow §5) |
| WF-08 | **Ansible lease rule:** lease = phase timeout + kill grace + `fence_margin` | L2 | Kill worker mid-playbook with an orphan still running: no second Ansible run starts on that VM before the orphan is dead |
| WF-09 | DB restart (container stop/start) mid-step, mid-wait and idle | L2 | Reconnect with backoff; no lost/double step; fenced commit succeeds only with a current token |
| WF-10 | Duplicate delivery: two workers race one `ready` step; duplicate approval POST; duplicate abort | L2 | `SKIP LOCKED`: one claimant; partial unique index allows one `running` step per run; one audit event per effect |
| WF-11 | Concurrent renewals of the same service, or same blue/volume/FIP | L2 | `resource_lock` acquired all-or-nothing in sorted order at run creation; second start gets a clear conflict; no deadlock with crossed lock sets; locks survive crash |
| WF-12 | Different services, same quota; `renewal.max_concurrent_runs` (5) | L1/L2 | Cap enforced at start; quota failure of the second leaves the first unaffected |
| WF-13 | Resume from probed state at each stuck-prone step (W3, W5, S4, S5): volume `available` / `detaching` / `in-use` on blue / attached to green / `reserved` | L1 | Table-driven expected action per state; `detaching`→wait; `reserved`/`attaching` past deadline→`needs_human` |
| WF-14 | Waiting steps: `WAIT(poll_after)` frees the lease; backoff `poll.initial_interval`→`poll.max_interval`; `deadline_at` reached | L1 (fake clock) | Deadline → `needs_human` (state unknown), never `fatal`; no thread blocks |
| WF-15 | Approvals: G2 expired or plan hash changed while down; W1 claimed outside the policy window | L1 | W1 not claimed; re-checked at claim; G3 approver ≠ requester ≠ plan approver |
| WF-16 | Abort at every step boundary, during restore, during a data phase | L1 + L2 | Build: SIGTERM `configure` → Discarding; window: step finishes then restore; after W10 refused; matrix of 4.1 re-run with abort injected |
| WF-17 | Auto-restore (S1–S9; switch is the policy field `auto_restore_in_window`) only when every resource state is known; otherwise `needs_human`; restore skips satisfied steps; lock set only at R1, unlocked at S1 | L1 | Restore sequence is convergent: crash matrix on S1–S9 reaches blue serving, FIP on blue, green `SHUTOFF` |
| WF-18 | Error classes: `OverQuota` → **fatal** (no retry); `NoValidHost`/`ERROR` green → fatal for the attempt, green **kept** until operator rollback (TC), never auto-deleted; retryable exhaustion → `needs_human` | L1 | Exact class per case (renewal-workflow §2.1, §7) |
| WF-19 | Upgrade: `running` steps drained; `waiting`/`ready` steps of N-1 resume on N; unknown `strategy_version` refuses start with a listing | L2 | architecture.md §9 |
| WF-20 | Clock safety: lease and `not_before` use DB time, not worker clock | L2 | Skewed worker clock cannot extend its lease |
| WF-21 | **SRE-R-23:** approval evidence re-check fails inside the window (decider role revoked or evidence mismatch at W2–W8) | L1 + L2 | `needs_human(reason=approval_evidence_invalid)`, security audit event, page; never forward; known-state rows of §4.1 restore; a legitimate later change (role revoked, user disabled) after `decided_at` does **not** trip the historical check |
| WF-22 | **SRE-R-24:** signal consumed only with its effect; worker killed between signal read and commit | L2 (crash matrix) | `run_signal.consumed_at` is set in the same transaction as the effect; after the kill the signal is re-applied once, never lost and never applied twice; unconsumed signal is shown as pending |
| WF-23 | **SRE-R-26:** order after an OpenStack API outage across a step deadline (e.g. W3: volume `available`, blue SHUTOFF, FIP unchanged) | L1 (fake outage + fake clock) | Deadline → `needs_human(api_unreachable)`; on a successful re-probe rule 0 (budget) is checked first, then rule 1 (exact expected post-state → continue forward, nothing re-sent), then rule 2, else stay `needs_human`; W9/W10 never auto-continue |
| WF-24 | **Self-resolution after the approved budget:** outage lasts past `max_window_duration` | L1 (fake clock) | Run stays `needs_human` with a page even though the probe now matches an expected state; no `resume.auto`; only an operator action moves it |
| WF-25 | **Injected host key and rotation (B5):** bootstrap key pinned, rotated before anything else on the session; interrupted rotation; wrong key | L2 (two containers with different keys) | Bootstrap key accepted only before rotation; after rotation sshd rejects it and the rotated key is pinned; no `configure` or secret sent before rotation; re-run accepts only the bootstrap or rotated key matching step evidence, anything else → `needs_human` "host key unverifiable"; empty console does not block B5 |

## 5. Integration tests in CI (L2)
| Component | Setup | What is tested |
|---|---|---|
| PostgreSQL | Container (`postgres:<pinned digest>`) via compose/Testcontainers; fresh database per test module, template-DB clone for speed | Real locks, leases, `SKIP LOCKED`, serialisation errors, connection loss; roles `ovlm_owner`/`ovlm_api`/`ovlm_worker` as in security-model §9 and data-model.md §12 |
| Alembic | `upgrade head` on empty DB; `alembic check` (model vs migration, no drift); one-head check; upgrade **N-1 → N with seeded data**, including in-flight `waiting` runs (expand/contract rule); app refuses to start if schema is not at head. Downgrade is **not** a supported path (architecture.md §9: restore backup), so: any revision that does ship a `downgrade()` gets an up/down/up test, and a **backup → restore → resume run** test covers NFR-7 | No drift, no data loss on upgrade, in-flight runs resume, app-role privileges survive upgrade (audit grants, S-14) |
| ansible-runner | Real `ansible-runner` subprocess, pinned versions, isolated run dir, OVLM-generated one-host inventory | Event capture, timeouts (SIGTERM→SIGKILL), exit-code classification (contract §6), result.json parsing (missing/oversized/malformed → class), secrets files created 0600 and removed, `ANSIBLE_*` env hygiene, `--list-hosts` scope check |
| Target | Ubuntu 24.04 container with sshd + Python; systemd image (privileged) or `service`-stub for units; throwaway SSH key | SSH path, host-key policy (pinned fingerprint, TOFU opt-in), no root disk writes |
| `ovlm-counter` role | The reference workload of test-environment §4 | `configure` run twice → second `changed=0`; `healthcheck` ok / fails when data mount missing (503); `quiesce` refuses with a held mount; `start_service` idempotent; `--check` honoured |
| `data_attach` decision table | Privileged container, loopback file as the "volume", udev-less `by-id` symlink emulation (ASSUMPTION: privileged containers allowed in CI; if not, this test group moves to lab-only and the row of the contract table is marked lab-only) | Each row of contract §3.3: ext4 present → mount, no mkfs; wrong fs → needs_human; blank + `first_use=false` → needs_human, blkid unchanged; blank + `first_use=true` → mkfs with label; partition table → needs_human; negative control: skipping `data_attach` makes `ovlm-counter` health fail |
| End-to-end in CI | Whole renewal: real PostgreSQL + real worker process + real ansible-runner against the container target + **fake OpenStack** driving a "VM" that is the container | Wiring, not cloud behaviour. The fake's "new VM" resolves to a fresh container; the "data volume" is a bind-mounted loopback image moved between containers. Outcome label: **Integration tested** only |

Not in CI: anything needing KVM, real Cinder or Neutron. Compose files: `tests/integration/`, pinned digests, ephemeral ports/project names.

## 6. Security tests (security-model.md §10)

Automated where possible; "manual" is stated. Names `S-nn` = item number in §10. Level L1/L2 unless noted.

| S | Test | How automated |
|---|---|---|
| 1 | argon2id parameters, identical errors for unknown vs wrong password, rate limit | Unit + API test via `TestClient`; compare response body/status/timing bucket (no timing assert tighter than "same code path") |
| 2 | Cookie flags, session rotation, CSRF/Origin on every unsafe route | Parametrized over the **route table** exported by the app (a test fails if a route is neither in the CSRF allowlist nor tested) |
| 3 | Token hashed at rest, expired/revoked 401, scope ≤ owner's | DB inspection (no secret substring in any column) + API |
| 4 | Approve/confirm 403 for tokens; step-up older than 5 min fails | API test with fake clock |
| 5 | RBAC matrix | Table-driven role × route × method generated from the route table; matrix file reviewed by Agent 8; a new route without matrix row fails CI |
| 6 | Project scope → 404 | Two-project fixture, every resource route |
| 7–8 | Self-approval, two-person rule, voiding by hash change | Unit (engine) + API; mutation of each hash component in turn |
| 9 | Inventory credential cannot mutate | Fake `reader` role → any mutating adapter call raises; plus mocked-transport test that the inventory SDK session rejects non-GET/HEAD |
| 10 | Ownership guard (tag w/o DB record; DB record w/o tag) | Fake; every mutating adapter method parametrized |
| 11 | Old-VM delete refused if `delete_on_termination=true` | Fake |
| 12 | **Secret canary** | A unique canary string is stored in every secret type; a full renewal (incl. failing ones) runs; then grep logs, audit rows, API/UI responses, error pages, ansible argv (`/proc`-style capture), run dir after the run, DB dump outside secret columns. Zero hits required |
| 13 | api has no KEK; worker decrypts; KEK rotation | L2 compose: start `api` without the file mount, assert decrypt impossible; rotation test with old-key removal |
| 14 | `ovlm_api` and `ovlm_worker` cannot UPDATE/DELETE/TRUNCATE `audit_event` | L2 against real PostgreSQL, as each runtime role; also tests the trigger by acting as owner |
| 15 | Hostile guest output | Fuzz result.json (oversized, wrong schema, YAML tags, `<script>`); decisions unchanged |
| 16 | Ansible env has no `OS_*`/DB/KEK path; `ovlm-ansible` cannot read KEK | L2: playbook dumps `env` and `id`/read attempt on the container target |
| 17 | Branch/tag instead of SHA, non-allowlisted repo | Unit |
| 18 | Unverified SSH host key fails; pinned fingerprint enforced; injected bootstrap key trusted only until rotation (WF-25) | L2 against two containers with different keys |
| 24 | Self-approval at G3 refused even with `auth.allow_operator_approver` on; G1/G2 self-approval flagged `self_approved` only with it on; solo install without second approver leaves blue stopped and locked | Unit (engine) + API, setting on and off |
| 25 | Step-up reuse refused (consumed, older than 5 min, other action or target) | API test with fake clock |
| 26 | Admin-set password impossible; user create/reset returns only an enrolment link | API route-table test + DB inspection |
| 27 | Assessment without typed confirmation runs no repo code on the live VM | L2: fake target records no repo-content execution |
| 19 | Non-root, read-only rootfs, image scan, `pip-audit`, bandit, secret scan, SDK debug flag | CI pipeline stage "supply chain"; container assertions via `docker inspect` |

Release gate: Agent 8 has a veto on high/critical findings (agent-team.md). Security tests are never skipped or
marked flaky; a failing one blocks merge.

## 7. Lab acceptance tests (L3)

Environment: quick-lab with Cinder LVM (ADR-0001), OVLM on the lab VM, guests under TCG with generous configurable
timeouts. Every scenario below is **Designed**; none has run. Expected behaviours are from test-environment §5 and
renewal-workflow.md §7 (two architect decisions applied: insufficient capacity is fatal with no retry; a failed green is deleted only by operator rollback). Common preconditions (**CP**): CP1 lab
healthy (`openstack volume service list`, 1 GB test volume attach/detach on CirrOS passes); CP2 dedicated project,
quotas set; CP3 `ovlm-counter` v1 running on blue with data volume mounted, counter ≥ 10, marker recorded; CP4 profile
approved; CP5 evidence directory created (§7.3). Common evidence set (**CE**): audit trail export, DB dump of workflow
tables, `server/volume/floating ip list --long` before and after, ansible run records, timestamps (downtime), lab host
`docker ps` and `dmesg` tail, worker log.

### 7.1 Primary acceptance scenario (12 steps)
| Step | Action | Pass criterion (evidence) |
|---|---|---|
| 1 | Configure read-only credential; sync inventory | Blue, volume, FIP, image, flavor visible; zero write calls (request log) |
| 2 | Register blue; create service and profile | Profile version 1 stored; observed vs desired shown separately |
| 3 | Readiness assessment | `ready`, each check with evidence; negative control run earlier (`not-ready` with unpinned ref) |
| 4 | Set policy; plan shows deadline and window | Deadline = launch + max age adjusted to window |
| 5 | Plan renewal; capacity pre-check; G1 approved by approver ≠ requester; run starts (`B1 preflight`, `B2 claim_resources`) | Approval bound to hash; self-approval rejected; markers on blue, FIP, volume |
| 6 | `B3 create_green`, `B4 wait_green_active`, `B5 wait_green_ssh` (injected bootstrap host key pinned, then rotated over the authenticated session and the rotated key pinned, ADR-0006) | One server tagged `ovlm:managed` + `ovlm:run:<id>`, in the volume's AZ; ledger row `present`; blue untouched |
| 7 | `B6`–`B8` (`green_preflight`, `configure_green`, `verify_cutover_preconditions`); second `configure` run `changed=0` | `ovlm.result/1` ok; external baseline of blue recorded |
| 8 | G2 approved inside a policy window (typed confirmation: name + last 6 of ID); **`B9 verify_green_ready`** (before T0, no outage; green ACTIVE, SSH on the pinned key, `cloud-init status` done, `preflight.yml` ok, success younger than `green_ready.max_age`; negative control: green not yet SSH-reachable keeps the run before T0, EXP-01b R3 +55 s); `W1 quiesce_old` → `W2 stop_old` → `W3 detach_volume` → (`W4` snapshot optional) → `W5 attach_volume_green` → `W6 data_attach_green` → `W7 start_service_green` | Volume attached to exactly one server at all sampled instants; no mkfs; marker SHA equal |
| 9 | `W8 healthcheck_green` | `/health` ok, `fs_uuid` and `marker_sha256` equal to recorded, `counter ≥ recorded`, VM id differs from blue |
| 10 | `W9 move_fip`, `W10 verify_external` | FIP `port_id` = green port; probe answered by green; OVLM-measured downtime recorded and compared with the external probe timeline |
| 11 | `R1 retain_old`, `R2 await_retention` | Blue `SHUTOFF`, locked (`locked_reason=ovlm:retained:<run>`) only after W3; audit has every step attempt |
| 12 | G3 (approver ≠ requester ≠ plan approver), typed confirmation, `X1 retire_old` | `delete_on_termination=false` re-checked; data volume survives on green; blue gone; final health ok |
Also run **revert** (after W10, before G3): restore sequence S1–S9; FIP and volume return to blue, data written by green is still present (restore carries data forward).

### 7.2 Failure scenarios

Pass criterion common to all: no data loss (marker/counter), no second attachment of the data volume, old service
serving unless the scenario says otherwise, run ends in a defined state, OVLM-created leftovers are listed in the
evidence, nothing not tagged by OVLM is modified.

| ID | Preconditions | Injection | Expected OVLM behaviour | Evidence (beyond CE) | Pass criteria |
|---|---|---|---|---|---|
| LAB-01a–e Interrupted workflow | CP1–CP4; run started | `kill -9` worker during: (a) `B4`, (b) `B7`, (c) `W1`, (d) `W3`/`W5`, (e) `G2` wait | Lease expires, takeover with new fencing token; probes real state; (c) is `needs_human` with probe evidence, (d) resumes or `needs_human` per state; (a),(b),(e) resume | Step rows before/after; stray `ansible` processes; orphan run dirs; server/volume lists | One green VM; ≤ 1 attachment; no orphans after sweeper; data intact |
| LAB-02 Insufficient capacity | CP1–CP4 | (a) quota `cores 0` / `instances 1` → `OverQuota`; (b) `NoValidHost` (oversize flavor) | (a) `B1` refuses early (advisory) or `B3` fails **fatal, no retry**; (b) `B4` fatal for the attempt, green kept in `ERROR`; both → `BuildFailed`, blue untouched, no volume operation | Nova error/fault text, retry counter = 0, blue `/health` 200 | Fatal class, clear next action; green deleted only after operator rollback (LAB-03) |
| LAB-03 Failed provisioning | CP1–CP4 | Nonexistent image id / flavor too small for image | `B3`/`B4` fatal → `BuildFailed` with fault evidence; green **kept**; operator rollback (TC) then deletes it, only if tagged `ovlm:run:<this run>` | `server show` fault; resource diff before/after rollback | Green not deleted automatically; deleted only after TC; blue/volume untouched |
| LAB-04 Failed Ansible configuration | CP1–CP4 | Pinned ref with deliberate error (bad package/template var) | `B7` per AC §6: bounded retries or fatal → `BuildFailed`; blue untouched; volume never leaves blue | redacted run log, result.json, exit code, attachment unchanged | No data-phase step (`W1`+) started |
| LAB-05 Failed health check | Run at `W8` | Stop app on green or wrong port after `W7` | `healthcheck.max_attempts` exhausted → auto restore S2–S9 (FIP never moved); downtime includes restore | healthcheck history, attachments, FIP association, blue `/health` | Blue serving again; marker equal; run `Restored` |
| LAB-06 Failed cutover | Run at `W9` | Remove router external gateway (misleading 404) / policy denying `update_floatingip` | `W9` fails, FIP unchanged → auto restore S2–S9; error mapped to "no router path"; unknown FIP state → `needs_human` | `floating ip show` before/after, Neutron error body, timeline | FIP on working VM; message correct; downtime recorded |
| LAB-07 DB restart | Run in `B7`, again in `W3`–`W6` | Stop PostgreSQL 30 s | Non-data steps self-fence before lease end; data subprocess runs to completion; fenced commit if token current, else discarded and re-probed | DB log, step table, fencing tokens | No lost/double step; same as LAB-01 |
| LAB-08 Worker restart | as LAB-01 | SIGTERM and SIGKILL separately | SIGTERM: subprocess ended, step marked interrupted; SIGKILL: sweeper cleanup | as LAB-01 | as LAB-01 |
| LAB-09 Detach refused | Blue active, volume mounted | Hold the mount (`sleep` in `/srv/data`) | `quiesce` fails needs-human; volume not detached | quiesce result, Cinder `in-use` | No detach attempted |
| LAB-10 Data-safety negative | Blank extra volume | `first_use=false` with blank volume | `data_attach` needs-human, no mkfs | blkid before/after | Volume unchanged |
| LAB-11 Device naming | Attach a second volume first | Data volume not `/dev/vdb` | Correct device via by-id | device path, marker md5 | Marker equal |
| LAB-12 Locked blue | After handoff, admin locks blue | Admin-set lock, then revert | `S1 unlock_old` cannot unlock → `needs_human` | 409 body | No partial revert; locks retained |
| LAB-13 Stuck volume | Fault during detach | Kill nova-compute during detach | Detects `detaching`/error state, stops, reports; does not call admin-only APIs | volume/attachment states, instance actions | Operator action named in message |
| LAB-14 Ownership guard | Foreign VM tagged `ovlm:managed` | Try to act on unregistered tagged VM | Refused, audit event | audit export | Zero mutating calls on it |

Contract-suite runs (§3.2) and the §8 open questions run in the same lab session.

### 7.3 Evidence format → "lab validated"

Directory `evidence/lab/<date>-<release>-<commit8>/<scenario-id>/` (stored as a release artifact or in a dedicated
evidence repo, not in the source tree if large; ASSUMPTION):

| File | Content |
|---|---|
| `result.json` | `{schema:"ovlm.lab-result/1", scenario, verdict:"pass|fail|inconclusive", ovlm_commit, openstack_release, kolla_version, virt_type:"qemu|kvm", started, finished, steps:[…], assertions:[{id, ok, observed, expected}]}` |
| `assertions` | Machine-checked invariants (marker SHA, counter, attachment count, FIP port) with raw observed values |
| `openstack/{before,after}.json` | Listings (server/volume/FIP/port) with `--long`; secrets never captured |
| `ovlm/{audit,workflow-tables}.jsonl`, `worker.log` | Redacted; canary check run over the bundle |
| `timeline.csv` | Event timestamps; downtime computed from external probe (1 s interval) |
| `SHA256SUMS`, `ENV.md` | Hashes; lab specs (CPU/RAM/virt type, Cinder backend) |

A claim "X is lab validated on 2026.1" is allowed only if: scenario verdict `pass` for the commit tagged in the
claim; bundle complete and hash-verified; reviewed and signed by a human (name and date in `REVIEW.md`); the claim
states TCG vs KVM and the single-node/LVM limits. A later change to the affected code invalidates the claim until
re-run (the bundle's commit is compared by CI to the touched paths; ASSUMPTION: path-to-scenario map maintained by QA).

## 8. What cannot be tested without a real cloud
| Item | Why | Where it is addressed |
|---|---|---|
| OSI open questions 1–13 (policy defaults, microversion maxima, DVR/OVN FIP behaviour, access rules end to end, down-cell servers, Octavia/Designate) | Behaviour of a specific deployment | Lab only partly (single-node quick-lab has no Octavia/Designate/HA); remaining = production validation |
| Real Cinder attach/detach timing, refusal with mounted fs, backend (Ceph/iSCSI/NFS) behaviour | Backend-specific | Lab covers LVM/iSCSI only; Ceph/NFS = production |
| Virtio serial truncation, udev `by-id`, guest device naming | Guest kernel/QEMU | Lab (LAB-11); CI only emulates |
| FIP data-plane downtime, conntrack loss, L3 agent lag | Real network stack | Lab (single node, no HA router) |
| `NoValidHost`, scheduler filters, anti-affinity, real quota counting incl. failed builds | Admin config | Lab partly (LAB-02) |
| `enforce_new_defaults`, Neutron quota `manager` role, admin-set lock semantics | Policy overrides per cloud | Lab can set one config; other clouds = production |
| Timing under real KVM; production-scale inventory (5,000 servers) | TCG slows guests; no scale lab | Not covered; timeouts configurable; performance test deferred (**Later**) |
| Multiple releases, SDK drift against newer Nova (2.101+ 202-attach) | Lab runs 2026.1 only | Contract suite re-run per release candidate |
| Fake fidelity | The fake is what we wrote | Contract suite on fake and lab; `FIDELITY.md` |
| Operator usability (NFR-10), real runbooks | Human judgement | Production validation by a non-author |

## 9. Definition of done, CI, coverage, flakiness

### 9.1 Definition of done per backlog item

A backlog item is done only when **all** apply (extends agent-team.md rule 7):

| # | Criterion |
|---|---|
| 1 | Acceptance criteria written as tests *before/with* the code; each FR/NFR touched maps to ≥ 1 named test (traceability table in `tests/TRACEABILITY.md`, generated from markers `@pytest.mark.req("FR-REN-3")`) |
| 2 | L0 and L1 green; L2 green if the item touches DB, engine, Ansible or migrations; fake extended (and `FIDELITY.md` updated) if it touches OpenStack behaviour |
| 3 | Every new mutating OpenStack step: idempotency test (call twice), crash-point coverage (§4.1.2), ownership-guard test |
| 4 | New route: RBAC matrix row, CSRF/scope tests, audit event test |
| 5 | New secret-bearing field: added to the canary test (S-12) |
| 6 | New migration: up/down/with-data tests, no `alembic check` drift |
| 7 | Error paths tested: each error says what happened, current state, next action (NFR-10), asserted in the test |
| 8 | Docs updated; status label matches the highest level achieved (§2); no "validated" without evidence |
| 9 | Review recorded (security agent for items listed in §6; QA review for engine items) |
| 10 | Bugs found: regression test first, fix second, test named after the bug id |

### 9.2 CI pipeline stages
| Stage | Contents | Trigger | Blocking |
|---|---|---|---|
| 1 Static | ruff, mypy, import-linter (adapter boundary), `ansible-lint`, `yamllint`, `--syntax-check`, DCO check, lock-file hash check, doc link/status-vocabulary check | push | yes |
| 2 Unit | pytest L1 incl. crash-point matrix (in-process), property tests, coverage report | push | yes |
| 3 Integration | Compose: PostgreSQL, Alembic, ansible-runner + container target, L2 crash/fencing/concurrency, `ovlm-counter` role tests, E2E-with-fake | PR | yes |
| 4 Security & supply chain | pip-audit, bandit, Trivy/Grype image scan, secret scan, container hardening asserts, S-tests not already run | PR | yes (high/critical) |
| 5 Build | Image build, SBOM (V1), smoke start of `api` + `worker` | PR/merge | yes |
| 6 Lab (manual) | Provision/use quick-lab, run contract suite + §7 scenarios, collect evidence | release candidate; nightly later | gates the release label, not PRs |

Timing budget (ASSUMPTION, measure after first implementation): stage 2 < 2 min, stage 3 < 15 min; if exceeded,
split by marker, never by dropping tests. Actions pinned by SHA (security-model §9).

### 9.3 Coverage policy

- Coverage is reported (line + branch) and **diffs must not drop** on touched modules; there is no global percentage target and no
  gate on a vanity number.
- Required instead: 100 % of **engine steps** have crash-point and idempotency tests (enforced by the enumeration test,
  §4.1.2); 100 % of **routes** appear in the RBAC matrix; 100 % of **mutating adapter methods** have an ownership-guard
  test; each **error class** has a classification test. These are structural checks, not percentages.
- Mutation testing (`mutmut`/`cosmic-ray`) run periodically (not per PR) on the engine, approval-hash and ownership-guard
  modules; surviving mutants there are bugs in the tests.
- Coverage from the fake is never cited as evidence of OpenStack behaviour.

### 9.4 Flaky-test policy
| Rule | Detail |
|---|---|
| Zero tolerance for sleeps | Use fake clock, `tick()`, polling with deadlines, container health checks; no `time.sleep` in tests except in documented real-process tests (lint-flagged) |
| Quarantine | A test that fails and passes on the same commit is moved within 24 h to `@pytest.mark.quarantine` with an issue (owner, cause hypothesis, 14-day limit). Quarantined tests still run in a non-blocking job and are listed in CI summary |
| Never quarantine | Security tests, crash-point matrix, fencing, data-safety tests: they are fixed or the change is reverted |
| No blind retries | `pytest-rerunfailures` is not enabled globally. A reruns-on-infra-failure (image pull, network) is allowed only in the CI step, logged as such |
| Seeds | Hypothesis and any random data print and fix the seed; failures reproduced with it |
| Quarantine budget | More than 5 quarantined tests, or any older than 14 days, blocks feature merges until reduced |
| Lab | Lab failures are never "flaky": rerun creates a second evidence bundle and both are kept; a pass after a fail is `inconclusive` until the cause is understood |

## 10. Open items
| # | Item | Needs |
|---|---|---|
| 1 | Adapter interface method names; crash-point phase names (§4.1.1 are proposals mapped to ADR-0003) | Implementation **[ALIGN]** |
| 2 | ~~`renewal-workflow.md` §7 says `NoValidHost` green is deleted and `B3` retried, but §8 row 16 and the PM say operator-rollback only and fatal; tests follow the latter~~ **Closed 2026-11-04**: `NoValidHost` is fatal everywhere; green is deleted only by operator rollback (TC); renewal-workflow.md §2.1 B4 and §7 are now consistent with the tests | none |
| 3 | RBAC/CSRF tests parametrize over FastAPI's generated OpenAPI route table (api-design.md) | Confirm no routes outside it |
| 4 | Are privileged containers available in CI (loopback `data_attach` tests)? | Maintainer / CI choice |
| 5 | Evidence bundle storage and who signs `REVIEW.md` | Maintainer |
