# SRE code review — workflow engine core (E5-1)

| Field | Value |
|---|---|
| Reviewer | Agent 7 — SRE / Reliability Engineer, independent review (did not read `docs/team-log.md`) |
| Date | 2026-11-04 |
| Branch / commit reviewed | `claude/ovlm-engine` at `c0706f5` (merge-base with `main`: `837aeca`) |
| Files reviewed | `src/ovlm/workflow/{engine,fence,clock,contract,crashpoint,requests,registry,audit,metrics}.py`, `src/ovlm/worker/main.py`, `src/ovlm/db/engine.py`, `src/ovlm/config/settings.py`, `migrations/versions/0002_workflow.py`, `tests/unit/workflow/*`, `tests/integration/workflow/*`, `tests/integration/test_worker_process.py`, `tests/integration/conftest.py` |
| Judged against | ADR-0003 (revised), renewal-workflow.md §5 engine semantics, SRE-R-2/-4/-5/-24/-25/-26/-27/-28 (docs/reviews/sre-review-phase1.md) |
| Method | Code reading with line references, test reading, running the full suite and the static checks, and two throwaway probe tests (written in a scratch worktree, run, deleted; not committed) to confirm the two defects that needed a demonstration |

## 1. Verdict

**Accept with required changes.** No veto. The engine does what ADR-0003 promises on the points that decide
data safety: a stale or paused attempt cannot commit (token + owner + state guard on every write), cannot send a
mutating call after its local deadline (fence gate on a `CLOCK_BOOTTIME` clock, deadline from the send time), a
takeover waits before probing, signals are consumed in the same transaction as their effect, and resource locks
live exactly from admission to the terminal transition. The crash-point matrix is real: every enumerated point
is crashed in-process, seven of them by `os._exit(137)` in a real worker process, plus an external SIGKILL and a
SIGSTOP beyond the lease on a real process.

Three findings must be fixed before the renewal strategy (E5-4) is built on this engine, because the strategy
will rely on the broken behaviour: a signal-driven transition that hits a lock conflict leaves the run in
`needs_human` with **no open step**, so `retry-step` is refused and only `abort` gets out (SRE-C-1, confirmed by
a probe); `mark_resolved` closes the parked step as `succeeded` **without re-probing**, contrary to the design
rule "the engine re-probes before continuing" (SRE-C-2); and a step claimed after its deadline **still acts**
(SRE-C-3, confirmed by a probe). None of the three can corrupt data by itself; all three change what an
operator at 3 a.m. can expect from the buttons the design gives them.

Counts: critical 0 · high 0 · medium 3 · low 7.

## 2. Tests run

| Suite | Command | Result |
|---|---|---|
| Unit | `uv run --frozen pytest tests/unit` | **48 passed**, 1 warning (starlette/httpx deprecation), 4.4 s |
| Integration | `uv run --frozen pytest tests/integration` with `OVLM_TEST_DATABASE_URL` pointing at a local PostgreSQL 16.15 (Docker is not usable in this environment, so the container path of `tests/integration/conftest.py` was not exercised) | **89 passed**, 1 warning, 59.2 s |
| Static | `make lint` (ruff check, ruff format --check, mypy strict, import-linter) | all pass; 2 import contracts kept, 0 broken |
| Review probes (not committed) | two ad-hoc tests in `tests/integration/workflow/` of the scratch worktree | both reproduced the defect they targeted (SRE-C-1, SRE-C-3); file deleted afterwards |

Environment differences from CI: Python 3.13.18 here, 3.12 in CI; PostgreSQL 16.15 here, `postgres:16-bookworm`
in CI. Slowest tests are the two real-process SIGSTOP cases (5.2 s each); the whole integration suite is fast
enough to stay in the PR gate.

## 3. Answers to the review questions

### 3.1 Fencing and leases

**Can a stale or paused worker commit?** No. Every write of an attempt is guarded by
`id = :id AND fencing_token = :tok AND lease_owner = :owner AND state = 'running'`: the intent/evidence
checkpoint (`engine.py:263-280`), the outcome commit which first locks the run row, then the step row with the
same predicate `FOR UPDATE`, and re-applies the predicate on the UPDATE (`engine.py:621-732`), and the heartbeat
(`engine.py:498-512`). A takeover changes both token and owner (`engine.py:404-408`), so a re-issued sequence
value after a DB failover is not enough for a stale commit (SRE-R-4 resolved). Tested by WF-05 three ways,
including a local fence that is deliberately never expired (`test_fencing.py:90-116`).

**Can it issue a mutating call after takeover?** Not after its local deadline. `Fence.check` is called by the
contract before `act` (`contract.py:311`), by every fenced commit, by `ctx.gate` inside step code (the dummy
cloud does this for every PUT, as the WriteClient hook will), and before subprocess spawns per the contract
docstring. A paused process fails its first check on resume because the clock is `CLOCK_BOOTTIME`, which keeps
counting through a host suspend (`clock.py:7-10, 19, 32`): stricter than ADR-0003's "monotonic", and correct.
Tested on a real process with SIGSTOP beyond the lease at two points (`test_fencing.py:142-184`). What remains is
the documented limit: a request *sent* before the deadline can land later; the takeover delay (`engine.py:572-577`,
default 45 s, validated ≥ `fence_margin`) runs **before the probe** (SRE-R-27 resolved) and WF-06 shows the probe
then sees the landed effect (`test_fencing.py:202-228`).

**Is the local deadline measured from when the claim was sent?** Yes. `t_send = clock.monotonic()` is read
before `db.begin()` for the claim (`engine.py:384`) and for every heartbeat (`engine.py:493`), and the deadline is
`t_send + lease − margin` (`fence.py:68`), extended only forward (`fence.py:88`). Because `t_send` precedes even
the pool checkout, the local deadline is strictly earlier than the DB expiry by at least `fence_margin`,
whatever the network delay, and no DB timestamp is ever compared with a worker clock (static test
`test_contract_and_harness.py:190-202`). A 0-row heartbeat revokes immediately (`engine.py:519-525`,
`fence.py:107-111`); a DB error marks ownership unknown and the next gate re-confirms with a synchronous
guarded heartbeat (`fence.py:161-172`). A separate watchdog thread fires revoke callbacks at the deadline even
if the heartbeat thread is stuck on a hung connection (`engine.py:323-329`): good.

**Per-step lease for bounded subprocesses** (SRE-R-5): `Step.lease_for` sets the lease by a guarded heartbeat
before anything is probed or spawned (`engine.py:564-571`); WF-08 shows the step is not claimable meanwhile
(`test_fencing.py:344-361`). The orphan kill itself is E5-3, as stated.

### 3.2 Claim races under SKIP LOCKED

One claimant per step: the CTE locks candidate rows with `FOR UPDATE OF s SKIP LOCKED` and the UPDATE joins it
(`engine.py:389-411`); after commit the row is `running` with a live lease and no longer matches the predicate.
WF-10 races four engines ten times and asserts exactly one claim each round (`test_concurrency_signals.py:49-58`).
Lock ordering is consistent: outcome commit and signal application both lock run then step; claims lock steps
only and read the run without a lock; heartbeat and checkpoint lock the step only. No cycle. Admission is
serialised by a transaction-scoped advisory lock (`engine.py:1020`) with `FOR UPDATE SKIP LOCKED` on the run
row, so a concurrent abort signal on a `requested` run simply makes admission skip that run until the next tick.
Crossed lock sets cannot deadlock because locks are acquired in sorted order (`engine.py:962`), tested 8 rounds.

### 3.3 Signal consumption

Consumed only together with its effect: one transaction locks the signal row (`SKIP LOCKED`, `consumed_at IS
NULL`), the run row and the open step row, applies the effect, then writes `consumed_at`/`outcome`
(`engine.py:1146-1200`). The `signal.apply` crash point sits between effect and consumption and the test proves
both roll back and the signal is re-applied by another worker (`test_concurrency_signals.py:168-184`). Signals
that need a step boundary stay pending while a step runs (`_LeavePending`, rolled back), and `abort` is the one
kind applied mid-step by flag, picked up by the running attempt through the heartbeat's `RETURNING
abort_requested` (`engine.py:504, 526`). Metrics expose the oldest pending signal and overdue count
(SRE-R-24 resolved). Gap: the lock-conflict path inside a signal transition (SRE-C-1).

### 3.4 Resource-lock lifetime

Acquired all-or-nothing in the admission transaction (savepoint; a conflict rejects the run and leaves nothing
behind, `engine.py:1066-1071`, tested), extended in a step's outcome transaction for transition locks
(`engine.py:855-856`, green's server/port at B4), held through crashes, `needs_human` and takeovers (locks belong
to the run, not the worker: `test_concurrency_signals.py:113-136`), and deleted only inside the terminal
transaction `_finish_run` (`engine.py:907-909`) which also cancels open steps. No TTL, by design. Correct.

### 3.5 Crash-point coverage: tested versus claimed

Tested for real:

| Scenario | How | Where |
|---|---|---|
| WF-01 crash at every point | enumeration pinned (25 points incl. `run.create`, `lease.release`); `SimulatedCrash` at each; new worker, lease expiry, oracle (same cloud state, one effect per step, contiguous attempts, fresh tokens, locks released) | `test_crash_matrix.py:34-142` |
| Real process death | `os._exit(137)` at 7 points in a real worker process; external SIGKILL mid-step with heartbeats running | `test_crash_matrix.py:147-215` |
| WF-04 heartbeat thread dies | takeover, old attempt self-fences at its local deadline, revoke callback fired, resumed exactly once | `test_fencing.py:48-84` |
| WF-05 stale commit | DB guard with local fence fooled; stale intent checkpoint refused; SIGSTOP beyond lease then SIGCONT on a real process | `test_fencing.py:90-184` |
| WF-06 in-flight request lands during the takeover delay | probe after the delay sees it, no duplicate | `test_fencing.py:202-228` |
| WF-07 0-row heartbeat; DB unreachable | step stops at once / at local deadline before the DB lease expires | `test_fencing.py:234-299` |
| WF-09 connection loss mid-step, mid-wait, idle | backends terminated; pre-ping reconnects; nothing doubled | `test_fencing.py:315-338` |
| WF-10/11 claim race, duplicate signal, lock conflicts, crossed lock sets, locks across crash | | `test_concurrency_signals.py` |
| Grants | api can only insert `requested` runs and unconsumed signals; worker cannot delete runs or edit signal kinds | `test_engine_basics.py:236-263` |
| Worker loop | slots, sweeper before first claim, draining flag, SIGTERM stop, refuses crash-plan env and non-head schema | `test_concurrency_signals.py:328-359`, `test_worker_process.py` |

Claimed or implied but not tested (SRE-C-8): the `commit_unknown` branch (`engine.py:603-610`) is never executed,
because WF-09 kills backends before the commit and pre-ping reconnects; a COMMIT whose acknowledgement is lost is
not injected. "DB restart" is backend termination, which the test states honestly. Two workers racing on the
same signal row are not raced (only two signals on one run). The `set_lease` path when its synchronous heartbeat
fails is untested. The lock-conflict path of a signal transition (SRE-C-1) has no test, which is how it slipped.
`CLOCK_BOOTTIME` across a real suspend cannot be tested in CI and is not claimed to be.

### 3.6 Timers, backoff, DB-failover assumptions

All persisted times come from the DB clock: `lease_expires_at`, `not_before`, `deadline_at`, `heartbeat_at`
(`engine.py:406-408, 709-712, 939-945`); WF-20 skews the worker wall clock by ten days and the lease is unaffected
(`test_engine_basics.py:208-221`). Poll backoff doubles from `poll_initial` to `poll_max` by attempt number
(`engine.py:804-808`), retry backoff from `retry_backoff_initial` to `retry_backoff_max` by the number of prior
retryable attempts since `retry_floor` (`engine.py:810-824`). Deadline semantics: a timed `Wait` or a retryable
failure committed after `deadline_at` becomes `needs_human(deadline_exceeded)`, never fatal (`engine.py:768-785`),
and retry exhaustion becomes `needs_human(retries_exhausted)` (`engine.py:786-801`, test shows 3 attempts for
`max_attempts=3`). `retry_step` resets the budget and the deadline (`engine.py:1253-1262`). Two gaps: the deadline
is evaluated at commit only, so a late claim still acts (SRE-C-3), and backoff is keyed on the attempt counter,
which takeovers and retries also advance, with no per-step cap (SRE-C-5).

DB failover: the code assumes one PostgreSQL (pool pre-ping, `db/engine.py:13-19`); the only failover-specific
defence is `lease_owner` in every guard, exactly what SRE-R-4 asked for. Nothing in the code can detect a lost
COMMIT; after any DB error the worker treats ownership as unknown until a guarded heartbeat returns a row
(`engine.py:513-518`, `fence.py:102-105, 167-169`). This matches the documented posture (single instance with
backups, or synchronous replication; asynchronous failover unsupported). No finding.

## 4. Findings

Severity: critical / high / medium / low. Lines refer to `claude/ovlm-engine` at `c0706f5`.

| ID | Sev | File:line | Failure scenario | Required change |
|---|---|---|---|---|
| SRE-C-1 | **medium** | `src/ovlm/workflow/engine.py:1297-1298` (strategy signal transition), `:1272-1275` (`mark_resolved`), `:828-850` (`_apply_transition_safely` with `step=None`) | An operator sends `rollback` (or `mark_resolved`) while the run is parked; the strategy answers with a `Transition(next_step=…, acquire_locks=[…])` and one lock is held by another run. `_close_open_step` has already cancelled (or succeeded) the open step; `_apply_transition_safely` catches the conflict but, with `step=None`, only parks the run. Result (**confirmed by probe**): run `needs_human(lock_conflict)` with **no open step**; `retry_step` and `mark_resolved` answer "rejected: no step in needs_human"; the only exit is `abort`, which cancels the run and releases its locks. For a renewal in the window, that is "the operator cannot retry the restore; the only button left destroys the run". The outcome-commit path handles the same conflict correctly because it keeps the step (`:840-849`). | In `_signal_effect`, wrap close-step + transition in a savepoint; on `LockConflict`, roll the savepoint back so the step stays open, set it to `needs_human(lock_conflict)` like the outcome path does, and park the run. Add the engine invariant as a DB check or an assertion in tests: a run in `needs_human` always has exactly one open step. Add the probe above as a regression test. |
| SRE-C-2 | **medium** | `src/ovlm/workflow/engine.py:1271-1276` | `mark_resolved` closes the parked step as `succeeded` on the operator's attestation and calls `defn.next(...)` without running the step's `probe`/`verify`. renewal-workflow.md §6 says "the engine re-probes before continuing". Safety then rests on the *next* step's precondition probe. For the last step of a run (X1 `retire_old`) there is no next step: an operator can mark it resolved and the run completes without the engine ever seeing a 404 for blue. The same holds for any step whose successor does not re-check its predecessor's effect. | Make `mark_resolved` a re-queue of the step like `retry_step` (fresh budget, `retry_floor = attempt`, deadline reset) with the attestation stored in `evidence.mark_resolved`; the new attempt probes and must reach `Done` by itself. If the design wants an explicit bypass for steps that cannot verify, it must be a per-step opt-in (`Step.resolvable_without_probe`) that is `False` for destructive steps, and the audit row must say "verified by operator attestation, not by probe". |
| SRE-C-3 | **medium** | `src/ovlm/workflow/engine.py:532-591` (no deadline check at claim), `:634, :648-650` (`late` computed at commit only); `contract.py:304-314` | A step whose `deadline_at` has already passed is claimed (e.g. after a takeover, or after a long API outage) and runs probe → decide → **act** → verify; only at commit is `late` evaluated, and only `Wait`/retryable outcomes become `needs_human`. **Confirmed by probe**: a `set` step with a deadline one second in the past acted and succeeded. ADR-0003 says `deadline_at` bounds the wait and "deadline reached → needs_human (state unknown)": a late attempt should probe and, if the goal is not already reached, stop without acting, so the operator decides with a current-truth panel instead of the engine acting minutes or hours after the step's budget. For window steps (detach, attach, FIP move) a late act is exactly the "automation acting after its window" the design wanted to exclude. | Return `late` from the claim (`deadline_at <= now()` in `RETURNING`), expose it on the context, and in `run_contract` turn an `Act` decision into `Fail(NEEDS_HUMAN, "deadline passed before acting", needs_human_reason="deadline_exceeded")` when late. `Done` (goal already reached) stays allowed. Add a regression test. |
| SRE-C-4 | low | `src/ovlm/db/engine.py:13-19`; `src/ovlm/config/settings.py:63` | The pool is fixed at 5 + 5 overflow while `worker.slots` may be 64. Each running step has a heartbeat thread plus its own `ctx.read()`/checkpoint connections. Under many slots, or when a strategy author holds `ctx.read()` across network I/O, heartbeats wait on the pool (default `pool_timeout` 30 s, longer than `lease − margin − heartbeat` leaves), fail with `TimeoutError` (an `SQLAlchemyError`, so ownership becomes unknown) and healthy steps self-fence or stall at their next gate. Safe, but a self-inflicted availability failure under load. | Derive the pool from slots (≥ `2 × slots + 4`) or validate `slots` against the pool; set `pool_timeout` below `fence_margin` so a starved heartbeat fails fast and loudly; document in `StepContext.read` that the connection must not be held across network I/O. |
| SRE-C-5 | low | `src/ovlm/workflow/engine.py:804-808` | `_poll_delay` doubles by the step's `attempt` number, which takeovers and retryable failures also advance, and caps only at the global `poll_max` (default 300 s). A window step that forgets `poll_after` polls a 5-second detach at 5, 10, 20, 40 s… and a step taken over twice starts at 20 s. | Add `StepSpec.poll_max` (or clamp the delay to `min(poll_max, remaining deadline / 4)`), and count only consecutive `Wait` outcomes for the backoff exponent (reset on `Act`). The renewal strategy must set `poll_after` for every window step regardless. |
| SRE-C-6 | low | `src/ovlm/workflow/audit.py:37-50`; every `self.audit.record(c, …)` call in `engine.py` | `LogAuditSink` logs the event when `record` is called, inside the open transaction. A rolled-back transaction (lock conflict at admission, `_LeavePending`, a crash before commit) still emits `run.admitted`, `signal.rollback` or `step.outcome` lines. The tests' `RecordingAudit` listens on commit precisely to avoid this (`conftest.py:46-53`); production does not. The log-stream audit mirror (SEC-R-21) must be "after commit". | Make `LogAuditSink.record` attach to the connection's `commit` event (as `RecordingAudit` does) so a line is emitted only for a committed effect; keep the same shape when E3-4 wires the DB sink. |
| SRE-C-7 | low | `src/ovlm/workflow/engine.py:733-762` then `:840-850` | On a lock conflict in the outcome transition the step row is set to `needs_human`, but the attempt row (`outcome = 'succeeded'`) and the audit row (`step.outcome … state succeeded`) written moments earlier in the same transaction stay as they are. The operator sees a step "succeeded" that is parked. | In the conflict branch, update the attempt row to `outcome = 'parked'` and record a `step.parked` audit event with the conflicting lock and holder (the `LockConflict` has both). |
| SRE-C-8 | low | `tests/integration/workflow/test_fencing.py:315-338` (WF-09), `engine.py:603-610` | Untested paths listed in §3.5: `commit_unknown` (lost COMMIT acknowledgement), two workers racing one signal row, `set_lease` heartbeat failure, SRE-C-1's conflict path. | Add: a crash point `outcome.before_commit` whose action terminates the worker's own backend (`pg_terminate_backend` from another connection) so the COMMIT raises and the branch runs, then assert the next attempt re-probes and nothing doubles; a `_race(2, …)` on `process_signals` for one signal; a `set_lease` test with the worker role set `NOLOGIN` at that moment; the SRE-C-1 regression. |
| SRE-C-9 | low | `src/ovlm/workflow/engine.py:323-329` | The watchdog thread polls the fence every ≤ 50 ms per running step (real time, to serve the fake clock). At 64 slots that is ~1,300 wakeups per second for a check that only matters near the deadline. | Poll at `min(remaining / 2, 1.0)` with a floor of 50 ms only when the clock is a `FakeClock` (or make the interval an `EngineConfig` field the tests set). |
| SRE-C-10 | low | `src/ovlm/worker/main.py:357-374` (`register_worker`), `migrations/versions/0002_workflow.py:280` | `worker_heartbeat` rows are never deleted: the `GRANT DELETE` exists but no code uses it, so every restart leaves a row with a new `worker_id`, and a readiness check that looks at "any worker seen recently" could be satisfied by a dead worker's row forever if it is implemented as a max over rows. | Add a sweeper that deletes rows with `last_seen_at < now() − k × heartbeat_interval` and define `/readyz` as "at least one row younger than k × interval". |

Deviations from the design that the implementer reported and that I accept: one *open* step per run (stricter
than "one running"); `CLOCK_BOOTTIME` instead of `CLOCK_MONOTONIC`; the audit sink is a log hook until E3-4;
WF-09 is backend termination rather than a server restart.

## 5. Required before E5-4 builds on this engine

SRE-C-1, SRE-C-2, SRE-C-3, each with a regression test. The rest can land with E5-4 or as follow-ups. No change
to the DB schema is needed for the three.

## 6. Note on where this review is committed

Agent 1 asked for this file on a new branch `claude/ovlm-sre-review-engine` created from `main`. The standing rule
of this review session allows pushes to `claude/ovlm-sre-review` only, so the file is committed there; it is one
commit touching one file and can be cherry-picked or the branch rule relaxed by the maintainer.

> Decision support only. State-changing steps above require approval by the
> accountable owner and should be executed under your change process.
