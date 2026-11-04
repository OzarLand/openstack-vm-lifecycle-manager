# ADR-0003 — Workflow engine: PostgreSQL-backed durable step executor

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 2 (Chief Architect); maintainer approval required |

> **Revision 2026-11-04**: fence gate before every mutating call, subprocess spawn and commit, from a local monotonic
> deadline; 0-row heartbeat stops at once (SRE-R-2, SEC-R-26); `lease_owner` in every guard and DB HA posture
> (SRE-R-4); orphan subprocess containment (SRE-R-5); takeover delay for destructive steps (SEC-R-26); the api
> no longer writes run or step state: it inserts runs in `requested` and signals, the worker admits and acts (SEC-R-1).
>
> **Revision 2026-11-04 (round 2)**: signals consumed in the same fenced transaction as their effect (SRE-R-24);
> admission owns the concurrency cap, `requested` is non-terminal and alerted (SRE-R-25); takeover waits, then probes
> (SRE-R-27); thread-safe parent-death signal and token pre-warm outside transactions (SRE-R-28).

## Context

Renewals run for minutes (build, configure) to weeks (retention until retirement), wait on humans (approvals) and on
asynchronous OpenStack operations (server build, volume detach/attach, FIP data plane), and must survive worker and
database restarts without repeating a destructive step blindly (FR-REN-1, FR-REN-3, NFR-2). OpenStack offers **no client
idempotency token** for server create (openstack-integration.md §3, SOURCE-VERIFIED). Constraints: PostgreSQL only, no
broker, no Redis, one image (NFR-1). Scale: 5 concurrent renewals, 500 managed VMs (NFR-9).

## Options

| Option | Why not (or why) |
|---|---|
| Celery + Redis/RabbitMQ | Adds a broker (forbidden by NFR-1). At-least-once task delivery with visibility timeouts; no durable step state, so we would still build run/step tables, leases and fencing ourselves. |
| Temporal (or Cadence) | Excellent durability semantics, but a separate server cluster plus its own persistence, a deterministic-workflow coding model contributors must learn, and an operational burden far above 5 concurrent renewals. |
| APScheduler | A scheduler, not a workflow engine: no step state, leases, fencing or resumable multi-step runs. |
| Postgres job-queue libraries (procrastinate, pgqueuer) | Solve "run a job once", not "resume step 9 of 20 with evidence"; fencing and resource locks would still be ours. Extra dependency for little gain. |
| **Own durable step executor on PostgreSQL** | Small (target: a few hundred lines, fully unit- and crash-tested), same DB, same image, exact semantics we need. |

## Decision

A generic `workflow` module runs **runs** made of **steps**, all state in PostgreSQL, executed by the `worker` process
(same codebase and image as the API). The `workflow` module knows nothing about renewal; strategies (the `renewal`
module) register step handlers. Tables: see [data-model.md](../data-model.md) §8.

### Execution model

| Concern | Mechanism |
|---|---|
| Run / step | `workflow_run` (kind, strategy + version, state, target refs) and `workflow_step` (step_key, seq, state, attempt, lease, fencing token, `not_before`, `deadline_at`, `intent`, `evidence`, error class). Steps are appended as the strategy advances; history is never rewritten. |
| One active step per run | Partial unique index `workflow_step(run_id) WHERE state IN ('running')`. Renewal steps are strictly sequential. |
| Claiming | In one short transaction: `SELECT … FROM workflow_step WHERE (state='ready' AND not_before<=now()) OR (state='running' AND lease_expires_at<now()) ORDER BY not_before LIMIT :n FOR UPDATE SKIP LOCKED`, then `UPDATE … SET state='running', lease_owner=:worker_instance_id, lease_expires_at=now()+:lease, attempt=attempt+1, fencing_token=nextval('fencing_seq')`. Commit, then execute outside any transaction. |
| Lease + heartbeat | `worker_instance_id` is a UUID generated at each process start. Worker extends `lease_expires_at` every `worker.heartbeat_interval` with `UPDATE … WHERE id=:id AND fencing_token=:tok AND lease_owner=:worker_instance_id`. **A heartbeat returning 0 rows stops the step at once** (ownership already lost), not at lease end. Lease length `worker.lease_duration` > several heartbeats (defaults TBD in lab). A step that runs a bounded subprocess (Ansible) claims a lease covering the subprocess hard timeout + kill grace + margin, so no takeover can start a second run on the same VM while an orphan could still be running. |
| Fence gate (self-fencing) | The worker keeps a **local monotonic** fence deadline per step: `t_send + worker.lease_duration − worker.fence_margin`, where `t_send` is the monotonic time at which the successful claim or heartbeat request was *sent* (earlier than the DB's `now()`, so the local deadline is never later than the DB's expiry). It never compares its wall clock with a DB timestamp. The deadline is checked **immediately before every mutating OpenStack call** (request hook on the `WriteClient`'s keystoneauth session, so raw `session.post` paths are covered too, not only wrapper methods), **before every subprocess spawn** (automation module, before `exec`) and before every fenced commit. Past the deadline: the call is refused locally, the Ansible process group gets SIGTERM→SIGKILL (data phases: renewal-workflow.md §5), and the step result is discarded. This holds for a paused process (SIGSTOP, VM freeze, swap): on resume, its first check fails. |
| Takeover delay | A takeover of a step marked `destructive`, or of any step of a run in phase `window` or `restore`, **first** waits `worker.takeover_delay` (≥ the SDK request timeout + `fence_margin`), **then** probes, then acts, so a request the stale worker sent just before its deadline has landed (or timed out) before the probe reads state (SRE-R-27). |
| Takeover | Another worker may claim a step whose lease expired; attempt and fencing token increase. The new attempt **always starts with a probe** (below). |
| Fenced commit | Every write a step makes (`evidence`, `state`, next step, run state, audit rows) is one transaction guarded by `WHERE id=:id AND fencing_token=:tok AND lease_owner=:worker_instance_id AND state='running'`. 0 rows ⇒ the worker lost ownership and discards its result. A stale worker can never commit, even if a DB failover re-issued a `fencing_seq` value (SRE-R-4). After any lost DB connection the worker treats its ownership as unknown until a guarded heartbeat returns 1 row. |
| Subprocess containment | `ansible-runner` is spawned in its own process group, with its own `--timeout` and `PR_SET_PDEATHSIG` (AS, Linux) so parent death kills it. Because that signal fires when the spawning *thread* exits, each subprocess is spawned from a dedicated thread that lives exactly as long as the child (SRE-R-28 a); the worker runs under a minimal init that forwards signals and reaps (container kill ⇒ children killed). The startup sweeper kills every process group recorded in a run-dir marker **before** the worker claims any step (SRE-R-5). |
| Limit of fencing | OpenStack does not know our token: a stale worker's **in-flight** API call (sent before its fence deadline) can still land. Mitigations: the fence gate (no call is *sent* after the deadline); the takeover delay; one active step per run; every step re-probes; OpenStack attach rejects duplicates and FIP association is a pure state set (openstack-integration.md §3, SOURCE-VERIFIED); server create is found by run tag (ADR-0005). |
| Run admission | The `api` inserts a run only in state `requested` (it has no UPDATE on run or step state, data-model.md §12). The worker admits it in one transaction: re-validates the approval evidence (renewal-workflow.md §3.1), checks `renewal.max_concurrent_runs`, acquires the locks, appends the first step; or moves it to `rejected` with a reason. `requested` is non-terminal (it counts for the one-run-per-service index); a run in `requested` longer than `admission.alert_after` raises an alert (SRE-R-25). |
| Resource locks | `resource_lock(resource_type, resource_key)` primary key; types `service`, `server`, `volume`, `floating_ip`, `port`. Held by a **run**, not a worker: acquired all-or-nothing in sorted order by the worker in the admission transaction (green's server and port in the B4 success transaction), released in the transaction that makes the run terminal. Leases protect execution; locks protect business resources across days of retention. |
| Async OpenStack ops / timers | A step performs its action, records `intent`, and returns `WAIT(poll_after)`: state `waiting`, `not_before=now()+interval` (backoff from `poll.initial_interval` to `poll.max_interval`), lease released. Each re-claim probes; `deadline_at` (step timeout key) bounds the wait. No worker thread blocks on OpenStack. |
| Human waits | Approval and retention steps are `waiting` with no timer (approval) or a far `not_before` (retention). The api records a human decision (approval, abort, rollback, revert, retry-step, mark-resolved, probe) as an `approval` row and/or a `run_signal` row with its audit row; the worker consumes signals (poll every `poll.initial_interval`), re-validates the evidence and moves the step. `run_signal.consumed_at` and `outcome` are written **in the same fenced transaction** as the state change the signal causes (for `abort`, the flag itself); if that transaction does not commit, the signal stays unconsumed and is applied again (idempotent by signal id). Pending signals are shown on the run and alerted after `signal.alert_after` (SRE-R-24). Any network call a transaction depends on (e.g. a Keystone token pre-warm) happens before the transaction opens; only its result is checked inside (SRE-R-28 b). |
| Step contract | Every handler is `probe → decide → act → verify`: (1) read real OpenStack/guest state; (2) if the goal is already reached, record evidence and succeed without acting; if the state is unexpected, classify; (3) persist `intent` (what it is about to do, idempotency key) **before** acting; (4) act once; (5) verify, or `WAIT` and verify on next claim. |
| Error classes | `retryable` (bounded by `retry.max_attempts.<step>` with backoff, then `needs_human`), `needs_human` (run halts, operator chooses retry / rollback / mark-resolved), `fatal` (no retry; strategy decides rollback). |
| Abort | api inserts an `abort` `run_signal`; the worker sets `workflow_run.abort_requested=true`; honoured at step boundaries and by long non-data steps (Ansible `configure` is SIGTERMed). Data-phase steps finish (bounded) before abort applies. |
| Scheduler | Inside the worker: periodic jobs (inventory sync, policy evaluation, lease/run-dir sweepers) are created as single-step runs by whichever worker holds `pg_try_advisory_lock(scheduler)`. No separate process. |
| Concurrency | `worker.slots` concurrent steps per worker; `renewal.max_concurrent_runs` global cap (NFR-9: 5) checked at run start. Multiple worker containers are safe (SKIP LOCKED) but not required. |
| DB outage | Worker retries the connection with backoff; it cannot commit or heartbeat, so the fence gate stops the step at its local deadline. After recovery, the fenced commit decides who owns the step. |
| Upgrades | Runs store `strategy_version`; step keys are stable API. A release must resume `waiting`/`ready` steps of the previous minor version; `running` steps must be drained (worker graceful stop) before migration. |

## Consequences

- No broker, no extra service; backups of PostgreSQL capture all workflow state (NFR-7).
- We own correctness of a small, critical component: it needs crash/restart tests in CI against real PostgreSQL
  (kill -9 worker at every step boundary, DB restart, lease expiry with a paused worker, **SIGSTOP longer than the
  lease then SIGCONT: the resumed worker's mutating call is refused locally**, kill of the worker process only
  mid-`configure`: subprocess group gone before takeover).
- DB HA posture (SRE-R-4): single PostgreSQL instance with backups (MVP default), or synchronous replication
  (`synchronous_commit = on`, sync standby). Failover to an asynchronous replica is **unsupported** for the workflow
  tables; `lease_owner` in the guards limits the damage if it happens anyway.
- Throughput is far beyond NFR-9; polling latency (seconds) is acceptable for operations measured in minutes.
- A stale-worker side effect on OpenStack is limited to a request sent before the local fence deadline; the takeover
  delay and the probe-first step contract make it observable and non-destructive (renewal-workflow.md §5).
