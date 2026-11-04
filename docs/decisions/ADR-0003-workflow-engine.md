# ADR-0003 — Workflow engine: PostgreSQL-backed durable step executor

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 2 (Chief Architect); maintainer approval required |

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
| Claiming | In one short transaction: `SELECT … FROM workflow_step WHERE (state='ready' AND not_before<=now()) OR (state='running' AND lease_expires_at<now()) ORDER BY not_before LIMIT :n FOR UPDATE SKIP LOCKED`, then `UPDATE … SET state='running', lease_owner=:worker, lease_expires_at=now()+:lease, attempt=attempt+1, fencing_token=nextval('fencing_seq')`. Commit, then execute outside any transaction. |
| Lease + heartbeat | Worker extends `lease_expires_at` every `worker.heartbeat_interval` with `UPDATE … WHERE id=:id AND fencing_token=:tok`. Lease length `worker.lease_duration` > several heartbeats (defaults TBD in lab). A step that runs a bounded subprocess (Ansible) claims a lease covering the subprocess hard timeout + kill grace + margin, so no takeover can start a second run on the same VM while an orphan could still be running. |
| Self-fencing | If a heartbeat fails (0 rows or DB unreachable) and `lease_expires_at − worker.fence_margin` is reached, the worker stops the step locally: no further OpenStack call, Ansible process group SIGTERM→SIGKILL (data phases: see renewal-workflow.md §5). |
| Takeover | Another worker may claim a step whose lease expired; attempt and fencing token increase. The new attempt **always starts with a probe** (below). |
| Fenced commit | Every write a step makes (`evidence`, `state`, next step, run state, audit rows) is one transaction guarded by `WHERE id=:id AND fencing_token=:tok AND state='running'`. 0 rows ⇒ the worker lost ownership and discards its result. A stale worker can never commit. |
| Limit of fencing | OpenStack does not know our token: a stale worker's **in-flight** API call can still land. Mitigations: self-fencing before lease expiry; one active step per run; every step re-probes; OpenStack attach rejects duplicates and FIP association is a pure state set (openstack-integration.md §3, SOURCE-VERIFIED); server create is found by run tag (ADR-0005). |
| Resource locks | `resource_lock(resource_type, resource_key)` primary key; types `service`, `server`, `volume`, `floating_ip`, `port`. Held by a **run**, not a worker: acquired all-or-nothing in sorted order in the transaction that creates the run, released in the transaction that makes the run terminal. Leases protect execution; locks protect business resources across days of retention. |
| Async OpenStack ops / timers | A step performs its action, records `intent`, and returns `WAIT(poll_after)`: state `waiting`, `not_before=now()+interval` (backoff from `poll.initial_interval` to `poll.max_interval`), lease released. Each re-claim probes; `deadline_at` (step timeout key) bounds the wait. No worker thread blocks on OpenStack. |
| Human waits | Approval and retention steps are `waiting` with no timer (approval) or a far `not_before` (retention). The API transition (approve, abort) updates the step in the same transaction as the approval/audit row. |
| Step contract | Every handler is `probe → decide → act → verify`: (1) read real OpenStack/guest state; (2) if the goal is already reached, record evidence and succeed without acting; if the state is unexpected, classify; (3) persist `intent` (what it is about to do, idempotency key) **before** acting; (4) act once; (5) verify, or `WAIT` and verify on next claim. |
| Error classes | `retryable` (bounded by `retry.max_attempts.<step>` with backoff, then `needs_human`), `needs_human` (run halts, operator chooses retry / rollback / mark-resolved), `fatal` (no retry; strategy decides rollback). |
| Abort | `workflow_run.abort_requested=true`; honoured at step boundaries and by long non-data steps (Ansible `configure` is SIGTERMed). Data-phase steps finish (bounded) before abort applies. |
| Scheduler | Inside the worker: periodic jobs (inventory sync, policy evaluation, lease/run-dir sweepers) are created as single-step runs by whichever worker holds `pg_try_advisory_lock(scheduler)`. No separate process. |
| Concurrency | `worker.slots` concurrent steps per worker; `renewal.max_concurrent_runs` global cap (NFR-9: 5) checked at run start. Multiple worker containers are safe (SKIP LOCKED) but not required. |
| DB outage | Worker retries the connection with backoff; it cannot commit, so it self-fences when the lease would expire. After recovery, the fenced commit decides who owns the step. |
| Upgrades | Runs store `strategy_version`; step keys are stable API. A release must resume `waiting`/`ready` steps of the previous minor version; `running` steps must be drained (worker graceful stop) before migration. |

## Consequences

- No broker, no extra service; backups of PostgreSQL capture all workflow state (NFR-7).
- We own correctness of a small, critical component: it needs crash/restart tests in CI against real PostgreSQL
  (kill -9 worker at every step boundary, DB restart, lease expiry with a paused worker).
- Throughput is far beyond NFR-9; polling latency (seconds) is acceptable for operations measured in minutes.
- A stale-worker side effect on OpenStack remains theoretically possible during the self-fencing margin; the
  probe-first step contract makes it observable and non-destructive (see renewal-workflow.md §5).
