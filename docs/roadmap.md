# Roadmap and MVP backlog

| Field | Value |
|---|---|
| Owner | Agent 1 — Product Manager / Engineering Manager (single source of truth for the backlog) |
| Last updated | 2026-11-05 |
| Authorization | The maintainer said on 2026-11-04: "you must continue until the end of the MVP". Phases 2–6 are authorized. |

Status vocabulary: **Designed → Implemented → Unit tested → Integration tested → Lab validated → Production
validated**. An item is **Done** only when its tests pass in CI, QA (Agent 9) confirms them, its docs are updated, and
the required reviews are recorded.

## Milestones

| Milestone | Content | Exit criteria |
|---|---|---|
| **M1 — Phase 1 frozen** ✅ 2026-11-04 | Design round 2 closed, reviewers have no open "required before implementation" item | Both review files say "accept" for the items in scope |
| **M2 — Foundation** (Phase 2) ✅ 2026-11-04 (#1) | Runnable skeleton: api + worker + PostgreSQL in Compose, config, logging, health, migrations, CI | `docker compose up` gives a healthy api and worker; CI green |
| **M3 — Inventory** (Phase 3) | Read-only discovery, managed VM registration, sync | Inventory of a fake cloud in CI; of Felcloud in the lab (read-only) |
| **M4 — Lifecycle** (Phase 4) | Profiles, policies, deadlines, planning, audit, auth/RBAC/TOTP | CRUD + audit + RBAC tests in CI |
| **M5 — Readiness** (Phase 5) | Explainable readiness checks | Rule-based levels with evidence, unit tested |
| **M6 — Renewal engine** (Phase 6) | Workflow engine + `bluegreen_fip_v1` + the acceptance scenario | Crash-injection suite green in CI; **acceptance scenario lab validated** on Felcloud (ADR-0007) |
| **MVP** | M1–M6 + operator UI for the MVP pages + install guide | Section 9 acceptance scenario and failure scenarios lab validated, with stored evidence |

## Backlog

Owner numbers refer to [agent-team.md](agent-team.md). "Model" is the default level; the escalation policy is in
[model-selection-strategy.md](model-selection-strategy.md).

### E0 — Phase 1 closure

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E0-1 | Design revision round 2 (decisions M9, SEC-R-11/13/34/35/36, SRE-R-23/24/26, ADR-0006 fallback, readiness before T0) | 2 | Opus | — | Done | Edits merged; list of edits for other owners |
| E0-2 | Apply cross-owner edits | doc-sync | Sonnet | E0-1 | Done | Files consistent |
| E0-3 | Reviewers check their own open items only | 7, 8 | Fable | E0-2 | Done (SRE: accept; Security: accept with conditions) | "Accept" for implementation scope |
| E0-4 | README, CONTRIBUTING, issue/PR templates (OzarLand conventions) | 10 | Haiku | M2 | To do | check_content-style rules: no secrets, statuses honest |

### E1 — Foundation (Phase 2)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E1-1 | Repo layout, `pyproject`, pinned deps, lint (ruff), type check (mypy), pytest | 4 | Sonnet | — | Integration tested, merged (#1) | CI job green |
| E1-2 | Settings (pydantic-settings, secrets from files), structured JSON logging with correlation IDs | 4 | Sonnet | E1-1 | Integration tested, merged (#1) | Unit tests; no secret in logs (test) |
| E1-3 | PostgreSQL via SQLAlchemy 2 + Alembic, split DB roles `ovlm_owner` / `ovlm_api` / `ovlm_worker` with grants | 4 | Sonnet | E1-1 | Integration tested, merged (#1) | Migration test on real PostgreSQL in CI |
| E1-4 | FastAPI app skeleton, `/healthz`, `/readyz`, `/metrics`; worker process skeleton with a heartbeat | 4 | Sonnet | E1-2, E1-3 | Integration tested, merged (#1) | Integration test in Compose |
| E1-5 | Docker image (non-root, two OS users), Compose file, Makefile | 4 | Sonnet | E1-4 | Integration tested, merged (#1) | `docker compose up` healthy in CI |
| E1-6 | GitHub Actions CI (actions pinned to SHA, as in OzarLand) | 4 | Sonnet | E1-1 | Done: CI green on #1 | Green on the working branch |
| E1-7 | Reference workload `ovlm-counter`: Ansible role and phase playbooks per the automation contract | 6 | Sonnet | — | Implemented; CI Ansible job added (PR #4) | `ansible-lint`, syntax check, run against a local container in CI |
| E1-8 | openstack-quick-lab: opt-in Cinder (LVM) option, run once, then proposed upstream | 6 + ozar-dev | Sonnet | — | Dropped (ADR-0007: lab on Felcloud) | quick-lab deploys with Cinder; upstream issue filed with evidence |

### E2 — Inventory (Phase 3)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E2-1 | OpenStack adapter interface; read client (GET/HEAD-only guard) and a hand-written fake | 3 → 4 | Sonnet | E1 | Integration tested (PR #3) | Fake models async states and the observed gotchas |
| E2-2 | Inventory sync job (worker), snapshots, `gone` handling, Nova changes-since | 4 | Sonnet | E2-1 | Integration tested (PR #3) | Unit tests with the fake |
| E2-3 | Managed VM registration and services | 4 | Haiku | E2-2 | Integration tested (PR #3) | API tests |
| E2-4 | Read-only inventory against Felcloud (lab) | ozar-dev | — | E2-2 | To do | Evidence stored |

### E3 — Lifecycle (Phase 4)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E3-1 | Auth: local users (argon2id), sessions, CSRF, API tokens, **TOTP for approver/admin**, step-up | 4 | Sonnet | E1 | Integration tested (PR #3) | Security tests from security-model §10 |
| E3-2 | RBAC with project scope, requester sets, separation of duties, "self-approved" flag | 4 | Opus | E3-1 | Integration tested; security review fixes merged (PR #7) | Matrix tests; review by 8 |
| E3-3 | Profiles + immutable versions; policies + bindings + exceptions; deadlines | 4 | Sonnet | E1 | Integration tested (PR #4); automation lint job, waivers and repo allowlist still to do | API + unit tests |
| E3-4 | Append-only audit (grants + trigger), mirror to the log stream | 4 | Sonnet | E1-3 | Integration tested (PR #3) | DB-level tests: UPDATE/DELETE refused |
| E3-5 | Renewal planning: upcoming list, advisory quota check, same-service lock | 4 | Sonnet | E3-3, E2 | To do | Unit tests |

### E4 — Readiness (Phase 5)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E4-1 | Check framework (versioned checks, pass/fail/unknown/n-a, severity, evidence, recommendation) and level rules | 4 | Sonnet | E3-3 | Integration tested (PR #7) | Unit tests per rule |
| E4-2 | MVP checks: data separation, automation pinned, strategy applicability (FIP, single volume, image boot), health check defined, volume type explicit | 4 | Sonnet | E4-1 | Integration tested (PR #7) | Unit tests |

### E5 — Renewal engine (Phase 6)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E5-1 | Workflow engine core: runs/steps, SKIP LOCKED claims, leases, fencing (local deadline), resource locks, signals, timers | 4 | **Opus** | E1 | Integration tested; SRE review fixes merged (PR #7) | WF-01..WF-20 crash-injection suite; review by 7 |
| E5-2 | OpenStack write client with ownership guard and write allowlist | 4 | Opus | E2-1, E5-1 | Integration tested; security review fixes merged (PR #7) | Tests: untagged/unregistered target refused; review by 8 |
| E5-3 | Automation runner (ansible-runner subprocess, per-run dir, `ovlm.result/1`, redaction, restricted artefact store, lint) | 6 | Sonnet | E1-7, E5-1 | Integration tested (PR #7) | Integration test against a local container |
| E5-4 | `bluegreen_fip_v1` steps B1–X1, W1–W10, S1–S10 per renewal-workflow.md | 4 | Opus | E5-1..3 | Integration tested, reviewed, fixes verified (PR #8) | Unit tests with the fake per step and per failure row; reviews by 7 and 8 |
| E5-5 | Gates G1–G3, approval evidence re-validation, typed confirmation | 4 | Opus | E3-2, E5-4 | Integration tested, reviewed (PR #8) | Security tests |
| E5-7 | Encrypted credential store and project connections (envelope AES-GCM, worker-only unsealing, Keystone application credentials) | 4 | Opus | E5-2 | Integration tested; reviewed (CS-1..CS-10), fixes verified; CS-6 open | Binding and role tests; review by 8 |
| E5-8 | Worker egress proxy (`HTTPS_PROXY`/`NO_PROXY` for OpenStack and the automation clone, guests always direct) | 6 | Sonnet | E5-3 | Unit tested; lab check pending | Unit tests; lab run behind the Felcloud proxy |
| E5-6 | Acceptance scenario + failure scenarios on Felcloud (ADR-0007) | 9 + ozar-dev | Sonnet | E5-4 | To do | Evidence stored; status "lab validated" |

### E6 — Operator UI (HTMX)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E6-1 | Layout, auth pages, TOTP enrolment | 5 | Sonnet | E3-1 | Integration tested (PR #4) | UI tests (HTTP-level) |
| E6-2 | Inventory list + VM details (observed vs desired) | 5 | Sonnet | E2 | Integration tested (PR #4) | |
| E6-3 | Readiness view; renewal plan; approvals with hash inputs and diff | 5 | Sonnet | E4, E5-5 | Integration tested (PR #8) | |
| E6-4 | Run timeline with step evidence, available actions, audit view | 5 | Sonnet | E5 | Integration tested (PR #8) | |

### Security follow-ups (before production, not blocking the MVP lab)

| ID | Task | Source | Status |
|---|---|---|---|
| SF-1 | Worker container: no root init holding `DAC_READ_SEARCH`; document `docker compose exec -u ovlm` | CS-6 (Low) | To do; verify with `make smoke` |
| SF-2 | Bind `guest_access` (jump host) into the `ssh_key` binding when the jump host is wired into the runner | N-1 (Low) | To do |
| SF-3 | Refuse an application credential when Keystone omits the `unrestricted` field | N-2 (Low) | To do |
| SF-4 | Remove or exclude rejected `ovlm-env-v1` credentials so `ovlm kek status` can reach 0 after rotation | N-3 (Low) | To do |
| SF-5 | Signal a direct endpoint rewrite immediately (trigger) or document the up-to-24 h delay | N-4 (Info) | To do |
| SF-6 | `/readyz` reports an api/worker KEK mismatch | CS-10 (Low, control done) | Optional |

### Later (V1, not in the MVP)

Scenario B (greenfield), multiple data volumes, boot from volume, other strategies, signed approvals, OIDC, audit hash
chain, periodic sync scheduling UI, Barbican/Vault, the SRE V1 backlog (SRE-R-19..22).
