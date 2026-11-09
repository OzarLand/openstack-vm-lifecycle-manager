# Roadmap and MVP backlog

| Field | Value |
|---|---|
| Owner | Agent 1 — Product Manager / Engineering Manager (single source of truth for the backlog) |
| Last updated | 2026-11-09 |
| Authorization | The maintainer said on 2026-11-04: "you must continue until the end of the MVP". Phases 2–6 are authorized. **The MVP is done (2026-11-09)**: lab validated on Felcloud, not production validated ([MVP report](mvp-report.md)). The post-MVP plan below needs the maintainer's go per phase. |

Status vocabulary: **Designed → Implemented → Unit tested → Integration tested → Lab validated → Production
validated**. An item is **Done** only when its tests pass in CI, QA (Agent 9) confirms them, its docs are updated, and
the required reviews are recorded.

## Milestones

| Milestone | Content | Exit criteria |
|---|---|---|
| **M1 — Phase 1 frozen** ✅ 2026-11-04 | Design round 2 closed, reviewers have no open "required before implementation" item | Both review files say "accept" for the items in scope |
| **M2 — Foundation** (Phase 2) ✅ 2026-11-04 (#1) | Runnable skeleton: api + worker + PostgreSQL in Compose, config, logging, health, migrations, CI | `docker compose up` gives a healthy api and worker; CI green |
| **M3 — Inventory** (Phase 3) ✅ | Read-only discovery, managed VM registration, sync | Inventory of a fake cloud in CI; of Felcloud in the lab (read-only) |
| **M4 — Lifecycle** (Phase 4) ✅ | Profiles, policies, deadlines, planning, audit, auth/RBAC/TOTP | CRUD + audit + RBAC tests in CI |
| **M5 — Readiness** (Phase 5) ✅ | Explainable readiness checks | Rule-based levels with evidence, unit tested |
| **M6 — Renewal engine** (Phase 6) ✅ 2026-11-08 | Workflow engine + `bluegreen_fip_v1` + the acceptance scenario | Crash-injection suite green in CI; **acceptance scenario lab validated** on Felcloud (ADR-0007) |
| **MVP** ✅ 2026-11-09 | M1–M6 + operator UI for the MVP pages + install guide | Section 9 acceptance scenario and failure scenarios lab validated, with stored evidence |
| **M7 — Production hardening** | P0 and P1 below: known MVP defects closed, security follow-ups closed, ops basics (paging, backup/restore, upgrade) | Each item Done; LAB-02/03/05..09 lab validated; one independent security and SRE review "accept" for a production pilot |
| **M8 — Production pilot** | One real service renewed on a real (non-lab) cloud by its operators | Status "production validated" for that scope, with evidence |
| **V1** | Scope extensions (P3) | Per item |

## Backlog

Owner numbers refer to [agent-team.md](agent-team.md). "Model" is the default level; the escalation policy is in
[model-selection-strategy.md](model-selection-strategy.md).

### E0 — Phase 1 closure

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E0-1 | Design revision round 2 (decisions M9, SEC-R-11/13/34/35/36, SRE-R-23/24/26, ADR-0006 fallback, readiness before T0) | 2 | Opus | — | Done | Edits merged; list of edits for other owners |
| E0-2 | Apply cross-owner edits | doc-sync | Sonnet | E0-1 | Done | Files consistent |
| E0-3 | Reviewers check their own open items only | 7, 8 | Fable | E0-2 | Done (SRE: accept; Security: accept with conditions) | "Accept" for implementation scope |
| E0-4 | README, CONTRIBUTING, issue/PR templates (OzarLand conventions) | 10 | Haiku | M2 | Done (README with diagrams and screenshots #41) | check_content-style rules: no secrets, statuses honest |

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
| E2-4 | Read-only inventory against Felcloud (lab) | ozar-dev | — | E2-2 | Lab validated (E2-4 evidence) | Evidence stored |

### E3 — Lifecycle (Phase 4)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E3-1 | Auth: local users (argon2id), sessions, CSRF, API tokens, **TOTP for approver/admin**, step-up | 4 | Sonnet | E1 | Integration tested (PR #3) | Security tests from security-model §10 |
| E3-2 | RBAC with project scope, requester sets, separation of duties, "self-approved" flag | 4 | Opus | E3-1 | Integration tested; security review fixes merged (PR #7) | Matrix tests; review by 8 |
| E3-3 | Profiles + immutable versions; policies + bindings + exceptions; deadlines | 4 | Sonnet | E1 | Integration tested (PR #4); lint waivers added by SF-13; automation lint job and repo allowlist still to do | API + unit tests |
| E3-4 | Append-only audit (grants + trigger), mirror to the log stream | 4 | Sonnet | E1-3 | Integration tested (PR #3) | DB-level tests: UPDATE/DELETE refused |
| E3-5 | Renewal planning: upcoming list, advisory quota check, same-service lock | 4 | Sonnet | E3-3, E2 | Integration tested; the quota reading is not collected yet, so the advisory check reports `unknown` (P2-4) | Unit tests |

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
| E5-8 | Worker egress proxy (`HTTPS_PROXY`/`NO_PROXY` for OpenStack and the automation clone, guests always direct) | 6 | Sonnet | E5-3 | Unit tested; not exercised in the Felcloud lab (direct egress) | Unit tests; lab run behind the Felcloud proxy |
| E5-9 | Inventory sync through project connections (worker run, API, periodic), blue host-key scan + human confirmation | 4 | Opus | E5-7 | Integration tested; security review: fit for the lab, IS-1 fix round | Sync and host-key tests; review by 8 |
| E5-6 | Acceptance scenario + failure scenarios on Felcloud (ADR-0007) | 9 + ozar-dev | Sonnet | E5-4 | **Lab validated**: ACC-01d, LAB-04, LAB-01, operator rollback; 24 lab defects fixed (#19–#38) | Evidence stored; status "lab validated" |

### E6 — Operator UI (HTMX)

| ID | Task | Owner | Model | Depends on | Status | Acceptance / tests |
|---|---|---|---|---|---|---|
| E6-1 | Layout, auth pages, TOTP enrolment | 5 | Sonnet | E3-1 | Integration tested (PR #4) | UI tests (HTTP-level) |
| E6-2 | Inventory list + VM details (observed vs desired) | 5 | Sonnet | E2 | Integration tested (PR #4) | |
| E6-3 | Readiness view; renewal plan; approvals with hash inputs and diff | 5 | Sonnet | E4, E5-5 | Integration tested (PR #8) | |
| E6-4 | Run timeline with step evidence, available actions, audit view | 5 | Sonnet | E5 | Integration tested, merged (#8, audit view #27); used on Felcloud | Audit view: scoping, admin-only actions, `run=` trail, pagination, token scope, HTTP-level page test |

### Security follow-ups (before production, not blocking the MVP lab)

| ID | Task | Source | Status |
|---|---|---|---|
| SF-1 | Worker container: no root init holding `DAC_READ_SEARCH`; document `docker compose exec -u ovlm` | CS-6 (Low) | Fixed (`claude/ovlm-security-followups`): tini as PID 1 started after the drop, no `init: true`, healthcheck drops to `ovlm`; entrypoint unit tested as root; the new `make smoke` check was **not run** in the author's sandbox (no Docker): CI runs it |
| SF-2 | Bind `guest_access` (jump host) into the `ssh_key` binding when the jump host is wired into the runner | N-1 (Low) | To do |
| SF-3 | Refuse an application credential when Keystone omits the `unrestricted` field | N-2 (Low) | Fixed (`claude/ovlm-security-followups`) |
| SF-4 | Remove or exclude rejected `ovlm-env-v1` credentials so `ovlm kek status` can reach 0 after rotation | N-3 (Low) | Fixed (`claude/ovlm-security-followups`): excluded from usage and re-wrap, counted apart |
| SF-5 | Signal a direct endpoint rewrite immediately (trigger) or document the up-to-24 h delay | N-4 (Info) | Fixed (`claude/ovlm-security-followups`): statement trigger, `connections_0003` |
| SF-6 | `/readyz` reports an api/worker KEK mismatch | CS-10 (Low, control done) | Optional |
| SF-7 | `managed_vm` insert guard and tombstone, confirmation cleared on fingerprint change, live re-check at the first SSH to blue | IS-1 (Medium) | Fixed (#21, #22) |
| SF-11 | Bind the plan's `resolved.blue` to the `managed_vm` row (server, service, project connection, plan's managed_vm_id) in the live host-key check and at preflight | IS-11 (Medium) | Fixed (#22) |
| SF-12 | Insert guard identifies the api by role membership, not by name | IS-12 (Info) | Fixed (#22) |
| SF-8 | One address rule for the host-key scan and the renewal | IS-3 (Low) | Fixed and verified |
| SF-9 | Fixed reason codes for sync failures shown to viewers | IS-4 (Low) | Fixed and verified |
| SF-13 | Lint waiver API (approver, step-up, audited, per profile version) | automation-contract §9 | Fixed (`claude/ovlm-security-followups`): grant/list/revoke, B6 uses the version's waivers, plan hash binds them, `profiles_0002` |
| AU-1 | Audit `run=` also returns the plan's approvals (G1) and the engine's step events (`step.claim`, `step.outcome`), which today go only to the log stream | Felcloud lab, 2026-11-06 | Fixed (`claude/ovlm-ui1-au1`): `run=` adds the plan's events and every approval of the plan; the worker's `DbAuditSink` writes the engine's events (one row per claim, outcome, park, run transition, signal) into `audit_event`, allowlisted, without the fencing token |
| UI-1 | Show the signed-in user and their roles in every page header (the maintainer was on a run page as approver-a without noticing) | Felcloud lab, 2026-11-06 | Fixed (`claude/ovlm-ui1-au1`): header `approver-a · approver (global)` with "Sign out / switch account"; a role refusal says "Signed in as approver-a (approver). This action needs the operator role." |
| UI-2 | Policies list page, policy detail (current version, bindings, effective windows) and an admin-only edit form that creates a new version through the API's service code; the Felcloud lab needed a hand-written script for weekend windows | Felcloud lab, 2026-11-06 | Fixed (`claude/ovlm-ui2-policy-page`): `/policies`, `/policies/{id}`, `/policies/{id}/edit` and a "Policies" nav entry. The form pre-fills every field (a missing field is refused, never defaulted), sends the ETag as `If-Match` (stale → 409, nothing saved), needs a human admin session and CSRF, and writes the same `policy.update` audit row as the API. It warns that a new version changes the plan hash, shows the open plans and live approvals it would void, and demands the typed policy name when the count is above 0 |
| SF-10 | Host-key confirm hardening (paste, not prefill; optional step-up); `--reissue` audit names the OS user; TOTP key backup in the install guide | IS-2, IS-6, IS-7 | Fixed (`claude/ovlm-security-followups`): UI confirm form (paste, source recorded), `os_user` + `hostname` in the audit, install guide §3a. The optional step-up was not added |

## After the MVP (from 2026-11-09)

Ordered by risk. P0 must be closed before OVLM runs for long periods or on any cloud other than the lab. Sources: the
[MVP report](mvp-report.md) (sections 4 and 6), [HANDOFF](HANDOFF.md) and the reviews.

### P0 — Known MVP defects and gaps

| ID | Task | Source | Status | Acceptance / tests |
|---|---|---|---|---|
| P0-1 | Release the run checkout in the tmpfs `run_root` when a run ends (nothing calls `release()`), and sweep leftovers at start-up | Lab, Z fix review | Integration tested (#43) | Test: run ends → checkout gone; worker memory stable over N runs |
| P0-2 | An OVLM exit when a step's own (pinned) playbook refuses a state the operator has made safe: an audited, approver-only "accept step as done" with attestation, limited to restore steps that change no cloud resource, or a pin bump for restore phases only. Design first (ADR) | D-8b | **Integration tested (#47)**: [ADR-0008](decisions/ADR-0008-accept-step-restore-exit.md) option A, `accept-step` (approver, never the requester; step-up `run.accept_step`, TC of green, attestation), S2 only, restore only, playbook refusals only; OVLM's own fresh read-only probe (cloud + `lsblk` on the by-id device, per-unit state) must show the postcondition; `step_acceptance` (`renewal_0004`, append-only), audit `run.accept_step.*`, metric, badge. `tests/integration/renewal/test_accept_step.py` reproduces D-8 and converges S3–S10 without a manual guest action. Security and SRE review of the change still to do (P1-6) | ADR accepted by SRE and security reviewers; integration test reproducing D-8 converges without a manual guest action |
| P0-3 | Record every downtime interval of a run (window and revert), not only the first | AC (LAB-01b / rollback) | **Integration tested (#44)**: `run_downtime` (`renewal_0003`), window W1→W10/S9 and restore S2→S9, api `downtime` object, run page, metric `{kind}`, audit | Run with a revert after the cutover shows both intervals; metric and UI |
| P0-4 | Contract tests for every phase result field OVLM reads, against the reference roles' real output (AB class of defect) | AB, AD | Unit tested (#46): `tests/unit/test_result_contract.py` pins every facts key OVLM reads to contract 3.7.1, the reference playbooks/roles and the renewal doubles; found and fixed AD (S2 read `marker_checksum`) | Static test fails on any field OVLM reads that no role emits |
| P0-5 | W6 checks the filesystem by label when the profile names it by label (today W6 checks neither UUID nor label in that case; the role already reports `fs_label`) | P0-4 review | **Integration tested (this branch)**: W6 compares `facts.fs_label` with the profile's `label` (a `fs_uuid` profile still compares `facts.fs_uuid` only); a missing or different value parks W6 `needs_human` (`data_attach_mismatch`) before the service starts and the FIP moves; evidence `fs_identity_checked`. Contract 3.3 rule 7 and 3.7.1 (`data_attach.fs_label`, read by W6). W8 gets `expected_fs_uuid` for a `fs_uuid` profile only (the service reports no label). `tests/integration/renewal/test_fs_label.py` | Integration test: label mismatch on green parks W6 |

### P1 — Before a production pilot

| ID | Task | Source | Status |
|---|---|---|---|
| P1-1 | Failure scenarios LAB-02, LAB-03, LAB-05..09 on a real cloud (only integration tested today) | testing-strategy | To do |
| P1-2 | Paging path: sample Prometheus rules wired and documented, `OvlmPostStartFailure` and "needs_human in window" routed | SRE-R-9, architecture §6 | **Done (this branch)**: [`deploy/prometheus/ovlm-alerts.yml`](../deploy/prometheus/ovlm-alerts.yml) (moved from `src/ovlm/renewal/alert_rules.yml`), 7 `page` and 10 `ticket` alerts covering every alert of architecture §6 plus accept-step used (ticket) and restore downtime open > 30 min (page, new gauge `ovlm_renewal_downtime_open_seconds{kind}`, refreshed by the worker through `Registry.metric_refreshers`); [operations.md](operations.md): scrape config, loading, Alertmanager route paging on `severity="page"`, a runbook per alert linking the operator actions. `tests/unit/test_alert_rules.py` checks every metric, label and label value against the code and the runbook anchors, and runs `promtool check rules` / `promtool test rules` (`ovlm-alerts.test.yml`) when promtool is available (`OVLM_PROMTOOL`; the CI unit job installs promtool 2.53.2, checksum pinned). Not lab validated: no deployment has paged from it |
| P1-3 | Backup/restore and upgrade procedure for OVLM itself (PostgreSQL, KEK), tested | SRE review | **Integration tested (this branch)**: [backup-restore-upgrade.md](backup-restore-upgrade.md): what to back up (logical `pg_dump -Fc` with roles for reference; the KEK private key(s) and TOTP key offline, apart; no checkout cache), consistency rules (no backup its keys cannot restore; keep a KEK while a backup needs it; append-only evidence restored, never edited), restore and upgrade procedures, rollback by restore only (no downgrades, PMR-10). Read-only tooling: `ovlm upgrade preflight` (refuses while a run is in phase `window`/`restore` or a downtime interval is open, a database ahead of the release, and with `--worker-stopped` a live worker or leased step) and `ovlm backup check` (KEK ids in use vs the public keys kept, TOTP key decrypts); `make backup`, `make restore`, `make upgrade-preflight`; `deploy/backup/create-database.sql` restores the database privileges `pg_dump` omits. `tests/integration/test_backup_restore.py`: dump → restore → migrate keeps credentials (same KEK decrypts, another does not), audit rows, every trigger/owner/privilege and `fencing_seq`; an older-revision dump migrates to the guards of a fresh install; the preflight refuses during a window. The Make targets are not run in CI (they need the Compose stack); not lab validated |
| P1-4 | SF-2 (jump host binding), SF-6 (`/readyz` KEK mismatch), SF-10 optional step-up on host-key confirm | Security follow-ups above | To do |
| P1-5 | Worker egress proxy checked on a cloud that requires it (E5-8) | E5-8 | To do |
| P1-6 | Independent security and SRE review of the post-MVP code (#31–#49: checkout cache, reprepare exit, AA, AB, checkout sweep, downtime intervals, result contract, accept-step, heartbeat fence, W6 label) | Process | **Review done** (PR #50, [review-post-mvp.md](reviews/review-post-mvp.md): 1 Medium, 5 Low, 4 Info, no High, no vetoed operation). **Fixed, unit and integration tested**: PMR-1 (the accept-step guest probe runs under a total budget `renewal.accept_probe_timeout`, default 20 s: the worker main loop waits at most that long; no second probe of a run while one runs; api 409 `probe-pending`), PMR-2 (a `reprepare-automation` authorization is consumed only by an attempt of its step holding the lease, fenced before the take and the clone; void once its step closed), PMR-3 (the cache sweep removes only OVLM's run entries; a shared or foreign cache directory is refused at start-up and in settings), PMR-6 (a mismatching cached copy is moved aside and recorded; `automation_reprepare` append-only by trigger, `renewal_0005`). **Open**: PMR-4, PMR-5 (Low), PMR-7 to PMR-10 (Info) |
| P1-7 | Install guide for a real cloud (today: evaluation only) | README | To do |

### P2 — Operator experience

| ID | Task | Source | Status |
|---|---|---|---|
| P2-1 | Login redirects back to the requested page | Lab (UX) | To do |
| P2-2 | VM page shows the profile version readiness was assessed against | README screenshots | To do |
| P2-3 | Downtime panel shows a measured value or "not measured", never "0s" | README screenshots | **Integration tested (this branch)**, with P0-3: sub-second shown as "under 0.1s"/"0.4s", no record as "not measured" |
| P2-4 | Collect a quota reading so the advisory quota check can pass or fail (E3-5) | E3-5 | To do |
| P2-5 | Periodic sync scheduling UI | V1 list | To do |

### P3 — V1 scope (not in the MVP)

Scenario B (greenfield), multiple data volumes, boot from volume, other strategies, signed approvals, OIDC, audit hash
chain, Barbican/Vault, the SRE V1 backlog (SRE-R-19..22, including a notification channel SRE-R-20).
