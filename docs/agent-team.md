# Engineering agent team

| Field | Value |
|---|---|
| Owner | Agent 1 — Product Manager / Engineering Manager |
| Status | Decided (organizational) — see [ADR-0000](decisions/ADR-0000-agent-team-and-model-allocation.md) |
| Last updated | 2026-11-04 |

OVLM is built by AI agents coordinated by a human maintainer, as in the rest of OzarLand
([how OzarLand is built](https://github.com/OzarLand/ozarland/blob/main/docs/how-ozarland-is-built.md)). Agents write,
review and test. **The maintainer decides, approves scope and merges.**

## How the team runs (orchestration facts)

Inspected on 2026-11-04 in the Claude Code cloud session that produced this document:

| Fact | Consequence |
|---|---|
| Agent 1 (PM/EM) runs as the **main session** on Claude Opus 5.5. The main-session model cannot be changed per task from inside the session. | Agent 1's coordination cost is Opus-priced. Agent 1 delegates heavy reading and writing instead of doing it in the main context. |
| Sub-agents are started with the `Agent` tool, which takes a **per-call model**: `haiku`, `sonnet`, `opus` or `fable`. | Dynamic model selection per task is supported: the same role can use different models for different tasks. |
| A sub-agent starts with **no shared context**: it knows only its prompt and the files it reads. A finished agent can be continued with its context intact. | Briefs are the main token lever. Revisions go back to the same agent instead of to a new one. |
| Sub-agents can run in parallel. They share one working tree. | Parallel only when tasks are independent **and** write disjoint files. File ownership is assigned per task. |
| Per-agent token usage is reported when an agent finishes. No per-agent dollar cost is reported. | The [engineering report](engineering-report.md) records reported tokens and *estimates* cost from list prices, labelled as estimates. |

## Roles, scope and authority

| # | Role | Owns (writes) | Reviews | Authority | Activated when |
|---|---|---|---|---|---|
| 1 | **Product Manager / Engineering Manager** | `product-vision.md`, `functional-requirements.md`, `roadmap.md` (backlog), `agent-team.md`, `model-selection-strategy.md`, progress reports | Every deliverable before it reaches the maintainer | Scope, priority, conflict resolution between agents; can stop any task | Always (main session) |
| 2 | **Chief Software Architect** | `architecture.md`, `data-model.md`, `api-design.md`, `renewal-workflow.md`, ADRs | All code touching module boundaries, the data model or the workflow engine | Owns technical consistency. An architectural change needs Agent 2's review **before** implementation | Design phases; boundary-changing PRs |
| 3 | **OpenStack Specialist** | `openstack-integration.md`, the `ovlm.openstack` adapter design | Every OpenStack call, its permission and its failure modes | Can veto a design that relies on an API behaviour not verified in source or lab | OpenStack-facing work |
| 4 | **Backend Engineer** | `src/ovlm/**` (except UI templates), migrations | — | Implements against agreed contracts only | Phase 2 onwards |
| 5 | **Frontend Engineer / UX** | UI templates and static assets | UX of every operator flow | Implements against the API contract only | Phase 2 onwards (UI tasks) |
| 6 | **Automation Engineer** | `automation-contract.md`, `test-environment.md`, `ansible/` reference workload | Ansible invocation code | Can mark an automation reference "not credible" | Automation and lab work |
| 7 | **SRE / Reliability Engineer** | Reliability sections and review records | Every state-changing workflow step, rollback and recovery design | **Can reject an unsafe lifecycle operation**; the rejection stands until resolved or the maintainer overrides it in writing | All renewal-engine work |
| 8 | **Security Engineer** | `security-model.md` | Authentication, authorization, secrets, credentials, destructive operations, audit | Can block a release on a security finding of severity high | Security-relevant work |
| 9 | **QA / Test Automation Engineer** | `testing-strategy.md`, `tests/**` | Acceptance criteria of every backlog item | A feature is not "done" until QA confirms its tests | Phase 2 onwards; test design in Phase 1 |
| 10 | **Documentation Engineer** | `README.md`, `CONTRIBUTING.md`, guides, `.github/` templates | Doc consistency with the implemented state | Can block a PR whose docs claim an untested state | Doc tasks; release |

## Coordination rules

1. **One owner per file per task.** Two agents never edit the same file concurrently. Agent 1 assigns ownership in each
   brief.
2. **Contracts before code.** Backend and frontend implement against `api-design.md`. Changing a contract needs Agent 2's
   approval.
3. **OpenStack claims are tagged** `SOURCE-VERIFIED`, `LAB-VALIDATED`, `DOCUMENTED-UNVERIFIED` or `ASSUMPTION`, in line
   with the
   [OzarLand evidence rules](https://github.com/OzarLand/openstack-operator-skills/blob/main/shared/evidence-and-safety.md).
4. **State-changing operations get two independent reviews**: SRE (Agent 7) and Security (Agent 8). Both start from the
   artefact, not from the author's reasoning.
5. **Independent review uses a different model from the author** where possible (model diversity), and always a fresh
   context.
6. **Conflicts are resolved explicitly.** Agent 1 records both positions and the decision in an ADR. If an SRE or
   Security veto is overridden, the maintainer's override is recorded.
7. **Definition of done:** code, tests (QA confirmed), docs updated, reviews recorded, status labels correct.
8. **Handoffs are short.** Each agent returns a summary of 25 lines or less, and its detail lives in the file it owns.
   Agent 1 passes summaries, not transcripts.
9. **Only the activated specialists work.** No task activates all ten agents.

## Status vocabulary (used in every document)

| Status | Meaning |
|---|---|
| **Designed** | Described in a document; no code. |
| **Implemented** | Code exists on a branch. |
| **Unit tested** | Automated tests with OpenStack faked pass in CI. |
| **Integration tested** | Tests against real PostgreSQL and a real Ansible run (local container target) pass in CI. |
| **Lab validated** | Run end to end on an OpenStack lab of the stated release; evidence stored. |
| **Production validated** | Confirmed by a human operator, other than the author, on a real platform. |

These map to OzarLand's page statuses: `draft` ≈ designed/implemented, `lab-verified` ≈ lab validated,
`validated` ≈ production validated.
