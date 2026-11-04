# Model selection strategy

| Field | Value |
|---|---|
| Owner | Agent 1 — Product Manager / Engineering Manager |
| Status | Decided (organizational), revised as evidence comes in |
| Last updated | 2026-11-04 |

**Principle: use the smallest capable model for each task, and keep the strongest models for decisions where mistakes
are expensive. Never trade away security, correctness or reliability for cost.**

## Available models (inspected 2026-11-04)

The orchestration environment's `Agent` tool accepts four models. Prices are Anthropic first-party API list prices from
the Claude API reference bundled with Claude Code (cache dated 2026-10-06). The project runs inside a Claude Code
session, whose billing may differ from API list prices, so **every cost in this project is an estimate**.

| Model | Context | Input $/1M tok | Output $/1M tok | Relative cost (output) | Positioning (from Anthropic's reference) |
|---|---|---:|---:|---:|---|
| Claude Haiku 5.5 (`haiku`) | 1M | 0.10 | 0.50 (≤100K prompt; 0.50 / 2.50 beyond) | 1× | Fastest, cheapest. Extraction, formatting, simple writing. |
| Claude Sonnet 5.5 (`sonnet`) | 1M | 2.00 | 10.00 | 20× | Speed and capability for everyday coding and agent work. |
| Claude Opus 5.5 (`opus`) | 1M | 4.00 | 20.00 | 40× | Default high-capability model; strong reasoning and coding. |
| Claude Fable 5.1 (`fable`) | 1M | 10.00 | 50.00 | 100× | Most capable widely released model: hardest reasoning, long-horizon agentic work. |

What we do **not** know: no benchmark numbers for these models are available in this environment, and none are
invented here. The positioning column paraphrases Anthropic's own reference. OzarLand's previous project
([DR-000 in openstack-upgrade-journeys](https://github.com/OzarLand/openstack-upgrade-journeys/blob/main/journeys/ussuri-to-2026.1/decision-records/DR-000-agent-team-and-model-allocation.md))
recorded that Fable reviews "found issues that the other agents and the architect had missed". That is one observation,
not a measurement.

## Three levels

| Level | Model | Used for |
|---|---|---|
| **L1 — lightweight** | Haiku 5.5 | Inventories of files, formatting, README and doc updates from an agreed outline, simple CRUD code from a spec, boilerplate tests, link and consistency checks |
| **L2 — standard** | Sonnet 5.5 | Feature implementation, OpenStack integration code, source-code investigations, API design drafts, integration tests, Ansible content, UI implementation |
| **L3 — high reasoning** | Opus 5.5 (author) / Fable 5.1 (independent reviewer) | Architecture, workflow engine and state machine, data consistency, security model, failure and recovery design, critical reviews, debugging that L2 failed |

**Why Fable for independent review and not for authorship:** Fable costs 2.5× Opus. Reviews read a bounded artefact and
write a short verdict, so their output is small. That is where the stronger model buys the most per dollar. Using a
different model from the author also gives the review real independence (different blind spots), not just a fresh
context.

## Role-to-model matrix (default per role; the task decides)

| # | Role | Default | Escalate to | De-escalate to | Rationale |
|---|---|---|---|---|---|
| 1 | Product / Engineering Manager | Opus 5.5 (main session, fixed) | — | Haiku for mechanical sub-tasks (delegated) | The main session's model cannot change. Agent 1 limits its own token use by delegating reading and writing. |
| 2 | Chief Software Architect | **Opus 5.5** | Fable 5.1 if a design is rejected twice by reviewers | Sonnet for diagram or doc touch-ups | Architecture and state machine errors are the most expensive to fix later. |
| 3 | OpenStack Specialist | **Sonnet 5.5** (source investigation) | Opus 5.5 for a design decision with data-loss or outage risk | Haiku for listing API fields | Reading openstacksdk and Nova or Cinder source is factual work; the decisions it feeds are reviewed at L3. |
| 4 | Backend Engineer | **Sonnet 5.5** | Opus 5.5 for the workflow engine core and locking | Haiku for CRUD endpoints and schemas from spec | Strong coding; the engine core is L3 because of concurrency. |
| 5 | Frontend Engineer / UX | **Sonnet 5.5** | — | Haiku for templates following an existing pattern | Server-rendered UI; low risk. |
| 6 | Automation Engineer | **Sonnet 5.5** | Opus 5.5 for data-handoff and quiesce logic | Haiku for role skeletons | Ansible plus reasoning about idempotency. |
| 7 | SRE / Reliability | **Fable 5.1** (review) | — | Sonnet for runbook drafting from an approved design | Holds the veto on unsafe operations; must be independent of the Opus architect. |
| 8 | Security Engineer | **Fable 5.1** (review), **Opus 5.5** (authoring `security-model.md`) | — | Sonnet for checklists and dependency audits | Security mistakes are expensive. Reviews use a different model from the author. |
| 9 | QA / Test Automation | **Sonnet 5.5** | Opus 5.5 for interruption and concurrency test design | Haiku for unit-test scaffolding | Efficient coding; failure-scenario design needs more reasoning. |
| 10 | Documentation Engineer | **Haiku 5.5** | Sonnet 5.5 for guides that must explain design trade-offs | — | Writing from agreed sources. Accuracy is checked by the owning agent. |

## Escalation policy

1. Start at the role's default level for the task type (table above).
2. **Escalate one level** when any of these happens:
   - the agent reports low confidence or unverifiable claims on a decision with data-loss, outage or security impact;
   - an independent reviewer rejects the deliverable for reasoning errors (not for missing information);
   - the task needs more than one failed attempt at L2 (for example, a bug L2 could not fix).
3. **Never escalate to fix missing information.** Give the missing file or fact to the same agent instead (continue it
   with its context intact).
4. **De-escalate** mechanical follow-ups (formatting, renaming, applying an agreed fix) to L1.
5. Every escalation is recorded in the [engineering report](engineering-report.md) with its reason.

## Token optimization rules applied

| Rule | How it is applied |
|---|---|
| No whole-repository context | Briefs list the exact files to read. The ecosystem repos are cloned once, and agents get paths, not contents. |
| Concise handoffs | Every agent returns 25 lines or less, and the detail lives in the file it owns. |
| Single source of truth | `architecture.md` for design, `roadmap.md` for the backlog, ADRs for decisions. Agents read these instead of past discussions. |
| No duplicate work | One agent per question. Reviewers review the artefact; they do not redo the design. |
| Parallel only when independent | Wave 1 (OpenStack source investigation; automation and lab) ran in parallel because the files and topics were disjoint. |
| Revisions reuse context | Fixes go back to the authoring agent via continuation, not to a new agent re-reading everything. |
| Reuse validated decisions | Accepted ADRs are not re-debated without new evidence. |
| Cheap models for bulk reading | Haiku for inventories; Sonnet for source reading; L3 only reads distilled documents. |

## Limitations

- The main-session model (Agent 1) is fixed for the session: Opus 5.5.
- Per-agent **effort** (reasoning depth) can be set only when the maintainer asks for it. It is left at each model's
  default.
- All models come from one family. Independence relies on separate contexts and model diversity within the family.
- Token counts per agent are those reported by the platform at completion; main-session tokens are not itemized.
