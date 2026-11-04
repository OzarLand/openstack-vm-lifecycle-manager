# ADR-0000 — Agent team and model allocation

| Field | Value |
|---|---|
| Status | Accepted (organizational) — pending maintainer approval of the Phase 1 proposal |
| Date | 2026-11-04 |
| Deciders | Agent 1 (PM/EM); maintainer approval required |

## Context

The mission requires ten specialized agent roles and dynamic, cost-aware model selection. The Claude Code `Agent` tool
accepts a per-call model (`haiku`, `sonnet`, `opus`, `fable`), while the main session (Agent 1) is fixed on Opus 5.5.
List prices differ by up to 100× between the cheapest and most expensive model (see
[model-selection-strategy.md](../model-selection-strategy.md)).

The previous OzarLand multi-agent project (openstack-upgrade-journeys, DR-000) found two things. An independent
reviewer on a different model caught issues the authors missed. And a budget stop part-way through forced a reallocation
that broke model diversity.

## Options

1. **One strong model for everything.** Simple, but expensive, with no review diversity.
2. **Fixed model per role.** Predictable, but wastes L3 tokens on mechanical work and under-powers critical tasks of L2
   roles.
3. **Default per role, chosen per task, with an escalation policy (chosen).** The task's risk sets the level, not the
   agent's title. Fable is reserved for independent reviews, and Opus for authoring critical designs.

## Decision

Option 3, with the matrix and escalation policy in [model-selection-strategy.md](../model-selection-strategy.md).

For Phase 0–1, the activated roles were Agent 1 (Opus, main session), Agent 2 (Opus), Agent 3 (Sonnet), Agent 6
(Sonnet), Agents 7 and 8 (Fable, independent reviews), and Agent 9 (Sonnet). Agents 4, 5 and 10 were **not activated**:
there is no code yet, and the README and contribution files are thin enough for Agent 1 to write without starting
another agent.

## Consequences

- Cost is concentrated on the architecture author (Opus) and the two independent reviewers (Fable).
- If a budget limit stops Fable, the reviews are re-run on Opus with a fresh context, and the loss of model diversity is
  recorded here.
- Actual runs are logged in [engineering-report.md](../engineering-report.md).
