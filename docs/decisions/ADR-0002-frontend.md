# ADR-0002 — Frontend: server-rendered Jinja2 + HTMX

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 2 (Chief Architect); maintainer approval required |

## Context

OVLM's UI is an operator console: tables (inventory, readiness, plans), detail pages (observed vs desired), a run
timeline that updates while a renewal runs, forms (profiles, policies) and typed confirmations for destructive actions
(FR-UI-1, FR-UI-2). Users are infrastructure operators. Maintainers are a small Python-centric community
(OzarLand, NFR-11). The backend is Python + FastAPI (fixed). FR-UI-3 requires that every UI capability also exists in the
REST API.

## Options

| Criterion | A. Jinja2 templates + HTMX (+ minimal vanilla JS) | B. React (or similar) SPA over the REST API |
|---|---|---|
| Languages / toolchains a contributor needs | Python, HTML, Jinja2 | Python **and** TypeScript, npm, bundler, a component library |
| Build pipeline in the image | none (static files copied) | Node build stage, lockfile with hundreds of transitive packages to audit |
| Live run timeline | HTMX polling of a fragment (`hx-trigger="every Ns"`) — enough for step-level updates | WebSocket/SSE or polling; richer, not needed |
| Authorization | one place: the FastAPI service layer renders only what the role allows | enforced in API, duplicated in UI logic for hiding controls |
| Security surface | server-side rendering with autoescape; session cookie + CSRF token; no token in browser storage | token handling in the browser, CORS, XSS in a larger JS surface |
| Accessibility / no-JS degradation | pages work as plain HTML forms | requires JS |
| Richness ceiling | lower (complex client-side graphs are awkward) | high |
| Dependency churn for a small team | low | high (framework majors, npm advisories) |

## Decision

**Option A.** Server-rendered Jinja2 pages served by the same FastAPI process, progressively enhanced with HTMX
(vendored, version-pinned, no CDN at runtime) and small vanilla JS only where unavoidable (the run timeline is plain HTML refreshed by
HTMX). No Node toolchain in the repository.

To satisfy the intent of FR-UI-3 without the UI calling the REST API over HTTP:

- UI routes (`/ui/...`) and API routes (`/api/v1/...`) are thin adapters over **the same service-layer functions**
  (see [architecture.md](../architecture.md)); authorization and audit happen in the service layer, never in a route.
- A CI test enumerates UI actions and asserts each has a REST equivalent with the same required role.
- The UI never reads the database or OpenStack directly.

## Consequences

- One image, one language; contributors can fix a page without frontend expertise.
- Run timeline refresh is polling (interval = config key `ui.poll_interval`, default TBD); no WebSocket server.
- Rich visualisations (dependency graphs, calendars) are harder; if V1 needs them, a single isolated JS widget may be
  added — a full SPA requires a new ADR.
- A third party can still build its own UI on the REST API.
- FR-UI-3 wording needs a small change (requested from the PM): "the UI offers no capability the REST API lacks".
  Approvals and typed destructive confirmations exist in the API but require an interactive human session with
  step-up re-auth; API tokens cannot perform them (security-model.md §7.2).
- HTMX requests carry the CSRF token via `hx-headers`; CSP forbids inline script (security-model.md §2.3).
