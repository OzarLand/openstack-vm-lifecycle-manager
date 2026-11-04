# Functional and non-functional requirements

| Field | Value |
|---|---|
| Owner | Agent 1 — Product Manager (functional), Agent 2 — Chief Architect (non-functional) |
| Status | **Designed** (Phase 1 proposal) |
| Last updated | 2026-11-04 |

Priority: **MVP** is needed for the first end-to-end acceptance scenario. **V1** completes the first public release.
**Later** is designed for, but not built.

## User journeys

### J1 — "Which of my VMs could I replace?" (Scenario A, read-only)

1. The operator configures a **read-only** OpenStack credential for one project.
2. OVLM synchronizes the inventory: servers, volumes, attachments, ports, floating IPs, images and flavors.
3. The operator sees each VM's age, image, attached volumes and whether its root disk holds data that matters.
4. The operator **registers** the VMs worth managing and groups them by service.

### J2 — "What is missing before I can renew this VM?"

1. The operator (or workload owner) creates a **profile**: desired flavor, image, network, data volumes, Ansible
   reference and health check.
2. OVLM runs a **readiness assessment**. It compares the profile with the observed VM and checks the automation
   evidence.
3. The result is a level (`not-ready` / `partially-ready` / `ready`). Each check shows pass, fail or unknown, with
   evidence, and the result lists **blockers** and **recommendations**.
4. The workload owner fixes the blockers (for example, moves data to a Cinder volume, or pins the Ansible ref) and
   reassesses.

### J3 — "Renew this VM, safely"

1. A lifecycle policy marks the VM as due (maximum age reached, or renewal window open).
2. The operator plans the renewal. OVLM checks the prerequisites: readiness, quota headroom, no conflicting run, and a
   policy window.
3. The approver approves the plan. Where policy requires it, a second approval is needed before cutover.
4. The engine provisions the replacement, configures it, hands over the data volume, runs health checks, cuts over and
   keeps the old VM.
5. After the retention period and a final approval, the old VM is retired.
6. At any point the operator can see the current step, its evidence and the audit trail. A failure stops the workflow
   in a known state, with a rollback or resume action.

### J4 — "New service, managed from day one" (Scenario B, later)

The first instance is created from a profile with no previous VM. Planned after the brownfield MVP.

## Functional requirements

### FR-INV — Inventory

| ID | Requirement | Priority |
|---|---|---|
| FR-INV-1 | Discover servers, volumes and attachments, ports, fixed and floating IPs, security groups, networks, images and flavors for each configured project, through openstacksdk. | MVP |
| FR-INV-2 | Inventory uses read-only API calls only. It must work with a credential that has no write permission. | MVP |
| FR-INV-3 | Store observed state as snapshots with a sync timestamp. Mark resources that disappear as `gone`; do not delete them from history. | MVP |
| FR-INV-4 | Detect drift between a registered VM's profile (desired) and its observed state. | V1 |
| FR-INV-5 | Several projects and clouds, each with its own credential. | V1 |
| FR-INV-6 | Scheduled synchronization (periodic) plus on-demand. | MVP (on demand), V1 (periodic) |

### FR-REG — Managed VM registration and profiles

| ID | Requirement | Priority |
|---|---|---|
| FR-REG-1 | Register an observed server as a **managed VM**, linked to a **service** (the long-lived identity that outlives VMs). | MVP |
| FR-REG-2 | A **profile** describes desired state: flavor, image (resolved at **plan** time and included in the plan hash), networks and ports, security groups, data volume (by Cinder ID, mounted in the guest by filesystem UUID or label, never by device name), guest access (SSH user, host-key policy), automation reference (commit SHA), health check, cutover method and renewal strategy. | MVP |
| FR-REG-3 | Profiles are versioned. A renewal records the profile version it used. | MVP |
| FR-REG-4 | Desired state (profile) and observed state (inventory) are stored and displayed separately. | MVP |
| FR-REG-5 | Application dependencies and required external services are declared in the profile (free-form plus typed endpoint checks). | V1 |

### FR-POL — Lifecycle policies

| ID | Requirement | Priority |
|---|---|---|
| FR-POL-1 | Policy fields: maximum VM age, renewal interval, allowed renewal windows (weekday and time ranges, time zone), approval requirements (plan, cutover, retirement), retention period of the replaced VM. | MVP |
| FR-POL-2 | A policy attaches to a service group or a single service. The most specific policy wins, and the effective policy is displayed. | MVP |
| FR-POL-3 | **Exceptions**: a time-boxed waiver with reason, owner and expiry. Expired exceptions stop applying automatically. | V1 |
| FR-POL-4 | No global default lifetime is imposed. A service without a policy is never "due". | MVP |
| FR-POL-5 | Compute the renewal deadline per managed VM: launch time + maximum age, adjusted to the next allowed window. | MVP |

### FR-RDY — Rebuild readiness

| ID | Requirement | Priority |
|---|---|---|
| FR-RDY-1 | Run named, versioned checks in five categories: configuration reproducibility, persistent data separation, dependencies, validation capability, external services. | MVP (first four, minimal) |
| FR-RDY-2 | Each check returns `pass` / `fail` / `unknown` / `not-applicable`, a severity (`blocker` / `warning` / `info`), its evidence and a recommendation. | MVP |
| FR-RDY-3 | The readiness level is derived by **explicit rules**: any failed blocker gives `not-ready`, any unknown blocker gives at most `partially-ready`, otherwise `ready`. No opaque weighted score. A count summary (for example "7/9 checks pass") is shown for orientation only. | MVP |
| FR-RDY-4 | Assessments are stored with their check versions and input snapshot, and are never overwritten. | MVP |
| FR-RDY-5 | Some checks need a human attestation (for example "no data is written outside /srv/data"). An attestation records who and when, and expires. | V1 |

### FR-PLN — Renewal planning

| ID | Requirement | Priority |
|---|---|---|
| FR-PLN-1 | List upcoming renewals by deadline, with readiness level and blockers. | MVP |
| FR-PLN-2 | Capacity pre-check against project quotas and absolute limits for the temporary extra VM. The check is **advisory**: real free capacity (hypervisors, Placement) is visible only to admins, and Neutron quota needs the `manager` role, which OVLM does not request ([openstack-integration.md](openstack-integration.md)). | MVP |
| FR-PLN-3 | Detect conflicts: another renewal of the same service in progress, renewals that overlap in the same window in the same project and exceed quota, and declared dependencies renewed at the same time. | V1 (MVP: same-service lock and quota only) |
| FR-PLN-4 | Schedule a renewal in a policy window; request approval. | MVP (manual start after approval), V1 (scheduled start) |

### FR-REN — Renewal engine

| ID | Requirement | Priority |
|---|---|---|
| FR-REN-1 | Execute the renewal as a durable, step-by-step workflow (state machine in [renewal-workflow.md](renewal-workflow.md)). | MVP |
| FR-REN-2 | One strategy in the MVP: **blue/green with data-volume handoff and floating IP cutover** ([ADR-0004](decisions/ADR-0004-mvp-renewal-strategy.md)). MVP scope limits: at most **one** data volume (or a stateless service), the replacement boots from an image (not from a volume), the service must be reached through a floating IP, and no temporary floating IPs are used. The strategy interface allows rolling, stop-and-rebuild and manual-assisted later. | MVP |
| FR-REN-3 | Every step is idempotent and resumable after a worker or database restart. Before acting, it checks the real OpenStack state. | MVP |
| FR-REN-4 | Approval gates: before start (plan), **before the downtime window** (gate G2, placed before quiesce of the old VM; it is also the cutover gate, and there is no gate inside the window), and before retirement, as the policy requires. | MVP |
| FR-REN-5 | Rollback is available from every step up to and including cutover, and converges to the old VM serving again. After cutover, until retirement, a "revert" action does the same. Stuck volume states, admin-set locks and down compute hosts cannot be resolved by OVLM's credentials: the run stops and asks a human OpenStack admin. | MVP |
| FR-REN-6 | Destructive steps (detach of the production data volume, cutover, deletion of the old VM) are clearly labelled. Each requires an explicitly authorized actor and the write credential. **Ownership guard:** before every mutating call, the target must be registered in the OVLM database **and** carry the OVLM tag. Each approval is bound to a hash of plan, profile version, automation commit SHA and target IDs, so a changed plan voids it. | MVP |
| FR-REN-7 | The old VM is retained (stopped) for the policy's retention period and deleted only after approval. It is locked **only after** the data volume has left it, and OVLM unlocks it before any revert: a locked server rejects attach, detach and start from a non-admin. | MVP |
| FR-REN-8 | An operator can pause a run, resume it, or abort it into rollback. Abort takes effect at the next step boundary. A data-phase Ansible run (quiesce, data attach) is never interrupted midway. | MVP (abort and resume), V1 (pause) |

### FR-AUD — Audit

| ID | Requirement | Priority |
|---|---|---|
| FR-AUD-1 | Append-only audit log: actor, action, target, before/after, result, correlation ID (workflow run). Before/after values come from an **allowlist of fields**; secrets are never written, rather than redacted afterwards. | MVP |
| FR-AUD-2 | Covers: registration, profile and policy changes, assessments, plans, approvals, every workflow step attempt, failures, manual recovery actions and credential changes (metadata only). | MVP |
| FR-AUD-3 | Exportable (JSON lines) for an external SIEM. | V1 |

### FR-UI — Operator interface

| ID | Requirement | Priority |
|---|---|---|
| FR-UI-1 | Pages: dashboard (counts, upcoming renewals, runs needing attention), inventory list and VM details (observed vs desired), profiles, policies, readiness results, renewal plan, run timeline with step evidence, audit. | MVP (inventory, VM details, readiness, run timeline), V1 (the rest) |
| FR-UI-2 | Every destructive action shows its blast radius and needs a typed confirmation: the VM name **plus the last 6 characters of its server ID**, because Nova names are not unique. The check is done on the server side, and the API requires the same field. | MVP |
| FR-UI-3 | A REST API with the same capabilities: the UI offers nothing the API lacks, and CI checks it. **Exception:** approvals and destructive confirmations are accepted only from an interactive human session that re-authenticated recently, never from an API token or an automated agent ([security-model.md](security-model.md)). | MVP |

## Non-functional requirements

| ID | Area | Requirement |
|---|---|---|
| NFR-1 | Simplicity | Modular monolith: one codebase, one container image, two process roles (api, worker), PostgreSQL. No message broker, no Redis, no Kubernetes. |
| NFR-2 | Reliability | Workflow state is in PostgreSQL. A worker crash at any point leaves a resumable run. No step runs twice concurrently: lease plus row lock, and a **fencing token** so a stale worker cannot commit. OpenStack side effects themselves cannot be fenced, so every step probes the real state before acting. |
| NFR-3 | Idempotency | Every OpenStack-mutating step is "observe, then act if needed, then verify". Resources created by OVLM carry ownership metadata (run ID) so retries find instead of re-create. |
| NFR-4 | Security | Separate read-only and write credentials; secrets encrypted at rest and never logged; RBAC roles `viewer`, `operator`, `approver`, `admin`, scoped per project; separation of duties (a requester cannot be the only approver), configurable for plan and cutover gates only; **retirement can never be self-approved**. The `api` process never calls OpenStack and cannot decrypt secrets. |
| NFR-5 | Auditability | All state changes are audited (FR-AUD). Audit rows are append-only at the database permission level. |
| NFR-6 | Observability | Structured JSON logs with run and step correlation IDs, Prometheus metrics endpoint, health and readiness endpoints. |
| NFR-7 | Recoverability | Backup and restore of the PostgreSQL database documented and tested. An OVLM outage never affects running workloads. |
| NFR-8 | Portability | Supported OpenStack: the releases the lab tests (2026.1 first). openstacksdk pinned; microversions negotiated and recorded. |
| NFR-9 | Scale target (V1) | 5,000 inventoried servers and 500 managed VMs per installation; 5 concurrent renewals. Larger scales are not designed for. |
| NFR-10 | Usability | Operators can use every MVP function without reading code. Every error says what happened, what state things are in, and what to do next. |
| NFR-11 | Community | Apache-2.0, OzarLand conventions, English, DCO sign-off, beginner-friendly issues. |
