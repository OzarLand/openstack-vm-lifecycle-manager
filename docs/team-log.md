# Team log

The open record of the agent team's work: who was activated, what each agent was asked, what it reported back, and
what needs the maintainer. Agent 1 (PM/EM) updates it after every handoff. Agent reports are copied **verbatim**.

## Roster and status

| # | Role | Model | Status | Output |
|---|---|---|---|---|
| 1 | Product / Engineering Manager | Opus 5.5 (main session) | Active: coordinating | `product-vision.md`, `functional-requirements.md`, `agent-team.md`, `model-selection-strategy.md`, ADR-0000, this log |
| 2 | Chief Software Architect | Opus 5.5 | **Design revision done**: all 6 high findings resolved, merged. $3.26 | `architecture.md`, `data-model.md`, `api-design.md`, `renewal-workflow.md`, ADRs |
| 3 | OpenStack Specialist | Sonnet 5.5 | **Done** (Wave 1): 233,687 tokens, 102 tool calls, 11 min 52 s | `openstack-integration.md` |
| 4 | Backend Engineer | Sonnet 5.5 | **Running**: E1 Foundation (E1-1..E1-6) | `src/`, `tests/`, Compose, CI on `claude/ovlm-backend` |
| 5 | Frontend Engineer / UX | — | Not activated | — |
| 6 | Automation Engineer | Sonnet 5.5 | Wave 1 done. **Running**: E1-7 reference workload `ovlm-counter` | `automation-contract.md`, `test-environment.md` |
| 7 | SRE / Reliability | Fable 5.1 | **Done**: accept with required changes, no veto (0 critical, 3 high, 9 medium, 6 low). $5.70 | `reviews/sre-review-phase1.md` on `claude/ovlm-sre-review` |
| 8 | Security Engineer | Opus 5.5 (author) → Fable 5.1 (review) | Authoring **done**: 115,807 tokens, 11 tool calls, 4 min 34 s. Fable review **done**: accept with required changes (both parts; 6 high in total). $7.17 | `security-model.md` |
| 9 | QA / Test Automation | Sonnet 5.5 | **Done**: `testing-strategy.md`, 20 engine crash scenarios. $1.03 | `testing-strategy.md` on `claude/ovlm-qa` |
| 10 | Documentation Engineer | — | Not activated (Agent 1 writes the README) | — |
| — | **Dev VM session** `ozar-dev` (maintainer's machine) | Opus 5.5 (local) | EXP-01 and EXP-01b done: the floating-IP move takes 1.1–1.3 s, best-case outage about 40 s, ACTIVE ≠ ready, and the console log is unreliable. $4.40 in total. Standing approval for `ovlm-*` on `ozar-lab` saved there by the maintainer | https://claude.ai/code/session_016ti9w2xkWinTeHFRq3zgS3 |

## ✅ Standing authorization (maintainer, 2026-11-04)

"All agents are my go to run; don't ask me for every action." Agent 1 applies it as follows.

**Agents proceed without asking:**
- commits and pushes to the working branch and the per-agent branches, and merging agent branches into the working
  branch;
- creating, briefing and continuing agent sessions and sub-agents, with model choice following the strategy;
- lab work on Felcloud (`ozar-lab`) limited to `ovlm-*` resources, within quota, deleted when finished;
- design changes, ADRs and requirement updates. Each is recorded here and stays reviewable.

**Still brought to the maintainer, once per item:**
- the Phase 1 → Phase 2 gate (the mission requires explicit approval before substantial implementation);
- anything touching `main`, other OzarLand repositories (the upstream quick-lab proposal is already approved), or
  public posts;
- an SRE or Security veto that agents cannot resolve between themselves;
- residual risks the maintainer must accept as owner;
- any action outside `ovlm-*` resources on a cloud.

**Lab resource limit (2026-11-04):** only **one floating IP** is available on `ozar-lab` today. Lab work uses it as the
single cutover address and allocates no other.

**Questions to the maintainer are asked with the in-app question popup** (maintainer, 2026-11-04).

**Escalation threshold (maintainer, 2026-11-04):** "ask me only for important decisions". Agent 1 decides reversible
and technical matters itself and records them here. The maintainer gets only product and scope choices, risk
acceptance, decisions that affect data safety, and the phase gate.

The `ozar-dev` session applies its own approval rules: it accepts only approvals typed in its own conversation.

## 💬 Dedicated agent conversations

Each conversation can be opened in the Claude app. You can read everything the agent does and type into it to
unblock it. Each agent pushes only to its own branch, and Agent 1 reviews the branch and merges it into
`claude/openstack-vm-lifecycle-manager-9nf9cc`.

| Agent | Model | Conversation | Branch |
|---|---|---|---|
| 2 — Architect, design revision | Opus 5.5 | https://claude.ai/code/session_016ti9w3B7uuCUrzzL1QrXZW | `claude/ovlm-architect` |
| 4 — Backend: foundation done; now CI Ansible job and profiles/policies (E3-3) | Sonnet 5.5 | https://claude.ai/code/session_016ti9w32wY5ZDgLijH6QUnf | `claude/ovlm-backend` |
| 4b — Workflow engine core (E5-1) | **Opus 5.5** | https://claude.ai/code/session_016ti9vywkeoCSGZGMFzFPxV | `claude/ovlm-engine` |
| 4c — OpenStack adapter and inventory (E2-1..3) | Sonnet 5.5 | https://claude.ai/code/session_016ti9vzKi1fqsTgLVu6o7w3 | `claude/ovlm-inventory` |
| 4d — Auth, TOTP and audit (E3-1, E3-4) | Sonnet 5.5 | https://claude.ai/code/session_016ti9w3txqUnUJFzEBSyjXk | `claude/ovlm-auth` |
| 6 — Automation, reference workload | Sonnet 5.5 | https://claude.ai/code/session_016ti9vzqoWEEXYUi7HZ4qT1 | `claude/ovlm-automation` |
| 7 — SRE reliability reviewer (veto holder) | Fable 5.1 | https://claude.ai/code/session_016ti9w2Rhy79ZyTv4fvtUTJ | `claude/ovlm-sre-review` |
| 8 — Security reviewer | Fable 5.1 | https://claude.ai/code/session_016ti9vzmfDPFJ7HnXMMD5n5 | `claude/ovlm-security-review` |
| 9 — QA / test strategy | Sonnet 5.5 | https://claude.ai/code/session_016ti9w1BJ2CeCfoC2a47xQT | `claude/ovlm-qa` |

Agents 2, 3, 6 and 8 (authoring) ran as in-session sub-agents before dedicated conversations existed; their briefs and
reports are below. Backend, Frontend and Docs get their conversations when they are activated after Phase 1 approval.

## 🔓 Needs the maintainer

| # | Raised by | Question | Blocks |
|---|---|---|---|
| ~~M1~~ | Agent 6, Agent 1 | ✅ **Decided 2026-11-04:** quick-lab extended with Cinder ([ADR-0001](decisions/ADR-0001-test-environment.md)). Still needed later: a cloud account to host the lab. | — |
| ~~M2~~ | Agent 6 | ✅ **Decided 2026-11-04:** propose the Cinder option upstream to `openstack-quick-lab`. It is filed once the change has run at least once (backlog, Phase 2). | — |
| ~~M4~~ | Agent 2 | ✅ **Decided 2026-11-04:** MVP scope limits accepted (one data volume, image boot, floating IP required, no temporary FIP); pre-handoff snapshot off by default (subject to the SRE review); the new VM stays stopped after a revert until discarded. Recorded in [ADR-0004](decisions/ADR-0004-mvp-renewal-strategy.md). | — |
| ~~M5~~ | Agent 1 | ✅ **Authorized 2026-11-04** by the maintainer directly in the `ozar-dev` session: EXP-01 on `ozar-lab`, `ovlm-exp01-*` resources only. | — |
| ~~M6~~ | Agent 2 | ✅ **Decided by the maintainer, 2026-11-04: D-1 = B.** After a W7–W10 failure there is no automatic restore. OVLM stops in `needs_human`, keeps the locks and pages an operator, unless a pre-handoff snapshot exists. The Architect is applying it in ADR-0004 and renewal-workflow.md. | — |
| ~~M7~~ | `ozar-dev` | ✅ Approved; EXP-01b done. | — |
| ~~M8~~ | Agent 9 | ✅ **Decided by Agent 1** (reversible, so it was not escalated): CI uses GitHub-hosted runners with unprivileged containers (PostgreSQL service container; the Ansible target is an SSH-enabled container without systemd-as-PID-1, and privileged-only cases move to the lab). Lab evidence is stored redacted in the repository under `docs/experiments/` and committed with DCO sign-off. Only a human operator moves a claim to `validated`. | — |
| ~~M9~~ | Agent 8 | ✅ **Decided by the maintainer, 2026-11-04 (security posture):**
- SEC-R-2: operator+approver in the same scope is forbidden by default; an admin can allow it per installation, with each such approval audited and flagged "self-approved"; retirement still needs a second person.
- SEC-R-3: Ansible output goes to a restricted store (operators and admins of the project only, own retention, never exported); diffs opt-in; blocking `no_log` lint.
- SEC-R-10: **TOTP for approvers and admins in the MVP**.
- SEC-R-28: readiness never runs repo code on the live VM by default; doing so is an explicit operator action with typed confirmation and audit. | — |
| ~~M3~~ | Agent 1 | ✅ **Go to the end of the MVP**, maintainer, 2026-11-04 ("tu dois continuer jusqu'à la fin du MVP"). Phases 2–6 are authorized. The backlog is in [roadmap.md](roadmap.md). | — |

## Wave 1 — 2026-11-04 (parallel, independent)

### Agent 3 — OpenStack Specialist (Sonnet 5.5) — done, 233,687 tokens, 102 tool calls, 11 min 52 s

**Brief (summary):** validate OpenStack capabilities against the **source code** of openstacksdk 4.22 and Nova, Cinder,
Neutron and Keystone from PyPI, because `docs.openstack.org` is blocked here. Topics: read-only discovery and the
permissions it needs, server tags and metadata for ownership, idempotency without client tokens, the detach and attach
of a data volume (states, failures, finding the device in the guest), multiattach, floating IP move as cutover,
lock/stop/delete, capacity checks for non-admins, Keystone application credentials and `reader` vs `member`, and
limitations of replacing VMs (fixed IP, MAC, cloud-init). Every claim tagged SOURCE-VERIFIED, DOCUMENTED-UNVERIFIED or
ASSUMPTION.

**Report (verbatim):**

> I wrote docs/openstack-integration.md (285 lines, nothing else written, no commit). I read about 90 source files from
> the wheels. I read only text and never imported anything.
>
> Release scope: openstacksdk 4.22.0, nova 34.0.0 (API max 2.104), cinder 29.0.0 (API max 3.71), neutron 29.0.0,
> neutron-lib 5.0.1, keystone 30.0.0, keystonemiddleware 13.0.2. I also read glance 33, octavia 19, designate 23 and
> placement 16 for their policies. A real cloud runs older releases with its own policy overrides, so these are
> upstream defaults.
>
> Most decision-relevant findings:
> 1. **Floating IP move:** it is a single PUT of port_id, committed in one DB transaction, so it is atomic at the API.
>    The data plane is applied afterwards by the L3 agent, so expect seconds of inconsistency. A target port with no
>    router path fails with ExternalGatewayForFloatingIPNotFound, which is a NotFound subclass, so it comes back as a
>    misleading HTTP 404. Run it as a preflight. The FIP must be in the same project as the port.
> 2. **Idempotency:** Nova server create has no client token and names are not unique. return_reservation_id is
>    generated server side, so it does not help when a response is lost, and the SDK does not support it. Use tags set
>    at create (Nova 2.52 or later), then look up by tag plus an anchored name on retry.
> 3. **Metadata lookup is a trap:** a metadata filter on GET /servers is silently dropped for non-admins, so it returns
>    every server. Tags and name are the safe lookup keys (name is a regex, so anchor it).
> 4. **Volume handoff works, with caveats:**
>    - Detach and attach both return before the work is done, so OVLM must poll.
>    - A failed or refused detach rolls the volume back to `in-use`. The values `error_detaching` and `error_attaching`
>      are attachment `attach_status` values, not volume `status`.
>    - Libvirt waits about 160 s (8 attempts of 20 s) before giving up on a hot-unplug, so stopping the old VM first is
>      the safest default.
>    - Attaching an in-use non-multiattach volume gets HTTP 400 from both Nova and Cinder.
>    - `delete_on_termination` must be false on the data volume. It defaults to false for attach and for an existing
>      volume at boot, but true for volumes Nova creates itself.
> 5. **Locks:** a locked server rejects attach, detach, stop, start and delete from a non-admin. This conflicts with
>    FR-REN-7 (old VM "stopped and locked") unless the lock is applied after the handoff and removed before a revert.
>    A member cannot remove an admin-set lock (that needs admin).
> 6. **Reader inventory:**
>    - Nova, Cinder, Neutron and Glance reads work with reader, but Neutron quota needs the `manager` role.
>    - Host names, hypervisors and Placement capacity are admin only, so free capacity cannot be pre-checked.
>      FR-PLN-2 can only be quota-based and advisory.
>    - Cinder 29 still uses older project-role rules, with no system scope.
> 7. **Incremental sync:**
>    - Only Nova supports it. changes-since includes deleted servers, and changes-before works from 2.66.
>    - Neutron has no changes-since. Cinder has updated_at filters from 3.60 but no tombstones. Those need a full
>      listing each cycle.
> 8. **Application-credential access rules:** they can restrict by service type, method and path (`*`, `**`, `{tag}`).
>    - They are enforced only where keystonemiddleware is current and `service_type` is configured. Otherwise the
>      token is rejected.
>    - They are bypassed when a valid service token accompanies the request.
>    - Nova's `send_service_user_token` defaults to False, so Nova's downstream calls are also checked against the
>      rules.
> 9. **Fixed IP and blue/green:**
>    - A port with a device_id set cannot be reused by a second server, and an already used fixed IP is refused
>      (FixedIpAlreadyInUse). Blue and green therefore cannot both hold the same fixed IP at once.
>    - A pre-created port survives deletion of the server that used it.
>    - A new MAC needs net-owner `member` to preset and `manager` to change.
> 10. **Smaller points:**
>     - A `member` cannot create a FIP with a chosen address (needs `manager`), migrate servers, or force-detach or
>       reset a stuck volume (those are admin only).
>     - Multiattach needs an admin-created volume type and Nova 2.60 or later.
>
> Contradictions or corrections to your assumptions:
> - Floating IP as the cutover: partly. It is atomic in the API but not instant, it needs a router path, and it is
>   impossible for a VM that sits directly on a provider network.
> - Volume detach from A and attach to B: partly. The old VM must not be locked, its compute host must be up, and the
>   server must be in an allowed state with no running task. Admin help is needed for stuck states.
> - Read-only inventory with the reader role: mostly works, with two exceptions. Neutron quota needs `manager`, and
>   admin-only server attributes (host, instance name, user_data) stay empty.
> - Whether the legacy-rule fallback is still active (`enforce_new_defaults`) could not be checked. If it is active,
>   the role checks are only a lower bound.
>
> The file ends with 15 recommendations and 13 open questions that need a real cloud. Cloud-init behaviour, the guest
> device path (`/dev/disk/by-id/virtio-<first 20 characters of the volume id>`) and DVR/OVN data-plane behaviour are
> tagged ASSUMPTION or DOCUMENTED-UNVERIFIED.

**Agent 1 disposition:** accepted. Three effects on the product:
- **FR-REN-7:** the old VM is locked only after the volume handoff, and OVLM unlocks it before a revert. Agent 2
  confirms this in the state machine.
- **FR-PLN-2:** the capacity check is based on quotas and is advisory only, because real capacity is visible only to
  admins.
- **Cutover:** the MVP supports only VMs reached through a floating IP. VMs on provider networks are out of MVP scope.
  The readiness engine reports them as `not-applicable` for this strategy.

### Agent 6 — Automation Engineer (Sonnet 5.5) — done, 84,205 tokens, 5 tool calls, 2 min 17 s

**Brief (summary):** define the OVLM ↔ Ansible contract (phases, idempotency, secrets, timeouts, reproducibility
evidence) and analyse `openstack-quick-lab` against the acceptance scenario, with a failure-injection plan. Self-review
against the `openstack-automation-review` skill.

**Report (verbatim):**

> Wrote the two docs; nothing was lab-run and no git commit was made:
> - docs/automation-contract.md (230 lines)
> - docs/test-environment.md (134 lines)
>
> Recommended test environment: Option A (extend quick-lab with Cinder LVM, proposed as an opt-in variant flag
> contributed to openstack-quick-lab) for the acceptance gate and failure injection. Add Option B (dedicated project on
> the outer cloud) only as a pre-release realism smoke run. In both, OVLM needs a dedicated project with a name
> allow-pattern and a tag-only pre-flight check, and must never act on untagged resources.
>
> Quick-lab README says outright "no Cinder", and its external network is a veth into br-ex, so floating IPs are
> reachable only from the lab VM. OVLM therefore has to run on the lab VM or have a route to 10.99.0.0/24. The Cinder
> globals and loop-VG steps are tagged DOCUMENTED-UNVERIFIED because I did not find them in quick-lab. Virt type falls
> back to qemu without /dev/kvm; that is SOURCE-VERIFIED in remote-deploy.sh.
>
> Five most important contract rules:
> 1. Automation `ref` must be an immutable commit SHA, and every entry in requirements.yml must be pinned. OVLM records
>    the SHA and the requirements hash in each run record. Runs use ansible-runner as a subprocess in a fresh 0700
>    per-run dir, with a one-host generated inventory and no shared state.
> 2. `data_attach` finds the device by /dev/disk/by-id serial = Cinder volume id, never /dev/vdb. It never runs mkfs on
>    a volume with a filesystem. A blank volume with `first_use=false`, a foreign filesystem or any other signature
>    gives needs_human, never a reformat.
> 3. `quiesce` on the old VM stops writers, syncs and unmounts. If umount fails, needs_human and no detach. Any
>    failure, timeout or missing result.json in `quiesce` or `data_attach` is needs_human, with both VMs and the volume
>    left where they are and no auto-retry before a read-only state probe.
> 4. Secrets are never in extra-vars on the command line, never in the repo and never logged. They reach the runner as
>    0600 files in the run dir (tmpfs preferred) and are wiped at the end of the run. Ansible never gets OpenStack
>    credentials; OVLM makes all API calls. Logs are redacted, but that is only a backstop.
> 5. Every phase writes a `ovlm.result/1` JSON file, and `healthcheck` also returns an exit code (0 healthy,
>    2 unhealthy). Health is judged on capability: the service responds, the volume is mounted by the expected fs UUID,
>    and the marker checksum equals the one `quiesce` reported on the old VM. A VM that silently writes to its root
>    disk must fail.
>
> Reproducibility evidence: the automatic checks are pinned ref, `configure` succeeded on a replacement within N days
> (N left as a policy value, no default invented), a second `configure` run shows changed=0, and `--check --diff` on
> the current VM. Shell tasks are skipped in check mode, so an empty diff is weaker evidence than it looks. Whether the
> volume holds all state, and whether the healthcheck is representative, need a human attestation.
>
> Assumptions about the workflow engine for the architect to confirm:
> 1. Step state is persisted and re-derived from OpenStack plus a read-only probe after a worker crash.
> 2. There is a lock or lease per VM and per volume.
> 3. Rollback is OVLM-owned (re-attach volume to the old VM, restore the floating IP), and `rollback_hooks` is
>    optional.
> 4. A human confirmation gate exists before `quiesce` (downtime) and before cutover.
> 5. Profile validation can reject non-SHA refs and unpinned requirements, and OVLM owns cleanup of its own tagged
>    resources.
> 6. The `ovlm.result/1` file route and the host-key trust policy for fresh VMs need your sign-off.
>
> I assumed the virtio serial is a prefix of the volume uuid and flagged it for lab verification. All timeouts are
> ASSUMPTION and need tuning under TCG.

**Agent 1 disposition:** accepted as input. Assumptions 1–6 are passed to Agent 2 (Architect) to confirm or reject in
`renewal-workflow.md`. Agent 3's report covers the virtio-serial question: the guest path `/dev/disk/by-id/virtio-<first 20 chars of volume id>` is still an ASSUMPTION, to be confirmed in the lab.

## Wave 2 — 2026-11-04 (parallel: disjoint files, shared decisions fixed in both briefs)

### Agent 2 — Chief Architect (Opus 5.5) — done (token count not available: the completion notice was lost in a container restart)

**Brief (summary):** write `architecture.md`, `data-model.md`, `api-design.md` and `renewal-workflow.md`, plus these
ADRs:
- ADR-0002: frontend, HTMX vs React.
- ADR-0003: a workflow engine on PostgreSQL, with leases, fencing and resource locks; why not Celery, Temporal or
  APScheduler.
- ADR-0004: the MVP renewal strategy, blue/green with data-volume handoff and floating IP cutover. It must place the
  approval gates and the downtime window, decide whether to stop the old VM before detach and when to lock it, and give
  the rollback at every step.

Agent 2 must confirm or reject Agent 6's six assumptions and choose an SSH host-key trust policy. Every OpenStack claim
uses Agent 3's tags. No invented numbers: timeouts become named configuration keys. It must not edit the requirements;
it lists requested changes instead.

**Report (verbatim):**

> I've written the Phase 1 architecture: 4 docs and 5 ADRs. No code, no commit, no edits to PM or security files. I
> read security-model.md and applied Agent 8's six decisions.
>
> Files: architecture.md (211 lines), data-model.md (162), api-design.md (162), renewal-workflow.md (220),
> ADR-0002-frontend, ADR-0003-workflow-engine, ADR-0004-mvp-renewal-strategy, ADR-0005-ownership-and-idempotency,
> ADR-0006-guest-ssh-host-key-trust.
>
> **Key decisions**
> - ADR-0002: Jinja2 + HTMX, no Node toolchain. UI and API share one service layer, and CI checks that every UI action
>   has an API equivalent.
> - ADR-0003: Postgres step executor in the worker. Steps are claimed with SKIP LOCKED, held by lease and heartbeat,
>   and committed only if the fencing token still matches. Only one step per run can be running. The worker stops
>   itself before its lease expires. Resource locks belong to the run (not the worker) and hold through retention.
>   OpenStack waits are re-claim timers. Every step does probe → decide → act → verify. Celery, Temporal and
>   APScheduler rejected.
> - ADR-0004:
>   - Approval gate G2 sits before quiesce and covers the whole downtime window; there is no gate inside it.
>   - The old VM is always stopped before detach; no hot-detach.
>   - The old VM is locked only after external verify and unlocked first on revert or retirement.
>   - One restore sequence handles rollback and revert. Each step skips if its target state already holds.
>   - MVP scope: exactly one data volume (or a stateless service), the new VM boots from image, a floating IP is
>     required, no temporary floating IPs.
> - ADR-0005: ownership uses a DB ledger plus Nova tags set at create; resume looks up by tag and exact name, and more
>   than one match stops for a human. A first step, `claim_resources`, marks the old VM, the floating IP and the volume
>   so Agent 8's ownership guard can pass.
> - ADR-0006: host keys come from the console log by default; TOFU only as an audited per-profile opt-in. I preferred
>   an injected key and gave way to Agent 8.
>
> **Changes made to align with security-model.md**
> - Green is no longer deleted automatically after a build failure; an operator rollback with typed confirmation
>   deletes it.
> - Approvals are bound to the plan hash. Typed confirmation is the VM name plus the last 6 characters of its ID.
>   Approve and confirm endpoints accept only a human session.
> - The api process makes no OpenStack calls.
>
> **Requested FR changes (PM)**
> - FR-UI-3: change to "the UI offers no capability the REST API lacks", with the exception that tokens cannot
>   approve or confirm.
> - FR-REN-4: the cutover gate is the downtime gate, placed before quiesce.
> - FR-REN-5: say "rollback converges to the old VM serving again". Stuck volumes, admin locks and down hosts need a
>   human or OpenStack admin.
> - FR-REN-2: add the MVP scope limits from ADR-0004.
> - FR-PLN-2: the capacity pre-check is quota-based and advisory only.
> - FR-REG-2: the data volume is identified by filesystem UUID/label, not device name; add `guest_access`; the image
>   is resolved at plan time and is part of the plan hash.
> - FR-REN-8: abort takes effect at step boundaries; data-phase Ansible is not interrupted.
> - NFR-2: add the fencing token, and state that OpenStack side effects cannot be fenced.
>
> **Disagreements**
> - Agent 6:
>   - Rejected: quiesce removing the fstab line. Revert needs it.
>   - Rejected: the contract timeouts as defaults; they are now config keys tuned in the lab.
>   - Changed: failure-injection rows 2–4 — capacity failure is fatal, and green is deleted by operator rollback.
> - Agent 3: hot-detach as a per-profile opt-in, rejected for MVP.
> - Agent 8: needs to review two points:
>   - Automatic in-window restore (`renewal.auto_rollback_in_window`, default true). Their table only lists
>     operator-initiated revert.
>   - `claim_resources`, the one mutation exempt from the "must already carry the tag" rule.
>
> **Top 5 risks**
> 1. The worker must reach the new VM's fixed IP over SSH, by a direct route or a jump host. This is unverified in
>    the lab (Agent 6).
> 2. Clouds that only offer `disk=0` flavors force boot-from-volume, so the MVP cannot renew there.
> 3. Real floating-IP cutover time and downtime are unknown (data plane documented but not source-verified; the lab
>    runs on slow emulation).
> 4. Stuck volume states and down hosts need a cloud admin. A run can stay stopped mid-downtime until one acts.
> 5. Our own engine (fencing, leases) is critical code and needs crash tests in CI against real PostgreSQL.
>
> **Needs the maintainer**
> - Accept the MVP scope limits (one volume, image boot, floating IP required, no temporary floating IP).
> - Default of the optional snapshot before handoff: I set it to off.
> - Keep the new VM stopped after a revert until an operator discards it.
> - Whether the console-output API is available to a project member is unverified. If the lab says no, a VM's host
>   key can't be verified and that profile has to opt into TOFU to proceed (ADR-0006).

**Agent 1 disposition:** accepted.
- All eight requested requirement changes are applied.
- The disagreements with Agents 3 and 6 are resolved in Agent 2's favour (Architect authority); they are recorded in
  ADR-0004.
- The two security points go to the independent Security reviewer: automatic in-window rollback, and the tag
  exemption of `claim_resources`.
- The maintainer questions are added to the milestone.

### Agent 8 — Security Engineer, authoring (Opus 5.5) — done, 115,807 tokens, 11 tool calls, 4 min 34 s

**Brief (summary):** write `security-model.md`, covering:
- a STRIDE threat model that treats a compromised guest VM and malicious automation content as threats;
- local authentication with argon2id, API tokens, sessions and CSRF;
- an RBAC matrix with separation of duties and per-project scoping;
- least-privilege OpenStack credentials from Agent 3's findings (reader and member, application credentials, a
  position on access rules, an ownership guard on every mutating call);
- secrets encryption and rotation;
- SSH key handling and host-key policy;
- the list of destructive operations with role, approval, confirmation and audit for each;
- an append-only audit log;
- supply-chain hardening;
- the security tests QA must automate.

Approvals come only from humans, never from AI agents. Its independent review (Fable 5.1) follows.

**Report (verbatim):**

> I wrote docs/security-model.md (349 lines, Status Designed, dated 2026-11-04). Nothing is committed and no other
> file was touched. Every OpenStack permission claim cites Agent 3's tag (written "OSI §n"), and my own unverified
> claims are tagged ASSUMPTION.
>
> **Top decisions**
> - **Credentials:** read credential is `reader` only; I do not add `manager` for Neutron quota, so FR-PLN-2
>   port/FIP headroom stays advisory. Write credential is `member` in one project, worker only. Both are restricted
>   Keystone application credentials, owned by a dedicated Keystone service user, with mandatory expiry of 180 days or
>   less. Access rules: GET-only on the read credential (it fails closed); none on the write credential in MVP,
>   because they are fragile and cannot restrict by resource. Revisit in V1 after a lab test.
> - **Ownership guard:** before every mutating call, the target must be in the OVLM DB *and* carry the `ovlm:*` tag.
>   Tags alone are never trusted, because any project member can edit them (SV).
> - **Secrets:** envelope encryption (AES-GCM per secret). Data keys are wrapped to the worker's key pair, and the
>   private key file is mounted into the worker only. The api can encrypt but never decrypt. Vault/Barbican are a
>   later option.
> - **Authentication:** argon2id passwords, server-side sessions, CSRF token plus Origin check, scoped API tokens
>   stored as hashes with 90-day expiry. TOTP is mandatory for approver/admin in V1.
> - **Authorization:** RBAC matrix with project scoping enforced from MVP. The admin role does not inherit approver.
>   Separation of duties may be relaxed for plan and cutover gates only; retirement never allows self-approval, and
>   the two-person rule is on by default.
> - **Approvals:** only an interactive human session with re-authentication in the last 5 minutes can approve or
>   confirm a destructive action. API tokens and AI agents cannot.
> - **Host keys:** fingerprints are read from the console log by default; trust-on-first-use is a per-profile,
>   audited opt-in.
> - **Ansible:** runs as a separate OS user with a scrubbed environment and no access to the key file. Allowlisted
>   repos, full commit SHA, no runtime Galaxy downloads.
> - **Audit:** append-only through DB grants plus a trigger. Hash chaining is deferred to V1 with an external signed
>   checkpoint, because a chain without an outside anchor adds little.
>
> **Requirement changes**
> - **FR-UI-3:** add an exception — approval and destructive-confirm endpoints are human-session only. Without it, a
>   token or AI agent could approve runs.
> - **FR-UI-2:** typing the VM name is not enough, because Nova server names are not unique (SV) and green and blue
>   can share one. Require the name plus the last 6 characters of the ID, checked server-side, and make the API
>   require the same field.
> - **NFR-4:** "configurable separation of duties" must never allow self-approval of retirement.
> - **FR-AUD-1:** secrets must be excluded from before/after diffs by an allowlist of fields, not redacted afterwards.
> - **FR-REN-6:** add the rule "the target must be in the OVLM DB and carry the tag, and the approval is bound to a
>   hash of plan, profile version, automation SHA and target IDs".
>
> **Conflicts with your assumptions**
> - You assumed the read credential is used by both api and worker. I recommend the api never calls OpenStack and
>   cannot decrypt anything; on-demand sync and "test credential" become worker jobs. Agent 2 should align
>   `architecture.md`.
> - The Ansible user separation means one image with two OS users. That is compatible with NFR-1 but Agent 2 should
>   know.
>
> **Residual risks the maintainer must accept**
> - **Reader may be able to write:** if the cloud has `enforce_new_defaults=False`, the legacy fallback rules may let
>   a reader write. Agent 3 verified the rule but not whether it is active. Mitigations: an OVLM-side GET/HEAD-only
>   guard and the cloud admin's statement of the setting.
> - **Write credential reaches the whole project:** a `member` credential can delete any server in its project, not
>   only OVLM's. The ownership guard is application-level only.
> - **Approved code still runs:** a malicious commit that someone approved still runs on the worker host and on
>   guests.
> - **Console-log fingerprints may be missing:** they depend on the image logging to the console, and on
>   console-output access for `member`, which I could not verify (ASSUMPTION). Clouds without it fall back to
>   trust-on-first-use.
> - **Stuck volumes, admin-set locks and down compute hosts:** OVLM can only stop and escalate these to a human
>   OpenStack admin.
> - **Stolen key file plus DB backup exposes all secrets.**
> - **Guest health output is unverifiable:** a lying guest can delay a cutover but cannot cause one alone, because an
>   external probe is also required.

**Agent 1 disposition:** accepted.
- All five requirement changes are applied to `functional-requirements.md`, together with Agent 3's effects on
  FR-PLN-2 and FR-REN-7.
- The architecture conflicts (the api never calls OpenStack; two OS users) were sent to Agent 2 while it was still
  running.
- The residual risks go to the maintainer at the Phase 1 milestone. The most important is that the write credential
  can reach the whole project, which is why ADR-0001 requires a dedicated OpenStack project.

## Wave 3 — 2026-11-04: independent reviews, test strategy, real-cloud experiment

The costs below are what the platform reports per session (list price, estimates). Full documents:
[SRE review](reviews/sre-review-phase1.md), [Security review](reviews/security-review-phase1.md),
[testing strategy](testing-strategy.md), [EXP-01](experiments/EXP-01-design-assumptions-on-felcloud.md).

### Agent 7 — SRE reviewer (Fable 5.1, dedicated conversation) — done, $5.70

**Verdict: accept with required changes, no veto.** The reviewer found no state where two VMs write the same data
volume, and no step that repeats a destructive action blindly after a crash. Three **high** findings must be fixed in
the design before the downtime-window and restore steps are implemented:
- **SRE-R-1:** the restore sequence does not converge from "quiesced but still running".
- **SRE-R-2:** fencing only reacts to a missed heartbeat, so a paused worker can still issue a mutating call after
  another worker has taken over.
- **SRE-R-3:** the only `mkfs` path is not closed off for renewals.

Build-phase and engine work can proceed in parallel. Counts: 0 critical, 3 high, 9 medium, 6 low, and 4 V1 items.

### Agent 8 — Security reviewer (Fable 5.1, dedicated conversation) — done, $7.17

**Verdict: accept with required changes**, for both the security model and the architecture. The high findings:
- **SEC-R-1:** a compromised api can forge approvals in the database. Fix: split the DB roles (`ovlm_api` and
  `ovlm_worker`), have the worker re-validate approval evidence before every destructive step, and mirror audit rows
  to the log stream.
- **SEC-R-2:** separation of duties ignores the profile author, who chooses the code that runs. Fix: a per-gate
  requester set; by default no operator+approver in the same scope; the approval shows the automation diff.
- **SEC-R-3:** stored Ansible output can copy workload secrets into the OVLM database and UI. Fix: restricted
  artefacts, diffs opt-in only, and a blocking `no_log` lint.

Rulings asked for by the Architect:
- **(a) automatic in-window rollback:** yes, under conditions. The approval must state it, the setting is bound to
  the approval, there is a list of "unambiguous" cases, a single attempt, and audit. A **maintainer decision** is
  needed on the W7/W8 case (finding SEC-R-30).
- **(b) `claim_resources` tag exemption:** yes, under conditions.

### Agent 9 — QA (Sonnet 5.5, dedicated conversation) — done, $1.03

`testing-strategy.md` is aligned with the real step keys (B1–X1, W1–W10, S1–S9). It contains:
- 20 engine crash scenarios (WF-01 to WF-20), including a stale worker whose OpenStack call lands after takeover;
- lab tests mapped to gates G1–G3;
- a migration test N-1 → N with runs in flight, replacing the up/down test because downgrade is not supported.

Issues raised:
- `renewal-workflow.md` §7 contradicts §8 on `NoValidHost`; the Architect must fix §7.
- For the maintainer: may CI use privileged containers? Where is lab evidence stored, and who signs it?

### `ozar-dev` — EXP-01 on Felcloud (Opus 5.5, maintainer's machine) — done, about 15 minutes of cloud time

7 of 8 questions answered on a real cloud:
- Console-log host keys work for a non-admin, which confirms ADR-0006.
- The `/dev/disk/by-id` path holds a truncated volume ID; mounting by UUID works.
- **Best-case outage is about 45 s**, before the floating-IP move.
- Tags work, and the metadata filter returns *everyone's* servers.
- A lock blocks detach.

Not measured: the floating-IP move, because no free floating IP was available. New findings:
- the cloud has **no working default volume type**, so OVLM must always pass one;
- the floating IP pool can be empty even with an unlimited quota.

Cleanup was verified: no `ovlm-*` resource is left.

**Agent 1 disposition:**
- All three branches are merged into the working branch, and the EXP-01 results are recorded.
- Next: a **design revision**. The Architect resolves the 6 high findings, the §7 contradiction and the EXP-01
  findings. Then the SRE and Security reviewers check only those changes.
- Commit rule from the maintainer, given in `ozar-dev`: commit messages no longer mention Claude.

## Wave 4 — 2026-11-04: design revision

### Agent 2 — Architect, design revision (Opus 5.5, dedicated conversation) — done, $3.26

All six high findings are resolved in the architecture documents (commit `aa8c1de`, merged):
- **SRE-R-1:** restore restarts the old VM if it was quiesced but is still running. Units are never disabled, so they
  come back from fstab.
- **SRE-R-2:** before every write, launch and commit, the worker checks a local fence deadline measured from when it
  sent the claim. A takeover of a destructive step waits a fixed delay first.
- **SRE-R-3:** renewals always pass `first_use=false`, so a volume is never formatted during a renewal.
- **SEC-R-1:** DB roles are split (`ovlm_api`, `ovlm_worker`). The worker re-validates approval evidence before every
  destructive step, and the audit is mirrored to the logs. Residual risk: consistent forgery still passes. Signed
  approvals are planned for V1.
- **SEC-R-2:** each gate has a requester set, and no operator+approver in the same scope by default. The approval
  shows the hash inputs and the automation diff.
- **SEC-R-3:** Ansible artefacts are restricted, diffs are opt-in, and the `no_log` lint is blocking.

Also in this revision:
- `NoValidHost` is fatal everywhere.
- ADR-0005 and ADR-0006 are now lab-observed.
- MVP creates no volumes and no temporary floating IPs.
- Measured times are recorded as documentation, not as defaults.

The edits needed in files owned by other agents (security model, automation contract, test strategy, OpenStack notes)
were handed to a documentation-sync agent (Sonnet 5.5). **One maintainer decision: D-1** (see "Needs the
maintainer"). Next: a re-review by the SRE and Security reviewers of the changes only.

## Wave 5 — 2026-11-04: delta reviews and EXP-01b

- **SRE delta review (Fable): Accept, no veto.** 17 of 18 findings are resolved and 1 is partly resolved. New:
  - SRE-R-23 (medium): a failed evidence re-check inside the window;
  - SRE-R-24 (medium): an operator signal consumed with no effect after a crash;
  - 7 low findings.
- **Security delta review (Fable): accept with required changes.** 24 of 36 findings are resolved, including all
  three high ones. Still required before implementation: SEC-R-10, -11, -13, -28, -34, -35. The four posture questions
  were decided by the maintainer (M9).
- **EXP-01b:**
  - the floating-IP move takes 1.1–1.3 s; the best-case outage is about 40 s;
  - ACTIVE ≠ ready, so readiness must be proven before T0;
  - **the console log is unreliable**, so ADR-0006 needs a fallback.

**Next:** Architect round 2 for these items, then a short check by the reviewers of their own items only.

## Phase 2 started — 2026-11-04

On the maintainer's go, the backlog is in [roadmap.md](roadmap.md). Running in parallel, on disjoint files:
- Agent 4: Foundation E1-1..E1-6 (Sonnet).
- Agent 6: reference workload E1-7 (Sonnet).
- Agent 2: design round 2, E0-1 (Opus).

The quick-lab Cinder option (E1-8) starts when the engine work starts, so the lab VM does not sit idle at cost.

## Phase 2 results and the next wave — 2026-11-04 14:45 UTC

**Verified by Agent 1 on the merged working branch** (not only reported by the agents):
- `make lint`: ruff, format, mypy and import-linter pass.
- 25 unit tests pass.
- 9 integration tests pass against a real PostgreSQL 16. A local server was used, because Docker Hub rate-limited this
  container (429).
- Ansible reference workload: Agent 6 reports lint, syntax check, a 9-case `data_attach` decision table and an
  unprivileged-container run passing. **Agent 1 did not re-run it** (no image pull possible here); CI will.
- One integration fix by Agent 1: ruff excludes `ansible/`.

**Design round 2 (Architect, Opus, $7.48 in total):**
- ADR-0006 now injects an OVLM-generated bootstrap host key through cloud-init user-data and replaces it at B5.
- New step B9 `verify_green_ready` runs before T0.
- The M9 decisions are applied (solo installs need a second human account for G3, TOTP step-up bound to an action),
  plus SEC-R-11/13/34/35/36 and SRE-R-23..31.
- The Security reviewer is asked for a sign-off on the user-data exception and the SEC-R-34 deviation.
- Cross-owner edits are being applied by a documentation-sync agent.

**Monitoring incident:** the three scheduled check-ins (09:26, 10:30, 12:57) failed with `ACCESS_DENIED`. This session
is limited to the maintainer's trusted devices, so reminders cannot wake it, and about 2 hours were lost after 12:43.
They are replaced by a local watcher that wakes Agent 1 when an agent branch receives a push.

**Running now (code, disjoint modules, see agent-working-rules.md):**
- E5-1 engine (Opus).
- E2-1..3 adapter and inventory (Sonnet).
- E3-1/E3-4 auth, TOTP and audit (Sonnet).
- E3-3 profiles and policies plus the CI Ansible job (Sonnet).

## Milestones M1 and M2 reached — 2026-11-04 14:50 UTC

- **Security sign-off, round 2 (Fable):** accept with conditions for the implementation scope. The ADR-0006 bootstrap
  key and the SEC-R-34 deviation are accepted with conditions. Together with the SRE's "accept", **Phase 1 is
  frozen**.
- **[OzarLand/openstack-vm-lifecycle-manager#1](https://github.com/OzarLand/openstack-vm-lifecycle-manager/pull/1)
  is merged into `main`** (squash, `e52856a`). CI was green: lint, unit, integration (PostgreSQL), image build and
  Compose smoke test.
- **Integration model from now on:**
  - Agent work is brought into the working branch.
  - The working branch goes to `main` by pull request, one per batch, merged only when CI is green (the maintainer's
    instruction).
  - Pull requests are merged with a **merge commit**, not a squash. The squash of #1 cut the history link with the
    agent branches. Agent work started before #1 is brought in **by the paths each agent owns**, not by `git merge`.
- **Incident:** a `git merge` of the security-review branch after the squash left conflict markers, which were
  committed to the working branch (not to `main`). The working branch was reset to `main` and the review file was
  taken from the agent branch alone. Nothing reached `main`.

## Batch 2 integrated — 2026-11-04

The following are brought into the working branch for PR #3:
- workflow engine core (E5-1, Opus, merged from its rebased branch);
- auth, TOTP and audit (E3-1/E3-4, Sonnet, merged);
- OpenStack adapter, inventory and registration (E2-1..3, Sonnet, cherry-picked, because the branch predated the
  squash of #1).

Integration work by Agent 1:
- resolved the conflicts in `settings.py`, `cli.py`, `app.py`, `pyproject.toml` and the lock files;
- added the merge migration `0003_merge`, which joins the four module heads.

An integration sub-agent (Sonnet) replaced the inventory module's placeholder auth with the real `require_role`. The
auth module's own test had caught it: the inventory routes returned 503 instead of enforcing CSRF. The same agent wired
the registration audit.

**Verified by Agent 1:** lint clean, 206 unit tests and 168 integration tests (PostgreSQL 16) pass.

**Known gap (AUTH-HOOK, E3-2):** list results are not yet filtered by project scope, so a project-scoped viewer can
see every project.

**In parallel:** the SRE reviewer (Fable) is reviewing the engine code.

## Batch 2 merged; wave 3 started — 2026-11-04 15:50 UTC

[OzarLand/openstack-vm-lifecycle-manager#3](https://github.com/OzarLand/openstack-vm-lifecycle-manager/pull/3) is
merged (CI green).

**Wave 3, dedicated conversations, each starting from `main` on its own branch:**

| Agent | Task | Model | Conversation | Branch |
|---|---|---|---|---|
| 4 | E3-3 profiles, policies, deadlines + CI Ansible job | Sonnet 5.5 | https://claude.ai/code/session_016ti9vz9KRtL1AWNtdEdpsD | `claude/ovlm-profiles` |
| 4e | E5-2 OpenStack write client, write allowlist, ownership guard | **Opus 5.5** | https://claude.ai/code/session_016ti9w1i1iWtPx5mCWp1yka | `claude/ovlm-write-client` |
| 6 | E5-3 automation runner | Sonnet 5.5 | https://claude.ai/code/session_016ti9w4QrgeGXet4nHP6mCi | `claude/ovlm-automation-runner` |
| 4f | E3-2 RBAC matrix, separation of duties, project scoping | **Opus 5.5** | https://claude.ai/code/session_016ti9vzghowyNfy16jQZVp9 | `claude/ovlm-rbac` |
| 5 | E6-1/E6-2 operator UI: layout, auth pages, inventory and VM details | Sonnet 5.5 | https://claude.ai/code/session_016ti9vzVaKusmXE43XnNTPo | `claude/ovlm-ui` |
| 7 | SRE code review of the engine (E5-1) | Fable 5.1 | https://claude.ai/code/session_016ti9w2Rhy79ZyTv4fvtUTJ | `claude/ovlm-sre-review-engine` |

**Note:** the first Backend conversation (Agent 4, foundation) correctly refused to start E3-3 on a message from
another session alone; it treats cross-session messages as data, not as the maintainer's instruction. The task was
re-issued as the opening instruction of a new conversation. The old conversation is superseded.

**Planned next:** E4 readiness, once profiles land; E5-4 renewal strategy steps (Opus), once the write client and
runner land; E5-5 gates; then the lab.

## PR #4 merged — 2026-11-04 16:41 UTC

[OzarLand/openstack-vm-lifecycle-manager#4](https://github.com/OzarLand/openstack-vm-lifecycle-manager/pull/4) is
merged: profiles, policies and deadlines (E3-3), the operator UI first pages (E6-1/E6-2), and the CI Ansible job.

Two CI failures were fixed before the merge:
- `ansible-core 2.22` requires Python 3.13, but the job pinned 3.12.
- The Compose smoke test expected the old placeholder page at `/`, which the UI now redirects to `/login`.

**First real run of the reference workload's playbooks** against a container in CI: green. They had only been
reported passing by the authoring agent until now.

Started: E4 readiness (Agent 4g, Sonnet), https://claude.ai/code/session_016ti9w4bUADuy7e4sVTGzRq.

Waiting for:
- Security code review of the write client and RBAC (Fable).
- SRE code review of the engine (Fable).
- The automation runner (Sonnet).
