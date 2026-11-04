# Team log

The open record of the agent team's work: who was activated, what each agent was asked, what it reported back, and
what needs the maintainer. Agent 1 (PM/EM) updates it after every handoff. Agent reports are copied **verbatim**.

## Roster and status

| # | Role | Model | Status | Output |
|---|---|---|---|---|
| 1 | Product / Engineering Manager | Opus 5.5 (main session) | Active: coordinating | `product-vision.md`, `functional-requirements.md`, `agent-team.md`, `model-selection-strategy.md`, ADR-0000, this log |
| 2 | Chief Software Architect | Opus 5.5 | **Done** (Wave 2). Token count lost in a container restart: not reported | `architecture.md`, `data-model.md`, `api-design.md`, `renewal-workflow.md`, ADRs |
| 3 | OpenStack Specialist | Sonnet 5.5 | **Done** (Wave 1): 233,687 tokens, 102 tool calls, 11 min 52 s | `openstack-integration.md` |
| 4 | Backend Engineer | — | Not activated (no code before approval) | — |
| 5 | Frontend Engineer / UX | — | Not activated | — |
| 6 | Automation Engineer | Sonnet 5.5 | **Done** (Wave 1) | `automation-contract.md`, `test-environment.md` |
| 7 | SRE / Reliability | Fable 5.1 | **Running** in its own conversation (link below) | `reviews/sre-review-phase1.md` on `claude/ovlm-sre-review` |
| 8 | Security Engineer | Opus 5.5 (author) → Fable 5.1 (review) | Authoring **done**: 115,807 tokens, 11 tool calls, 4 min 34 s. Fable review **running** in its own conversation (link below) | `security-model.md` |
| 9 | QA / Test Automation | Sonnet 5.5 | **Running** in its own conversation (link below) | `testing-strategy.md` on `claude/ovlm-qa` |
| 10 | Documentation Engineer | — | Not activated (Agent 1 writes the README) | — |
| — | **Dev VM session** `ozar-dev` (maintainer's machine, Remote Control) | maintainer's local Claude Code | Probe done (read-only): 2 vCPU / 7 GB, KVM nested, openstack CLI, cloud `ozar-lab` (Felcloud). Too small to host the lab itself, but a good control host. **Needs the maintainer's direct authorization in that session** to create `ovlm-exp01-*` resources ([EXP-01](experiments/EXP-01-design-assumptions-on-felcloud.md)) | https://claude.ai/code/session_016ti9w2xkWinTeHFRq3zgS3 |

## 💬 Dedicated agent conversations

Each conversation can be opened in the Claude app. You can read everything the agent does and type into it to
unblock it. Each agent pushes only to its own branch, and Agent 1 reviews the branch and merges it into
`claude/openstack-vm-lifecycle-manager-9nf9cc`.

| Agent | Model | Conversation | Branch |
|---|---|---|---|
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
| M5 | Agent 1 | **Authorize EXP-01 on Felcloud** directly in the `ozar-dev` session: it does not accept approvals relayed by another session. Scope: `ovlm-exp01-*` resources only, less than 1 hour, everything deleted at the end. | Checking ADR-0006 (host keys), the data-volume path in the guest, real cutover and downtime times |
| M3 | Agent 1 | **Phase 1 approval.** Work-in-progress drafts are pushed to `claude/openstack-vm-lifecycle-manager-9nf9cc` (authorized 2026-11-04). The final Phase 1 proposal still needs approval before implementation starts. | Publishing the documents |

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
