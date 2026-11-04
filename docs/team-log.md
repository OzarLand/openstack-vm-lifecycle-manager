# Team log

The open record of the agent team's work: who was activated, what each agent was asked, what it reported back, and
what needs the maintainer. Agent 1 (PM/EM) updates it after every handoff. Agent reports are copied **verbatim**.

## Roster and status

| # | Role | Model | Status | Output |
|---|---|---|---|---|
| 1 | Product / Engineering Manager | Opus 5.5 (main session) | Active: coordinating | `product-vision.md`, `functional-requirements.md`, `agent-team.md`, `model-selection-strategy.md`, ADR-0000, this log |
| 2 | Chief Software Architect | Opus 5.5 | **Running** (Wave 2) | `architecture.md`, `data-model.md`, `api-design.md`, `renewal-workflow.md`, ADRs |
| 3 | OpenStack Specialist | Sonnet 5.5 | **Done** (Wave 1): 233,687 tokens, 102 tool calls, 11 min 52 s | `openstack-integration.md` |
| 4 | Backend Engineer | — | Not activated (no code before approval) | — |
| 5 | Frontend Engineer / UX | — | Not activated | — |
| 6 | Automation Engineer | Sonnet 5.5 | **Done** (Wave 1) | `automation-contract.md`, `test-environment.md` |
| 7 | SRE / Reliability | Fable 5.1 | Queued: independent review of the architecture | review record |
| 8 | Security Engineer | Opus 5.5 (author) → Fable 5.1 (review) | **Running** (Wave 2): authoring `security-model.md` | `security-model.md` |
| 9 | QA / Test Automation | Sonnet 5.5 | Queued: after the architecture | `testing-strategy.md` |
| 10 | Documentation Engineer | — | Not activated (Agent 1 writes the README) | — |
| — | **Dev VM session** (maintainer's machine, Remote Control) | maintainer's local Claude Code | Asked for a **read-only** capability probe (KVM, tools, which OpenStack clouds exist, quick-lab state) to plan where the lab runs | reply pending |

## 🔓 Needs the maintainer

| # | Raised by | Question | Blocks |
|---|---|---|---|
| ~~M1~~ | Agent 6, Agent 1 | ✅ **Decided 2026-11-04:** quick-lab extended with Cinder ([ADR-0001](decisions/ADR-0001-test-environment.md)). Still needed later: a cloud account to host the lab. | — |
| ~~M2~~ | Agent 6 | ✅ **Decided 2026-11-04:** propose the Cinder option upstream to `openstack-quick-lab`. It is filed once the change has run at least once (backlog, Phase 2). | — |
| M3 | Agent 1 | **Commit authorization.** Nothing is committed yet, per your brief. Approve the Phase 1 proposal to allow committing to `claude/openstack-vm-lifecycle-manager-9nf9cc`. | Publishing the documents |

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

### Agent 2 — Chief Architect (Opus 5.5) — running

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

**Report:** pending.

### Agent 8 — Security Engineer, authoring (Opus 5.5) — running

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

**Report:** pending.
