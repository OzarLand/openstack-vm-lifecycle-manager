# ADR-0006 — SSH host-key trust for guests

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 8 (Security, owner of the control, [security-model.md](../security-model.md) §6.2); Agent 2 (Chief Architect, workflow integration); maintainer approval required |

## Context

The worker runs Ansible over SSH on the old VM (blue) and on the freshly built VM (green). cloud-init regenerates host
keys on a new instance (openstack-integration.md §9, ASSUMPTION), so green's key is unknown before boot. Agent 6 left the
policy open (automation-contract.md §2, test-environment.md §7.5). This ADR records the decision for the workflow; the
security rationale lives in security-model.md §6.2.

## Options

| Option | Weakness |
|---|---|
| A. Disable host-key checking | MITM gets the session. Forbidden. |
| B. TOFU (`accept-new`), fingerprint recorded | MITM in the first-connect window undetected. |
| C. Fingerprints read from the console log (`os-getConsoleOutput`, write credential) | Image must print fingerprints to the serial console; console-output policy not verified by Agent 3 (ASSUMPTION); parsing. |
| D. OVLM-generated host key injected via user-data | Private host key stored in Nova and readable from inside the guest via the metadata service (§2, ASSUMPTION). |

## Decision

**C by default; B only as an audited per-profile opt-in** (`profile.guest_access.host_key_policy = console | tofu`,
default `console`). D rejected (Agent 8). The architect initially preferred D for determinism; accepted C because it keeps
private key material out of Nova.

| Rule | Detail |
|---|---|
| Where | Step `wait_green_ssh` (renewal-workflow.md §2): poll console output until the cloud-init fingerprint block appears or `timeouts.green_host_key` expires; then ssh-keyscan via the guest-access path and accept only a key whose fingerprint matches. |
| No fingerprint by deadline | `needs_human` "host key unverifiable". Operator may switch the profile to `tofu` (new profile version → plan re-approval, since the profile version is in the approval hash). |
| Pinning | Per-run `known_hosts`, `StrictHostKeyChecking=yes`; fingerprint stored in step evidence and on the managed VM when green becomes current. |
| Blue | Fingerprint recorded at registration (worker scan, operator confirms, audited). Mismatch at run time = `needs_human`. |
| Console text | Untrusted guest output: size-capped, parsed by a strict pattern, never rendered unescaped (security-model.md §6.4). |

## Consequences

- Readiness check "image prints SSH fingerprints to console" becomes `unknown` until one green build has proved it.
- Lab must confirm: console-output role, and that the Ubuntu 24.04 cloud image prints fingerprints (test plan item).
- Building on C keeps option D available later as a third policy value if Agent 8 accepts it.
