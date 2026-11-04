# ADR-0006 — SSH host-key trust for guests

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval; the round-2 change of default needs Agent 8's sign-off as owner of the control) |
| Date | 2026-11-04 |
| Deciders | Agent 8 (Security, owner of the control, [security-model.md](../security-model.md) §6.2); Agent 2 (Chief Architect, workflow integration); maintainer approval required |
| Evidence | Console option: **LAB-OBSERVED, inconsistent** on Felcloud: worked in EXP-01 (Q1), console output empty (HTTP 200, `output: ""`) for both servers in EXP-01b, still empty 14 min after boot. Injected option: cloud-init host-key injection and in-session rotation are **ASSUMPTION** (lab item). |

> **Revision 2026-11-04**: evidence upgraded from ASSUMPTION to LAB-OBSERVED by EXP-01 Q1; console text storage
> narrowed (SEC-R-19).
>
> **Revision 2026-11-04 (round 2)**: EXP-01b showed the console log can stay empty. The default becomes an
> OVLM-generated **bootstrap** host key injected through user-data and **rotated** over the first authenticated
> session (option D′). Console remains an option; TOFU remains an audited opt-in.

## Context

The worker runs Ansible over SSH on the old VM (blue) and on the freshly built VM (green). cloud-init regenerates host
keys on a new instance (openstack-integration.md §9, ASSUMPTION), so green's key is unknown before boot. The first
decision (option C, console log) worked once (EXP-01) and then failed on the same cloud (EXP-01b: empty console for
14 minutes), so a default that depends on the console would block renewals at B5 unpredictably.

## Options

| Option | Weakness |
|---|---|
| A. Disable host-key checking | MITM gets the session. Forbidden. |
| B. TOFU (`accept-new`) on the project network, fingerprint recorded and shown at G2 | MITM in the first-connect window is undetected, and the approver cannot verify a fingerprint out of band, so showing it at G2 adds no assurance. |
| C. Fingerprints read from the console log | Not reliable: empty console on Felcloud in EXP-01b (LO). Upstream console-output policy still not source-verified (SEC-R-19). |
| D. OVLM-generated host key injected via user-data, kept | Private host key stays in Nova's user-data and the metadata service for the life of the VM (OSI §2, ASSUMPTION), readable inside the guest and possibly by others; rejected earlier by Agent 8. |
| **D′. Injected bootstrap key, rotated at first contact** | The bootstrap private key is exposed in user-data, but only trusted until B5 rotates it, during the build phase (no data, no FIP, no secrets sent before rotation). |

## Decision

**D′ by default** (`profile.guest_access.host_key_policy = injected | console | tofu`, default `injected`).
C stays available for clouds where the console is reliable and the owner prefers no key material in user-data.
B stays an audited per-profile opt-in (a new profile version, hence re-approval). A is forbidden.

| Rule | Detail |
|---|---|
| Generate | In B3 the worker generates an ed25519 bootstrap host key pair in memory, puts the private key in the user-data `ssh_keys` section (cloud-init, AS → lab), records only the public key and its fingerprint in step evidence. The private key is never stored by OVLM. |
| Pin and rotate (B5) | Connect with `StrictHostKeyChecking=yes` against the bootstrap public key. Before anything else on that session (no `configure`, no secret delivered), regenerate the host keys on green, read the new public keys back over the same authenticated session, pin them in the per-run `known_hosts`, reconnect on the new key and verify. The bootstrap key is then no longer accepted by sshd; its exposure in user-data is harmless for impersonation of the rotated key. |
| Interrupted rotation | Re-run of B5 accepts the bootstrap key or a rotated key only if it matches the step evidence; anything else → `needs_human` "host key unverifiable". |
| Why D′ over B | An attacker needs both the bootstrap private key (user-data access) **and** a network position on the guest-access path during the build phase; under B a network position alone suffices. D′ is strictly stronger than B and does not depend on the console. |
| Why D′ over C as default | Same assurance class for the rotated key (it never leaves the guest except over an authenticated session), and it works on clouds where the console is empty. |
| Residual | Anyone who can read green's user-data during the build phase (cloud admins; project members if the cloud exposes user-data to them, AS) and can intercept the guest-access path can impersonate green until rotation, i.e. receive the `configure` run. They never receive the data volume (attached by OpenStack to the real green, verified by W6's UUID and marker checks). |
| Security-model rule | security-model.md §5.2 forbids secrets in user-data; the bootstrap key needs an explicit, documented exception there (Agent 8 to accept or reject). |
| Blue | Fingerprint recorded at registration (worker scan, operator confirms, audited). Mismatch at run time = `needs_human`. |
| Console text (policy `console`) | Untrusted guest output: size-capped, parsed by a strict pattern, never rendered unescaped (security-model.md §6.4). OVLM stores only the extracted fingerprint lines plus a SHA-256 of the console text (SEC-R-19). |
| No key by deadline | `needs_human` "host key unverifiable" in the build phase (no outage). Operator may change the policy (new profile version → plan re-approval). |
| Approvals | Unchanged: approvals and TCs remain human-only (security-model.md §7.2); the host-key policy is part of the profile version and so of the plan hash. |

## Consequences

- The default no longer depends on console output; renewals do not stall at B5 on clouds like Felcloud.
- Readiness check for `console`: "image prints SSH fingerprints to console" stays `unknown` until proved per image ID
  on the target cloud. For `injected`: "image's cloud-init honours `ssh_keys`" is checked by the first green build.
- Lab items: cloud-init `ssh_keys` injection on Ubuntu 24.04; rotation and reconnect within B5; visibility of
  user-data to a project member through the Nova API (AS).
- Timing (EXP-01): the console block appeared ~190 s after create when it appeared at all; EXP-01b: SSH answered ~85 s
  after ACTIVE. Both inform documentation of `timeouts.green_ssh` / `timeouts.green_host_key`; defaults stay TBD.
