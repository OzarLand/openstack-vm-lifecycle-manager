# ADR-0001 — Acceptance-test environment

| Field | Value |
|---|---|
| Status | **Superseded by [ADR-0007](ADR-0007-lab-on-felcloud.md)** (2026-11-04) |
| Date | 2026-11-04 |
| Deciders | Maintainer (decision), Agent 6 (recommendation), Agent 1 (record) |

## Context

The acceptance scenario needs an Ubuntu guest VM, a Cinder data volume, floating IPs and an Ansible-configured
application. `openstack-quick-lab` builds an all-in-one OpenStack 2026.1 (Kolla-Ansible 22.2.0) on one cloud VM, but
does **not** deploy Cinder. This session has no OpenStack credentials and no `/dev/kvm`. Analysis:
[test-environment.md](../test-environment.md).

## Options

- **A.** Extend `openstack-quick-lab` with an opt-in Cinder (LVM) option and run the acceptance and failure tests there.
- **B.** Use a dedicated project on a real OpenStack cloud.

## Decision

**Option A**, decided by the maintainer on 2026-11-04. The Cinder option is to be **proposed upstream** to
`openstack-quick-lab` as a contribution, not kept as a private fork.

## Consequences

- The upstream proposal (an issue first, then a pull request following that repository's `CONTRIBUTING.md` and
  `variant-or-exercise-proposal` template) is a backlog item for Phase 2. It is filed when the change has been run at
  least once, so the proposal carries evidence and not only a plan.
- Lab guests run under QEMU (TCG) without nested KVM, so timings measured there are not representative of production.
  Timeouts must be configurable.
- Lab floating IPs are reachable only from the lab VM. OVLM runs on the lab VM during acceptance tests, or has a route
  to the lab external network.
- Lab validation still needs an OpenStack cloud account to host quick-lab. That account is not available in this
  session.
- Option B remains possible later as a pre-release realism check. It is not required.
