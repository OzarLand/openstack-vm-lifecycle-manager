# ADR-0007 — Acceptance tests run directly on Felcloud (supersedes ADR-0001)

| Field | Value |
|---|---|
| Status | Accepted. **Supersedes [ADR-0001](ADR-0001-test-environment.md).** |
| Date | 2026-11-04 |
| Deciders | Maintainer (decision), Agent 1 (record) |

## Context

ADR-0001 chose an `openstack-quick-lab` all-in-one extended with Cinder. In the meantime, EXP-01 and EXP-01b ran
directly on Felcloud, the cloud behind the `ozar-lab` entry used by the `ozar-dev` session. Felcloud is a real
OpenStack cloud with Nova, Cinder (volume types `NVMe` and `HDD`), Neutron floating IPs, Glance and Ubuntu 24.04
images. Those experiments answered the design questions there with the same non-admin credential OVLM will use.

## Decision

The maintainer decided on 2026-11-04: **do not use quick-lab; run the acceptance and failure scenarios directly on
Felcloud**, through the `ozar-dev` session.

## Consequences

- **Dropped from the backlog:**
  - E1-8 (the quick-lab Cinder option);
  - the upstream proposal to `openstack-quick-lab` that followed from ADR-0001.
- **"Lab validated" means "validated on Felcloud"**, with the OpenStack microversions recorded (compute 2.100,
  block-storage 3.71 at EXP-01). It is real KVM, not nested QEMU, so the measured times are representative of a real
  cloud, but of this one cloud only.
- **Every resource is named `ovlm-*`.** It is created and deleted under `ozar-dev`'s standing approval, within quota.
- **Known constraints:**
  - the floating IP pool can be empty, so the cutover reuses the address the maintainer sets aside;
  - there is no working default volume type, so OVLM always passes one;
  - the console log can be empty, so ADR-0006 relies on the bootstrap key.
- **Risk to keep visible:** the shared project also holds other resources (`ozar-dev` and at least one non-OVLM
  server). The write credential (`member`) can technically reach them. Only OVLM's ownership guard and write allowlist
  prevent it, which is the security model's stated residual risk. A **dedicated Felcloud project** for OVLM, with its
  own application credential, removes most of it, and is recommended.

## Maintainer decision on the project (2026-11-04)

Tests run in the **current `ozar-lab` project**, with `ovlm-*` resources only. The maintainer accepts the residual
risk: OVLM's ownership guard and write allowlist are the only protection for the other resources in the project,
including `ozar-dev`. Lab runs must therefore also check, before and after each run, that no non-`ovlm-*` resource
changed (a read-only snapshot comparison).
