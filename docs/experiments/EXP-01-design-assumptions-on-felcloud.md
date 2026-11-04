# EXP-01 — Check the Phase 1 design assumptions on a real cloud

| Field | Value |
|---|---|
| Owner | Agent 1 (plan); run by the maintainer's dev VM session (`ozar-dev`) |
| Status | **Proposed**: needs the maintainer's direct authorization in the `ozar-dev` session |
| Cloud | Felcloud, `clouds.yaml` entry `ozar-lab` (OpenStack release reported by the cloud, recorded at run time) |
| Last updated | 2026-11-04 |

## Why

The Phase 1 design depends on cloud behaviour that was checked only in the OpenStack source code
([openstack-integration.md](../openstack-integration.md)), or not checked at all. Checking it on a real cloud before
implementation is cheap, and an error found now costs a document edit instead of a rewrite.

| # | Question | Design that depends on it | Current evidence |
|---|---|---|---|
| Q1 | Can a project `member` read a server's console log, and does an Ubuntu cloud image print its SSH host-key fingerprints there? | ADR-0006 host-key policy | ASSUMPTION |
| Q2 | Which `/dev/disk/by-id/` path does an attached Cinder volume get inside the guest, and does it contain the volume ID? | automation contract `data_attach` | ASSUMPTION |
| Q3 | How long do stop → detach → attach take, and which volume and attachment states are seen in between? | renewal-workflow timeouts, the downtime window | SOURCE-VERIFIED (states), times unknown |
| Q4 | How long until a moved floating IP answers on the new VM (SSH and HTTP), as seen from outside? | cutover, downtime measurement | DOCUMENTED-UNVERIFIED |
| Q5 | Can tags be set at create, and does a tag filter find the server, as `member`? Is a metadata filter ignored for non-admins? | ADR-0005 idempotency | SOURCE-VERIFIED (upstream defaults) |
| Q6 | Does a locked server reject volume attach and detach from `member`, and can the same credential unlock it? | ADR-0004 lock timing | SOURCE-VERIFIED (upstream defaults) |
| Q7 | Maximum compute and volume API microversions, and the quotas and absolute limits of the project | NFR-8, FR-PLN-2 | unknown |
| Q8 | Can a host on the project network reach a new VM's fixed IP over SSH (the worker-to-guest path)? | architecture risk 1 | unknown |

## Rules for the run

- ⚠️ Every created resource is named `ovlm-exp01-*` and tagged `ovlm-exp01`. **Nothing else is touched.** Other
  resources in the project (other labs, other teams) are off-limits, even for read-only inspection beyond listing.
- Read-only steps first. Check quotas against current usage before creating anything.
- Show the cost estimate per hour before creating anything, and stop if the maintainer has not authorized it.
- Smallest flavor that runs an Ubuntu 24.04 cloud image; a 1 GB volume; one floating IP.
- 🛑 At the end, delete everything named `ovlm-exp01-*`, then list servers, volumes, floating IPs, ports, security
  groups and keypairs to prove nothing is left. Target duration: under 1 hour.
- Never print secrets, real IP addresses or hostnames in the report: use placeholders.

## Steps

| # | Step | Type | Answers |
|---|---|---|---|
| 1 | `openstack versions show`; `catalog list`; `limits show --absolute`; `quota show`; list flavors, Ubuntu 24.04 images, external networks and volume types | read-only | Q7 |
| 2 | Create keypair `ovlm-exp01-key`, security group `ovlm-exp01-sg` (SSH and HTTP 8080 from the dev VM only), volume `ovlm-exp01-data` (1 GB) | ⚠️ state-changing | — |
| 3 | Create servers `ovlm-exp01-blue` and `ovlm-exp01-green` with `--tag ovlm-exp01` (needs compute microversion ≥ 2.52) and `--property ovlm=exp01` | ⚠️ | Q5 |
| 4 | `server list --tags ovlm-exp01` and `server list --property ovlm=exp01` as member: compare results | read-only | Q5 |
| 5 | `console log show ovlm-exp01-blue`: look for the `BEGIN SSH HOST KEY FINGERPRINTS` block; compare with the fingerprint seen on first SSH | read-only | Q1 |
| 6 | SSH from the dev VM to blue's **fixed** IP (no floating IP yet) | read-only | Q8 |
| 7 | Attach the volume to blue; record the states seen; in the guest: `ls -l /dev/disk/by-id/`; make a filesystem (new blank volume, experiment only), mount it, write a marker file with a checksum | ⚠️ | Q2 |
| 8 | Start a tiny HTTP server on blue that serves the marker; create a floating IP and associate it with blue; check it answers | ⚠️ | — |
| 9 | Lock blue; try a detach as member (expect a refusal); unlock | ⚠️ | Q6 |
| 10 | Start a probe loop from the dev VM (HTTP to the floating IP every second, with timestamps). Then: unmount and stop blue → detach → attach to green → mount on green (by filesystem UUID) → start the HTTP server → move the floating IP to green. Timestamp every state change. | ⚠️ (simulates the downtime window) | Q3, Q4 |
| 11 | Check that green serves the same marker and checksum | read-only | Q3 |
| 12 | 🛑 Delete all `ovlm-exp01-*` resources and prove nothing is left | 🛑 destructive (own resources only) | — |

## Report

A table answering Q1–Q8, each with: observed result, evidence (redacted command output), and the measured times for
Q3 and Q4. Plus anything that contradicts [openstack-integration.md](../openstack-integration.md). The report goes
into this file under **Results**, with status `lab-observed on Felcloud, <date>, OpenStack <release>`.

## Results

Not run yet.
