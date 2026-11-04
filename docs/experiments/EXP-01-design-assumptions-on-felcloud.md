# EXP-01 — Check the Phase 1 design assumptions on a real cloud

| Field | Value |
|---|---|
| Owner | Agent 1 (plan); run by the maintainer's dev VM session (`ozar-dev`) |
| Status | **Run 2026-11-04**: lab-observed on Felcloud. Q1–Q3 and Q5–Q8 answered; Q4 not measured (no floating IP free) |
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
- Smallest flavor that runs an Ubuntu 24.04 cloud image; a 1 GB volume; **exactly one floating IP**, the only one available on 2026-11-04. If it cannot be allocated, Q4 is skipped and the report says so.
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

**Lab-observed on Felcloud, 2026-11-04.** The OpenStack release is not exposed; compute microversion 2.100
suggests Nova 2025.1 or later, block storage 3.71. Run by the `ozar-dev` session after the maintainer authorized it
directly. It took about 15 minutes, and every `ovlm-exp01-*` resource was deleted.

**Setup:** credential is a project user, not admin (HTTP 403 on `identity:list_role_assignments`). Flavor
`G0.basic.1c1g`, image "Ubuntu 24.04 LTS" (guest 24.04.4, kernel 6.8), volume type `NVMe`, project network shared
with the dev VM.

| # | Observed result | Evidence (redacted) |
|---|---|---|
| Q1 | **Yes.** This credential can read the console log. cloud-init prints `BEGIN SSH HOST KEY FINGERPRINTS` (ECDSA, ED25519, RSA) and the full `BEGIN SSH HOST KEY KEYS` block. The fingerprint matched first SSH contact. Green's key was pinned from the console log alone, then SSH worked with `StrictHostKeyChecking=yes`. The block appeared about 190 s after `server create`. | `cloud-init: 256 SHA256:<redacted> root@<host> (ED25519)` |
| Q2 | `/dev/disk/by-id/virtio-<first 20 characters of the volume ID>` → `vdb`: only a truncated ID. The API's device hint was `/dev/vdb`. Mounting on green by filesystem UUID worked. | `virtio-<volid[0:20]> -> ../../vdb` |
| Q3 | **States:** attach goes reserved → attaching → in-use; detach goes detaching → available. **Times:**<br>• stop to SHUTOFF: 13.4 s<br>• detach to available: 5.0 s<br>• attach to in-use: 9.3 s (6.7 s for the first attach)<br>• mount by UUID plus service start: 6.0 s<br>• HTTP answering: 10.4 s later (1 vCPU guest)<br>**Best-case outage:** about 45 s from unmount to green serving, excluding the floating-IP move and the time spent pinning a host key. | Event timeline with timestamps in the `ozar-dev` transcript |
| Q4 | **Not measured.** Floating IP allocation failed twice: HTTP 400 "Unable to find any IP address on external network", even though the project quota is unlimited. The maintainer's one floating IP is in use by `ozar-dev` and was not touched. | `BadRequestException: 400` |
| Q5 | Tags set at create (microversion 2.52) work: `tags=` and `tags-any=` returned exactly the 2 servers, and a tag matching nothing returned 0. The **metadata filter is silently ignored** for this credential: HTTP 200 with *every* server in the project, including one that is not ours. | raw `GET /servers?...` |
| Q6 | A locked server **refused detach and stop** (HTTP 409 "Instance is locked"). Attaching a volume that is in use elsewhere was refused (HTTP 400 "already attached"). The same credential could unlock. | 409 on `os-volume_attachments` DELETE |
| Q7 | Compute 2.100, block storage 3.71. Limits: 50 instances, 128 cores, 256 GB RAM, 48 volumes, 4096 GB of volumes; floating IPs and security groups unlimited. Catalog: keystone, nova, neutron, glance, cinderv3, placement, heat, swift, octavia, skyline. | `limits show --absolute` |
| Q8 | **Yes.** SSH from the dev VM to a fixed IP worked without a floating IP, and so did HTTP. The security group was restricted to the dev VM's addresses. | `ssh-ok` |

**Differences from [openstack-integration.md](../openstack-integration.md), and new findings:**

1. **No working default volume type:** `volume create` without a type returns HTTP 500 (`__DEFAULT__` not found).
   OVLM must always pass an explicit volume type, and preflight must check it.
2. **The floating IP pool can be empty while the quota is unlimited.** A quota check is not enough: allocation failure
   needs its own error path, and the MVP design (no temporary floating IPs) is confirmed as the right choice.
3. **Metadata filter ignored:** confirmed, and it returns other people's servers with no error. This confirms ADR-0005
   (tags, never metadata).
4. **by-id path:** confirms recommendation 11 (a 20-character prefix). Mounting by UUID works.
5. **Readiness:** the service needed about 10 s to listen on a 1 vCPU guest. Cutover waits on the health check, never on
   a fixed delay.

**Status changes:**
- ADR-0006: console-log host keys → **lab-observed** (Felcloud, member-equivalent credential, Ubuntu 24.04).
- Tag lookup, the metadata filter and lock behaviour → **lab-observed** (previously source-verified only).

**Still open:** the floating-IP move time (Q4). It needs a free floating IP, so it runs as EXP-01b when one is
available.

## EXP-01b — floating-IP cutover time (Q4) and the full window

**Planned 2026-11-04**, after the maintainer reported a free floating IP. It runs under `ozar-dev`'s standing approval
for `ovlm-*` resources on `ozar-lab`.

| # | Step | Type |
|---|---|---|
| 1 | Use the free floating IP. If it is already allocated and unassociated, use that one and leave it allocated but unassociated at the end. Otherwise allocate one and release it at the end. Never touch the floating IP that `ozar-dev` itself uses. | ⚠️ |
| 2 | Recreate `ovlm-exp01b-blue`, `ovlm-exp01b-green` (smallest flavor, Ubuntu 24.04, explicit volume type) and `ovlm-exp01b-data` (1 GB). Pin both host keys from the console log. | ⚠️ |
| 3 | On blue, serve the marker over HTTP from the mounted volume. Associate the floating IP with blue. Start a probe loop (HTTP every 0.5 s with timestamps) **through the floating IP**. | ⚠️ |
| 4 | Run the full window three times. Run 1: blue → green, with every state change timestamped (unmount, SHUTOFF, available, in-use, mount, service listening, floating IP updated, first successful probe through the floating IP). Run 2: back to blue (as a revert). Run 3: blue → green again. | ⚠️ |
| 5 | Report per run: the API time of the floating-IP update; the time from the update to the first good probe; and the **total outage seen by the probe**. Note where the probe ran from. | read-only |
| 6 | 🛑 Delete all `ovlm-exp01b-*` resources, handle the floating IP as in step 1, and prove nothing is left. | 🛑 own resources only |

### EXP-01b results — lab-observed on Felcloud, 2026-11-04

**Setup:** run by `ozar-dev`. Flavor `G0.basic.1c1g`, Ubuntu 24.04, `NVMe` 1 GB ext4 volume mounted by UUID, marker
served over HTTP from the volume. The pool had no free floating IP, so the maintainer's set-aside address was used,
then returned unassociated and unchanged. **Probe:** HTTP through the floating IP every 0.5 s, from the dev VM on the
same project network and router (a hairpin through the router's floating-IP translation, not from the internet).

| Run | Window | Floating-IP update (API time) | Update → first good probe | Total outage seen by the probe |
|---|---|---|---|---|
| R1 | blue → green | 1.26 s | ≤ 0.6 s | **40.6 s** |
| R2 | green → blue (revert) | 1.06 s | ≤ 0.3 s | **46.1 s** |
| R3 | blue → green | 1.10 s | ≤ 0.3 s | 94.9 s (target guest not yet reachable at T0: +55 s) |

**Where the outage goes (R1, about 40 s):**
- stop to SHUTOFF: about 11–12 s
- detach: about 3 s
- attach: about 5 s
- service start on 1 vCPU: about 10 s
- gaps between steps: 6–8 s, mostly CLI start-up time
- floating-IP move: about 3% of the window

There was no flapping: exactly one failure streak per run.

**Findings:**
1. **Q4 answered:** the floating-IP move is fast (about 1.1–1.3 s) and takes effect at once. No settle delay is needed
   after it.
2. **"ACTIVE" is not "ready".** Nova reported ACTIVE about 15 s after start, but SSH answered only about 85 s later
   (R3). **The workflow must prove the target guest is reachable before T0 (quiesce of the old VM)**, otherwise the
   outage doubles.
3. **The console log is not reliable.** Nova returned an empty console output for both servers (HTTP 200,
   `output: ""`), still empty 14 minutes after boot. This changes the EXP-01 Q1 result: console-log host keys are
   **lab-observed as sometimes unavailable** on this cloud. ADR-0006 needs a fallback; trust-on-first-use was used for
   these test VMs.
4. Confirmed again: the default volume type fails, and the floating IP pool can be empty while the quota is unlimited.

**Cleanup:** 0 `ovlm-*` resources left. The set-aside floating IP is unassociated and unchanged, and `ozar-dev`'s
floating IP was not touched.
