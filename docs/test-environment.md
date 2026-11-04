# OVLM acceptance-test environment

Status: DRAFT by Agent 6. Nothing here was lab-run (this container has no cloud credentials, no /dev/kvm).
Tags: SOURCE-VERIFIED (file named) / DOCUMENTED-UNVERIFIED / ASSUMPTION.
Acceptance scenario: Ubuntu guest VM + Cinder persistent data volume + Ansible-configured simple app + health check + floating IP cutover, ending with retention and retirement of the old VM.

## 1. Gap analysis: openstack-quick-lab vs the scenario

Read: openstack-quick-lab/README.md, variants/openstack-cloud/{README.md, config.example.env, remote-deploy.sh}.

| Need | quick-lab today | Gap / action |
|---|---|---|
| OpenStack control plane | Kolla-Ansible 22.2.0, OpenStack 2026.1, one Ubuntu 24.04 VM, 4 vCPU / 16 GB / 50 GB (SOURCE-VERIFIED: variants/openstack-cloud/README.md, config.example.env `KOLLA_ANSIBLE_VERSION`) | none |
| Cinder | "One node: no high availability, no Cinder, no Octavia" (SOURCE-VERIFIED: variants/openstack-cloud/README.md) | Must be added (2.1) |
| Compute virt type | `nova_compute_virt_type` = kvm if `/dev/kvm` exists and cpuinfo has vmx/svm, else qemu (SOURCE-VERIFIED: remote-deploy.sh `configure()`) | Depends on the outer cloud; see 2.2 |
| Image | CirrOS only, flavors m1.tiny.. from Kolla's `init-runonce` (SOURCE-VERIFIED: README table) | Add an Ubuntu cloud image (2.3) |
| Floating IPs | Lab external network `public1`, range `LAB_EXT_CIDR` default 10.99.0.0/24, on a veth pair into Neutron br-ex; "its floating IPs are reachable from the VM itself" (SOURCE-VERIFIED: README + config.example.env + remote-deploy.sh) | Works for cutover; OVLM must run ON the lab VM or reach 10.99.0.0/24 by a route/tunnel (2.4) |
| Key pair | `mykey`, private key on the lab VM at `~/.ssh/id_ecdsa` (SOURCE-VERIFIED: README) | reuse or create a dedicated OVLM key |
| Cost/time | Full run create..destroy 56 min 41 s measured 2026-10-23, pull 17 min 53 s (SOURCE-VERIFIED: README) | Cinder adds some minutes: unmeasured |

### 2.1 Cinder (not in quick-lab)
All of the following is DOCUMENTED-UNVERIFIED (not found in quick-lab; from Kolla-Ansible docs as recalled; verify against 22.2.0 docs before use):
- `globals.yml`: `enable_cinder: "yes"`, `enable_cinder_backend_lvm: "yes"` (key names may differ by release; also `cinder_volume_group: "cinder-volumes"`, default name per docs).
- Prerequisite on the host: an LVM volume group named as above. In a lab VM without a spare disk: create a sparse file, attach with `losetup`, `pvcreate`, `vgcreate cinder-volumes /dev/loopN`, and make it survive reboot (systemd unit). A second Cinder volume on the OUTER cloud attached to the lab VM would be cleaner but needs outer Cinder and changes `create.sh` (ASSUMPTION).
- Sizing: loop file must hold data volume(s) + test copies; size is a lab decision, not a number to copy from here.
- Other: `lvm2` and iSCSI tooling on the host (DOCUMENTED-UNVERIFIED: target-side iSCSI daemon in Kolla's LVM backend; for a single node, tgt/lioadm). Attaching the volume to a QEMU instance on the same node goes through iSCSI/os-brick on the host.
- Cinder in the lab also adds containers to a 16 GB VM that already hosts all-in-one core services: RAM pressure risk (ASSUMPTION; measure).
- After `kolla-ansible deploy`: verify with `openstack volume service list`, create/attach/detach a 1 GB test volume to the CirrOS `demo1` BEFORE any OVLM test.

### 2.2 Nested virtualisation
- quick-lab auto-falls back to qemu (TCG) when the lab VM has no /dev/kvm (SOURCE-VERIFIED: remote-deploy.sh line `local virt=qemu; [ -e /dev/kvm ] ...`). Its README measured a run "with nested KVM" on the reference cloud (SOURCE-VERIFIED: README), so nested KVM is possible there but is not guaranteed on any other outer cloud.
- With TCG an Ubuntu guest boots slowly (minutes; cloud-init and package installs slower still). OVLM and Ansible timeouts in the lab need generous values (ASSUMPTION; measure, do not copy the contract defaults). Two Ubuntu guests at the same time (old + new) on a 16 GB lab host is tight: pick a small flavor and measure memory (Nova overcommit applies; DOCUMENTED-UNVERIFIED).
- Check first: `ls /dev/kvm` and `virt-host-validate` (or `grep -E 'vmx|svm' /proc/cpuinfo`) on the lab VM; record the result in the evidence.

### 2.3 Ubuntu image
- Upload an official Ubuntu 24.04 cloud image (qcow2) to Glance with `--disk-format qcow2 --container-format bare`; verify the published checksum before upload (do not hard-code a checksum here). The lab VM may sit behind an HTTPS proxy (config `HTTPS_PROXY`, SOURCE-VERIFIED), so the download should be done where the proxy applies.
- Flavor: m1.small/m1.medium from init-runonce exist (SOURCE-VERIFIED: README lists them) but their sizes are not stated there; check `openstack flavor list`, and create a dedicated flavor if the disk is too small for the Ubuntu image.
- cloud-init: key injection via `mykey`/dedicated key; SSH user `ubuntu`.
- Python is present in the Ubuntu cloud image (ASSUMPTION; Ansible needs it on the guest).

### 2.4 Floating IPs
- The lab external network gives real Neutron floating IP semantics (associate/disassociate/move between ports) which is what MVP cutover needs. The lab net is a veth into br-ex, so only the lab VM (or hosts routed to it) reach those IPs (SOURCE-VERIFIED: README). Consequence: run the OVLM worker, the Ansible runner and the healthcheck on the lab VM or a host that can reach 10.99.0.0/24. Choose one and document it.
- The guest VMs need outbound access for apt (ASSUMPTION): lab SNAT or a local mirror/proxy; the demo network is 10.98.0.0/24 by default in `init-runonce` call (SOURCE-VERIFIED: remote-deploy.sh). Verify egress before testing.
- "Port without router" failure injection relies on Neutron router semantics: floating IPs need the port's network connected to a router with an external gateway (DOCUMENTED-UNVERIFIED for this lab; `init-runonce` creates a router per Kolla docs).

## 3. Options

| | A. Extend quick-lab with Cinder LVM | B. Dedicated project on the OUTER cloud with Cinder + floating IPs |
|---|---|---|
| Realism | Lower: single node, loop-device LVM, TCG possible, iSCSI loopback | Higher: real multi-host compute, real Cinder backend, real attach/detach timing, real quota behaviour |
| Cost | Low and known (README gives per-hour cost and a 56 min run for the base lab); extra loop device cost negligible | Per-resource cost on the outer cloud (volumes, FIPs, VMs); no lab install time |
| Time to first test | Long: build lab (~1 h) + add Cinder + debug | Short if the project exists |
| Safety | High: disposable, `destroy.sh` removes the lab; OVLM credentials only touch the lab | Risk: OVLM could act on unrelated resources; needs hard isolation |
| Failure injection | Full control: stop services, set quotas, break Neutron, kill containers | Limited to project-level levers (quotas if admin, security groups, bad flavor/image); cannot stop outer services |
| Reproducibility for contributors | High (public repo) | Low (depends on a private cloud) |
| Contribution value | A `variant flag` for Cinder LVM in quick-lab would benefit OzarLand | none |

Recommendation: **A for the acceptance gate (CI-adjacent, destructive tests, failure injection), plus B as a smoke/realism run before release**, if a dedicated project exists. Do A first because failure injection needs control of the cloud and because OVLM must never be exposed to a project holding unrelated resources. Proposed contribution to openstack-quick-lab: an opt-in variant flag (for example `ENABLE_CINDER_LVM=yes` in config.env; name is a proposal) that writes the Cinder globals, creates the loop-backed VG and runs a volume smoke test in `post-deploy` (ASSUMPTION: maintainers agree; follows the style of `remote-deploy.sh` `configure()`).

Safety rules for either option (mandatory):
1. Dedicated OpenStack project (and, in B, dedicated credentials via `OS_CLOUD`/application credential limited to that project); OVLM refuses to start unless the project name matches a configured allow-pattern and the project contains no resources lacking an OVLM tag (ASSUMPTION: architect implements; pre-flight listing shows the human what exists).
2. OVLM only acts on resources it created or that are explicitly named in a profile (by id); never "all servers in the project".
3. Quotas set on the dedicated project to cap damage.
4. Teardown script lists, then deletes only resources carrying the run tag.

## 4. Reference workload: `ovlm-counter`

Tiny HTTP service (Python stdlib or Go, a single file) with state on the data volume:
- `GET /` returns and increments a counter stored in SQLite `/srv/data/counter.db` (WAL off, `synchronous=FULL`), plus a monotonically increasing `generation` row.
- `POST /marker` writes `/srv/data/.ovlm-marker` containing a random token and returns its SHA-256; the test harness stores that before the renewal.
- `GET /health` returns JSON: `{mounted: bool, fs_uuid, marker_sha256, counter, ok}`; `mounted` is true only if `/srv/data` is a mount point whose backing device is the expected volume (`findmnt`); returns 503 if the data volume is absent, so a VM that silently writes to its root disk fails health.
- Writes only to the data volume; the service unit has `RequiresMountsFor=/srv/data`.

Mechanical "data survived" test: (1) before renewal, call `/` N times and `POST /marker`; record counter and marker; (2) after cutover, `GET /health` via the floating IP: `marker_sha256` equals stored, `counter >= recorded`, `fs_uuid` equals recorded, and server hostname/VM id differs from before (proves it is the new VM). (3) negative control: a renewal where `data_attach` is skipped must fail the health check.

Ansible role layout (sketch, matching the contract):
```
app-ansible/
  requirements.yml            # pinned collections (ansible.posix, community.general if used)
  playbooks/{preflight,configure,data_attach,quiesce,start_service,healthcheck,rollback_hooks}.yml
  roles/
    base/        # packages, ovlm user, chrony, unattended-upgrades policy
    counter_app/ # app file, systemd unit (not started), env file (no secrets)
    data_volume/ # find by-id device, blkid decision table, mount by UUID
    quiesce/     # stop units, fuser check, sync, umount, emit marker checksum
    healthcheck/ # uri checks, assert, write result.json
  molecule/      # container-target tests (section 6)
```

## 5. Failure-injection plan (lab only unless noted)

"Expected" is the behaviour OVLM should show, to be CONFIRMED by the architect (ASSUMPTION for all rows).

| # | Failure | Inject | Expected OVLM behaviour | Evidence to collect |
|---|---|---|---|---|
| 1 | Interrupted workflow | `kill -9` the worker during (a) provisioning wait, (b) `configure`, (c) `quiesce`, (d) volume detach/attach, (e) before cutover | On restart the workflow resumes from persisted state; derives truth from OpenStack + read-only probe; no duplicate VM/volume attach; data phases go to needs-human if state ambiguous | DB step rows before/after, OpenStack server/volume/attachment lists, orphan run dirs, worker log, process list for stray ansible |
| 2 | Insufficient compute capacity | `openstack quota set --cores 0` (or instances 1) on the dedicated project | Provisioning step fails fast with a clear class (retryable then needs-human); old VM untouched; no volume change | Nova error/fault message, workflow state, proof old VM still serving (health 200) |
| 3 | Failed provisioning | Profile with nonexistent image id / flavor that cannot boot (too small disk) | Step fails, new VM (if created in ERROR) cleaned up by OVLM only if tagged as its own; nothing else modified | `server show` fault, cleanup log, resource diff before/after |
| 4 | Failed Ansible config | Broken var in profile (e.g. nonexistent package, bad template var) or pin ref with a deliberate error | `configure` fatal/retryable classification per contract; new VM left or deleted per policy; old VM untouched, volume still on old VM | redacted run log, result.json, exit code, proof volume attachment unchanged |
| 5 | Failed health check | Start service with wrong port/ stop app on the new VM after `start_service`; or skip marker file | Bounded repeat then rollback: volume returned to old VM, old service restarted, floating IP never moved | healthcheck result.json history, attachments, FIP association, old VM `/health` |
| 6 | Failed cutover | Remove the router external gateway; or Neutron policy denying `update_floatingip` for the OVLM user; or port security issue | Cutover step fails; floating IP stays on old VM or is restored; workflow rolls back or needs-human; downtime duration recorded | `floating ip show` before/after, Neutron error, timeline |
| 7 | Database restart | `docker restart`/stop PostgreSQL (Docker in CI too) mid-workflow, for 30 s | OVLM reconnects, no lost or double-applied step; idempotency keys honoured | DB logs, step table, workflow outcome |
| 8 | Worker restart | SIGTERM (graceful) and SIGKILL separately | SIGTERM: current subprocess terminated, state saved as interrupted; SIGKILL: sweeper cleans leftovers | as row 1 |
| 9 | Detach refused | Keep a process holding the mount on old VM (`sleep` in `/srv/data`) | `quiesce` fails needs-human; volume not detached | quiesce result, Cinder status `in-use` |
| 10 | Data safety negative | Give OVLM a blank volume with `first_use=false` | `data_attach` fails needs-human, no mkfs | blkid before/after, result.json |
| 11 | Volume device naming | Attach a second volume first so the data volume is not `/dev/vdb` | Correct device found via by-id | device path in result, md5 of marker |

Common evidence set for every run: OVLM audit trail, DB dump of workflow tables, `openstack server/volume/floating ip list` (with `--long`) before and after, Ansible run record, timestamps for downtime, lab VM `docker ps` and `dmesg` tail.

## 6. CI (no cloud) vs lab-only

| Test | CI without cloud | Lab-only |
|---|---|---|
| Unit tests: state machine, classification, redaction, secret handling, profile validation (pinned SHA) | yes | |
| OpenStack calls against a fake (SDK stubbed/`requests_mock`/own fake server) for happy path and fault returns | yes (fidelity limited: fake is what we wrote) | |
| PostgreSQL in Docker: migrations, locks, crash-resume (kill worker process in test) | yes | |
| `ansible-playbook` against a local container as target (Ubuntu 24.04 container, SSH, systemd may be missing; use molecule/systemd image or `service` mocks) for `configure` twice-idempotency, `healthcheck` | yes (partly) | |
| `data_attach` logic with a loopback file image + `losetup` in a privileged container (decision table cases: blank, ext4, wrong fs) | possible if privileged containers allowed (ASSUMPTION; /dev/disk/by-id absent in containers, emulate with udev-less symlinks) | real virtio serial naming |
| ansible-lint, yamllint, `--syntax-check`, requirements pin lint | yes | |
| Real Cinder attach/detach, virtio serial truncation, udev by-id, iSCSI behaviour | | yes |
| Nova scheduling/quota/fault, Neutron floating IP move, router/gateway failures | | yes |
| TCG timing, boot time, timeouts tuning | | yes |
| Rows 1-11 of section 5 end-to-end | | yes (rows 7 and parts of 1/8 reproduce in CI against fakes) |
| Reproducibility check-mode drift on a real VM | | yes |

Pass criterion for acceptance (proposal): one full renewal with data-survival assertions, plus rows 1, 5, 6 and 10 behaving as expected; evidence archived per run.

## 7. Open points for the architect

1. Is workflow state persisted and re-derivable after a worker crash (the contract relies on it)?
2. Is there a lock/lease per VM and volume?
3. Who owns cleanup of OVLM-created but unreferenced resources?
4. Where does OVLM run in the lab (on the lab VM, or reaching 10.99.0.0/24)?
5. Policy for host-key trust on freshly provisioned VMs.
