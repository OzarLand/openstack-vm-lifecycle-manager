# ovlm-counter: the OVLM reference workload (backlog E1-7)

A tiny HTTP service whose state lives on a Cinder data volume, plus one Ansible playbook per phase of
[`docs/automation-contract.md`](../docs/automation-contract.md). It is the target of the acceptance scenario
([`docs/test-environment.md`](../docs/test-environment.md) section 4) and of OVLM's automation-runner tests (E5-3).
Written for Ubuntu 24.04 (EXP-01). The layout matches the contract: this directory is "the automation repo".

Status (see the summary in the commit message and `tests/run.sh`): lint, syntax check, the decision table and a
run against a local unprivileged container pass. **Nothing here has run on a real VM with a real volume.**
Tags used below: SOURCE-VERIFIED / DOCUMENTED-UNVERIFIED / ASSUMPTION, as in the docs.

## Layout

```
ansible/
  playbooks/{preflight,configure,data_attach,quiesce,start_service,healthcheck}.yml   # the contract's entry points
  playbooks/group_vars/all.yml      # short names + defaults for the `ovlm` extra-vars
  roles/ovlm_result/                # writes ovlm.result/1 (shared by every phase)
  roles/base|counter_app|data_volume|quiesce|healthcheck|preflight/
  roles/counter_app/files/ovlm_counter.py   # the service, Python standard library only
  lab/bootstrap_data.yml            # LAB ONLY: first-time mkfs. Outside playbooks/. OVLM never calls it.
  requirements.yml                  # pinned: ansible.posix 2.2.2
  tests/                            # run.sh, Dockerfile, decision-table test, result checker
```
`rollback_hooks.yml` is optional in the contract and is not provided (OVLM's own rollback comes first).
The roles need `ANSIBLE_ROLES_PATH=<repo>/roles` (ansible-runner sets it for a project; `tests/run.sh` sets it).
`ansible.posix` must come from the image or be vendored: OVLM does not run Galaxy at run time (contract section 2).

## The service

| Endpoint | Behaviour |
|---|---|
| `GET /` | increments the counter in SQLite on the data volume (`journal_mode=DELETE`, `synchronous=FULL`); 503 if the volume is not the expected mount |
| `POST /marker` | writes `<mount>/.ovlm-marker` (random token), returns its SHA-256 |
| `GET /health` | read-only JSON: `ok, mounted, fs_uuid, fs_type, device, marker_sha256, counter, generation, hostname`; **503** if `/srv/data` is not a mount point backed by `/dev/disk/by-id/virtio-<first 20 chars of the volume id>` |

The systemd unit has `RequiresMountsFor=/srv/data`. A `generation` row is added at each service start, so it only grows.
The service user has a **fixed uid/gid 9101**, so file ownership on the volume survives a VM replacement.

## Contract mapping

| Contract | Where | Notes |
|---|---|---|
| 3.1 `preflight` | `playbooks/preflight.yml`, `roles/preflight` | assert-only: become, free space, required commands, systemd |
| 3.2 `configure` | `base`, `counter_app` | packages (pins in `ovlm_packages`), user, app, env file, unit **not enabled, not started**, empty mount-point dir `0000` + `chattr +i` (DOCUMENTED-UNVERIFIED). Skips the dir tasks when the path is already a mount, so `--check` on the CURRENT VM does not touch the volume. A second run reports `changed=0` (tested) |
| 3.3 `data_attach` | `roles/data_volume` | by-id prefix match on `expected_serial[:20]`, bounded wait (`device_wait_seconds`, default 120), `blkid -o export -p`, decision table in `decide.yml` (tested with canned output), read-only `e2fsck -n`, mount **by UUID** with `defaults,nofail` (fstab by UUID), marker checksum. No formatting, ever: blank + `first_use=true` is `fatal` here |
| 3.4 `quiesce` | `roles/quiesce` | stops units (never disables), `fuser -m` must be clean, `sync`, `ansible.posix.mount state=unmounted` (never touches fstab, no force), retries 5 x 3 s then `needs_human`. Records the marker checksum under `/var/lib/ovlm-counter-state` on the **root disk** so a rerun after the unmount still reports it. Not mounted and no record: `needs_human` (state unknown), except with `ovlm.quiesce_allow_unmounted` on role `new` (restore S2 only): ok, `was_mounted: false`, no marker (lab finding AA) |
| 3.5 `start_service` | `playbooks/start_service.yml` | refuses (`needs_human`) when the mount is missing; enables+starts; waits for the port (60 s) |
| 3.6 `healthcheck` | `roles/healthcheck` | read-only, check-mode safe. Checks: `service_responds`, `data_mount` (fs UUID from the service must equal the host's `findmnt` view, and `ovlm.expected_fs_uuid` if given), `marker_checksum` (service view = Ansible's own SHA-256; = `ovlm.expected_marker_checksum` if given) |
| 3.7 result JSON | `roles/ovlm_result` | written to `ovlm_result_path` on the controller in a `block/rescue/always`, so a failed phase still writes it; `changed_when: false` keeps recap `changed=0` honest |
| 3.3 rule 6, section 10 lints | `tests/run.sh` (static lints) | no `mkfs/wipefs/dd/parted` in data_attach; `mkfs` only in `lab/bootstrap_data.yml`; `hosts: ovlm_target` only; no `ignore_errors`; quiesce never edits fstab or disables units; stand-in for the blocking `no_log` lint (this workload handles no secrets, so any secret-like arg fails) |

Every state-changing task is marked `STATE-CHANGING` in its name; read-only probes say `(read-only)` and set `check_mode: false` and `changed_when: false`.

### Inputs
Read from the `ovlm` object (`env/extravars`): `data_volume.{id,expected_serial,mount_point,fs_type,first_use}`, `vars.{app_port,data_marker,service_units,min_free_root_mib,device_wait_seconds}`, plus optional `expected_marker_checksum`, `expected_fs_uuid` and `quiesce_allow_unmounted` (restore S2 only). `ovlm_result_path` is a top-level extra-var. No secrets are used.

### Result classification and exit codes
Planned stops set a class (`needs_human`, `retryable`, `fatal`); an unplanned failure gets the phase default (`needs_human` for `data_attach` and `quiesce`, `retryable` otherwise) and `facts.error_kind = automation_error`. Any failed phase exits **2** (Ansible's "host failed"). **Contract ambiguity:** the contract's healthcheck exit table (0 / 2 unhealthy / 3 degraded / 1 other) cannot be produced by a playbook: Ansible fixes 3 = unreachable and reports every failed task as 2. So here `result.json` is authoritative (`classification`, `facts.health_state`, `facts.error_kind`) and no "degraded" state exists. OVLM should classify by `result.json` and use the exit code only as a fallback.

## Test mode (CI only)

An unprivileged container has no systemd, no block device and no mount. With the extra-var `ovlm_test_mode=true` (OVLM never passes it; it is not an `inventory_vars` key): the service is run by `start-stop-daemon` through a launcher script; the "mount" is a plain directory and the filesystem UUID is a constant; `/health` and the result say `simulated` / `test_mode: true`, and a **real** VM reporting a simulated mount fails `data_mount`. In test mode the unit file, `chattr`, `umount` and `fuser` paths are **not exercised**.

## Running the tests

```
pip install ansible-core ansible-lint yamllint     # CI pins its own versions
ansible/tests/run.sh lint        # yamllint, ansible-lint (production profile), --syntax-check, static lints, decision table
ansible/tests/run.sh container   # builds the Ubuntu 24.04 SSH target, runs the phases against it (needs docker, ssh, ssh-keygen)
ansible/tests/run.sh             # both
```
The container run does: preflight, configure twice (second `changed=0`), healthcheck before start (must fail), start_service twice, healthcheck (also `--check`), 5 increments + marker, healthcheck with right and wrong expected checksum, quiesce twice (checksum equals the marker; second `changed=0`; fstab untouched), healthcheck after quiesce (must fail), service restart (counter not lower, generation higher, marker equal).

### Not covered here (lab only, tracked in test-environment.md)
Real virtio by-id naming, `blkid`/`e2fsck -n` on a real volume (including a journal that needs recovery), mount/umount/fuser, systemd unit behaviour, `chattr +i` on the mount point, apt pins, the failure rows 9-11, and the "skip `data_attach` must fail health" negative control. `lab/bootstrap_data.yml` has never run.
