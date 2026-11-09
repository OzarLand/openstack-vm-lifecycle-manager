# OVLM <-> Ansible automation contract

Status: DRAFT by Agent 6 (Automation Engineer). Nothing here has been run: this container has no cloud, no /dev/kvm.
Tags: SOURCE-VERIFIED (read in a named file) / DOCUMENTED-UNVERIFIED / ASSUMPTION.
Principle: the VM is replaceable; the service and its data outlive it. OVLM must not assume a VM is reproducible: it must measure it (section 9).

> **Revision 2026-11-04**: synced to the architecture revision (renewal-workflow.md). Addressed: SRE-R-8 and SEC-R-12 (section 2:
> one verified clone per run, no run-time Galaxy, no submodules), SRE-R-3 (section 3 `first_use`), SRE-R-1 (section 3.4: no
> fstab edit, units stopped never disabled), SEC-R-3 (sections 5 and 9: blocking `no_log` lint with audited waiver,
> `store_diffs`, OVLM stores task results).
>
> **Revision 2026-11-04 (round 2)**: synced to architecture round 2. Section 9: lint is static analysis only, `check_mode`/`delegate_to` rules
> (SEC-R-35); section 2: `--syntax-check`/`--list-hosts` move to step B6; section 3.6/3.7: healthcheck result authoritative in `result.json`,
> optional input `ovlm.expected_fs_uuid` (reference workload).
>
> **Revision 2026-11-04 (image/docs alignment)**: section 3.6.1 defines the external-probe identity contract.

## 1. Profile reference to automation

A workload profile holds an `automation` block (ASSUMPTION: profile is a DB/JSON document owned by the architect).

```yaml
automation:
  repo: https://git.example.org/team/app-ansible.git   # https or ssh URL
  ref: 3f9c2a1e...            # full commit SHA. Tags allowed only if OVLM resolves and stores the SHA at profile save
  playbook_dir: playbooks/    # contains the phase entry points (section 3)
  requirements: requirements.yml   # collections + roles, every entry version-pinned
  inventory_vars: {app_port: 8080, data_mount: /srv/data}   # non-secret only
  secret_refs: {vault_password: ovlm-secret://..., ssh_key: ovlm-secret://...}
  timeouts: {configure: 1800, ...}   # optional overrides, bounded by OVLM maximums
```

Rules:
- `ref` must resolve to an immutable commit. Branch names (`main`, `stable/*`) are refused at validation. Reason: moving refs make a re-run differ silently; pinned `stable/<series>` branches are renamed when a series goes Unmaintained (SOURCE-VERIFIED: openstack-automation-review/SKILL.md, step 7).
- OVLM records the resolved SHA, the `requirements.yml` hash and the ansible-core version in every run record (needed for reproducibility evidence).
- `requirements.yml`: every collection/role has an exact `version:` (roles from git need a SHA). Unpinned entries fail validation. Installation uses an isolated per-run path (`ANSIBLE_COLLECTIONS_PATH`, `ANSIBLE_ROLES_PATH` set to the run dir), never `~/.ansible`.
- OVLM does not execute anything from the repo at validation time (no template rendering, no `ansible.cfg` honoured: OVLM sets its own `ANSIBLE_CONFIG`, see 2).
- The repo contains no secrets. Secrets come via section 5.

## 2. Invocation

Recommendation: **ansible-runner as a subprocess** (`ansible-runner run <private_data_dir> ...`, run from the OVLM worker via `subprocess`, not imported as a library). DOCUMENTED-UNVERIFIED (ansible-runner behaviour; verify in version chosen).

| Criterion | ansible-runner (subprocess) | raw ansible-playbook |
|---|---|---|
| Structured events (task, host, status) in `artifacts/<id>/job_events` | yes | stdout parsing only |
| Per-run dir layout (project/inventory/env/artifacts) | built in | hand-built |
| Secrets via `env/passwords`, `env/ssh_key`, `env/extravars` files | yes | hand-built |
| Timeout / idle timeout | `--timeout`, `--idle-timeout` options (DOCUMENTED-UNVERIFIED) | outer `timeout` only |
| Interruption / cancel | terminates process group; `artifacts` kept | same, no events |
| Extra dependency | yes (pin it) | none |

Reason for subprocess over in-process library: a crash or hang in Ansible must not take down the OVLM worker; the worker can SIGTERM then SIGKILL the process group (ASSUMPTION: worker is the process that owns the step). A fallback to bare `ansible-playbook` with `ANSIBLE_STDOUT_CALLBACK=json`/`yaml` is acceptable if ansible-runner is unavailable; the contract (inputs/outputs below) is identical.

Isolation rules (per run, per phase attempt):
- New directory `$OVLM_RUN_ROOT/<workflow_id>/<step_id>/<attempt>/` mode 0700: `project/` (a local copy of the run-level checkout below), `inventory/`, `env/`, `artifacts/`, `tmp/`.
- No shared mutable state between runs: no shared `~/.ansible`, no fact cache across runs (`gathering` per run; fact cache disabled), no shared known_hosts (see below), no reuse of a checkout across runs.
- **One verified clone per run.** OVLM clones the automation repo once per run (step `prepare_automation`, before the downtime window), checks out the full commit SHA, verifies `git rev-parse HEAD == ref`, and keeps the result as a read-only run-level checkout. Each phase attempt copies from it locally; nothing contacts the git host inside the downtime window. Git submodules are disabled and not supported.
  The run-level checkout lives on `automation.run_root` (tmpfs): it survives a worker *process* restart, not a *container* restart. With `automation.checkout_cache` set (compose: the worker-only `checkouts` volume at `/var/lib/ovlm/checkouts`, 0700 `ovlm`, not readable by `ovlm-ansible`), B6 also keeps a copy there and records the checkout's **tree digest** (sha256 over a sorted manifest of relative path, type, permission bits, symlink target and content sha256) in its step evidence (`prepared.tree_digest`). After a container restart the worker re-adopts the copy only if the digest of the tree it copies back into `run_root` equals the recorded one, then re-runs the lint, pin and collection checks; a mismatch, a copy without a recorded digest, or no copy at all stops the step for a human (`needs_human`). This path never contacts the git host. **Lifecycle of the checkout (roadmap P0-1).** The run-level checkout on `run_root` (RAM) and its cached copy are removed together, by one sweep with one rule: a run that is not terminal keeps both whatever their age (it may wait days at a gate, and the cached copy is what a restarted container re-adopts); a run the database reads terminal (`completed`, `rolled_back`, `failed`, `cancelled`, `rejected`; terminal is final) loses both at once; an entry of no known run only once older than the orphan max age (a run admitted after the active runs were read is never swept). The worker applies it after each step it executed, for that step's run (so the run's last step frees its checkout as soon as the run is terminal, whichever worker committed that and whatever became of this attempt), at start-up before the first claim (runs that ended while the worker was down) and hourly (runs ended by a signal, without a step). Each worker sweeps its own `run_root`. On `run_root` only `<workflow_id>/_checkout`, `_checkout.sha` and an interrupted `_checkout.adopt` are removed (then the directory, if empty); step run directories stay with the orphan sweeper and the worker's own entries (`.ca`, `.cp`, `.ssh-*`) are never touched. A checkout the worker process still remembers but that is gone from disk is forgotten and adopted again as above. A sweep that cannot read the runs removes nothing and is not fatal.
  **The only git contact allowed inside the window** is an explicit approver authorization, `reprepare-automation` (renewal-workflow.md §2): on a step parked because the checkout is gone or unverifiable, an approver who is not the run's requester, with a password+TOTP step-up and the TC, authorizes **one** re-clone of the run's pinned SHA. The worker consumes the authorization before cloning, runs the normal verified clone, lint and waivers, and keeps the result only if its tree digest equals B6's recorded digest (when B6 recorded one); otherwise it discards it and stops for a human. Each authorization is used once, recorded in `automation_reprepare` and audited (`automation.reprepare.authorized`, `.used`, `.refused`).
- **No downloads at run time.** No Ansible Galaxy (or any other registry) download during a run: collections and roles come from the repo at that SHA (vendored) or from the OVLM image. This supersedes the per-run install of `requirements.yml` in section 1, which becomes a version-pin check against what is vendored or shipped.
- OVLM-owned `ansible.cfg` (written into the run dir, `ANSIBLE_CONFIG` env): `host_key_checking` per policy below, `retries`, `timeout`, `callbacks_enabled` minimal, `display_args_to_stdout = false`, `no_target_syslog = true` (DOCUMENTED-UNVERIFIED option names, verify).
- Inventory is generated by OVLM with exactly the target host(s) of the step (never `all`, never a group from the repo): `ansible_host`, `ansible_user`, `ovlm_role` (old|new). Playbooks must declare `hosts: ovlm_target`; a playbook with another `hosts:` pattern is a contract violation detected by a `ansible-playbook --list-hosts` check. `--syntax-check` and `--list-hosts` execute Ansible on repo content, so they run **only inside a run, in step B6 (after G1)**, never at lint, diff or readiness time (SEC-R-35).
- Host keys: OVLM reads the new VM's host key from console log / cloud-init output when available and writes a per-run known_hosts; otherwise `StrictHostKeyChecking=accept-new` for the first connect on a freshly provisioned VM only (ASSUMPTION: acceptable for MVP; architect decides). For the OLD VM use the key recorded at its first onboarding.
- Run end: artifacts are copied to OVLM storage (redacted), then the dir is wiped (`shred` not required; 0700 + tmpfs recommended for `env/`).
- Concurrency: at most one automation run per target VM (lock keyed by VM id, held by the workflow engine; ASSUMPTION: engine offers locks/leases).

## 3. Phases (entry points)

One playbook per phase in `playbook_dir`: `configure.yml`, `quiesce.yml`, `data_attach.yml`, `start_service.yml`, `healthcheck.yml`, optional `rollback_hooks.yml`, optional `preflight.yml`. OVLM calls only these names. A profile may omit `quiesce`/`start_service` only if it declares `stateless_service: true` (then no data volume handover is allowed for it).

Common extra-vars (always passed, as a JSON file `env/extravars`, never on the command line):

| Var | Type | Notes |
|---|---|---|
| `ovlm.workflow_id`, `ovlm.step`, `ovlm.attempt` | string/int | for log correlation and idempotency tokens |
| `ovlm.role` | `old`\|`new` | which VM this run targets |
| `ovlm.check_mode` | bool | OVLM also passes `--check --diff` itself; playbook must honour it |
| `ovlm.service_name` | string | profile value |
| `ovlm.data_volume.id` | uuid | Cinder volume id |
| `ovlm.data_volume.expected_serial` | string | see below; equals volume id (ASSUMPTION, see 3.3) |
| `ovlm.data_volume.mount_point` | path | e.g. `/srv/data` |
| `ovlm.data_volume.fs_type` | string | expected fs, e.g. `ext4` |
| `ovlm.data_volume.first_use` | bool | **Always `false` for renewals**: the renewal strategy cannot pass `true`, and the value passed is recorded in the step evidence. `true` is reserved for a future initial-provisioning strategy with its own gate. A blank volume during a renewal stops for a human (decision table, section 3.3) and is never formatted. |
| `ovlm.vars` | object | profile `inventory_vars` (non-secret) |
| `ovlm.quiesce_allow_unmounted` | bool, optional | `quiesce` on the NEW VM in restore step S2 only (section 3.4). OVLM refuses to render it for any other phase or for role `old`; absent means `false` |

Secrets are NOT in this object (section 5).

### 3.1 `preflight` (optional, read-only)
Checks SSH, sudo, python, disk space. Must change nothing (assert-only). Output: JSON result (3.7). Failure is retryable.

### 3.2 `configure`
- Runs on the NEW VM before the data volume is attached. "No data present" is an invariant: tasks must not reference `data_volume.mount_point` contents.
- Idempotent: a second run reports `changed=0` (OVLM checks this in the reproducibility step, section 9). Use modules, not raw `shell`; `command`/`shell` need `creates`/`changed_when`.
- Installs packages (versions pinned in vars), users, systemd unit files, but **does not enable-and-start** the data-dependent service (that is `start_service`). It may create the mount-point directory (empty, owned root, mode 0000 or immutable attr so nothing writes to the root disk by mistake: `chattr +i` on the empty directory is recommended; DOCUMENTED-UNVERIFIED on target fs).
- Safe to rerun at any time on the new VM and, in check mode, on the current VM (reproducibility, section 9).

### 3.3 `data_attach` (runs on NEW VM after OVLM attached the Cinder volume)
Inputs: `ovlm.data_volume.*`.
Rules (mandatory):
1. Locate the device by `/dev/disk/by-id/virtio-<serial>` where serial = Cinder volume id truncated per the guest's udev rule; never `/dev/vdb`. DOCUMENTED-UNVERIFIED: the virtio serial is the first 20 characters of the volume uuid and may be truncated, so the match is a prefix match on `expected_serial[:20]`; OVLM must confirm in the lab (ASSUMPTION flagged in test-environment.md).
2. Wait for the device (bounded, default 120 s), then fail "retryable" if absent. Never fall back to "the only extra disk".
3. Inspect with `blkid -o export <dev>` (read-only). Decision table:

| Observed | Action |
|---|---|
| fs present, type == `fs_type` | do NOT mkfs; `fsck -n` (read-only) must pass or fail `needs-human`; mount |
| fs present, type != expected | fail `fatal`/needs-human; never reformat |
| no fs and `first_use == true` | `mkfs` allowed, with label = volume id |
| no fs and `first_use == false` | fail `needs-human` (a volume that should hold data is blank: possible wrong device or data loss) |
| partition table / LVM / unknown signature | fail needs-human |

4. Mount by UUID or label via `ansible.posix.mount` with `state: mounted`, `opts: defaults,nofail`; write fstab by UUID, never by device name.
5. Verify marker: if `data_marker` (a file path profile-defined, default `.ovlm-marker`) exists, read it; its checksum is returned in the result JSON.
6. Never `wipefs`, `mkfs -f`, `dd`, `parted mklabel` anywhere in the repo's `data_attach`. OVLM static-lints the playbook for these strings before the run (cheap, advisory; not a proof).

### 3.4 `quiesce` (runs on OLD VM, before OVLM detaches the volume; on the NEW VM in restore step S2)
- Stop write sources: stop the service units listed in `ovlm.vars.service_units`, confirm no process holds the mount (`fuser -m`/`lsof` read-only), `sync`, `umount <mount_point>`; never edit fstab and never disable units. Service units are stopped, never disabled, and the fstab entry (by UUID or label, `nofail`) stays in place: restore boots the old VM again and relies on fstab to remount the volume and on enabled units to restart the service.
- Idempotent: if already stopped/unmounted, report ok. "Already unmounted" means a record of an earlier quiesce exists (the reference workload keeps it on the root disk, `last-quiesce.json`) and its marker checksum is reported again.
- **Not mounted and no earlier record**: on the OLD VM (W1) this state is unknown (someone unmounted it, or the VM is not the one OVLM thinks): fail `needs_human`. On the NEW VM in restore step S2, OVLM passes `ovlm.quiesce_allow_unmounted: true` (lab finding AA, 2026-11-08: the worker died after W5 attached the volume and before W6 mounted it, so green holds the volume but never mounted it). Then the phase stops the units as usual and reports **ok** with `facts.was_mounted: false` and **no** marker checksum (`facts.marker_sha256: null`), writes no record, and unmounts nothing. The playbook honours the flag only when `ovlm.role` is `new`. OVLM never passes it from W1, and the restore compares no marker (S7's healthcheck on the old VM gets no `expected_marker_checksum`): S2's evidence records `green_was_mounted: false` and `marker_comparison: skipped ...` so the gap is visible, and W1's checksum from the old VM stays the recorded value. A repo that ignores the flag still fails `needs_human` there, which is safe (restore parks).
- Must refuse (fail needs-human) if `umount` fails after the bounded wait: OVLM must not detach a mounted volume in MVP. OVLM never passes a "force" flag.
- Output includes final marker checksum (the value later compared on the NEW VM) as `facts.marker_sha256` (section 3.7; the same key in `data_attach` and `healthcheck`). Except in the S2 "never mounted" case above (`null`), it is **required whenever the renewal has a data volume**: a successful quiesce without it parks W1 `needs_human` (`quiesce_no_marker`) before the old VM is stopped, because without it OVLM cannot prove on the new VM that the data survived. OVLM does not skip the comparison silently. The data marker file must therefore exist on the volume before a renewal.
- This phase causes service downtime; OVLM requires the maintenance-window decision to be recorded before calling it (section 10).

### 3.5 `start_service` (NEW VM)
Enables and starts units; waits for the unit to be active; no data modification beyond what the service does normally. Idempotent (`state: started`).

### 3.6 `healthcheck`
Read-only, may run any number of times and in check mode. Contract:
- Exit code: 0 healthy, 2 unhealthy (retryable: wait and repeat), 3 degraded-but-serving (treated as unhealthy unless profile sets `accept_degraded`), 1/other = automation error. **Clarification (reference workload): the result is authoritative in `result.json`** (`classification` and `facts.health_state`), not the exit code, because Ansible's own exit codes cannot express 2/3/1 (a playbook run ends 0 or non-zero; there is no "degraded" state). The exit code is used only when `result.json` is missing or malformed (section 3.7).
- Produces `artifacts/result.json` (3.7) with `checks[]`: each `{name, ok, detail, observed, expected}`. Required checks: service responds (profile-defined URL/port), data mount present and by expected fs UUID, marker checksum equals `ovlm.expected_marker_checksum` (passed by OVLM from the `quiesce` output of the old VM). Optional input `ovlm.expected_fs_uuid` (the filesystem UUID recorded for the data volume): when present, the data-mount check compares the mounted filesystem UUID against it.
- Timeout per call 60 s default; OVLM does the repetition/backoff, not the playbook.

### 3.6.1 External-probe identity contract (B8, W10, S9)
The health endpoint behind `health_check.external` must prove **which server answered**; "something answered" is not
enough, because after the FIP move a stale or still-attached VM could answer too. OVLM reads the identity in this
order and uses the first one present:
1. HTTP response header `X-OVLM-Server-Id`;
2. else JSON field `server_id` in the body;
3. else JSON field `hostname` in the body.

The value must equal what OVLM expects for that probe: the Nova server id of the VM that must be serving (blue at B8
and S9, green at W10). A response without any of the three, with a different value, or a plain TCP/HTTP-status-only
check **cannot pass B8, W10 or S9**. The value is data from the guest: compared for equality, length-capped, never
interpreted. The reference workload serves the header on every response and `server_id` in `/health`, taken from the
cloud-init instance-id (equal to the Nova server id on OpenStack); it never falls back to the hostname and sends
nothing when the id is unknown (`ansible/tests/test_identity.py`). `hostname` (3) exists for workloads that cannot
read the instance-id; it is only as strong as the hostname is unique per VM, so profiles should prefer 1 or 2.

### 3.7 Result JSON (all phases)
Written by the playbook to `{{ ovlm_result_path }}` (OVLM passes the path; ASSUMPTION) via `ansible.builtin.copy` of a dict, or via `set_stats` (DOCUMENTED-UNVERIFIED which of these ansible-runner exposes; OVLM must support the file route).
```json
{ "schema": "ovlm.result/1", "phase": "data_attach", "ok": true,
  "changed": true, "classification": "ok|retryable|fatal|needs_human",
  "facts": {"device": "/dev/disk/by-id/...", "fs_uuid": "...", "marker_sha256": "..."},
  "checks": [{"name":"mount","ok":true,"detail":"..."}], "message": "short, no secrets" }
```
The marker key is `marker_sha256` in every phase; OVLM reads no other spelling (a `marker_checksum` fact is ignored, so W1 parks). `tests/unit/test_marker_contract.py` ties this name to OVLM and the reference roles.
OVLM must treat a missing or malformed result as `classification = needs_human` for data phases and `retryable` (bounded) for `configure`/`healthcheck`. `result.json` is size-limited (64 KiB, ASSUMPTION) and redacted again by OVLM.

### 3.8 `rollback_hooks` (optional)
Inputs: `ovlm.rollback.phase` (which phase failed). Typical: on the OLD VM, remount the volume and restart the service if OVLM aborts after `quiesce`. Idempotent. OVLM never relies on it existing: OVLM's own rollback (re-attach volume to old VM, restore floating IP) comes first (ASSUMPTION: architect defines in workflow).

## 4. Idempotency summary

| Phase | Target | Rerun safe? | Dry run (`--check`) meaningful? |
|---|---|---|---|
| preflight | new/old | yes (read-only) | yes |
| configure | new (and old, check only) | yes | partly (shell tasks skipped unless written for it; SOURCE-VERIFIED: ansible-and-kolla-notes.md, mapping table) |
| data_attach | new | yes, never mkfs on existing fs | no; OVLM instead uses the read-only `blkid` decision as preview |
| quiesce | old | yes | no (changes state by nature) |
| start_service | new | yes | partly |
| healthcheck | new/old | yes | yes |

## 5. Secrets

- Never in extra-vars on the command line, never in `-e` strings, never in the repo, never in `inventory_vars`.
- SSH private key: OVLM writes it to `env/ssh_key` (mode 0600, run dir 0700, preferably tmpfs); passed to runner as a file. Removed in a `finally` block and by the run-dir wipe; startup sweeper deletes orphan run dirs older than the maximum timeout (covers worker kill).
- Vault password: delivered via `env/passwords` (ansible-runner pattern match on the vault prompt; DOCUMENTED-UNVERIFIED) or a 0600 `vault-password-file` temp file, never an env var visible in `/proc` to other users (run worker as dedicated user).
- Cloud credentials (OpenStack) are never given to Ansible. All OpenStack API calls are made by OVLM (SDK) only; the playbooks work on guests. This keeps blast radius off the control plane.
- Playbooks must use `no_log: true` on any task handling secret values; OVLM sets `ANSIBLE_NO_LOG` not globally (that would hide failures), but `display_args_to_stdout=false`. The `no_log` lint is **blocking**: a task using `vault`, `password`, `token`, `key` or other secret-like names in module args without `no_log` fails profile validation and the run-time re-lint, unless an approver grants an audited per-profile waiver (recorded with the profile version).
- **OVLM stores task results.** ansible-runner events, stdout and per-task results are kept per attempt as restricted artefacts (operator/admin in scope, own retention, never exported), and they can contain whatever a task prints or templates, including vault-decrypted workload secrets that OVLM does not know and cannot redact. Playbook authors must assume everything a task returns is stored. `--diff` output is stored only if the profile opts in with `store_diffs: true`; otherwise OVLM keeps only per-task changed/unchanged.
- OVLM never prints the extra-vars file; the run record stores a SHA-256 of it and the list of keys only.
- Redaction (log capture): OVLM stores logs after replacing every known secret value (exact-match set built from the run's secret refs, plus regexes for `-----BEGIN`, `password=`, `token=`, bearer headers). Redaction is a backstop, not the control.

## 6. Timeouts and exit-code classification

| Phase | Default timeout (ASSUMPTION: tune in lab) | Idle (no output) |
|---|---|---|
| preflight | 120 s | 60 s |
| configure | 1800 s | 300 s |
| data_attach | 300 s | 120 s |
| quiesce | 300 s | 120 s |
| start_service | 300 s | 120 s |
| healthcheck | 60 s per call | 30 s |

Timeouts are `min(profile value, OVLM maximum)`. On timeout: SIGTERM to the process group, 30 s grace, SIGKILL; classification below.

ansible-runner/ansible-playbook exit codes (DOCUMENTED-UNVERIFIED, verify in version used): 0 ok; 1 error; 2 host failed; 3 unreachable (ansible-playbook); 4 parse error; 5 bad options; 99 user interrupt; 250 unexpected.

| Condition | Class | OVLM action |
|---|---|---|
| exit 0 and result.ok | ok | proceed |
| unreachable (SSH not up yet), timeout in `preflight`/`configure`/`healthcheck`, package mirror failure, `result.classification=retryable` | retryable | bounded retries (default 3, exponential backoff), then escalate to needs-human |
| parse error, bad options, missing playbook/phase, unpinned requirement, SHA mismatch, `result.classification=fatal` | fatal | stop step, trigger OVLM rollback of that step, do not retry |
| any failure in `quiesce` or `data_attach`, timeout or kill during them, missing/invalid result.json on these phases, blank-volume or fs mismatch | needs_human | stop workflow, keep both VMs, keep volume attached where it is, require operator decision |
| process killed by worker crash | unknown | on resume treat as needs-human for data phases; for `configure`/`healthcheck` re-run (idempotent) |

Never auto-retry `data_attach` or `quiesce` after a timeout without first reading the real state (volume attachment in Cinder/Nova, mount state through a read-only probe).

## 7. Log capture

- Capture stdout/stderr and ansible-runner events per attempt; store redacted under the run record, plus `result.json`, `ansible --version`, resolved SHA, requirements hash.
- Per-phase size cap (ASSUMPTION: 5 MiB); truncate with marker, keep head and tail.
- Never log the extra-vars file, the inventory with keys, or `env/`.
- Each log line batch carries `workflow_id/step/attempt` for correlation with the OVLM audit trail.

## 8. Interruption behaviour

| Interrupted at | State left | Recovery |
|---|---|---|
| mid `configure` | partial config on new VM | rerun (idempotent) or discard the new VM (replaceable) |
| mid `quiesce` | service maybe stopped, volume maybe mounted | probe old VM read-only; rerun quiesce; never detach until quiesce reports ok |
| mid `data_attach` | volume attached, maybe mounted on new | read-only probe, rerun; decision table protects data |
| mid `start_service` | unit maybe running | rerun |
| worker killed | orphan run dir, maybe orphan ansible process | startup sweeper kills by run-dir marker and wipes; step re-evaluated from OVLM state, not from the log |

ASSUMPTION for the architect: OVLM persists step state before and after each phase and re-derives truth from OpenStack + a read-only probe after a restart.

## 9. Reproducibility evidence

OVLM computes an evidence record per profile; only machine-checkable items count toward "credible".

| Check | Automatic? | Meaning |
|---|---|---|
| `ref` is a pinned SHA; requirements all pinned | yes | automation is immutable |
| `configure` succeeded on a replacement VM in the last N days (N is a policy value, ASSUMPTION; no default fixed here) | yes (run records) | automation actually builds a working VM |
| `configure` twice on the replacement: second run `changed=0` | yes | idempotent |
| `configure --check --diff` on the CURRENT VM: empty or small drift report | yes, with limits | current VM matches automation; drift list shown to the human. Shell tasks are skipped in check mode, so "empty" is weaker evidence than it looks (SOURCE-VERIFIED: ansible-and-kolla-notes.md) |
| Previous renewal succeeded with `healthcheck` ok and marker checksum equal | yes | end-to-end evidence |
| Static lint (no mkfs/wipefs, no `hosts: all`, `no_log` on secret tasks, `check_mode`/`delegate_to` rules below) | yes | blocking (the `no_log` rule included) unless an approver grants an audited per-profile waiver; a lint is cheap and not a proof |

The lint is **static analysis only** (YAML and git parsing and rule matching): it starts no Ansible process, loads no plugins and evaluates no Jinja (SEC-R-35). Rules: `check_mode: false` and `always_run` are flagged (a task that forces itself to run in check mode defeats the read-only guarantee of `--check`), except `check_mode: false` on a task that is read-only by construction: the modules `stat`, `find`, `slurp`, `setup`, `wait_for`, `getent`, `uri` with GET/HEAD and no `body`/`src`/`dest`, or `command` (never `shell`) with `changed_when: false` running `mountpoint`, `findmnt`, `blkid`, `readlink`, `id`, `df`, `fuser`, `which`, `lsblk`, `e2fsck -n` (no repair flag) or `start-stop-daemon --status`. Block-level forcing and `always_run` are never exempt; `delegate_to` and `local_action` are flagged in `configure.yml` (work must run on the target host). Any `ansible-playbook`/`ansible-inventory` invocation on repo content (including `--syntax-check`, `--list-hosts`) happens only inside a run from B6 on.

Only humans can attest: the app's state outside the data volume is truly reproducible (manual config, secrets elsewhere, external DNS, cron on other hosts), the data volume holds ALL persistent state, the healthcheck represents real user-facing function, the RPO/RTO acceptable, the owner named. OVLM stores these as signed-off attestations with date and name and expires them with the profile ref change.

Note for playbook authors: OVLM stores task results (section 5). The reproducibility `--check --diff` run stores only per-task changed/unchanged unless the profile sets `store_diffs: true`.

Verdict values: `credible` (all automatic checks green + valid attestation), `partial`, `unverified`. OVLM must not auto-run a renewal for `unverified` without an explicit human override recorded (ASSUMPTION: policy decided by the architect).

## 10. Self-review against openstack-automation-review (SOURCE-VERIFIED: SKILL.md)

| Criterion | Assessment |
|---|---|
| Purpose / judgement vs execution | Execution is automated; decisions (accept drift, accept data loss risk, force detach, override unverified) stay human. OVLM never decides a blank volume is "fine". |
| Blast radius | Per run: one VM (generated one-host inventory), no OpenStack credentials in Ansible, one workflow per volume (lock). Residual: the playbook runs as root on the guest. |
| Preview / dry run | `--check --diff` for configure/healthcheck; read-only `blkid` decision for data; `--list-hosts` scope check. Gap: shell tasks hide in check mode. |
| Explicit scope | Generated inventory; `hosts: ovlm_target` enforced. |
| Confirmation | Human go required before `quiesce` (downtime) and before cutover; OVLM-level (architect). |
| Stop conditions | needs-human classification halts on any data-phase anomaly; bounded retries; no `ignore_errors` allowed on data phases (lint). |
| Pre/post checks | `preflight`, `data_attach` decision table, `healthcheck` by capability (service + data marker), not exit code of the play alone. |
| Idempotency | Required per phase and tested (second run `changed=0`). |
| Concurrency | Lock per VM/volume. |
| Interruption | Section 8; state re-derived, not trusted from logs. |
| Observability | Run record with SHA, versions, redacted logs, result JSON. |
| Ownership / maintainability | Profile requires a named owner; pinned dependencies; Ansible repo versioned. Control-debt risk: a profile with only its author able to explain it is flagged by the human attestation step. |

Open limits: none of this has been executed. The first lab run (test-environment.md) is the validation.


## 11. Implementation notes (E5-3, `src/ovlm/automation/`)

Status: implemented and tested as listed in the E5-3 hand-off; nothing here is "lab validated". Where the code makes a
choice the contract left open, or is stricter than the text, it is recorded here.

| Topic | What the code does |
|---|---|
| Data-phase classification | Any failure of `quiesce`, `data_attach` or `rollback_hooks` is `needs_human`, even when the playbook reports `retryable` or `fatal` (the reported value stays in the evidence as `reported_classification`). This resolves the tension between 3.3 rule 2 ("fail retryable if the device is absent") and section 6 (never auto-retry a data phase without reading the real state): the engine re-runs only after the probe. |
| `start_service` timeout | `retryable` (idempotent, `state: started`); the engine bounds the retries. Section 6 does not name it. |
| Healthcheck | `result.json` is authoritative; the exit code is used only when the result is missing or invalid. `accept_degraded` turns a `retryable` result with `facts.health_state == "degraded"` into ok. |
| Private key file | Written as `env/guest_key` (0600), not `env/ssh_key`: ansible-runner loads `env/ssh_key` into its own ssh-agent and keeps a copy in `artifacts/`. The key is used by file only (`IdentitiesOnly`, `ForwardAgent no`). |
| Connection variables | `ansible_host/port/user/ssh_*` are inventory host vars only, never extra-vars: as extra-vars they also apply to `delegate_to: localhost` tasks (the result writer) and would send them to the guest. The lint refuses these names in plays, tasks, `add_host` and `group_vars`/`host_vars`. |
| Lint vs the reference workload | The reference roles pass the lint with no waiver (2026-11-05): their `check_mode: false` tasks are all read-only probes of the exempt forms above. Roles are found in `<playbook_dir>/roles`, the sibling `<parent>/roles` (the `ansible/playbooks` + `ansible/roles` layout of this repository) and `roles/` at the repository root. Audited per-profile-version waivers (SF-13): an approver grants one through the API (api-design.md §3.3); B6 loads the version's active waivers, the lint applies them by rule and path glob, and every finding a waiver covered is audited (`automation.lint_waiver.applied`). The re-verification of an adopted checkout applies the same waivers without auditing them again. |
| Pin check | `requirements.yml` is checked (exact versions; git roles need a SHA) and every pinned collection must already be present at that version in `collections_paths` or in the repo's `collections/`. Nothing is downloaded. |
| Fence | `Fence.check("automation:spawn:<phase>")` immediately before the spawn; the revoke callback stops the process tree at once. `lease_needed(timeout)` gives the lease a step must cover. |
| Signalling another OS user | The worker can signal `ovlm-ansible` processes only with privilege. The container image gives the worker `CAP_KILL` (see "Separate OS user in the container" below), so a direct `kill` works; `signal_prefix` (e.g. `sudo -n -u ovlm-ansible`) remains for installations that cannot grant the capability and use the sudoers alternative. The runner's own job/idle timeouts need no cross-user signal. |
| Run dir ownership | Worker root (or CAP_CHOWN): run dir chowned to `ovlm-ansible`, 0700/0600. Otherwise group `ovlm-ansible` with 0770/0660 and ancestors 0710; the KEK stays 0400 and owned by the worker user either way. |
| Artefacts | Table `automation_run` (migration `automation_0001`). Restricted columns `log`, `events`, `diff`; `diff` only with `store_diffs` (also a table CHECK); purge sets the restricted columns to NULL after `artifact_expires_at`; no DELETE grant. |
| Settings | `automation.*` in `Settings` (`src/ovlm/config/settings.py`): `run_root`, `require_tmpfs`, `checkout_cache`, `ansible_bin_dir`, `collections_paths`, `run_user`, `signal_prefix`, per-phase `timeout`/`idle_timeout`/`max_timeout`, `result_max_bytes`, `log_max_bytes`, `artifact_retention_days`, `allowed_repos`, `git_ssh_key_file` + `git_ssh_known_hosts_file`. `ovlm.automation.config.runner_config(settings)` builds the `RunnerConfig`; `ovlm.config` imports nothing from `automation`. Secrets are file paths, never values. Validation: unknown phases, non-positive or inconsistent timeouts (default above `max_timeout`, idle above timeout), relative paths, malformed OS user names, repository allowlist entries that are not `https://`/`ssh://` prefixes or carry credentials, a deploy key without its `known_hosts`. In production (no `development_mode`) a worker refuses `run_user = null`. |
| Start-up sweep | `Worker._start_workflow` calls `sweep_orphans(run_root, max_age)` first (before `register_worker`, the registry sweepers and any claim), then the checkout sweep (`Worker._sweep_checkouts`: `sweep_run_root_checkouts` and `sweep_checkout_cache`, section 2), which also runs hourly and after each executed step for that step's run. `max_age` is the largest phase ceiling plus the kill grace and 60 s. A failure to sweep is logged and does not stop the worker. |
| Image and collections | Two images from one Dockerfile: target `runtime` (api, migrate) has no ansible, ansible-runner or collections; target `worker` adds the `automation` group from `requirements-worker.lock` (`make lock` writes both lock files from `uv.lock`; `make lock-check` verifies both). `ansible.posix` is installed at build time into `/opt/ovlm/collections` from a pinned **commit** (the tag named in `ansible/requirements.yml`; the build fails if version or commit disagree) and the runner's `collections_paths` default points there. Galaxy is never contacted, at build or at run time. `make smoke` proves both images (`tests/smoke/`). |
| Restricted artefacts | The read rule is `ovlm.auth.authz.can_read_restricted` (the `automation_artefact.view` matrix row: `operator`/`admin` in the run's project or global; `viewer`/`approver` never). `GET /api/v1/automation-runs/{id}/artefacts` (`ovlm.api.routes_automation`) reads `automation_run` as `ovlm_api` and does not import `ovlm.automation`: 404 outside the caller's scope and for unknown runs, 403 for a visible-but-not-allowed caller, every read and every refusal audited (the content is never audited). The diff is returned only when the profile opted in. |

### Separate OS user in the container (decision and risk)

**Problem.** The worker must start ansible-runner as `ovlm-ansible` (uid 10002) so that playbook code cannot read the
worker's files (DB secret, KEK, other runs), yet the worker itself must not run as root. The compose hardening is
`cap_drop: ALL` and `no-new-privileges`, which rules out `sudo` and any setuid helper.

**Choice: ambient capabilities, no setuid binary.** `docker/worker-entrypoint.sh` starts as container root with four
capabilities (`SETUID`, `SETGID`, `SETPCAP`, `KILL`), and `setpriv` drops to uid/gid `ovlm` (10001) with the
supplementary group `ovlm-ansible` (10002), trims the bounding set to `SETUID, SETGID, KILL` and makes those three
*ambient*, then `exec`s `ovlm worker`. Nothing runs as root afterwards; `SETPCAP` is gone from the bounding set. With
them the worker can (a) `Popen(user=..., group=...)` the runner as `ovlm-ansible` and (b) signal that user's processes
directly, so `signal_prefix` stays empty. The run directory is shared through the group (`owned=False` layout: ancestors
0710, run dir 0770/files 0660, group `ovlm-ansible`; the worker is a member, so it needs no `CAP_CHOWN`); `run_root` is
a tmpfs `0710 ovlm:ovlm-ansible`. The KEK stays `0400` owned by `ovlm`.
Compose sets `user: "0:0"` for the worker only; started as `ovlm` without capabilities the worker still runs, but the
runner refuses to start ansible (it cannot switch user).

**Risk.** `CAP_SETUID` is not restricted to one uid: a *compromised worker process* could `setuid(0)` or to any uid in
the container. It stays inside the container's other limits (read-only rootfs, no other capabilities, no
`no-new-privileges` escape, no secrets other than the worker's own), and the worker already holds everything that
matters in the container (DB worker role, KEK), so the capability adds little for an attacker who has code execution
in the worker. What the design protects is the other direction: playbook code running as `ovlm-ansible` cannot read the
worker's secrets. `CAP_KILL` lets the worker signal any process in its PID namespace (the container's), which is the
minimum for stopping the runner's process tree (the runner kills by process group plus `/proc` descendants).
Mitigations kept: one process namespace per container, no `CAP_SYS_PTRACE`, the playbook user cannot signal the worker
(different uid, no capabilities), and `make smoke` asserts the worker's `CapEff/CapAmb/CapPrm/CapBnd` are exactly these three.

**Rejected alternatives.** *sudoers rule* (`ovlm ALL=(ovlm-ansible) NOPASSWD: /opt/venv/bin/ansible-runner *`, `kill`
for `signal_prefix`): needs a setuid `sudo` in the image and dropping `no-new-privileges`, and `*` in a sudoers argument
list is itself an injection surface; it remains the way to do it on a bare-metal/VM installation without the capability
(set `automation.signal_prefix`, and run the worker as a member of group `ovlm-ansible`). *Root worker that drops the
user per child*: root with a full runner code path is the larger blast radius. *File capabilities on a helper*: blocked
by `no-new-privileges`.
