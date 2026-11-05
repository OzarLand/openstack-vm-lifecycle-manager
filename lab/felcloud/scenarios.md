# Lab scenarios on Felcloud: acceptance and failure (backlog E5-6)

| Field | Value |
|---|---|
| Owner | Agent 6 — Automation Engineer (kit); Agent 9 owns the scenario definitions in [testing-strategy.md](../../docs/testing-strategy.md) §7 |
| Status | **Designed, not run.** Nothing below has been executed. Expected outcomes come from the design documents and are what the run must confirm or contradict |
| Environment | Felcloud, project `ozar-lab`, `ovlm-*` resources only ([ADR-0007](../../docs/decisions/ADR-0007-lab-on-felcloud.md)); runbook in [README.md](README.md) |
| Expected behaviour from | [renewal-workflow.md](../../docs/renewal-workflow.md) §4.1, §5, §7 and D-1 (maintainer option B), [automation-contract.md](../../docs/automation-contract.md), [ADR-0003](../../docs/decisions/ADR-0003-workflow-engine.md) |
| Last updated | 2026-11-05 |

Words used: **API** means the call in [api-design.md](../../docs/api-design.md) (the UI offers the same action);
**TC** is the typed confirmation; **human + TOTP** means a person at the UI, never a token or an agent.
`$RUN` is the run id returned by `POST /plans/{id}/start` (`Location: /api/v1/runs/{id}`). Commands that start with
`./` are in this directory. A scenario's *verdict* is `pass`, `fail` or `inconclusive`; it is written by a human, with
the evidence beside it.

## 0. Frame for every scenario

| # | Action | Command |
|---|---|---|
| F1 | Fresh blue (see README §6 *Reset*), the marker SHA-256 and counter recorded after `configure` | — |
| F2 | ◻︎ Baseline snapshot | `./snapshot.sh <ID>-before` |
| F3 | ◻︎ Evidence "before" | `./collect-evidence.sh <ID> before` |
| F4 | ◻︎ Start the external probe through the floating IP, in its own terminal; keep it running until the run ends | `./probe.sh --url http://<fip>:8080/health --out <ID>.csv` |
| F5 | Run the scenario (below) | — |
| F6 | ◻︎ Evidence "after", with the run id so OVLM's run, steps and audit are collected | `./collect-evidence.sh <ID> after --run-id $RUN` |
| F7 | ◻︎ Snapshot and guard | `./snapshot.sh <ID>-after && ./diff-snapshots.sh <ID>-before <ID>-after` |

**Common pass criteria (all scenarios, from testing-strategy §7.2):** no data loss (marker SHA-256 and counter equal
or higher than recorded); the data volume is never attached to two servers at once; the old service keeps serving
unless the scenario says otherwise; the run ends in a defined state; every OVLM-created leftover is listed in the
evidence; **`diff-snapshots.sh` passes (nothing outside `ovlm-*` changed)**. A diff violation makes the verdict `fail`
whatever else happened.

**Common evidence (CE):** the bundle from F3 and F6 (redacted `ovlm-*` inventory, the set-aside floating IP's holder, OVLM
run, steps and audit, worker and api logs, commit), the probe CSV and its summary line, the two snapshots and the diff
report, the downtime figure OVLM recorded next to the probe's.

**OVLM profile for the lab** (set once, API `POST /services/{id}/profiles` then `/profiles/{id}/versions`):
automation repo = the OVLM repository at the pinned SHA, `ansible/` as the playbook directory; image `Ubuntu 24.04 LTS - Noble Numbat`;
flavor `G0.basic.1c1g`; the lab network; green's security group **`ovlm-acc-sg-green`**; the data volume `ovlm-acc-data`;
volume type `NVMe` (always explicit); health check `GET /health` on 8080 with `fs_uuid` and `marker_sha256`; the
service floating IP is the set-aside one. **Green must be named `ovlm-*`**: `destroy-lab.sh` and the diff guard both
depend on it. The profile does not set green's name: OVLM derives it from the **service slug**
(`<slug>-ovlm-<last 12 characters of the run id>`, `renewal/plans.py` `green_name`). So the lab service's slug must
start with `ovlm-` (use `ovlm-acc`; green is then `ovlm-acc-ovlm-<12>`).

**OVLM policy for the lab** (admin, `POST /policies`, then `POST /policy-bindings` with `scope_type: service` and the
lab service's id: policies bind to a service or a service group, never to a VM): a window covering the session, and
**a window cannot cross midnight** (`end` later than `start` on the same local day; split a night window in two);
`require_distinct_approvers: false`, so **approver-a** decides G1 (plan) and G2 (cutover) and **approver-b** decides
G3 (retirement). The installation's self-approval setting stays **off**: the requester (the operator) never approves,
and G3's approver differs from the requester and from the plan approver whatever the policy says.

---

## 1. Primary acceptance scenario (ACC-01)

Source: testing-strategy §7.1, 12 steps. Preconditions: Steps 0 to 7 of the README done; an operator account and two
human approver accounts with TOTP (approver-a, approver-b; self-approval off); the lab policy above with a short
retention period.

`{pc}` below is the OVLM project connection id (`GET /api/v1/project-connections`), not the OpenStack project id.

| Step | OVLM action (API; UI equivalent exists) | What to observe on Felcloud | Pass criterion |
|---|---|---|---|
| A1 | Upload the credentials (admin + TOTP step-up + TC = connection name): `POST /project-connections/{pc}/credentials` with `kind` `os_read`, then `os_write`, then `ssh_key`; the worker validates each (`GET /credentials/{id}`: `state: active`; re-check with `POST /credentials/{id}/validate`). Then `POST /projects/{pc}/syncs` (**202**, operator) and follow `GET /projects/{pc}/syncs` | `./collect-evidence.sh ACC-01 before` | The sync record is `succeeded` (`kind: full`); blue, volume, floating IP, image, flavor appear in the inventory under `{pc}`; **no write call** from the read credential (OVLM request log / audit). A second `POST` while one is queued answers 409. The periodic sync (`inventory.sync_interval`, 15 min) also runs |
| A2 | `POST /services` with slug `ovlm-acc`, `POST /services/{id}/managed-vms {observed_server_id}` (201; it queues a host-key scan, `host_key_scan_run`). When `GET /managed-vms/{id}` shows `ssh_host_key_fingerprint`, **compare it with blue's own** (on blue: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`, through the lab host; or the console's fingerprint block if it is not empty) and confirm it: `POST /managed-vms/{id}/host-key/confirm {"fingerprint": "SHA256:..."}` (operator, human session). Then create the profile | — | Fingerprint confirmed (audit `managed_vm.host_key_confirm`); profile version 1 stored; observed and desired state shown separately. A plan before the confirmation is refused (409 `host-key-unconfirmed`) |
| A3 | `POST /managed-vms/{id}/assessments` | **Negative control first:** a profile version with an *unpinned* ref (branch, tag or short SHA) is **refused at creation (422)**. Then the pinned one | `ready`, every check has evidence |
| A4 | Create the lab policy and bind it to the service (above); `GET /managed-vms/{id}/deadline` | — | Deadline = launch + max age, adjusted to the window |
| A5 | `POST /plans`; `POST /plans/{id}/approval-requests`; approver-a decides (`POST /approvals/{id}/decision`, **human + TOTP**); `POST /plans/{id}/start` (**202**) | `openstack server list --tags ovlm:managed` shows blue only; the run holds the locks | Approval bound to the plan hash; **self-approval refused** (try it once); steps `B1 preflight`, `B2 claim_resources` done |
| A6 | Watch `GET /runs/$RUN` and `/steps` through `B3`, `B4`, `B5` | One new server named `ovlm-*`, tagged `ovlm:managed` and `ovlm:run:<id>`, in the volume's availability zone. ACTIVE comes ~15 s after create, SSH only ~85 s later (EXP-01b) | Ledger row `present`; blue untouched; exactly one green |
| A7 | `B6` to `B8`; run `configure` a second time (retry-step) | — | `ovlm.result/1` ok; second `configure` reports `changed=0` |
| A8 | `POST /runs/$RUN/cutover-request`; approver-a decides **with the TC** (server name + last 6 of the volume id) inside a policy window | `B9 verify_green_ready` runs **before** T0. Optional negative control N1 below | B9 proves green is reachable on the pinned key and `cloud-init` finished, before anything is stopped |
| A8-W | `W1 quiesce_old`, `W2 stop_old`, `W3 detach_volume`, (`W4` snapshot optional), `W5 attach_volume_green`, `W6 data_attach_green`, `W7 start_service_green` | The probe starts failing at `W1`/`W2`. `openstack volume show ovlm-acc-data` shows `in-use` → `detaching` → `available` → `reserved`/`attaching` → `in-use` (EXP-01 Q3) | Volume on exactly one server at every sample; **no `mkfs`**; marker SHA equal |
| A9 | `W8 healthcheck_green` | — | `/health` ok; `fs_uuid` and `marker_sha256` equal the recorded values; counter ≥ recorded; the answering VM id differs from blue's |
| A10 | `W9 move_fip`, `W10 verify_external` | Floating IP now on green's port; the probe recovers within about a second of the move (EXP-01b: 1.1–1.3 s) | OVLM's downtime figure and the probe's outage agree within a few seconds. For reference only: the best case measured on this cloud was about 40 s |
| A11 | `R1 retain_old`, `R2 await_retention` | Blue `SHUTOFF` and **locked** (`locked_reason=ovlm:retained:<run>`), only after `W3` | Audit lists every step attempt |
| A12 | `POST /runs/$RUN/retirement-request`; approver-b (≠ requester ≠ plan approver, with the TC) decides; `X1 retire_old` | Blue deleted; the volume **not** deleted (`delete_on_termination=false`, re-checked) | Data volume survives on green; blue gone; final health ok; `./snapshot.sh` + diff pass |

**N1 (optional negative control, ◻︎ + ⚠️ on `ovlm-*` only).** Between A7 and A8, remove the SSH rule from the host group
on green's group, approve the cutover, and watch B9 hold the run before T0:

```bash
# ⚠️ ovlm-acc-sg-green only. Find the rule, delete it, later put it back.
openstack security group rule list ovlm-acc-sg-green --long -f json \
  | jq -r '.[] | select(.["Port Range"]=="22:22" and .["Remote Security Group"]!=null) | .ID'
openstack security group rule delete <rule id>
# ... B9 must refuse to reach T0 (blue still serving, probe all 200) ...
openstack security group rule create ovlm-acc-sg-green --ingress --protocol tcp --dst-port 22 --remote-group ovlm-lab-sg
# then retry-step on the run
```
Pass: the probe shows **no outage** while B9 is stuck. (EXP-01b R3: an unreachable green at T0 added 55 s of outage.)

### ACC-02 — revert after cutover (testing-strategy §7.1, last line)

After A10 and before A12: `POST /runs/$RUN/actions/revert` with the TC. Expected: restore sequence S1 to S9; the
floating IP and the volume return to blue; **data written by green is still present** (write through the floating IP
between A10 and the revert, then check the counter after). Pass: blue serving, counter ≥ the value read on green,
one attachment, marker equal. Evidence: CE, the counter read before and after (values, not addresses).

---

## 2. Failure scenarios

Each follows the frame in §0. "Feasible" says whether Felcloud allows the injection with `member` rights; when it does
not, the scenario is marked and the verdict is `inconclusive`, never `pass`.

### LAB-01 a to e — interrupted workflow

| | |
|---|---|
| Source | testing-strategy LAB-01, renewal-workflow §5, ADR-0003 (leases, fencing token) |
| Preconditions | ACC-01 steps A1 to A5 done for a fresh blue, so a plan is approved |
| Feasible | Yes. `inject.sh` acts on the OVLM Compose stack on the lab host, not on Felcloud |

Start the run (`POST /plans/{id}/start`), read `$RUN` from `Location`, then immediately:

```bash
./inject.sh worker-kill $RUN <STEP>      # polls GET /runs/$RUN every 0.5 s, then: docker compose kill -s KILL worker
# wait longer than worker.lease_duration (default 60 s), then
./inject.sh worker-start
```

| Case | `<STEP>` | Expected (testing-strategy, renewal-workflow §5) |
|---|---|---|
| a | `B4` (`wait_green_active`) | Lease expires; a new claim with a **new fencing token**; probes real state; the step resumes; **one** green only (ledger + tag + adoption checks) |
| b | `B7` (`configure_green`, Ansible running) | The sweeper kills the orphaned Ansible process group *before* claiming; `configure` re-runs; second run `changed=0` |
| c | `W1` (`quiesce_old`) | `needs_human` with probe evidence (mount state unknown); no detach |
| d | `W3` or `W5` (detach or attach in flight) | Resumes or `needs_human` according to the probed volume state; never a second attachment |
| e | the run state while it waits for the G2 approval (read it once from `GET /runs/$RUN`) | Resumes; approval evidence re-validated |

If `inject.sh` reports the step was already past, or the log shows the kill landed elsewhere, record the *actual* step
and repeat: a miss is not a pass. Steps `W1`, `W3` and `W5` last only seconds, so expect a few attempts, each on a fresh
blue (README *Reset*): this is the reason for the cost note.

**Extra evidence:** `steps` rows before and after the kill, the lease takeover and the fencing token in the worker log,
`docker compose top worker` and `ls` of the run directory on the lab host (no stray `ansible` process, no orphaned
run dir after the sweeper), server and volume lists. **Pass:** one green VM; at most one attachment; no orphan after the
sweeper; data intact.

### LAB-02 — insufficient capacity

| | |
|---|---|
| Source | testing-strategy LAB-02, renewal-workflow §7 and §4.1 |
| Expected | `OverQuota` at `B3` is **fatal, no retry**; `NoValidHost` (server `ERROR` with a fault) is **fatal** for the attempt and green is **kept** for diagnosis; both end in `BuildFailed`; blue untouched; **no volume operation**; the retry counter stays 0. Green is deleted only by operator `rollback` (with TC), and only if tagged `ovlm:run:<this run>` |
| Feasible | **Partly.** A `member` cannot lower quotas, and this project's limits (50 instances, 128 cores, 256 GB RAM) are far above the lab's use, so *OverQuota* cannot be provoked by the lab itself |

Two ways, choose in this order:

1. **Maintainer lever (preferred):** the maintainer (an admin) lowers the project quota for the duration of the test, for
   example `instances` or `cores` to the current usage, and restores it after. Not part of this kit; write down what was
   set and restored. Expected: the pre-check at `B1` refuses early (advisory), or `B3` fails fatal with `OverQuota`.
2. **Largest flavor:** create a profile version whose flavor is the largest one in `openstack flavor list --sort-column RAM`.
   Expected: `NoValidHost` (server `ERROR`), or `OverQuota` if the flavor exceeds the cores left. **Risk:** if the cloud
   *can* place it, green will boot and bill. If the run reaches `B4` ACTIVE for that flavor, `POST /runs/$RUN/actions/rollback`
   at once (verdict `inconclusive`). Needs its own cost yes (README §9).

Steps: plan and start with the capacity-failing profile; observe `B3`/`B4`; read `server show` fault text (redacted).
**Extra evidence:** the Nova fault text, the retry counter (= 0), blue's `/health` 200 throughout (probe all 200), the
volume untouched. **Pass:** fatal class with a clear next action; no volume operation; green kept until `rollback`, which
then deletes only the tagged green; probe shows no outage.

### LAB-03 — failed provisioning

| | |
|---|---|
| Source | testing-strategy LAB-03, renewal-workflow §7 |
| Expected | `B3`/`B4` fatal → `BuildFailed` with fault evidence; green **kept**; operator rollback (TC) deletes it, only if tagged for this run; blue and the volume untouched |
| Feasible | Yes, with an image the lab owns |

Injection ⚠️ (creates one small `ovlm-*` image; delete it at the end, `destroy-lab.sh` covers it):

```bash
head -c 1048576 /dev/zero > "$OVLM_LAB_WORKDIR/zero.raw"       # outside the repository
openstack image create --disk-format raw --container-format bare --min-ram 65536 \
  --file "$OVLM_LAB_WORKDIR/zero.raw" ovlm-lab-badimage         # needs far more RAM than the lab flavor has
```
Set the profile image to `ovlm-lab-badimage`, plan, start. Nova rejects the flavor/image pair at `B3` ("flavor's memory
is too small") or the server ends `ERROR` at `B4`. **Variant (plan-time check):** a nonexistent image id is expected to
be refused at `POST /plans` (image resolution), before any run starts. Record which of the two refusals happened.
**Extra evidence:** `server show` fault, the resource diff before/after rollback. **Pass:** green not deleted
automatically; deleted only after the TC rollback; blue and `ovlm-acc-data` untouched.

### LAB-04 — failed Ansible configuration

| | |
|---|---|
| Source | testing-strategy LAB-04, automation-contract §6 |
| Expected | `B7` ends in bounded retries then fatal, or fatal at once → `BuildFailed`; blue untouched; **the volume never leaves blue**; no data-phase step (`W1` onward) starts |
| Feasible | Yes, but it needs a pinned ref that contains a deliberate error |

⚠️ **Outward-facing:** this needs a throw-away branch with one broken task, on a repository the lab host can clone. Do
it only with the maintainer's yes, and delete the branch afterwards.

```bash
git switch -c lab/e5-6-broken-configure <the OVLM ref under test>
# add one failing task to ansible/roles/base/tasks/main.yml, for example:
#   - name: lab fault
#     ansible.builtin.command: /bin/false
git commit -s -m "lab: deliberate configure failure (do not merge)" && git push origin lab/e5-6-broken-configure
```
Create a profile version pinned to that commit SHA (`POST /profiles/{id}/versions`; the lint must still pass, since only
the task content is bad), assess, plan, start. **Extra evidence:** the redacted run log, `result.json`, the exit code,
the attachment unchanged (`volume show`), the retry count. **Pass:** the failure is classified as the contract says
(retryable bounded, then fatal); no step beyond `B7` ran. **Cleanup:** `git push origin --delete lab/e5-6-broken-configure`
(maintainer's repository: ask first), then `rollback` the run.

### LAB-05 — failed health check

| | |
|---|---|
| Source | testing-strategy LAB-05; **renewal-workflow §4.1 and D-1 supersede it** (see the note below) |
| Expected without a `W4` snapshot | `W7`/`W8` exhausts `healthcheck.max_attempts` → `needs_human(reason=post_start_failure)` and the alert `OvlmPostStartFailure` pages; the run keeps its locks; **no automatic restore**; the floating IP never moved. The operator then chooses `retry-step`, or `rollback` (TC): blue starts on data green may have changed, so the TC text says so |
| Expected with a `W4` snapshot at `available` and `auto_restore_in_window=true` | automatic restore S2 to S9 once; the snapshot is kept as a manual way back; run ends `Restored`; downtime includes the restore |
| Feasible | Yes, on green only, thanks to the separate `ovlm-acc-sg-green` |

Injection ⚠️ (an `ovlm-*` rule): run the renewal normally to just before the G2 decision, then block the worker's HTTP
access to green, so `W8` (and `W7`, if it waits from the worker) cannot succeed:

```bash
openstack security group rule list ovlm-acc-sg-green --long -f json \
  | jq -r '.[] | select(.["Port Range"]=="8080:8080" and .["Remote Security Group"]!=null) | .ID'
openstack security group rule delete <rule id>          # only on the green group; blue's group is untouched
# approve G2 (human + TOTP + TC) and let the run go
```
After the verdict is recorded: put the rule back (`rule create ... --dst-port 8080 --remote-group ovlm-lab-sg`) **before** a
rollback, then `POST /runs/$RUN/actions/rollback` (TC) and check blue serving. Run twice: without and with the snapshot.
**Extra evidence:** the healthcheck history, attachments (volume on green), floating IP holder (blue), the paging alert, blue's
`/health` after the rollback. **Pass (no snapshot):** `needs_human` with the page, no automatic restore, no further
OpenStack call while it waits. **Pass (snapshot):** automatic restore, blue serving, marker equal.
*Note:* testing-strategy LAB-05 still says "auto restore" for this failure. renewal-workflow D-1 (maintainer, option B)
replaced that, except with a `W4` snapshot. This scenario follows D-1; the testing-strategy row needs the same update.

### LAB-06 — failed cutover

| | |
|---|---|
| Source | testing-strategy LAB-06, renewal-workflow §7 and §4.1 |
| Expected | `W9` fails with the floating IP **unchanged** (`port_id` still blue's) → `needs_human` + page (D-1), or an automatic restore if a `W4` snapshot exists and the policy allows; the error is mapped to a "no router path" style message; an unknown floating-IP state is `needs_human` |
| Feasible | **Uncertain.** The testing-strategy injection (remove the router's external gateway, or deny `update_floatingip` by policy) is **forbidden here**: it would break every other resource in the shared project (ADR-0007), and policy is not ours to change |

Safe injection to try (all `ovlm-*`): put green on a network that has **no router to the external network**, so Neutron
cannot associate the floating IP with its port.

```bash
# ⚠️ choose a private range that no subnet in the project uses (check `openstack subnet list`)
openstack network create ovlm-lab-net2
openstack subnet create --network ovlm-lab-net2 --subnet-range <unused-private-cidr> ovlm-lab-subnet2     # no router
openstack port create --network ovlm-lab-net2 --security-group ovlm-lab-sg ovlm-lab-port2
openstack server add port ovlm-lab-host ovlm-lab-port2            # so the worker reaches green over this L2 network
# on the lab host: bring the new interface up (netplan, DHCP) and check `ip -br addr`
```
Profile: green's network = `ovlm-lab-net2`. Expected at `W9`: Neutron refuses (HTTP 400, no router). **It may not run
at all:** if green cannot boot or be configured on an isolated network (no metadata service without a router, so no
injected key at `B5`), the run stops at `B5` instead, which is a different (also useful) failure. In that case the verdict
is `inconclusive` for LAB-06 and the report says the failure is **not injectable on this cloud without admin rights**;
the fake-adapter tests (levels 1 and 2) remain the only coverage of `W9`.
**Extra evidence:** `floating ip show` before and after (holder names only), the Neutron error body (redacted), the
timeline. **Pass:** the floating IP is still on blue; the message is correct; downtime recorded; marker equal.

### LAB-07 — database restart

| | |
|---|---|
| Source | testing-strategy LAB-07, renewal-workflow §5 |
| Expected | Non-data steps self-fence **before** the lease ends and stop; an in-flight OpenStack data operation runs to completion; the commit is fenced and accepted if the token is still current, else discarded and the state re-probed. No lost or doubled step; outcome as LAB-01 |
| Feasible | Yes (lab host only) |

```bash
./inject.sh db-stop $RUN B7 30        # case 1: during configure_green (PostgreSQL stopped for 30 s, then started)
./inject.sh db-stop $RUN W3 30        # case 2: during the data phase (a second run on a fresh blue)
```
**Extra evidence:** the PostgreSQL and worker logs for the gap, the step table and fencing tokens, the OpenStack state
(volume attachments) during the gap. **Pass:** same as LAB-01; plus, in case 2, the volume ends on exactly one server and
the run resumes or goes to `needs_human` with probe evidence. The 30 s gap is shorter than the lease (60 s default): a
second pass with 90 s exercises lease expiry.

### LAB-08 — worker restart

| | |
|---|---|
| Source | testing-strategy LAB-08 |
| Expected | **SIGTERM:** the Ansible subprocess is ended and the step is marked interrupted; **SIGKILL:** the sweeper cleans the orphan on the next start |
| Feasible | Yes (lab host only) |

```bash
./inject.sh worker-term $RUN B7 ; ./inject.sh worker-start     # graceful: Compose waits up to stop_grace_period 40 s
# on a fresh blue:
./inject.sh worker-kill $RUN B7 ; ./inject.sh worker-start     # abrupt
```
**Evidence and pass:** as LAB-01, plus the step marked `interrupted` after TERM, and no stray `ansible` process after
the restart in both cases.

---

## 3. Verdict summary to fill in after each run

| Scenario | Date | OVLM commit | Verdict | Injection worked? | Diff guard | Evidence bundle | Reviewed by |
|---|---|---|---|---|---|---|---|
| ACC-01 / ACC-02 | | | | n/a | | | |
| LAB-01 a to e | | | | | | | |
| LAB-02 | | | | quota lever or largest flavor | | | |
| LAB-03 | | | | | | | |
| LAB-04 | | | | | | | |
| LAB-05 (no snapshot, snapshot) | | | | | | | |
| LAB-06 | | | | likely `inconclusive` | | | |
| LAB-07 | | | | | | | |
| LAB-08 | | | | | | | |

A scenario with a missing bundle, a violated diff guard, or an injection that did not take is `inconclusive` or `fail`.
It is never `pass`, and no document may call a feature "lab validated" until a human has reviewed this table.

## 4. Not in this brief (testing-strategy LAB-09 to LAB-14), for the backlog

| ID | Feasible on Felcloud with `member`? | Note |
|---|---|---|
| LAB-09 detach refused | Yes | hold the mount with `sleep` in `/srv/data` over SSH to blue |
| LAB-10 data-safety negative | Yes | a second blank `ovlm-*` volume |
| LAB-11 device naming | Yes | attach a second `ovlm-*` volume first, so the data volume is not `vdb` |
| LAB-12 locked blue | Partly | a member lock can be unlocked by the same credential (EXP-01 Q6); an *admin-set* lock cannot be created |
| LAB-13 stuck volume | **No** | needs a stopped `nova-compute` (admin) |
| LAB-14 ownership guard | Yes, **safely** | tag an extra server named `ovlm-lab-foreign` with `ovlm:managed`; never tag a real foreign server |
