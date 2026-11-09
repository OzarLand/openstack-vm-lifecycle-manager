# Renewal timeouts: defaults, sources, checks

| Field | Value |
|---|---|
| Status | Defaults `ovlm-renewal-defaults/1` (roadmap P1-8). Derived from the Felcloud lab (one cloud, 1 vCPU guests, `NVMe` volume type, few runs) with margins; **not production validated** |
| Code | `src/ovlm/config/renewal_defaults.py` (values and checks), `src/ovlm/renewal/config.py` (step deadlines, worst-case window, plan record) |
| Related | [renewal-workflow.md](renewal-workflow.md) sections 2 to 4 (which step uses which key), [automation-contract.md §6](automation-contract.md#6-timeouts-and-exit-code-classification) (runner timeouts), [install-guide-real-cloud.md §5.3](install-guide-real-cloud.md#53-the-configuration-file) |

Every timeout of the renewal is still a **named configuration key**. What changed with P1-8: a key the configuration
leaves out no longer blocks plan creation; it takes the built-in value listed below. The design rule "timeouts are
explicit and reviewable" is kept this way:

- **Named and versioned.** The defaults are one table in the code, identified as `ovlm-renewal-defaults/1`. Any change of
  a value changes that identifier and this page.
- **Logged at start.** The api and the worker log, at start, how many keys use the defaults and the worst-case windows
  they give (stateless, with a volume, with a volume and a snapshot). They warn when a worst case reaches one hour
  (see the Keystone limit below).
- **Recorded in every plan.** Plan creation writes `resolved.renewal_settings` into the plan: the effective value of
  **every** key, the list of keys that came from the defaults, and the defaults' identifier. `resolved` is bound into
  the plan hash, so G1 and G2 approve these exact values, next to the worst-case window computed from them
  (`resolved.worst_case_window_seconds`). The approval's `blast_radius.timeouts` says how many keys use the defaults.
  The api logs the same at plan creation. Each step's `deadline_at` stays recorded on the step, as before.
- **The worker says when it differs.** At admission the worker compares its own effective values with the plan's
  record and logs a warning naming every key that differs (the worker enforces its own configuration; the api and the
  worker must read the same file).
- **Overrides win, key by key.** Set any key in `[renewal.*]` of the TOML file or as `OVLM_RENEWAL__...`; the other keys
  keep their defaults. Unknown keys under `[renewal.timeouts]` and `[renewal.automation_timeouts]` are errors.

## 1. Evidence used

| Ref | What was measured | Source |
|---|---|---|
| E1 | Stop to `SHUTOFF` 13.4 s (11–12 s in EXP-01b R1); detach to `available` 5.0 s (about 3 s); attach to `in-use` 9.3 s (6.7 s first attach, about 5 s); mount by UUID plus service start 6.0 s; HTTP answering 10.4 s later on 1 vCPU | EXP-01 Q3, EXP-01b; [renewal-workflow.md §10](renewal-workflow.md#10-lab-observations-exp-01-and-exp-01b-felcloud-2026-11-04) |
| E2 | Floating-IP move: API 1.06–1.26 s, first good probe 0.6 s or less after the update, no flapping | EXP-01b R1–R3 |
| E3 | Nova `ACTIVE` about 15 s after start, SSH about 85 s later (EXP-01b); green `ACTIVE` in about 40 s, SSH about 100 s later (first Felcloud build) | EXP-01b finding 2; [team-log.md](team-log.md) 2026-11-05 |
| E4 | Console host-key block about 190 s after `server create`; sometimes empty (still empty after 14 min) | EXP-01 Q1, EXP-01b finding 3 |
| E5 | Build phase B1–B9 about 3 min 17 s | [mvp-report.md](mvp-report.md) §2 (ACC-01b) |
| E6 | Downtime of a full cutover W1–W10: 134.7 s (OVLM), 112.8 s (probe), all steps first attempt | mvp-report.md §2 (ACC-01d) |
| E7 | Worker killed at W3: about 84 s without a worker, takeover resumed W3; downtime 225.6 s (OVLM) / 199.7 s (probe). Revert after the cutover: probe outage 218.4 s | mvp-report.md §2 (LAB-01 re-run, ROLLBACK) |
| E8 | The lab's own settings gave a worst-case window of 49 min, inside the policy's 1 h window. The individual values were kept in the lab agent's notes and are **not** in this repository | team-log.md 2026-11-05 |
| K1 | W1 is refused unless a fresh Keystone token outlives the worst-case window; Keystone's default token lifetime is 3600 s (`[token] expiration`) | renewal-workflow.md §2.2; `credential_ok` |
| N1 | Nova stop waits up to `[DEFAULT] shutdown_timeout` (default 60 s) for a clean guest shutdown before powering off | Nova configuration reference (documented, not lab measured) |

## 2. The budget that shapes the defaults

The worst-case window shown at G2 is the **sum** of the deadlines of W1–W10 and S1–S10 (renewal-workflow.md §3): every
step of the window running into its deadline, then a full restore doing the same. Because of K1 this sum must stay
**below one hour** on a cloud with Keystone's default token lifetime, or W1 is never claimed. The lab ran at 49 min
(E8). The defaults below give:

| Service shape | Worst-case window |
|---|---|
| Stateless (no data volume) | 2180 s (36 min) |
| Data volume | 2660 s (44 min) |
| Data volume, `snapshot_before_handoff` | 2960 s (49 min) |

So the defaults keep at least 10 minutes between the worst case and a default token lifetime, at a margin of about 7x to 25x
over the measured OpenStack steps (section 3.1); the window steps (W1–W10) add up to 1130 s, or 1430 s with a snapshot,
against a measured cutover of 113–135 s (E6). The largest single item is the
restore's S7 (`recover_old_service`, 780 s): rollback hooks, then start and health-check blue up to
`healthcheck.max_attempts` times.

A consequence to know: a step whose deadline passes **before it acts** never acts (ADR-0003 deadlines). A worker that
dies between a step's claim and its action is replaced after the lease (`worker.lease_duration`, 60 s) plus the takeover
delay (`worker.takeover_delay`, 45 s), about 105 s; E7 saw 84 s without a worker. Steps with a deadline below that
(`fip_status`, `server_lock`, `volume_detach`, `external_verify`, `server_stop`, `volume_attach`) then stop for a human
instead of resuming. A step that had already acted (the usual case: claim to action takes a second) is finished by
the probe after takeover, deadline or not; that is what LAB-01 showed at W3. Raising all of them to 120 s would push the
worst case with a snapshot to about 62 min, above the token lifetime, so the defaults accept that narrow risk. A cloud
with longer Keystone tokens can raise them.

## 3. The defaults

Tags: **LO** = derived from a lab observation (the evidence ref is given), **EST** = estimated (no lab measurement of
that segment), **DER** = derived from other keys. "Margin" compares the default with the measured value.

### 3.1 `[renewal.timeouts]` (seconds)

| Key | Default | Used by (step) | Tag | Source and reasoning |
|---|---|---|---|---|
| `preflight` | 120 | B1 `preflight`, B8 `verify_cutover_preconditions` | EST | OpenStack reads and a guest probe, no outage; generous on purpose (build phase, not in the window sum) |
| `claim_resources` | 120 | B2 | EST | Tag and metadata writes (a few API calls), build phase |
| `green_create_call` | 120 | B3 | EST | One Nova create call and its ledger record; the build itself is `green_build` |
| `green_build` | 900 | B4 `wait_green_active` | LO (E3, E5) | `ACTIVE` came in 15–40 s; 15 min covers an image not cached on the compute host. Build phase |
| `green_ssh` | 600 | B5 `wait_green_ssh` (plus `green_host_key`) | LO (E3) | SSH answered 85–100 s after `ACTIVE`; 6x margin. Build phase |
| `green_host_key` | 300 | B5, added to `green_ssh` | LO (E4) | Host-key material seen about 190 s after create; B5's bound is 900 s in all |
| `green_ready` | 300 | B9 `verify_green_ready` (plus `automation_timeouts.preflight`) | EST | Re-probe of green just before W1; B9's bound is 420 s in all |
| `server_stop` | 90 | W2, S3, S6 (with `server_start`) | LO (E1) + N1 | 13.4 s measured; Nova may wait 60 s for a clean shutdown, then powers off; 90 s covers that |
| `server_start` | 90 | S6 `boot_old` (with `server_stop`) | EST | Start to `ACTIVE` not measured separately; boot completion is checked by S7, not here |
| `server_lock` | 30 | R1, S1, S10 | EST | One synchronous Nova call; used in the lab (EXP-01, R1, S1) but not timed |
| `server_delete` | 600 | X1 `retire_old`, `discard_green` | EST | Outside the window. X1 also runs a fresh green health check inside this bound (checked, section 4) |
| `volume_detach` | 60 | W3, S4 | LO (E1) | 3–5 s measured; 12x margin |
| `volume_attach` | 90 | W5, S5 | LO (E1) | 5–9.3 s measured; about 10x margin |
| `snapshot` | 300 | W4 (only with `snapshot_before_handoff`) | EST | Not measured on Felcloud; depends on the backend and the volume size. Raise it for large volumes on a copying backend |
| `fip_status` | 30 | W9, S8 | LO (E2) | API 1.06–1.26 s, effective at once; 25x margin |
| `external_verify` | 60 | W10, S9 | LO (E2) | First good probe 0.6 s or less after the move; two successes 5 s apart need about 6 s |

### 3.2 `[renewal.automation_timeouts]` and the runner (seconds)

The renewal's step bound of an Ansible phase defaults to **the runner's timeout of that phase**
(`automation.timeout.<phase>`, else the contract default), so the step deadline and the step lease always cover the
playbook (both add 60 s: 30 s kill grace plus 30 s slack). Raising `automation.timeout.<phase>` raises the step bound
with it, unless `renewal.automation_timeouts.<phase>` is set.

The contract defaults of the four phases that run **inside the window or the restore** were lowered from 300 s to
120 s (idle 120 s to 90 s) with P1-8: at 300 s the restore alone (S2 and S7) would exceed the token lifetime of K1.

| Phase | Runner timeout / idle (contract) | Step deadline | Used by | Tag | Source and reasoning |
|---|---|---|---|---|---|
| `preflight` | 120 / 60 (unchanged) | 180 (B6); B9 adds it to `green_ready` | B6, B9 | EST | Read-only checks on green |
| `configure` | 1800 / 300 (unchanged) | 1860 | B7 | EST | Package installs; build phase, no outage; whole build measured at about 3 min (E5) |
| `quiesce` | 120 / 90 (was 300 / 120) | 180 | W1, S2 | LO (E1, E6) | Stop units, unmount, sync. The whole cutover took 113–135 s (E6), so one phase took tens of seconds; 120 s per phase. A slow-stopping workload asks for more in its profile (see section 4) |
| `data_attach` | 120 / 90 (was 300 / 120) | 180 | W6 | LO (E1) | Mount by UUID 6.0 s including the service start; no fsck |
| `start_service` | 120 / 90 (was 300 / 120) | 180 | W7, S7 | LO (E1) | Start measured within the 6.0 s above; the wait for the service to answer is W8's |
| `healthcheck` | 60 / 30 (unchanged) | W8: `max_attempts` x (60 + 60 + `interval`) = 260 | W8, S7, X1 | LO (E1) | The service answered 10.4 s after start; one call per attempt |
| `rollback_hooks` | 120 / 90 (was 300 / 120) | part of S7 | S7 | EST | Optional workload hooks on blue after a failure; not exercised in the lab |

### 3.3 Other renewal keys

| Key | Default | Tag | Source and reasoning |
|---|---|---|---|
| `[renewal.green_ready] max_age` | 1800 s | EST | B9 must be younger than this when W1 is claimed; a stale B9 is simply re-run before W1 (no outage), so 30 min only bounds how old the proof of green may be |
| `[renewal.healthcheck] max_attempts` | 2 | LO (E1) / budget | The service answered 10 s after start, well within one 60 s call; a second attempt covers a slow start. A third adds 360 s to the worst case (W8 and S7) |
| `[renewal.healthcheck] interval` | 10 s | LO (E1) | Of the order of the 10 s the service needed to listen |
| `[renewal.external_verify] required_successes` | 2 | EST | Two good answers in a row from the expected VM, so one lucky answer is not enough; EXP-01b saw no flapping |
| `[renewal.external_verify] interval` | 5 s | LO (E2) | The move is effective at once; 5 s apart keeps W10 short |
| `[renewal.retire] health_max_age` | 3600 s | EST | X1 runs its own fresh green health check right before the delete, so this bound is never the limiting one today |
| `[renewal.approval_validity] retirement` | 14400 s (4 h) | EST | Same as the cutover validity of security-model.md 7.1: G3 leads to the one irreversible step (blue deleted) |

`approval_validity.plan` (24 h) and `.cutover` (4 h) keep the defaults security-model.md 7.1 always gave them.

## 4. Checks

At start (api and worker; settings that fail a check refuse to load):

| Check | Why |
|---|---|
| Unknown key under `[renewal.timeouts]` or `[renewal.automation_timeouts]`, or a value not above 0 | A typo would otherwise be silently ignored and the default used |
| `renewal.automation_timeouts.<phase>` at least the runner's timeout of that phase | Otherwise the step deadline and lease end while the playbook may still run, and the G2 worst case understates the window |
| `green_ready.max_age` at least B9's deadline (`green_ready` + `automation_timeouts.preflight`) | Otherwise W1 could find every B9 stale and loop |
| `timeouts.external_verify` above `(required_successes - 1) x external_verify.interval` | Otherwise W10 and S9 could never collect their successes in time |
| `timeouts.server_delete` at least `automation_timeouts.healthcheck` + 60 s | X1 runs a green health check inside its own deadline |
| Worst case at or above 3600 s | **Warning** only (a cloud may issue longer tokens): W1 is refused on a default Keystone (K1) |

The existing worker checks stay: `worker.lease_duration` at least 3 heartbeats, `fence_margin + heartbeat_interval`
below the lease, `takeover_delay` at least `fence_margin`; runner idle timeout not above the timeout, default not above
`max_timeout`.

At plan creation: a profile whose `automation.timeouts.<phase>` asks the runner for more than the renewal's step bound
of that phase is refused (409 `renewal-timeouts-inconsistent`): lower the profile's value or raise
`renewal.automation_timeouts.<phase>`. A config built without the defaults (tests, tools) is still refused with the
list of missing keys (409 `renewal-config-incomplete`, and at admission).

## 5. Tuning on your cloud

Run a first renewal with the defaults on a non-critical service and compare the step durations
(`ovlm_step_duration_seconds{step_key}`, the run timeline) with the deadlines in the plan's
`resolved.renewal_settings.values`. Raise a key where a step came near its deadline; lower keys only with measurements,
and keep the worst case below your Keystone token lifetime. A changed configuration applies to plans created after
the change (the plan's record is what G1 and G2 approved); restart the api and the worker together.
