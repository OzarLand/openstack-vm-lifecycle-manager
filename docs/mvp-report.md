# MVP report — DRAFT

| Field | Value |
|---|---|
| Owner | Agent 1 — PM / Engineering Manager |
| Status | **Draft, 2026-11-08.** The primary acceptance scenario **passed on Felcloud** (ACC-01d, run `01a1b752`, 2026-11-07). The first attempt (ACC-01c) had failed at the cutover (bugs W and X, fixed in #31). The three kept failure scenarios are running. Nothing below is marked "lab validated" without stored evidence. |
| Code | `main` at `3d4fce0` or later (PRs #1–#29) |

## 1. What the MVP is

OVLM renews an OpenStack VM on a plan instead of preserving it forever: build a new VM (green) from automation, prove
it ready, then in a short window stop the old VM (blue), move its data volume and floating IP to green, check health,
keep blue stopped for a way back, and retire it after a second approval. Strategy `bluegreen_fip_v1`, one data volume,
boot from image, floating IP required (MVP limits, decided 2026-11-04).

## 2. Status per area

Vocabulary: designed → implemented → unit tested → integration tested → lab validated → production validated.

| Area | Status | Evidence |
|---|---|---|
| Foundation (api, worker, PostgreSQL, Compose, CI) | Integration tested; runs on Felcloud (`make smoke` on the lab host) | CI; lab host |
| Workflow engine (durable, fenced, crash-safe) | Integration tested, reviewed | WF-01..WF-20 crash suites; WF-07 race root-caused and fixed (#27) |
| Authentication, TOTP, RBAC, separation of duties, audit | Integration tested, reviewed; **used for real on Felcloud** (enrolment, step-up, approvals, audit API) | Lab evidence ACC-01/01b |
| Encrypted credential store, project connections | Integration tested, reviewed, fixes verified; **used on Felcloud** (application credentials validated, Keystone self-read confirmed) | Reviews CS-1..CS-10; lab |
| Inventory sync through project connections | Integration tested, reviewed; **ran on Felcloud** (read-only) | Lab evidence (E2-4) |
| Readiness | Integration tested; **ran on Felcloud**: level `ready`, negative control (unpinned ref refused, 422) | Lab evidence (A3) |
| Policies, deadlines, windows | Integration tested; **ran on Felcloud** (deadline moved to the next window as designed) | Lab evidence (A4) |
| Host-key scan and human confirmation | Integration tested, reviewed (IS-1..IS-12 fixed) ; used on Felcloud | Reviews; lab |
| Renewal build phase (B1–B9) | Integration tested; **ran end to end on Felcloud twice** (about 3 min 17 s, 0 probe failures, data volume never attached twice) | ACC-01b build evidence |
| Abort / discard in the build phase | Integration tested; **ran on Felcloud** after bug S was fixed (green deleted, blue untouched, locks released) | 2026-11-07 |
| Cutover window (W1–W10) | **Lab validated** (ACC-01d): all steps first attempt, no manual intervention; downtime 134.7 s (OVLM), 112.8 s (probe through the floating IP); volume never attached twice (2,357 samples); data marker and fs UUID equal | ACC-01d; ACC-01c failed first (bug W) |
| Restore (S1–S10) after an operator rollback | Integration tested; **ran on Felcloud**: volume and floating IP back on blue, data intact; S7 needed a manual service start (bug X), fixed in #31; re-run is failure scenario 3 | ACC-01c |
| Retention, retirement (G3, X1) | **Lab validated** (ACC-01d): blue deleted, data volume kept on green, run completed with 0 locks; G3 by a lab account (D-7b) | ACC-01d |
| Failure scenarios (Felcloud) | Not run yet | Prepared |
| Production validated | No | — |

**A renewal is lab validated on Felcloud** (ACC-01d, 2026-11-07): G1 and G2 decided by the maintainer in OVLM
(`password+totp`), B1–B9, W1–W10, R1, R2, G3, X1, guard diff PASS (0 violations), evidence stored. Failure behaviour
on Felcloud is limited to the three kept scenarios (section 5); the others are integration tested only.

## 3. What the lab found that CI could not

Running on a real cloud with the real process model found 21 defects that the CI suites (root, fake cloud, test HTTP
client) could not see. All are fixed, each with a test that fails without the fix where a test is possible.

| ID | Defect | Fix |
|---|---|---|
| kit A–F | Lab kit order, proxy, SSH stdin, smoke rerun, probe source rule | #19, #21 |
| — | Inventory never synced through a project connection (no API, no worker job) | #20 |
| — | Blue's host key never set: every renewal would stop at its first SSH | #20 |
| G, H | No dev TOTP key; enrolment link could not be reissued | #20 |
| roles path | Roles not found in `ansible/playbooks` + `ansible/roles` | #21 |
| lint | The blocking lint refused the reference workload's read-only probes | #21 |
| K | Worker could not read Ansible's result as another OS user | #23, #24 |
| J | Version check needed a writable `$TMPDIR` on a read-only root | #23 |
| L | Floating-IP hairpin from the worker (lab network) | lab configuration |
| M | Green's user-data failed the cloud-init schema | #25 |
| N | `Referrer-Policy: no-referrer` broke every browser form | #26 |
| O | No audit API or page (roadmap had it as done) | #27 |
| P | Guard diff dropped the set-aside floating IP | #27 |
| Q | Evidence redaction erased audit action names | #28 |
| R | Ed25519 lab certificate refused by browsers | lab configuration |
| S | A server Nova still lists as DELETED blocked the abort | #28 |
| W | Quiesce busy check used `fuser -vm`, which exits 0 on every idle mount: every real cutover parked at W1 | this fix |
| X | Restore after a W1 park never restarted the service on blue: S6 saw unknown unit state as healthy, S7 only health-checked | this fix |

## 4. Deviations, recorded honestly

- **D-1:** G1 and G2 of the first run (`01a1ac5d`) were submitted by the `ozar-dev` agent with approver secrets after
  the maintainer's yes, not by the maintainer in OVLM. That run is not evidence for the approval control. Since
  2026-11-06 the maintainer holds all account secrets (KeePassXC) and no agent holds any.
- **D-4:** the lab UI is reachable on a floating IP over HTTPS (self-signed), TCP 443 open to the maintainer's IP
  only. Removed at teardown.
- **D-5:** a guard FAIL caused by kit bug P, re-run PASS after the fix.
- **D-6 (ACC-01c, run `01a1b658`):** G1 and G2 were approved by the maintainer in OVLM (`password+totp`), and the
  rollback was typed by the maintainer. The cutover parked at W1 (bug W) with the service stopped on blue. The
  restore then stopped at S7 (bug X). With the maintainer's yes, the lab agent started the service on blue by hand
  (`systemctl start`) and then retried S7; OVLM finished the restore. Downtime: about 949 s measured by OVLM, about
  896 s by the probe through the floating IP. Guard diff PASS. This run is **not** evidence of a successful
  renewal; it is evidence that the restore keeps the data on blue (volume never attached twice, marker equal).
- **D-7:** at the maintainer's request (2026-11-07), the failure-scenario runs are approved by two lab-only accounts
  (`lab-agent-a` approver, `lab-agent-b` operator), created through a temporary admin that was disabled right after.
  Their secrets stay on the lab host; all three accounts are removed at teardown. These runs prove failure behaviour,
  not the approval control.
- **D-7b:** G3 of ACC-01d was decided by `lab-agent-a`, on the maintainer's direct authorization. The approval-control
  evidence of ACC-01d is G1 and G2, decided by the maintainer; G3 proves the retirement mechanics only.

## 5. What remains before the MVP is done

1. ~~Primary scenario on Felcloud~~: done (ACC-01d).
2. The failure scenarios on Felcloud, reduced by the maintainer's decision to three: LAB-04 (configure failure),
   LAB-01 (worker kill in the window), operator rollback after the cutover. The others (LAB-02/03/05..09) remain
   integration tested only.
3. Evidence, guard diff, teardown (`destroy-lab.sh`; floating IPs stay allocated).
4. This report finalised and the README statuses updated with what is lab validated.

## 6. After the MVP

The roadmap's security follow-ups (SF), AU/UI items and V1 list: signed approvals, OIDC, multiple data volumes, boot
from volume, other strategies.
