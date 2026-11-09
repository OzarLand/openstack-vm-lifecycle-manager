# Handoff: paused 2026-11-09, after the MVP and the production-hardening work (P0, most of P1)

| Field | Value |
|---|---|
| Owner | Agent 1, PM / Engineering Manager |
| State | **Paused at the maintainer's request.** The MVP is done: lab validated on Felcloud, not production validated. All P0 items and P1-2, P1-3, P1-4, P1-6, P1-7, P1-8 and P1-9 are merged. Nothing is running: no lab, no open run, no agent at work. |

This page is everything needed to resume, by this session or a new one. The backlog with every status is in
[roadmap.md](roadmap.md), the story in [team-log.md](team-log.md), and the MVP results and deviations in the
[MVP report](mvp-report.md).

## Where things are

| Place | State |
|---|---|
| `main` | PRs #1–#57 merged. CI is green: lint and types, unit, integration on PostgreSQL 16, Ansible, image build and Compose smoke, `promtool` rule check, `docker compose config` on both Compose files. |
| Open PRs | None. |
| Felcloud `ozar-lab` | Nothing from OVLM is left. The lab's floating IPs were released at the maintainer's request; ozar-dev's own server, its floating IP and the three pre-existing volumes are untouched. |
| Lab evidence | On the maintainer's agent host (ozar-dev): `~/.ovlm-lab/evidence/`, `~/.ovlm-lab/snapshots/`, `~/.ovlm-lab/MANIFEST.sha256` (177 entries). Not in the repository, because it holds lab identifiers. |
| Accounts | Lab accounts are disabled with their secrets shredded (deviation D-9). The maintainer holds the remaining OVLM account secrets. |
| Git branches | Many merged `claude/*` branches remain. This session cannot delete branches or push tags (403). The maintainer runs the cleanup script that archives the 12 never-merged early branches as `archive/*` tags, then deletes the rest. |

## What was done after the MVP (2026-11-09)

| Item | Result | PR |
|---|---|---|
| P0-1 | Run checkouts released from the tmpfs `run_root` when a run ends | #43 |
| P0-2 | `accept-step`: audited approver exit for restore S2 when the pinned playbook refuses a safe state (ADR-0008) | #45, #47 |
| P0-3, P2-3 | Every downtime interval recorded (window and revert); never "0s" on the run page | #44 |
| P0-4 | Contract test pins every result field OVLM reads; defect AD fixed | #46 |
| P0-5 | W6 checks the filesystem label when the profile names it by label | #49 |
| Engine | A heartbeat could extend the lease of an attempt that had already exited (found behind CI flakes) | #48 |
| P1-6 | Independent security and SRE review of #31–#49: 10 findings, no authorization bypass | #50 |
| PMR-1/2/3/6 | Review fixes: bounded accept probe, reprepare bound to its step and fenced, safe cache sweep, quarantine and append-only | #51 |
| P1-2 | Paging: 17 Prometheus alerts, drift test, `promtool` in CI, runbooks in `operations.md` | #52 |
| P1-3 | Backup, restore and upgrade procedure; `ovlm upgrade preflight`, `ovlm backup check`; two restore defects fixed | #53 |
| P1-4 | SF-2 (guard), SF-6, SF-10, PMR-4, PMR-8 | #54 |
| P1-7 | Install guide for a real cloud, with a drift test | #55 |
| P1-9 | Production Compose file, sample TLS proxy; `make secrets` never loosens a mode | #56 |
| P1-8 | Renewal timeout defaults from the lab, recorded in every plan and bound into the plan hash | #57 |
| Docs | README diagrams and screenshots, post-MVP roadmap | #41, #42 |

## Next steps, in order

1. **P1-10** (largest): setup without hand-made API calls (UI pages or CLI for clouds, connections, credentials, users,
   services, profiles; OpenAPI document).
2. **P1-11**: automation repository allowlist and lint checked when a profile is saved, not first at B6 after G1.
3. **P1-12**: Keystone role names configurable; missing readiness checks (fstab `nofail`, enabled units,
   `delete_on_termination`, worker-to-guest reachability); `GET /orphans`.
4. **Needs a lab and the maintainer's go:** P1-1 (failure scenarios LAB-02, LAB-03, LAB-05..09 on a real cloud) and P1-5
   (egress proxy on a cloud that needs it). Also run the production Compose file and the backup/restore targets on a
   real host for the first time.
5. Remaining review items PMR-5, PMR-7, PMR-9, PMR-10 (Low/Info), then P2 (operator experience) and a production pilot
   (milestone M8). V1 scope (P3) after the pilot.

Estimate given to the maintainer on 2026-11-09: about 3 to 4 days of work to milestone M7, plus whatever the lab
reveals; M8 depends on a real service and its operators.

## How to resume

- Read this page, then the roadmap section "After the MVP".
- Work rules that held for the whole project: one PR per item, tests that fail without the fix, merge only on green CI,
  commits authored and signed as the maintainer with no AI mention or trailers, no IPs, hostnames or secrets in the
  repository, honest statuses (nothing "lab validated" without stored evidence).
- Integration tests without Docker: start a throw-away PostgreSQL 16 (`initdb -E UTF8 --locale=C.UTF-8`) and set
  `OVLM_TEST_DATABASE_URL`; the backup test needs PostgreSQL 16 client tools (`OVLM_TEST_PG_BIN`).
