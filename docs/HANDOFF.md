# Handoff — paused 2026-11-05 ~20:30 UTC (maintainer: resume tomorrow)

| Field | Value |
|---|---|
| Owner | Agent 1 — PM / Engineering Manager |
| State | Paused for the night. Code complete in `main` (aba9ec2); Felcloud run parked safely at B9; lab up overnight (approved). |

This page is everything needed to resume, by this session or a new one. The story so far is in
[team-log.md](team-log.md), and the backlog in [roadmap.md](roadmap.md).

## Where things are (2026-11-05 20:30 UTC)

| Place | State |
|---|---|
| `main` | `aba9ec2`, CI green: PRs #1–#25. Credential store, inventory sync, host-key confirmation, six lab bug fixes (roles path, lint probes, K, J, I, M), IS-1..IS-12 closed. |
| Felcloud lab | `ovlm-lab-host` (OVLM at `86e7463`, needs redeploy at `aba9ec2`), blue `ovlm-acc-blue` serving, green from run `01a1ac5d` idle, data volume on blue, set-aside floating IP on blue, one new floating IP on the lab host (hairpin, bug L), one spare. Run `01a1ac5d` parked in `needs_human` at B9, before T0. |
| `ozar-dev` | session_016ti9w2xkWinTeHFRq3zgS3; plan for tomorrow recorded in its notes. Its login expired once today: if it fails, the maintainer runs `/login` there. |

## Next steps, in order (tomorrow)

1. **Maintainer:** reset `approver-a` and `approver-b` himself (`~/.ovlm-lab/reset-approver.sh` on ozar-dev, own passwords, new TOTP), and store the three accounts with their TOTP in his password manager (decision 2026-11-06: TOTP stays on). After that no agent holds approver secrets.
2. `ozar-dev` redeploys OVLM at `aba9ec2` (keep DB and TOTP key), `make smoke`.
3. **Maintainer:** rollback of run `01a1ac5d` in the UI with his own typed confirmation (deletes green, blue untouched).
4. `ozar-dev`: profile v3 pinned to `aba9ec2` (`playbook_dir: ansible/playbooks`), readiness, new plan.
5. **Maintainer in the UI:** G1, G2 (cutover; probe through the floating IP; about 40 s expected), G3 (approver-b).
6. Evidence bundle, guard diff; then the failure scenarios (incl. throw-away branch `claude/ovlm-lab-broken-config`); then `destroy-lab.sh` (floating IPs stay allocated, unassociated).
7. MVP report; README statuses ("lab validated on Felcloud" only where evidence exists).

**Deviation to keep in the report:** G1 and G2 of run `01a1ac5d` were submitted by `ozar-dev` with approver secrets, not by the human in OVLM. Not valid evidence for the approval control.

## Rules in force (from the maintainer)

- Continue to the end of the MVP. Ask **only important decisions**, with the question popup.
- Merge PRs into `main` when CI is green.
- **Commit messages never mention Claude or any AI model, and carry no Co-Authored-By or session trailers.** Sign off
  as `Soufian Zaouam <18644174+soufian-zaouam@users.noreply.github.com>`.
- Cloud work only on `ovlm-*` resources on `ozar-lab` (Felcloud), within quota, deleted when done. One floating IP
  was available on 2026-11-04.
- Decisions taken:
  - D-1 = B: no automatic restore after W7–W10.
  - M9: no operator+approver in one scope by default; restricted Ansible artefacts; TOTP in the MVP; no repo code on
    the live VM without an explicit action.
  - MVP limits: one data volume, boot from image, floating IP required.

## Known environment facts (this coordination session)

- Scheduled reminders do not reach this session (`ACCESS_DENIED`, trusted-device restriction). Use a local
  branch-watcher (a background `git ls-remote` loop) and PR subscriptions instead.
- Docker Hub rate-limits this container. A local PostgreSQL 16 works for integration tests:
  `OVLM_TEST_DATABASE_URL=postgresql://postgres:admin-pw-test@127.0.0.1:55432/postgres`, recreated with `initdb` if
  the container restarted. Automation-container tests need `ssh` and Docker images, so they run in CI only.
- `pkill -f <pattern>` kills its own shell (exit 144); use the background task id or a PID instead.
