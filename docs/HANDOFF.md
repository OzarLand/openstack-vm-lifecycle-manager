# Handoff — paused 2026-11-04 ~17:20 UTC

| Field | Value |
|---|---|
| Owner | Agent 1 — PM / Engineering Manager |
| State | Active. Credential store fixed and verified; Felcloud lab being prepared by `ozar-dev`. |

This page is everything needed to resume, by this session or a new one. The story so far is in
[team-log.md](team-log.md), and the backlog in [roadmap.md](roadmap.md).

## Where the code is (updated 2026-11-05 08:10 UTC)

| Place | State |
|---|---|
| `main` | PRs #1–#9 merged: everything up to the renewal strategy, UI, lab kit and contributor docs. |
| Working branch `claude/openstack-vm-lifecycle-manager-9nf9cc` | Encrypted credential store + review fixes (verified, fit to merge), lab kit fixes, worker egress proxy. A PR to `main` is open or about to be. |
| `ozar-dev` (session_016ti9w2xkWinTeHFRq3zgS3) | Resetting the workload and redeploying OVLM at `49621cc` behind the proxy; stops before any renewal and reports. |

## Next steps, in order

1. Merge the working-branch PR when CI is green.
2. Read `ozar-dev`'s report. If the restricted application credential cannot read its own Keystone record, the CS-3
   check needs a policy-aware fallback before credentials can validate on Felcloud.
3. **Felcloud acceptance campaign (E5-6)** through `ozar-dev`, with `lab/felcloud/scenarios.md` and the decisions in
   team-log.md (cost approved, two test approvers with TOTP, the set-aside floating IP, the throw-away branch
   `claude/ovlm-lab-broken-config`). Primary scenario, then the failure scenarios. Store the evidence, run the
   before/after guard, then `destroy-lab.sh`.
4. MVP report: what is lab validated on Felcloud and what is not; update README statuses.
5. Security follow-ups SF-1..SF-6 (roadmap) before any production use.

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
