# Handoff — paused 2026-11-04 ~17:20 UTC

| Field | Value |
|---|---|
| Owner | Agent 1 — PM / Engineering Manager |
| State | Active. Work resumed 2026-11-04; waiting on the maintainer's approval in the credential-store session. |

This page is everything needed to resume, by this session or a new one. The story so far is in
[team-log.md](team-log.md), and the backlog in [roadmap.md](roadmap.md).

## Where the code is (updated 2026-11-05 00:35 UTC)

| Place | State |
|---|---|
| `main` | PRs #1–#9 merged, CI green: design and reviews, foundation, engine, auth/TOTP/audit, inventory, profiles/policies, readiness, OpenStack read and write clients, RBAC, Ansible runner, **renewal strategy `bluegreen_fip_v1` (reviewed, fixes verified)**, operator UI incl. renewal pages, worker image, Felcloud lab kit, CONTRIBUTING, install guide, templates. Good first issues #10–#17 are open. |
| `claude/ovlm-credential-store` | **The only blocker for the MVP.** The encrypted credential store and project connections (Opus). The session is waiting on a **permission prompt** that only the maintainer can approve: https://claude.ai/code/session_016ti9vzvtr3eKwtKW8Zsf9r |

## Next steps, in order

1. **The maintainer approves the prompt** in the credential-store session. It finishes and pushes.
2. Agent 1 integrates it, runs all tests (also as non-root), and gets an independent security review (fresh Fable,
   focused). Then a fix round if needed, a short Opus verification, a PR, and a merge when CI is green.
3. **Felcloud acceptance campaign (E5-6), through `ozar-dev`**, with `lab/felcloud/` and the decisions in team-log.md
   (cost approved, two test approvers with TOTP, the set-aside floating IP, the throw-away branch
   `claude/ovlm-lab-broken-config`). Run the primary scenario, then the failure scenarios. Store the evidence. Take a
   before/after snapshot proving no non-`ovlm-*` resource changed. Then `destroy-lab.sh`.
   - `ozar-dev` runs in acceptEdits mode, so Bash prompts may need the maintainer.
4. MVP report: what is lab validated on Felcloud and what is not; update README statuses.

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
