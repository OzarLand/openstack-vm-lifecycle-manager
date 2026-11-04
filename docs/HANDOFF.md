# Handoff — paused 2026-11-04 ~17:20 UTC

| Field | Value |
|---|---|
| Owner | Agent 1 — PM / Engineering Manager |
| State | **PAUSED** by the maintainer ("mets tout en pause jusqu'à ce que je te dise reprends"). Resume only on the maintainer's word. |

This page is everything needed to resume, by this session or a new one. The story so far is in
[team-log.md](team-log.md), and the backlog in [roadmap.md](roadmap.md).

## Where the code is

| Place | Content | State |
|---|---|---|
| `main` | Design and reviews, foundation, engine core, auth/TOTP/audit, inventory, profiles/policies/deadlines, UI first pages, CI incl. Ansible job | PRs #1–#4 merged, CI green |
| `claude/openstack-vm-lifecycle-manager-9nf9cc` (working branch) | `main` + write client (E5-2), RBAC (E3-2), Ansible runner (E5-3), readiness (E4), merge migration `0005_merge` | Lint clean, 952 unit and 271 integration tests pass locally. **Not yet PR'd: waiting for the two fix rounds below.** |
| `claude/ovlm-fix-engine` (`ba872eb`) | Fixes for the SRE engine review SRE-C-1..10 | **Done** per the agent: all 10 fixed, lint and tests pass. To verify, merge and PR. |
| `claude/ovlm-fix-security` (`6f85fd9`) | Fixes for security review SEC-C-1..11 (two **High**: SEC-C-1 login rate limit keyed on the proxy IP, SEC-C-2 DEBUG logging of request bodies) | **Done** per the agent, except SEC-C-8, which is partial (needs the `project_connection` table). To verify, merge and PR. |
| `claude/ovlm-renewal` (`0bd035c`, WIP) | Renewal strategy `bluegreen_fip_v1` (E5-4/E5-5) | **Partial:** steps implemented with 44 integration tests passing. The crash matrix and the REST API are not started. |

Reviews: [sre-review-engine-e5-1.md](reviews/sre-review-engine-e5-1.md) is on branch `claude/ovlm-sre-review`, and
[security-review-code-wave3.md](reviews/security-review-code-wave3.md) is on branch `claude/ovlm-security-review`.
Merge both review files into the working branch on resume.

## Paused agent conversations (resume each by telling it to continue)

| Task | Conversation |
|---|---|
| Engine fixes (Opus) | https://claude.ai/code/session_016ti9w3k3JuQ6ezbbbb1req |
| Security fixes (Opus) | https://claude.ai/code/session_016ti9vzbPq7VgEgMRtnjjWV |
| Renewal strategy (Opus) | https://claude.ai/code/session_016ti9w2W4u5bRegw53P7dqM |
| SRE reviewer (Fable, holds the veto) | https://claude.ai/code/session_016ti9w2Rhy79ZyTv4fvtUTJ |
| Security reviewer (Fable) | https://claude.ai/code/session_016ti9vzmfDPFJ7HnXMMD5n5 |
| `ozar-dev` (lab, Felcloud, standing approval for `ovlm-*` resources) | https://claude.ai/code/session_016ti9w2xkWinTeHFRq3zgS3 |

## Next steps, in order

1. **Read each paused conversation's last message:** what is done, what is partial.
2. **Engine fixes and security fixes.** Finish them, merge into the working branch, re-run lint and all tests. Have
   the fixes verified by a short, fresh **Opus** session, not the long Fable sessions, which have become expensive.
3. **Open the PR "write client, RBAC, runner, readiness + review fixes"** to `main`. Merge when CI is green, with a
   merge commit (not a squash).
4. **Renewal strategy (E5-4/E5-5).** Finish it, then get an independent Fable review (SRE + security) of the renewal
   code, fix, PR, merge.
5. **Remaining backlog:**
   - E6-3/E6-4 UI: readiness view, renewal plan and approvals, run timeline;
   - wiring the runner's open points (worker start-up `sweep_orphans()`, B5 bootstrap-key helpers, restricted-artefact
     read rule in `auth`, `automation` dependency group in the runtime image, sudoers/`signal_prefix` for the Ansible
     user);
   - the automation lint worker job and the waiver endpoint.
6. **Lab (E5-6), directly on Felcloud ([ADR-0007](decisions/ADR-0007-lab-on-felcloud.md); quick-lab dropped):**
   - work through `ozar-dev`, in the current `ozar-lab` project, with `ovlm-*` resources only, and with a before/after snapshot proving that no other resource changed;
   - run the primary acceptance scenario and the failure scenarios, and store the evidence;
7. Install guide and release notes, then the MVP report to the maintainer.

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
