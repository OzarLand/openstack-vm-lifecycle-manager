# Handoff: MVP done, 2026-11-09

| Field | Value |
|---|---|
| Owner | Agent 1, PM / Engineering Manager |
| State | **MVP done.** The MVP is lab validated on Felcloud, not production validated. The lab is torn down. No run is active and no lab account is enabled. |

This page is everything needed to resume, by this session or a new one. The results and every deviation are in the
[MVP report](mvp-report.md). The story is in [team-log.md](team-log.md), and the backlog is in
[roadmap.md](roadmap.md).

## Where things are

| Place | State |
|---|---|
| `main` | Code PRs #1–#38, docs PR #39, plus this final docs PR. CI is green. |
| Felcloud `ozar-lab` | No `ovlm-*` resource is left. The maintainer's floating IPs stay allocated, unassociated and untagged. The guard diff passes against the first baseline. |
| Evidence | Kept on the maintainer's agent host: `~/.ovlm-lab/evidence/` and `~/.ovlm-lab/snapshots/`, with a sha256 manifest of 177 entries in `~/.ovlm-lab/MANIFEST.sha256`. It is not in the repository, because it holds lab identifiers. |
| Accounts | `lab-agent-a`, `lab-agent-b` and `lab-agent-admin` are disabled, and their secrets are shredded (D-9). The maintainer holds the remaining OVLM account secrets. |

## Open follow-ups (after the MVP)

- The run checkouts in the tmpfs `run_root` are never released when a run ends. Confirm, then fix.
- AC: OVLM records only the first downtime interval of a run. The downtime of a revert after the cutover is measured by the probe only.
- D-8b gap: if the run's automation pin predates a role fix, a playbook refusal has no exit through OVLM.
- Login does not redirect back to the requested page.
- The roadmap items: security follow-ups (SF), AU/UI, and V1 (signed approvals, OIDC, multiple data volumes, boot from volume, other strategies).
- The failure scenarios LAB-02, LAB-03 and LAB-05 to LAB-09 are integration tested only.
