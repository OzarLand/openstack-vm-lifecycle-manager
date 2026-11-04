# ADR-0005 — Resource ownership and idempotency: DB ledger + Nova tags

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 2 (Chief Architect); maintainer approval required |

## Context

NFR-3 requires that retries find instead of re-create. Nova server create has **no client idempotency token**, names are
not unique, and `return_reservation_id` cannot be known before the request (openstack-integration.md §3,
SOURCE-VERIFIED). Server tags can be set atomically at create (mv ≥ 2.52) and are filterable by non-admins; metadata is
**not** filterable by non-admins and a metadata filter is silently dropped, returning all servers (§1, §2,
SOURCE-VERIFIED). Tags and metadata are editable by any project member (§2, SOURCE-VERIFIED). Agent 6 asked who owns
cleanup of OVLM-created resources (test-environment.md §7.3).

## Options

| Option | Problem |
|---|---|
| Name-based lookup | Names are not unique; regex filter (§1). Ambiguous. |
| Metadata-based lookup | Silently ignored for non-admins → would "find" every server. Dangerous. |
| `return_reservation_id` | Unknown until the response arrives; useless when the response is lost; not in the SDK. |
| **DB intent ledger + tags at create + anchored name** | Small residual risk only if a member deletes the tag in the seconds before the id is recorded. |

## Decision

1. **OVLM's database is the source of truth**; OpenStack markers are lookup aids, never authorization.
2. Table `owned_resource` (data-model.md §9): `resource_type`, `intended_name`, `openstack_id` (nullable until known),
   `run_id`, `role` (`green`, `snapshot`), `state` (`intended`, `present`, `deleted`, `orphan`).
3. Create protocol (step `create_green`):
   - persist `owned_resource(state=intended, intended_name='ovlm-<service-slug>-<run8>-<attempt-free n>')` and commit;
   - create with tags `ovlm:managed`, `ovlm:run:<run_uuid>` (45 chars, fits the 60-char limit, §2 SOURCE-VERIFIED) and
     metadata `ovlm.service`, `ovlm.profile_version`, `ovlm.role=green` (payload, never secrets: metadata reaches the
     guest, §2 ASSUMPTION);
   - record `openstack_id` immediately when the response arrives.
4. Resume / retry lookup: `GET /servers/detail?tags=ovlm:run:<run_uuid>` plus anchored name `^name$`, re-checked
   client-side. 0 → create; 1 → adopt; >1 → `needs_human` ("duplicate create detected"), never auto-delete.
5. **Ownership guard** (security-model.md §4.3): before every mutating call the target must be recorded in the DB for
   this run **and** carry the OVLM marker. Pre-existing resources therefore get marked by the first run step
   `claim_resources` (worker, write credential): tag `ovlm:managed` on blue and on the FIP (Neutron tags), metadata
   `ovlm.managed=true` on the data volume (Cinder has metadata, not tags). This marking is the only mutation exempt from
   guard rule 2 (it still needs rule 1: the ID is in the approved plan). Marks stay after the run (they record that OVLM
   manages the resource). Blue's lock uses `locked_reason='ovlm:retained:<run_uuid>'` (mv ≥ 2.73).
6. Snapshots (optional) are found by name + Cinder metadata filter `ovlm.run` (volume metadata filter is allowed per
   `resource_filters.json`, §1 SOURCE-VERIFIED for volumes; snapshot filters ASSUMPTION — lab to confirm, else name +
   ledger id only).
7. **Cleanup ownership:** OVLM deletes only resources that are in its ledger, belong to one of its runs, and whose
   deletion is a defined step of that run (green on operator rollback, snapshot at retirement). The
   inventory sync flags `ovlm:*`-tagged resources that are not in the ledger, or belong to terminal runs, as **orphans**;
   deleting an orphan is a manual `admin` action with typed confirmation.
8. Microversions OVLM relies on are pinned and recorded per call in step evidence: 2.26/2.52 (tags), 2.47 (embedded
   flavor), 2.73 (lock reason), 2.79/2.85 (`delete_on_termination` read/update) (§ recommendations 10).

## Consequences

- Duplicate green servers are detected, not silently created; the residual window (tag removed by a human within
  seconds of create) ends in `needs_human`, not data loss.
- SDK debug HTTP logging stays off in the worker (security-model.md §4.5).
- Every run starts with one extra write (`claim_resources`); a member who removes a marker mid-run makes the next
  mutating step stop with `ownership_violation` (`needs_human`), which is the intended fail-safe.
- Orphan report is part of inventory (FR-INV) and the dashboard "runs needing attention".
