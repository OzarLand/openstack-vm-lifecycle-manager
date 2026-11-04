# ADR-0005 — Resource ownership and idempotency: DB ledger + Nova tags

| Field | Value |
|---|---|
| Status | Proposed (Phase 1, awaiting maintainer approval) |
| Date | 2026-11-04 |
| Deciders | Agent 2 (Chief Architect); maintainer approval required |

> **Revision 2026-11-04**: tag lookup and the ignored metadata filter are now LAB-OBSERVED (EXP-01 Q5); honest framing
> of marker rule 2 and merge-only marking (SEC-R-24, SRE-R-15); adoption checks (SEC-R-23); orphans report-only in MVP
> (SEC-R-25); ledger uniqueness allows history (SRE-R-11).

## Context

NFR-3 requires that retries find instead of re-create. Nova server create has **no client idempotency token**, names are
not unique, and `return_reservation_id` cannot be known before the request (openstack-integration.md §3,
SOURCE-VERIFIED). Server tags can be set atomically at create (mv ≥ 2.52) and are filterable by non-admins; metadata is
**not** filterable by non-admins and a metadata filter is silently dropped, returning all servers (§1, §2,
SOURCE-VERIFIED). **EXP-01 (Felcloud, member-equivalent credential) observed both**: tags set at create (mv 2.52) and
`tags=`/`tags-any=` returned exactly the run's servers; a metadata filter returned HTTP 200 with every server of the
project, including servers of other users (LAB-OBSERVED). This decision is confirmed. Tags and metadata are editable by any project member (§2, SOURCE-VERIFIED). Agent 6 asked who owns
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
   `run_id`, `role` (`green`, `snapshot`), `state` (`intended`, `present`, `deleted`, `orphan`). At most one
   `intended`/`present` row per (run, role); `deleted` rows stay as history.
3. Create protocol (step `create_green`):
   - persist `owned_resource(state=intended, intended_name='ovlm-<service-slug>-<run8>-<attempt-free n>')` and commit;
   - create with tags `ovlm:managed`, `ovlm:run:<run_uuid>` (45 chars, fits the 60-char limit, §2 SOURCE-VERIFIED) and
     metadata `ovlm.service`, `ovlm.profile_version`, `ovlm.role=green` (payload, never secrets: metadata reaches the
     guest, §2 ASSUMPTION);
   - record `openstack_id` immediately when the response arrives.
4. Resume / retry lookup: `GET /servers/detail?tags=ovlm:run:<run_uuid>` plus anchored name `^name$`, re-checked
   client-side. 0 → create; >1 → `needs_human` ("duplicate create detected"), never auto-delete; 1 → **adopt only if**
   the candidate also matches facts a member is unlikely to forge (SEC-R-23): image ID and flavor equal the plan's
   `resolved` values, `created` is not earlier than the ledger row's commit time, no volume is attached, and `user_id`
   equals the Keystone user of OVLM's write credential (visibility of `user_id` to a member is ASSUMPTION → lab; if not
   visible, that check is dropped and recorded). Any mismatch → `needs_human` ("adoption refused"), never adopt.
5. **Ownership guard** (security-model.md §4.3): before every mutating call the target must be recorded in the DB for
   this run **and** carry the OVLM marker. **Authority comes from rule 1 only**: the ID is in the plan hash approved at
   G1, and the DB is the truth. For a pre-existing resource (blue, FIP, data volume) the marker proves nothing, because
   OVLM sets it itself; rule 2 there adds visibility to other humans and detection of DB/cloud divergence, not
   authorization (SEC-R-24). The markers are set by `claim_resources` (worker, write credential, after G1 and run
   start): tag `ovlm:managed` on blue and on the FIP (Neutron tags), metadata `ovlm.managed=true` on the data volume
   (Cinder has metadata, not tags). Marking uses the **per-tag add** and the **metadata merge** forms, never a
   replace-all form (verb semantics ASSUMPTION, not in OSI → lab with foreign metadata present), and reads back to
   verify every pre-existing tag and key is intact. A server at 50 tags or 128 metadata items (OSI §2, SV) fails the
   step `fatal`. Marks stay after the run (they record that OVLM manages the resource). Blue's lock uses
   `locked_reason='ovlm:retained:<run_uuid>'` (mv ≥ 2.73).
6. Snapshots (optional) are found by name + Cinder metadata filter `ovlm.run` (volume metadata filter is allowed per
   `resource_filters.json`, §1 SOURCE-VERIFIED for volumes; snapshot filters ASSUMPTION — lab to confirm, else name +
   ledger id only).
7. **Cleanup ownership:** OVLM deletes only resources that are in its ledger, belong to one of its runs, and whose
   deletion is a defined step of that run (green on operator rollback; never a snapshot: those are kept and only reported as orphan candidates, renewal-workflow.md §4). The
   inventory sync flags `ovlm:*`-marked resources that are not in the ledger, or belong to terminal runs, as **orphans**,
   **excluding** anything a current `service`, `managed_vm` or `profile_version` references (the data volume, the
   service FIP and the current VM keep their marks forever and are never orphans). **MVP orphan handling is report-only**
   (SEC-R-25): list, evidence, and a suggested CLI command for a human with the needed rights. OVLM has no orphan
   delete endpoint, never deletes a volume or a FIP, and its write-session allowlist refuses those calls (SEC-R-7).
8. Microversions OVLM relies on are pinned and recorded per call in step evidence: 2.26/2.52 (tags), 2.47 (embedded
   flavor), 2.73 (lock reason), 2.79/2.85 (`delete_on_termination` read/update) (§ recommendations 10).

## Consequences

- Duplicate green servers are detected, not silently created; the residual window (tag removed by a human within
  seconds of create) ends in `needs_human`, not data loss.
- SDK debug HTTP logging stays off in the worker (security-model.md §4.5).
- Every run starts with one extra write (`claim_resources`); a member who removes a marker mid-run makes the next
  mutating step stop with `ownership_violation` (`needs_human`), which is the intended fail-safe.
- Orphan report is part of inventory (FR-INV) and the dashboard "runs needing attention".
