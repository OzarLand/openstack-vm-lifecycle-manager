[← OVLM home](../README.md)

# Backup, restore and upgrade of OVLM itself

| Field | Value |
|---|---|
| Status | **Implemented, integration tested; not lab validated.** `tests/integration/test_backup_restore.py` dumps a populated database, restores it with the steps below into a new database, migrates it to head and checks credentials, audit rows, privileges and append-only guards; it also checks that the upgrade preflight refuses during a window. The `make backup` / `make restore` / `make upgrade-preflight` targets have not run on a real installation yet. |
| Audience | Whoever runs OVLM: before the first renewal, before every upgrade, and during a recovery |
| Tooling | `ovlm backup check`, `ovlm upgrade preflight` (read-only, [`src/ovlm/maintenance/`](../src/ovlm/maintenance/)); `make backup`, `make restore`, `make upgrade-preflight`; [`deploy/backup/create-database.sql`](../deploy/backup/create-database.sql) |
| Requirements | NFR-7 (recoverability), architecture.md §9 (upgrades), security-model.md §5.1 (KEK backup), SRE-R-4 (single PostgreSQL with backups), review PMR-10 (no downgrades) |
| Last updated | 2026-11-09 |

> [!IMPORTANT]
> **Never upgrade, restore or stop the worker while a renewal is in its downtime window or a restore.** The service
> of that VM is down or moving, and a stopped worker keeps it down until it is back. `ovlm upgrade preflight` refuses
> in that state (§4.1). Let the window finish, or follow the run's runbook in [operations.md](operations.md).

Commands in this page are for the Compose stack. On a real installation that is `compose.prod.yaml`, named by
`COMPOSE_FILE=compose.prod.yaml` in `.env` ([install-guide-real-cloud.md §5.4](install-guide-real-cloud.md#54-the-production-compose-file-and-env)):
every `docker compose` command below and the targets `make backup`, `make restore`, `make upgrade-preflight` and
`make smoke` then use it (or pass `COMPOSE_FILE=compose.prod.yaml` to `make`). Without it they use the development
file `compose.yaml` ([install-guide.md](install-guide.md)). ⚠️ marks a command that changes state, 🛑 one that
destroys data.

## 1. What to back up

| Item | Where (Compose) | How | Why |
|---|---|---|---|
| PostgreSQL database `ovlm` | volume `pgdata` | `pg_dump -Fc` (logical, consistent snapshot): `make backup` | Everything OVLM knows: inventory, registry, profiles, policies, plans, approvals, runs and steps, the ownership ledger, users, the audit trail, the sealed credentials (ciphertext) |
| Cluster roles | the PostgreSQL cluster | `pg_dumpall --roles-only --no-role-passwords` (in `make backup`, for reference) | `pg_dump` holds no roles. `ovlm_owner` (CREATEROLE), `ovlm_api`, `ovlm_worker` must exist before a restore; the Compose init script creates them from `./secrets` |
| **KEK private key(s)** | `secrets/worker_kek` | Offline, **apart from the dump**, two custodians (security-model.md §5.1) | Every sealed credential is wrapped to it. Without it the dump's credentials are ciphertext only: re-upload them all |
| **TOTP key** | `secrets/totp_key` | With the KEK, apart from the dump (install-guide.md §3a) | Encrypts every TOTP secret. Without it every admin and approver is locked out of step-up |
| Database passwords | `secrets/db_*_password` | With the deployment's secrets | Not in the dump: the roles get them again on a new volume. New passwords also work (§3, step 2) |
| KEK public key | `secrets/worker_kek.pub` | Optional | Derived from the private key: `ovlm kek public --private-in <file>` |
| Configuration | `.env` (image references, external URL), `config/ovlm.toml`, any site Compose file, the TLS proxy, `deploy/prometheus/` | Version control or the deployment's config backup | Not data |

**Not backed up:**

- The checkout cache (volume `checkouts`, `automation.checkout_cache`) and the tmpfs `run_root`: copies of
  verified git checkouts, no secret. A run that needs a checkout outside the window clones and verifies it again; a
  run inside a window never survives into a backup by rule (§2, rule 3).
- Run artefacts outside PostgreSQL: there are none (logs and evidence are size-capped columns).

What a dump contains is sensitive even without the keys: Argon2 password hashes, hashed session ids, the encrypted
TOTP secrets, sealed credentials (ciphertext), restricted Ansible output (`automation_run.log`, SEC-R-3) and the
whole audit trail. Store dumps encrypted, with the access rules of the database itself. `make backup` writes them
with mode `0600` under `backups/` (git-ignored).

## 2. Consistency rules

1. **No backup that its keys cannot restore.** Every sealed secret in use must be wrapped to a KEK whose private key
   is kept for that backup. `ovlm backup check` (run by `make backup` before it dumps) compares the key ids in use
   with the public key(s) given (default: the api's `kek.public_key_file`) and refuses (exit 2) when a secret is
   wrapped to another key, e.g. in the middle of a KEK rotation. It also refuses when a stored TOTP secret does not
   decrypt with the api's TOTP key. The manifest (`manifest.txt`) records the release, the schema revision and the
   `kek_id`s the backup needs; label the offline KEK copy with its `kek_id` (`ovlm kek public --private-in` prints it).
2. **Keep a KEK as long as a backup needs it.** After a KEK rotation, the old private key may be destroyed only when
   no retained backup lists its `kek_id` in its manifest, or when you accept that restoring such a backup means
   uploading every credential again ([credential-store.md §5](credential-store.md#5-rotating-the-kek-security-modelmd-51)).
   Take a new backup right after a rotation finished (`ovlm kek status` exit 0).
3. **Back up outside a window.** `pg_dump` is consistent at any time, but restoring a dump taken during a window puts a
   run back in the middle of its outage, with OpenStack state that has moved on. Back up when
   `ovlm upgrade preflight` shows no `outage-in-progress` / `downtime-open`.
4. **Append-only evidence is restored, never edited.** `audit_event`, `run_downtime`, `step_acceptance` and
   `automation_reprepare` are append-only by trigger; the tombstones and the inventory revisions by grants. A restore
   loads them with `pg_restore` (rows first, triggers and grants after), so their guards are back before anything
   else writes. Do not "fix" a restored database by hand: an `UPDATE` or `DELETE` on the guarded tables is refused,
   by design, even for the owner.
5. **Restore the whole database or nothing.** One transaction (`pg_restore --single-transaction --exit-on-error`):
   a failed restore leaves an empty database, never a partial one.
6. **A restore goes back in time.** Everything after the backup is gone from OVLM: runs that progressed, approvals,
   credentials uploaded or rotated, users and tokens created or revoked, and audit rows. The audit rows still exist in
   the log-stream mirror (`event=audit` lines, security-model.md §8); keep that collector's retention longer than the
   backup interval.
7. **Client tools have the server's major version.** `pg_dump`, `pg_restore` and `psql` must be the major version of
   the PostgreSQL server they talk to (`SHOW server_version_num`, divided by 10000). A newer `pg_dump` writes
   settings an older server does not know (`pg_dump` 17 emits `SET transaction_timeout`, which a 16 server refuses
   with `unrecognized configuration parameter`, so `--exit-on-error` aborts the restore); an older one refuses to dump
   a newer server. `make backup` and `make restore` run the tools inside the `postgres` container, so they always
   match. When you dump or restore from another host, use `/usr/lib/postgresql/<major>/bin` (Debian/Ubuntu package
   `postgresql-client-<major>`), not whatever `pg_dump` is first on `PATH`. Restoring into a newer major (a
   PostgreSQL upgrade) is the one supported mismatch: dump with the old server's tools, restore with the new ones.

## 3. Restore

Use it to recover from a lost or corrupted database, to move OVLM to a new host, or to roll an upgrade back (§4.3).

**Before:** note every non-terminal run and its state (UI **Runs**, or `GET /api/v1/runs`), if the old database is
still readable. Stop renewals: nobody confirms a cutover until step 6 passed.

1. Put the keys of the backup back: `secrets/worker_kek` (the private key whose `kek_id` the manifest lists, mode
   `0400`) and `secrets/totp_key` (install-guide.md §3a; on a real installation `0400` owned by `10001`), **before**
   `make secrets` or `make up` run: both create a missing key, and a new key does not open the backup. `make secrets`
   never changes a file that exists, or its mode. Derive the public key if it is missing:
   ```bash
   # ⚠️ State-changing: writes secrets/worker_kek.pub (as `make secrets` does)
   openssl pkey -in secrets/worker_kek -pubout -out secrets/worker_kek.pub && chmod 0444 secrets/worker_kek.pub
   ```
2. The database passwords: keep `secrets/db_*_password` of the installation. On a new host, new passwords work: the
   init script creates the roles with them on the new, empty `pgdata` volume.
3. Restore (🛑 drops the database `ovlm`; the target asks for a typed confirmation):
   ```bash
   make restore DUMP=backups/20261109T020000Z CONFIRM=replace-ovlm-database
   ```
   It checks `SHA256SUMS`, prints the manifest, stops api and worker, drops the database, creates it again with
   `deploy/backup/create-database.sql`, runs `pg_restore --single-transaction --exit-on-error`, ends every restored
   browser session, then `docker compose up -d --wait` (the `migrate` service runs `ovlm migrate`: a no-op for a dump
   of this release, the pending migrations for an older one), and runs the two key checks of step 4.
4. The keys open the database:
   - `docker compose exec -T api ovlm backup check`: exit 0. `BLOCK kek-missing`: the KEK given is not the one the
     sealed secrets need. `BLOCK totp-key-mismatch`: wrong TOTP key.
   - `docker compose exec -T -u ovlm worker ovlm kek status`: exit 0 (or 3 while a previous key is still held for a
     rotation). Exit 2: the worker holds no key for some secrets.
5. `make smoke`. Log in as an admin (password + TOTP).
6. Every non-terminal run: open it, press **Probe** and compare with the list from "Before". The worker probes before
   every step, so a run whose OpenStack state moved on after the backup parks `needs_human` rather than acting on
   stale state; resolve it as its runbook says. Resources created after the backup are not in the ownership ledger:
   OVLM never touches them (orphans are report-only, SEC-R-25); clean them up by hand.
7. Users, roles and API tokens: changes after the backup are gone. Revoke again what was revoked since.

**PostgreSQL outside Compose:** create the three roles as `docker/postgres/10-ovlm-roles.sh` does (`ovlm_owner`
with `CREATEROLE`; none a superuser), then as the superuser:
```bash
psql -U postgres -d postgres -v ON_ERROR_STOP=1 -v dbname=ovlm -f deploy/backup/create-database.sql
pg_restore -U postgres -d ovlm --exit-on-error --single-transaction ovlm.dump
psql -U postgres -d ovlm -v ON_ERROR_STOP=1 -c 'DELETE FROM auth_session'
```
then `ovlm migrate` and step 4. Restore as a superuser (owners and grants are restored as dumped). Use the
`create-database.sql` file, not a bare `CREATE DATABASE`: `pg_dump` without `--create` holds no database-level
privileges, and the baseline migration that revoked `CONNECT` from `PUBLIC` does not run again.

**Restore test (NFR-7):** restore the latest backup into a throw-away stack (another host or a copy of the Compose
directory with its own volumes) at least every quarter and after every KEK rotation, and run steps 4 and 5. A backup
that was never restored is not a backup.

## 4. Upgrade

Supported path: release N-1 → N (architecture.md §9). Skipping releases is untested.

### 4.1 Preflight: when the upgrade is refused

`ovlm upgrade preflight` runs with the **new** release (its migrations decide the direction) and reads only. It
prints one `LEVEL<TAB>code<TAB>message` line per finding and exits 2 when one blocks:

| Code | Level | When |
|---|---|---|
| `outage-in-progress` | block | a non-terminal run is in phase `window` or `restore` (any state, `needs_human` included) |
| `downtime-open` | block | a run has an open `run_downtime` interval (the service is not back yet) |
| `database-ahead` | block | the database is at a revision this release does not know: it was migrated by a newer release. Downgrades are not supported |
| `database-off-history` | block | the database revision is not an ancestor of this release's head |
| `worker-live` | block with `--worker-stopped`, else info | a worker beat within 3 heartbeat intervals |
| `step-leased` | block with `--worker-stopped`, else info | a step is `running` under an unexpired lease: the worker did not drain |
| `runs-active` | warn | runs outside the window (`requested`, build, retained, retire): they wait and resume after the upgrade; each step probes first |
| `planned-window-soon` | warn | an approved plan's planned window starts within `--planned-window-hours` (default 2) |
| `migrations-pending`, `schema-at-head`, `fresh-database` | info | what `ovlm migrate` will do |

**Drain.** OVLM has no maintenance mode. Only the worker admits runs, consumes operator signals and runs steps, so a
stopped worker is the drain: requests and signals sent meanwhile wait in the database (`requested`, unconsumed
`run_signal`) and are handled when the worker is back. A worker stopped with `SIGTERM` (`docker compose stop`, 40 s
grace) marks itself draining, claims nothing new and lets running steps finish for `worker.shutdown_grace` (30 s).
Expect `OvlmRunRequestedOverdue` / `OvlmRunSignalPendingOverdue` tickets during a long upgrade; silence them for the
maintenance.

### 4.2 Procedure (Compose)

1. Read the release notes. Get the new release and build its images under a new tag; running containers keep the
   old ones:
   ```bash
   git fetch --tags && git checkout <new release tag>
   make build IMAGE_TAG=$(git rev-parse --short=12 HEAD)
   ```
   With `compose.prod.yaml`, set `OVLM_IMAGE` and `OVLM_WORKER_IMAGE` in `.env` to the new tag now (keep the old
   values for §4.3): `make upgrade-preflight` runs the new image, and step 7 starts it. Pulled images: the new
   digests. (The development stack builds `:dev` and needs no `.env` change.)
2. Preflight with the worker still running (read-only):
   ```bash
   make upgrade-preflight
   ```
   Exit 2: stop here. `outage-in-progress` / `downtime-open`: wait until the window or restore ends (or the run is
   resolved), then start again at step 2. `database-ahead`: you are about to downgrade; don't.
3. Stop the worker (⚠️ no step, window or restore runs until step 7):
   ```bash
   docker compose stop worker
   ```
4. Preflight again, now requiring a stopped worker:
   ```bash
   make upgrade-preflight PREFLIGHT_ARGS=--worker-stopped
   ```
   - `outage-in-progress` / `downtime-open`: a window started between steps 2 and 3. **Start the worker again at once**
     (`docker compose start worker`) and retry after the window.
   - `worker-live`: wait 15 s (3 heartbeats) and repeat. Another worker host: stop it too.
   - `step-leased`: the drain did not finish; wait for the lease to expire (`worker.lease_duration`, 60 s) and repeat.
5. Back up (the api is still up, the worker is stopped, so nothing changes under the dump):
   ```bash
   make backup
   ```
   Check that the KEK and TOTP key for the manifest's `kek_id` are in the offline store (§1).
6. Stop the api: `docker compose stop api`.
7. Migrate and start the new release (⚠️ `migrate` changes the schema as `ovlm_owner`; api and worker refuse to start
   unless the schema is at head):
   ```bash
   docker compose up -d --wait
   ```
8. Verify:
   ```bash
   make smoke
   docker compose exec -T api ovlm backup check
   docker compose exec -T -u ovlm worker ovlm kek status
   make upgrade-preflight          # schema-at-head; the runs-active list of step 2 is back
   ```
   Then open the runs of step 2 and check that they move again (signals consumed, `requested` runs admitted).

### 4.3 Rollback

There is no downgrade. `alembic downgrade` is not part of any procedure: several revisions would drop append-only
evidence (`renewal_0003` drops every downtime interval, `renewal_0004` drops `step_acceptance` and the
`accept_step` signals; review PMR-10), and the preflight of an older release refuses a database migrated by a newer
one (`database-ahead`).

| Failure | Way back |
|---|---|
| `migrate` fails (step 7) | All pending migrations run in one transaction (PostgreSQL transactional DDL): the database is still at the old revision. Put the old image references back in `.env` (development stack: check out the old release, `make build`), `docker compose up -d --wait`. Report the migration error. |
| `make smoke` or the checks of step 8 fail, the worker has not run a renewal step yet | Restore: check out the old release and put its image references back in `.env` (development stack: `make build`), then `make restore DUMP=<the backup of step 5> CONFIRM=replace-ovlm-database` (§3). Nothing is lost: nothing changed since the backup. |
| A problem found after renewals ran on the new release | Prefer a fix forward. A restore loses every run step, approval and audit row since the upgrade (§2, rule 6) and puts runs back behind their OpenStack state; if you must, follow §3 in full, step 6 included. |

## 5. What is tested

`tests/integration/test_backup_restore.py` (real PostgreSQL, real `pg_dump`/`pg_restore`/`psql` of the server's major
version, §2 rule 7: from `OVLM_TEST_PG_BIN` (a directory), else `/usr/lib/postgresql/<major>/bin`, else `PATH` if its
tools have that major; any other version fails the test with the reason, it is never skipped):

- A database with active credentials sealed to a KEK, a TOTP-enrolled admin, audit rows and a closed downtime
  interval is dumped (`pg_dump -Fc`), restored with `create-database.sql` and `pg_restore --single-transaction`, and
  migrated to head. Then: the same KEK decrypts the write credential, another KEK does not; the audit rows are
  identical; every trigger, owner, table, column, function, schema and database privilege and `fencing_seq` are
  identical to the original; the append-only triggers on `audit_event` and `run_downtime` still refuse, even for
  the owner; `ovlm backup check` passes with the backup's keys and refuses another KEK or TOTP key; the api logs the
  same admin in with password and TOTP and serves the restored project connection; a role outside the three cannot
  connect.
- A dump taken at an older revision (`renewal_0003`) restores and migrates to head with exactly the triggers and
  privileges of a fresh install of this release.
- `ovlm upgrade preflight` refuses (exit 2) while a run is in phase `window` (running or `needs_human`) or `restore`,
  while a downtime interval is open, with `--worker-stopped` while a worker beats or a step holds a lease, and for a
  database migrated by a newer release; it passes once the window closed (with the `runs-active` warning).

Unit tests (`tests/unit/test_maintenance_unit.py`): the migration direction check against the real migration
scripts, and the CLI's exit codes. Not tested: the `make backup` / `make restore` / `make upgrade-preflight`
targets themselves (they need a running Compose stack), and an upgrade between two real releases.
