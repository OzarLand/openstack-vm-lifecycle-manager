# Credential store

| Field | Value |
|---|---|
| Owner | Agent 4f — Backend Engineer; review fixes CS-1…CS-10 by the security-fix engineer |
| Status | **Implemented, unit and integration tested**, independent review ([review-credential-store.md](reviews/review-credential-store.md)) findings fixed except CS-6 (§8). Not lab validated (no real Keystone in CI). |
| Last updated | 2026-11-05 |

Implements [security-model.md](security-model.md) §4.4 and §5.1 and the `cloud`, `project_connection` and
`credential_ref` tables of [data-model.md](data-model.md) §2. Code: `src/ovlm/secrets/` (cryptography),
`src/ovlm/connections/` (api side: `service`, `api`; worker side: `credentials`, `validation`, `metrics`),
migrations `connections_0001` and `connections_0002` (review fixes).

**The rule the review added:** a secret is only ever sent to the endpoint it was uploaded and validated for. It is
cryptographically bound to its credential row, its project connection, its kind, its cloud and the cloud's endpoint
(`auth_url`, region, interface, CA bundle); the worker rebuilds that binding from the **live** rows before it
decrypts, so a changed endpoint or a moved row decrypts nothing.

## 1. How it works

| Item | Implementation |
|---|---|
| Data key | 32 random bytes per secret, AES-256-GCM, 12-byte random nonce. AAD = `ovlm-data-v2|credential_ref|<credential id>|secret|pc=<connection id>|kind=<kind>|cloud=<cloud id>|endpoint=<endpoint digest>`. |
| Endpoint digest | SHA-256 of canonical JSON `{auth_url, region, interface, ca_bundle_sha256}`: everything that decides where the secret goes (`ovlm.secrets.store.endpoint_digest`, same code in api and worker). |
| Key wrapping | The data key is sealed to the **worker's X25519 public key**: ephemeral X25519 key, ECDH, HKDF-SHA256 (salt = both public keys), AES-256-GCM with AAD = `ovlm-wrap-v2|<the same context as the data AAD>|<kek_id>`. Format `ovlm-env-v2`. The retired `ovlm-env-v1` (row only) is refused by the worker; `connections_0002` rejected every pending/active v1 credential with a "upload it again" reason. |
| `kek_id` | First 16 hex characters of SHA-256 of the raw public key. Names the key pair; not secret. |
| api | Holds the **public key only** (`kek.public_key_file`). Seals, never decrypts: no decrypting code is importable (import-linter contract *the api cannot decrypt*, and a test that importing the api loads none of it); `load_keyring()` refuses any process role but `worker`; settings refuse `kek.private_key_file` outside the worker. |
| Database | `ovlm_api`: `INSERT`/`DELETE` on `sealed_secret` and `SELECT` on its metadata columns only (never `wrapped_dek`, `nonce`, `ciphertext`); it may only insert **pending, unvalidated** `credential_ref` rows bound to the connection's current cloud (trigger) and update `validation_requested_at`; it cannot update `project_connection.cloud_id`/`openstack_project_id`. **No rebinding:** a trigger refuses any change of a binding column (id, connection, kind, secret, cloud, endpoint digest, Keystone id, uploaded expiry, SSH public key) by every role, and every deleted credential leaves a tombstone (`credential_ref_tombstone`, written by a `SECURITY DEFINER` trigger, read-only for both roles) whose id and secret id can never be inserted again. `ovlm_worker`: `SELECT` on all; `UPDATE` of wrap, validation/state columns and `verified_expires_at`; `DELETE` on `sealed_secret` (orphan sweep); writes `kek_key`. |
| Worker | Loads the private key file (mode 0400/0600, owned by the worker user, refused otherwise). Decrypts in memory only when a step or the validation job needs a credential; nothing is cached. |
| AAD context | The row id from the referencing `credential_ref` row; the binding from the **live** `project_connection` and `cloud` rows (worker). A credential whose stored destination differs from the live one is refused *before* decryption with a readable reason; one moved to another row, connection, cloud or endpoint does not authenticate (tested, including the two review proofs of concept). A KEK re-wrap uses the stored destination: it sends nothing and keeps the binding. |
| Worker keys announced | Each validation run (and the worker start) writes the key ids the worker holds to `kek_key`; the api seals only to an announced key id (`503 credential-store-key-unknown` otherwise). |

**Why `kek_id` is in the wrap AAD and not the data AAD.** security-model.md §5.1 lists `kek_id` in the AAD *and*
says KEK rotation re-wraps data keys while "secrets themselves [stay] unchanged". Both can only hold if `kek_id`
binds the wrapping. Reported as a reading of the design.

## 2. Keys in the Compose stack

* `make secrets` creates `secrets/worker_kek` (private, PEM PKCS#8, mode 0400 on the host) and
  `secrets/worker_kek.pub` with `openssl genpkey -algorithm X25519`. `ovlm kek generate` does the same in Python.
* **worker**: Docker secret `worker_kek`. Compose mounts file secrets as bind mounts with the host mode, so the
  0400 file is readable by no container user. The launcher (`docker/worker-entrypoint.sh`, root with
  `CAP_DAC_READ_SEARCH`) reads it once and writes it, as uid `ovlm`, to `/run/ovlm-kek/worker_kek` (tmpfs 0700,
  file 0600), then drops every capability but `SETUID/SETGID/KILL`. `ovlm-ansible` can read neither the original nor
  the copy (smoke check). `OVLM_KEK__PRIVATE_KEY_FILE=/run/ovlm-kek/worker_kek`.
* **api**: Docker secret `worker_kek_pub`, `OVLM_KEK__PUBLIC_KEY_FILE=/run/secrets/worker_kek_pub`.
* Never an environment value. Back the private key up offline (two custodians); DB backups hold ciphertext only.

## 3. Registering a project

1. Admin: `POST /api/v1/clouds` (`name`, `auth_url` **https only**, `region`, `interface`, optional
   `ca_bundle_pem`). TLS verification has no switch.
2. Admin: `POST /api/v1/project-connections` (`cloud_id`, `openstack_project_id`, `openstack_project_name`, `name`,
   `guest_access`). Project ids are normalised to lower-case 32-hex. Role bindings `project:<connection id>` are
   accepted only for existing connections and stored lower case (SEC-C-8).
3. The cloud admin creates, for a dedicated Keystone service user, two **restricted** application credentials
   (`reader`; `member`), `expires_at` at most 180 days ahead.
4. Admin, per credential: `POST /api/v1/session/reauth` with `action=credential.upload`,
   `target_id=<connection id>` (password + TOTP), then
   `POST /api/v1/project-connections/{id}/credentials` with `kind` (`os_read`, `os_write`, `ssh_key`),
   `app_credential_id`, `secret` (write-only), `expires_at`, `stepup_id`, `typed_confirmation` = connection name.
   The answer is `202` with `state: pending`. The guest SSH key (`ssh_key`) is an unencrypted OpenSSH private key;
   only its public key and fingerprint are shown.
5. The worker's `credential_validate` job (every `kek.validation_interval`, default 60 s) first checks, without
   decrypting, that the credential is bound to the connection's current endpoint. It then sends **one** Keystone
   token request and **one GET** of the application credential's own record
   (`/v3/users/{user}/application_credentials/{id}`), over a read-only guarded session, TLS verified, and checks:
   token scoped to the connection's project; roles exactly `reader` (`os_read`) or `member` with at most the
   implied `reader` (`os_write`); the token names the uploaded application credential; not unrestricted (token or
   record); the record's roles within the expected ones; **Keystone's `expires_at`** present (never-expiring is
   refused), at most 180 days ahead and not later than the uploaded date. Keystone's date is stored
   (`verified_expires_at`); the earlier of the two is enforced everywhere. Pass: `active`. Fail: `rejected` with the
   reason. Keystone unreachable, the connection disabled, or the secret wrapped to a key the worker does not hold:
   stays pending, retried (not a verdict).
6. A renewal is admitted only when the project has an **active, validated, unexpired** `os_write` and `ssh_key`;
   otherwise admission rejects it with the reason.

`POST /api/v1/credentials/{id}/validate` asks for a re-validation (e.g. after a role change in Keystone). Every
active credential is also re-validated on its own once its last validation is older than
`kek.revalidation_interval` (default 86400 s). An active credential that fails it stays recorded but is refused for
new runs.

Monitoring (worker metrics port): `ovlm_credentials_expiring{within="30d"|"7d"|"expired"}`,
`ovlm_credentials_failing_validation`, `ovlm_credentials_unknown_kek`; plus a `credential expiring` /
`credential expired` warning line once a day per credential (credential and connection ids, kind, date).

### Changing a cloud's endpoint or a connection's jump host

* `PATCH /api/v1/clouds/{id}` (every field of it is an endpoint field) and `DELETE /api/v1/clouds/{id}` take a
  step-up (`action=cloud.update` / `cloud.delete`, `target_id=<cloud id>`) and `typed_confirmation` = the cloud's
  name. A change of `auth_url`, region, interface or CA bundle sends every pending/active credential of the cloud
  back to validation (`validation.state: pending`, `endpoint_matches: false`, audited `credential.endpoint_changed`;
  the `cloud.update` row carries `stepup_id` and `invalidated_count`). The worker marks them invalid **without
  decrypting them**; renewals are refused at admission with the reason. The cloud admin's credentials are then
  uploaded again (they are validated against the new endpoint). This is deliberate: OVLM cannot tell an approved
  Keystone move from a compromised api rewriting the row, so a secret is never sent to an endpoint it was not
  uploaded for.
* `PATCH /api/v1/project-connections/{id}` with a changed `guest_access` takes a step-up
  (`project_connection.update`, the connection id) and the typed connection name. Name and `enabled` changes do not.

## 4. Rotating an application credential (security-model.md §4.4)

1. The cloud admin creates the new application credential in Keystone.
2. Upload it (step 4 above). The old one keeps working meanwhile.
3. When the worker validates the new one, it **switches atomically** in one transaction: new `active`, old
   `superseded` with `superseded_by` and `cloud_deletion_pending = true`. Audited as `credential.rotate`.
4. The cloud admin deletes the old application credential in Keystone. OVLM never creates or deletes Keystone
   credentials. Then an admin may delete the superseded row (`DELETE /api/v1/credentials/{id}`, step-up
   `credential.delete` + typed confirmation; refused for an active credential while a renewal of the project runs).

## 5. Rotating the KEK (security-model.md §5.1)

1. Generate a new pair: `ovlm kek generate --private-out secrets/worker_kek.new --public-out secrets/worker_kek.new.pub`.
2. **Worker first**: current key = new, previous = old
   (`OVLM_KEK__PRIVATE_KEY_FILE` → new, `OVLM_KEK__PREVIOUS_PRIVATE_KEY_FILES` → old). Restart the worker. It can now
   decrypt both, and its `kek_rewrap` job re-wraps every data key to the new key (ciphertext unchanged), audited as
   `kek.rewrap`.
3. **Then the api**: `OVLM_KEK__PUBLIC_KEY_FILE` → new public key. Restart. New uploads are sealed to the new key.
   (Doing the api first would seal secrets the worker cannot open until step 2.)
   **Enforced:** the api refuses to seal (`503 credential-store-key-unknown`) to a key id the worker has not
   announced (`kek_key`), and a secret the worker cannot unwrap is retried, not rejected.
4. Verify: `ovlm kek status` in the worker lists the sealed secrets **in use** per key id and the orphan count. Exit
   `0` only when every secret in use is wrapped to the current key; `3` while some are still wrapped to a previous
   key (re-wrap not finished: keep it); `2` while some are wrapped to a key the worker does not hold. Orphan sealed
   secrets (left by a database actor) are deleted by the validation job after 10 minutes, audited as
   `kek.orphans_deleted`. Secrets in the retired format `ovlm-env-v1` (credentials rejected by migration
   `connections_0002`) are never decrypted, so they are not counted per key and not re-wrapped: they do not keep the
   old key "in use" (review N-3). `kek status` prints their count; delete those credentials when convenient.
   Run it as the worker user: `docker compose exec -u ovlm worker ovlm kek status`.
5. Remove the old private key from the worker configuration and destroy it (and its offline backup) after the
   verified pass.

## 6. What never contains a secret

API responses (`secret_set: true` only), audit rows (`changed_fields: ["secret"]`, key id), log lines, error
messages (validation errors carry field names, never values), the `credential_ref` table. The canary tests in
`tests/integration/test_credential_store.py` hunt a known secret in every response, audit row, log line and
plain column.

## 7. Residual risks and limits

* **Python strings cannot be wiped.** Plaintext is held in a `bytearray` that is zeroed after use, but
  keystoneauth needs the application credential secret as `str` and the runner the SSH key as `bytes`; those
  immutable copies live until garbage collection, and the worker registers the secret with the log redaction
  backstop (a process-lifetime set). The api briefly holds the submitted secret as a Pydantic `SecretStr`.
* Worker compromise = all secrets (by design, security-model.md §1.2). A compromised api (or the `ovlm_api`
  database role) can upload credentials (they still need the worker's validation against Keystone) but cannot read
  any, **and can no longer make the worker send one elsewhere** (review CS-1/CS-2, fixed): rewriting a cloud's
  endpoint, moving a connection to another cloud, or deleting and re-inserting a credential under another connection
  yields secrets that do not decrypt. What it still can do is deny service: redirecting a cloud invalidates its
  credentials until they are uploaded again (the change is visible in `credential.validate` audit rows and the
  `ovlm_credentials_failing_validation` metric). A direct write of the `cloud` row, bypassing the API, raises the same
  signal at once: a statement trigger requests re-validation of the cloud's credentials (review N-4, `connections_0003`).
* The database owner role (migrations) can disable triggers; it is not used by any running process.
* Keystone's record of the application credential is read with the credential's own token (default policy: the
  owner may read its application credentials). If a cloud's policy forbids it, every validation fails with
  "Keystone did not show the application credential's record": to be confirmed in the lab.
* The CA bundle is stored in the database (not secret) and written by the worker to `<automation.run_root>/.ca/`,
  content-addressed and re-checked by SHA-256.
* `renewal.credentials_dir` (plain files) remains for **development only**: settings refuse it unless
  `development_mode` is on.
* Not implemented here: vault passwords and per-service secrets (`vault_password`, `secret` kinds exist in the
  schema only), worker-generated SSH keys (§6.1 says the worker generates the per-project key; here an admin
  uploads it), wiring the read credential into a worker inventory-sync job (`connect_read_credential` exists and is
  unit-level only), reporting a public-key mismatch in the api's `/readyz` (the api refuses at upload instead).

## 8. Review findings (2026-11-05)

| ID | Fix | Tests |
|---|---|---|
| CS-1 | Destination (connection, kind, cloud, endpoint digest) in the AAD, rebuilt from live rows; step-up + typed confirmation on cloud PATCH/DELETE and `guest_access`; endpoint change invalidates the cloud's credentials, audited. | `tests/integration/test_credential_binding.py::test_cs1_*`, unit `test_cs1_cs2_ciphertext_is_bound_to_connection_kind_cloud_and_endpoint` |
| CS-2 | Same AAD; binding columns immutable (trigger), tombstones refuse re-insertion of a deleted id or secret, api insert must name the connection's cloud, api cannot update `project_connection.cloud_id`. | `test_cs2_*` (integration) |
| CS-3 | Keystone's application credential record read at validation; null, > 180 days or later than uploaded refused; stored and enforced. | unit `test_cs3_*`, integration `test_cs3_keystone_expiry_is_stored_and_enforced` |
| CS-4 | Daily re-validation of active credentials (`kek.revalidation_interval`); expiry/failing metrics and daily log line. | `test_cs4_active_credentials_are_revalidated_and_expiry_is_reported` |
| CS-5, CS-10 | `UnknownKekError` transient; worker announces held key ids; api seals only to announced ids. | `test_cs5_unknown_key_is_transient_and_the_api_seals_only_to_announced_keys` |
| CS-6 | **Not fixed here** (`compose.yaml`, `docker/worker-entrypoint.sh` are outside this change; needs `make smoke`). | — |
| CS-7 | Secret registered with the redaction backstop before the Keystone call; disabled connections not validated. | `test_cs7_disabled_connection_is_neither_decrypted_nor_sent` |
| CS-8 | Missing connection answers 404; an empty expected confirmation never matches. | unit `test_cs8_typed_confirmation_never_matches_an_empty_expected_name` |
| CS-9 | `kek status` exit codes; usage counts referenced secrets only; orphan sweep, audited. | unit `test_cs9_kek_status_*`, integration `test_cs9_orphan_sealed_secrets_are_swept_and_audited` |
