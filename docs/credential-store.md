# Credential store

| Field | Value |
|---|---|
| Owner | Agent 4f — Backend Engineer |
| Status | **Implemented, unit and integration tested.** Not lab validated (no real Keystone in CI). |
| Last updated | 2026-11-05 |

Implements [security-model.md](security-model.md) §4.4 and §5.1 and the `cloud`, `project_connection` and
`credential_ref` tables of [data-model.md](data-model.md) §2. Code: `src/ovlm/secrets/` (cryptography),
`src/ovlm/connections/` (api side: `service`, `api`; worker side: `credentials`, `validation`), migration
`connections_0001`.

## 1. How it works

| Item | Implementation |
|---|---|
| Data key | 32 random bytes per secret, AES-256-GCM, 12-byte random nonce. AAD = `ovlm-data-v1|credential_ref|<credential id>|secret`. |
| Key wrapping | The data key is sealed to the **worker's X25519 public key**: ephemeral X25519 key, ECDH, HKDF-SHA256 (salt = both public keys), AES-256-GCM with AAD = `ovlm-wrap-v1|credential_ref|<credential id>|secret|<kek_id>`. Format `ovlm-env-v1`. |
| `kek_id` | First 16 hex characters of SHA-256 of the raw public key. Names the key pair; not secret. |
| api | Holds the **public key only** (`kek.public_key_file`). Seals, never decrypts: no decrypting code is importable (import-linter contract *the api cannot decrypt*, and a test that importing the api loads none of it); `load_keyring()` refuses any process role but `worker`; settings refuse `kek.private_key_file` outside the worker. |
| Database | `ovlm_api`: `INSERT`/`DELETE` on `sealed_secret` and `SELECT` on its metadata columns only (never `wrapped_dek`, `nonce`, `ciphertext`); it may only insert **pending, unvalidated** `credential_ref` rows (trigger) and update `validation_requested_at`. `ovlm_worker`: `SELECT` on all; `UPDATE` of wrap and validation/state columns. |
| Worker | Loads the private key file (mode 0400/0600, owned by the worker user, refused otherwise). Decrypts in memory only when a step or the validation job needs a credential; nothing is cached. |
| AAD context | Always derived from the **referencing** `credential_ref` row. A ciphertext copied into another credential's row does not decrypt (tested). |

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
5. The worker's `credential_validate` job (every `kek.validation_interval`, default 60 s) sends **one** Keystone
   token request (read-only guarded session, TLS verified) and checks: token scoped to the connection's project;
   roles exactly `reader` (`os_read`) or `member` with at most the implied `reader` (`os_write`); the token names
   the uploaded application credential; `restricted` is not false; not expired. Pass: `active`. Fail:
   `rejected` with the reason. Keystone unreachable: stays pending, retried.
6. A renewal is admitted only when the project has an **active, validated, unexpired** `os_write` and `ssh_key`;
   otherwise admission rejects it with the reason.

`POST /api/v1/credentials/{id}/validate` asks for a re-validation (e.g. after a role change in Keystone). An
active credential that fails it stays recorded but is refused for new runs.

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
4. Verify: `ovlm kek status` in the worker lists sealed secrets per key id; the old id must show `0` (exit code 0).
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
* Worker compromise = all secrets (by design, security-model.md §1.2). A compromised api can upload credentials
  (they still need the worker's validation against Keystone) but cannot read any.
* The CA bundle is stored in the database (not secret) and written by the worker to `<automation.run_root>/.ca/`,
  content-addressed and re-checked by SHA-256.
* `renewal.credentials_dir` (plain files) remains for **development only**: settings refuse it unless
  `development_mode` is on.
* Not implemented here: vault passwords and per-service secrets (`vault_password`, `secret` kinds exist in the
  schema only), worker-generated SSH keys (§6.1 says the worker generates the per-project key; here an admin
  uploads it), expiry warnings as metrics (the API reports `expiry_warning` at 30/7 days), wiring the read
  credential into a worker inventory-sync job (`connect_read_credential` exists and is unit-level only).
