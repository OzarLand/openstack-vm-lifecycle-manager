# Security review — encrypted credential store and project connections

| Field | Value |
|---|---|
| Reviewer | Independent security review (separate session from the authors; `docs/team-log.md` not read) |
| Date | 2026-11-05 |
| Reviewed | `main` at `571ff01` (merge "encrypted credential store and project connections"): `docs/credential-store.md`, `src/ovlm/secrets/`, `src/ovlm/connections/`, the credential part of `src/ovlm/renewal/production.py`, `src/ovlm/config/settings.py` (`kek`, `credentials_dir`), `src/ovlm/worker/main.py`, `Makefile`, `compose.yaml`, `docker/worker-entrypoint.sh`, `migrations/versions/connections_0001.py`, `src/ovlm/auth/users.py` (SEC-C-8), the unit, integration and smoke tests of the change |
| Specification | security-model.md §4.4, §4.5, §5.1, §5.2; SEC-C-8 in `docs/reviews/security-review-code-wave3.md` |
| Method | Read every file above in full; ran the suites (section "Tests run"); wrote two proof-of-concept tests for the finding CS-1/CS-2 and ran them against PostgreSQL (kept out of the tree) |

## Verdict

**Accept with required changes.** The cryptography, the process separation (the api seals and cannot decrypt, the
private key only in the worker), the database grants, the upload path (TOTP step-up, typed confirmation, worker-side
validation) and the container hardening are built as designed and tested. One design gap is serious enough to block
the lab: the sealed secret is bound to its **row** but not to its **destination**. The worker will decrypt an
application credential and send it, as a Keystone token request, to whatever `auth_url` the cloud row names *now*,
and the cloud row can be changed by a plain admin session (no step-up) or by the `ovlm_api` database role. So the
promise of `docs/credential-store.md` §7, "a compromised api ... cannot read any [secret]", does not hold yet
(CS-1, CS-2, both demonstrated). The fix is small (AAD plus step-up on cloud changes) and must land before a real
credential is uploaded.

## Answers to the review questions

1. **Crypto.** Sound. AES-256-GCM with a fresh 32-byte DEK and a random 96-bit nonce per secret; every DEK encrypts
   exactly one message (a KEK re-wrap keeps the DEK and the ciphertext and never re-encrypts the data, so no nonce is
   reused). Key wrapping: ephemeral X25519, ECDH with the worker public key, HKDF-SHA256 (salt = ephemeral ‖ worker
   public key, info = `kek_id`), AES-256-GCM over the DEK with AAD `ovlm-wrap-v1|table|row|column|kek_id`; a
   re-wrap uses a fresh ephemeral key. The data AAD `ovlm-data-v1|credential_ref|<id>|secret` is derived from the
   referencing row, so a ciphertext moved to another row, column or table, or relabelled to another `kek_id`, does
   not authenticate (unit and integration tests, re-read). The one gap is what the AAD does *not* contain: the
   project connection, the kind and the cloud (CS-1, CS-2). Sealing is unauthenticated by design (anyone with the
   public key can seal); that is acceptable because the api may only insert *pending* rows and the worker validates.
2. **Can the api decrypt or leak?** No decryption path: the import-linter contract is kept, a unit test asserts that
   importing the api loads no key-ring module, settings refuse `kek.private_key_file` outside the worker,
   `load_keyring` refuses any other process role, and `ovlm_api` has no `SELECT` on `wrapped_dek`, `nonce`,
   `ciphertext` (integration test re-run). Responses carry `secret_set: true` only; 422 bodies carry field names,
   never values (`_field_errors`); the audit allowlist records `changed_fields: ["secret"]` and the key id; the
   canary tests hunt the secret in responses, audit rows, log lines and plain columns. **But** the api can make the
   worker *use* a secret against an endpoint of the api's choosing (CS-1, CS-2), which is a leak by proxy.
3. **Container hardening.** `DAC_READ_SEARCH` is really dropped before the worker runs: the launcher's `setpriv`
   sets the bounding set to `setuid,setgid,kill` only, with `--no-new-privs`, and the smoke script asserts
   `CapBnd`/`CapPrm`/`CapEff`/`CapAmb` of the worker. The copy is written by uid `ovlm` into a 0700 tmpfs; the
   original Docker secret stays mounted 0400 with the host owner, readable by neither `ovlm` nor `ovlm-ansible`
   (smoke check). No secret value in the environment (paths only), rootfs read-only. Two caveats: `init: true` keeps
   a root PID 1 that still holds `DAC_READ_SEARCH` (CS-6), and `docker compose exec worker` enters as root with the
   container's capabilities. `make smoke` could not be run here (no Docker daemon); this answer is from reading.
4. **Rotation and expiry.** KEK rotation: the worker holds current + previous keys, re-wraps in batches with a
   compare-and-set on the old key id, audited; previous keys never seal; tested. Expiry: refused at upload (past, or
   more than 180 days ahead), at validation and at use (`usable_row`); an expired active credential blocks new runs
   only, as §4.4 says. Gaps: the expiry is self-asserted, never read from Keystone (CS-3); nothing re-validates an
   active credential on its own, so a revoked or re-roled credential stays "valid" until an admin asks or a run
   fails (CS-4); an upload sealed to a key the worker does not hold yet is *rejected* instead of retried (CS-5).
5. **Upload path.** Admin, human session, TOTP step-up bound to `credential.upload` and the connection id, issued
   to the same session, single-use, consumed in the same transaction (replay answers 403/409), typed confirmation
   of the connection name, 202 + `pending`. Validation is worker-only, out of band, over a session carrying the
   read-only guard (one token request), TLS verified; the verdict is a pure function covering project scope, exact
   roles, the application credential id, `restricted`, and expiry. Audited on both sides. Correct.
6. **`renewal.credentials_dir`.** Still present, fenced twice: `Settings` refuse it unless `development_mode`, and
   `credential_source()` raises again. The Compose stack does not set it. Acceptable for now; remove it once the lab
   runs against the store (it is a plain-file path with no audit).

**SEC-C-8** is fixed: scopes are canonicalised to lower-case UUID on write and compared through `canonical_scope`
on both sides; a binding to a non-existent project connection answers 404 (integration tests re-run).

## Findings

Severity: High = secret disclosure or control bypass reachable by a role the design distrusts; Medium = a stated
control is weaker than specified; Low = hardening or operability.

| ID | Severity | Where | Attack scenario | Required change |
|---|---|---|---|---|
| CS-1 | **High** | `src/ovlm/connections/api.py:129-139` (PATCH cloud, no step-up), `src/ovlm/connections/service.py:166-202`, `src/ovlm/secrets/store.py:26-27` (AAD = row only), `src/ovlm/connections/validation.py:225-229` and `src/ovlm/renewal/production.py:292-311` (secret sent to `auth_url`) | An admin with a password-only session (or anyone holding an admin session cookie) patches the cloud's `auth_url` to `https://attacker.example/v3` (optionally with their own `ca_bundle_pem`), then calls `POST /api/v1/credentials/{id}/validate` (no step-up either) or simply waits for the next renewal. The worker decrypts the `os_write`/`os_read` secret and posts it in the token request to the attacker's server. Audit shows a `cloud.update` afterwards; the secret is already gone. **Demonstrated** (proof-of-concept test: the validator's checker received `("https://attacker.example/v3", <secret>)`). The `credential.manage` matrix row prescribes a typed confirmation that the cloud and connection routes do not enforce. | (a) Bind the secret to its owner and destination: derive the seal context from the referencing row **joined to its connection and cloud**, e.g. AAD `credential_ref|<id>|secret|<project_connection_id>|<kind>|<cloud_id>|sha256(auth_url)`; a changed URL then fails to decrypt (fail closed) and a legitimate Keystone URL change means re-uploading the credentials, which is the right cost. (b) `PATCH`/`DELETE /clouds/{id}` and changes to `guest_access` on a connection take the TOTP step-up and typed confirmation the matrix already prescribes. (c) Turn the proof of concept into a regression test. |
| CS-2 | **High** | `migrations/versions/connections_0001.py:137-143` (`ovlm_api`: INSERT/DELETE on `credential_ref`), `src/ovlm/secrets/store.py:26-27` | The `ovlm_api` role (a compromised api process, or its password) registers a cloud whose `auth_url` it controls, deletes the victim's `credential_ref` row and re-inserts it **with the same id** under the attacker's connection (the trigger allows a pending insert; `secret_id` is still unique). The AAD is `credential_ref|<same id>|secret`, so the worker decrypts and validates it against the attacker's URL. **Demonstrated** (second proof-of-concept test). | The AAD binding of CS-1(a) closes this (the re-inserted row has another connection and cloud). Defence in depth: a tombstone of deleted `credential_ref` ids that the insert trigger refuses to reuse, or let the worker perform deletions. |
| CS-3 | Medium | `src/ovlm/connections/service.py:470-499`, `src/ovlm/connections/validation.py:149-150` | `expires_at` is typed by the uploading admin. Keystone's real `expires_at` (which may be *null* = never) is never read, so the §4.4 rule "expiry mandatory, ≤ 180 days" is enforced on the form field, not on the credential. An admin uploads a never-expiring credential with a plausible date; OVLM later "expires" it on paper while it keeps working in Keystone. | During validation, after the token request, `GET /v3/users/{user_id}/application_credentials/{id}` over the same read-only session (one more GET; the owner may read its own application credentials under default policy); reject when Keystone's `expires_at` is null, later than the uploaded date, or the `roles` differ; store Keystone's value. Confirm the policy in the lab (data-model.md already notes "Keystone read only if confirmed"). |
| CS-4 | Medium | `src/ovlm/connections/validation.py:188-201` (`due()`) | Only credentials with a pending request are validated. A credential the cloud admin deleted, or whose roles were widened to `admin`, stays `active` and "valid" in OVLM until an admin asks for re-validation or a renewal fails at W1. The 30/7-day expiry warning of §4.4 exists only as a response field; no metric, no log line. | Periodic re-validation of active credentials (daily by default, configurable); a gauge/log for credentials expiring within 30/7 days and for the last validation failure per project. |
| CS-5 | Medium | `src/ovlm/connections/validation.py:210-213, 297-303`; `src/ovlm/secrets/keyring.py:96-100` | A secret wrapped to a key the worker does not hold (api switched to the new public key before the worker during a KEK rotation; a stale or swapped public key file) is a *verdict*: the pending credential becomes `rejected` and must be re-uploaded with a new step-up; an active one is marked invalid. Nothing enforces the "worker first" order of `docs/credential-store.md` §5. | Treat `UnknownKekError` as transient (`Verdict(None, …)`, retried). Have the worker publish the key ids it holds (a small `kek_key` table or the worker row); the api refuses to seal (503) to a key id the worker does not announce and reports it in `/readyz`. |
| CS-6 | Low | `compose.yaml:75-83`, `docker/worker-entrypoint.sh:17-29` | `init: true` makes `docker-init` PID 1, running as root with the container's capability set (`SETUID SETGID SETPCAP KILL DAC_READ_SEARCH`) for the container's life. The worker itself holds only three capabilities (smoke-tested), but "no root process remains" is not exact. `docker compose exec worker …` also enters as root with those capabilities. | Drop `init: true` and run an init *after* dropping privileges (`exec setpriv … -- tini -- "$@"`, or let the worker reap its runner trees), so nothing with `DAC_READ_SEARCH` survives the copy. Document `docker compose exec -u ovlm`. |
| CS-7 | Low | `src/ovlm/connections/validation.py:219-229` (vs `credentials.py:188`); `validation.py:203-213` | The validator hands the decrypted secret to keystoneauth without `register_secret()`, so the log redaction backstop does not know it during validation (the keystoneauth loggers are pinned to WARNING in production, so this is the backstop only). Credentials of a *disabled* connection are still decrypted and sent to Keystone. | `register_secret(secret)` before the checker call; skip (or postpone) validation when the connection is disabled. |
| CS-8 | Low | `src/ovlm/connections/api.py:311-312` | `_confirm(body.typed_confirmation, pc["name"] if pc else "")`: when the connection row is missing the expected confirmation is the empty string, which an empty `typed_confirmation` matches. Unreachable today (foreign key), but a fail-open default. | Answer 404 (or 500) when the connection is missing. |
| CS-9 | Low | `src/ovlm/secrets/cli.py:77`, `src/ovlm/secrets/store.py:55-67, 84-89`, `docs/credential-store.md` §5 step 4 | `ovlm kek status` exits 0 whenever every key in use is *held*, not when the old key shows 0 as the docs say. `kek_usage` counts orphan `sealed_secret` rows (a `credential_ref` deleted by a database actor leaves its sealed row; the api's own delete removes both), and `rows_wrapped_to_other_keys` joins `credential_ref`, so orphans are never re-wrapped and keep the old key id "in use" forever. | Exit non-zero while any non-current key still has secrets; a worker sweep that deletes orphan sealed rows (audited); align the doc wording. |
| CS-10 | Low | `src/ovlm/connections/api.py:49-66` | The api seals to whatever PEM is at `kek.public_key_file`; nothing ties it to a key the worker holds. A swapped file (host compromise of `./secrets`, a mix-up after rotation) silently produces secrets the worker cannot open — rejected (CS-5) — and that the swapper, with database read access, can. | Same announcement as CS-5: the api verifies its public key id against the worker's published ids at start and on `/readyz`. |

## Required before the lab

* **CS-1 and CS-2**: AAD bound to connection, kind, cloud and `auth_url`; step-up + typed confirmation on cloud and
  `guest_access` changes; regression tests (the two proofs of concept, adapted).
* **CS-3**: read the application credential's `expires_at` (and roles) from Keystone during validation, or record
  as a lab item that the policy forbids it and keep the self-asserted date as a documented residual.
* **CS-5**: `UnknownKekError` is transient, not a verdict (small change; the key-id announcement may follow later).

## Later

* CS-4 (periodic re-validation, expiry metrics), CS-6 (PID 1 without `DAC_READ_SEARCH`), CS-7, CS-8, CS-9, CS-10,
  and removal of `renewal.credentials_dir` once the lab runs on the store.
* `docs/credential-store.md` §7 must be amended until CS-1/CS-2 land: a compromised api *can* obtain application
  credential secrets by redirecting the worker.

## What was checked and holds

* `Sealed`, `AppCredential`, `WriteCredential`, `_Key` and `ConnectionInfo` keep secrets out of `repr`;
  `KeyringError`/`EnvelopeError`/`CredentialUnavailableError` messages carry no secret or ciphertext; the
  `InvalidTag` and wrong-row cases collapse to one message.
* Plaintext lives in a `bytearray` wiped in `finally`; the `str`/`bytes` copies a client library needs are the
  documented residual; the worker registers the write secret with the redaction backstop at use.
* Database: `ovlm_api` cannot read ciphertext, cannot update `state`, `validation_result`, `secret_id`,
  `project_connection_id` or `kind`, and may insert only pending rows (trigger, integration test); `ovlm_worker`
  cannot change `secret_id`, `project_connection_id`, `kind`, `app_credential_id` or `expires_at`. One active and one
  pending credential per (connection, kind) by partial unique index; the active switch takes `FOR UPDATE` on both
  rows and is audited as `credential.rotate` with `cloud_deletion_pending`.
* `auth_url` must be `https://` without credentials (API and CHECK constraint); `ca_bundle_pem` must parse as
  certificates and never contain `PRIVATE KEY`; the worker re-checks the bundle's SHA-256 before writing it.
* `ovlm kek generate` creates with `O_EXCL` and never overwrites; `make secrets` creates the private key 0400.
* The api's `public_kek` fails closed (503) without a public key or with an unreadable one.
* Admission rejects a renewal with the store's reason (no credential, expired, failed validation, disabled
  connection, key missing), so no run takes a lock it cannot use; `NoCredentialStore` rejects everything when the
  worker has no KEK.

## Tests run

| Suite | Command | Result |
|---|---|---|
| Credential store unit tests | `uv run --frozen --group automation pytest tests/unit/test_credential_store_crypto.py tests/unit/test_credential_validation_unit.py tests/unit/test_audit_unit.py` | 61 passed |
| Whole unit suite | `uv run --frozen --group automation pytest tests/unit` | 1179 passed, 1 skipped |
| Credential store, authz, SoD integration | `OVLM_TEST_DATABASE_URL=… pytest tests/integration/test_credential_store.py tests/integration/test_auth_authz.py tests/integration/test_sod_db.py` (local PostgreSQL 16.15) | 63 passed |
| Whole integration suite | `OVLM_TEST_DATABASE_URL=… pytest tests/integration` | 439 passed, 11 skipped (the skips need Docker, e.g. `test_automation_container.py`) |
| Import contracts | `uv run --frozen lint-imports` | 3 kept, 0 broken (incl. "the api cannot decrypt") |
| Proof of concept CS-1 / CS-2 | two tests on the `Store` fixture of `test_credential_store.py`, validator checker replaced by a spy | 2 passed = both attacks deliver the plaintext secret to the attacker URL |
| `make smoke` (container checks) | not run: no Docker daemon in the review environment | — (verified by reading `compose.yaml`, the entrypoint and `tests/smoke/*`) |
