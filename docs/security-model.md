# Security model

| Field | Value |
|---|---|
| Owner | Agent 8 — Security Engineer |
| Status | **Designed** (Phase 1 proposal, nothing implemented) |
| Last updated | 2026-11-05 |

Scope: `api`, `worker`, PostgreSQL, Ansible, OVLM's OpenStack credentials, managed guests. Inputs: [functional-requirements.md](functional-requirements.md) (NFR-4/5, FR-REN-6,
FR-AUD, FR-UI-2), [openstack-integration.md](openstack-integration.md) (Agent 3, "OSI" below; its tags SV =
SOURCE-VERIFIED, DU = DOCUMENTED-UNVERIFIED, AS = ASSUMPTION are kept), [automation-contract.md](automation-contract.md)
§5. Statements tagged **ASSUMPTION** here are mine and unverified. Every control below is PROPOSED-UNVERIFIED.

> **Revision 2026-11-04**: synced to the architecture revision. Addressed: SEC-R-1 (T7 residual, §8, §9, §10 item 14), SEC-R-2
> (§3.2, §10), SEC-R-3 (§5.2, §6.4, §10), SEC-R-6, SEC-R-8, SEC-R-25, SEC-R-33 (§7.1), SEC-R-7, SEC-R-23, SEC-R-24 (§4.3,
> §10), SEC-R-21 (§8 audit mirror).
>
> **Revision 2026-11-04 (round 2)**: synced to architecture round 2 (M9, ADR-0006). TOTP mandatory for approver/admin, single-use
> action-bound step-up, enrolment links (§2); self-approval setting and solo installations (§3.2); out-of-band credential rotation
> (§4.4); bootstrap host key exception (§5.2) and host-key default `injected` (§6.2); tests added (§10 items 24-27).
>
> **Revision 2026-11-04 (image/docs alignment)**: §6.1 records an open item for the security review (cloud-init user
> `sudo NOPASSWD` for the B5 host-key rotation).
>
> **Revision 2026-11-05 (inventory sync / host-key review fixes)**: blue's host-key trust is enforced in the database and
> re-checked by the worker (§6.2.1, review IS-1); one SSH address rule for the scan and the renewal (§6.2.1, IS-3);
> viewers see reason codes for failed syncs, never exception text (§4.1, IS-4, IS-8); acceptance criteria 28-31 (§10).

## 1. Threat model

### 1.1 Assets

| Asset | Where | Impact if lost |
|---|---|---|
| OpenStack credentials (read, write) | DB, encrypted (§5) | Write: any `member` action on every resource of the project, not only OVLM's (OSI §8, SV). Read: full project inventory disclosure. |
| SSH private key to guests | DB, encrypted; run dir 0600 during a run | Root-equivalent on every managed guest of the project. |
| Ansible vault passwords / app secrets | DB, encrypted; run dir during a run | Workload secrets (DB passwords, TLS keys). |
| Workload data volumes | Cinder | Business data; corruption by double mount or deletion by `delete_on_termination` (OSI §4, §5, SV). |
| Audit log | DB, append-only table | Loss of accountability, hides abuse. |
| OVLM DB (state, approvals, master-key-wrapped secrets) | PostgreSQL | Forged approvals or plans; ciphertext of all secrets. |
| Master key (KEK) | File mounted into the worker only (§5) | With a DB dump: every secret in clear. |

### 1.2 Actors and trust

| Actor | Trust | Notes |
|---|---|---|
| Viewer / operator / approver / admin | Authenticated, trusted for their role only | Bound by RBAC and separation of duties (§3). |
| Malicious insider (OVLM user) | Partially trusted | Can request, cannot approve alone; cannot read secrets back. |
| OpenStack project member (non-OVLM human) | Outside OVLM | Can edit or remove `ovlm:*` tags and metadata (OSI §2, SV); can unlock a member lock (OSI §7, SV). |
| Compromised OVLM host / container | Untrusted | Worker compromise = all secrets; api compromise must not be (§5.1). |
| Compromised guest VM | **Untrusted** | Everything coming back from a guest is attacker-controlled data. |
| Automation repo content | Trusted only at a pinned, approved commit SHA | Ansible content is code that runs on the worker host (`delegate_to: localhost`, plugins, `ansible.cfg`). |
| AI agents / scripts using the API | Non-human principals | May request and read; never approve (§7.2). |

### 1.3 Top threats (STRIDE)

| # | STRIDE | Threat | Mitigation (section) |
|---|---|---|---|
| T1 | S | Stolen session or API token used to approve a renewal | Approvals need an interactive human session with fresh re-auth; tokens cannot approve (§2, §7.2). |
| T2 | E | Insider requests and approves own destructive run | Requester ≠ approver, two-person rule on retirement (§3.2). |
| T3 | E | Read credential is not actually read-only: with `enforce_new_defaults=False`, legacy rules like Nova `is_admin:True or project_id:%(project_id)s` may let any project role write (OSI policy baseline: SV for the rule, AS for activation) | Client-side GET/HEAD-only guard on the inventory session; GET-only access rules where enforceable; cloud admin attests `enforce_new_defaults` (§4.1). |
| T4 | T/E | OVLM mutates a foreign VM (bug, mis-registration, or a member who adds `ovlm:managed` to another server) | Ownership guard checks the OVLM DB **and** the tag before every mutating call; tags alone are never trusted (§4.3). |
| T5 | I | Secrets leak into logs, audit diffs, errors, extra-vars, UI | Secrets never enter those paths by design; redaction only as backstop (§5.2). |
| T6 | I/E | DB dump or backup stolen | Envelope encryption; KEK not in DB, not in api, not in env (§5). |
| T7 | E | api process (internet-facing) compromised → OpenStack credentials | api never calls OpenStack and cannot decrypt: it only seals to the worker's public key (§5.1). The DB role split (§9) stops the api from changing run and step state, and the worker re-validates approval evidence before every destructive step (renewal-workflow.md §3.1). **Residual risk**: a compromised api that consistently forges approvals, step-up records and role bindings could still pass the worker's re-validation; closing it needs approvals signed with a key the api does not hold (planned for V1). The audit log-stream mirror (§8) makes such forgeries visible afterwards. |
| T8 | T | Compromised guest returns crafted healthcheck JSON or Ansible facts (fake "healthy", XSS payload, huge output, prompt-injection text) | Guest output is untrusted data: size cap, strict schema, no eval/templating, autoescaped UI, never used as authorization; cutover health also probed from outside the guest (§6.4). |
| T9 | T/E | Automation repo changed (force-push, compromised maintainer) → code execution on the worker | Repo allowlist, commit SHA pinned in profile and bound into approval hash; Ansible runs as a separate OS user with a scrubbed env and no read access to KEK or DB secrets (§6.5). |
| T10 | S | MITM on first SSH to a freshly built VM | Host-key fingerprint read from the console log; TOFU only as a per-profile opt-in (§6.2). |
| T11 | R | Actor denies an approval or a manual action | Append-only audit with actor, principal type, auth method; V1 hash chain with external anchor (§8). |
| T13 | T | Approved plan altered after approval (profile, SHA, target VM) | Approval binds a hash of the plan, profile version, automation SHA and target IDs; any change voids it (§7.1). |
| T14 | E | CSRF via HTMX form triggers an action | Synchronizer token + Origin check + SameSite cookies (§2.3). |
| T15 | T | Supply-chain compromise of a Python dependency or base image | Hash-pinned lock file, digest-pinned image, CI scanning (§9). |

## 2. Authentication

### 2.1 Users
- MVP: local users. Passwords hashed with **argon2id** (`argon2-cffi`), parameters at least m=64 MiB, t=3, p=4
  (RFC 9106 second recommendation), re-hash on login when parameters rise. Minimum length 12, checked against a
  breached-password list shipped offline (ASSUMPTION: a list such as the top 100k is acceptable licence-wise).
- Login: generic error (no enumeration), per-account and per-IP rate limit with backoff; no hard lockout (DoS on
  approvers). Bootstrap admin via CLI one-time password, forced change; no default credentials anywhere.
- **Enrolment links; admins never set passwords** (SEC-R-11). Creating a user or resetting a password returns a one-time
  enrolment link; the admin never chooses or sees the password. First login forces the user to set one and, for
  `approver`/`admin`, to enrol TOTP in their own session. The account records who created it and who last reset its credential.
- **TOTP second factor is mandatory for `approver` and `admin`** (M9, SEC-R-10). Later: OIDC (authorization code + PKCE); role
  mapping from IdP groups is optional, local role bindings stay the source of truth.

### 2.2 API tokens
| Property | Rule |
|---|---|
| Format | `ovlm_<id>_<32 random bytes, base32>`; shown once at creation. |
| Storage | SHA-256 of the secret part (high-entropy, so a fast hash is fine); id, owner, scopes, expiry, last use stored. |
| Scope | Subset of the owner's role bindings (role and project); never more. Scopes: `read`, `inventory:sync`, `operate`. |
| Expiry | Mandatory, max 90 days; admin can revoke any token; tokens die with the user. |
| Limits | **No token can approve, confirm a destructive action, manage users, credentials or keys** (§7.2). Audit records `principal_type=token`. |

### 2.3 Sessions and browser
- Server-side session table; cookie `__Host-ovlm_session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. New
  session id at login and on privilege change. Idle timeout 30 min, absolute 12 h; logout deletes the row.
- **Step-up re-auth (TOTP)**: approvals and destructive confirmations require a TOTP step-up. A step-up is **single-use**,
  valid **5 minutes**, and **bound to one action type and one target** (and the session); it is consumed by exactly that
  approval or confirmation and cannot be replayed for another action or target (SEC-R-10, M9).
- CSRF: per-session synchronizer token, sent by HTMX via `hx-headers` (`X-CSRF-Token`) and in form fields; every
  unsafe method checks the token **and** the `Origin`/`Referer` against the configured external URL. Bearer-token API
  calls carry no cookie and are exempt.
- Headers: strict CSP (`default-src 'self'`, no inline script; HTMX served from OVLM), `X-Frame-Options: DENY`
  (or `frame-ancestors 'none'`), `Referrer-Policy: same-origin`, HSTS by the TLS proxy. Jinja2 autoescape everywhere.

## 3. Authorization

### 3.1 RBAC matrix
`viewer ⊂ operator`. `approver` = viewer + approvals. `admin` = configuration; it does **not** inherit `approver` or
`operator` (admins assign roles; an admin cannot change their own bindings unless they are the only admin, audited).
Typed confirmation (TC) = FR-UI-2. ✓ = allowed, — = denied.

| FR family | Action | viewer | operator | approver | admin |
|---|---|---|---|---|---|
| FR-INV | View inventory, VM details | ✓ | ✓ | ✓ | ✓ |
| FR-INV | Trigger sync | — | ✓ | — | ✓ |
| FR-REG | Register / unregister VM, create service | — | ✓ | — | — |
| FR-REG | Confirm a managed VM's scanned SSH host-key fingerprint (ADR-0006; human session) | — | ✓ | — | — |
| FR-REG | Create/edit profile (incl. automation ref + SHA, health check) | — | ✓ | — | — |
| FR-REG | Manage automation repo allowlist | — | — | — | ✓ |
| FR-POL | Create/edit policy (incl. approval rules, SoD, retention) | — | — | — | ✓ |
| FR-POL | Grant exception (V1) | — | request | ✓ (≠ requester) | — |
| FR-RDY | Run assessment | — | ✓ | — | — |
| FR-RDY | Human attestation (V1) | — | ✓ | ✓ | — |
| FR-PLN | Create plan / request approval | — | ✓ | — | — |
| FR-PLN, FR-REN-4 | Approve plan, cutover, retirement | — | — | ✓ (≠ requester, human session) | — |
| FR-REN | Start approved run, resume, abort into rollback | — | ✓ | — | — |
| FR-REN | Revert after cutover (FIP back) | — | ✓ + TC | — | — |
| FR-REN | Mark manual recovery done, continue | — | ✓ + TC; approver if next step is destructive | ✓ | — |
| FR-AUD | View audit (own project scope) | ✓ | ✓ | ✓ | ✓ |
| FR-AUD | Export audit (V1) | — | — | — | ✓ |
| Credentials | Create/rotate/delete OpenStack credential, SSH key, vault secret | — | — | — | ✓ + TC |
| Users | Manage users, role bindings, revoke tokens | — | — | — | ✓ |
| Tokens | Create own API token (≤ own scope, §2.2) | ✓ | ✓ | ✓ | ✓ |

### 3.2 Separation of duties
- **Requester set, per gate**: the profile version author, the plan creator, the run starter, the policy editor (last
  editor of the policy version in effect) and the requester of the approval. None of them may approve that gate. The
  worker recomputes the set and checks it (renewal-workflow.md §3.1); the API enforces it too, not the UI.
- Default: one person cannot hold `operator` and `approver` in the same scope. An admin may allow it **per installation**
  (setting `auth.allow_operator_approver`, default false, TOTP step-up + typed confirmation, history kept); the change is
  audited. When on, a requester-set member may approve G1 and G2, and each such approval is flagged **`self_approved`** on
  the approval, the run and every page showing it.
- **G3 (retirement) never allows self-approval**, whatever the setting. A solo installation needs a **second human account**
  with `approver`, created by an admin through an enrolment link (§2.1; the user self-enrols password and TOTP). The G3
  approval page shows the account's origin ("created by X on D; last credential reset by Y on D"). One person holding both
  accounts defeats the rule; OVLM cannot prevent it and records the origin so an auditor can see it. Without a second
  account the old VM stays stopped and locked.
- Policy flag `require_distinct_approvers` (default **on** for retirement, off for plan/cutover): plan approver and
  retirement approver must be different people from each other and from the requester (two-person rule).
- NFR-4 says SoD is "configurable". Decision: an admin may relax it **only for plan and cutover gates**, per policy;
  the relaxation is audited and shown on every affected run. Retirement (irreversible delete) never allows
  self-approval. Single-person installs must add a second approver account to retire VMs.
- The OVLM system principal never approves. A gate set to "no approval" by policy is an admin decision, recorded.

### 3.3 Project scoping — recommended for MVP
Role bindings are `(user, role, scope)` with `scope = global | project:<id>`. MVP enforces scope on every query and
action, even with one project (cheap now, a breaking retrofit later); the UI for scoped bindings may be minimal.
Listing endpoints filter by scope; a resource outside scope returns 404, not 403 (no existence leak).

## 4. OpenStack credentials

### 4.1 Read credential (`ovlm-inventory`, role `reader`)
Used for FR-INV and FR-RDY. Works for servers, attachments, volumes, ports, networks, SGs, FIPs, images, Nova/Cinder
quota and limits (OSI §1, SV). It **cannot** see:

| Not visible to `reader` | Source (OSI) | Consequence for OVLM |
|---|---|---|
| Neutron quota (`get_quota` = manager) | §1, SV | Port/FIP headroom in FR-PLN-2 is derived (count ports vs assumed defaults, AS) — advisory only. |
| Host, hypervisor hostname, instance name, `user_data`, `root_device_name` | §1 "What a non-admin does not see", SV | Cannot detect "blue's compute host is down" before detach fails; cannot read blue's cloud-init → reproducibility check stays `unknown`. |
| `host_status`, instance-action **events** (list/show allowed) | §1, SV | Root causes of failed detach/attach are opaque; OVLM reports, operator escalates. |
| Hypervisor and Placement capacity | §1, §7, SV | `NoValidHost` is a normal failure with cleanup. |
| All-tenant and deleted listings | §1, SV | One credential per project (FR-INV-5). |

Decision: do **not** add `manager` to obtain Neutron quota (manager also allows chosen-address FIPs, migrate, MAC
update — OSI §8, §9, SV). A separate quota credential is a Later option.

Read-only is not guaranteed by the role alone (T3). Controls: (1) the inventory SDK session gets a keystoneauth/
requests hook that raises before sending any method other than GET/HEAD — cheap and cloud-independent; (2) GET-only
access rules (§4.4); (3) onboarding checklist asks the cloud admin to state `enforce_new_defaults` (OSI open question 1).

**What a failed sync shows** (review IS-4, IS-8). SDK and keystoneauth messages carry the Keystone URL, HTTP status
lines and response fragments; log redaction removes registered secrets, not those. Viewers therefore see a **fixed
reason code** only: `sync_run.error` is `{"code": ...}` and a run's `end_reason` is the code (`credential_unavailable`,
`client_setup_failed`, `auth_failed`, `project_mismatch`, `cloud_error`, `interrupted`, `sync_already_running`,
`worker_error`; `src/ovlm/inventory/reasons.py`). The redacted text goes to the worker log and to the step error's
`detail` (`workflow_step.error`, not served by the api). Records written before the codes are mapped when read. A read
client that cannot be built from a valid credential (a bad CA file, a configuration error) is a recorded
`client_setup_failed`, not an endless retry; a database error while reading the credential stays retryable.

### 4.2 Write credential (`ovlm-renewal`, role `member`, one project)
Used **only by the worker**, only inside a renewal step whose gate is approved (FR-REN-6).

| Needed operation | Role | OSI ref |
|---|---|---|
| Server create (image, tags at create mv≥2.52, port, SG, server group), stop, start, delete | member | §7, §2, SV |
| Lock / unlock own lock (`locked_by=owner`) | member | §7, SV |
| Volume attach/detach via Nova; fix `delete_on_termination` (mv≥2.85) | member | §4, SV |
| FIP re-association (existing FIP) | member | §6.1, SV |
| Port create on project-owned networks; tags/metadata on server, port, volume | member | §2, §8, SV |
| Cinder snapshot before handoff (optional) | member | §4, SV |

Cannot do (→ **stop, report, escalate to a named human OpenStack admin** with the run's evidence; OVLM never retries
with other credentials and never stores admin credentials):

| Not possible as member | OSI ref | Typical trigger |
|---|---|---|
| Cinder `os-force_detach`, `os-reset_status`, `os-force_delete` | §4, §8, SV | Volume stuck `detaching`/`reserved`/`attaching` |
| Unlock an admin-set lock (`unlock_override`) | §7, §9, SV | Blue locked by cloud staff; revert impossible |
| Detach when compute host is down; evacuate; `reset_state` | §4, §9, SV | Blue host failure mid-renewal |
| Delete `compute:*` ports; MAC set on update; FIP with chosen address | §8, §9, SV | Fixed-IP/MAC preservation (out of MVP) |

Blast radius is the **whole project** (member can delete any server in it): recommend a dedicated project for managed VMs.

### 4.3 Ownership guard
Before every mutating call the worker checks, in this order, and stops with `ownership_violation` on any mismatch:
1. The target ID is recorded in the OVLM DB for this run: a registered managed VM (blue), a data volume ID from the
   approved profile version, the FIP recorded at plan time, or a resource created by this run.
2. The OpenStack resource currently carries `ovlm:managed` (and `ovlm:run:<id>` for created ones). Tags are markers
   any member can edit (OSI §2, SV), so (2) never suffices alone; it catches DB/cloud divergence. Rule 2 gives no
   authority over pre-existing resources: a marker on a resource that rule 1 does not list never allows a call.
3. For delete: target was **created by OVLM** (green on rollback) or is the approved retirement target; attachment
   `delete_on_termination == false` on every data volume (OSI §4, SV) re-read immediately before the call.

**Write allowlist.** The worker's `WriteClient` checks a (method, path-pattern) allowlist limited to the strategy's
operations (the table in §4.2) and the fence gate before sending any request; anything else raises before it is sent.
Explicitly refused: `DELETE …/volumes/*`, `POST` and `DELETE …/floatingips*`, any `security-groups*` write and
`POST …/volumes` (architecture.md §3, SEC-R-7). **OVLM never deletes a volume or a floating IP** and never allocates one.
The ownership guard and the allowlist are independent: a call must pass both.

### 4.4 Application credentials and access rules
- Use Keystone **application credentials**, one per project and purpose, owned by a dedicated Keystone service user
  created by the cloud admin (not a human's account). `unrestricted` must be false (then it cannot create other app
  credentials or trusts — OSI §8, SV); roles limited to `reader` or `member` (subset of user roles, one project, SV);
  `expires_at` mandatory, ≤ 180 days. OVLM rejects a credential whose token shows other roles (it checks the token's
  role list at validation; ASSUMPTION: the SDK exposes it via `get_access()`).
- Rotation (admin, audited) is **out of band**: the cloud admin creates the new app credential in Keystone; OVLM only
  validates it (worker, read-only) and switches atomically, then **marks the old credential for deletion by the cloud
  admin**. OVLM never deletes or creates Keystone credentials itself. OVLM warns at 30/7 days before expiry; an expired write credential blocks new runs only.
- Access rules, stance: **read credential: recommended** (`GET` on `compute`, `block-storage`, `network`, `image`
  with `/**`); failure mode is fail-closed (token rejected, OSI §8, SV), so inventory breaks loudly, never silently.
  **Write credential: not in MVP.** Rules cannot restrict by resource (IDs change per run), need downstream paths
  when Nova sends no service token (OSI §8, SV/AS), and a fail-closed rejection mid-handoff is worse than the extra
  privilege. Revisit in V1 with a lab-validated rule set (OSI rec. 8, open question 7).

### 4.5 Logging of OpenStack traffic
openstacksdk/keystoneauth debug logging is off in production and cannot be enabled by config alone (needs an env
flag plus a startup banner). Never log the `clouds` dict, auth dicts, tokens, catalog bodies or `X-Auth-Token`/
`X-Subject-Token` headers; a logging filter strips them (backstop). SDK exception text is logged after redaction.
TLS verification to OpenStack is always on; a custom CA bundle is configurable; `insecure` is refused.

## 5. Secrets management

### 5.1 MVP: encrypted columns with envelope encryption
| Item | Design |
|---|---|
| Secrets stored | OpenStack app credential secret, SSH private keys, vault passwords, other per-profile secrets. Public keys and fingerprints are not secret. |
| Data key | Random 256-bit DEK per secret; AES-256-GCM; AAD = `table|row_id|column|kek_id` (ciphertext cannot be swapped between rows). |
| Key wrapping | DEK wrapped with the **worker key pair** (X25519 sealed box or RSA-OAEP-3072). Public key in the DB/api config; private key (the KEK) in a file. |
| KEK location | Docker secret / file mode 0400 owned by the worker user, mounted **only into the worker** container. Never an env var (leaks via `/proc`, `docker inspect`, child processes). |
| Write path | Admin submits secret over TLS → api seals it with the public key → stores ciphertext. api cannot decrypt. |
| Read path | Worker unwraps in memory for one step; never written to disk except the run-dir files of automation-contract §5. |
| Rotation (KEK) | Admin adds new key pair with new `kek_id` → worker job re-wraps all DEKs (secrets themselves unchanged) → old private key removed after a verified pass. Audited. Secret rotation (e.g. app credential) is separate (§4.4). |
| Backup | DB backups contain ciphertext only; the KEK is backed up separately (offline, two custodians). Restore test must cover both (NFR-7). |

Later: Vault or Barbican behind a pluggable `SecretStore` (get/put/rotate by reference), designed now.
**Process separation.** api: no KEK, no OpenStack calls (on-demand sync and "test credential" are worker jobs). worker: KEK, outbound to
OpenStack and guests, no inbound port. This differs from the brief's assumption that the read credential is used by
api and worker — see the hand-off note.

### 5.2 Where secrets must never appear
UI and API responses (write-only fields; show "set, last rotated <date>"), logs, audit before/after (secret fields are
**excluded by allowlist** from diffs; only "changed: true" and the key id are recorded — FR-AUD-1), error messages,
Ansible command line / `-e` / inventory vars (automation-contract §5), Nova metadata or user_data (exposed to the guest;
OSI §2, AS), exception tracebacks shown to users, Prometheus labels. Redaction of known values and patterns in logs is
the backstop (automation-contract §5), tested (§10).

**Exception: bootstrap host key in user-data (ADR-0006).** The one private key allowed in cloud-init user-data is the
per-run **bootstrap SSH host key** of the new VM (`ssh_keys` section; ASSUMPTION, lab item). What it is: an ed25519 host
key OVLM generates in memory in B3; OVLM stores only its public key and fingerprint, never the private part. Why it is
acceptable: it is short-lived and trusted only until B5, where OVLM, over the session authenticated against it and before
any `configure` or secret is sent, regenerates green's host keys, pins the new public keys in the per-run `known_hosts`,
reconnects and verifies; sshd then no longer accepts the bootstrap key, so its later exposure in user-data cannot be used
to impersonate the rotated key. It is never an authentication credential for logins. Residual risk: whoever can read green's
user-data during the build phase (cloud admins; project members if the cloud exposes user-data to them, ASSUMPTION) and can
also intercept the guest-access path can impersonate green until rotation and receive the `configure` run. They cannot
obtain the data volume (OpenStack attaches it to the real green, verified by W6 UUID and marker checks). No other secret
may be placed in user-data.

**Automation artefacts may contain workload secrets.** ansible-runner events, stdout and diffs show what playbooks
template onto the guest, including vault-decrypted values that OVLM never knows in clear and so cannot redact. They are
restricted artefacts: readable by operator/admin in scope only (viewers see the validated result JSON and per-task
status), kept under their own retention (`automation.artifact_retention`, separate from audit) and never exported.
Diffs are stored only when the profile opts in (`store_diffs`, default off); otherwise OVLM keeps only per-task
changed/unchanged.

## 6. Guest access

### 6.1 SSH keys for Ansible
- One ed25519 key pair per project, generated by the worker; private part encrypted (§5). Rotation: playbook adds new
  public key, verifies login, removes old; then old private key destroyed. Audited.
- Injection into **new** VMs: cloud-init user_data `ssh_authorized_keys` for a dedicated `ovlm` user (public key only;
  user_data is fine for non-secrets). Preferred over a Nova keypair because keypairs are user-owned and must exist at
  create (OSI §9, SV for name resolution; ownership ASSUMPTION). A Nova keypair is an accepted fallback per profile.
- **Existing (blue) VMs**: the workload owner installs the public key; FR-RDY check "OVLM can SSH" is a blocker.
- **Open item for the security review (not decided here):** the B5 host-key rotation (§6.2, ADR-0006) replaces the
  guest's SSH host keys, which needs root. The cloud-init `ovlm` user on a new VM therefore gets `sudo NOPASSWD`
  (the reference CI target does the same). That makes a compromise of the `ovlm` key a root compromise of the guest.
  The review must decide whether to accept it, to limit it (a sudoers rule for the rotation command only), or to
  rotate the keys another way. Until then, treat the grant as accepted-pending-review.

### 6.2 Host-key verification for freshly built VMs
| Option | Risk | Verdict |
|---|---|---|
| Disable checking | Any MITM gets the key session and the vault-decrypted secrets | Forbidden |
| TOFU, record fingerprint at first connect | MITM in the first-connect window on the tenant network goes undetected | Opt-in per profile only, audited as accepted risk |
| Fingerprints from console log (cloud-init prints host key fingerprints to the serial console; read via `os-getConsoleOutput` with the write credential) | Image must log to console; **lab-observed unreliable**: worked in EXP-01, empty for 14 min in EXP-01b (Felcloud); a pre-compromised image could print fake lines | Secondary source (`host_key_policy=console`) |
| Pre-generated **bootstrap** host key injected via user_data, rotated at B5 (ADR-0006) | Private bootstrap key is exposed in Nova user-data until rotation (§5.2 exception) | **Default** (`injected`) |

Decision (ADR-0006): the injected bootstrap key is the default (`profile.guest_access.host_key_policy = injected | console |
tofu`). The console log is a secondary source, selectable per profile where it is reliable. TOFU is an **audited per-profile
opt-in** (a new profile version, hence re-approval). If no key can be verified before the deadline the step fails with
"host key unverifiable" (no outage yet). The verified (rotated) key is pinned
in a per-run `known_hosts` with `StrictHostKeyChecking=yes`. Blue's key is recorded at registration (TOFU, confirmed
by the operator, §6.2.1). cloud-init regenerates host keys on a new instance (OSI §9, AS), so green always needs this step.

#### 6.2.1 Blue's host key (the existing VM)

The renewal reaches blue with `StrictHostKeyChecking=yes` and accepts only keys whose SHA-256 fingerprint equals the
plan's snapshot of `managed_vm.ssh_host_key_fingerprint`; a plan is refused unless that fingerprint was **confirmed** by
an operator in a human session (ADR-0006, api-design.md §3.3). The confirmation is the trust root of every later SSH
to blue, so it is protected against a compromised api or `ovlm_api` role (review IS-1, migration `registry_0002`):

| Control | Where | What it stops |
|---|---|---|
| Column grants: `ovlm_api` may UPDATE only `host_key_confirmed_by/at`; the worker only `ssh_host_key_fingerprint` (no grant on `host_key_confirmed_*`) | `registry_0001` | the api writing a fingerprint; the worker confirming one |
| Insert guard `managed_vm_api_insert_guard`: for `current_user = 'ovlm_api'`, `ssh_host_key_fingerprint`, `host_key_confirmed_by`, `host_key_confirmed_at` must be NULL (SQLSTATE 42501) | `registry_0002` | inserting a row that arrives already scanned or confirmed |
| Tombstone `managed_vm_tombstone`: every deleted id is recorded by a `SECURITY DEFINER` AFTER DELETE trigger (fixed `search_path = pg_catalog, public, pg_temp`, EXECUTE revoked from PUBLIC); the insert guard refuses a tomb-stoned id for **every** role. `ovlm_api` has SELECT only on it | `registry_0002` | delete + re-insert under the same id (the reviewer's probe), so an approved plan can never be pointed at a forged row |
| `managed_vm_host_key_follow`: any change of `ssh_host_key_fingerprint` clears `host_key_confirmed_*`, whoever writes it; CHECK `managed_vm_host_key_confirmation`: a confirmation names its confirmer and a fingerprint | `registry_0002` | a confirmation outliving the key it vouched for (the scan's own `WHERE` is the first line) |
| Live re-check at the first SSH to blue: W1 `quiesce_old`, **before** the outage starts, re-reads the row and refuses unless the key is confirmed, the fingerprint equals the plan's, and `host_key_confirmed_by` is an `active` `app_user` (a human: tokens and agents are never confirmers). Refusal parks `needs_human` with `blue_host_key_untrusted`: nothing ran on blue, no restore. Every later SSH to blue (`blue_ref`, restore included) re-checks that the row still carries the plan's confirmed fingerprint, but not the confirmer's state, so disabling a user mid-outage cannot block a restore | `src/ovlm/renewal/base.py` `blue_host_key_problems`, `steps_window.py` | a plan that snapshot a key forged or changed before the run |

The role cannot switch these off: `TRUNCATE` (which would skip the row trigger), `ALTER TABLE … DISABLE TRIGGER`,
`DROP TRIGGER`, `SET session_replication_role = replica`, a temporary table shadowing the tombstone, CREATE in
`public`, replacing or altering the functions, writing the tombstone and dropping the CHECK are all refused to
`ovlm_api` (tested, as for the credential store in reviews/verification-credential-store-fixes.md). Residual: a
compromised api can still confirm a **scanned** key in the name of a real active operator (it holds the column grant
by design); the out-of-band comparison and the audit row are the controls (review IS-2).

**Which address is scanned** (review IS-3). The scan and the renewal use one rule (`src/ovlm/registry/ssh_target.py`):
`fixed_ips[0]` of the port the **service floating IP** is attached to. The scan finds that floating IP in the latest
profile version (`cutover.floating_ip_id`); before a profile exists it takes the only port of blue that carries a
floating IP and refuses when there are several. The scanned port id and floating IP id are in the step evidence and
the audit row (`managed_vm.host_key_scan`), next to the address and fingerprint. The target is always an inventory
address parsed as an IP (no hostname, `ssh-keyscan … --`).

### 6.3 Network path
Worker → guest SSH (22) on the fixed IP: green has no FIP before cutover. Options: worker on a routed management
network, or a bastion (`ProxyJump`, its host key pinned). Profiles' security groups allow 22 only from the worker/
bastion source address; OVLM's readiness check flags `0.0.0.0/0` on 22 as a warning. Guests never connect to OVLM.

### 6.4 Guest output is untrusted
Healthcheck JSON, Ansible facts, stdout and `set_stats` are attacker-controlled once a guest is compromised:
size cap (e.g. 1 MiB per step), strict JSON schema with allowlisted fields, parsed with a safe parser (no YAML
tags, no eval, never rendered through Jinja), stored as data, displayed escaped and labelled "reported by guest".
Ansible events, stdout and diffs are additionally treated as possibly holding workload secrets (§5.2).
Facts never feed authorization, ownership, or which resource is mutated. Cutover acceptance also uses an external
probe from the worker (FIP reachability), so a lying guest can delay but not alone cause cutover of a broken service.
Text in guest or repo output is never treated as instructions by humans or AI tools reading OVLM (OzarLand rule 14).

### 6.5 Automation repo content
Allowlisted repo URLs (admin); profile pins a full commit SHA (no branches/tags at run time); the SHA is part of the
approved plan hash (T13). Dependencies (collections/roles) come from the image or are vendored at that SHA — no
Galaxy download at run time. ansible-runner runs as a separate OS user (`ovlm-ansible`) with a scrubbed environment
(no `OS_*`, DB URL, KEK path), a private run dir (0700, tmpfs), and no read access to the KEK file or DB secret files.
Residual risk: an approved but malicious SHA still runs code on the worker host as `ovlm-ansible` and on guests.

## 7. Destructive operations

### 7.1 Inventory
All require: write credential, worker only, ownership guard (§4.3), approval binding a hash of (plan, profile version,
automation SHA, target IDs, policy version), audit of attempt + result. TC = typed confirmation of the target's
**server name plus the last 6 characters of its ID** (names are not unique, OSI §3/§9, SV), checked server-side.

| Operation | Phase | Role | Approval | TC | Note |
|---|---|---|---|---|---|
| Stop blue (outage starts) | Cutover | operator starts step | Cutover gate | Yes (at cutover approval) | Default "stop first" (OSI rec. 3) |
| Detach production data volume from blue | Cutover | operator | Cutover gate | Yes (same) | Preflight lists only observable facts: `locked == false` (mv 2.73), `ACTIVE` with no `task_state`, `delete_on_termination == false` (mv 2.79), volume `in-use` by blue only, not multiattach (OSI rec. 4). A down compute host and an admin lock are not observable; they are detected only when the stop/detach call fails, which goes to needs_human (SEC-R-6) |
| Attach data volume to green | Cutover | operator | Cutover gate | — | Green must be OVLM-created in this run |
| FIP move to green | Cutover | operator | Cutover gate | — (covered above) | Router preflight (OSI §6.1) |
| Revert (FIP and volume back to blue) | Post-cutover | operator | None (restores prior state) | Yes | Unlock own lock first (OSI §9). A revert voids every open or granted retirement (G3) approval of the run (SEC-R-8) |
| Lock / unlock old VM | Retention | system step | Covered by cutover / revert | — | Lock only after handoff (OSI rec. 5) |
| Delete old VM (retirement) | Retirement | operator starts | **Retirement gate, two-person rule default on** | Yes | Irreversible; re-check `delete_on_termination` immediately before; the worker re-derives the target's state from OpenStack and re-validates the approval evidence (renewal-workflow.md §2.3 X1, §3.1; SEC-R-33) |
| Delete green on rollback | Rollback | operator (abort) | None | Yes on abort | Only if tagged `ovlm:run:<this run>` and no data volume attached |
| Orphans (ports, snapshots, anything marked `ovlm:*` outside the ledger) | Cleanup | — | — | — | **Report-only** in MVP: evidence and a suggested CLI command for a human with the rights; no delete endpoint (SEC-R-25) |
| Delete/rotate credential, SSH key, KEK | Admin | admin | — | Yes | Blocked while a run uses it |

The UI shows blast radius (service, VM, volume, FIP, outage) before every TC (FR-UI-2); the API requires the same field, no "force".

**Approval validity.** Approvals expire (default 24 h for plan, 4 h for cutover); any change to the bound hash voids them; a resumed run
after a crash re-checks approval validity before a destructive step. Retirement approvals have a default expiry
(config key `approval.validity.retirement`; the value is set in configuration, not fixed here). A revert voids retirement
approvals (SEC-R-8).

### 7.2 Human principals only (agent safety)
Approvals and typed confirmations are accepted only from an interactive session of a human user with step-up
re-auth; API tokens and service principals get 403 on those endpoints. This is a deliberate exception to FR-UI-3
("same capabilities in the API"). OVLM must not be driven by an AI agent to approve its own or any run; each
destructive action needs a named human owner (OzarLand rule 6). Audit records `principal_type` and `auth_method`.

## 8. Audit

| Topic | Decision |
|---|---|
| Append-only | Table `audit_event` owned by `ovlm_owner` (migrations only). Runtime roles `ovlm_api` and `ovlm_worker` have `INSERT, SELECT` only — no `UPDATE, DELETE, TRUNCATE`; enforced by GRANTs plus a trigger raising on UPDATE/DELETE (catches mis-grants). |
| Log-stream mirror | After commit, `audit.record()` also emits each row as an `event=audit` log line from both api and worker to the operator's log collector (architecture.md §2). A DB administrator cannot then rewrite history without a divergence against the collector (SEC-R-21). |
| Hash chain | **Not in MVP; V1.** A chain only helps if its head is anchored outside the DB (a DB superuser can recompute it). V1: per-row `prev_hash`/`hash` (SHA-256 over canonical JSON), inserts serialized by advisory lock, and a daily signed checkpoint exported to the SIEM. |
| Logged | Everything in FR-AUD-2 plus: logins (success/failure), step-up re-auth, token create/revoke/use of privileged scope, role changes, SoD relaxations, TC events, ownership violations, KEK rotation, credential validation results, authorization denials on mutating endpoints. |
| Fields | time (UTC), actor id, principal type, auth method, source IP, project scope, action, target type/id, before/after (allowlisted fields, secrets excluded), result, correlation (run id, step), request id. |
| Retention | Configurable, default 400 days (ASSUMPTION: no regulatory requirement stated); purge by a separate offline role (`ovlm_audit_admin`), the purge itself audited. |
| Export | V1 JSON lines (FR-AUD-3), admin only, stream to SIEM recommended; export includes checkpoints. |

## 9. Supply chain and deployment hardening

| Area | Requirement |
|---|---|
| Dependencies | Lock file with hashes (`uv`/`pip-tools`, `--require-hashes`); openstacksdk and ansible-core pinned (NFR-8). Renovate/Dependabot updates by PR. |
| CI scanning | `pip-audit` (deps), `bandit` (code), Trivy or Grype (image), secret scanning, GitHub Actions pinned by SHA. High/critical findings block release (Agent 8 veto, agent-team.md). |
| Image | Slim base pinned by digest; no compilers or SSH server; runs as non-root uid (worker and `ovlm-ansible` distinct uids); read-only root FS, tmpfs for run dirs; `cap_drop: ALL`, `no-new-privileges`. V1: SBOM and signed images. |
| TLS | OVLM serves HTTP only on the compose network; a reverse proxy terminates TLS ≥ 1.2 with HSTS. Forwarded headers trusted only from the proxy address. |
| Database | Not published outside the compose network; `scram-sha-256`; separate roles `ovlm_owner` (migrate; its secret is never mounted into api or worker), `ovlm_api` and `ovlm_worker` (runtime, grants per data-model.md §12), `ovlm_audit_admin` (purge); passwords via Docker secrets files; TLS if the DB is remote. |
| Disclosure | `SECURITY.md`: private reporting via GitHub Security Advisories, supported versions, acknowledgement target, no public issues for vulnerabilities (OzarLand pattern; ASSUMPTION: the exact OzarLand template was not read). |

## 10. Security acceptance criteria (QA automates)

1. Password hashes are argon2id with configured parameters; login errors identical for unknown user and wrong password; rate limit triggers after N attempts.
2. Session cookie has `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Lax`; session id changes at login. Every unsafe UI endpoint rejects requests without a valid CSRF token or with a foreign `Origin` (parametrized over the route table).
3. API token secret is stored only as a hash; expired or revoked tokens get 401; a token cannot exceed its owner's scope.
4. Approve and destructive-confirm endpoints return 403 for API tokens, and require re-auth older than 5 min to fail.
5. RBAC matrix (§3.1) is a table-driven test: every role × every route, allowed and denied.
6. Project scope: a user bound to project X gets 404 for every resource of project Y.
7. Requester approving own gate is rejected; retirement with the same approver for plan and retirement is rejected when the two-person rule is on.
8. Changing profile version, automation SHA or target ID after approval voids the approval.
9. Inventory session raises on any non-GET/HEAD request (unit test with a mocked transport).
10. Ownership guard: mutating calls on a VM with the tag but no DB record, or a DB record but no tag, are refused (fake SDK).
11. Delete of old VM is refused when any data attachment has `delete_on_termination=true`.
12. Secret canary: a known canary secret placed in every secret type never appears in logs, audit rows, API/UI responses, error pages, ansible command lines or the run-dir after the run.
13. api container has no KEK file and cannot decrypt a stored secret; worker can. KEK rotation re-wraps all DEKs and old key removal leaves all secrets decryptable.
14. `ovlm_api` and `ovlm_worker` DB roles cannot UPDATE/DELETE/TRUNCATE `audit_event`; every committed audit row also appears as an `event=audit` line in the log stream.
15. Malicious guest output (oversized JSON, wrong schema, `<script>`, YAML tags) is rejected or stored escaped; it never changes run decisions.
16. Ansible subprocess environment contains no `OS_*`, DB URL or KEK path; `ovlm-ansible` cannot read the KEK file.
17. Profile with branch or tag instead of a full SHA, or a non-allowlisted repo, fails validation.
18. SSH with an unverified host key fails unless the profile opted into TOFU; the pinned fingerprint is enforced on later connects.
19. Container runs as non-root, read-only root FS; image scan and `pip-audit` gate in CI. openstacksdk debug logging cannot be enabled without the explicit env flag; tokens never appear at INFO/DEBUG with the flag off.
20. A profile version author approving a plan built on their own profile version is rejected, as are the plan creator, run starter, policy editor and approval requester for their gates (parametrized over the requester set); one person holding `operator` and `approver` in the same scope is refused unless an admin allowed it, and the allowance is shown on the approval.
21. Vault canary: a canary placed in an Ansible vault file (and templated onto the guest) never appears in stored artefacts (events, stdout, diffs, task results), logs, audit rows or API/UI responses; diffs are absent unless the profile has `store_diffs`; a viewer cannot read automation artefacts.
22. Write allowlist enforced: `WriteClient` raises before sending for a volume delete, volume create, floating IP create/delete and any security-group write, and for any call outside the strategy's operations (fake transport records zero such requests).
23. Adoption checks of claimed resources: a server found by `tags=ovlm:run:<id>` is adopted only if image, flavor, creation time, attached volumes and creating user match; any mismatch ends in needs_human "adoption refused". Marking uses add/merge forms only, and pre-existing foreign tags and metadata survive.
24. Self-approval at G3 is refused even when `auth.allow_operator_approver` is on; G1/G2 self-approval succeeds only with the setting on and is flagged `self_approved`; a solo installation without a second human approver account leaves the old VM stopped and locked.
25. Step-up reuse is refused: a consumed step-up, one older than 5 minutes, or one bound to another action type or target is rejected.
26. Admin-set password is impossible: no API or UI path lets an admin choose or read another user's password; user creation and reset return only a one-time enrolment link.
27. An assessment without typed confirmation runs no repo code on the live VM (only OVLM-owned read-only checks and static analysis).
28. `ovlm_api` cannot delete a confirmed managed VM and re-insert it under the same id (tombstone, every role), cannot insert a row with a fingerprint or a confirmation, and cannot disable the guards (TRUNCATE, DISABLE TRIGGER, `session_replication_role`, temp-table shadowing, function replacement); a fingerprint change clears the confirmation (`tests/integration/test_managed_vm_host_key_guard.py`).
29. W1 refuses blue before the outage when the live row's key is unconfirmed, differs from the plan's, or was confirmed by a disabled or unknown user (`tests/integration/renewal/test_blue_host_key_live_check.py`).
30. The host-key scan targets `fixed_ips[0]` of the service floating IP's port, as the renewal does, and records the port id (`tests/integration/test_host_key_scan.py::test_is3_*`).
31. Viewers see only reason codes for failed syncs (no Keystone URL, status line or exception text, also for records written before the codes); a client set-up error is a recorded failure (`tests/integration/test_inventory_sync_job.py`).
