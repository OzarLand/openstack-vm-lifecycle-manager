"""Worker jobs of the credential store: credential validation and KEK re-wrap (security-model.md 4.4, 5.1).

**Validation** (``credential_test`` / ``credential_validate``, periodic): every ``pending`` or ``active`` credential
of an enabled connection whose validation was requested after its last one, **or** whose last validation is older
than ``kek.revalidation_interval`` (default daily, review CS-4), is checked **out of band, by the worker only**:

* First, without decrypting anything: the credential must be bound to the connection's **current** destination
  (cloud and endpoint digest, review CS-1/CS-2). A changed endpoint is a failed validation, never a token request to
  the new endpoint: the secret was validated for the old one.
* ``os_read`` / ``os_write``: one Keystone token request with the application credential, over a session that carries
  the read-only guard (it can send nothing but the token request and GETs), TLS verified, then **one GET** of the
  application credential's own record (``/users/{user}/application_credentials/{id}``, review CS-3). The token must
  be scoped to the connection's project, carry exactly the expected roles (``reader``; ``member`` with at most the
  implied ``reader``), name the uploaded application credential and, when Keystone reports it, be restricted. The
  record must show an ``expires_at`` (never-expiring is refused), at most 180 days ahead and not later than the
  uploaded date, ``unrestricted`` false and no role outside the expected ones. Keystone's ``expires_at`` is stored
  (``verified_expires_at``) and the earlier of the two dates is the one enforced.
* ``ssh_key``: decrypted and parsed; its public key must equal the one recorded at upload.

A pending credential that passes **replaces the active one atomically** (the old one becomes ``superseded`` and, for
application credentials, ``cloud_deletion_pending``: only the cloud admin can delete it in Keystone). One that fails
becomes ``rejected``. An active credential that fails a re-validation stays active but is marked invalid, so no new
run uses it. Keystone being unreachable, a disabled connection, or a secret wrapped to a key this worker does not hold
(review CS-5: the api was switched to a new key before the worker) are not verdicts: the credential is retried at the
next period.

Each run also publishes the key ids the worker holds (``kek_key``: the api seals only to those), deletes orphan
sealed secrets (audited, review CS-9) and reports expiring and failing credentials (metrics and a daily log line).

**Re-wrap** (``rewrap`` / ``kek_rewrap``, periodic, only while previous keys are configured): every sealed secret
whose data key is wrapped to another key than the current one is re-wrapped to the current key (the ciphertext
itself is unchanged). Audited per run with counts.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from ovlm import audit
from ovlm.config.secrets import register_secret
from ovlm.connections import events as _events  # noqa: F401 - registers the audit allowlists
from ovlm.connections import metrics
from ovlm.connections.credentials import (
    ConnectionInfo,
    CredentialKeyMissingError,
    CredentialStore,
    CredentialUnavailableError,
    binding_mismatch,
    ca_bundle_path,
    effective_expiry,
    load_connection,
)
from ovlm.secrets.keyring import KeyringError, wipe
from ovlm.secrets.store import (
    announce_keys,
    credential_context,
    delete_orphans,
    rows_wrapped_to_other_keys,
    store_rewrap,
)
from ovlm.workflow.contract import (
    Act,
    Admission,
    Decision,
    Defer,
    Done,
    Outcome,
    Reject,
    Step,
    StepContext,
    StepSpec,
    Transition,
    TxContext,
    WorkflowDefinition,
)
from ovlm.workflow.registry import PeriodicJob

log = logging.getLogger("ovlm.connections.validation")

VALIDATE_KIND, VALIDATE_STRATEGY = "credential_test", "credential_validate"
REWRAP_KIND, REWRAP_STRATEGY = "rewrap", "kek_rewrap"
BATCH = 20
#: security-model.md 4.4: an application credential expires at most 180 days after upload.
MAX_CREDENTIAL_DAYS = 180
#: Keystone's expiry may be later than the uploaded date by this much (clock and rounding), never more.
EXPIRY_TOLERANCE = timedelta(minutes=1)
#: security-model.md 4.4: warn 30 and 7 days before expiry.
EXPIRY_WARN_DAYS = (7, 30)

#: Roles a token may show per kind (Keystone's default role hierarchy implies ``reader`` from ``member``).
REQUIRED_ROLE = {"os_read": "reader", "os_write": "member"}
ALLOWED_ROLES = {"os_read": frozenset({"reader"}), "os_write": frozenset({"member", "reader"})}


@dataclass(frozen=True)
class TokenFacts:
    """What Keystone said about a token issued for the application credential. No secret here."""

    project_id: str | None
    roles: tuple[str, ...]
    user_id: str | None
    app_credential_id: str | None
    restricted: bool | None
    token_expires_at: datetime | None
    #: The application credential's own record (``GET /users/{user}/application_credentials/{id}``, review CS-3).
    #: ``record_status``: the HTTP status of that GET (200 when read).
    record_status: int | None = None
    record_expires_at: datetime | None = None
    record_unrestricted: bool | None = None
    record_roles: tuple[str, ...] = ()

    @property
    def record_read(self) -> bool:
        return self.record_status == 200


class TransientValidationError(Exception):
    """Keystone could not be asked (network, 5xx): not a verdict, retried later."""


class KeystoneRefusedError(Exception):
    """Keystone refused the credential (401/403/404): a verdict."""


#: ``(auth_url, app_credential_id, secret, verify) -> TokenFacts``. Replaced by a double in tests.
TokenChecker = Callable[[str, str, str, "bool | str"], TokenFacts]


def keystone_token_check(
    auth_url: str, app_cred_id: str, secret: str, verify: bool | str, *, adapter: Any = None
) -> TokenFacts:
    """One token request with the application credential, over a session that can send nothing else."""
    from keystoneauth1 import exceptions as ks_exc
    from keystoneauth1 import session as ks_session
    from keystoneauth1.identity import v3

    from ovlm.openstack.guard import install_read_only_guard

    auth = v3.ApplicationCredential(
        auth_url=auth_url,
        application_credential_id=app_cred_id,
        application_credential_secret=secret,
    )
    sess = ks_session.Session(auth=auth, verify=verify)
    if adapter is not None:  # tests: a canned transport
        sess.session.mount("https://", adapter)
    install_read_only_guard(sess)
    try:
        access = auth.get_access(sess)
    except (ks_exc.Unauthorized, ks_exc.Forbidden, ks_exc.NotFound) as exc:
        raise KeystoneRefusedError(
            f"Keystone refused the credential (HTTP {getattr(exc, 'http_status', '?')})"
        ) from None
    except (
        ks_exc.ConnectionError,
        ks_exc.SSLError,
        ks_exc.ConnectTimeout,
        ks_exc.HttpServerError,
    ) as exc:
        raise TransientValidationError(f"Keystone unreachable: {type(exc).__name__}") from None
    except ks_exc.ClientException as exc:
        raise TransientValidationError(f"Keystone error: {type(exc).__name__}") from None
    app = getattr(access, "_application_credential", None) or {}
    restricted = app.get("restricted") if isinstance(app, Mapping) else None
    record = _read_record(sess, auth_url, access.user_id, app_cred_id, ks_exc)
    return TokenFacts(
        project_id=access.project_id,
        roles=tuple(sorted(access.role_names or ())),
        user_id=access.user_id,
        app_credential_id=getattr(access, "application_credential_id", None),
        restricted=restricted if isinstance(restricted, bool) else None,
        token_expires_at=access.expires,
        **record,
    )


def _keystone_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _read_record(
    sess: Any, auth_url: str, user_id: str | None, app_cred_id: str, ks_exc: Any
) -> dict[str, Any]:
    """One GET of the application credential's own record, over the same guarded session (review CS-3). Keystone's
    default policy lets the owner read its application credentials; a refusal is reported (``record_status``) and
    becomes a failed verdict, because the real expiry is then unknown."""
    if not user_id:
        return {"record_status": None}
    url = f"{auth_url.rstrip('/')}/users/{user_id}/application_credentials/{app_cred_id}"
    try:
        resp = sess.get(url, raise_exc=False)
    except (ks_exc.ConnectionError, ks_exc.SSLError, ks_exc.ConnectTimeout) as exc:
        raise TransientValidationError(f"Keystone unreachable: {type(exc).__name__}") from None
    if resp.status_code >= 500:
        raise TransientValidationError(f"Keystone error: HTTP {resp.status_code}")
    if resp.status_code != 200:
        return {"record_status": resp.status_code}
    try:
        rec = resp.json()["application_credential"]
        expires = _keystone_time(rec.get("expires_at"))
    except (ValueError, KeyError, TypeError):
        return {"record_status": 0}  # unreadable body: not a successful read
    unrestricted = rec.get("unrestricted")
    roles = tuple(
        sorted(str(r.get("name", "")) for r in rec.get("roles") or () if isinstance(r, Mapping))
    )
    return {"record_status": 200, "record_expires_at": expires,
            "record_unrestricted": unrestricted if isinstance(unrestricted, bool) else None,
            "record_roles": roles}  # fmt: skip


def evaluate_token(
    kind: str, facts: TokenFacts, connection: ConnectionInfo, app_cred_id: str, expires_at: datetime | None,
    now: datetime,
) -> tuple[bool, str]:  # fmt: skip
    """Pure verdict on what Keystone said (security-model.md 4.4). Returns ``(ok, reason)``."""
    if expires_at is None or expires_at <= now:
        return False, "the credential is expired"
    if (facts.project_id or "").lower() != connection.openstack_project_id:
        return False, "the token is not scoped to this connection's OpenStack project"
    roles = frozenset(r.lower() for r in facts.roles)
    if REQUIRED_ROLE[kind] not in roles:
        return False, f"the token lacks the role {REQUIRED_ROLE[kind]!r}"
    extra = sorted(roles - ALLOWED_ROLES[kind])
    if extra:
        return False, f"the token carries other roles than expected: {extra}"
    if facts.app_credential_id and facts.app_credential_id.lower().replace("-", "") != app_cred_id:
        return False, "the token was not issued for the uploaded application credential id"
    if facts.restricted is False or facts.record_unrestricted is True:
        return (
            False,
            "the application credential is unrestricted (it could create other credentials)",
        )
    return _evaluate_record(kind, facts, expires_at, now, sorted(roles))


def _evaluate_record(
    kind: str, facts: TokenFacts, uploaded: datetime, now: datetime, roles: list[str]
) -> tuple[bool, str]:
    """Keystone's own record of the application credential (review CS-3): the real expiry, not the form's."""
    if not facts.record_read:
        return False, (
            "Keystone did not show the application credential's record "
            f"(HTTP {facts.record_status if facts.record_status is not None else '?'}), so its real expiry cannot "
            "be verified (the credential's user must be allowed to read its own application credentials)"
        )
    ks = facts.record_expires_at
    if ks is None:
        return (
            False,
            "the application credential never expires in Keystone (security-model.md 4.4 requires an expiry)",
        )
    if ks <= now:
        return False, "the credential is expired (Keystone)"
    if ks > now + timedelta(days=MAX_CREDENTIAL_DAYS):
        return (
            False,
            f"Keystone's expiry {ks.isoformat()} is more than {MAX_CREDENTIAL_DAYS} days ahead",
        )
    if ks > uploaded + EXPIRY_TOLERANCE:
        return (
            False,
            f"Keystone's expiry {ks.isoformat()} is later than the uploaded one {uploaded.isoformat()}",
        )
    extra = sorted({r.lower() for r in facts.record_roles} - ALLOWED_ROLES[kind])
    if extra:
        return False, f"the application credential carries other roles than expected: {extra}"
    return (
        True,
        f"Keystone token scoped to the project with roles {roles}; expires {ks.isoformat()} (Keystone)",
    )


@dataclass(frozen=True)
class Verdict:
    ok: bool | None  # None: transient, no verdict
    reason: str
    roles: tuple[str, ...] = ()
    user_id: str | None = None
    #: Keystone's expiry of the application credential, when read (review CS-3).
    verified_expires_at: datetime | None = None

    def result(self) -> dict[str, Any]:
        return {"ok": bool(self.ok), "reason": self.reason[:300], "roles": list(self.roles),
                "user_id": self.user_id, "transient": self.ok is None,
                "keystone_expires_at": self.verified_expires_at.isoformat() if self.verified_expires_at else None}  # fmt: skip


_DUE_COLS = (
    "r.id, r.project_connection_id, r.kind, r.secret_id, r.app_credential_id, r.ssh_public_key, r.expires_at, "
    "r.verified_expires_at, r.cloud_id, r.endpoint_sha256, r.state, r.validation_requested_at"
)


class CredentialValidator:
    def __init__(
        self, store: CredentialStore, checker: TokenChecker = keystone_token_check
    ) -> None:
        self.store = store
        self.checker = checker
        self._warned: dict[str, datetime] = {}

    def due(self, limit: int = BATCH) -> list[Any]:
        """Requested validations, and active credentials not validated for ``store.revalidate_after`` seconds (CS-4).
        Credentials of a disabled connection wait (nothing of theirs is decrypted or sent, CS-7)."""
        with self.store.engine.connect() as c:
            return list(
                c.execute(
                    text(
                        f"SELECT {_DUE_COLS} FROM credential_ref r "  # noqa: S608
                        "JOIN project_connection p ON p.id = r.project_connection_id "
                        "WHERE r.state IN ('pending', 'active') AND r.kind IN ('os_read', 'os_write', 'ssh_key') "
                        "AND p.enabled AND (r.last_validated_at IS NULL OR r.validation_requested_at > r.last_validated_at "
                        "OR (r.state = 'active' AND r.last_validated_at < now() - make_interval(secs => :age))) "
                        "ORDER BY r.validation_requested_at, r.id LIMIT :l"
                    ),
                    {"l": limit, "age": float(self.store.revalidate_after)},
                ).all()
            )

    def check(self, row: Any, now: datetime | None = None) -> Verdict:
        """The verdict for one credential row. Network only for application credentials; nothing is written."""
        now = now or datetime.now(UTC)
        with self.store.engine.connect() as c:
            info = load_connection(c, str(row.project_connection_id))
            if info is None:
                return Verdict(False, "no such project connection")
            if not info.enabled:
                return Verdict(None, "the project connection is disabled: validation postponed")
            mismatch = binding_mismatch(row, info)
            if mismatch is not None:  # nothing decrypted, nothing sent (CS-1)
                return Verdict(False, mismatch)
            expiry = effective_expiry(row)
            if row.kind != "ssh_key" and (expiry is None or expiry <= now):
                return Verdict(False, "the credential is expired")
            try:
                buf = self.store.unseal_for(c, row.id, row.secret_id, info.destination(row.kind))
            except CredentialKeyMissingError as exc:  # rotation order, not a verdict (CS-5)
                return Verdict(None, str(exc))
            except CredentialUnavailableError as exc:
                return Verdict(False, str(exc))
        try:
            if row.kind == "ssh_key":
                return self._check_ssh(buf, row.ssh_public_key)
            try:
                secret = buf.decode("ascii")
            except UnicodeDecodeError:
                return Verdict(False, "the secret is not text")
        finally:
            wipe(buf)
        register_secret(secret)  # redaction backstop before keystoneauth sees it (CS-7)
        try:
            ca: Path | None = ca_bundle_path(info, self.store.ca_dir)
            facts = self.checker(
                info.auth_url, row.app_credential_id, secret, str(ca) if ca else True
            )
        except TransientValidationError as exc:
            return Verdict(None, str(exc))
        except (KeystoneRefusedError, CredentialUnavailableError) as exc:
            return Verdict(False, str(exc))
        finally:
            secret = ""  # drop the reference (the str itself cannot be wiped)
        ok, reason = evaluate_token(
            row.kind, facts, info, row.app_credential_id, row.expires_at, now
        )
        return Verdict(ok, reason, facts.roles, facts.user_id, facts.record_expires_at)

    @staticmethod
    def _check_ssh(buf: bytearray, public_line: str | None) -> Verdict:
        from cryptography.hazmat.primitives import serialization

        try:
            key = serialization.load_ssh_private_key(bytes(buf), password=None)
        except (ValueError, TypeError):
            return Verdict(False, "the stored SSH key does not parse")
        pub = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        if not public_line or pub.decode().split()[:2] != public_line.split()[:2]:
            return Verdict(False, "the stored SSH key does not match its recorded public key")
        return Verdict(True, "SSH private key parses and matches its public key")

    def apply(self, row: Any, verdict: Verdict) -> str:
        """Record the verdict in one transaction; switch a passing pending credential in. Returns the outcome."""
        if verdict.ok is None and row.state == "active":
            log.warning(
                "credential re-validation postponed",
                extra={"credential_id": str(row.id), "reason": verdict.reason},
            )
            return "postponed"
        result = verdict.result()
        with Session(self.store.engine) as s, s.begin():
            cur = s.execute(
                text(
                    "SELECT state, validation_requested_at FROM credential_ref WHERE id = :i FOR UPDATE"
                ),
                {"i": row.id},
            ).one_or_none()
            if (
                cur is None
                or cur.state != row.state
                or cur.validation_requested_at != row.validation_requested_at
            ):
                return "changed"  # deleted or re-requested meanwhile: the next period takes it
            outcome = self._write(s, row, verdict, result)
            audit.record(
                s, action="credential.validate", target_type="credential_ref", target_id=str(row.id),
                result="success" if verdict.ok else "failure", principal_type="worker", auth_method="none",
                project_scope=f"project:{row.project_connection_id}",
                after={"kind": row.kind, "project_connection_id": row.project_connection_id,
                       "state": outcome, "validation_ok": bool(verdict.ok), "validation_reason": result["reason"]},
            )  # fmt: skip
        return outcome

    @staticmethod
    def _write(s: Session, row: Any, verdict: Verdict, result: dict[str, Any]) -> str:
        import json

        params = {"i": row.id, "r": json.dumps(result), "v": verdict.verified_expires_at}
        if verdict.ok is None:  # pending, Keystone unreachable: keep it pending, show why
            s.execute(text("UPDATE credential_ref SET validation_result = CAST(:r AS jsonb), updated_at = now() "
                           "WHERE id = :i"), params)  # fmt: skip
            return "pending"
        if row.state == "active" or not verdict.ok:
            new_state = row.state if row.state == "active" else "rejected"
            s.execute(
                text("UPDATE credential_ref SET state = :st, validation_result = CAST(:r AS jsonb), "
                     "verified_expires_at = COALESCE(CAST(:v AS timestamptz), verified_expires_at), "
                     "last_validated_at = now(), updated_at = now() WHERE id = :i"), {**params, "st": new_state},
            )  # fmt: skip
            return new_state
        old = s.execute(
            text("SELECT id FROM credential_ref WHERE project_connection_id = :p AND kind = :k AND state = 'active' "
                 "FOR UPDATE"), {"p": row.project_connection_id, "k": row.kind},
        ).scalar_one_or_none()  # fmt: skip
        if old is not None:
            s.execute(
                text("UPDATE credential_ref SET state = 'superseded', superseded_by = :n, rotated_at = now(), "
                     "cloud_deletion_pending = :del, updated_at = now() WHERE id = :o"),
                {"n": row.id, "o": old, "del": row.kind in ("os_read", "os_write")},
            )  # fmt: skip
        s.execute(
            text("UPDATE credential_ref SET state = 'active', validation_result = CAST(:r AS jsonb), "
                 "verified_expires_at = COALESCE(CAST(:v AS timestamptz), verified_expires_at), "
                 "last_validated_at = now(), rotated_at = CASE WHEN :rot THEN now() END, updated_at = now() "
                 "WHERE id = :i"), {**params, "rot": old is not None},
        )  # fmt: skip
        if old is not None:
            audit.record(
                s, action="credential.rotate", target_type="credential_ref", target_id=str(row.id),
                principal_type="worker", auth_method="none", project_scope=f"project:{row.project_connection_id}",
                after={"kind": row.kind, "project_connection_id": row.project_connection_id, "state": "active",
                       "superseded_by": row.id, "cloud_deletion_pending": row.kind in ("os_read", "os_write")},
            )  # fmt: skip
        return "active"

    def run_once(self) -> dict[str, int]:
        self.announce()
        counts: dict[str, int] = {}
        for row in self.due():
            outcome = self.apply(row, self.check(row))
            counts[outcome] = counts.get(outcome, 0) + 1
        orphans = self.sweep_orphans()
        if orphans:
            counts["orphans_deleted"] = orphans
        self.report()
        return counts

    def announce(self) -> None:
        """Publish the key ids this worker holds (``kek_key``): the api seals only to those (CS-5, CS-10)."""
        ring = self.store.keyring
        with self.store.engine.begin() as c:
            announce_keys(c, ring.current_kek_id, ring.kek_ids)

    def sweep_orphans(self) -> int:
        """Delete sealed secrets no credential refers to (CS-9). Audited with the count."""
        with Session(self.store.engine) as s, s.begin():
            n = delete_orphans(s)
            if n:
                audit.record(
                    s, action="kek.orphans_deleted", target_type="kek", target_id=self.store.keyring.current_kek_id,
                    principal_type="worker", auth_method="none", after={"kek_id": self.store.keyring.current_kek_id,
                                                                        "orphans_deleted": n},
                )  # fmt: skip
        return n

    def report(self, now: datetime | None = None) -> dict[str, int]:
        """Metrics and a daily warning for active credentials expiring within 30/7 days, expired or failing their
        last validation (security-model.md 4.4, CS-4)."""
        now = now or datetime.now(UTC)
        with self.store.engine.connect() as c:
            rows = c.execute(
                text(
                    "SELECT r.id, r.project_connection_id, r.kind, r.expires_at, r.verified_expires_at, s.kek_id, "
                    "COALESCE((validation_result->>'ok')::boolean, false) AS ok FROM credential_ref r "
                    "JOIN sealed_secret s ON s.id = r.secret_id WHERE r.state = 'active'"
                )
            ).all()
        buckets = {"expired": 0, "7d": 0, "30d": 0}
        failing = unknown = 0
        held = self.store.keyring.kek_ids
        for r in rows:
            failing += not r.ok
            unknown += r.kek_id not in held
            exp = effective_expiry(r)
            if exp is None:
                continue
            bucket = (
                "expired" if exp <= now else next(
                    (f"{d}d" for d in EXPIRY_WARN_DAYS if exp - now < timedelta(days=d)), None)
            )  # fmt: skip
            if bucket is None:
                continue
            buckets[bucket] += 1
            key = f"{r.id}:{bucket}"
            last = self._warned.get(key)
            if last is None or now - last >= timedelta(days=1):
                self._warned[key] = now
                log.warning(
                    "credential expiring" if bucket != "expired" else "credential expired",
                    extra={"credential_id": str(r.id), "project_connection_id": str(r.project_connection_id),
                           "credential_kind": r.kind, "expires_at": exp.isoformat(), "within": bucket},
                )  # fmt: skip
        for k, v in buckets.items():
            metrics.CREDENTIALS_EXPIRING.labels(k).set(v)
        metrics.CREDENTIALS_FAILING.set(failing)
        metrics.KEK_UNKNOWN.set(unknown)
        return {**buckets, "failing": failing, "unknown_kek": unknown}


def rewrap_all(store: CredentialStore, batch: int = 100) -> dict[str, int]:
    """Re-wrap every DEK not wrapped to the current key (KEK rotation), in batches, one transaction each. Secrets
    wrapped to a key this worker does not hold are counted as ``unknown_key`` and left alone."""
    done = 0
    unknown: set[Any] = set()
    current = store.keyring.current_kek_id
    while True:
        n = 0
        with Session(store.engine) as s, s.begin():
            rows = [
                r
                for r in rows_wrapped_to_other_keys(s, current, batch + len(unknown))
                if r[2] not in unknown
            ]
            for cred_id, destination, secret_id, sealed in rows:
                try:
                    new = store.keyring.rewrap(sealed, credential_context(cred_id, destination))
                except KeyringError:
                    unknown.add(secret_id)
                    continue
                if store_rewrap(s, secret_id, sealed.kek_id, new):
                    n += 1
            if n:
                audit.record(
                    s, action="kek.rewrap", target_type="kek", target_id=current, principal_type="worker",
                    auth_method="none", after={"kek_id": current, "rewrapped": n},
                )  # fmt: skip
        done += n
        if n == 0:
            if unknown:
                log.error("sealed secrets wrapped to a key this worker does not hold",
                          extra={"count": len(unknown)})  # fmt: skip
            return {"rewrapped": done, "unknown_key": len(unknown)}


# --- workflow definitions ---------------------------------------------------------------------------------------


class _OneStep(Step):
    def __init__(self, key: str, work: Callable[[], Mapping[str, int]]) -> None:
        self.key = key  # type: ignore[misc]
        self.work = work

    def probe(self, ctx: StepContext) -> Any:
        return None

    def decide(self, ctx: StepContext, observed: Any) -> Decision:
        return Act({self.key: True})

    def act(self, ctx: StepContext, intent: Mapping[str, Any]) -> None:
        ctx.gate(f"commit:{self.key}")
        counts = dict(self.work())
        ctx.checkpoint(evidence={"counts": counts})

    def verify(self, ctx: StepContext, intent: Mapping[str, Any]) -> Outcome:
        return Done({})


class _OneStepDefinition(WorkflowDefinition):
    version = "1"

    def __init__(self, kind: str, strategy: str, work: Callable[[], Mapping[str, int]]) -> None:
        self.kind, self.strategy = kind, strategy  # type: ignore[misc]
        self._steps = {strategy: _OneStep(strategy, work)}

    @property
    def steps(self) -> Mapping[str, Step]:
        return self._steps

    def admit(self, ctx: TxContext) -> Admission | Reject | Defer:
        return Admission(first_step=StepSpec(self.strategy))

    def next(self, ctx: TxContext, done: Done) -> Transition:
        return Transition(run_state="completed")

    def validate_signal(self, ctx: TxContext) -> str | None:
        return "this job takes no signals"


def validation_definition(validator: CredentialValidator) -> WorkflowDefinition:
    return _OneStepDefinition(VALIDATE_KIND, VALIDATE_STRATEGY, validator.run_once)


def rewrap_definition(store: CredentialStore) -> WorkflowDefinition:
    return _OneStepDefinition(REWRAP_KIND, REWRAP_STRATEGY, lambda: rewrap_all(store))


def validation_job(interval: float) -> PeriodicJob:
    return PeriodicJob(
        kind=VALIDATE_KIND, strategy=VALIDATE_STRATEGY, version="1", interval=interval
    )


def rewrap_job(interval: float) -> PeriodicJob:
    return PeriodicJob(kind=REWRAP_KIND, strategy=REWRAP_STRATEGY, version="1", interval=interval)
