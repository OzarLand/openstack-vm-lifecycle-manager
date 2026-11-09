"""The automation runner: ``prepare_automation`` (once per run) and ``run_phase`` (once per phase attempt).

Flow of ``run_phase`` (automation-contract.md sections 2, 3, 5, 6, 7):

1. validate the request, resolve timeouts ``min(profile, OVLM maximum)``;
2. per-attempt run dir 0700 (tmpfs if available), private copy of the run-level checkout, OVLM-owned
   ``ansible.cfg``, one-host inventory, known_hosts, extra-vars file, secrets as 0600 files (never argv);
3. **fence gate** immediately before the spawn (``Fence.check``), revoke callback registered for the duration;
4. ansible-runner as a supervised subprocess (own process group, PDEATHSIG, separate OS user, scrubbed env);
5. read ``result.json`` with a size cap and strict validation, collect events/stdout, redact, classify;
6. wipe the run dir in ``finally`` (secrets overwritten first).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Container, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from ovlm.automation import checkout as co
from ovlm.automation.classify import RunFacts, classify
from ovlm.automation.hostkeys import (
    PublicKey,
    parse_known_hosts,
    render_known_hosts,
)
from ovlm.automation.lint import (
    Finding,
    Waiver,
    WaiverProvider,
    check_requirements_pinned,
    lint_repo,
)
from ovlm.automation.model import (
    AutomationSpec,
    PhaseOutcome,
    PhaseRequest,
    PreparedAutomation,
    RunnerConfig,
    RunRecord,
)
from ovlm.automation.process import ProcessOutcome, run_supervised, scrubbed_env
from ovlm.automation.redact import Redactor, truncate_head_tail
from ovlm.automation.render import (
    HOST_ALIAS,
    build_extravars,
    connection_vars,
    control_path,
    extravars_digest,
    render_ansible_cfg,
    render_inventory,
)
from ovlm.automation.result import ResultError, ValidatedResult, parse_result
from ovlm.automation.rundir import RunDir, RunUser, processes_referencing
from ovlm.automation.types import (
    KILL_GRACE_SECONDS,
    AutomationError,
    CheckoutUnverifiable,
    Classification,
    Phase,
)

log = logging.getLogger("ovlm.automation.runner")

_MAX_EVENT_FILES = 5000
_MAX_EVENT_BYTES = 256 * 1024
_MAX_SUMMARY = 500
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def roles_search_path(project: Path, playbook_dir: str) -> str:
    """Ansible roles path for a checkout: ``<playbook_dir>/roles``, then the sibling ``<parent>/roles`` (the common
    ``ansible/playbooks`` + ``ansible/roles`` layout), then ``roles`` at the repository root. Duplicates are dropped;
    every entry stays inside the checkout because ``playbook_dir`` is a validated relative path."""
    rel = PurePosixPath(playbook_dir.strip("/"))
    candidates = [rel / "roles"]
    if rel.parent != PurePosixPath("."):
        candidates.append(rel.parent / "roles")
    candidates.append(PurePosixPath("roles"))
    seen: list[str] = []
    for c in candidates:
        path = str(project / c)
        if path not in seen:
            seen.append(path)
    return ":".join(seen)


class FenceLike(Protocol):
    """The part of ``ovlm.workflow.fence.Fence`` the runner uses (structural, no import of the workflow module)."""

    def check(self, action: str) -> None: ...

    def add_revoke_callback(self, cb: Callable[[str], None]) -> Callable[[], None]: ...


def lease_needed(timeout: float) -> float:
    """Seconds a step lease must cover to run one phase: timeout + SIGTERM grace + preparation/collection slack.
    The step handler passes this to ``Fence.set_lease`` (which also demands it exceed ``worker.fence_margin``)."""
    return timeout + KILL_GRACE_SECONDS + 30.0


class AutomationRunner:
    def __init__(self, config: RunnerConfig) -> None:
        self.cfg = config
        self._run_user: RunUser | None = (
            RunUser.lookup(config.run_user) if config.run_user else None
        )
        self._core_version: str | None = None

    # ---- helpers ----------------------------------------------------------------------------------------

    def timeout_for(self, phase: Phase, spec: AutomationSpec) -> int:
        asked = spec.timeouts.get(phase.value)
        base = self.cfg.default_timeout[phase]
        value = base if asked is None else int(asked)
        if value <= 0:
            raise AutomationError("timeouts must be positive")
        return min(value, self.cfg.max_timeout[phase])

    def _bin(self, name: str) -> str:
        path = self.cfg.ansible_bin_dir / name
        if not path.is_file():
            raise AutomationError(f"{name} not found in {self.cfg.ansible_bin_dir}")
        return str(path)

    def ansible_core_version(self) -> str:
        if self._core_version is None:
            try:
                # ansible creates ~/.ansible/tmp even for --version: a throw-away, writable HOME is required for
                # a non-root worker (an unwritable HOME made it crash; root could create it, so tests hid it).
                # Under the run root (a writable tmpfs in the container), not $TMPDIR: the root filesystem is
                # read-only there, so /tmp is not writable (lab bug J).
                tmp_base = self.cfg.run_root if self.cfg.run_root.is_dir() else None
                with tempfile.TemporaryDirectory(
                    prefix="ovlm-ansible-version-", dir=tmp_base
                ) as home:
                    out = subprocess.run(  # noqa: S603
                        [self._bin("ansible"), "--version"],
                        capture_output=True, text=True, timeout=60, check=True,
                        env=scrubbed_env(
                            {"HOME": home, "ANSIBLE_HOME": str(Path(home, ".ansible")),
                             "ANSIBLE_LOCAL_TEMP": str(Path(home, "ansible-local"))},
                            bin_dirs=[self.cfg.ansible_bin_dir],
                        ),
                    ).stdout  # fmt: skip
            except (OSError, subprocess.SubprocessError):
                raise AutomationError("cannot determine the ansible-core version") from None
            m = re.search(r"core ([0-9][0-9A-Za-z.\-]*)", out)
            self._core_version = m.group(1) if m else "unknown"
        return self._core_version

    # ---- once per run: verified clone + blocking lint ---------------------------------------------------

    def prepare_automation(
        self,
        spec: AutomationSpec,
        workflow_id: str,
        *,
        waivers: WaiverProvider | None = None,
        on_waiver: Callable[[Finding, Waiver], None] | None = None,
    ) -> PreparedAutomation:
        """Step ``prepare_automation`` (before the downtime window): the only contact with the git host. With
        ``checkout_cache`` set, the verified checkout is also copied there (worker-only, persistent storage); the
        returned :attr:`~PreparedAutomation.tree_digest` is what B6 records to re-adopt that copy later."""
        dest = self.cfg.run_root / _safe_component(workflow_id) / "_checkout"
        self.cfg.run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest.parent.mkdir(exist_ok=True, mode=0o700)
        if dest.exists():
            co.remove_tree(dest)
        sha = co.clone_verified(spec.repo, spec.ref, dest, self.cfg.clone)
        try:
            self._sha_file(dest).write_text(sha + "\n", encoding="ascii")
            digest = co.tree_digest(dest)
            prepared = self._verify(spec, workflow_id, dest, sha, waivers, on_waiver, digest)
            self._store_in_cache(workflow_id, dest, digest)
            return prepared
        except BaseException:
            co.remove_tree(dest)
            self._sha_file(dest).unlink(missing_ok=True)
            self._drop_cache(workflow_id)
            raise

    @staticmethod
    def _sha_file(dest: Path) -> Path:
        """The verified commit, recorded next to the checkout: ``clone_verified`` drops ``.git``, so the commit
        cannot be read back from the (read-only) tree."""
        return dest.parent / "_checkout.sha"

    # ---- the persistent copy of the checkout (automation.checkout_cache, lab finding Z) ------------------------

    def _cache_root(self) -> Path | None:
        """The cache directory, checked by :func:`check_checkout_cache` (created 0700 with OVLM's marker if missing;
        refused unless the worker user owns it and it holds only OVLM's entries): it must not be shared with
        ``ovlm-ansible`` or anyone else (a copy they could change would be adopted as verified)."""
        root = self.cfg.checkout_cache
        if root is None:
            return None
        check_checkout_cache(root)
        return root

    def _cache_entry(self, workflow_id: str) -> Path | None:
        root = self._cache_root()
        return None if root is None else root / _safe_component(workflow_id)

    def _store_in_cache(self, workflow_id: str, dest: Path, digest: str) -> None:
        """Copy the verified checkout to ``<checkout_cache>/<workflow_id>/_checkout`` (written aside, checked
        against ``digest``, then renamed into place)."""
        entry = self._cache_entry(workflow_id)
        if entry is None:
            return
        entry.mkdir(exist_ok=True, mode=0o700)
        final, tmp = entry / "_checkout", entry / "_checkout.tmp"
        for old in (final, tmp):
            co.remove_tree(old)
        try:
            co.copy_exact(dest, tmp)
            if co.tree_digest(tmp) != digest:
                raise AutomationError(
                    "the cached copy of the checkout differs from the verified checkout",
                    Classification.RETRYABLE,
                )
            tmp.rename(final)
        except OSError as exc:
            co.remove_tree(tmp)
            raise AutomationError(
                f"cannot write the checkout cache: {type(exc).__name__}", Classification.RETRYABLE
            ) from None
        except BaseException:
            co.remove_tree(tmp)
            raise
        os.utime(entry)

    def _drop_cache(self, workflow_id: str) -> None:
        """Remove this run's cached checkout (never fails the caller)."""
        try:
            entry = self._cache_entry(workflow_id)
        except (AutomationError, OSError):
            return
        if entry is not None and entry.exists():
            co.remove_tree(entry)

    def _adopt_from_cache(
        self, spec: AutomationSpec, cached: Path, dest: Path, expected_digest: str | None
    ) -> str:
        """Bring the cached checkout back to ``dest`` (``run_root`` emptied by a container restart). The copy that
        will be used is digested and must equal ``expected_digest``, the digest B6 recorded in the database (outside
        the cache); otherwise nothing is adopted and a human decides. Never contacts the git host."""
        if not expected_digest:
            raise CheckoutUnverifiable(
                "a cached checkout exists but the run has no recorded tree digest to check it against"
            )
        co.validate_sha(spec.ref)
        self.cfg.run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest.parent.mkdir(exist_ok=True, mode=0o700)
        tmp = dest.parent / "_checkout.adopt"
        co.remove_tree(tmp)
        try:
            co.copy_exact(cached, tmp)
            got = co.tree_digest(tmp)
        except (AutomationError, OSError) as exc:
            co.remove_tree(tmp)
            raise AutomationError(
                f"the cached checkout cannot be read back: {exc}", Classification.NEEDS_HUMAN
            ) from None
        if got != expected_digest:
            co.remove_tree(tmp)
            raise CheckoutUnverifiable(
                "the cached checkout does not match the tree digest recorded by prepare_automation "
                "(modified on disk?); not adopted"
            )
        try:
            tmp.rename(dest)
            co.check_tree(dest)
            self._sha_file(dest).write_text(spec.ref + "\n", encoding="ascii")
        except BaseException:
            co.remove_tree(tmp)
            co.remove_tree(dest)
            self._sha_file(dest).unlink(missing_ok=True)
            raise
        log.warning(
            "re-adopted the run's verified checkout from the checkout cache (digest matched)",
            extra={"workflow_id": dest.parent.name},
        )
        return got

    def reverify_checkout(
        self,
        spec: AutomationSpec,
        workflow_id: str,
        *,
        waivers: WaiverProvider | None = None,
        expected_digest: str | None = None,
    ) -> PreparedAutomation | None:
        """Re-verify, locally, the run-level checkout that :meth:`prepare_automation` left (no git host contact).

        * On ``run_root`` (a worker *process* restart): refused (``NEEDS_HUMAN``) when it is not at ``spec.ref`` (the
          commit recorded by ``prepare_automation``) or, given ``expected_digest``, when its tree digest differs.
        * Gone from ``run_root`` (a worker *container* restart emptied the tmpfs) but kept in ``checkout_cache``: the
          copy is adopted only if its digest equals ``expected_digest`` (B6's recorded evidence); a mismatch or no
          expected digest is ``NEEDS_HUMAN``.
        * Neither: ``None``.

        Then the same lint / pin / collection checks as ``prepare_automation`` run and a fresh
        :class:`PreparedAutomation` is returned. Used by the renewal code to adopt a checkout after a crash."""
        dest = self.cfg.run_root / _safe_component(workflow_id) / "_checkout"
        if not dest.is_dir():
            entry = self._cache_entry(workflow_id)
            cached = None if entry is None else entry / "_checkout"
            if cached is None or not cached.is_dir():
                return None
            digest = self._adopt_from_cache(spec, cached, dest, expected_digest)
            return self._verify(spec, workflow_id, dest, spec.ref, waivers, None, digest)
        try:
            head = self._sha_file(dest).read_text(encoding="ascii").strip()
        except (
            OSError
        ):  # a checkout from before the record existed: ask git (works only if .git is present)
            head = co._git(["rev-parse", "HEAD"], dest, self.cfg.clone, retryable=False)  # noqa: SLF001
        if head != spec.ref:
            raise AutomationError(
                "the checkout on disk is not at the pinned SHA", Classification.NEEDS_HUMAN
            )
        digest = co.tree_digest(dest)
        if expected_digest is not None and digest != expected_digest:
            raise CheckoutUnverifiable(
                "the checkout on disk does not match the tree digest recorded by prepare_automation"
            )
        # the same waivers as B6 (SF-13), not audited again: B6 recorded every finding they covered
        return self._verify(spec, workflow_id, dest, head, waivers, None, digest)

    def _verify(
        self,
        spec: AutomationSpec,
        workflow_id: str,
        dest: Path,
        sha: str,
        waivers: WaiverProvider | None,
        on_waiver: Callable[[Finding, Waiver], None] | None,
        tree_digest: str | None = None,
    ) -> PreparedAutomation:
        try:
            lint = lint_repo(dest, spec.playbook_dir, waivers=waivers, on_waiver=on_waiver)
        except ValueError as exc:
            raise AutomationError(f"lint refused the repository layout: {exc}") from None
        if not lint.ok:
            rules = sorted({f.rule for f in lint.blocking})
            raise AutomationError(f"blocking lint findings: {', '.join(rules)}")
        req_path = (dest / spec.requirements).resolve()
        if not req_path.is_relative_to(dest.resolve()):
            raise AutomationError("requirements path escapes the repository")
        problems = check_requirements_pinned(req_path)
        if problems:
            raise AutomationError("unpinned requirements: " + "; ".join(problems))
        req_hash = (
            hashlib.sha256(req_path.read_bytes()).hexdigest() if req_path.is_file() else "none"
        )
        self._check_collections_present(req_path, dest)
        return PreparedAutomation(
            spec=spec,
            workflow_id=workflow_id,
            checkout=dest,
            sha=sha,
            requirements_hash=req_hash,
            ansible_core_version=self.ansible_core_version(),
            lint=lint,
            tree_digest=tree_digest,
        )

    def _collections_search_path(self, checkout: Path) -> list[Path]:
        return [*self.cfg.collections_paths, checkout / "collections"]

    def _check_collections_present(self, req_path: Path, checkout: Path) -> None:
        """The pin check of contract section 2: every pinned collection must already be vendored or shipped at that
        exact version. Nothing is downloaded."""
        if not req_path.is_file():
            return
        from ovlm.automation.lint import load_yaml

        doc = load_yaml(req_path)
        for coll in (doc or {}).get("collections", []) if isinstance(doc, dict) else []:
            entry = coll if isinstance(coll, dict) else {"name": coll}
            name, version = str(entry.get("name", "")), str(entry.get("version", ""))
            if not re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", name):
                raise AutomationError(f"collection name {name!r} is not namespace.name")
            ns, nm = name.split(".")
            found = None
            for base in self._collections_search_path(checkout):
                manifest = base / "ansible_collections" / ns / nm / "MANIFEST.json"
                if manifest.is_file():
                    try:
                        found = json.loads(manifest.read_text())["collection_info"]["version"]
                    except (OSError, ValueError, KeyError):
                        found = None
                    break
            if found != version:
                raise AutomationError(
                    f"collection {name} {version} is not vendored or shipped (found {found!r}); "
                    "Galaxy is never contacted at run time"
                )

    def release(self, prepared: PreparedAutomation) -> None:
        """Remove the run-level checkout and its cached copy (end of the run)."""
        co.remove_tree(prepared.checkout)
        self._sha_file(prepared.checkout).unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            prepared.checkout.parent.rmdir()
        self._drop_cache(prepared.workflow_id)

    # ---- once per phase attempt -------------------------------------------------------------------------

    def run_phase(
        self,
        prepared: PreparedAutomation,
        req: PhaseRequest,
        *,
        fence: FenceLike | None = None,
    ) -> PhaseOutcome:
        spec = prepared.spec
        timeout = self.timeout_for(req.phase, spec)
        idle = min(self.cfg.idle_timeout[req.phase], timeout)
        playbook_rel = f"{spec.playbook_dir.strip('/')}/{req.phase.value}.yml"
        src_playbook = (prepared.checkout / playbook_rel).resolve()
        if (
            not src_playbook.is_relative_to(prepared.checkout.resolve())
            or not src_playbook.is_file()
        ):
            raise AutomationError(f"playbook {playbook_rel} is missing in the repository")

        redactor = Redactor(
            [
                req.ssh_key.value,
                *([req.vault_password.value] if req.vault_password else []),
                *req.extra_secrets,
            ]
        )
        run = RunDir.create(
            self.cfg.run_root,
            req.workflow_id,
            req.step_id,
            req.attempt,
            run_user=self._run_user,
            require_tmpfs=self.cfg.require_tmpfs,
        )
        try:
            return self._run(prepared, req, run, timeout, idle, playbook_rel, redactor, fence)
        finally:
            for pid in processes_referencing(
                run.path
            ):  # stragglers (ansible-playbook outlives a dead runner)
                with contextlib.suppress(OSError):
                    os.kill(pid, 9)
            run.wipe()

    def _run(
        self,
        prepared: PreparedAutomation,
        req: PhaseRequest,
        run: RunDir,
        timeout: int,
        idle: int,
        playbook_rel: str,
        redactor: Redactor,
        fence: FenceLike | None,
    ) -> PhaseOutcome:
        spec = prepared.spec
        p = run.path
        ident = f"{req.phase.value}-{req.attempt}"
        artifacts = run.sub("artifacts") / ident
        result_path = artifacts / "result.json"

        # project: private copy of the verified checkout
        project = run.sub("project")
        shutil.rmtree(project)
        co.copy_for_attempt(prepared.checkout, project)
        run.share_tree(project)

        # secrets: files only
        key_path = run.write_secret(
            # not ``env/ssh_key``: ansible-runner would load that file into its own ssh-agent and keep a copy
            # in the artifacts directory. The key is used by file only (IdentitiesOnly, no agent).
            "env/guest_key",
            _ensure_nl(req.ssh_key.value),
        )
        env_extra: dict[str, str] = {}
        if req.vault_password is not None:
            vp = run.write_secret("env/vault_pass", _ensure_nl(req.vault_password.value))
            env_extra["ANSIBLE_VAULT_PASSWORD_FILE"] = str(vp)

        policy = req.target.host_keys
        known_hosts_text = (
            render_known_hosts(req.target.host, req.target.port, policy.keys)
            if policy.mode == "pinned"
            else ""
        )
        known_hosts = run.write_file("known_hosts", known_hosts_text.encode())
        cp = self._control_path(run)
        conn = connection_vars(req, key_path, known_hosts, cp)
        run.write_file("inventory/hosts.yml", render_inventory(req, conn).encode())
        extravars = build_extravars(
            req,
            result_path,
            inventory_vars=spec.inventory_vars,
            allow_first_use=self.cfg.allow_first_use,
            allow_test_extravars=self.cfg.allow_test_extravars,
        )
        ev_sha, ev_bytes, ev_keys = extravars_digest(extravars)
        run.write_secret("env/extravars", ev_bytes)

        roles = roles_search_path(project, spec.playbook_dir)
        collections = ":".join(str(c) for c in self._collections_search_path(project))
        run.write_file("ansible.cfg", render_ansible_cfg(p, collections, roles).encode())
        run.write_file(
            "env/settings",
            json.dumps(
                {"job_timeout": timeout, "idle_timeout": idle, "suppress_ansible_output": True}
            ).encode(),
        )
        cmdline = ["--check"] if req.check_mode else []
        if spec.store_diffs:
            cmdline.append("--diff")
        argv = [
            self._bin("ansible-runner"), "run", str(p),
            "-p", playbook_rel, "-i", ident, "--omit-env-files", "--rotate-artifacts", "0",
        ]  # fmt: skip
        if cmdline:
            argv.append("--cmdline=" + " ".join(cmdline))  # "=" form: the value starts with "--"
        env = scrubbed_env(
            {
                "HOME": str(run.sub("home")),
                "TMPDIR": str(run.sub("tmp")),
                "ANSIBLE_CONFIG": str(p / "ansible.cfg"),
                "ANSIBLE_HOME": str(run.sub("home") / ".ansible"),
                "ANSIBLE_LOCAL_TEMP": str(run.sub("tmp")),
                "ANSIBLE_COLLECTIONS_PATH": collections,
                "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "false",
                "ANSIBLE_ROLES_PATH": roles,
                "ANSIBLE_HOST_KEY_CHECKING": "True",
                "ANSIBLE_NOCOLOR": "1",
                **env_extra,
            },
            bin_dirs=[self.cfg.ansible_bin_dir],
        )

        # the fence gate: immediately before the spawn (SRE-R-2, SEC-R-26)
        if fence is not None:
            fence.check(f"automation:spawn:{req.phase.value}")
        outcome = run_supervised(
            argv,
            cwd=project,
            env=env,
            out_path=run.sub("tmp") / "runner.out",
            watch_dir=run.sub("artifacts"),
            timeout=timeout
            + 15,  # the runner's own job_timeout fires first and needs no cross-user signal
            idle_timeout=idle + self.cfg.supervisor_slack,
            max_artifact_bytes=self.cfg.max_artifact_bytes,
            run_user=self._run_user,
            signal_prefix=self.cfg.signal_prefix,
            register_revoke=fence.add_revoke_callback if fence is not None else None,
            umask=0o077 if run.owned else 0o007,
        )
        return self._collect(
            prepared, req, run, outcome, artifacts, result_path, ev_sha, ev_keys, redactor
        )

    def _control_path(self, run: RunDir) -> str | None:
        """Per-run ssh ControlPath in a *short* directory (unix socket paths are limited to ~100 bytes), owned by
        the runner user and removed with the run. ``None`` (ControlMaster off) when it would not fit."""
        cp_dir = self.cfg.run_root / ".cp"
        token = hashlib.sha256(str(run.path).encode()).hexdigest()[:8]
        cp = control_path(cp_dir / token)
        if cp is None:
            return None
        cp_dir.mkdir(exist_ok=True, mode=0o700)
        if self._run_user is not None:
            RunDir.allow_traversal(cp_dir, self._run_user, run.owned)
        ctl = cp_dir / token
        ctl.mkdir(mode=0o700)
        run.share_path(ctl)
        run.adopt_dir(ctl)
        return cp

    # ---- step B6 (after G1): contract checks that execute ansible on repo content ------------------------------

    def check_scope(
        self, prepared: PreparedAutomation, req: PhaseRequest, *, fence: FenceLike | None = None
    ) -> list[str]:
        """``ansible-playbook --syntax-check`` and ``--list-hosts`` for every phase playbook, in the same
        containment as a run (separate OS user, scrubbed environment, own process group, timeouts). Returns the
        problems found (empty = every playbook parses and targets exactly the generated one-host inventory).
        These commands execute Ansible on repo content, so they run only here, never at lint/diff/readiness time
        (SEC-R-35); the caller (the B6 step) is responsible for being past G1."""
        spec = prepared.spec
        problems: list[str] = []
        pb_dir = (prepared.checkout / spec.playbook_dir).resolve()
        phases = [p for p in Phase if (pb_dir / f"{p.value}.yml").is_file()]
        if not phases:
            return ["no phase playbook found"]
        run = RunDir.create(
            self.cfg.run_root, req.workflow_id, req.step_id, req.attempt, run_user=self._run_user,
            require_tmpfs=self.cfg.require_tmpfs,
        )  # fmt: skip
        try:
            project = run.sub("project")
            shutil.rmtree(project)
            co.copy_for_attempt(prepared.checkout, project)
            run.share_tree(project)
            known_hosts = run.write_file("known_hosts", b"")
            conn = connection_vars(req, run.sub("env") / "guest_key", known_hosts, None)
            run.write_file("inventory/hosts.yml", render_inventory(req, conn).encode())
            roles = roles_search_path(project, spec.playbook_dir)
            collections = ":".join(str(c) for c in self._collections_search_path(project))
            run.write_file("ansible.cfg", render_ansible_cfg(run.path, collections, roles).encode())
            env = scrubbed_env(
                {
                    "HOME": str(run.sub("home")), "TMPDIR": str(run.sub("tmp")),
                    "ANSIBLE_CONFIG": str(run.path / "ansible.cfg"), "ANSIBLE_HOME": str(run.sub("home") / ".ansible"),
                    "ANSIBLE_LOCAL_TEMP": str(run.sub("tmp")), "ANSIBLE_COLLECTIONS_PATH": collections,
                    "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "false", "ANSIBLE_ROLES_PATH": roles, "ANSIBLE_NOCOLOR": "1",
                },
                bin_dirs=[self.cfg.ansible_bin_dir],
            )  # fmt: skip
            extra = {"ovlm_result_path": str(run.sub("artifacts") / "unused.json")}
            run.write_file("env/extravars", json.dumps(extra).encode())
            for phase in phases:
                rel = f"{spec.playbook_dir.strip('/')}/{phase.value}.yml"
                for mode, flag in (
                    ("syntax-check", "--syntax-check"),
                    ("list-hosts", "--list-hosts"),
                ):
                    if fence is not None:
                        fence.check(f"automation:check_scope:{phase.value}")
                    out_path = run.sub("tmp") / f"{phase.value}.{mode}.out"
                    outcome = run_supervised(
                        [self._bin("ansible-playbook"), "-i", str(run.sub("inventory")), flag, "-e", f"@{run.path}/env/extravars", rel],  # noqa: E501
                        cwd=project, env=env, out_path=out_path, watch_dir=run.sub("artifacts"),
                        timeout=60, idle_timeout=60, max_artifact_bytes=self.cfg.max_artifact_bytes,
                        run_user=self._run_user, signal_prefix=self.cfg.signal_prefix,
                        register_revoke=fence.add_revoke_callback if fence is not None else None,
                        umask=0o077 if run.owned else 0o007,
                    )  # fmt: skip
                    text = _read_text(out_path, 64 * 1024)
                    if outcome.exit_code != 0:
                        problems.append(
                            f"{phase.value}: {mode} failed (exit {outcome.exit_code}, {outcome.reason or 'error'})"
                        )
                    elif mode == "list-hosts":
                        hosts = set(re.findall(r"^\s{2,}(\S+)\s*$", text, re.M))
                        if hosts != {HOST_ALIAS}:
                            problems.append(
                                f"{phase.value}: targets {sorted(hosts)} instead of only the generated host"
                            )
        finally:
            for pid in processes_referencing(run.path):
                with contextlib.suppress(OSError):
                    os.kill(pid, 9)
            run.wipe()
        return problems

    # ---- after the process: untrusted output -> validated record ----------------------------------------

    def _collect(
        self,
        prepared: PreparedAutomation,
        req: PhaseRequest,
        run: RunDir,
        outcome: ProcessOutcome,
        artifacts: Path,
        result_path: Path,
        ev_sha: str,
        ev_keys: list[str],
        redactor: Redactor,
    ) -> PhaseOutcome:
        spec = prepared.spec
        result: ValidatedResult | None = None
        result_error: str | None = None
        raw = _read_bounded(result_path, self.cfg.result_max_bytes)
        if raw is None and self._run_user is not None:
            # Automation content may write result.json readable by the run user only (the reference role did,
            # lab bug K): read it as that user, with the same cap and no symlink following.
            raw = _read_as_run_user(result_path, self.cfg.result_max_bytes, self._run_user)
        if raw is None:
            result_error = "result.json missing"
        else:
            try:
                result = parse_result(raw, req.phase, max_bytes=self.cfg.result_max_bytes)
            except ResultError as exc:
                result_error = exc.reason
        events, summary, unreachable = _read_events(
            artifacts / "job_events", spec.store_diffs, self.cfg.log_max_bytes, redactor
        )
        decision = classify(
            req.phase,
            RunFacts(outcome.exit_code, outcome.timed_out, outcome.killed, unreachable),
            result,
            accept_degraded=spec.accept_degraded,
        )
        stdout = _read_head_tail(artifacts / "stdout", self.cfg.log_max_bytes) + _read_head_tail(
            run.sub("tmp") / "runner.out", self.cfg.log_max_bytes // 5
        )
        log_text, _ = truncate_head_tail(
            redactor.text(_CTRL.sub("", stdout)), self.cfg.log_max_bytes
        )
        diff = None
        if spec.store_diffs:
            diff = "\n".join(_collect_diffs(events))[: self.cfg.log_max_bytes] or None
            diff = redactor.text(diff) if diff else None
        observed: tuple[PublicKey, ...] = ()
        if req.target.host_keys.mode == "tofu":
            observed = tuple(parse_known_hosts(_read_text(run.path / "known_hosts", 65536)))
        record = RunRecord(
            workflow_id=req.workflow_id,
            step_id=req.step_id,
            attempt=req.attempt,
            phase=req.phase.value,
            target_role=req.target.role,
            project_scope=req.project_scope,
            repo=spec.repo,
            sha=prepared.sha,
            requirements_hash=prepared.requirements_hash,
            ansible_core_version=prepared.ansible_core_version,
            extravars_sha256=ev_sha,
            extravars_keys=ev_keys,
            first_use=bool(req.data_volume.first_use) if req.data_volume else None,
            exit_code=outcome.exit_code,
            classification=decision.classification.value,
            reported_classification=decision.reported_classification.value
            if decision.reported_classification
            else None,
            reason=f"{decision.reason} [{outcome.reason}]" if outcome.reason else decision.reason,
            result=redactor.obj(result.as_json()) if result else None,
            result_error=result_error,
            task_summary=summary,
            log=log_text,
            events=events,
            diff=diff,
            duration_seconds=round(outcome.duration, 3),
            host_key_mode=req.target.host_keys.mode,
            lint_digest=prepared.lint.as_json()["digest"],
        )
        return PhaseOutcome(
            decision=decision, result=result, record=record, observed_host_keys=observed
        )


# ---- module-level helpers -------------------------------------------------------------------------------


#: The file OVLM writes at the top of ``automation.checkout_cache`` on first use: the directory is OVLM's (PMR-3).
CACHE_MARKER = ".ovlm-checkout-cache"
#: A canonical run id (the worker's ``workflow_run.id``): the only names of entries the cache sweep may remove.
_RUN_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
#: What a run's cache entry ``<cache>/<run id>/`` holds: the copy, a copy being written, and copies moved aside on a
#: digest mismatch (``_checkout.mismatch-<UTC time>``, PMR-6). Anything else: not an entry OVLM wrote.
_CACHE_ENTRY_PART = re.compile(
    r"_checkout|_checkout\.tmp|_checkout\.mismatch-[0-9]{8}T[0-9]{6}(?:\.[0-9]{1,6})?Z"
)


def is_cache_entry(entry: Path) -> bool:
    """Whether ``entry`` looks like a run entry OVLM wrote in the checkout cache: a real directory named by a
    canonical run id that holds nothing but :data:`_CACHE_ENTRY_PART` names (review PMR-3)."""
    if not _RUN_UUID.fullmatch(entry.name) or entry.is_symlink() or not entry.is_dir():
        return False
    try:
        return all(_CACHE_ENTRY_PART.fullmatch(p.name) for p in entry.iterdir())
    except OSError:
        return False


def check_checkout_cache(root: Path) -> None:
    """Make sure ``automation.checkout_cache`` is OVLM's own directory before anything is written or swept there
    (review PMR-3); the worker calls it at start-up and refuses to start on :class:`AutomationError`.

    * missing: created 0700 (parents too) and :data:`CACHE_MARKER` written;
    * a symlink, not a directory, or not owned by the worker's euid: refused;
    * no marker yet (a cache from before the marker, or a directory an operator named): accepted only if every entry
      in it is a run entry OVLM wrote (:func:`is_cache_entry`) or ``lost+found``, then the marker is written; a directory holding
      anything else (other worker state, credentials) is refused: it is shared, and OVLM would chmod and sweep it;
    * only then is its mode forced to 0700."""
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        st = os.lstat(root)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise AutomationError(
                "automation.checkout_cache is not a directory owned by the worker user",
                Classification.NEEDS_HUMAN,
            )
        marker = root / CACHE_MARKER
        if not marker.is_file() or marker.is_symlink():
            # lost+found: the cache is the root of a filesystem of its own (never swept: not a run id)
            foreign = sorted(
                e.name for e in root.iterdir() if e.name != "lost+found" and not is_cache_entry(e)
            )
            if foreign:
                raise AutomationError(
                    "automation.checkout_cache holds entries OVLM did not write ("
                    + ", ".join(foreign[:5]) + (", ..." if len(foreign) > 5 else "")
                    + "): give the checkout cache a directory of its own",
                    Classification.NEEDS_HUMAN,
                )  # fmt: skip
            marker.unlink(missing_ok=True)
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write("OVLM automation checkout cache: entries are swept by the worker\n")
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.chmod(root, 0o700)
    except OSError as exc:
        raise AutomationError(
            f"automation.checkout_cache is not usable: {type(exc).__name__}",
            Classification.NEEDS_HUMAN,
        ) from None


#: What the run-level checkout leaves in ``<run_root>/<workflow_id>`` (the checkout, its commit record, an adoption
#: in progress). The step run directories next to them belong to the orphan sweeper (``rundir.sweep_orphans``).
_RUN_ROOT_CHECKOUT_PARTS = ("_checkout", "_checkout.sha", "_checkout.adopt")


def _sweepable(
    root: Path,
    max_age: float,
    keep: Container[str],
    terminal: Container[str],
    now: float | None,
) -> list[Path]:
    """The ``<root>/<workflow_id>`` entries the sweep may remove: never a run in ``keep`` (the non-terminal runs);
    a run in ``terminal`` (read terminal in the database; terminal is final) at once; any other (unknown) entry only
    once it was last written more than ``max_age`` seconds ago, so a run admitted after ``keep`` was read is safe."""
    import time

    now = time.time() if now is None else now
    found: list[Path] = []
    if not root.is_dir():
        return found
    for entry in sorted(root.iterdir()):
        if entry.name in keep or entry.is_symlink() or not entry.is_dir():
            continue
        if entry.name not in terminal:
            try:
                age = now - entry.lstat().st_mtime
            except OSError:
                continue
            if age < max_age:
                continue
        found.append(entry)
    return found


def sweep_checkout_cache(
    cache: Path,
    max_age: float,
    *,
    keep: Container[str],
    terminal: Container[str] = (),
    now: float | None = None,
) -> list[Path]:
    """Remove cached checkouts (``<cache>/<workflow_id>``) of runs not in ``keep`` (the non-terminal runs): at once
    for a run in ``terminal``, otherwise once last written more than ``max_age`` seconds ago. Run by the worker at
    start-up, periodically and after a run's last step, so the cache does not grow forever. Returns the removed
    entries.

    Only entries that look like OVLM's run entries are candidates (:func:`is_cache_entry`: a canonical run id holding
    only checkout copies, review PMR-3); anything else in the directory is left alone and logged."""
    removed: list[Path] = []
    foreign: list[str] = []
    for entry in _sweepable(cache, max_age, keep, terminal, now):
        if not is_cache_entry(entry):
            foreign.append(entry.name)
            continue
        co.remove_tree(entry)
        removed.append(entry)
    if foreign:
        log.warning(
            "checkout cache sweep left entries OVLM did not write",
            extra={"count": len(foreign), "entries": foreign[:10]},
        )
    return removed


def sweep_run_root_checkouts(
    run_root: Path,
    max_age: float,
    *,
    keep: Container[str],
    terminal: Container[str] = (),
    now: float | None = None,
) -> list[Path]:
    """The same rules as :func:`sweep_checkout_cache` for the run-level checkouts on ``run_root`` (tmpfs: RAM).
    Only the checkout, its commit record and an interrupted adoption are removed, then ``<run_root>/<workflow_id>``
    if it is left empty; step run directories (secrets, maybe processes) stay with the orphan sweeper. Entries that
    cannot be a workflow id (``.ca``, ``.cp``, ``.ssh-*``) are never touched. Returns the entries whose checkout was
    removed."""
    removed: list[Path] = []
    for entry in _sweepable(run_root, max_age, keep, terminal, now):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", entry.name):
            continue
        parts = [entry / name for name in _RUN_ROOT_CHECKOUT_PARTS]
        if not any(p.exists() or p.is_symlink() for p in parts):
            continue
        for part in parts:
            if part.is_dir() and not part.is_symlink():
                co.remove_tree(part)
            else:
                part.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            entry.rmdir()  # only if empty
        removed.append(entry)
    return removed


def _safe_component(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise AutomationError("invalid workflow id")
    return value


def _ensure_nl(data: bytes) -> bytes:
    return (
        data if data.endswith(b"\n") else data + b"\n"
    )  # OpenSSH rejects a key file without a final newline


def _read_as_run_user(path: Path, cap: int, user: RunUser) -> bytes | None:
    """Read a regular file as the run user (``head -c`` behind a ``test -f && ! test -h`` guard). ``None`` on any
    failure. Only used for the run's own result file, inside the run directory."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv; the path is the run's own result file
            ["/bin/sh", "-c", 'test -f "$1" && ! test -h "$1" && exec head -c "$2" -- "$1"', "ovlm-read",
             str(path), str(cap + 1)],
            user=user.uid, group=user.gid, extra_groups=[],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            capture_output=True, timeout=30, check=False,
        )  # fmt: skip
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _read_bounded(path: Path, cap: int) -> bytes | None:
    """Read a regular file without following symlinks, at most ``cap`` + 1 bytes (the +1 makes oversize visible)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(cap + 1)
    finally:
        os.close(fd)


def _read_head_tail(path: Path, cap: int) -> str:
    """Whole file if it fits in ``cap`` bytes, else its head and tail around a marker (contract section 7). Never
    reads more than ``cap`` bytes, whatever the guest made the file grow to."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return ""
        with os.fdopen(fd, "rb", closefd=False) as fh:
            if st.st_size <= cap:
                return fh.read(cap).decode("utf-8", "replace")
            head_n = cap * 2 // 3
            tail_n = cap - head_n
            head = fh.read(head_n)
            fh.seek(max(st.st_size - tail_n, head_n))
            tail = fh.read(tail_n)
        gap = f"\n[... {st.st_size - len(head) - len(tail)} bytes omitted ...]\n"
        return head.decode("utf-8", "replace") + gap + tail.decode("utf-8", "replace")
    finally:
        os.close(fd)


def _read_text(path: Path, cap: int) -> str:
    raw = _read_bounded(path, cap)
    return "" if raw is None else raw[:cap].decode("utf-8", "replace")


def _task_status(event: str, res: dict[str, Any]) -> str | None:
    return {
        "runner_on_ok": "changed" if res.get("changed") else "ok",
        "runner_on_failed": "failed",
        "runner_on_unreachable": "unreachable",
        "runner_on_skipped": "skipped",
    }.get(event)


def _read_events(
    directory: Path, store_diffs: bool, cap: int, redactor: Redactor
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """(restricted events, per-task summary, saw-unreachable). Events are guest-influenced: size-limited, parsed as
    plain JSON, redacted, diffs removed unless the profile opted in."""
    events: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    unreachable = False
    used = 0
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))[:_MAX_EVENT_FILES]
    except OSError:
        return events, summary, unreachable
    for name in names:
        raw = _read_bounded(directory / name, _MAX_EVENT_BYTES)
        if raw is None or len(raw) > _MAX_EVENT_BYTES:
            continue
        try:
            ev = json.loads(raw)
        except (ValueError, RecursionError):
            continue
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("event", ""))
        data: dict[str, Any] = ev.get("event_data") or {}
        if not isinstance(data, dict):
            data = {}
        res: dict[str, Any] = data.get("res") or {}
        if not isinstance(res, dict):
            res = {}
        status = _task_status(kind, res)
        if status == "unreachable":
            unreachable = True
        if status and len(summary) < _MAX_SUMMARY:
            summary.append(
                {
                    "task": _CTRL.sub("", str(data.get("task", "")))[:200],
                    "host": _CTRL.sub("", str(data.get("host", "")))[:100],
                    "status": status,
                }
            )
        if not store_diffs:
            for holder in (res, data):
                holder.pop("diff", None)
            res.pop("diff_before", None)
        kept: dict[str, Any] = {k: data[k] for k in ("task", "host", "role", "play") if k in data}
        if res:
            kept["res"] = res
        slim: dict[str, Any] = {
            "event": kind[:64],
            "counter": ev.get("counter"),
            "event_data": kept,
        }
        red = redactor.obj(slim)
        size = len(json.dumps(red))
        if used + size > cap:
            events.append({"event": "truncated", "note": "event log capped"})
            break
        used += size
        events.append(red)
    return events, summary, unreachable


def _collect_diffs(events: Sequence[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for ev in events:
        res = ev.get("event_data", {}).get("res", {})
        diff = res.get("diff") if isinstance(res, dict) else None
        if diff:
            out.append(json.dumps(diff))
    return out
