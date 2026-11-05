"""Blocking static lint of the automation repo (automation-contract.md sections 5 and 9, SEC-R-3, SEC-R-35).

**Static analysis only**: YAML parsing and rule matching. No Ansible process is started, no plugin loaded and no
Jinja evaluated (templates are only scanned as text for identifiers). The YAML loader is ``SafeLoader`` plus
``!vault``/``!unsafe`` read as plain strings: no Python tags, no object construction.

Rules (id: meaning). Findings of severity ``error`` block profile validation and the run-time re-lint unless an
approver granted an audited waiver (:class:`WaiverProvider`); the audit hook is called for every applied waiver.

* ``no_log_secret``    a task whose module args or task vars use secret-like names (vault, password, token,
                       key, secret, ...) or template a secret-like variable, without ``no_log: true``;
* ``hosts_pattern``    a play whose ``hosts`` is not exactly ``ovlm_target``;
* ``check_mode_forced`` ``check_mode: false`` or ``always_run`` (defeats the read-only guarantee of ``--check``);
* ``delegate_to``      ``delegate_to``/``local_action`` reachable from ``configure.yml`` (work must run on the
                       target); ``connection: local`` anywhere. Tasks that only write ``ovlm_result_path`` on the
                       controller are the one exempt pattern (the reference result writer);
* ``formatting``       mkfs/wipefs/dd/parted/... or a filesystem/partition module (data_attach rule 6 and beyond);
* ``ignore_errors``    ``ignore_errors`` in a data phase (error) or elsewhere (warning);
* ``ssh_override``     playbook-level ``ansible_ssh_*`` variables or agent forwarding (``-A``, ``ForwardAgent``);
* ``quiesce_state``    quiesce editing fstab, removing a mount entry or disabling a unit (contract 3.4);
* ``templated_task_name`` (warning) a templated task name hides what runs;
* ``unresolved_include`` (warning) a templated role/include cannot be followed statically;
* ``parse_error``      a YAML file that does not parse or is too large.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import shlex
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol

import yaml

from ovlm.automation.types import Phase

MAX_YAML_BYTES = 1024 * 1024
MAX_FILES = 2000
Severity = Literal["error", "warning"]

_RESULT_VAR = "ovlm_result_path"
_SECRET_TOKENS = frozenset(
    {"vault", "password", "passwd", "passphrase", "token", "secret", "secrets", "key", "credential", "credentials", "apikey"}
)  # fmt: skip
_NOT_SECRET_TOKENS = frozenset(
    {"public", "pub", "pubkey", "file", "path", "name", "fingerprint", "id", "length", "ttl", "dir"}
)
_FORMAT_RE = re.compile(
    r"\b(mkfs(?:\.\w+)?|wipefs|sgdisk|sfdisk|mklabel|blkdiscard|mkswap)\b|\bdd\s+(?:if|of)=|\bparted\b"
)
_FORMAT_MODULES = frozenset(
    {"filesystem", "parted", "lvg", "lvol", "lvm", "mkfs", "wipefs"}
)  # short names, collection prefix stripped
_TASK_KEYWORDS = frozenset(
    {
        "name", "when", "vars", "tags", "register", "become", "become_user", "become_method", "become_flags",
        "no_log", "delegate_to", "delegate_facts", "check_mode", "ignore_errors", "ignore_unreachable", "loop",
        "loop_control", "until", "retries", "delay", "changed_when", "failed_when", "environment", "args", "notify",
        "listen", "run_once", "connection", "module_defaults", "collections", "any_errors_fatal", "throttle",
        "timeout", "diff", "async", "poll", "always_run", "remote_user", "port", "block", "rescue", "always",
        "action", "local_action", "debugger", "vars_files", "max_fail_percentage",
    }
)  # fmt: skip
_CONNECTION_KEYS = frozenset(
    {
        "ansible_host",
        "ansible_port",
        "ansible_user",
        "ansible_connection",
        "ansible_private_key_file",
    }
)
_PHASE_FILES = {p: f"{p.value}.yml" for p in Phase}
_TEMPLATE_RE = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# ---- YAML (safe, with line numbers) -----------------------------------------------------------------------


class _Line(dict):  # type: ignore[type-arg]
    line: int = 0


class _Loader(yaml.SafeLoader):
    pass


def _construct_map(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    mapping = _Line(loader.construct_mapping(node, deep=True))
    mapping.line = node.start_mark.line + 1
    return mapping


_Loader.add_constructor("tag:yaml.org,2002:map", _construct_map)


def _plain(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    return loader.construct_scalar(node)  # type: ignore[arg-type]


_Loader.add_constructor("!vault", _plain)
_Loader.add_constructor("!unsafe", _plain)


def load_yaml(path: Path) -> Any:
    if path.stat().st_size > MAX_YAML_BYTES:
        raise ValueError("file larger than the lint limit")
    with path.open("rb") as fh:
        return yaml.load(fh, Loader=_Loader)  # noqa: S506 - SafeLoader subclass, see class docstring


# ---- results ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    path: str
    line: int
    message: str
    waived_by: str | None = None

    def as_json(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass(frozen=True)
class Waiver:
    """An approver's audited, per-profile exception (recorded with the profile version by the caller)."""

    id: str
    rule: str
    path_glob: str  # fnmatch pattern on the repo-relative path; "*" waives the rule everywhere
    approver: str
    reason: str


class WaiverProvider(Protocol):
    def find(self, rule: str, path: str) -> Waiver | None: ...


@dataclass(frozen=True)
class StaticWaivers:
    """In-memory provider (tests, and the worker once it loaded the profile version's ``lint_waiver`` rows)."""

    waivers: tuple[Waiver, ...] = ()

    def find(self, rule: str, path: str) -> Waiver | None:
        for w in self.waivers:
            if w.rule == rule and fnmatch.fnmatchcase(path, w.path_glob):
                return w
        return None


@dataclass
class LintResult:
    findings: list[Finding] = field(default_factory=list)
    files_checked: int = 0

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error" and f.waived_by is None]

    @property
    def waived(self) -> list[Finding]:
        return [f for f in self.findings if f.waived_by is not None]

    @property
    def ok(self) -> bool:
        return not self.blocking

    def as_json(self) -> dict[str, Any]:
        doc = {
            "ok": self.ok,
            "files_checked": self.files_checked,
            "findings": [f.as_json() for f in self.findings],
        }
        doc["digest"] = hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
        return doc


# ---- task model -------------------------------------------------------------------------------------------


@dataclass
class _Task:
    path: str
    line: int
    data: dict[str, Any]
    no_log: bool
    module: str | None
    in_play_vars: bool = False


def _is_true(value: Any) -> bool:
    return value is True or (
        isinstance(value, str) and value.strip().lower() in {"true", "yes", "on", "1"}
    )


def _is_false(value: Any) -> bool:
    return value is False or (
        isinstance(value, str) and value.strip().lower() in {"false", "no", "off", "0"}
    )


def _module_of(task: dict[str, Any]) -> str | None:
    for key in task:
        if key not in _TASK_KEYWORDS and not str(key).startswith("with_"):
            return str(key)
    if "action" in task:
        return "action"
    return None


def _walk_tasks(items: Any, path: str, inherited_no_log: bool) -> Iterator[_Task]:
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        no_log = inherited_no_log or _is_true(item.get("no_log"))
        if any(k in item for k in ("block", "rescue", "always")):
            for sect in ("block", "rescue", "always"):
                yield from _walk_tasks(item.get(sect), path, no_log)
            # keywords on the block itself (check_mode, delegate_to, ...) are checked as a pseudo-task
            yield _Task(path, getattr(item, "line", 0), item, no_log, None)
            continue
        yield _Task(path, getattr(item, "line", 0), item, no_log, _module_of(item))


# ``check_mode: false`` is accepted only on a task that is read-only by construction (automation-contract.md s.9):
# a read-only module, or ``command`` (never ``shell``) whose program is on this list, with ``changed_when: false``.
# Everything else that forces itself to run in check mode stays an error.
_READ_ONLY_MODULES = frozenset({"stat", "find", "slurp", "setup", "wait_for", "getent"})
_READ_ONLY_PROGRAMS = frozenset(
    {"mountpoint", "findmnt", "blkid", "readlink", "id", "df", "fuser", "which", "lsblk"}
)
_URI_WRITE_ARGS = frozenset({"body", "src", "dest", "creates", "removes", "unix_socket"})


def _short_module(module: str | None) -> str | None:
    if module is None:
        return None
    for prefix in ("ansible.builtin.", "ansible.legacy."):
        if module.startswith(prefix):
            return module[len(prefix) :]
    return None if "." in module else module


def _command_argv(args: Any) -> list[str] | None:
    raw: Any = args
    if isinstance(args, dict):
        if isinstance(args.get("argv"), list):
            return [str(a) for a in args["argv"]]
        raw = args.get("cmd")
    if not isinstance(raw, str):
        return None
    try:
        return shlex.split(raw)
    except ValueError:
        return None


def _read_only_probe(t: _Task) -> bool:
    data, module = t.data, _short_module(t.module)
    if module is None or "always_run" in data:
        return False
    args = data.get(t.module) if t.module else None
    if module in _READ_ONLY_MODULES:
        return True
    if module == "uri":
        if not isinstance(args, dict) or _URI_WRITE_ARGS & set(args):
            return False
        method = str(args.get("method", "GET")).upper()
        return method in {"GET", "HEAD"}
    if module != "command" or not _is_false(data.get("changed_when")):
        return False
    argv = _command_argv(args)
    if not argv or "{{" in argv[0] or "{%" in argv[0]:
        return False
    prog = argv[0].rsplit("/", 1)[-1]
    rest = argv[1:]
    if prog in _READ_ONLY_PROGRAMS:
        return True
    if prog == "e2fsck":  # -n opens read-only and answers "no"; refuse any repair flag
        return "-n" in rest and not {"-p", "-a", "-y", "-D", "-E"} & set(rest)
    if prog == "start-stop-daemon":
        return "--status" in rest and not {"--start", "--stop", "-S", "-K"} & set(rest)
    return False


def _strings(value: Any, seen: set[int] | None = None) -> Iterator[str]:
    seen = set() if seen is None else seen
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict | list):
        if id(value) in seen:
            return
        seen.add(id(value))
        items = value.values() if isinstance(value, dict) else value
        for v in items:
            yield from _strings(v, seen)


def _keys(value: Any, seen: set[int] | None = None) -> Iterator[str]:
    seen = set() if seen is None else seen
    if isinstance(value, dict):
        if id(value) in seen:
            return
        seen.add(id(value))
        for k, v in value.items():
            yield str(k)
            yield from _keys(v, seen)
    elif isinstance(value, list):
        if id(value) in seen:
            return
        seen.add(id(value))
        for v in value:
            yield from _keys(v, seen)


def _is_connection_key(key: str) -> bool:
    return key.startswith("ansible_ssh_") or key in _CONNECTION_KEYS


def _secret_like(identifier: str) -> bool:
    tokens = set(re.split(r"[^a-z0-9]+", re.sub(r"(?<=[a-z])(?=[A-Z])", "_", identifier).lower()))
    tokens.discard("")
    if "api" in tokens and "key" in tokens:
        tokens.add("apikey")
    return bool(tokens & _SECRET_TOKENS) and not (tokens & _NOT_SECRET_TOKENS)


def _templated_secret(text: str) -> bool:
    for expr in _TEMPLATE_RE.findall(text):
        for m in _WORD_RE.finditer(expr):
            word = m.group(0)
            # ``item.key`` (dict2items) is an attribute named key, not a secret; other attributes still count.
            if word == "key" and m.start() > 0 and expr[m.start() - 1] == ".":
                continue
            if _secret_like(word):
                return True
    return False


def _task_args(t: _Task) -> list[Any]:
    out: list[Any] = []
    if t.module is not None:
        out.append(t.data.get(t.module))
    if "args" in t.data:
        out.append(t.data["args"])
    for kw in ("local_action", "action"):
        if kw in t.data:
            out.append(t.data[kw])
    return out


def _writes_result_only(t: _Task) -> bool:
    """The exempt pattern: a controller-side task that writes the ovlm.result/1 file."""
    deleg = t.data.get("delegate_to")
    if deleg not in ("localhost", "127.0.0.1"):
        return False
    text = " ".join(s for a in _task_args(t) for s in _strings(a))
    return _RESULT_VAR in text


# ---- the linter -------------------------------------------------------------------------------------------


class _Linter:
    def __init__(
        self,
        root: Path,
        playbook_dir: str,
        waivers: WaiverProvider | None,
        on_waiver: Callable[[Finding, Waiver], None] | None,
    ) -> None:
        self.root = root.resolve()
        self.pb_dir = self._safe(playbook_dir)
        self.waivers, self.on_waiver = waivers, on_waiver
        self.result = LintResult()
        self._cache: dict[Path, Any] = {}
        self._seen_findings: set[tuple[str, str, int, str]] = set()

    def _safe(self, rel: str) -> Path:
        p = (self.root / rel).resolve()
        if not p.is_relative_to(self.root):
            raise ValueError("path escapes the repository")
        return p

    def rel(self, p: Path) -> str:
        return str(PurePosixPath(p.resolve().relative_to(self.root)))

    # findings
    def add(self, rule: str, severity: Severity, path: str, line: int, message: str) -> None:
        key = (rule, path, line, message)
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        waiver = self.waivers.find(rule, path) if (self.waivers and severity == "error") else None
        finding = Finding(
            rule, severity, path, line, message, waived_by=waiver.id if waiver else None
        )
        self.result.findings.append(finding)
        if waiver and self.on_waiver:
            self.on_waiver(finding, waiver)

    def load(self, path: Path) -> Any:
        if path in self._cache:
            return self._cache[path]
        doc: Any = None
        if self.result.files_checked >= MAX_FILES:
            self.add("parse_error", "error", self.rel(path), 0, "too many files")
        else:
            self.result.files_checked += 1
            try:
                doc = load_yaml(path)
            except (yaml.YAMLError, ValueError, OSError) as exc:
                self.add(
                    "parse_error", "error", self.rel(path), 0, f"cannot parse: {type(exc).__name__}"
                )
        self._cache[path] = doc
        return doc

    # role / include resolution (literal names only)
    def role_dirs(self, name: str) -> list[Path]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            return []
        # Same search order as the runner's roles path: <playbook_dir>/roles, the sibling <parent>/roles (only when
        # the parent is still inside the repository), then roles/ at the root.
        bases = [self.pb_dir / "roles"]
        if self.pb_dir != self.root and self.pb_dir.parent.is_relative_to(self.root):
            bases.append(self.pb_dir.parent / "roles")
        bases.append(self.root / "roles")
        out: list[Path] = []
        for base in bases:
            d = base / name
            if d.is_dir() and d not in out:
                out.append(d)
        return out

    def role_files(self, role: Path) -> list[Path]:
        files: list[Path] = []
        for sub in ("tasks", "handlers"):
            base = role / sub
            if base.is_dir():
                files += sorted(
                    p for p in base.rglob("*.y*ml") if p.is_file() and not p.is_symlink()
                )
        return files

    def reachable(self, playbook: Path, phase: Phase) -> Iterator[tuple[str, list[_Task]]]:
        """Yield (relative path, tasks) for the playbook and every role/include statically reachable from it."""
        todo: list[tuple[Path, bool]] = [(playbook, True)]
        seen: set[Path] = set()
        while todo:
            path, is_playbook = todo.pop()
            if path in seen:
                continue
            seen.add(path)
            doc = self.load(path)
            rel = self.rel(path)
            tasks: list[_Task] = []
            if is_playbook:
                plays = doc if isinstance(doc, list) else []
                for play in plays:
                    if not isinstance(play, dict):
                        continue
                    self.check_play(play, rel, phase)
                    play_no_log = _is_true(play.get("no_log"))
                    for sect in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                        tasks += list(_walk_tasks(play.get(sect), rel, play_no_log))
                    for role in play.get("roles") or []:
                        name = (
                            role.get("role") or role.get("name") if isinstance(role, dict) else role
                        )
                        self.follow_role(name, rel, getattr(play, "line", 0), todo)
            elif isinstance(doc, list):
                tasks = list(_walk_tasks(doc, rel, False))
            for t in tasks:
                self.follow_includes(t, path, todo)
            yield rel, tasks

    def follow_role(self, name: Any, rel: str, line: int, todo: list[tuple[Path, bool]]) -> None:
        if not isinstance(name, str) or "{{" in name:
            self.add(
                "unresolved_include", "warning", rel, line, "templated role name cannot be linted"
            )
            return
        dirs = self.role_dirs(name)
        if not dirs:
            self.add(
                "unresolved_include", "warning", rel, line, f"role {name!r} not found in the repo"
            )
        for d in dirs:
            todo.extend((f, False) for f in self.role_files(d))

    def follow_includes(self, t: _Task, current: Path, todo: list[tuple[Path, bool]]) -> None:
        mod = (t.module or "").rsplit(".", 1)[-1]
        arg = t.data.get(t.module) if t.module else None
        if mod in {"include_role", "import_role"} and isinstance(arg, dict):
            self.follow_role(arg.get("name"), t.path, t.line, todo)
        elif mod in {"include_tasks", "import_tasks"}:
            target = arg.get("file") if isinstance(arg, dict) else arg
            if isinstance(target, str) and "{{" not in target:
                p = (current.parent / target).resolve()
                if p.is_relative_to(self.root) and p.is_file() and not p.is_symlink():
                    todo.append((p, False))
                    return
            self.add(
                "unresolved_include",
                "warning",
                t.path,
                t.line,
                "include cannot be followed statically",
            )

    # play-level rules
    def check_play(self, play: dict[str, Any], rel: str, phase: Phase) -> None:
        line = getattr(play, "line", 0)
        if play.get("hosts") != "ovlm_target":
            self.add("hosts_pattern", "error", rel, line, "hosts must be exactly 'ovlm_target'")
        if str(play.get("connection", "")).strip() == "local":
            self.add("delegate_to", "error", rel, line, "connection: local runs on the worker host")
        for key in _keys(play.get("vars") or {}):
            if key.startswith("ansible_ssh_") or key in {
                "ansible_ssh_common_args",
                "ansible_ssh_extra_args",
            }:
                self.add("ssh_override", "error", rel, line, f"playbook-level {key}")

    # task-level rules
    def check_task(self, t: _Task, phase: Phase) -> None:
        data = t.data
        data_phase = phase in (Phase.QUIESCE, Phase.DATA_ATTACH, Phase.ROLLBACK_HOOKS)
        result_writer = _writes_result_only(t)
        name = data.get("name")
        if isinstance(name, str) and "{{" in name:
            self.add("templated_task_name", "warning", t.path, t.line, "task name is templated")

        # no_log on secret-like args
        if t.module is not None and not t.no_log:
            hit = None
            scan = [*_task_args(t), data.get("vars") or {}]
            for obj in scan:
                for key in _keys(obj):
                    if _secret_like(key):
                        hit = f"secret-like name {key!r}"
                        break
                if hit is None:
                    for s in _strings(obj):
                        if _templated_secret(s):
                            hit = "templates a secret-like variable"
                            break
                if hit:
                    break
            if hit:
                self.add("no_log_secret", "error", t.path, t.line, f"{hit} without no_log: true")

        # check_mode / always_run
        forced = ("check_mode" in data and _is_false(data["check_mode"])) or "always_run" in data
        if forced and not result_writer and not _read_only_probe(t):
            self.add(
                "check_mode_forced",
                "error",
                t.path,
                t.line,
                "task forces itself to run in check mode",
            )

        # delegate_to / local_action (configure.yml reachable code; local connection is play-level)
        away = "local_action" in data or "delegate_to" in data
        if phase is Phase.CONFIGURE and away and not result_writer:
            self.add(
                "delegate_to", "error", t.path, t.line, "delegate_to/local_action in configure"
            )

        # ignore_errors
        if _is_true(data.get("ignore_errors")):
            self.add(
                "ignore_errors",
                "error" if data_phase else "warning",
                t.path,
                t.line,
                "ignore_errors: true",
            )

        if t.module is not None and t.module.rsplit(".", 1)[-1] == "add_host":
            self.add(
                "ssh_override",
                "error",
                t.path,
                t.line,
                "add_host adds targets outside the inventory",
            )

        # formatting / wiping
        if t.module is not None:
            short = t.module.rsplit(".", 1)[-1]
            if short in _FORMAT_MODULES:
                self.add(
                    "formatting",
                    "error",
                    t.path,
                    t.line,
                    f"module {t.module} formats or partitions",
                )
            for obj in _task_args(t):
                for s in _strings(obj):
                    if _FORMAT_RE.search(s):
                        self.add("formatting", "error", t.path, t.line, "formatting/wiping command")
                        break

        # ssh overrides, agent forwarding
        for obj in [*_task_args(t), data.get("vars") or {}, data.get("environment") or {}]:
            for key in _keys(obj):
                if _is_connection_key(key):
                    self.add("ssh_override", "error", t.path, t.line, f"task-level {key}")
            for s in _strings(obj):
                if re.search(r"ForwardAgent|(?<![\w-])-A(?![\w-])", s):
                    self.add("ssh_override", "error", t.path, t.line, "agent forwarding")

        # quiesce state edits (contract 3.4)
        if phase is Phase.QUIESCE and t.module is not None:
            short = t.module.rsplit(".", 1)[-1]
            args = data.get(t.module)
            args = args if isinstance(args, dict) else {}
            text = " ".join(s for a in _task_args(t) for s in _strings(a))
            if short in {"lineinfile", "replace", "blockinfile"} and "fstab" in text:
                self.add("quiesce_state", "error", t.path, t.line, "quiesce edits fstab")
            if short == "mount" and str(args.get("state")) == "absent":
                self.add("quiesce_state", "error", t.path, t.line, "quiesce removes a mount entry")
            if short in {"systemd", "systemd_service", "service"} and _is_false(
                args.get("enabled")
            ):
                self.add("quiesce_state", "error", t.path, t.line, "quiesce disables a unit")

    def check_vars_files(self) -> None:
        """group_vars/host_vars files next to the playbooks or at the repo root: connection variables there would
        steer where OVLM's run connects (inventory host vars win over them, but the intent is still refused)."""
        for base in {self.pb_dir, self.root}:
            for sub in ("group_vars", "host_vars"):
                d = base / sub
                if not d.is_dir():
                    continue
                for f in sorted(p for p in d.rglob("*") if p.is_file() and not p.is_symlink()):
                    if f.suffix not in {".yml", ".yaml", ""}:
                        continue
                    doc = self.load(f)
                    for key in _keys(doc):
                        if _is_connection_key(key):
                            self.add(
                                "ssh_override", "error", self.rel(f), 0, f"vars file sets {key}"
                            )

    def run(self) -> LintResult:
        if not self.pb_dir.is_dir():
            self.add("parse_error", "error", str(self.pb_dir.name), 0, "playbook_dir not found")
            return self.result
        self.check_vars_files()
        for phase, fname in _PHASE_FILES.items():
            playbook = self.pb_dir / fname
            if not playbook.is_file() or playbook.is_symlink():
                continue
            for _rel, tasks in self.reachable(playbook, phase):
                for t in tasks:
                    self.check_task(t, phase)
        return self.result


def lint_repo(
    root: Path,
    playbook_dir: str = "playbooks",
    *,
    waivers: WaiverProvider | None = None,
    on_waiver: Callable[[Finding, Waiver], None] | None = None,
) -> LintResult:
    """Lint the phase playbooks under ``root/playbook_dir`` and the roles they reach.

    ``on_waiver(finding, waiver)`` is the audit hook: called once per finding a waiver covered, so the caller
    can append the audit row (the lint itself touches no database).
    """
    return _Linter(root, playbook_dir, waivers, on_waiver).run()


# ---- requirements pin check (contract section 1/2: a pin check, not an install) ---------------------------

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_EXACT_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+.][0-9A-Za-z.-]+)?$")


def check_requirements_pinned(path: Path) -> list[str]:
    """Return problems: every collection needs an exact ``version``; every role from git needs a full SHA."""
    if not path.is_file():
        return []
    try:
        doc = load_yaml(path)
    except (yaml.YAMLError, ValueError, OSError):
        return ["requirements file cannot be parsed"]
    problems: list[str] = []
    if isinstance(doc, list):  # legacy roles-only format
        doc = {"roles": doc}
    if not isinstance(doc, dict):
        return ["requirements file is not a mapping"]
    for coll in doc.get("collections") or []:
        entry = coll if isinstance(coll, dict) else {"name": coll}
        version = entry.get("version")
        if not isinstance(version, str) or not _EXACT_VERSION_RE.match(version):
            problems.append(f"collection {entry.get('name', '?')}: version is not an exact pin")
    for role in doc.get("roles") or []:
        entry = role if isinstance(role, dict) else {"name": role}
        version = entry.get("version")
        if "src" in entry and not (isinstance(version, str) and _SHA_RE.match(version)):
            problems.append(
                f"role {entry.get('name') or entry.get('src')}: git role needs a full commit SHA"
            )
        elif "src" not in entry and not (
            isinstance(version, str)
            and (_EXACT_VERSION_RE.match(version) or _SHA_RE.match(version))
        ):
            problems.append(f"role {entry.get('name', '?')}: version is not an exact pin")
    return problems
