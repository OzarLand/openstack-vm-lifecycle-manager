"""Roadmap P0-4: every result field OVLM reads is pinned to the contract and to the reference roles' real output.

Defect AB (``marker_checksum`` read, ``marker_sha256`` emitted) was found only in the lab because nothing tied the
names OVLM reads to what a playbook writes. This test closes that class for every field, statically (no Ansible run):

* **OVLM's reads** are found by parsing ``src/ovlm`` (``<x>.facts.get(K)``, ``<x>.facts[K]``, and reads of facts kept
  in step evidence, ``ev.get("facts").get(K)``). Each read is attributed to a phase: the ``phase`` class attribute of
  the step it sits in, or :data:`READ_SITES` for a function. A read the test cannot attribute fails, so a new read
  site cannot slip past.
* **The contract** is the facts table of automation-contract 3.7.1, parsed from the document.
* **The reference workload's output** is the ``ovlm_facts`` of the phase playbook and of every role and task file it
  includes (followed recursively), plus the keys the shared result writer adds.
* **The renewal doubles** (``tests/integration/renewal/doubles.py`` and ``production_doubles.py``) may report only
  keys the contract defines for that phase: a double with its own spelling would hide a mismatch, as it did for AB.

It also ties the top-level fields, the ``checks[]`` fields and the classification values to the parser and to the
reference result writer. Defect AD (S2 read ``marker_checksum``) was found by this test; its behaviour is pinned below.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml

from ovlm.automation import result as result_mod
from ovlm.automation.types import Classification, Phase
from ovlm.workflow.contract import StepContext

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "ovlm"
ANSIBLE = ROOT / "ansible"
PLAYBOOKS = ANSIBLE / "playbooks"
ROLES = ANSIBLE / "roles"
CONTRACT = ROOT / "docs" / "automation-contract.md"
DOUBLES = [
    ROOT / "tests" / "integration" / "renewal" / "doubles.py",
    ROOT / "tests" / "integration" / "renewal" / "production_doubles.py",
]
ALL = "*"

#: Read sites outside a step class with a ``phase`` attribute: qualified function name -> phase whose result it reads.
READ_SITES: dict[str, str] = {
    "ovlm.automation.classify._healthcheck": "healthcheck",  # accept_degraded (contract 3.6)
    "ovlm.renewal.steps_window.w1_marker": "quiesce",  # W1's stored quiesce facts (fallback for older runs)
}

#: Keys OVLM reads that the reference workload does not report. Only for a key the contract table marks "optional",
#: with the reason here. Empty today: the reference roles report every key OVLM reads.
OPTIONAL_NOT_EMITTED: dict[tuple[str, str], str] = {}


# --- the contract ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    phase: str
    key: str
    requirement: str
    read_by: str

    @property
    def optional(self) -> bool:
        return self.requirement.startswith("optional")

    @property
    def read(self) -> bool:
        return self.read_by != "none"


def contract_rows() -> list[Row]:
    text = CONTRACT.read_text()
    start = text.index("#### 3.7.1 Facts per phase")
    section = text[start : text.index("\n### ", start)]
    rows = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not cells[0].startswith("`"):
            continue
        rows.append(Row(cells[0].strip("`"), cells[1].strip("`"), cells[2], cells[3]))
    assert rows, "no facts table in contract 3.7.1"
    return rows


def contract_keys(phase: str) -> dict[str, Row]:
    return {r.key: r for r in contract_rows() if r.phase in (phase, ALL)}


def contract_example() -> dict[str, Any]:
    text = CONTRACT.read_text()
    section = text[text.index("### 3.7 Result JSON") :]
    block = re.search(r"```json\n(.*?)```", section, re.S)
    assert block, "no result.json example in contract 3.7"
    return dict(json.loads(block.group(1)))


# --- OVLM's reads ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Read:
    phase: str | None
    key: str
    where: str  # module:line (qualified name)


def _is_facts(node: ast.AST) -> bool:
    """``<x>.facts``, or facts kept in evidence: ``<x>.get("facts")``, ``<x>["facts"]``, either ``or {}``."""
    if isinstance(node, ast.BoolOp):
        return _is_facts(node.values[0])
    if isinstance(node, ast.Attribute):
        return node.attr == "facts"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
    ):
        return bool(node.args) and bool(_const(node.args[0]) == "facts")
    if isinstance(node, ast.Subscript):
        return bool(_const(node.slice) == "facts")
    return False


def _const(node: ast.AST) -> Any:
    return node.value if isinstance(node, ast.Constant) else None


class _Reads(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module = module
        self.mod: Any = None
        self.scope: list[tuple[str, str | None]] = []  # (name, phase of a class body)
        self.reads: list[Read] = []

    def _key(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):  # a module constant such as MARKER_FACT
            self.mod = self.mod or importlib.import_module(self.module)
            value = getattr(self.mod, node.id)
            assert isinstance(value, str), (self.module, node.id)
            return value
        line = getattr(node, "lineno", "?")
        raise AssertionError(f"{self.module}:{line}: facts key is not a literal or a constant")

    def _record(self, key_node: ast.AST, line: int) -> None:
        qual = ".".join([self.module, *(n for n, _ in self.scope)])
        phase = next((p for _, p in reversed(self.scope) if p), None) or READ_SITES.get(qual)
        self.reads.append(Read(phase, self._key(key_node), f"{qual}:{line}"))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        phase = None
        for stmt in node.body:
            if (
                isinstance(stmt, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "phase" for t in stmt.targets)
                and isinstance(_const(stmt.value), str)
            ):
                phase = _const(stmt.value)
        self.scope.append((node.name, phase))
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope.append((node.name, None))
        self.generic_visit(node)
        self.scope.pop()

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "get" and node.args and _is_facts(f.value):
            self._record(node.args[0], node.lineno)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _is_facts(node.value) and isinstance(node.ctx, ast.Load):
            self._record(node.slice, node.lineno)
        self.generic_visit(node)


def ovlm_reads() -> list[Read]:
    reads: list[Read] = []
    for path in sorted(SRC.rglob("*.py")):
        module = ".".join(path.relative_to(SRC.parent).with_suffix("").parts)
        visitor = _Reads(module)
        visitor.visit(ast.parse(path.read_text(), str(path)))
        reads += visitor.reads
    return reads


# --- the reference workload's output --------------------------------------------------------------------------------


def _tasks(tasks: Any) -> Iterator[dict[str, Any]]:
    for task in tasks or []:
        yield task
        for part in ("block", "rescue", "always"):
            yield from _tasks(task.get(part))


def _facts_in(value: Any) -> set[str]:
    """Keys of an ``ovlm_facts`` value: a literal dict, or a ``combine({...})`` expression."""
    if isinstance(value, dict):
        return set(value)
    if isinstance(value, str):
        return set(re.findall(r"'([a-z_0-9]+)':", value))
    return set()


def _emitted(path: Path, seen: set[Path]) -> set[str]:
    if path in seen:
        return set()
    seen.add(path)
    keys: set[str] = set()
    doc = yaml.safe_load(path.read_text())
    plays = doc if doc and "hosts" in doc[0] else [{"tasks": doc}]
    for play in plays:
        for task in _tasks(play.get("tasks")):
            keys |= _facts_in((task.get("ansible.builtin.set_fact") or {}).get("ovlm_facts"))
            inc = task.get("ansible.builtin.include_role") or task.get(
                "ansible.builtin.import_role"
            )
            if (
                inc and inc["name"] != "ovlm_result"
            ):  # the writer's own keys are added by writer_keys()
                keys |= _emitted(
                    ROLES / inc["name"] / "tasks" / f"{inc.get('tasks_from', 'main')}.yml", seen
                )
            sub = task.get("ansible.builtin.include_tasks") or task.get(
                "ansible.builtin.import_tasks"
            )
            if sub:
                keys |= _emitted(path.parent / sub, seen)
    return keys


def _writer_task() -> dict[str, Any]:
    tasks = yaml.safe_load((ROLES / "ovlm_result" / "tasks" / "write.yml").read_text())
    return next(t for t in tasks if "ansible.builtin.copy" in t)


def writer_keys() -> set[str]:
    return _facts_in(_writer_task()["vars"]["ovlm_result_doc"]["facts"])


def role_emits(phase: str) -> set[str]:
    return _emitted(PLAYBOOKS / f"{phase}.yml", set()) | writer_keys()


REFERENCE_PHASES = sorted(p.stem for p in PLAYBOOKS.glob("*.yml"))


# --- the doubles ----------------------------------------------------------------------------------------------------


def _phases_of(test: ast.AST) -> set[str]:
    """Phases named by ``phase == "x"`` or ``phase in ("x", ...)`` (also ``<x>.phase`` / ``<x>.phase.value``)."""
    out: set[str] = set()
    for node in ast.walk(test):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            if isinstance(node.ops[0], ast.Eq) and isinstance(_const(node.comparators[0]), str):
                out.add(_const(node.comparators[0]))
            if isinstance(node.ops[0], ast.In) and isinstance(
                node.comparators[0], ast.Tuple | ast.List | ast.Set
            ):
                out |= {_const(e) for e in node.comparators[0].elts if isinstance(_const(e), str)}
    return out & {p.value for p in Phase}


def double_facts(path: Path) -> list[tuple[str, frozenset[str] | None, set[str]]]:
    """``(where, phases, keys)`` for every ``PhaseResult``/``ValidatedResult`` built with a literal facts dict."""
    out: list[tuple[str, frozenset[str] | None, set[str]]] = []

    def walk(node: ast.AST, phases: frozenset[str] | None) -> None:
        if isinstance(node, ast.If) and (named := _phases_of(node.test)):
            for child in node.body:
                walk(child, frozenset(named))
            for child in node.orelse:
                walk(child, phases)
            return
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            pos = {"PhaseResult": 2, "ValidatedResult": 4}.get(node.func.id)
            if pos is not None:
                arg: ast.expr | None = node.args[pos] if len(node.args) > pos else None
                arg = next((k.value for k in node.keywords if k.arg == "facts"), arg)
                if isinstance(arg, ast.Dict):
                    keys = {_const(k) for k in arg.keys if k is not None}
                    assert None not in arg.keys, f"{path.name}:{node.lineno}: ** in a facts literal"
                    assert all(isinstance(k, str) for k in keys), (
                        f"{path.name}:{node.lineno}: computed key"
                    )
                    out.append((f"{path.name}:{node.lineno}", phases, keys))
                elif arg is not None:
                    src = ast.unparse(arg)
                    assert re.fullmatch(r"dict\(\w+\.facts\)", src), (
                        f"{path.name}:{node.lineno}: facts {src!r} neither a literal nor passed through"
                    )
        for sub in ast.iter_child_nodes(node):
            walk(sub, phases)

    walk(ast.parse(path.read_text()), None)
    return out


# --- tests: OVLM's reads against the contract and the reference workload --------------------------------------------


def test_the_scan_finds_the_reads_it_must_find() -> None:
    """Guard the scanner itself: the known read sites are seen, so an empty or broken scan cannot pass."""
    found = {(r.phase, r.key) for r in ovlm_reads()}
    assert {
        ("quiesce", "marker_sha256"),
        ("quiesce", "was_mounted"),
        ("data_attach", "fs_uuid"),
        ("data_attach", "fs_label"),
        ("data_attach", "marker_sha256"),
        ("healthcheck", "marker_sha256"),
        ("healthcheck", "health_state"),
    } <= found, sorted(found, key=str)


def test_every_read_is_attributed_to_a_phase() -> None:
    lost = [r.where for r in ovlm_reads() if r.phase is None]
    assert not lost, (
        f"facts read outside a step with a phase; add the function to READ_SITES: {lost}"
    )


@pytest.mark.parametrize(
    "read", ovlm_reads(), ids=lambda r: f"{r.phase}.{r.key}@{r.where.rsplit('.', 1)[-1]}"
)
def test_ovlm_reads_only_what_the_contract_defines_for_the_phase(read: Read) -> None:
    assert read.phase is not None
    row = contract_keys(read.phase).get(read.key)
    assert row is not None, (
        f"{read.where} reads facts.{read.key} from {read.phase}, which contract 3.7.1 does not define for that phase"
    )
    assert row.read, (
        f"contract 3.7.1 says no step reads {read.phase}.{read.key}, but {read.where} does"
    )


@pytest.mark.parametrize(
    "read", ovlm_reads(), ids=lambda r: f"{r.phase}.{r.key}@{r.where.rsplit('.', 1)[-1]}"
)
def test_the_reference_workload_reports_every_key_ovlm_reads(read: Read) -> None:
    assert read.phase is not None
    emitted = role_emits(read.phase)
    if read.key in emitted:
        return
    reason = OPTIONAL_NOT_EMITTED.get((read.phase, read.key))
    row = contract_keys(read.phase).get(read.key)
    assert reason and row is not None and row.optional, (
        f"{read.where} reads facts.{read.key}, which the reference {read.phase} playbook never reports "
        f"(it reports {sorted(emitted)})"
    )


def test_every_contract_row_said_to_be_read_is_read() -> None:
    """The table cannot go stale the other way: a row naming a reader must match a read in the code."""
    reads = {(r.phase, r.key) for r in ovlm_reads()}
    stale = [(r.phase, r.key) for r in contract_rows() if r.read and (r.phase, r.key) not in reads]
    assert not stale, f"contract 3.7.1 names readers for keys OVLM no longer reads: {stale}"


def test_the_allowlist_holds_only_optional_contract_keys() -> None:
    for (phase, key), reason in OPTIONAL_NOT_EMITTED.items():
        row = contract_keys(phase).get(key)
        assert row is not None and row.optional and reason, (phase, key)


def test_every_contract_phase_is_a_real_phase() -> None:
    phases = {p.value for p in Phase} | {ALL}
    assert {r.phase for r in contract_rows()} <= phases


@pytest.mark.parametrize("phase", REFERENCE_PHASES)
def test_the_reference_workload_reports_the_required_keys(phase: str) -> None:
    """Required (non-optional) keys of a phase are reported by the reference playbook for that phase."""
    required = {k for k, r in contract_keys(phase).items() if r.phase == phase and not r.optional}
    assert required <= role_emits(phase), (phase, sorted(required - role_emits(phase)))


def test_the_result_writer_adds_only_contract_keys() -> None:
    assert writer_keys() == {k for k, r in contract_keys("preflight").items() if r.phase == ALL}


# --- tests: the doubles ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", DOUBLES, ids=lambda p: p.name)
def test_the_renewal_doubles_report_only_contract_keys(path: Path) -> None:
    found = double_facts(path)
    if path.name == "doubles.py":
        assert len(found) >= 5, "the scan of FakeGuest.run_phase found too few results"
    for where, phases, keys in found:
        assert phases, f"{where}: a result with facts outside a phase branch"
        for phase in phases:
            unknown = keys - set(contract_keys(phase))
            assert not unknown, (
                f"{where}: the double reports {sorted(unknown)} for {phase}, not in contract 3.7.1"
            )


# --- tests: the result document around the facts --------------------------------------------------------------------


def test_the_parser_accepts_exactly_the_contracts_top_level_fields() -> None:
    assert set(contract_example()) == result_mod._TOP_KEYS


def test_the_reference_writer_writes_exactly_the_contracts_top_level_fields() -> None:
    assert set(_writer_task()["vars"]["ovlm_result_doc"]) == result_mod._TOP_KEYS
    assert (
        _writer_task()["vars"]["ovlm_result_doc"]["schema"]
        == result_mod.SCHEMA
        == contract_example()["schema"]
    )


def test_the_classification_values_are_the_contracts() -> None:
    assert set(contract_example()["classification"].split("|")) == {c.value for c in Classification}


def test_the_check_fields_are_the_contracts() -> None:
    text = CONTRACT.read_text()
    section = text[text.index("### 3.6 `healthcheck`") : text.index("### 3.6.1")]
    fields = re.search(r"each `\{([a-z, ]+)\}`", section)
    assert fields, "no checks[] field list in contract 3.6"
    assert {f.strip() for f in fields.group(1).split(",")} == result_mod._CHECK_KEYS
    assert set(contract_example()["checks"][0]) <= result_mod._CHECK_KEYS


def _role_check_keys() -> dict[str, set[str]]:
    """Keys of every check the reference workload builds, per task file."""
    out: dict[str, set[str]] = defaultdict(set)
    for path in [*PLAYBOOKS.glob("*.yml"), *ROLES.glob("*/tasks/*.yml")]:
        for doc in [yaml.safe_load(path.read_text())]:
            plays = doc if doc and "hosts" in doc[0] else [{"tasks": doc}]
            for play in plays:
                for task in _tasks(play.get("tasks")):
                    checks = (task.get("ansible.builtin.set_fact") or {}).get("ovlm_checks")
                    if isinstance(checks, list):
                        for c in checks:
                            out[path.name] |= set(c)
                    elif isinstance(checks, str):
                        out[path.name] |= set(re.findall(r"'([a-z_]+)':", checks))
    return out


def test_the_reference_checks_use_only_the_contracts_fields() -> None:
    found = _role_check_keys()
    assert found, "no ovlm_checks found in the reference workload"
    for where, keys in found.items():
        assert keys <= result_mod._CHECK_KEYS, (where, sorted(keys - result_mod._CHECK_KEYS))


@pytest.mark.parametrize("phase", REFERENCE_PHASES)
def test_each_playbook_reports_its_own_phase(phase: str) -> None:
    """``phase`` in the result must equal the phase OVLM ran, or the parser refuses the result."""
    play = yaml.safe_load((PLAYBOOKS / f"{phase}.yml").read_text())[0]
    assert play["vars"]["ovlm_phase"] == phase == Phase(phase).value
    assert play["vars"]["ovlm_default_class"] in {c.value for c in Classification}


# --- behaviour: defect AD (S2 read a non-contract marker spelling) --------------------------------------------------


def _s2_verify(facts: dict[str, Any]) -> Any:
    from ovlm.renewal.ports import PhaseResult
    from ovlm.renewal.steps_after import QuiesceGreen

    class Ctx:  # just enough StepContext for verify (memo is keyed weakly by the context)
        run = SimpleNamespace(id="run-1")
        previous_evidence = None

    step = QuiesceGreen(cast(Any, SimpleNamespace(cfg=SimpleNamespace())))
    ctx = cast(StepContext, Ctx())
    step.memo(ctx)["result"] = PhaseResult("ok", "nothing to quiesce", facts)
    return step.verify(ctx, {})


def test_s2_never_mounted_case_follows_the_contract_marker_key_only() -> None:
    """A green that never mounted the volume, from a repo still writing ``marker_checksum``: S2 must read the contract's
    key only, so this is the "never mounted" case (evidence says the comparison was skipped), not a normal quiesce."""
    from ovlm.workflow.contract import Done

    out = _s2_verify({"was_mounted": False, "marker_checksum": "0" * 64})
    assert isinstance(out, Done), out
    assert out.evidence["green_was_mounted"] is False and out.evidence["marker_checksum"] is None


def test_s2_with_a_contract_marker_is_a_normal_quiesce() -> None:
    from ovlm.workflow.contract import Done

    out = _s2_verify({"was_mounted": False, "marker_sha256": "0" * 64})
    assert isinstance(out, Done), out
    assert "green_was_mounted" not in out.evidence


def test_s2_never_mounted_with_the_contract_shape() -> None:
    from ovlm.workflow.contract import Done

    out = _s2_verify({"was_mounted": False, "marker_sha256": None})
    assert isinstance(out, Done) and out.evidence["green_was_mounted"] is False, out
