"""The real-cloud install guide names only commands and settings that exist (roadmap P1-7).

* Every ``make <target>`` in a code span or block of the guide is a target of the Makefile.
* Every ``ovlm <subcommand> [<subcommand>]`` in a code span or block is accepted by the CLI: ``ovlm.cli.main`` is
  called with the words and ``--help``, which every sub-parser answers with exit 0 and an unknown word with exit 2.
* Every ``OVLM_*`` environment variable maps to a field of ``Settings`` (``__`` separates the nesting levels).
* The TOML example, placeholders filled, loads and sets every renewal key the strategy needs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import BaseModel

from ovlm.cli import main
from ovlm.config import Settings
from ovlm.renewal.config import RenewalConfig

ROOT = Path(__file__).parents[2]
GUIDE = ROOT / "docs" / "install-guide-real-cloud.md"
MAKEFILE = ROOT / "Makefile"

_FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_SPAN = re.compile(r"`([^`\n]+)`")
_MAKE = re.compile(r"(?<![\w-])make ([a-z][a-z-]*)")
# `-u ovlm` names the container user, `ovlm-ansible`/`ovlm:managed`/`ovlm.toml` are not the command.
_OVLM = re.compile(r"(?<![\w./:-])(?<!-u )ovlm((?: [a-z][a-z-]*){1,2})")
_ENV = re.compile(r"\bOVLM_[A-Z0-9_]+\b")
#: Read by the settings loader itself, not a field.
_ENV_NOT_FIELDS = {"OVLM_CONFIG_FILE"}


def _code(text: str) -> list[str]:
    blocks = _FENCE.findall(text)
    prose = _FENCE.sub("", text)
    return blocks + _SPAN.findall(prose)


def _makefile_targets() -> set[str]:
    return set(re.findall(r"^([a-z][a-z-]*):", MAKEFILE.read_text(), re.MULTILINE))


def _make_targets_named(text: str) -> set[str]:
    return {m for chunk in _code(text) for m in _MAKE.findall(chunk)}


def _ovlm_commands_named(text: str) -> set[tuple[str, ...]]:
    return {tuple(m.split()) for chunk in _code(text) for m in _OVLM.findall(chunk)}


def _cli_accepts(words: tuple[str, ...], capsys: pytest.CaptureFixture[str]) -> bool:
    """True when ``ovlm <words> --help`` prints help (exit 0). A two-word match whose second word is not a
    sub-command (``ovlm migrate and``) is retried with the first word alone."""
    for n in range(len(words), 0, -1):
        with pytest.raises(SystemExit) as exc:
            main([*words[:n], "--help"])
        capsys.readouterr()
        if exc.value.code == 0:
            return n == len(words) or words[0] in {"api", "worker", "migrate"}
    return False


def _setting_exists(var: str) -> bool:
    model: type[BaseModel] = Settings
    parts = var.removeprefix("OVLM_").lower().split("__")
    for i, part in enumerate(parts):
        field = model.model_fields.get(part)
        if field is None:
            return False
        if i < len(parts) - 1:
            annotation = field.annotation
            if not (isinstance(annotation, type) and issubclass(annotation, BaseModel)):
                return False
            model = annotation
    return True


def test_guide_exists_and_names_commands() -> None:
    text = GUIDE.read_text()
    assert _make_targets_named(text), "the guide names no make target: the extraction is broken"
    assert _ovlm_commands_named(text), "the guide names no ovlm command: the extraction is broken"


def test_every_make_target_in_the_guide_exists() -> None:
    missing = _make_targets_named(GUIDE.read_text()) - _makefile_targets()
    assert not missing, (
        f"make targets named in {GUIDE.name} but not in the Makefile: {sorted(missing)}"
    )


def test_every_ovlm_command_in_the_guide_exists(capsys: pytest.CaptureFixture[str]) -> None:
    unknown = [
        " ".join(w)
        for w in sorted(_ovlm_commands_named(GUIDE.read_text()))
        if not _cli_accepts(w, capsys)
    ]
    assert not unknown, f"ovlm commands named in {GUIDE.name} that the CLI refuses: {unknown}"


def test_every_ovlm_environment_variable_in_the_guide_is_a_setting() -> None:
    names = set(_ENV.findall(GUIDE.read_text())) - _ENV_NOT_FIELDS
    assert names, "the guide names no OVLM_ variable: the extraction is broken"
    unknown = sorted(n for n in names if not _setting_exists(n))
    assert not unknown, f"OVLM_ variables named in {GUIDE.name} that are not settings: {unknown}"


def test_the_configuration_example_sets_every_renewal_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guide's TOML, with its placeholders filled, loads into ``Settings`` and leaves no renewal key missing."""
    blocks = re.findall(r"^```toml\n(.*?)^```", GUIDE.read_text(), re.MULTILINE | re.DOTALL)
    assert len(blocks) == 1
    config = tmp_path / "ovlm.toml"
    config.write_text(re.sub(r"<(?:seconds|count)>", "1", blocks[0]))
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(config))
    settings = Settings(process_role="worker")
    assert RenewalConfig.from_settings(settings).missing(snapshot=True) == []
    assert settings.automation.allowed_repos


def test_the_checks_catch_drift(capsys: pytest.CaptureFixture[str]) -> None:
    fake = "Run `make no-such-target`, then `ovlm kek no-such-action` and `OVLM_NO__SUCH`.\n"
    assert _make_targets_named(fake) - _makefile_targets() == {"no-such-target"}
    assert not _cli_accepts(("kek", "no-such-action"), capsys)
    assert not _cli_accepts(("no-such-command",), capsys)
    assert _cli_accepts(("kek", "status"), capsys)
    assert not _setting_exists("OVLM_NO__SUCH")
    assert _setting_exists("OVLM_HTTP__TRUSTED_PROXIES")
    assert not _setting_exists("OVLM_HTTP__TRUSTED_PROXIES__X")
