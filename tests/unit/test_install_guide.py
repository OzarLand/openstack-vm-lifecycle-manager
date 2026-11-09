"""The real-cloud install guide names only commands and settings that exist (roadmap P1-7).

* Every ``make <target>`` in a code span or block of the guide is a target of the Makefile.
* Every ``ovlm <subcommand> [<subcommand>]`` in a code span or block is accepted by the CLI: ``ovlm.cli.main`` is
  called with the words and ``--help``, which every sub-parser answers with exit 0 and an unknown word with exit 2.
* Every ``OVLM_*`` environment variable maps to a field of ``Settings`` (``__`` separates the nesting levels), unless
  it is a variable that ``compose.prod.yaml`` interpolates (``${OVLM_IMAGE:?...}``) and the guide sets in ``.env``.
* The TOML example loads as written (renewal keys left to their built-in defaults), and with every commented override
  uncommented it still loads, every value in it equal to the default it documents (docs/timeouts.md, roadmap P1-8).
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
PROD_COMPOSE = ROOT / "compose.prod.yaml"

_FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_SPAN = re.compile(r"`([^`\n]+)`")
_MAKE = re.compile(r"(?<![\w-])make ([a-z][a-z-]*)")
# `-u ovlm` names the container user, `ovlm-ansible`/`ovlm:managed`/`ovlm.toml` are not the command.
_OVLM = re.compile(r"(?<![\w./:-])(?<!-u )ovlm((?: [a-z][a-z-]*){1,2})")
_ENV = re.compile(r"\bOVLM_[A-Z0-9_]+\b")
#: Read by the settings loader itself, not a field.
_ENV_NOT_FIELDS = {"OVLM_CONFIG_FILE"}
#: Interpolated by the production Compose file (image references, network, proxy address), set in ``.env``.
_COMPOSE_VARS = set(re.findall(r"\$\{(OVLM_[A-Z0-9_]+)", PROD_COMPOSE.read_text()))


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
    names = (
        set(_ENV.findall(GUIDE.read_text()))
        - _ENV_NOT_FIELDS
        - (_COMPOSE_VARS - {"OVLM_EXTERNAL_URL"})
    )
    assert names, "the guide names no OVLM_ variable: the extraction is broken"
    unknown = sorted(n for n in names if not _setting_exists(n))
    assert not unknown, f"OVLM_ variables named in {GUIDE.name} that are not settings: {unknown}"


def _toml_example() -> str:
    blocks = re.findall(r"^```toml\n(.*?)^```", GUIDE.read_text(), re.MULTILINE | re.DOTALL)
    assert len(blocks) == 1
    return str(blocks[0])


def test_the_configuration_example_needs_no_renewal_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guide's TOML as written loads into ``Settings``, and the renewal needs nothing more (built-in defaults)."""
    config = tmp_path / "ovlm.toml"
    config.write_text(_toml_example())
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(config))
    settings = Settings(process_role="worker")
    cfg = RenewalConfig.from_settings(settings)
    assert cfg.missing(snapshot=True) == []
    assert len(cfg.defaulted) == len(cfg.values())  # every renewal key from the defaults
    assert settings.automation.allowed_repos


def test_the_commented_overrides_are_the_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Uncommented, the guide's optional overrides load, set every renewal key, and repeat the documented defaults."""
    text = re.sub(r"^# ?(\[renewal[^\]]*\]|[a-z_]+ = )", r"\1", _toml_example(), flags=re.MULTILINE)
    config = tmp_path / "ovlm.toml"
    config.write_text(text)
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(config))
    settings = Settings(process_role="worker")
    cfg = RenewalConfig.from_settings(settings)
    assert cfg.defaulted == ()  # every key is set by the example
    monkeypatch.setenv("OVLM_CONFIG_FILE", str(tmp_path / "absent.toml"))
    assert cfg.values() == RenewalConfig.from_settings(Settings(process_role="worker")).values()


def test_the_checks_catch_drift(capsys: pytest.CaptureFixture[str]) -> None:
    fake = "Run `make no-such-target`, then `ovlm kek no-such-action` and `OVLM_NO__SUCH`.\n"
    assert _make_targets_named(fake) - _makefile_targets() == {"no-such-target"}
    assert not _cli_accepts(("kek", "no-such-action"), capsys)
    assert not _cli_accepts(("no-such-command",), capsys)
    assert _cli_accepts(("kek", "status"), capsys)
    assert not _setting_exists("OVLM_NO__SUCH")
    assert _setting_exists("OVLM_HTTP__TRUSTED_PROXIES")
    assert not _setting_exists("OVLM_HTTP__TRUSTED_PROXIES__X")
    assert {"OVLM_IMAGE", "OVLM_WORKER_IMAGE", "OVLM_TRUSTED_PROXIES"} <= _COMPOSE_VARS
    assert not _setting_exists("OVLM_TRUSTED_PROXIES")
