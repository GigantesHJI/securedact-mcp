from __future__ import annotations

import io
from pathlib import Path

import pytest

from securedact_mcp.cli import build_parser, run_guided_install
from securedact_mcp.model_registry import SupportedModel
from tests.unit.model_install_helpers import (
    patch_registered_model,
    store_at,
    synthetic_model,
    write_installed_model,
)


class RecordingInstaller:
    def __init__(self, installed: list[str]) -> None:
        self.installed = installed

    def install(self, model: SupportedModel) -> None:
        self.installed.append(model.language)


def _recording_factory(installed: list[str]):
    return lambda _store, _progress: RecordingInstaller(installed)


def _answers(*values: str):
    remaining = iter(values)
    return lambda _prompt: next(remaining)


def _models(monkeypatch: pytest.MonkeyPatch):
    english = synthetic_model(b"english")
    dutch = synthetic_model(
        b"dutch",
        language="nl",
        model_id="dutch-large",
        repository="flair/ner-dutch-large",
        revision="b" * 40,
    )
    patch_registered_model(monkeypatch, english)
    patch_registered_model(monkeypatch, dutch)
    return english, dutch


@pytest.mark.parametrize(
    ("choice", "consents", "expected"),
    [
        ("1", ("y",), ["en"]),
        ("2", ("y",), ["nl"]),
        ("3", ("y", "y"), ["en", "nl"]),
    ],
)
def test_interactive_language_selections_install_expected_models(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    choice: str,
    consents: tuple[str, ...],
    expected: list[str],
) -> None:
    _models(monkeypatch)
    store = store_at(tmp_path)
    installed: list[str] = []
    output = io.StringIO()

    result = run_guided_install(
        language=None,
        accept_upstream_terms=False,
        input_fn=_answers(choice, *consents),
        output=output,
        store=store,
        installer_factory=_recording_factory(installed),  # type: ignore[arg-type,return-value]
    )

    assert result == 0
    assert installed == expected
    assert store.read_configuration() is not None
    assert store.read_configuration().enabled_languages == expected  # type: ignore[union-attr]
    assert "Licensing note:" in output.getvalue()
    assert "Citation:" in output.getvalue()


def test_minimal_installation_is_explicit_and_does_not_enable_regex_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _models(monkeypatch)
    store = store_at(tmp_path)
    output = io.StringIO()

    result = run_guided_install(
        language=None,
        accept_upstream_terms=False,
        input_fn=_answers("4"),
        output=output,
        store=store,
    )

    assert result == 0
    assert store.read_configuration().enabled_languages == []  # type: ignore[union-attr]
    assert "fail closed" in output.getvalue()
    assert "enabled explicitly" in output.getvalue()


def test_default_consent_is_no_and_configuration_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _models(monkeypatch)
    store = store_at(tmp_path)
    output = io.StringIO()

    result = run_guided_install(
        language=None,
        accept_upstream_terms=False,
        input_fn=_answers("1", ""),
        output=output,
        store=store,
    )

    assert result == 2
    assert store.read_configuration() is None
    assert "cancelled" in output.getvalue()
    assert "[awaiting_consent]" in output.getvalue()


def test_closed_stdin_is_treated_as_declined_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _models(monkeypatch)
    store = store_at(tmp_path)
    output = io.StringIO()

    prompts = 0

    def closed_stdin(_prompt: str) -> str:
        nonlocal prompts
        prompts += 1
        if prompts == 1:
            return "1"
        raise EOFError

    result = run_guided_install(
        language=None,
        accept_upstream_terms=False,
        input_fn=closed_stdin,
        output=output,
        store=store,
    )
    assert result == 2
    assert store.read_configuration() is None


def test_noninteractive_download_requires_explicit_terms_flag(tmp_path: Path) -> None:
    output = io.StringIO()
    result = run_guided_install(
        language="english",
        accept_upstream_terms=False,
        output=output,
        store=store_at(tmp_path),
    )

    assert result == 2
    assert "--accept-upstream-terms" in output.getvalue()


def test_noninteractive_english_dutch_and_all_use_explicit_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _models(monkeypatch)
    for selection, expected in (
        ("english", ["en"]),
        ("dutch", ["nl"]),
        ("all", ["en", "nl"]),
    ):
        installed: list[str] = []
        result = run_guided_install(
            language=selection,
            accept_upstream_terms=True,
            output=io.StringIO(),
            store=store_at(tmp_path / selection),
            installer_factory=_recording_factory(installed),  # type: ignore[arg-type,return-value]
        )
        assert result == 0
        assert installed == expected


def test_existing_verified_installation_does_not_prompt_for_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    english, _dutch = _models(monkeypatch)
    store = store_at(tmp_path)
    write_installed_model(store, english, b"english")
    installed: list[str] = []

    result = run_guided_install(
        language=None,
        accept_upstream_terms=False,
        input_fn=_answers("1"),
        output=io.StringIO(),
        store=store,
        installer_factory=_recording_factory(installed),  # type: ignore[arg-type,return-value]
    )

    assert result == 0
    assert installed == ["en"]


def test_cli_parser_exposes_required_command_structure() -> None:
    parser = build_parser()
    assert parser.parse_args(["install", "--language", "all"]).language == "all"
    assert parser.parse_args(["models", "update", "english"]).model_command == "update"
    assert parser.parse_args(["models", "remove", "dutch"]).model_command == "remove"
    assert parser.parse_args(["models", "verify"]).model_command == "verify"
