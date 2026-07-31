from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from securedact_mcp import server
from securedact_mcp.model_store import ModelConfiguration
from tests.unit.model_install_helpers import (
    patch_registered_model,
    store_at,
    synthetic_model,
    write_installed_model,
)


class FakeFlairDetector:
    contextual = True
    name = "flair"
    calls: ClassVar[list[str]] = []
    constructed: ClassVar[list[str]] = []

    def __init__(self, model_path: str | Path, **_kwargs: object) -> None:
        self.language = Path(model_path).parent.name.split("-")[0]
        self.ready = False
        self.constructed.append(self.language)

    def load(self) -> None:
        self.ready = True

    def detect(self, _text: str):
        self.calls.append(self.language)
        return []


def _prepare_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    languages: list[str],
):
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
    store = store_at(tmp_path)
    if "en" in languages:
        write_installed_model(store, english, b"english")
    if "nl" in languages:
        write_installed_model(store, dutch, b"dutch")
    store.write_configuration(
        ModelConfiguration(
            enabled_languages=languages,
            active_models={
                language: {"en": english.id, "nl": dutch.id}[language] for language in languages
            },
        )
    )
    monkeypatch.setattr(
        server.ModelStoragePaths,
        "resolve",
        classmethod(lambda _cls: store.paths),
    )
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "1")
    monkeypatch.delenv("SECUREDACT_MODEL_PATH", raising=False)
    monkeypatch.delenv("SECUREDACT_FLAIR_MODEL", raising=False)
    monkeypatch.delenv("SECUREDACT_MODEL_ID", raising=False)
    monkeypatch.setattr(server, "FlairDetector", FakeFlairDetector)
    FakeFlairDetector.calls = []
    FakeFlairDetector.constructed = []
    return store, english, dutch


def test_both_installed_models_route_english_dutch_and_uncertain_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_runtime(tmp_path, monkeypatch, ["en", "nl"])
    runtime = server.build_runtime()
    runtime.engine.startup()

    runtime.engine.analyze("Please send the report to John with this note")
    assert FakeFlairDetector.calls == ["english"]
    FakeFlairDetector.calls.clear()
    runtime.engine.analyze("Stuur het rapport naar Jan en neem contact op")
    assert FakeFlairDetector.calls == ["dutch"]
    FakeFlairDetector.calls.clear()
    runtime.engine.analyze("Acme 123")
    assert FakeFlairDetector.calls == ["english", "dutch"]


def test_single_model_is_used_conservatively_for_other_language(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prepare_runtime(tmp_path, monkeypatch, ["en"])
    runtime = server.build_runtime()
    runtime.engine.startup()

    runtime.engine.analyze("Stuur het rapport naar Jan")

    assert FakeFlairDetector.calls == ["english"]


def test_corrupt_model_is_never_constructed_or_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, english, _dutch = _prepare_runtime(tmp_path, monkeypatch, ["en"])
    (store.model_path(english) / "pytorch_model.bin").write_bytes(b"tampered")

    runtime = server.build_runtime()

    assert FakeFlairDetector.constructed == []
    assert runtime.contextual_error is not None
    assert "required English contextual model is not installed" in runtime.contextual_error


@pytest.mark.asyncio
async def test_minimal_configuration_remains_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _english, _dutch = _prepare_runtime(tmp_path, monkeypatch, [])
    assert store.read_configuration().enabled_languages == []  # type: ignore[union-attr]
    mcp_server = server.create_server()

    result = await mcp_server._tool_manager._tools["analyze_text"].run(
        {"text": "alex.example@example.test", "policy": "default"}
    )

    assert result["status"] == "blocked"
    assert "No contextual model is enabled" in result["reason"]
