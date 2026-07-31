from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from securedact_mcp.cli import run_guided_install
from securedact_mcp.model_installer import ModelInstaller
from tests.unit.model_install_helpers import (
    patch_registered_model,
    store_at,
    synthetic_model,
)


def test_guided_setup_downloads_validates_tests_and_activates_mocked_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"synthetic-flair-checkpoint"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    download_calls: list[dict[str, object]] = []
    loaded_paths: list[Path] = []

    def snapshot_download(**kwargs: object) -> str:
        download_calls.append(kwargs)
        destination = Path(str(kwargs["local_dir"]))
        destination.mkdir(parents=True)
        (destination / "pytorch_model.bin").write_bytes(content)
        return str(destination)

    def installer_factory(model_store, progress):  # type: ignore[no-untyped-def]
        return ModelInstaller(
            model_store,
            snapshot_download=snapshot_download,
            smoke_test=loaded_paths.append,
            progress=progress,
            sleeper=lambda _seconds: None,
        )

    output = StringIO()
    result = run_guided_install(
        language="english",
        accept_upstream_terms=True,
        output=output,
        store=store,
        installer_factory=installer_factory,
    )

    assert result == 0
    assert download_calls[0]["repo_id"] == "flair/ner-english-large"
    assert download_calls[0]["revision"] == "a" * 40
    assert loaded_paths and loaded_paths[0].name == "pytorch_model.bin"
    assert store.verify_model(model).entrypoint.is_file()
    configuration = store.read_configuration()
    assert configuration is not None
    assert configuration.enabled_languages == ["en"]
    assert "[testing]" in output.getvalue()
    assert "ready for offline runtime use" in output.getvalue()
