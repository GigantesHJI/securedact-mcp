from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from securedact_mcp import model_registry
from securedact_mcp.model_registry import SupportedModel
from securedact_mcp.model_store import InstalledFile, ModelStoragePaths, ModelStore


def synthetic_model(
    content: bytes,
    *,
    language: str = "en",
    model_id: str = "english-large",
    repository: str = "flair/ner-english-large",
    revision: str = "a" * 40,
) -> SupportedModel:
    digest = hashlib.sha256(content).hexdigest()
    language_name = "English" if language == "en" else "Dutch"
    return SupportedModel(
        id=model_id,
        language=language,
        language_name=language_name,
        display_name=f"Synthetic {language_name}",
        upstream_repo=repository,
        upstream_revision=revision,
        required_files=("pytorch_model.bin",),
        optional_files=(),
        approximate_size_bytes=len(content),
        citation="Synthetic citation",
        license_identifier=None,
        license_note="Synthetic licensing warning",
        minimum_securedact_version="0.1.0",
        required_file_sizes=(("pytorch_model.bin", len(content)),),
        required_file_sha256=(("pytorch_model.bin", digest),),
    )


def patch_registered_model(monkeypatch: pytest.MonkeyPatch, model: SupportedModel) -> None:
    monkeypatch.setitem(model_registry.MODELS_BY_ID, model.id, model)
    monkeypatch.setitem(model_registry.MODELS_BY_LANGUAGE, model.language, model)


def store_at(tmp_path: Path) -> ModelStore:
    app_root = tmp_path / "app-data"
    model_root = app_root / "models"
    return ModelStore(
        ModelStoragePaths(
            app_root=app_root,
            model_root=model_root,
            staging_root=model_root / ".staging",
            rollback_root=model_root / ".rollback",
            config_path=app_root / "model-config.json",
        )
    )


def write_installed_model(store: ModelStore, model: SupportedModel, content: bytes) -> Path:
    root = store.model_path(model)
    root.mkdir(parents=True, exist_ok=True)
    target = root / "pytorch_model.bin"
    target.write_bytes(content)
    record = InstalledFile(size=len(content), sha256=hashlib.sha256(content).hexdigest())
    manifest = store.manifest_for_files(model, {"pytorch_model.bin": record})
    store.write_manifest(root, manifest)
    return root
