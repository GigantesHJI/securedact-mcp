from __future__ import annotations

import json
from pathlib import Path

import pytest

from securedact_mcp.model_store import (
    ModelConfiguration,
    ModelIntegrityError,
    ModelPathError,
    ModelStoragePaths,
)
from tests.unit.model_install_helpers import (
    patch_registered_model,
    store_at,
    synthetic_model,
    write_installed_model,
)


def test_valid_local_manifest_and_hashes_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    write_installed_model(store, model, content)

    verified = store.verify_model(model)

    assert verified.entrypoint.read_bytes() == content
    assert verified.manifest.upstream_repo == "flair/ner-english-large"
    assert verified.manifest.upstream_revision == "a" * 40


@pytest.mark.parametrize("mutation", ["modified", "missing", "partial"])
def test_file_modification_missing_and_partial_files_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    root = write_installed_model(store, model, content)
    target = root / "pytorch_model.bin"
    if mutation == "modified":
        target.write_bytes(b"synthetic-tamper")
    elif mutation == "missing":
        target.unlink()
    else:
        (root / "pytorch_model.bin.incomplete").write_bytes(b"partial")

    with pytest.raises(ModelIntegrityError):
        store.verify_model(model)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("upstream_repo", "example/unknown"),
        ("upstream_revision", "b" * 40),
    ],
)
def test_wrong_upstream_provenance_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    root = write_installed_model(store, model, content)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ModelIntegrityError, match="provenance"):
        store.verify_model(model)


def test_corrupt_manifest_and_executable_extra_file_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    root = write_installed_model(store, model, content)
    (root / "manifest.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(ModelIntegrityError, match="corrupt"):
        store.verify_model(model)

    root = write_installed_model(store, model, content)
    (root / "run.exe").write_bytes(b"not executable")
    with pytest.raises(ModelIntegrityError, match="executable"):
        store.verify_model(model)


def test_configuration_write_and_corruption_recovery_are_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    write_installed_model(store, model, content)
    store.paths.ensure()
    store.paths.config_path.write_text("not-json", encoding="utf-8")

    recovered = store.load_or_recover_configuration()

    assert recovered == ModelConfiguration(
        enabled_languages=["en"],
        active_models={"en": "english-large"},
    )
    assert not list(store.paths.app_root.glob("*.tmp"))


def test_unsafe_model_directory_overrides_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ModelPathError, match="absolute"):
        ModelStoragePaths.resolve(model_dir_override="relative-models")
    with pytest.raises(ModelPathError, match="allowed"):
        ModelStoragePaths.resolve(model_dir_override=tmp_path / ".venv" / "models")
    with pytest.raises(ModelPathError, match="current working"):
        ModelStoragePaths.resolve(model_dir_override=Path.cwd() / "local-models")
    with pytest.raises(ModelPathError, match="filesystem root"):
        ModelStoragePaths.resolve(model_dir_override=Path(Path.cwd().anchor))
