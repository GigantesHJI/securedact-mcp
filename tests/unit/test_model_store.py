from __future__ import annotations

import json
from pathlib import Path

import pytest

import securedact_mcp.model_store as model_store
from securedact_mcp.model_store import (
    ModelConfiguration,
    ModelIntegrityError,
    ModelPathError,
    ModelStoragePaths,
    _validate_model_root,
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


def test_model_root_equal_to_current_working_directory_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    working_directory = tmp_path / "user"
    working_directory.mkdir()
    monkeypatch.setattr(model_store.tempfile, "gettempdir", lambda: str(tmp_path / "temp"))

    with pytest.raises(ModelPathError, match="current working"):
        _validate_model_root(working_directory, cwd=working_directory)


def test_appdata_style_model_root_beneath_working_directory_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    working_directory = tmp_path / "user"
    model_root = working_directory / "AppData" / "Local" / "Securedact" / "models"
    working_directory.mkdir()
    monkeypatch.setattr(model_store.tempfile, "gettempdir", lambda: str(tmp_path / "temp"))
    monkeypatch.setattr(Path, "exists", lambda _path: False)

    _validate_model_root(model_root, cwd=working_directory)


def test_model_root_inside_git_repository_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    working_directory = tmp_path / "user"
    repository = tmp_path / "repository"
    working_directory.mkdir()
    (repository / ".git").mkdir(parents=True)
    monkeypatch.setattr(model_store.tempfile, "gettempdir", lambda: str(tmp_path / "temp"))
    git_marker = repository / ".git"
    monkeypatch.setattr(Path, "exists", lambda path: path == git_marker)

    with pytest.raises(ModelPathError, match="Git repository"):
        _validate_model_root(repository / "models", cwd=working_directory)


def test_temporary_model_root_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    working_directory = tmp_path / "user"
    temporary_root = tmp_path / "temporary"
    working_directory.mkdir()
    monkeypatch.setattr(model_store.tempfile, "gettempdir", lambda: str(temporary_root))
    monkeypatch.setattr(Path, "exists", lambda _path: False)

    with pytest.raises(ModelPathError, match="temporary"):
        _validate_model_root(temporary_root / "models", cwd=working_directory)


def test_filesystem_root_model_path_is_rejected() -> None:
    with pytest.raises(ModelPathError, match="filesystem root"):
        _validate_model_root(Path(Path.cwd().anchor))


def test_unsafe_model_directory_overrides_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ModelPathError, match="absolute"):
        ModelStoragePaths.resolve(model_dir_override="relative-models")
    with pytest.raises(ModelPathError, match="allowed"):
        ModelStoragePaths.resolve(model_dir_override=tmp_path / ".venv" / "models")
