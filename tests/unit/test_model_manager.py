from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from securedact_core import ModelManagementError, ModelManager, ModelState, SecuredactPaths


def make_pack(
    root: Path,
    *,
    model_id: str = "english-large",
    model_bytes: bytes = b"model-v1",
    min_version: str = "0.1.0",
    extra_files: int = 0,
) -> Path:
    (root / "model").mkdir(parents=True)
    (root / "tokenizer").mkdir()
    (root / "model" / "pytorch_model.bin").write_bytes(model_bytes)
    (root / "tokenizer" / "tokenizer.json").write_bytes(b"tokenizer")
    for index in range(extra_files):
        (root / "tokenizer" / f"extra-{index}.json").write_bytes(str(index).encode())
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            content = path.read_bytes()
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                }
            )
    manifest = {
        "schema_version": 1,
        "model_id": model_id,
        "display_name": "Test privacy model",
        "language": "en",
        "model_type": "flair-sequence-tagger",
        "securedact_min_version": min_version,
        "securedact_max_version": None,
        "created_at": datetime.now(UTC).isoformat(),
        "files": files,
        "entrypoint": "model/pytorch_model.bin",
        "tokenizer_root": "tokenizer",
        "signatures": [],
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def zip_pack(source: Path, destination: Path) -> Path:
    with zipfile.ZipFile(destination, "w") as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return destination


def manager_at(root: Path, **kwargs: object) -> ModelManager:
    return ModelManager(SecuredactPaths.resolve(root / "app-data"), **kwargs)


def test_missing_model_state(tmp_path: Path) -> None:
    manager = manager_at(tmp_path, configured_model_id="english-large")
    assert manager.resolve_active_model() is None
    assert manager.status().state == ModelState.MISSING


def test_valid_directory_and_zip_installation(tmp_path: Path) -> None:
    directory_manager = manager_at(tmp_path / "directory")
    result = directory_manager.install(make_pack(tmp_path / "directory-pack"))
    assert result.installed and directory_manager.status().state == ModelState.INSTALLED

    archive = zip_pack(make_pack(tmp_path / "zip-pack"), tmp_path / "model.zip")
    zip_manager = manager_at(tmp_path / "zip")
    result = zip_manager.install(archive)
    assert result.installed
    assert (
        zip_manager.current_model
        and zip_manager.current_model.entrypoint.read_bytes() == b"model-v1"
    )


@pytest.mark.parametrize("mutation", ["missing", "size", "hash"])
def test_installed_model_detects_missing_size_and_hash_failures(
    tmp_path: Path, mutation: str
) -> None:
    manager = manager_at(tmp_path)
    manager.install(make_pack(tmp_path / "pack"))
    model_file = manager.paths.models / "english-large" / "model" / "pytorch_model.bin"
    if mutation == "missing":
        model_file.unlink()
    elif mutation == "size":
        model_file.write_bytes(b"different-size")
    else:
        model_file.write_bytes(b"model-v2")
    with pytest.raises(ModelManagementError):
        manager.validate_installed_model("english-large")
    assert manager.status().state == ModelState.INVALID


def test_incompatible_application_version_is_rejected(tmp_path: Path) -> None:
    manager = manager_at(tmp_path, app_version="0.1.0")
    with pytest.raises(ModelManagementError, match="newer"):
        manager.install(make_pack(tmp_path / "pack", min_version="9.0.0"))
    assert manager.status().state == ModelState.INCOMPATIBLE


def test_invalid_and_oversized_archives_clean_staging(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.zip"
    invalid.write_bytes(b"not a zip")
    manager = manager_at(tmp_path / "invalid")
    with pytest.raises(ModelManagementError):
        manager.install(invalid)
    assert not any(manager.paths.model_staging.iterdir())

    pack = make_pack(tmp_path / "large", model_bytes=b"12345")
    archive = zip_pack(pack, tmp_path / "large.zip")
    limited = manager_at(tmp_path / "limited", max_pack_bytes=4)
    with pytest.raises(ModelManagementError, match="limits"):
        limited.install(archive)
    assert not any(limited.paths.model_staging.iterdir())


def test_insufficient_disk_space_is_reported_and_staging_is_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = zip_pack(make_pack(tmp_path / "pack"), tmp_path / "model.zip")
    manager = manager_at(tmp_path / "application")
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _path: shutil._ntuple_diskusage(total=100, used=100, free=0),
    )
    with pytest.raises(ModelManagementError) as raised:
        manager.install(archive)
    assert raised.value.code.value == "MODEL_INSUFFICIENT_DISK_SPACE"
    assert not any(manager.paths.model_staging.iterdir())


def test_excessive_file_count_and_archive_traversal_are_rejected(tmp_path: Path) -> None:
    many = zip_pack(make_pack(tmp_path / "many", extra_files=2), tmp_path / "many.zip")
    manager = manager_at(tmp_path / "count", max_file_count=2)
    with pytest.raises(ModelManagementError, match="limits"):
        manager.install(many)

    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape", b"bad")
    with pytest.raises((ModelManagementError, ValueError)):
        manager_at(tmp_path / "traversal").install(traversal)


def test_zip_symlink_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "link.zip"
    info = zipfile.ZipInfo("model/link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(info, "target")
    with pytest.raises(ModelManagementError, match="links"):
        manager_at(tmp_path).install(archive_path)


def test_atomic_replacement_and_rollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager = manager_at(tmp_path)
    manager.install(make_pack(tmp_path / "v1", model_bytes=b"model-v1"))
    replacement = make_pack(tmp_path / "v2", model_bytes=b"model-v2")
    manager.install(replacement)
    final_file = manager.paths.models / "english-large" / "model" / "pytorch_model.bin"
    assert final_file.read_bytes() == b"model-v2"

    third = make_pack(tmp_path / "v3", model_bytes=b"model-v3")
    real_replace = os.replace

    def interrupted(source: str | Path, destination: str | Path) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        if source_path.name.startswith("install-") and destination_path.name == "english-large":
            raise OSError("simulated interruption")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(ModelManagementError, match="safely"):
        manager.install(third)
    assert final_file.read_bytes() == b"model-v2"
    assert not any(manager.paths.model_staging.iterdir())


def test_failed_replacement_restores_prior_ready_state(tmp_path: Path) -> None:
    manager = manager_at(tmp_path)
    manager.install(make_pack(tmp_path / "working", model_bytes=b"working"))
    manager.mark_ready()
    corrupt = zip_pack(
        make_pack(tmp_path / "corrupt", model_bytes=b"corrupt"),
        tmp_path / "corrupt.zip",
    )
    with zipfile.ZipFile(corrupt, "a") as archive:
        archive.writestr("unexpected.txt", b"unexpected")
    with pytest.raises(ModelManagementError):
        manager.install(corrupt)
    assert manager.status().state == ModelState.READY
    assert manager.current_model is not None
    assert manager.current_model.entrypoint.read_bytes() == b"working"


def test_explicit_runtime_states(tmp_path: Path) -> None:
    manager = manager_at(tmp_path)
    manager.install(make_pack(tmp_path / "pack"))
    manager.mark_loading()
    assert manager.status().state == ModelState.LOADING
    manager.mark_ready()
    assert manager.status().state == ModelState.READY
    manager.mark_failed()
    assert manager.status().state == ModelState.FAILED


def test_concurrent_install_attempt_is_rejected(tmp_path: Path) -> None:
    manager = manager_at(tmp_path)
    manager._install_lock.acquire()
    try:
        with pytest.raises(ModelManagementError, match="already in progress"):
            manager.install(make_pack(tmp_path / "pack"))
    finally:
        manager._install_lock.release()


def test_manifest_backed_development_override_is_explicit(tmp_path: Path) -> None:
    manager = manager_at(tmp_path)
    pack = make_pack(tmp_path / "override")
    model = manager.resolve_development_override(pack / "model" / "pytorch_model.bin")
    assert model is not None
    assert manager.status().development_override
    assert manager.status().integrity == "verified"

    invalid = tmp_path / "bare-checkpoint.bin"
    invalid.write_bytes(b"unverified")
    assert manager.resolve_development_override(invalid) is None
    assert manager.status().state == ModelState.INVALID
