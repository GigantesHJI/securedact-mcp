from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from securedact_mcp import model_installer
from securedact_mcp.model_installer import InstallerState, ModelDownloadError, ModelInstaller
from securedact_mcp.model_store import ModelIntegrityError
from tests.unit.model_install_helpers import (
    patch_registered_model,
    patch_runtime_component,
    store_at,
    synthetic_model,
    synthetic_runtime_component,
    write_installed_model,
)


def snapshot_for(content: bytes, calls: list[dict[str, object]]):
    def download(**kwargs: object) -> str:
        calls.append(kwargs)
        root = Path(str(kwargs["local_dir"]))
        root.mkdir(parents=True)
        (root / "pytorch_model.bin").write_bytes(content)
        return str(root)

    return download


def test_snapshot_download_uses_exact_allowlisted_source_and_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    calls: list[dict[str, object]] = []
    smoke_paths: list[Path] = []

    result = ModelInstaller(
        store,
        snapshot_download=snapshot_for(content, calls),
        smoke_test=lambda path, _cache: smoke_paths.append(path),
        sleeper=lambda _seconds: None,
    ).install(model)

    assert result.state == InstallerState.READY
    assert calls[0]["repo_id"] == "flair/ner-english-large"
    assert calls[0]["revision"] == "a" * 40
    assert calls[0]["allow_patterns"] == ["pytorch_model.bin"]
    assert calls[0]["endpoint"] == "https://huggingface.co"
    assert "resume_download" not in calls[0]
    assert "local_dir_use_symlinks" not in calls[0]
    assert calls[0]["token"] is False
    assert smoke_paths and smoke_paths[0].name == "pytorch_model.bin"
    assert store.verify_model(model).entrypoint.is_file()
    assert not any(store.paths.staging_root.iterdir())


@pytest.mark.parametrize(
    "forged",
    (
        lambda model: replace(model, upstream_repo="example/unknown"),
        lambda model: replace(model, upstream_revision="main"),
    ),
)
def test_downloader_rejects_models_outside_exact_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    forged,
) -> None:
    model = synthetic_model(b"synthetic-model")
    patch_registered_model(monkeypatch, model)
    with pytest.raises(ModelDownloadError, match="allowlist"):
        ModelInstaller(
            store_at(tmp_path),
            snapshot_download=lambda **_kwargs: pytest.fail("download must not run"),
            smoke_test=lambda _path, _cache: None,
        ).install(forged(model))


def test_existing_valid_installation_does_not_download_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    write_installed_model(store, model, content)

    result = ModelInstaller(
        store,
        snapshot_download=lambda **_kwargs: pytest.fail("download must not run"),
        smoke_test=lambda path, _cache: assert_checkpoint_path(path),
    ).install(model)

    assert result.already_installed


def assert_checkpoint_path(path: Path) -> None:
    assert path.name == "pytorch_model.bin"


def test_retry_is_bounded_and_interrupted_download_never_activates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    attempts = 0
    sleeps: list[float] = []

    def failing(**_kwargs: object) -> str:
        nonlocal attempts
        attempts += 1
        raise OSError("synthetic network interruption")

    with pytest.raises(ModelDownloadError, match="bounded retries"):
        ModelInstaller(
            store,
            snapshot_download=failing,
            smoke_test=lambda _path, _cache: None,
            sleeper=sleeps.append,
        ).install(model)

    assert attempts == 3
    assert sleeps == [1.0, 2.0]
    assert not store.model_path(model).exists()
    assert not any(store.paths.staging_root.iterdir())


def test_cancellation_and_disk_space_failure_are_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    monkeypatch.setattr(
        model_installer.shutil,
        "disk_usage",
        lambda _path: shutil._ntuple_diskusage(total=100, used=100, free=0),
    )
    with pytest.raises(ModelDownloadError, match="disk space"):
        ModelInstaller(store, smoke_test=lambda _path, _cache: None).install(model)
    assert not store.model_path(model).exists()

    monkeypatch.undo()
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path / "cancel")
    with pytest.raises(ModelDownloadError, match="cancelled"):
        ModelInstaller(
            store,
            snapshot_download=lambda **_kwargs: pytest.fail("download must not run"),
            smoke_test=lambda _path, _cache: None,
            cancel_check=lambda: True,
        ).install(model)
    assert not any(store.paths.staging_root.iterdir())


def test_unexpected_snapshot_file_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"synthetic-model"
    model = synthetic_model(content)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)

    def unexpected(**kwargs: object) -> str:
        root = Path(str(kwargs["local_dir"]))
        root.mkdir(parents=True)
        (root / "pytorch_model.bin").write_bytes(content)
        (root / "unexpected.txt").write_text("unexpected", encoding="utf-8")
        return str(root)

    with pytest.raises(ModelIntegrityError, match="unexpected"):
        ModelInstaller(
            store,
            snapshot_download=unexpected,
            smoke_test=lambda _path, _cache: None,
        ).install(model)
    assert not store.model_path(model).exists()


def test_failed_smoke_test_preserves_previous_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_content = b"old-model"
    new_content = b"new-model"
    old_model = synthetic_model(old_content, revision="b" * 40)
    new_model = synthetic_model(new_content, revision="c" * 40)
    patch_registered_model(monkeypatch, old_model)
    store = store_at(tmp_path)
    root = write_installed_model(store, old_model, old_content)
    patch_registered_model(monkeypatch, new_model)

    with pytest.raises(ModelDownloadError, match="load failed"):
        ModelInstaller(
            store,
            snapshot_download=snapshot_for(new_content, []),
            smoke_test=lambda _path, _cache: (_ for _ in ()).throw(
                ModelDownloadError("load failed")
            ),
        ).install(new_model)

    assert (root / "pytorch_model.bin").read_bytes() == old_content


def test_atomic_activation_failure_restores_previous_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_content = b"old-model"
    new_content = b"new-model"
    old_model = synthetic_model(old_content, revision="b" * 40)
    new_model = synthetic_model(new_content, revision="c" * 40)
    patch_registered_model(monkeypatch, old_model)
    store = store_at(tmp_path)
    root = write_installed_model(store, old_model, old_content)
    patch_registered_model(monkeypatch, new_model)
    real_replace = os.replace

    def interrupted(source: str | Path, destination: str | Path) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        if source_path.name == "payload" and destination_path.name == new_model.id:
            raise OSError("synthetic activation interruption")
        real_replace(source, destination)

    monkeypatch.setattr(model_installer.os, "replace", interrupted)
    with pytest.raises(OSError, match="activation interruption"):
        ModelInstaller(
            store,
            snapshot_download=snapshot_for(new_content, []),
            smoke_test=lambda _path, _cache: None,
        ).install(new_model)

    assert (root / "pytorch_model.bin").read_bytes() == old_content
    assert not any(store.paths.staging_root.iterdir())


def test_installer_downloads_and_manifests_required_runtime_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = b"synthetic-model"
    dependency_files = {
        "config.json": b"{}",
        "sentencepiece.bpe.model": b"sentencepiece",
        "tokenizer.json": b'{"synthetic": true}',
        "tokenizer_config.json": b"{}",
    }
    component = synthetic_runtime_component(dependency_files)
    model = synthetic_model(
        checkpoint,
        runtime_component_ids=(component.id,),
    )
    patch_runtime_component(monkeypatch, component)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    calls: list[dict[str, object]] = []
    smoke_caches: list[Path] = []

    def download(**kwargs: object) -> str:
        calls.append(kwargs)
        root = Path(str(kwargs["local_dir"]))
        root.mkdir(parents=True)
        if kwargs["repo_id"] == model.upstream_repo:
            (root / "pytorch_model.bin").write_bytes(checkpoint)
        else:
            for name, content in dependency_files.items():
                (root / name).write_bytes(content)
        return str(root)

    result = ModelInstaller(
        store,
        snapshot_download=download,
        smoke_test=lambda _entrypoint, cache: smoke_caches.append(cache),
        sleeper=lambda _seconds: None,
    ).install(model)

    assert result.state == InstallerState.READY
    assert [call["repo_id"] for call in calls] == [
        model.upstream_repo,
        component.upstream_repo,
    ]
    assert calls[1]["revision"] == component.upstream_revision
    assert calls[1]["allow_patterns"] == list(component.required_files)
    verified = store.verify_model(model)
    runtime_records = {
        key: value
        for key, value in verified.manifest.files.items()
        if value.storage == "runtime_cache"
    }
    assert len(runtime_records) == len(component.required_files) + 1
    assert all(record.component_id == component.id for record in runtime_records.values())
    assert smoke_caches
    assert (
        store.paths.runtime_cache_root
        / "hub"
        / component.cache_repository_name
        / "snapshots"
        / component.upstream_revision
        / "tokenizer.json"
    ).is_file()
    tokenizer = (
        store.paths.runtime_cache_root
        / "hub"
        / component.cache_repository_name
        / "snapshots"
        / component.upstream_revision
        / "tokenizer.json"
    )
    tokenizer.write_bytes(b"tampered")
    with pytest.raises(ModelIntegrityError, match="runtime component"):
        store.verify_model(model)


def test_repair_downloads_only_missing_runtime_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = b"synthetic-model"
    dependency_files = {"tokenizer.json": b"synthetic-tokenizer"}
    component = synthetic_runtime_component(dependency_files)
    model = synthetic_model(checkpoint, runtime_component_ids=(component.id,))
    patch_runtime_component(monkeypatch, component)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    write_installed_model(store, model, checkpoint)
    calls: list[dict[str, object]] = []

    def dependency_download(**kwargs: object) -> str:
        calls.append(kwargs)
        assert kwargs["repo_id"] == component.upstream_repo
        root = Path(str(kwargs["local_dir"]))
        root.mkdir(parents=True)
        (root / "tokenizer.json").write_bytes(dependency_files["tokenizer.json"])
        return str(root)

    result = ModelInstaller(
        store,
        snapshot_download=dependency_download,
        smoke_test=lambda _entrypoint, _cache: None,
        sleeper=lambda _seconds: None,
    ).repair(model)

    assert result.state == InstallerState.READY
    assert len(calls) == 1
    assert calls[0]["repo_id"] == component.upstream_repo
    assert (store.model_path(model) / "pytorch_model.bin").read_bytes() == checkpoint
    assert store.verify_model(model).manifest.schema_version == 2


def test_failed_repair_smoke_test_preserves_legacy_manifest_and_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = b"synthetic-model"
    dependency_files = {"tokenizer.json": b"synthetic-tokenizer"}
    component = synthetic_runtime_component(dependency_files)
    model = synthetic_model(checkpoint, runtime_component_ids=(component.id,))
    patch_runtime_component(monkeypatch, component)
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path)
    root = write_installed_model(store, model, checkpoint)
    manifest_path = root / "manifest.json"
    legacy_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    legacy_manifest["schema_version"] = 1
    legacy_manifest["files"] = {
        "pytorch_model.bin": {
            "size": len(checkpoint),
            "sha256": model.expected_hashes["pytorch_model.bin"],
        }
    }
    manifest_path.write_text(json.dumps(legacy_manifest), encoding="utf-8")
    original_manifest = (root / "manifest.json").read_bytes()

    def dependency_download(**kwargs: object) -> str:
        destination = Path(str(kwargs["local_dir"]))
        destination.mkdir(parents=True)
        (destination / "tokenizer.json").write_bytes(dependency_files["tokenizer.json"])
        return str(destination)

    with pytest.raises(ModelDownloadError, match="synthetic offline failure"):
        ModelInstaller(
            store,
            snapshot_download=dependency_download,
            smoke_test=lambda _entrypoint, _cache: (_ for _ in ()).throw(
                ModelDownloadError("synthetic offline failure")
            ),
            sleeper=lambda _seconds: None,
        ).repair(model)

    assert (root / "manifest.json").read_bytes() == original_manifest
    assert (root / "pytorch_model.bin").read_bytes() == checkpoint
    assert not store.runtime_component_root(component).exists()


def test_shared_runtime_dependency_is_removed_only_after_last_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependency_files = {"tokenizer.json": b"shared-tokenizer"}
    component = synthetic_runtime_component(dependency_files)
    english = synthetic_model(b"english", runtime_component_ids=(component.id,))
    dutch = synthetic_model(
        b"dutch",
        language="nl",
        model_id="dutch-large",
        repository="flair/ner-dutch-large",
        revision="b" * 40,
        runtime_component_ids=(component.id,),
    )
    patch_runtime_component(monkeypatch, component)
    patch_registered_model(monkeypatch, english)
    patch_registered_model(monkeypatch, dutch)
    store = store_at(tmp_path)
    dependency_downloads = 0

    def download(**kwargs: object) -> str:
        nonlocal dependency_downloads
        root = Path(str(kwargs["local_dir"]))
        root.mkdir(parents=True)
        if kwargs["repo_id"] == component.upstream_repo:
            dependency_downloads += 1
            (root / "tokenizer.json").write_bytes(dependency_files["tokenizer.json"])
        elif kwargs["repo_id"] == english.upstream_repo:
            (root / "pytorch_model.bin").write_bytes(b"english")
        else:
            (root / "pytorch_model.bin").write_bytes(b"dutch")
        return str(root)

    installer = ModelInstaller(
        store,
        snapshot_download=download,
        smoke_test=lambda _entrypoint, _cache: None,
        sleeper=lambda _seconds: None,
    )
    installer.install(english)
    installer.install(dutch)
    component_root = store.runtime_component_root(component)

    assert dependency_downloads == 1
    assert component_root.is_dir()
    assert store.remove_model(english)
    assert component_root.is_dir()
    assert store.remove_model(dutch)
    assert not component_root.exists()
