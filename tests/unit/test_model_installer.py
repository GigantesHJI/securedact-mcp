from __future__ import annotations

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
    store_at,
    synthetic_model,
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
        smoke_test=smoke_paths.append,
        sleeper=lambda _seconds: None,
    ).install(model)

    assert result.state == InstallerState.READY
    assert calls[0]["repo_id"] == "flair/ner-english-large"
    assert calls[0]["revision"] == "a" * 40
    assert calls[0]["allow_patterns"] == ["pytorch_model.bin"]
    assert calls[0]["endpoint"] == "https://huggingface.co"
    assert calls[0]["resume_download"] is True
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
            smoke_test=lambda _path: None,
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
        smoke_test=lambda path: assert_checkpoint_path(path),
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
            smoke_test=lambda _path: None,
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
        ModelInstaller(store, smoke_test=lambda _path: None).install(model)
    assert not store.model_path(model).exists()

    monkeypatch.undo()
    patch_registered_model(monkeypatch, model)
    store = store_at(tmp_path / "cancel")
    with pytest.raises(ModelDownloadError, match="cancelled"):
        ModelInstaller(
            store,
            snapshot_download=lambda **_kwargs: pytest.fail("download must not run"),
            smoke_test=lambda _path: None,
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
            smoke_test=lambda _path: None,
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
            smoke_test=lambda _path: (_ for _ in ()).throw(ModelDownloadError("load failed")),
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
            smoke_test=lambda _path: None,
        ).install(new_model)

    assert (root / "pytorch_model.bin").read_bytes() == old_content
    assert not any(store.paths.staging_root.iterdir())
