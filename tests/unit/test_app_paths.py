from __future__ import annotations

import sys
from pathlib import Path

from securedact_core import SecuredactPaths


def test_explicit_app_data_override_is_single_storage_root(tmp_path: Path) -> None:
    paths = SecuredactPaths.resolve(tmp_path / "Securedact")
    paths.ensure()
    assert paths.models == paths.root / "models"
    assert paths.model_staging == paths.root / "model-staging"
    assert paths.logs == paths.root / "logs"
    assert all(path.is_dir() for path in (paths.models, paths.model_staging, paths.logs))


def test_windows_resolution_uses_local_app_data_not_working_directory(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("SECUREDACT_APP_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setattr(sys, "platform", "win32")
    paths = SecuredactPaths.resolve()
    assert paths.root == (tmp_path / "LocalAppData" / "Securedact").resolve()
