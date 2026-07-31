from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

APP_DIRECTORY_NAME = "Securedact"


@dataclass(frozen=True, slots=True)
class SecuredactPaths:
    """All writable Securedact locations, rooted outside the installation directory."""

    root: Path
    models: Path
    model_staging: Path
    logs: Path

    @classmethod
    def resolve(cls, override: str | Path | None = None) -> SecuredactPaths:
        explicit = override or os.getenv("SECUREDACT_APP_DATA_DIR")
        if explicit:
            root = Path(explicit).expanduser()
        elif sys.platform == "win32":
            local_app_data = os.getenv("LOCALAPPDATA")
            if not local_app_data:
                raise RuntimeError("The local application-data directory is unavailable")
            root = Path(local_app_data) / APP_DIRECTORY_NAME
        elif sys.platform == "darwin":
            root = Path.home() / "Library" / "Application Support" / APP_DIRECTORY_NAME
        else:
            data_home = os.getenv("XDG_DATA_HOME")
            root = (
                Path(data_home) if data_home else Path.home() / ".local" / "share"
            ) / APP_DIRECTORY_NAME
        root = root.resolve()
        return cls(
            root=root,
            models=root / "models",
            model_staging=root / "model-staging",
            logs=root / "logs",
        )

    def ensure(self) -> None:
        for directory in (self.root, self.models, self.model_staging, self.logs):
            directory.mkdir(parents=True, exist_ok=True)
