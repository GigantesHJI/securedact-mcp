from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .model_management import ModelManifest


class ModelSource(Protocol):
    """Extension point for a future user-approved, authenticated download source."""

    async def fetch_manifest(self, model_id: str) -> ModelManifest: ...

    async def download_pack(self, model_id: str, destination: Path) -> None: ...
