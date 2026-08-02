from __future__ import annotations

import os
from pathlib import Path

OFFLINE_ENVIRONMENT_KEYS = (
    "HF_HOME",
    "HF_HUB_CACHE",
    "TRANSFORMERS_CACHE",
    "HF_HUB_OFFLINE",
    "TRANSFORMERS_OFFLINE",
    "HF_HUB_DISABLE_TELEMETRY",
)


def managed_offline_environment(cache_root: Path) -> dict[str, str]:
    """Return the one cache/offline environment used by setup, verify, and runtime."""

    resolved = cache_root.resolve()
    hub = resolved / "hub"
    return {
        "HF_HOME": str(resolved),
        "HF_HUB_CACHE": str(hub),
        # Transformers 4.x still consults this variable for legacy serialized
        # model identifiers. HF_HOME remains the forward-compatible setting.
        "TRANSFORMERS_CACHE": str(hub),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
    }


def configure_managed_offline_environment(cache_root: Path) -> None:
    os.environ.update(managed_offline_environment(cache_root))
