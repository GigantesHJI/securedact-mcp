from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from .runtime_environment import managed_offline_environment

VERIFY_TIMEOUT_SECONDS = 300


class OfflineModelLoadError(RuntimeError):
    """A model did not load in a clean, network-disabled child process."""

    def __init__(self, safe_exception_type: str | None = None) -> None:
        super().__init__("The contextual model failed its isolated offline load test")
        self.safe_exception_type = safe_exception_type


def isolated_offline_flair_load_test(entrypoint: Path, cache_root: Path) -> None:
    environment = dict(os.environ)
    for name in (
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "HUGGINGFACE_HUB_TOKEN",
        "HF_ENDPOINT",
    ):
        environment.pop(name, None)
    environment.update(managed_offline_environment(cache_root))
    environment["PYTHONNOUSERSITE"] = "1"
    command = (
        sys.executable,
        "-m",
        "securedact_mcp.model_verifier",
        "--entrypoint",
        str(entrypoint.resolve()),
        "--cache-root",
        str(cache_root.resolve()),
    )
    try:
        result = subprocess.run(  # noqa: S603
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OfflineModelLoadError(type(exc).__name__) from exc
    if result.returncode == 0:
        return

    exception_type: str | None = None
    try:
        diagnostic = json.loads(result.stderr.strip().splitlines()[-1])
        candidate = diagnostic.get("exception_type")
        if isinstance(candidate, str) and candidate.isidentifier():
            exception_type = candidate
    except (IndexError, json.JSONDecodeError, AttributeError):
        pass
    if os.getenv("SECUREDACT_MODEL_DIAGNOSTICS") == "1":
        print(
            f"Securedact isolated model verification failed ({exception_type or 'unknown_error'}).",
            file=sys.stderr,
        )
    raise OfflineModelLoadError(exception_type)
