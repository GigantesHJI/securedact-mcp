# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class BenchmarkWorkspace:
    root: Path
    downloads: Path
    extracted: Path
    generated: Path
    external: Path
    private_holdout: Path
    cache: Path
    manifests: Path
    reports: Path
    restricted: Path


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _reject_linked_ancestors(path: Path) -> None:
    for parent in (path, *path.parents):
        if not parent.exists():
            continue
        reparse = bool(getattr(parent.stat(), "st_file_attributes", 0) & 0x400)
        if parent.is_symlink() or reparse:
            raise ValueError("benchmark_workspace_symlink_forbidden")


def resolve_workspace(
    *,
    repository_root: Path | None = None,
    create: bool = True,
    environment: dict[str, str] | None = None,
) -> BenchmarkWorkspace:
    env = os.environ if environment is None else environment
    configured = env.get("SECUREDACT_BENCHMARK_DATA_DIR")
    if configured:
        root = Path(configured).expanduser()
        if not root.is_absolute():
            raise ValueError("benchmark_workspace_path_must_be_absolute")
    elif os.name == "nt":
        local_app_data = env.get("LOCALAPPDATA")
        if not local_app_data:
            raise ValueError("benchmark_workspace_home_unavailable")
        root = Path(local_app_data) / "Securedact" / "benchmark-data"
    else:
        data_home = env.get("XDG_DATA_HOME")
        root = (
            Path(data_home) / "securedact" / "benchmark-data"
            if data_home
            else Path.home() / ".local" / "share" / "securedact" / "benchmark-data"
        )
    candidate = root.absolute()
    _reject_linked_ancestors(candidate)
    resolved = candidate.resolve(strict=False)
    if repository_root is not None and _is_relative_to(resolved, repository_root.resolve()):
        raise ValueError("benchmark_workspace_must_be_outside_repository")
    # External and restricted data must never traverse a link back into the repository.
    _reject_linked_ancestors(resolved)
    paths = {
        name: resolved / name
        for name in (
            "downloads",
            "extracted",
            "generated",
            "external",
            "restricted",
            "private-holdout",
            "cache",
            "manifests",
            "reports",
        )
    }
    if create:
        resolved.mkdir(parents=True, exist_ok=True)
        _reject_linked_ancestors(candidate)
        for path in paths.values():
            path.mkdir(exist_ok=True)
    return BenchmarkWorkspace(
        root=resolved,
        downloads=paths["downloads"],
        extracted=paths["extracted"],
        generated=paths["generated"],
        external=paths["external"],
        restricted=paths["restricted"],
        private_holdout=paths["private-holdout"],
        cache=paths["cache"],
        manifests=paths["manifests"],
        reports=paths["reports"],
    )
