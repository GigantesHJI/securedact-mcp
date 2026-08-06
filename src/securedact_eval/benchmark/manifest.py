# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


class BenchmarkManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: Literal[2] = 2
    profile: str
    generator_version: str
    seed: int
    dependency_lock_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    tier: Literal["public", "external", "restricted"]
    document_count: int = Field(ge=1)
    entity_count: int = Field(ge=0)
    negative_count: int = Field(ge=0)
    adversarial_count: int = Field(ge=0)
    mixed_entity_count: int = Field(ge=0)
    language_counts: dict[str, int]
    source_counts: dict[str, int]
    split_counts: dict[str, int]
    assertion_type_counts: dict[str, int]
    category_counts: dict[str, int]
    domain_counts: dict[str, int]
    transformation_counts: dict[str, int]
    template_family_counts: dict[str, int]
    files: dict[str, str]
    generation: dict[str, Any] = Field(default_factory=dict)


def verify_benchmark(root: Path) -> BenchmarkManifest:
    manifest_path = root / "manifest.json"
    try:
        manifest = BenchmarkManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("benchmark_manifest_invalid") from exc
    resolved_root = root.resolve()
    for relative, expected in manifest.files.items():
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError("benchmark_manifest_path_escape") from exc
        if not candidate.is_file() or sha256_file(candidate) != expected:
            raise ValueError("benchmark_manifest_hash_mismatch")
    return manifest


def write_manifest(path: Path, manifest: BenchmarkManifest) -> None:
    path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
