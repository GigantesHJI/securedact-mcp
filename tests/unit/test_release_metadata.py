from __future__ import annotations

import json
from pathlib import Path

from scripts.release_metadata import _module_version, _version, create_metadata


def test_package_and_module_versions_match() -> None:
    assert _module_version() == _version()


def test_release_metadata_records_artifact_lock_corpus_and_model_provenance(
    tmp_path: Path,
) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "synthetic.whl").write_bytes(b"synthetic-wheel")
    (dist / "securedact-mcp.spdx.json").write_text("{}", encoding="utf-8")
    (dist / "quality-deterministic.json").write_text("{}", encoding="utf-8")
    output = dist / "provenance.json"

    metadata = create_metadata(dist, output, "v0.1.0")
    serialized = output.read_text(encoding="utf-8")

    assert json.loads(serialized) == metadata
    assert metadata["dependency_lock_digest"]
    assert metadata["benchmark_corpus_manifest_digest"]
    assert len(metadata["model_registry"]["models"]) == 2
    assert len(metadata["model_registry"]["runtime_components"]) == 1
    assert all(
        file["sha256"]
        for model in metadata["model_registry"]["models"]
        for file in model["required_files"].values()
    )
    assert str(Path.cwd()) not in serialized
