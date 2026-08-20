from __future__ import annotations

import json
import shutil
from pathlib import Path

from scripts.release_metadata import (
    MODEL_ASSET_REVIEW_PATH,
    VERIFIED_CODEOWNER,
    VERIFIED_SECURITY_CONTACT,
    _module_version,
    _version,
    create_metadata,
    unresolved_release_blockers,
)


def test_package_and_module_versions_match() -> None:
    assert _module_version() == _version()


def _copy_release_records(destination: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    for relative_path in (
        Path(".github/CODEOWNERS"),
        Path("SECURITY.md"),
        Path("pyproject.toml"),
        Path(MODEL_ASSET_REVIEW_PATH),
        Path("server.json"),
    ):
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative_path, target)


def test_authoritative_release_records_resolve_all_blockers(tmp_path: Path) -> None:
    _copy_release_records(tmp_path)

    assert unresolved_release_blockers(tmp_path) == []


def test_codeowner_must_be_the_verified_repository_owner(tmp_path: Path) -> None:
    _copy_release_records(tmp_path)
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.write_text(
        codeowners.read_text(encoding="utf-8").replace(VERIFIED_CODEOWNER, "@placeholder"),
        encoding="utf-8",
    )

    assert unresolved_release_blockers(tmp_path) == ["codeowners_maintainer"]


def test_security_contact_must_be_authoritative_and_monitored(tmp_path: Path) -> None:
    _copy_release_records(tmp_path)
    security = tmp_path / "SECURITY.md"
    security.write_text(
        security.read_text(encoding="utf-8").replace(
            VERIFIED_SECURITY_CONTACT, "unconfirmed@example.test"
        ),
        encoding="utf-8",
    )

    assert unresolved_release_blockers(tmp_path) == ["security_contact_confirmation"]


def test_model_review_must_preserve_nonredistribution_decision(tmp_path: Path) -> None:
    _copy_release_records(tmp_path)
    review_path = tmp_path / MODEL_ASSET_REVIEW_PATH
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["distribution_decision"]["redistributed_by_securedact"] = True
    review_path.write_text(json.dumps(review), encoding="utf-8")

    assert unresolved_release_blockers(tmp_path) == ["model_weight_license_review"]


def test_registry_metadata_must_match_release_version(tmp_path: Path) -> None:
    _copy_release_records(tmp_path)
    server_path = tmp_path / "server.json"
    server = json.loads(server_path.read_text(encoding="utf-8"))
    server["version"] = "9.9.9"
    server_path.write_text(json.dumps(server), encoding="utf-8")

    assert unresolved_release_blockers(tmp_path) == ["registry_metadata"]


def test_release_metadata_records_artifact_lock_corpus_and_model_provenance(
    tmp_path: Path,
) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "synthetic.whl").write_bytes(b"synthetic-wheel")
    (dist / "securedact-mcp.spdx.json").write_text("{}", encoding="utf-8")
    (dist / "quality-deterministic.json").write_text("{}", encoding="utf-8")
    output = dist / "provenance.json"

    metadata = create_metadata(dist, output, "v0.2.0")
    serialized = output.read_text(encoding="utf-8")

    assert json.loads(serialized) == metadata
    assert metadata["dependency_lock_digest"]
    assert metadata["model_asset_license_review_digest"]
    assert metadata["benchmark_corpus_manifest_digest"]
    assert len(metadata["model_registry"]["models"]) == 2
    assert len(metadata["model_registry"]["runtime_components"]) == 1
    assert all(
        file["sha256"]
        for model in metadata["model_registry"]["models"]
        for file in model["required_files"].values()
    )
    assert str(Path.cwd()) not in serialized
