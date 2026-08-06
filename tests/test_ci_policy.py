from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.retry_network import is_transient
from scripts.validate_repository_size import validate_sizes
from scripts.validate_workflows import validate_workflows

ROOT = Path(__file__).resolve().parents[1]


def test_workflow_yaml_inventory_permissions_timeouts_and_fork_safety() -> None:
    assert validate_workflows(ROOT) == []
    essential = (ROOT / ".github" / "workflows" / "ci-essential.yml").read_text(encoding="utf-8")
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "pull_request:" in essential
    assert "contents: read" in essential
    assert "secrets." not in essential
    assert "pull_request:" not in release
    assert "cancel-in-progress: false" in release


def test_mutable_action_reference_is_rejected(tmp_path: Path) -> None:
    shutil.copytree(ROOT / ".github", tmp_path / ".github")
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts")
    workflow = tmp_path / ".github" / "workflows" / "ci-essential.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
            "actions/checkout@v6",
            1,
        ),
        encoding="utf-8",
    )
    assert any("not pinned to a full SHA" in error for error in validate_workflows(tmp_path))


def test_repository_and_fixture_size_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    normal = tmp_path / "normal.bin"
    normal.write_bytes(b"12345")
    monkeypatch.setattr("scripts.validate_repository_size.GENERAL_LIMIT", 4)
    assert any("exceeds" in error for error in validate_sizes(tmp_path, [normal]))

    fixture = tmp_path / "benchmarks" / "fixtures" / "smoke" / "data.jsonl"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(b"12345")
    monkeypatch.setattr("scripts.validate_repository_size.GENERAL_LIMIT", 10)
    monkeypatch.setattr("scripts.validate_repository_size.FIXTURE_TOTAL_LIMIT", 4)
    assert "committed benchmark fixtures exceed 25 MiB total" in validate_sizes(tmp_path, [fixture])

    private = tmp_path / "benchmarks" / "private-holdout" / "records.jsonl"
    private.parent.mkdir(parents=True)
    private.write_text("{}\n", encoding="utf-8")
    assert any("forbidden" in error for error in validate_sizes(tmp_path, [private]))


def test_retry_classifier_retries_only_known_transient_failures() -> None:
    assert is_transient("HTTP 503 temporarily unavailable")
    assert is_transient("connection reset")
    assert not is_transient("403 Forbidden")
    assert not is_transient("checksum mismatch after download timeout")
    assert not is_transient("pytest assertion failed")
