from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from securedact_core.model_management import ModelManifest


def manifest_data() -> dict[str, object]:
    return {
        "schema_version": 1,
        "model_id": "english-large",
        "display_name": "English privacy model",
        "language": "en",
        "model_type": "flair-sequence-tagger",
        "securedact_min_version": "0.1.0",
        "securedact_max_version": None,
        "created_at": datetime.now(UTC).isoformat(),
        "files": [
            {"path": "model/pytorch_model.bin", "sha256": "a" * 64, "size": 1},
            {"path": "tokenizer/tokenizer.json", "sha256": "b" * 64, "size": 1},
        ],
        "entrypoint": "model/pytorch_model.bin",
        "tokenizer_root": "tokenizer",
    }


def test_valid_manifest() -> None:
    assert ModelManifest.model_validate(manifest_data()).model_id == "english-large"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("model_id", "../English"),
        ("entrypoint", "C:/model.bin"),
        ("entrypoint", "../model.bin"),
    ],
)
def test_manifest_rejects_unsupported_or_unsafe_values(field: str, value: object) -> None:
    data = manifest_data()
    data[field] = value
    with pytest.raises(ValidationError):
        ModelManifest.model_validate(data)


def test_manifest_rejects_duplicate_paths_case_insensitively() -> None:
    data = manifest_data()
    data["files"] = [
        {"path": "model/pytorch_model.bin", "sha256": "a" * 64, "size": 1},
        {"path": "MODEL/PYTORCH_MODEL.BIN", "sha256": "a" * 64, "size": 1},
        {"path": "tokenizer/tokenizer.json", "sha256": "b" * 64, "size": 1},
    ]
    with pytest.raises(ValidationError, match="Duplicate"):
        ModelManifest.model_validate(data)
