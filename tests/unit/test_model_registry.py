from __future__ import annotations

from dataclasses import replace

import pytest

from securedact_mcp.model_registry import (
    DUTCH_MODEL,
    ENGLISH_MODEL,
    IMMUTABLE_REVISION_PATTERN,
    ModelRegistryError,
    validate_registry,
)


def test_official_repositories_and_pinned_revisions_are_exact() -> None:
    assert ENGLISH_MODEL.upstream_repo == "flair/ner-english-large"
    assert DUTCH_MODEL.upstream_repo == "flair/ner-dutch-large"
    assert ENGLISH_MODEL.upstream_revision == "e2b1caabf7f9bac1e7829db73eac734df7e6ad7b"
    assert DUTCH_MODEL.upstream_revision == "44c285912a9d6eec4d0858580f3cb13b7b8c9959"
    assert IMMUTABLE_REVISION_PATTERN.fullmatch(ENGLISH_MODEL.upstream_revision)
    assert IMMUTABLE_REVISION_PATTERN.fullmatch(DUTCH_MODEL.upstream_revision)
    assert ENGLISH_MODEL.required_files == ("pytorch_model.bin",)
    assert DUTCH_MODEL.required_files == ("pytorch_model.bin",)
    assert ENGLISH_MODEL.expected_sizes["pytorch_model.bin"] == 2_239_866_761
    assert DUTCH_MODEL.expected_sizes["pytorch_model.bin"] == 2_239_866_697
    assert ENGLISH_MODEL.expected_hashes["pytorch_model.bin"] == (
        "1f59c05bbd3db05518b632f212b1aac7de1ff0b3914d6c0d587b6a68e214a287"
    )
    assert DUTCH_MODEL.expected_hashes["pytorch_model.bin"] == (
        "69644e87635b92a84d0f23f67c0fce11eac39a3c9a0dae107e7e3e0d6ef20edd"
    )


@pytest.mark.parametrize("revision", ["main", "master", "latest", "v1", "abc123"])
def test_moving_or_incomplete_revisions_are_rejected(revision: str) -> None:
    with pytest.raises(ModelRegistryError, match="immutable"):
        validate_registry((replace(ENGLISH_MODEL, upstream_revision=revision), DUTCH_MODEL))


def test_unknown_repository_is_rejected() -> None:
    with pytest.raises(ModelRegistryError, match="allowlisted"):
        validate_registry((replace(ENGLISH_MODEL, upstream_repo="example/unknown"), DUTCH_MODEL))


def test_duplicate_language_assignment_is_rejected() -> None:
    duplicate = replace(DUTCH_MODEL, language="en")
    with pytest.raises(ModelRegistryError, match="duplicate language"):
        validate_registry((ENGLISH_MODEL, duplicate))
