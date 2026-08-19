from __future__ import annotations

import pytest

from scripts.validate_release_artifacts import _validate_member


@pytest.mark.parametrize(
    "name",
    [
        "package/pytorch_model.bin",
        "package/model.safetensors",
        "package/model.pt",
        "package/.cache/huggingface/checkpoint.json",
        "package/models--xlm-roberta-large/tokenizer.json",
    ],
)
def test_model_weights_and_caches_are_forbidden_from_release_archives(name: str) -> None:
    assert _validate_member(name, 100)


def test_model_registry_source_is_allowed_without_model_assets() -> None:
    assert _validate_member("package/securedact_mcp/model_registry.py", 100) == []
