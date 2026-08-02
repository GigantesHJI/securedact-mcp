from __future__ import annotations

import os
from pathlib import Path

import pytest

from securedact_mcp.model_verifier_client import (
    OfflineModelLoadError,
    isolated_offline_flair_load_test,
)


def _write_fake_flair(root: Path) -> Path:
    package = root / "flair" / "models"
    package.mkdir(parents=True)
    (root / "flair" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "sequence_tagger_model.py").write_text(
        """
import os
from pathlib import Path

class SequenceTagger:
    @staticmethod
    def load(_entrypoint):
        assert os.environ["HF_HUB_OFFLINE"] == "1"
        assert os.environ["TRANSFORMERS_OFFLINE"] == "1"
        cache = Path(os.environ["HF_HUB_CACHE"])
        if cache != Path(os.environ["TRANSFORMERS_CACHE"]):
            raise RuntimeError("cache variables differ")
        required = cache / "models--xlm-roberta-large" / "tokenizer.json"
        if not required.is_file():
            raise OSError("ambient tokenizer cache is unavailable")
        print("synthetic Flair loader output must remain captured")
        return object()
""".lstrip(),
        encoding="utf-8",
    )
    return root


def test_fresh_process_fails_without_managed_assets_and_succeeds_with_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_packages = _write_fake_flair(tmp_path / "fake-packages")
    previous = os.environ.get("PYTHONPATH")
    python_path = str(fake_packages) if not previous else f"{fake_packages}{os.pathsep}{previous}"
    monkeypatch.setenv("PYTHONPATH", python_path)
    checkpoint = tmp_path / "pytorch_model.bin"
    checkpoint.write_bytes(b"tiny-mocked-checkpoint")
    cache_root = tmp_path / "managed-cache"

    with pytest.raises(OfflineModelLoadError) as failure:
        isolated_offline_flair_load_test(checkpoint, cache_root)
    assert failure.value.safe_exception_type == "OSError"

    tokenizer = cache_root / "hub" / "models--xlm-roberta-large" / "tokenizer.json"
    tokenizer.parent.mkdir(parents=True)
    tokenizer.write_text("{}", encoding="utf-8")

    isolated_offline_flair_load_test(checkpoint, cache_root)
