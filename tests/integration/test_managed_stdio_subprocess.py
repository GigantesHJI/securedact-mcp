from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sysconfig
from datetime import UTC, datetime
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _console_entrypoint() -> str:
    discovered = shutil.which("securedact-mcp")
    if discovered:
        return discovered
    scripts = Path(sysconfig.get_path("scripts"))
    for name in ("securedact-mcp.exe", "securedact-mcp"):
        candidate = scripts / name
        if candidate.is_file():
            return str(candidate)
    raise AssertionError("the installed securedact-mcp console entry point is required")


def _write_model(root: Path, *, model_id: str, language: str, revision: str, data: bytes) -> None:
    model_root = root / "models" / model_id
    model_root.mkdir(parents=True)
    model_file = model_root / "pytorch_model.bin"
    model_file.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    manifest = {
        "schema_version": 1,
        "model_id": model_id,
        "language": language,
        "upstream_repo": f"flair/ner-{'english' if language == 'en' else 'dutch'}-large",
        "upstream_revision": revision,
        "installed_at": datetime.now(UTC).isoformat(),
        "securedact_version": "0.1.0",
        "entrypoint": "pytorch_model.bin",
        "files": {"pytorch_model.bin": {"size": len(data), "sha256": digest}},
    }
    (model_root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _write_subprocess_fakes(root: Path, english: bytes, dutch: bytes) -> None:
    (root / "flair" / "models").mkdir(parents=True)
    (root / "flair" / "__init__.py").write_text("", encoding="utf-8")
    (root / "flair" / "models" / "__init__.py").write_text("", encoding="utf-8")
    (root / "flair" / "data.py").write_text(
        "class Sentence:\n"
        "    def __init__(self, text):\n"
        "        self.text = text\n"
        "    def get_spans(self, _label):\n"
        "        return []\n",
        encoding="utf-8",
    )
    (root / "flair" / "models" / "sequence_tagger_model.py").write_text(
        "from pathlib import Path\n"
        "class SequenceTagger:\n"
        "    @classmethod\n"
        "    def load(cls, path):\n"
        "        if not Path(path).is_file():\n"
        "            raise RuntimeError('missing synthetic model')\n"
        "        return cls()\n"
        "    def predict(self, _sentence):\n"
        "        return None\n",
        encoding="utf-8",
    )

    english_hash = hashlib.sha256(english).hexdigest()
    dutch_hash = hashlib.sha256(dutch).hexdigest()
    (root / "sitecustomize.py").write_text(
        "from securedact_mcp import model_registry as registry\n"
        "from securedact_mcp import model_store\n"
        "model_store.tempfile.gettempdir = lambda: '__synthetic_non_temp_root__'\n"
        "def model(model_id, language, name, repo, revision, size, digest):\n"
        "    return registry.SupportedModel(\n"
        "        id=model_id, language=language, language_name=name,\n"
        "        display_name='Synthetic ' + name, upstream_repo=repo,\n"
        "        upstream_revision=revision, required_files=('pytorch_model.bin',),\n"
        "        optional_files=(), approximate_size_bytes=size, citation='Synthetic',\n"
        "        license_identifier=None, license_note='Synthetic',\n"
        "        minimum_securedact_version='0.1.0',\n"
        "        required_file_sizes=(('pytorch_model.bin', size),),\n"
        "        required_file_sha256=(('pytorch_model.bin', digest),),\n"
        "    )\n"
        f"english = model('english-large', 'en', 'English', 'flair/ner-english-large', "
        f"{'a' * 40!r}, {len(english)}, {english_hash!r})\n"
        f"dutch = model('dutch-large', 'nl', 'Dutch', 'flair/ner-dutch-large', "
        f"{'b' * 40!r}, {len(dutch)}, {dutch_hash!r})\n"
        "registry.SUPPORTED_MODELS = (english, dutch)\n"
        "registry.MODELS_BY_ID.clear()\n"
        "registry.MODELS_BY_ID.update({model.id: model for model in registry.SUPPORTED_MODELS})\n"
        "registry.MODELS_BY_LANGUAGE.clear()\n"
        "registry.MODELS_BY_LANGUAGE.update(\n"
        "    {model.language: model for model in registry.SUPPORTED_MODELS}\n"
        ")\n",
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_fresh_console_process_uses_active_managed_models(
    tmp_path: Path,
) -> None:
    app_root = tmp_path / "app-data"
    fake_imports = tmp_path / "subprocess-fakes"
    english = b"tiny-english-flair-model"
    dutch = b"tiny-dutch-flair-model"
    _write_model(app_root, model_id="english-large", language="en", revision="a" * 40, data=english)
    _write_model(app_root, model_id="dutch-large", language="nl", revision="b" * 40, data=dutch)
    (app_root / "model-config.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "enabled_languages": ["en", "nl"],
                "active_models": {"en": "english-large", "nl": "dutch-large"},
            }
        ),
        encoding="utf-8",
    )
    _write_subprocess_fakes(fake_imports, english, dutch)

    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONUTF8": "1",
            "PYTHONPATH": os.pathsep.join(
                value for value in (str(fake_imports), environment.get("PYTHONPATH")) if value
            ),
            "SECUREDACT_APP_DATA_DIR": str(app_root),
            "SECUREDACT_REQUIRE_FLAIR": "1",
            # Reproduces the inherited legacy setting that previously diverted
            # build_runtime away from the valid managed configuration.
            "SECUREDACT_MODEL_ID": "english-large",
        }
    )
    environment.pop("SECUREDACT_MODEL_DIR", None)
    environment.pop("SECUREDACT_MODEL_PATH", None)
    environment.pop("SECUREDACT_FLAIR_MODEL", None)
    entrypoint = _console_entrypoint()

    for command in ("status", "verify"):
        completed = subprocess.run(  # noqa: S603 - resolved installed entry point
            [entrypoint, "models", command],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout == ""

    diagnostic = subprocess.run(  # noqa: S603 - resolved installed entry point
        [entrypoint, "models", "diagnose"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert diagnostic.returncode == 0, diagnostic.stderr
    assert diagnostic.stdout == ""
    assert str(app_root) not in diagnostic.stderr
    assert "pytorch_model.bin" not in diagnostic.stderr
    details = json.loads(diagnostic.stderr)
    assert details["config_found"] is True
    assert details["enabled_languages"] == ["en", "nl"]
    assert details["active_model_ids"] == {
        "en": "english-large",
        "nl": "dutch-large",
    }
    assert details["verified_model_states"] == {
        "dutch-large": "ready",
        "english-large": "ready",
    }
    router = next(
        state
        for state in details["runtime_detector_states"]
        if state["name"] == "flair_language_router"
    )
    assert router["state"] == "ready"
    assert router["children"] == {"en": "ready", "nl": "ready"}
    assert details["contextual_ready"] is True
    assert details["final_failure_code"] is None

    parameters = StdioServerParameters(command=entrypoint, env=environment)
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "analyze_text",
                {"text": "Contact alex.example@example.test", "policy": "default"},
            )

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent.get("failure_code") != "contextual_model_not_configured"
    assert result.structuredContent.get("status") != "blocked"
    assert result.structuredContent["engine_ready"] is True
