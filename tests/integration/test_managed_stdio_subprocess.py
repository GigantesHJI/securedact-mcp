from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import subprocess
import sysconfig
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

RUNTIME_REVISION = "c" * 40
RUNTIME_CONTENT = b"tiny-synthetic-tokenizer"
RUNTIME_DIGEST = hashlib.sha256(RUNTIME_CONTENT).hexdigest()
RUNTIME_CACHE_REPOSITORY = "models--synthetic-transformer"
PROTOCOL_STARTUP_DEADLINE_SECONDS = 10.0


def _console_entrypoint() -> str:
    explicit = os.getenv("SECUREDACT_TEST_CONSOLE_ENTRYPOINT")
    if explicit and Path(explicit).is_file():
        return explicit
    discovered = shutil.which("securedact-mcp")
    if discovered:
        return discovered
    scripts = Path(sysconfig.get_path("scripts"))
    for name in ("securedact-mcp.exe", "securedact-mcp"):
        candidate = scripts / name
        if candidate.is_file():
            return str(candidate)
    raise AssertionError("the installed securedact-mcp console entry point is required")


def _read_protocol_message(
    process: subprocess.Popen[str], timeout: float = PROTOCOL_STARTUP_DEADLINE_SECONDS
) -> dict[str, object]:
    assert process.stdout is not None
    received: queue.Queue[str] = queue.Queue(maxsize=1)
    thread = threading.Thread(
        target=lambda: received.put(process.stdout.readline()),
        daemon=True,
    )
    thread.start()
    try:
        line = received.get(timeout=timeout)
    except queue.Empty as exc:
        raise AssertionError("MCP protocol response missed the startup deadline") from exc
    if not line:
        raise AssertionError("MCP stdio server closed before returning a protocol response")
    payload = json.loads(line)
    assert isinstance(payload, dict)
    return payload


def _send_protocol_message(process: subprocess.Popen[str], payload: dict[str, object]) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
    process.stdin.flush()


def _write_model(root: Path, *, model_id: str, language: str, revision: str, data: bytes) -> None:
    model_root = root / "models" / model_id
    model_root.mkdir(parents=True)
    model_file = model_root / "pytorch_model.bin"
    model_file.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    manifest = {
        "schema_version": 2,
        "model_id": model_id,
        "language": language,
        "upstream_repo": f"flair/ner-{'english' if language == 'en' else 'dutch'}-large",
        "upstream_revision": revision,
        "installed_at": datetime.now(UTC).isoformat(),
        "securedact_version": "0.1.0",
        "entrypoint": "pytorch_model.bin",
        "files": {
            "pytorch_model.bin": {
                "size": len(data),
                "sha256": digest,
                "component_id": model_id,
                "upstream_repo": f"flair/ner-{'english' if language == 'en' else 'dutch'}-large",
                "upstream_revision": revision,
                "storage": "model",
                "relative_path": "pytorch_model.bin",
            },
            "runtime/synthetic-transformer-runtime/refs/main": {
                "size": len(RUNTIME_REVISION),
                "sha256": hashlib.sha256(RUNTIME_REVISION.encode("ascii")).hexdigest(),
                "component_id": "synthetic-transformer-runtime",
                "upstream_repo": "example/synthetic-transformer",
                "upstream_revision": RUNTIME_REVISION,
                "storage": "runtime_cache",
                "relative_path": f"hub/{RUNTIME_CACHE_REPOSITORY}/refs/main",
            },
            "runtime/synthetic-transformer-runtime/tokenizer.json": {
                "size": len(RUNTIME_CONTENT),
                "sha256": RUNTIME_DIGEST,
                "component_id": "synthetic-transformer-runtime",
                "upstream_repo": "example/synthetic-transformer",
                "upstream_revision": RUNTIME_REVISION,
                "storage": "runtime_cache",
                "relative_path": (
                    f"hub/{RUNTIME_CACHE_REPOSITORY}/snapshots/{RUNTIME_REVISION}/tokenizer.json"
                ),
            },
        },
    }
    (model_root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _write_subprocess_fakes(root: Path, english: bytes, dutch: bytes) -> None:
    (root / "flair" / "models").mkdir(parents=True)
    (root / "flair" / "__init__.py").write_text("", encoding="utf-8")
    (root / "flair" / "models" / "__init__.py").write_text("", encoding="utf-8")
    (root / "flair" / "data.py").write_text(
        "class Label:\n"
        "    def __init__(self, value, score=0.99):\n"
        "        self.value = value\n"
        "        self.score = score\n"
        "class Span:\n"
        "    def __init__(self, start, end, value='PER'):\n"
        "        self.start_position = start\n"
        "        self.end_position = end\n"
        "        self._label = Label(value)\n"
        "    def get_label(self, _name):\n"
        "        return self._label\n"
        "class Sentence:\n"
        "    def __init__(self, text):\n"
        "        self.text = text\n"
        "        self.spans = []\n"
        "    def get_spans(self, _label):\n"
        "        return self.spans\n",
        encoding="utf-8",
    )
    (root / "flair" / "models" / "sequence_tagger_model.py").write_text(
        "import os\n"
        "import time\n"
        "from pathlib import Path\n"
        "class SequenceTagger:\n"
        "    @classmethod\n"
        "    def load(cls, path):\n"
        "        count = os.environ.get('SECUREDACT_TEST_LOAD_COUNT')\n"
        "        if count:\n"
        "            with open(count, 'a', encoding='ascii') as stream:\n"
        "                stream.write('load\\n')\n"
        "        started = os.environ.get('SECUREDACT_TEST_LOAD_STARTED')\n"
        "        if started:\n"
        "            Path(started).write_text('started', encoding='ascii')\n"
        "        gate = os.environ.get('SECUREDACT_TEST_LOAD_GATE')\n"
        "        deadline = time.monotonic() + 20\n"
        "        while gate and not Path(gate).is_file():\n"
        "            if time.monotonic() >= deadline:\n"
        "                raise RuntimeError('synthetic load gate timeout')\n"
        "            time.sleep(0.02)\n"
        "        if not Path(path).is_file():\n"
        "            raise RuntimeError('missing synthetic model')\n"
        f"        cache_file = Path(os.environ['HF_HUB_CACHE']) / "
        f"{RUNTIME_CACHE_REPOSITORY!r} / 'snapshots' / {RUNTIME_REVISION!r} / "
        "'tokenizer.json'\n"
        "        if not cache_file.is_file():\n"
        "            raise RuntimeError('missing managed tokenizer dependency')\n"
        "        return cls()\n"
        "    def predict(self, sentence):\n"
        "        predicted = os.environ.get('SECUREDACT_TEST_PREDICT_COUNT')\n"
        "        if predicted:\n"
        "            with open(predicted, 'a', encoding='ascii') as stream:\n"
        "                stream.write('predict\\n')\n"
        "        value = 'Emma de Vries'\n"
        "        start = sentence.text.find(value)\n"
        "        if start >= 0:\n"
        "            from flair.data import Span\n"
        "            sentence.spans = [Span(start, start + len(value))]\n",
        encoding="utf-8",
    )

    english_hash = hashlib.sha256(english).hexdigest()
    dutch_hash = hashlib.sha256(dutch).hexdigest()
    (root / "sitecustomize.py").write_text(
        "from securedact_mcp import model_registry as registry\n"
        "from securedact_mcp import model_store\n"
        "model_store.tempfile.gettempdir = lambda: '__synthetic_non_temp_root__'\n"
        "runtime = registry.SupportedRuntimeComponent(\n"
        "    id='synthetic-transformer-runtime', display_name='Synthetic runtime',\n"
        "    upstream_repo='example/synthetic-transformer',\n"
        f"    upstream_revision={RUNTIME_REVISION!r},\n"
        f"    cache_repository_name={RUNTIME_CACHE_REPOSITORY!r},\n"
        "    required_files=('tokenizer.json',),\n"
        f"    required_file_sizes=(('tokenizer.json', {len(RUNTIME_CONTENT)}),),\n"
        f"    required_file_sha256=(('tokenizer.json', {RUNTIME_DIGEST!r}),),\n"
        f"    approximate_size_bytes={len(RUNTIME_CONTENT)},\n"
        "    license_identifier='MIT', license_note='Synthetic')\n"
        "registry.RUNTIME_COMPONENTS_BY_ID.clear()\n"
        "registry.RUNTIME_COMPONENTS_BY_ID[runtime.id] = runtime\n"
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
        "        runtime_component_ids=(runtime.id,),\n"
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
    runtime_root = app_root / "models" / ".runtime-cache" / "hub" / RUNTIME_CACHE_REPOSITORY
    (runtime_root / "refs").mkdir(parents=True)
    (runtime_root / "refs" / "main").write_text(
        RUNTIME_REVISION,
        encoding="ascii",
        newline="",
    )
    snapshot = runtime_root / "snapshots" / RUNTIME_REVISION
    snapshot.mkdir(parents=True)
    (snapshot / "tokenizer.json").write_bytes(RUNTIME_CONTENT)
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
    assert details["deterministic_detectors_ready"] is True
    assert details["regex_detector"] == "enabled"
    assert details["email_rule"] == "enabled"

    runtime_diagnostic = subprocess.run(  # noqa: S603 - resolved installed entry point
        [entrypoint, "diagnostics", "runtime"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert runtime_diagnostic.returncode == 0, runtime_diagnostic.stderr
    assert runtime_diagnostic.stdout == ""
    assert json.loads(runtime_diagnostic.stderr)["full_engine_ready"] is True

    parameters = StdioServerParameters(command=entrypoint, env=environment)
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            for _ in range(100):
                result = await session.call_tool(
                    "analyze_text",
                    {"text": "readiness probe", "policy": "default"},
                )
                payload = result.structuredContent or {}
                if payload.get("failure_code") != "contextual_model_initializing":
                    break
                await anyio.sleep(0.02)
            exact_text = "Mijn naam is Emma de Vries en mijn e-mailadres is emma@example.com."
            exact = await session.call_tool(
                "analyze_text",
                {"text": exact_text, "policy": "default", "response_mode": "review"},
            )
            redacted = await session.call_tool(
                "redact_text",
                {"text": exact_text, "policy": "default"},
            )

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent.get("failure_code") != "contextual_model_not_configured"
    assert result.structuredContent.get("status") != "blocked"
    assert result.structuredContent["status"] == "ok"
    assert exact.structuredContent is not None
    detected = {
        (item["entity_type"], exact_text[item["start"] : item["end"]])
        for item in exact.structuredContent["findings"]
    }
    assert ("person", "Emma de Vries") in detected
    assert ("email", "emma@example.com") in detected
    assert redacted.structuredContent is not None
    assert redacted.structuredContent["status"] == "ok"
    assert "Emma de Vries" not in redacted.structuredContent["sanitized_text"]
    assert "emma@example.com" not in redacted.structuredContent["sanitized_text"]


def test_stdio_initializes_before_slow_contextual_model_and_loads_once(
    tmp_path: Path,
) -> None:
    app_root = tmp_path / "app-data"
    fake_imports = tmp_path / "subprocess-fakes"
    english = b"tiny-english-flair-model"
    dutch = b"tiny-unused-dutch-model"
    runtime_root = app_root / "models" / ".runtime-cache" / "hub" / RUNTIME_CACHE_REPOSITORY
    (runtime_root / "refs").mkdir(parents=True)
    (runtime_root / "refs" / "main").write_text(
        RUNTIME_REVISION,
        encoding="ascii",
        newline="",
    )
    snapshot = runtime_root / "snapshots" / RUNTIME_REVISION
    snapshot.mkdir(parents=True)
    (snapshot / "tokenizer.json").write_bytes(RUNTIME_CONTENT)
    _write_model(
        app_root,
        model_id="english-large",
        language="en",
        revision="a" * 40,
        data=english,
    )
    (app_root / "model-config.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "enabled_languages": ["en"],
                "active_models": {"en": "english-large"},
            }
        ),
        encoding="utf-8",
    )
    _write_subprocess_fakes(fake_imports, english, dutch)
    gate = tmp_path / "release-model-load"
    started = tmp_path / "model-load-started"
    loads = tmp_path / "model-load-count"
    predictions = tmp_path / "prediction-count"
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONUTF8": "1",
            "PYTHONPATH": os.pathsep.join(
                value for value in (str(fake_imports), environment.get("PYTHONPATH")) if value
            ),
            "SECUREDACT_APP_DATA_DIR": str(app_root),
            "SECUREDACT_REQUIRE_FLAIR": "1",
            "SECUREDACT_TEST_LOAD_GATE": str(gate),
            "SECUREDACT_TEST_LOAD_STARTED": str(started),
            "SECUREDACT_TEST_LOAD_COUNT": str(loads),
            "SECUREDACT_TEST_PREDICT_COUNT": str(predictions),
        }
    )
    for name in (
        "SECUREDACT_MODEL_DIR",
        "SECUREDACT_MODEL_PATH",
        "SECUREDACT_FLAIR_MODEL",
        "SECUREDACT_MODEL_ID",
    ):
        environment.pop(name, None)

    process = subprocess.Popen(  # noqa: S603 - resolved installed entry point
        [_console_entrypoint()],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "securedact-test-host", "version": "1"},
            },
        }
        started_at = time.perf_counter()
        _send_protocol_message(process, initialize)
        initialized_response = _read_protocol_message(process)
        initialize_elapsed = time.perf_counter() - started_at
        assert initialized_response["id"] == 1
        assert "result" in initialized_response
        # Bound real console startup without treating Windows executable-shim and
        # antivirus cold-scan variance as contextual-model work.
        assert initialize_elapsed < PROTOCOL_STARTUP_DEADLINE_SECONDS
        # Heavy work is tied to the standard initialized notification, not the
        # lifespan that must be entered before the initialize response.
        assert not started.exists()

        _send_protocol_message(
            process,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )
        deadline = time.monotonic() + 2.0
        while not started.is_file() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started.is_file()

        listed_at = time.perf_counter()
        _send_protocol_message(
            process,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        listed = _read_protocol_message(process)
        assert time.perf_counter() - listed_at < 2.0
        assert listed["id"] == 2
        tool_names = {item["name"] for item in listed["result"]["tools"]}  # type: ignore[index]
        assert tool_names.issuperset(
            {
                "prepare_for_external_ai",
                "analyze_text",
                "redact_text",
                "restore_text",
                "create_safe_copy",
            }
        )

        _send_protocol_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "analyze_text",
                    "arguments": {
                        "text": "Mijn e-mailadres is first@example.com.",
                        "policy": "default",
                    },
                },
            },
        )
        first = _read_protocol_message(process)
        first_payload = first["result"]["structuredContent"]  # type: ignore[index]
        assert first_payload["status"] == "blocked"
        assert first_payload["failure_code"] == "contextual_model_initializing"
        assert first_payload["reason_codes"] == ["contextual_model_initializing"]
        assert not predictions.exists()

        gate.write_text("ready", encoding="ascii")
        request_id = 4
        deadline = time.monotonic() + 2.0
        while True:
            _send_protocol_message(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {
                        "name": "analyze_text",
                        "arguments": {
                            "text": "Second request to emma@example.com.",
                            "policy": "default",
                        },
                    },
                },
            )
            second = _read_protocol_message(process)
            second_payload = second["result"]["structuredContent"]  # type: ignore[index]
            if second_payload.get("failure_code") != "contextual_model_initializing":
                break
            assert time.monotonic() < deadline
            request_id += 1
            time.sleep(0.01)

        assert second_payload["status"] == "ok"
        assert loads.read_text(encoding="ascii").splitlines() == ["load"]
        assert predictions.read_text(encoding="ascii").splitlines() == ["predict"]
    finally:
        gate.write_text("ready", encoding="ascii")
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)

    assert process.stderr is not None
    diagnostic_output = process.stderr.read()
    assert "first@example.com" not in diagnostic_output
    assert "emma@example.com" not in diagnostic_output
