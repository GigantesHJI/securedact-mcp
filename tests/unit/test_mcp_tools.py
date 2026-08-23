from __future__ import annotations

import io
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from securedact_core import PrivacyEngine, ResidualScanResult
from securedact_core.detectors import ContextualPrivacyDetector, CredentialsDetector, RegexDetector
from securedact_mcp import server as server_module
from securedact_mcp.model_store import ModelStoragePaths
from securedact_mcp.server import create_server


def _server():
    engine = PrivacyEngine(
        [CredentialsDetector(), RegexDetector(), ContextualPrivacyDetector()],
        require_contextual=False,
    )
    return create_server(engine)


async def _call(server, name: str, arguments: dict[str, object]):
    return await server._tool_manager._tools[name].run(arguments)


def test_exact_tool_registry() -> None:
    assert set(_server()._tool_manager._tools) == {
        "prepare_for_external_ai",
        "analyze_text",
        "redact_text",
        "restore_text",
        "create_safe_copy",
        "securedact_read_file",
    }


@pytest.mark.asyncio
async def test_analyze_text_returns_local_synthetic_finding() -> None:
    result = await _call(
        _server(),
        "analyze_text",
        {"text": "Email alex.example@example.test", "policy": "default"},
    )

    assert result["status"] == "ok"
    assert result["counts"] == {"email": 1}
    assert "alex.example@example.test" not in str(result)
    assert "entities" not in result


@pytest.mark.asyncio
async def test_securedact_read_file_sanitizes_and_blocks_protected(tmp_path) -> None:
    server = _server()
    doc = tmp_path / "doc.txt"
    doc.write_text("Contact alex.example@example.test", encoding="utf-8")
    result = await _call(server, "securedact_read_file", {"path": str(doc)})
    assert result["status"] == "ok"
    assert "[EMAIL" in result["sanitized_text"]

    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abc", encoding="utf-8")
    blocked = await _call(server, "securedact_read_file", {"path": str(secret)})
    assert blocked["status"] == "blocked"


@pytest.mark.asyncio
async def test_prepare_for_external_ai_is_minimal_and_restore_capable() -> None:
    server = _server()
    canary = "alex.session@example.test"
    minimal = await _call(
        server,
        "prepare_for_external_ai",
        {"text": f"Contact {canary}"},
    )
    restorable = await _call(
        server,
        "prepare_for_external_ai",
        {
            "text": canary,
            "response_mode": "restore_capable",
        },
    )
    restored = await _call(
        server,
        "restore_text",
        {
            "text": restorable["sanitized_text"],
            "restoration_session": restorable["restoration_session"],
        },
    )

    assert minimal["status"] == "ok"
    assert minimal["sanitized_text"] == "Contact [EMAIL_1]"
    assert canary not in str(minimal)
    assert "mapping" not in str(minimal)
    assert "restoration_session" not in minimal
    assert restored["restored_text"] == canary


@pytest.mark.asyncio
async def test_debug_and_legacy_sensitive_responses_are_explicit() -> None:
    server = _server()
    canary = "alex.legacy@example.test"
    debug = await _call(
        server,
        "prepare_for_external_ai",
        {"text": canary, "response_mode": "debug"},
    )
    legacy = await _call(
        server,
        "redact_text",
        {"text": canary, "response_mode": "legacy"},
    )

    assert debug["status"] == "blocked"
    assert debug["reason_codes"] == ["debug_mode_disabled"]
    assert legacy["status"] == "ok"
    assert legacy["deprecation_code"] == "legacy_sensitive_response"
    assert legacy["mapping"] == {"[EMAIL_1]": canary}


@pytest.mark.asyncio
async def test_redact_text_uses_stable_placeholder_for_repeated_value() -> None:
    value = "alex.example@example.test"
    result = await _call(
        _server(),
        "redact_text",
        {"text": f"Email {value}; repeat {value}", "policy": "default"},
    )

    assert result["status"] == "ok"
    assert result["sanitized_text"].count("[EMAIL_1]") == 2
    assert value not in result["sanitized_text"]
    assert "mapping" not in result
    assert result["counts"] == {"email": 2}


@pytest.mark.asyncio
async def test_redact_text_fails_closed_when_residual_validation_is_unsafe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = PrivacyEngine(
        [RegexDetector(), ContextualPrivacyDetector()],
        require_contextual=False,
    )
    monkeypatch.setattr(
        engine,
        "scan_residual",
        lambda *args, **kwargs: ResidualScanResult(
            safe_to_send=False,
            critical_residual_count=1,
        ),
    )

    result = await _call(
        create_server(engine),
        "redact_text",
        {"text": "Email alex.example@example.test", "policy": "default"},
    )

    assert result["status"] == "blocked"
    assert result["reason_codes"] == ["residual_validation_failed"]
    assert "sanitized_text" not in result


@pytest.mark.asyncio
async def test_restore_text_restores_only_caller_supplied_mapping() -> None:
    server = _server()
    restored = await _call(
        server,
        "restore_text",
        {
            "text": "Contact [EMAIL_1] and leave [UNKNOWN_9] unchanged.",
            "mapping": {"[EMAIL_1]": "alex.example@example.test"},
            "trusted_local_review": True,
        },
    )

    assert restored["restored_text"] == (
        "Contact alex.example@example.test and leave [UNKNOWN_9] unchanged."
    )
    blocked = await _call(
        server,
        "restore_text",
        {"text": "[EMAIL_1]", "mapping": {}},
    )
    assert blocked["status"] == "blocked"
    assert blocked["reason_codes"] == ["restoration_session_required"]


@pytest.mark.asyncio
async def test_review_and_block_results_are_not_approved_output() -> None:
    server = _server()
    review = await _call(
        server,
        "redact_text",
        {"text": "Emma is Muslim.", "policy": "default"},
    )
    blocked = await _call(
        server,
        "redact_text",
        {
            "text": "Face template identifier: FACE-77A91B",
            "policy": "special_category_strict",
        },
    )

    assert review["status"] == "review_required"
    assert "sanitized_text" not in review
    assert blocked["status"] == "blocked"
    assert blocked["reason_codes"] == ["policy_blocked"]
    assert "sanitized_text" not in blocked


@pytest.mark.asyncio
async def test_missing_required_contextual_model_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    app_root = tmp_path / "app-data"
    model_root = app_root / "models"
    paths = ModelStoragePaths(
        app_root=app_root,
        model_root=model_root,
        staging_root=model_root / ".staging",
        rollback_root=model_root / ".rollback",
        config_path=app_root / "model-config.json",
    )
    monkeypatch.setattr(
        server_module.ModelStore,
        "resolve",
        classmethod(lambda _cls: server_module.ModelStore(paths)),
    )
    monkeypatch.delenv("SECUREDACT_APP_DATA_DIR", raising=False)
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "1")
    monkeypatch.delenv("SECUREDACT_MODEL_PATH", raising=False)
    monkeypatch.delenv("SECUREDACT_FLAIR_MODEL", raising=False)
    monkeypatch.delenv("SECUREDACT_MODEL_ID", raising=False)

    result = await _call(
        create_server(),
        "redact_text",
        {"text": "alex.example@example.test", "policy": "default"},
    )

    assert result["status"] == "blocked"
    assert result["reason_codes"] == ["contextual_model_not_installed"]
    assert "sanitized_text" not in result


@pytest.mark.asyncio
async def test_safe_copy_requires_configured_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECUREDACT_SAFE_COPY_DIR", raising=False)

    result = await _call(
        _server(),
        "create_safe_copy",
        {"content": "alex.example@example.test", "filename": "safe.txt"},
    )

    assert result == {
        "status": "blocked",
        "reason": "safe copy directory is not configured",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filename",
    [
        "../escape.txt",
        r"..\escape.txt",
        r"C:\escape.txt",
        "/absolute.txt",
        "unsafe.pdf",
        "..",
    ],
)
async def test_safe_copy_rejects_traversal_and_unsupported_extensions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filename: str,
) -> None:
    safe_root = tmp_path / "safe"
    monkeypatch.setenv("SECUREDACT_SAFE_COPY_DIR", str(safe_root))

    result = await _call(
        _server(),
        "create_safe_copy",
        {"content": "alex.example@example.test", "filename": filename},
    )

    assert result["status"] == "blocked"
    assert not safe_root.exists()


@pytest.mark.asyncio
async def test_safe_copy_writes_only_sanitized_content_and_never_overwrites(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    safe_root = tmp_path / "safe"
    monkeypatch.setenv("SECUREDACT_SAFE_COPY_DIR", str(safe_root))
    server = _server()
    value = "alex.example@example.test"

    first = await _call(
        server,
        "create_safe_copy",
        {"content": f"Contact {value}", "filename": "safe.md"},
    )
    second = await _call(
        server,
        "create_safe_copy",
        {"content": "different@example.test", "filename": "safe.md"},
    )

    target = safe_root / "safe.md"
    assert first["status"] == "ok"
    assert first["filename"] == "safe.md"
    assert target.read_text(encoding="utf-8") == "Contact [EMAIL_1]"
    assert value not in target.read_text(encoding="utf-8")
    assert second == {"status": "blocked", "reason": "destination already exists"}
    assert target.read_text(encoding="utf-8") == "Contact [EMAIL_1]"


@pytest.mark.asyncio
async def test_safe_copy_default_blocks_credentials_without_writing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    safe_root = tmp_path / "safe"
    monkeypatch.setenv("SECUREDACT_SAFE_COPY_DIR", str(safe_root))
    credential = "Authorization: Bearer syntheticBearerToken123456789"

    result = await _call(
        _server(),
        "create_safe_copy",
        {"content": credential, "filename": "blocked.txt"},
    )

    assert result["status"] == "blocked"
    assert result["reason_codes"] == ["policy_blocked"]
    assert "sanitized_text" not in result
    assert credential not in str(result)
    assert not (safe_root / "blocked.txt").exists()


@pytest.mark.asyncio
async def test_size_limit_blocks_without_echoing_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECUREDACT_MAX_TEXT_CHARS", "8")
    canary = "SYNTHETIC_CANARY_VALUE"

    result = await _call(
        _server(),
        "redact_text",
        {"text": canary, "policy": "default"},
    )

    assert result["status"] == "blocked"
    assert result["reason_codes"] == ["input_too_large"]
    assert canary not in str(result)


@pytest.mark.asyncio
async def test_malformed_tool_request_is_rejected() -> None:
    tool = _server()._tool_manager._tools["analyze_text"]

    with pytest.raises(ToolError, match="Field required"):
        await tool.run({})


@pytest.mark.asyncio
async def test_tool_call_writes_nothing_to_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)

    await _call(
        _server(),
        "analyze_text",
        {"text": "stdout-canary@example.test", "policy": "default"},
    )

    assert captured.getvalue() == ""
