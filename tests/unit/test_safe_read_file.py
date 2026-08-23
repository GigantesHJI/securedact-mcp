"""Focused tests for the secure local file reader (FW-011 / FW-012 / FW-013).

These tests exercise the engine-side ``read_file_safely`` core directly with a
lightweight redactor (no ML model required), plus a small end-to-end check
through ``SecuredactEngine.read_file``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from securedact_core import (
    SecuredactEngine,
    build_production_engine,
    default_firewall_policy,
    read_file_safely,
)
from securedact_core.detectors import RegexDetector


def _redactor(text: str) -> str:
    """A minimal stand-in for the privacy engine's sanitization."""

    out = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL]", text)
    out = re.sub(r"password\s*=\s*\S+", "password=[REDACTED]", out)
    out = re.sub(r"api_key\s*=\s*\S+", "api_key=[REDACTED]", out)
    return out


def test_read_normal_text_returns_sanitized(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("hello world", encoding="utf-8")

    result = read_file_safely(str(target), redactor=_redactor)

    assert result.ok
    assert result.sanitized_text == "hello world"
    assert result.reason_code is None


def test_read_redacts_pii_in_text(tmp_path: Path) -> None:
    target = tmp_path / "doc.md"
    target.write_text("Contact alex@example.test for details", encoding="utf-8")

    result = read_file_safely(str(target), redactor=_redactor)

    assert result.ok
    assert "[EMAIL]" in result.sanitized_text
    assert "alex@example.test" not in result.sanitized_text


def test_protected_env_blocked_before_read(tmp_path: Path) -> None:
    calls: list[str] = []

    def tracking_redactor(text: str) -> str:
        calls.append(text)
        return _redactor(text)

    target = tmp_path / ".env"
    target.write_text("SECRET=1", encoding="utf-8")

    result = read_file_safely(
        str(target),
        redactor=tracking_redactor,
        firewall=default_firewall_policy(),
    )

    assert not result.ok
    assert result.reason_code == "protected_path_blocked"
    assert calls == []  # content is never read


def test_traversal_to_protected_env_blocked(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("SECRET=1", encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()

    result = read_file_safely(
        str(nested / ".." / ".env"),
        redactor=_redactor,
        firewall=default_firewall_policy(),
    )

    assert not result.ok
    assert result.reason_code == "protected_path_blocked"


def test_symlink_to_protected_file_blocked(tmp_path: Path) -> None:
    secret = tmp_path / ".env"
    secret.write_text("SECRET=1", encoding="utf-8")
    link = tmp_path / "link.env"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unsupported in this environment")

    result = read_file_safely(
        str(link),
        redactor=_redactor,
        firewall=default_firewall_policy(),
    )

    assert not result.ok
    assert result.reason_code == "protected_path_blocked"


def test_renamed_secret_caught_by_content_scan(tmp_path: Path) -> None:
    target = tmp_path / "config.bak"
    target.write_text("password=hunter2", encoding="utf-8")

    result = read_file_safely(str(target), redactor=_redactor)

    assert result.ok
    assert "hunter2" not in result.sanitized_text
    assert "[REDACTED]" in result.sanitized_text


def test_large_file_safe_fails(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("x" * 200, encoding="utf-8")

    result = read_file_safely(str(target), redactor=_redactor, max_bytes=50)

    assert not result.ok
    assert result.reason_code == "file_too_large"


def test_binary_file_blocked(tmp_path: Path) -> None:
    target = tmp_path / "image.bin"
    target.write_bytes(b"\x00\x01\x02\x03raw\x00")

    result = read_file_safely(str(target), redactor=_redactor)

    assert not result.ok
    assert result.reason_code == "binary_file_unsupported"


def test_csv_scanned_as_text(tmp_path: Path) -> None:
    target = tmp_path / "data.csv"
    target.write_text("name,email\nalex,alex@example.test\n", encoding="utf-8")

    result = read_file_safely(str(target), redactor=_redactor)

    assert result.ok
    assert "[EMAIL]" in result.sanitized_text


def test_case_trick_env_blocked(tmp_path: Path) -> None:
    target = tmp_path / ".ENV"
    target.write_text("SECRET=1", encoding="utf-8")

    result = read_file_safely(
        str(target),
        redactor=_redactor,
        firewall=default_firewall_policy(),
    )

    assert not result.ok
    assert result.reason_code == "protected_path_blocked"


def test_unc_path_rejected() -> None:
    result = read_file_safely("\\\\server\\share\\file.txt", redactor=_redactor)

    assert not result.ok
    assert result.reason_code == "unsupported_unc_path"


def test_allowed_roots_enforced(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    inside = root / "ok.txt"
    inside.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("safe", encoding="utf-8")

    allowed = read_file_safely(str(inside), redactor=_redactor, allowed_roots=[str(root)])
    assert allowed.ok

    blocked = read_file_safely(str(outside), redactor=_redactor, allowed_roots=[str(root)])
    assert not blocked.ok
    assert blocked.reason_code == "path_outside_allowed_roots"


def test_empty_path_rejected() -> None:
    result = read_file_safely("", redactor=_redactor)

    assert not result.ok
    assert result.reason_code == "empty_path"


def test_missing_file_reported_blocked(tmp_path: Path) -> None:
    result = read_file_safely(str(tmp_path / "nope.txt"), redactor=_redactor)

    assert not result.ok
    assert result.reason_code == "file_not_found"


def test_engine_read_file_blocks_protected_and_redacts_normal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = SecuredactEngine.with_detectors([RegexDetector()])

    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abc", encoding="utf-8")
    blocked = engine.read_file(str(secret))
    assert not blocked.ok
    assert blocked.reason_code == "protected_path_blocked"

    doc = tmp_path / "doc.txt"
    doc.write_text("Contact alex@example.test", encoding="utf-8")
    ok = engine.read_file(str(doc))
    assert ok.ok
    assert "[EMAIL" in ok.sanitized_text


def test_safe_read_catches_unknown_secret_via_content_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = SecuredactEngine(build_production_engine(require_contextual=False))

    # Non-protected path (allowed by the firewall) but content holds a generic
    # unknown secret. The safe-read pipeline must still refuse to return it.
    target = tmp_path / "config.txt"
    target.write_text("INTERNAL_API_SECRET=X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12", encoding="utf-8")

    result = engine.read_file(str(target))
    assert not result.ok
    assert result.reason_code == "content_blocked"


def test_safe_read_allows_benign_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = SecuredactEngine(build_production_engine(require_contextual=False))

    target = tmp_path / "config.txt"
    target.write_text(
        "request_id = 9f8e7d6c5b4a39281706\n"
        "trace_id = 9f8e7d6c5b4a39281706\n"
        "DB_HOST=db.example.test\n",
        encoding="utf-8",
    )

    result = engine.read_file(str(target))
    assert result.ok
    assert "9f8e7d6c5b4a39281706" in result.sanitized_text
