"""Local, safe file-read for the SecuRedact Agent Privacy Firewall.

This module implements ``securedact_read_file`` as a small, auditable core that is
independent of MCP and provider concerns. It is the engine-side realization of
FW-011 (safe read + sanitize), FW-012 (traversal / symlink / UNC / case / rename
defenses) and FW-013 (text-focused size + binary handling).

Design guarantees:

* Sensitive paths are rejected **before** any file content is read. The firewall
  policy is evaluated on the canonical, resolved path so symlink/``..``/UNC tricks
  cannot hide a prohibited file.
* Path resolution is canonical and absolute; symlinks are followed so the policy
  sees the *real* target, and escape outside configured roots is rejected.
* Non-text / binary content is not silently passed through: it is blocked in the
  text-only MVP (FW-013). Renamed secret files are still caught later by the
  content scan (the redactor reuses the privacy engine), so a ``.bak`` containing
  credentials is sanitized rather than leaked.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .firewall import (
    MAX_INSPECTION_TEXT_CHARS,
    FirewallDecision,
    FirewallPolicy,
    ToolContext,
    ToolOperation,
    evaluate_firewall,
    load_firewall_policy_from_environment,
)
from .models import PrivacyAction

# Reuses the centralized inspection-size cap (FW-041). The env override still
# allows shrinking the safe-read bound without touching the code path.
DEFAULT_READ_MAX_BYTES = int(os.getenv("SECUREDACT_READ_MAX_BYTES", str(MAX_INSPECTION_TEXT_CHARS)))


class SafeReadError(Exception):
    """A blocked or failed safe-read attempt.

    ``code`` is a stable reason code; ``reason`` is a human-readable message that
    never contains file content.
    """

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class SafeReadResult:
    """Outcome of a safe-read attempt."""

    status: str  # "ok" | "blocked"
    sanitized_text: str | None = None
    reason: str | None = None
    reason_code: str | None = None
    path: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def resolve_safe_path(
    raw_path: str | os.PathLike[str], allowed_roots: list[str] | None = None
) -> Path:
    """Return a canonical absolute path with traversal/UNC/symlink defenses.

    Defenses (FW-012):
    * rejects empty, null-byte, and URL/UNC-style inputs;
    * resolves the path to its real, symlink-followed absolute form so the
      firewall evaluates the true target;
    * when ``allowed_roots`` is provided, rejects any resolved path that escapes
      every allowed root.
    """

    text = os.fspath(raw_path)
    if not isinstance(text, str) or not text.strip():
        raise SafeReadError("empty_path", "path must be a non-empty string")
    if "\x00" in text:
        raise SafeReadError("invalid_path", "path contains a null byte")
    lowered = text.lower().replace("\\", "/")
    if "://" in lowered:
        raise SafeReadError("invalid_path", "URLs are not supported as file paths")
    if lowered.startswith("//") or lowered.startswith("\\\\"):
        raise SafeReadError("unsupported_unc_path", "UNC paths are not supported")

    try:
        resolved = Path(text).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SafeReadError("invalid_path", f"path could not be resolved: {exc}") from exc

    if allowed_roots:
        roots = [Path(root).expanduser().resolve(strict=False) for root in allowed_roots]
        if not any(_is_within(resolved, root) for root in roots):
            raise SafeReadError(
                "path_outside_allowed_roots",
                "resolved path is outside the allowed read roots",
            )
    return resolved


def _is_within(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def _looks_binary(path: Path, sample_size: int = 8192) -> bool:
    """Conservative binary sniff (FW-013): NUL bytes imply non-text."""

    try:
        with path.open("rb") as handle:
            chunk = handle.read(sample_size)
    except OSError:
        return False
    if not chunk:
        return False
    return b"\x00" in chunk


def _default_reason(decision: FirewallDecision) -> str:
    message = decision.reason
    if isinstance(message, str) and message:
        return message
    return "SecuRedact blocked access to a protected file path."


def read_file_safely(
    path: str | os.PathLike[str],
    *,
    redactor: Callable[[str], str],
    firewall: FirewallPolicy | None = None,
    max_bytes: int | None = None,
    allowed_roots: list[str] | None = None,
) -> SafeReadResult:
    """Read ``path`` locally, block protected paths, and return sanitized text.

    The firewall is evaluated on the resolved canonical path **before** any file
    content is opened (FW-012 / sensitive-path-first). The supplied ``redactor``
    (typically the SecuRedact engine's ``prepare``) sanitizes the text; it may
    raise :class:`SafeReadError` to refuse content (e.g. residual validation
    failure), which is surfaced as a blocked result rather than leaking raw text.
    """

    try:
        resolved = resolve_safe_path(path, allowed_roots=allowed_roots)
    except SafeReadError as exc:
        return SafeReadResult(
            status="blocked", reason=exc.reason, reason_code=exc.code, path=str(path)
        )

    policy = firewall if firewall is not None else load_firewall_policy_from_environment()
    if policy is not None and policy.enabled:
        context = ToolContext(
            provider="securedact",
            tool_name="securedact_read_file",
            operation=ToolOperation.FILE_READ,
            path=str(resolved),
        )
        decision = evaluate_firewall(policy, context)
        if decision.action == PrivacyAction.BLOCK:
            return SafeReadResult(
                status="blocked",
                reason=_default_reason(decision),
                reason_code="protected_path_blocked",
                path=str(resolved),
            )

    if not resolved.exists():
        return SafeReadResult(
            status="blocked",
            reason="file does not exist",
            reason_code="file_not_found",
            path=str(resolved),
        )
    if resolved.is_dir():
        return SafeReadResult(
            status="blocked",
            reason="path is a directory",
            reason_code="is_directory",
            path=str(resolved),
        )

    cap = max_bytes if max_bytes is not None else DEFAULT_READ_MAX_BYTES
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        return SafeReadResult(
            status="blocked", reason=str(exc), reason_code="stat_failed", path=str(resolved)
        )
    if size > cap:
        return SafeReadResult(
            status="blocked",
            reason=f"file size {size} exceeds the limit of {cap} bytes",
            reason_code="file_too_large",
            path=str(resolved),
        )

    if _looks_binary(resolved):
        return SafeReadResult(
            status="blocked",
            reason="binary content is not supported by the text-only safe reader",
            reason_code="binary_file_unsupported",
            path=str(resolved),
        )

    try:
        text = resolved.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return SafeReadResult(
            status="blocked",
            reason="file is not valid UTF-8 text",
            reason_code="binary_file_unsupported",
            path=str(resolved),
        )

    try:
        sanitized = redactor(text)
    except SafeReadError as exc:
        return SafeReadResult(
            status="blocked", reason=exc.reason, reason_code=exc.code, path=str(resolved)
        )

    return SafeReadResult(status="ok", sanitized_text=sanitized, path=str(resolved))
