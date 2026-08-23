"""Local agent privacy firewall primitives for SecuRedact.

This module is deliberately small, auditable, and free of any MCP or provider
dependency. It introduces a ``ToolContext`` abstraction that provider hooks turn
into a structured description of what a tool is about to do (operation, path,
destination) and a ``FirewallPolicy`` that evaluates that context into a
``FirewallDecision``.

The firewall is an *additive* layer on top of the existing content-based privacy
policy. It never changes the ``PrivacyAction`` vocabulary (ALLOW / REDACT /
REVIEW / BLOCK); interaction requirements such as approval are carried on the
``FirewallDecision`` dataclass instead.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from .models import PrivacyAction

FIREWALL_ENABLED_ENV = "SECUREDACT_FIREWALL_ENABLED"

# Single source of truth for the maximum size (chars/bytes) of a single piece of
# content the privacy pipeline is willing to inspect. Both the direct text APIs
# and the safe-read path reuse this so the two limits can never silently drift
# apart (FW-041). Reuse, do not add parallel magic constants.
MAX_INSPECTION_TEXT_CHARS = 1_000_000

# Public alias kept for backward compatibility with importers of the safe-read
# module; its default is always derived from ``MAX_INSPECTION_TEXT_CHARS``.
DEFAULT_READ_MAX_BYTES = MAX_INSPECTION_TEXT_CHARS

# Practical per-tool-result inspection cap (FW-020). A tool result is a model-bound
# payload that the deterministic detector stack must scan before the model sees it.
# The global 1 MB cap is the absolute hard ceiling, but the recorded FW-041 baseline
# shows a 200 KB match-heavy result already approaches the provider hook timeout
# budget (~16 s). A provider hook therefore cannot safely assume the full 1 MB cap
# for a single result: results above this practical limit fail closed (hidden/blocked)
# without scanning, rather than being allowed raw. Centralized and configurable so
# the two limits cannot drift apart.
MAX_TOOL_RESULT_CHARS = int(os.getenv("SECUREDACT_MAX_TOOL_RESULT_CHARS", "200000"))


def recursive_text_length(payload: object) -> int:
    """Return the total length of every textual leaf in a (possibly structured) payload.

    Used by the result-inspection path to fail closed on oversized results before
    any detector runs, mirroring the cheap size guards used elsewhere (FW-041).
    """

    if isinstance(payload, str):
        return len(payload)
    if isinstance(payload, Mapping):
        return sum(recursive_text_length(value) for value in payload.values())
    if isinstance(payload, list):
        return sum(recursive_text_length(value) for value in payload)
    return 0


class ToolOperation(StrEnum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL_EXEC = "shell_exec"
    NETWORK_READ = "network_read"
    NETWORK_WRITE = "network_write"
    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    MCP_CALL = "mcp_call"
    UNKNOWN = "unknown"


class DestinationScope(StrEnum):
    """Normalized trust posture of an outbound destination (FW-030).

    ``INTERNAL`` means loopback / private / allowlisted; ``EXTERNAL`` means a
    public, untrusted destination; ``UNKNOWN`` means no destination could be
    extracted and must never be treated as trusted.
    """

    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolContext:
    """A provider-neutral description of a single tool invocation."""

    provider: str
    tool_name: str
    operation: ToolOperation
    path: str | None = None
    destination: str | None = None
    destination_scope: DestinationScope | None = None
    payload: object | None = None


@dataclass(frozen=True)
class FirewallDecision:
    """The firewall's disposition for one ``ToolContext``.

    ``action`` is the data decision. ``requires_approval`` and ``warning`` are
    interaction requirements that the host hook maps onto its own primitives
    without modifying the ``PrivacyAction`` enum.
    """

    action: PrivacyAction
    requires_approval: bool = False
    warning: str | None = None
    reason: str | None = None


class FirewallRule(BaseModel):
    """A single ordered context rule.

    An empty dimension is a wildcard for that dimension. Path-aware dimensions
    (``names``, ``extensions``, ``path_patterns``, ``path_fragments``) are ANDed
    and require ``context.path`` to be present.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    operations: list[ToolOperation] = Field(default_factory=list)
    tool_names: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    extensions: list[str] = Field(default_factory=list)
    path_patterns: list[str] = Field(default_factory=list)
    path_fragments: list[str] = Field(default_factory=list)
    destination_scopes: list[DestinationScope] = Field(default_factory=list)
    action: PrivacyAction
    requires_approval: bool = False
    message: str | None = Field(default=None, max_length=500)


class FirewallPolicy(BaseModel):
    """An ordered context policy evaluated before content actions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    rules: list[FirewallRule] = Field(default_factory=list)
    default_action: PrivacyAction = PrivacyAction.ALLOW
    # FW-030 egress options. ``egress_external_require_approval`` upgrades an
    # external/unknown NETWORK_WRITE whose payload was merely redacted (PII) into
    # a REQUIRE_APPROVAL decision instead of sending the redacted payload. It is
    # opt-in (default off) so the default behavior stays policy-driven by the
    # content engine; a stricter egress posture can enable it.
    egress_external_require_approval: bool = False
    egress_allowlist_domains: list[str] = Field(default_factory=list)


class FirewallPolicyError(ValueError):
    """Raised when a firewall policy violates a fail-closed invariant."""


# Concrete paths that must never be explicitly ALLOWed by a firewall rule.
PROTECTED_PATH_EXAMPLES: tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.secret",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
    "service-account-prod.json",
    "config.pem",
    "private-key.pem",
    "key.p12",
    "secret.pfx",
    ".ssh/id_rsa",
    ".ssh/config",
    ".ssh/known_hosts",
    "home/user/.ssh/id_ed25519",
    ".aws/credentials",
    "home/user/.aws/config",
)

_NATIVE_TOOL_OPERATIONS: dict[str, ToolOperation] = {
    "read": ToolOperation.FILE_READ,
    "write": ToolOperation.FILE_WRITE,
    "edit": ToolOperation.FILE_WRITE,
    "multiedit": ToolOperation.FILE_WRITE,
    "notebookedit": ToolOperation.FILE_WRITE,
    "bash": ToolOperation.SHELL_EXEC,
    "grep": ToolOperation.FILE_READ,
    "glob": ToolOperation.FILE_READ,
}

# Provider-specific tool-name aliases live here (classification maps), not in the
# firewall policy code, so policy stays about destinations/operations only.
_PATH_KEYS = ("file_path", "path", "filepath", "source", "target", "uri")
_URL_KEYS = ("url", "uri", "endpoint", "host", "destination", "remote", "repository", "repo")
_EXTERNAL_MARKERS = ("http", "web", "search", "fetch", "request", "api", "connect")
_NETWORK_WRITE_WORDS = (
    "post",
    "put",
    "patch",
    "webhook",
    "submit",
    "upload",
    "send",
    "push",
)
_HTTP_METHOD_WRITE = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_HTTP_METHOD_READ = frozenset({"GET", "HEAD", "OPTIONS", "CONNECT"})

_LOOPBACK_HOSTS = frozenset({"localhost", "::1", "0.0.0.0", "127.0.0.1"})  # noqa: S104
_PRIVATE_HOST_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.30.",
    "172.31.",
    "192.168.",
    "fc",
    "fd",
)
_PRIVATE_HOST_SUFFIXES = (".local", ".internal", ".corp", ".home", ".lan")


def _extract_path(tool_input: object) -> str | None:
    if not isinstance(tool_input, Mapping):
        return None
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _extract_url(tool_input: object) -> str | None:
    if not isinstance(tool_input, Mapping):
        return None
    for key in _URL_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def normalize_destination(raw: object) -> str | None:
    """Return a safe, query/body-free host for an outbound destination (FW-030).

    Accepts URLs, ``git@host:repo`` / SSH forms, ``user@host`` email-like forms,
    and bare hosts (optionally with a port). Never returns path, query, fragment,
    or credential material so the value stays safe for audit metadata.
    """

    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()

    if "://" in text or text.startswith("//"):
        try:
            parsed = urlparse(text if "://" in text else f"http:{text}")
            host = parsed.hostname
        except ValueError:
            host = None
        if host:
            return host.lower()

    ssh_match = re.match(r"^[^@\s/:]+@([^:/?\s#]+)", text)
    if ssh_match:
        return ssh_match.group(1).lower()

    email_match = re.match(r"^[^@\s]+@([^@\s]+)$", text)
    if email_match:
        return email_match.group(1).lower()

    host_match = re.match(r"^([a-z0-9.\-]+)(?::\d+)?$", text, re.IGNORECASE)
    if host_match:
        return host_match.group(1).lower()

    token = text.split()[0] if text.split() else text
    return token.lower()[:253]


def _is_private_host(normalized: str) -> bool:
    if normalized in _LOOPBACK_HOSTS:
        return True
    if normalized == "::1":
        return True
    if normalized.startswith("127."):
        return True
    if any(normalized.startswith(prefix) for prefix in _PRIVATE_HOST_PREFIXES):
        return True
    if any(normalized.endswith(suffix) for suffix in _PRIVATE_HOST_SUFFIXES):
        return True
    return False


def classify_destination_scope(
    destination: object, *, allowlist_domains: tuple[str, ...] | list[str] = ()
) -> DestinationScope:
    """Classify a destination as internal / external / unknown (FW-030).

    ``INTERNAL`` covers loopback, private ranges, and any host in
    ``allowlist_domains`` (matched exactly or as a suffix). Anything else with a
    resolvable host is ``EXTERNAL``; an absent/empty destination is ``UNKNOWN``
    and must never be treated as trusted.
    """

    normalized = normalize_destination(destination)
    if normalized is None:
        return DestinationScope.UNKNOWN
    if _is_private_host(normalized):
        return DestinationScope.INTERNAL
    allow = {domain.lower().lstrip(".") for domain in allowlist_domains}
    if allow:
        if any(normalized == d or normalized.endswith(f".{d}") for d in allow):
            return DestinationScope.INTERNAL
    return DestinationScope.EXTERNAL


_EGRESS_DESTINATION_KEYS = frozenset(key.lower() for key in _URL_KEYS)


def egress_scan_payload(payload: object) -> object:
    """Return a copy of an outbound payload with destination keys removed (FW-030).

    The destination (``url``/``endpoint``/``host``/``remote``/...) is metadata for
    scope/audit, not outbound content, so it is excluded from content scanning to
    avoid flagging ordinary destinations. Headers, body, ``json``, and form fields
    remain and are still scanned for secrets/PII.
    """

    if isinstance(payload, Mapping):
        return {
            key: value
            for key, value in payload.items()
            if key.lower() not in _EGRESS_DESTINATION_KEYS
        }
    return payload


def classify_tool(provider: str, tool_name: object, tool_input: object) -> ToolContext:
    """Translate a provider tool event into a neutral ``ToolContext``.

    Unknown tools map to ``UNKNOWN`` so the firewall routes them through content
    scanning rather than silently allowing them.
    """

    if not isinstance(tool_name, str) or not tool_name:
        payload = tool_input if isinstance(tool_input, Mapping) else None
        return ToolContext(provider, "", ToolOperation.UNKNOWN, payload=payload)

    lowered = tool_name.lower()
    operation = _NATIVE_TOOL_OPERATIONS.get(lowered)
    payload = tool_input if isinstance(tool_input, Mapping) else None

    if operation is not None:
        if operation in {ToolOperation.FILE_READ, ToolOperation.FILE_WRITE}:
            return ToolContext(
                provider, tool_name, operation, path=_extract_path(tool_input), payload=None
            )
        if operation == ToolOperation.SHELL_EXEC:
            command = tool_input.get("command") if isinstance(tool_input, Mapping) else None
            return ToolContext(
                provider,
                tool_name,
                operation,
                path=_extract_path(tool_input),
                payload=command,
            )
        return ToolContext(provider, tool_name, operation, payload=payload)

    # Structured metadata can be more reliable than the tool name: an explicit
    # HTTP method pins the network direction without guessing from the name.
    method = (
        tool_input.get("method")
        if isinstance(tool_input, Mapping) and isinstance(tool_input.get("method"), str)
        else None
    )
    if method is not None:
        normalized_method = method.strip().upper()
        if normalized_method in _HTTP_METHOD_WRITE:
            operation = ToolOperation.NETWORK_WRITE
        elif normalized_method in _HTTP_METHOD_READ:
            operation = ToolOperation.NETWORK_READ
        else:
            operation = (
                ToolOperation.NETWORK_WRITE if normalized_method else ToolOperation.NETWORK_READ
            )
        destination = _extract_url(tool_input)
        return ToolContext(
            provider,
            tool_name,
            operation,
            destination=destination,
            destination_scope=classify_destination_scope(destination),
            payload=payload,
        )

    if lowered.startswith("mcp_") or "filesystem" in lowered:
        if "read" in lowered or "filesystem" in lowered:
            operation = ToolOperation.FILE_READ
        elif any(word in lowered for word in _NETWORK_WRITE_WORDS):
            operation = ToolOperation.NETWORK_WRITE
        elif any(marker in lowered for marker in _EXTERNAL_MARKERS):
            operation = ToolOperation.NETWORK_READ
        else:
            operation = ToolOperation.MCP_CALL
        if operation in {ToolOperation.NETWORK_READ, ToolOperation.NETWORK_WRITE}:
            destination = _extract_url(tool_input)
            return ToolContext(
                provider,
                tool_name,
                operation,
                destination=destination,
                destination_scope=classify_destination_scope(destination),
                payload=payload,
            )
        return ToolContext(
            provider,
            tool_name,
            operation,
            path=_extract_path(tool_input),
            payload=payload,
        )

    if any(marker in lowered for marker in _EXTERNAL_MARKERS):
        operation = (
            ToolOperation.NETWORK_WRITE
            if any(word in lowered for word in _NETWORK_WRITE_WORDS)
            else ToolOperation.NETWORK_READ
        )
        destination = _extract_url(tool_input)
        return ToolContext(
            provider,
            tool_name,
            operation,
            destination=destination,
            destination_scope=classify_destination_scope(destination),
            payload=payload,
        )

    return ToolContext(provider, tool_name, ToolOperation.UNKNOWN, payload=payload)


def _path_matches(rule: FirewallRule, path: str) -> bool:
    lower = path.lower()
    basename = Path(path).name.lower()
    extension = Path(path).suffix.lower().lstrip(".")
    matched = False
    if rule.extensions:
        allowed = {ext.lower().lstrip(".") for ext in rule.extensions}
        if extension in allowed:
            matched = True
    if rule.names:
        if any(
            fnmatch(basename, name.lower()) or fnmatch(lower, name.lower()) for name in rule.names
        ):
            matched = True
    if rule.path_patterns:
        if any(fnmatch(lower, pattern.lower()) for pattern in rule.path_patterns):
            matched = True
    if rule.path_fragments:
        if any(fragment.lower() in lower for fragment in rule.path_fragments):
            matched = True
    return matched


def _rule_matches(rule: FirewallRule, context: ToolContext) -> bool:
    if rule.operations and context.operation not in rule.operations:
        return False
    if rule.tool_names:
        if not any(fnmatch(context.tool_name.lower(), name.lower()) for name in rule.tool_names):
            return False
    if rule.names or rule.extensions or rule.path_patterns or rule.path_fragments:
        if context.path is None:
            return False
        if not _path_matches(rule, context.path):
            return False
    if rule.destination_scopes:
        if context.operation not in {
            ToolOperation.NETWORK_READ,
            ToolOperation.NETWORK_WRITE,
            ToolOperation.DATABASE_READ,
            ToolOperation.DATABASE_WRITE,
            ToolOperation.MCP_CALL,
        }:
            return False
        if context.destination is None:
            return False
        scope = context.destination_scope or classify_destination_scope(context.destination)
        if scope not in rule.destination_scopes:
            return False
    return True


def _default_reason(action: PrivacyAction) -> str:
    if action == PrivacyAction.BLOCK:
        return "SecuRedact blocked this tool call because it targets a protected resource."
    if action == PrivacyAction.REVIEW:
        return "SecuRedact requires local review before this tool call can proceed."
    return "SecuRedact flagged this tool call."


def evaluate_firewall(policy: FirewallPolicy, context: ToolContext) -> FirewallDecision:
    """Return the first matching rule's decision, else the default action."""

    if not policy.enabled:
        return FirewallDecision(PrivacyAction.ALLOW)
    for rule in policy.rules:
        if _rule_matches(rule, context):
            return FirewallDecision(
                action=rule.action,
                requires_approval=rule.requires_approval,
                warning=rule.message if rule.action != PrivacyAction.BLOCK else None,
                reason=rule.message or _default_reason(rule.action),
            )
    return FirewallDecision(policy.default_action, reason=None)


def rule_allows_protected(rule: FirewallRule) -> bool:
    """True when an ``ALLOW`` rule would explicitly permit a protected path."""

    if rule.action != PrivacyAction.ALLOW:
        return False
    if not (rule.names or rule.extensions or rule.path_patterns or rule.path_fragments):
        return False
    return any(_path_matches(rule, example) for example in PROTECTED_PATH_EXAMPLES)


def validate_firewall_policy(policy: FirewallPolicy) -> None:
    """Reject firewall policies that would ``ALLOW`` a protected path."""

    for rule in policy.rules:
        if rule_allows_protected(rule):
            raise FirewallPolicyError(
                f"firewall rule {rule.id!r} would ALLOW a protected path or file type"
            )


def default_firewall_policy() -> FirewallPolicy:
    """A secure built-in firewall used when no explicit policy is configured."""

    return FirewallPolicy(
        enabled=True,
        default_action=PrivacyAction.ALLOW,
        rules=[
            FirewallRule(
                id="block_sensitive_files",
                operations=[ToolOperation.FILE_READ, ToolOperation.FILE_WRITE],
                names=[
                    ".env",
                    ".env.*",
                    "*.env",
                    "*.pem",
                    "*.key",
                    "*.p12",
                    "*.pfx",
                    "credentials.json",
                    "service-account*.json",
                    "id_rsa",
                    "id_dsa",
                    "id_ecdsa",
                    "id_ed25519",
                ],
                path_fragments=[".ssh/", ".aws/"],
                action=PrivacyAction.BLOCK,
                message=(
                    "SecuRedact blocked access to a protected file path "
                    "(secret or credential store)."
                ),
            ),
        ],
    )


def load_firewall_policy_from_environment() -> FirewallPolicy | None:
    """Resolve the active firewall policy.

    Returns ``None`` only when the firewall is explicitly disabled via
    ``SECUREDACT_FIREWALL_ENABLED=0`` (legacy behavior). Otherwise a configured
    policy is used, falling back to the secure built-in default so protection is
    fail-closed.
    """

    if os.getenv(FIREWALL_ENABLED_ENV, "1") == "0":
        return None
    try:
        from .policy_loader import load_policy_registry_from_environment

        registry = load_policy_registry_from_environment()
    except Exception:
        return default_firewall_policy()
    for policy in registry.list():
        if policy.firewall is not None:
            return policy.firewall
    return default_firewall_policy()
