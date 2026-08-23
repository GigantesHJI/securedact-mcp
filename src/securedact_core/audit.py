"""Privacy-preserving local audit events for the SecuRedact Agent Privacy Firewall.

FW-033 introduces a small, centralized, metadata-only audit-event abstraction for
security-relevant firewall actions. It is deliberately:

* **local only** — no network transmission, no external telemetry;
* **privacy-preserving** — events never contain raw sensitive values (passwords,
  API keys, tokens, PII text, redaction mappings, or original file content);
* **non-failing** — audit emission can never change or weaken an enforcement
  decision. A broken sink, a raised exception inside emission, or a disabled sink
  leaves the BLOCK/REDACT/ALLOW outcome untouched.

Event *generation* is always available. *Persistent storage* (FW-044) is a
separate, opt-in concern and is intentionally not implemented here: the default
sink is a no-op, and tests inject their own capturing sink.

The ``AuditEvent`` carries only explicit typed fields plus a restricted
``metadata`` mapping. Serialization (``AuditEvent.to_safe_dict``) drops any
metadata key that is not on a small allowlist or that looks like a raw sensitive
field, and refuses non-scalar values, so a developer mistake cannot leak a secret
through the audit log.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .models import EntityType
from .taxonomy import CATEGORY_DEFINITIONS, CategoryGroup


class AuditEventType(StrEnum):
    """Security-relevant firewall audit event types.

    ``EGRESS_BLOCKED`` and ``POLICY_OVERRIDE`` are reserved for later roadmap
    items (FW-030 / FW-044) and are intentionally never emitted by FW-033.
    """

    FILE_BLOCKED = "FILE_BLOCKED"
    SECRET_DETECTED = "SECRET_DETECTED"  # noqa: S105
    PII_REDACTED = "PII_REDACTED"
    TOOL_BLOCKED = "TOOL_BLOCKED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    FILE_READ = "FILE_READ"
    EGRESS_BLOCKED = "EGRESS_BLOCKED"
    POLICY_OVERRIDE = "POLICY_OVERRIDE"


# Credential / secret entity types that should be reported as SECRET_DETECTED
# rather than generic PII redactions. Derived from the taxonomy so it stays in
# sync with the detector/policy layer.
_SECRET_ENTITY_TYPES: frozenset[str] = frozenset(
    entity_type.value
    for entity_type in EntityType
    if (definition := CATEGORY_DEFINITIONS.get(entity_type)) is not None
    and definition.group == CategoryGroup.CREDENTIALS
)


def is_secret_entity_type(entity_type: str) -> bool:
    """Return whether ``entity_type`` is a credential/secret category."""

    return entity_type in _SECRET_ENTITY_TYPES


# Metadata keys that are safe to serialize. Anything else is dropped, so a
# developer cannot accidentally persist a raw value through the audit log.
_ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "count",
        "total",
        "min_span_length",
        "max_span_length",
        "confidence",
        "rule_id",
        "rule",
        "filename",
        "extension",
        "entity_type_group",
        "approved_by_user",
        "override_reason",
        "session_reference_hash",
        "policy_version",
        "detector",
    }
)

# Key fragments that are never allowed in serialized metadata, even if a caller
# tries to stash a raw value there. This is defense-in-depth against the most
# obvious naming mistakes (``value``, ``secret``, ``password``, ``mapping``...).
_DENIED_METADATA_KEY_FRAGMENTS: tuple[str, ...] = (
    "value",
    "secret",
    "password",
    "passwd",
    "token",
    "apikey",
    "api_key",
    "credential",
    "private_key",
    "key",
    "raw",
    "text",
    "content",
    "payload",
    "body",
    "plaintext",
    "mapping",
    "redaction_mapping",
    "replacement",
)

Scalar = str | int | float | bool | None
AuditSink = Callable[["AuditEvent"], None]


@dataclass(frozen=True)
class AuditEvent:
    """An immutable, privacy-preserving firewall audit event.

    Only metadata is stored beyond the explicit typed fields, and even that is
    restricted at serialization time. The event intentionally has no field that
    could carry a raw sensitive value (no ``text``, no ``mapping``).
    """

    event_type: AuditEventType
    action: str | None = None
    reason_code: str | None = None
    entity_type: str | None = None
    rule: str | None = None
    provider: str | None = None
    tool_name: str | None = None
    operation: str | None = None
    source: str | None = None
    destination: str | None = None
    policy_name: str | None = None
    entity_types: tuple[str, ...] | None = None
    count: int | None = None
    event_id: str | None = None
    timestamp_utc: str | None = None
    metadata: Mapping[str, Scalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalize the optional collection so callers may pass a list/dict.
        if self.entity_types is not None and not isinstance(self.entity_types, tuple):
            object.__setattr__(self, "entity_types", tuple(self.entity_types))
        if not isinstance(self.metadata, Mapping):
            object.__setattr__(self, "metadata", dict(self.metadata))

    def to_safe_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view with raw values structurally absent.

        Metadata keys that are not allowlisted, that look like raw sensitive
        fields, or whose values are non-scalar are dropped rather than escaped.
        """

        payload: dict[str, Any] = {
            "event_type": str(self.event_type),
            "action": self.action,
            "reason_code": self.reason_code,
            "entity_type": self.entity_type,
            "rule": self.rule,
            "provider": self.provider,
            "tool_name": self.tool_name,
            "operation": self.operation,
            "source": self.source,
            "destination": self.destination,
            "policy_name": self.policy_name,
            "entity_types": list(self.entity_types) if self.entity_types else None,
            "count": self.count,
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
        }
        safe_metadata = _sanitize_metadata(self.metadata)
        if safe_metadata:
            payload["metadata"] = safe_metadata
        return {key: value for key, value in payload.items() if value is not None}


def _sanitize_metadata(metadata: Mapping[str, Any]) -> dict[str, Scalar]:
    """Return only allowlisted, scalar, non-sensitive metadata entries."""

    cleaned: dict[str, Scalar] = {}
    for key, value in metadata.items():
        if not isinstance(key, str):
            continue
        lowered = key.lower()
        if lowered not in _ALLOWED_METADATA_KEYS:
            continue
        if any(fragment in lowered for fragment in _DENIED_METADATA_KEY_FRAGMENTS):
            continue
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            # Reject nested/structured values: the audit log is scalar-only.
            continue
        cleaned[key] = value
    return cleaned


def _make_event_id() -> str:
    import secrets

    return secrets.token_hex(8)


# --- Sink abstraction -------------------------------------------------------


def _noop_sink(_event: AuditEvent) -> None:
    """Default sink: does nothing (no persistent storage in FW-033)."""

    return None


_NOOP_SINK: AuditSink = _noop_sink

_sink_lock = threading.Lock()
_sink: AuditSink = _NOOP_SINK


def set_audit_sink(sink: AuditSink) -> AuditSink:
    """Install a process-wide audit sink; returns the previous sink.

    Tests should prefer :func:`capture_audit_events`, which restores the prior
    sink on exit so suites do not leak state into one another.
    """

    global _sink
    previous = _sink
    with _sink_lock:
        _sink = sink if sink is not None else _NOOP_SINK
    return previous


def get_audit_sink() -> AuditSink:
    with _sink_lock:
        return _sink


def emit_audit_event(event: AuditEvent) -> None:
    """Emit an audit event to the active sink.

    This function is intentionally fail-safe: any exception raised by the sink,
    the event, or metadata sanitization is swallowed so that audit emission can
    never turn a BLOCK into an ALLOW or otherwise affect enforcement.
    """

    try:
        sink = get_audit_sink()
        sink(event)
    except Exception:
        return


class AuditSinkCollector:
    """A thread-safe, in-memory audit sink used by tests and local diagnostics."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def __call__(self, event: AuditEvent) -> None:
        with self._lock:
            self.events.append(event)

    def serialized(self) -> list[dict[str, Any]]:
        with self._lock:
            return [event.to_safe_dict() for event in self.events]

    def clear(self) -> None:
        with self._lock:
            self.events.clear()


@contextmanager
def capture_audit_events(
    collector: AuditSinkCollector | None = None,
) -> Iterator[AuditSinkCollector]:
    """Temporarily install a capturing sink and restore the prior one on exit."""

    local = collector or AuditSinkCollector()
    previous = set_audit_sink(local)
    try:
        yield local
    finally:
        set_audit_sink(previous)


def build_audit_event(
    event_type: AuditEventType,
    *,
    action: str | None = None,
    reason_code: str | None = None,
    entity_type: str | None = None,
    rule: str | None = None,
    provider: str | None = None,
    tool_name: str | None = None,
    operation: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    policy_name: str | None = None,
    entity_types: tuple[str, ...] | None = None,
    count: int | None = None,
    metadata: Mapping[str, Scalar] | None = None,
    event_id: str | None = None,
    timestamp_utc: str | None = None,
) -> AuditEvent:
    """Construct an ``AuditEvent`` with a generated id/timestamp when omitted."""

    return AuditEvent(
        event_type=event_type,
        action=action,
        reason_code=reason_code,
        entity_type=entity_type,
        rule=rule,
        provider=provider,
        tool_name=tool_name,
        operation=operation,
        source=source,
        destination=destination,
        policy_name=policy_name,
        entity_types=entity_types,
        count=count,
        event_id=event_id or _make_event_id(),
        timestamp_utc=timestamp_utc or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        metadata=metadata or {},
    )
