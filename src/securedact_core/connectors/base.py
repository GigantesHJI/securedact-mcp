# SPDX-License-Identifier: Apache-2.0
"""Connector base orchestration (CONN-001).

This module wires the platform-neutral contracts to the SecuRedact engine. It is
deliberately free of any Microsoft/Graph/OAuth dependency so the abstraction can
be validated in core unit tests without a tenant.

The platform connector is responsible for *retrieval* and *extraction* (it knows
how to talk to Graph, GitHub, ...). This module owns the *prepare* and
*translate* steps, reusing ``SecuredactEngine.prepare`` and never duplicating
detector logic.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from ..api import (
    PrepareOutcome,
    PrepareStatus,
    RedactionRequest,
    ResponseMode,
    SecuredactEngine,
)
from ..audit import (
    AuditEventType,
    build_audit_event,
    emit_audit_event,
    is_secret_entity_type,
)
from ..firewall import MAX_INSPECTION_TEXT_CHARS
from ..taxonomy import SPECIAL_CATEGORY_TYPES
from .contracts import (
    ConnectorResource,
    NormalizedContent,
    ScanContext,
    validate_resource_identifier,
)
from .scan import (
    ScanError,
    ScanErrorCode,
    ScanFinding,
    ScanResult,
    ScanSeverity,
    ScanStatus,
)

_TEXT_MIME_TYPES = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/csv",
        "text/html",
        "application/json",
        "application/xml",
        "text/xml",
    }
)
_TEXT_EXTENSIONS = frozenset(
    {".txt", ".md", ".markdown", ".csv", ".json", ".html", ".htm", ".xml", ".log"}
)


def is_text_format(*, mime_type: str | None = None, name: str | None = None) -> bool:
    """Return whether the given format is extractable with core dependencies."""

    if mime_type in _TEXT_MIME_TYPES:
        return True
    if name:
        lowered = name.lower()
        if any(lowered.endswith(ext) for ext in _TEXT_EXTENSIONS):
            return True
    return False


def extract_text(
    raw: bytes,
    *,
    mime_type: str | None = None,
    name: str | None = None,
) -> NormalizedContent | None:
    """Extract normalized text from raw bytes for a supported text format.

    Returns ``None`` for unsupported formats so the caller can report
    ``UNSUPPORTED_FORMAT`` instead of claiming a successful scan. Binary content
    that claims to be text but fails UTF-8 decoding is treated as unsupported.
    """

    if not is_text_format(mime_type=mime_type, name=name):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return NormalizedContent(
        text=text, source_format=mime_type or "text/plain", char_count=len(text)
    )


def _severity_from_counts(counts: dict[str, int]) -> ScanSeverity:
    if not counts:
        return ScanSeverity.NONE
    for entity_type in counts:
        if is_secret_entity_type(entity_type) or entity_type in SPECIAL_CATEGORY_TYPES:
            return ScanSeverity.HIGH
    return ScanSeverity.MEDIUM


class ConnectorScanner:
    """Runs a prepared ``ConnectorResource`` through the SecuRedact engine.

    Platform connectors are expected to populate ``resource.extracted_text``
    (via retrieval + extraction) before calling :meth:`scan`. The scanner enforces
    size limits, reuses the engine, maps the result, and emits privacy-preserving
    connector audit events. It never reports a false success.
    """

    def __init__(self, engine: SecuredactEngine) -> None:
        self._engine = engine

    def scan(
        self,
        resource: ConnectorResource,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
    ) -> ScanResult:
        context = context or ScanContext()
        validate_resource_identifier(resource.resource_id, field="resource_id")

        if resource.extracted_text is None:
            return self._error(
                resource,
                context,
                integration_id,
                ScanErrorCode.UNSUPPORTED_FORMAT,
                "resource has no extractable text content",
            )

        text = resource.extracted_text
        if len(text) > MAX_INSPECTION_TEXT_CHARS:
            return self._error(
                resource,
                context,
                integration_id,
                ScanErrorCode.CONTENT_TOO_LARGE,
                "resource exceeds the maximum inspectable size",
            )

        self._emit(
            AuditEventType.CONNECTOR_SCAN_STARTED,
            resource,
            context,
            integration_id,
            user_id,
            metadata={"policy": context.policy},
        )

        request = RedactionRequest(
            text=text,
            policy=context.policy,
            language=context.language,
            response_mode=ResponseMode.REVIEW
            if context.response_mode == "review"
            else ResponseMode.MINIMAL,
        )
        try:
            prepared = self._engine.prepare(request)
        except Exception:
            self._emit(
                AuditEventType.CONNECTOR_ERROR,
                resource,
                context,
                integration_id,
                user_id,
                metadata={"stage": "prepare"},
            )
            return self._error(
                resource,
                context,
                integration_id,
                ScanErrorCode.ENGINE_UNAVAILABLE,
                "privacy engine was unavailable",
            )

        result = self._translate(resource, context, prepared, integration_id)
        event_type = (
            AuditEventType.CONNECTOR_POLICY_BLOCKED
            if prepared.status == PrepareStatus.BLOCKED
            else AuditEventType.CONNECTOR_SCAN_COMPLETED
        )
        self._emit(
            event_type,
            resource,
            context,
            integration_id,
            user_id,
            metadata={
                "policy": prepared.policy,
                "policy_digest": prepared.policy_digest,
                "status": str(prepared.status.value),
            },
        )
        return result

    def _translate(
        self,
        resource: ConnectorResource,
        context: ScanContext,
        prepared: Any,
        integration_id: str | None,
    ) -> ScanResult:
        counts = dict(prepared.counts or {})
        supported_action: Literal["none", "review", "redact", "quarantine"] = "none"
        if prepared.status == PrepareStatus.OK:
            status = ScanStatus.COMPLETED
            outcome = prepared.outcome
            policy_decision = outcome.value if outcome is not None else "allow"
            supported_action = (
                "redact"
                if outcome in {PrepareOutcome.REDACTED, PrepareOutcome.PSEUDONYMIZED}
                else "none"
            )
            redaction_available = outcome in {PrepareOutcome.REDACTED, PrepareOutcome.PSEUDONYMIZED}
        elif prepared.status == PrepareStatus.REVIEW_REQUIRED:
            status = ScanStatus.REVIEW_REQUIRED
            policy_decision = "review_required"
            supported_action = "review"
            redaction_available = False
        else:
            status = ScanStatus.BLOCKED
            policy_decision = "blocked"
            supported_action = "none"
            redaction_available = False

        findings = [
            ScanFinding(
                category=entity_type,
                count=count,
                decision="block" if entity_type in SPECIAL_CATEGORY_TYPES else "redact",
                is_secret=is_secret_entity_type(entity_type),
            )
            for entity_type, count in sorted(counts.items())
        ]
        severity = _severity_from_counts(counts)
        return ScanResult(
            status=status,
            severity=severity,
            resource_id=resource.resource_id,
            platform=resource.platform,
            org_id=resource.org_id,
            tenant_id=resource.tenant_id,
            integration_id=integration_id,
            categories=sorted(counts.keys()),
            counts=counts,
            findings=findings,
            policy_decision=policy_decision,
            supported_action=supported_action,
            redaction_available=redaction_available,
            requires_review=status == ScanStatus.REVIEW_REQUIRED,
            warnings=list(prepared.reason_codes or []),
            scan_metadata={
                "policy": prepared.policy,
                "policy_version": prepared.policy_version,
                "policy_digest": prepared.policy_digest,
            },
            correlation_id=context.correlation_id,
        )

    def _error(
        self,
        resource: ConnectorResource,
        context: ScanContext,
        integration_id: str | None,
        code: ScanErrorCode,
        message: str,
    ) -> ScanResult:
        self._emit(
            AuditEventType.CONNECTOR_ERROR,
            resource,
            context,
            integration_id,
            None,
            metadata={"scan_error_code": code.value},
        )
        return ScanResult(
            status=ScanStatus.ERROR,
            resource_id=resource.resource_id,
            platform=resource.platform,
            org_id=resource.org_id,
            tenant_id=resource.tenant_id,
            integration_id=integration_id,
            error=ScanError(code=code, message=message),
            correlation_id=context.correlation_id,
        )

    def _emit(
        self,
        event_type: AuditEventType,
        resource: ConnectorResource,
        context: ScanContext,
        integration_id: str | None,
        user_id: str | None,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        emit_audit_event(
            build_audit_event(
                event_type,
                action="scan",
                operation="connector_scan",
                source=resource.resource_id,
                provider=resource.platform,
                policy_name=context.policy,
                entity_types=tuple(),
                count=0,
                event_id=None,
                timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                metadata={
                    "org_id": resource.org_id,
                    "tenant_id": resource.tenant_id,
                    "integration_id": integration_id or "",
                    "user_id": user_id or "",
                    "resource_kind": resource.resource_kind.value,
                    **(metadata or {}),
                },
            )
        )
