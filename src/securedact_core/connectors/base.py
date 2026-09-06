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

import io
import logging
import time
import zipfile
from typing import Any, Literal
from xml.etree import ElementTree

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

logger = logging.getLogger(__name__)


# Structured debug logging for connector scan pipeline (privacy-safe)
def _log_connector_scan_diagnostics(
    *,
    stage: str,
    resource_id: str | None = None,
    platform: str | None = None,
    mime_type: str | None = None,
    text_chars: int | None = None,
    findings_count: int | None = None,
    category_counts: dict[str, int] | None = None,
    error: str | None = None,
    engine_status: str | None = None,
) -> None:
    """Emit privacy-safe structured diagnostics for the connector scan pipeline."""
    log_data = {
        "stage": stage,
        "connector_scan": True,
    }
    if resource_id is not None:
        log_data["resource_id_hash"] = (
            resource_id[:8] + "..." if len(resource_id) > 8 else resource_id
        )
    if platform is not None:
        log_data["platform"] = platform
    if mime_type is not None:
        log_data["mime_type"] = mime_type
    if text_chars is not None:
        log_data["text_chars"] = text_chars
    if findings_count is not None:
        log_data["findings_count"] = findings_count
    if category_counts is not None:
        log_data["category_counts"] = category_counts
    if error is not None:
        log_data["error"] = error
    if engine_status is not None:
        log_data["engine_status"] = engine_status
    logger.debug("conn_scan_diag %s", log_data)


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

_EXTRACTABLE_DOCUMENT_MIME_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
)
_EXTRACTABLE_DOCUMENT_EXTENSIONS = frozenset({".docx"})


def is_extractable_format(*, mime_type: str | None = None, name: str | None = None) -> bool:
    """Return whether the given format is a supported extractable document format.

    Unlike :func:`is_text_format`, this covers binary container formats (e.g. DOCX)
    whose text content can be extracted by the SecuRedact pipeline.
    """
    if mime_type in _EXTRACTABLE_DOCUMENT_MIME_TYPES:
        return True
    if name:
        lowered = name.lower()
        if any(lowered.endswith(ext) for ext in _EXTRACTABLE_DOCUMENT_EXTENSIONS):
            return True
    return False


def is_scannable_format(*, mime_type: str | None = None, name: str | None = None) -> bool:
    """Return whether the given format can be scanned (direct text or extractable document)."""
    return is_text_format(mime_type=mime_type, name=name) or is_extractable_format(
        mime_type=mime_type, name=name
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

    if not is_scannable_format(mime_type=mime_type, name=name):
        return None

    # Handle direct text formats
    if is_text_format(mime_type=mime_type, name=name):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return NormalizedContent(
            text=text, source_format=mime_type or "text/plain", char_count=len(text)
        )

    # Handle extractable document formats (e.g., DOCX)
    if is_extractable_format(mime_type=mime_type, name=name):
        extracted = _extract_document_text(raw, mime_type=mime_type, name=name)
        if extracted is not None:
            # Use a short format identifier for extractable documents
            doc_format = _doc_format_identifier(mime_type, name)
            return NormalizedContent(
                text=extracted, source_format=doc_format, char_count=len(extracted)
            )
        return None

    return None


def _doc_format_identifier(mime_type: str | None, name: str | None) -> str:
    """Return a short format identifier for extractable documents (max 64 chars)."""
    if mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        return "docx"
    if name and name.lower().endswith(".docx"):
        return "docx"
    return "extractable"


def _extract_document_text(
    raw: bytes,
    *,
    mime_type: str | None = None,
    name: str | None = None,
) -> str | None:
    """Extract text from supported document formats (DOCX, etc.).

    Returns the extracted text or ``None`` if extraction fails or format is not supported.
    Implements security bounds to prevent zip bombs and excessive resource consumption.
    """
    if not is_extractable_format(mime_type=mime_type, name=name):
        return None

    # Security bounds
    MAX_COMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
    MAX_EXTRACTED_BYTES = 10 * 1024 * 1024  # 10 MB
    MAX_COMPRESSION_RATIO = 100

    if len(raw) > MAX_COMPRESSED_BYTES:
        return None

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            # Check for zip bomb indicators
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if total_uncompressed > MAX_EXTRACTED_BYTES:
                return None
            if len(raw) > 0 and total_uncompressed / len(raw) > MAX_COMPRESSION_RATIO:
                return None

            # Look for word/document.xml in DOCX
            doc_xml_name = "word/document.xml"
            if doc_xml_name not in zf.namelist():
                return None

            # Read and parse the document XML
            with zf.open(doc_xml_name) as doc_xml:
                doc_bytes = doc_xml.read()
                if len(doc_bytes) > MAX_EXTRACTED_BYTES:
                    return None

            # Parse XML and extract text from w:t elements
            # DOCX uses the namespace http://schemas.openxmlformats.org/wordprocessingml/2006/main
            # The DOCX file comes from the user's own Microsoft 365 tenant (Graph download),
            # not from untrusted external sources. Size limits prevent billion laughs attacks.
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            root = ElementTree.fromstring(doc_bytes)  # noqa: S314

            # Extract text paragraph by paragraph to preserve boundaries
            paragraphs = []
            for p_elem in root.iter(f"{{{ns['w']}}}p"):
                # Join runs within the same paragraph
                # Spacing is already encoded in the w:t elements (xml:space="preserve" or explicit spaces)
                para_texts = []
                for t_elem in p_elem.iter(f"{{{ns['w']}}}t"):
                    if t_elem.text:
                        para_texts.append(t_elem.text)
                if para_texts:
                    paragraphs.append("".join(para_texts))

            # Join paragraphs with newline to maintain separation
            return "\n".join(paragraphs) if paragraphs else ""
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ElementTree.ParseError, KeyError, OSError):
        return None


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
            _log_connector_scan_diagnostics(
                stage="scan_start",
                resource_id=resource.resource_id,
                platform=resource.platform,
                mime_type=resource.mime_type,
                error="resource has no extractable text content",
            )
            return self._error(
                resource,
                context,
                integration_id,
                ScanErrorCode.UNSUPPORTED_FORMAT,
                "resource has no extractable text content",
            )

        text = resource.extracted_text
        _log_connector_scan_diagnostics(
            stage="scan_start",
            resource_id=resource.resource_id,
            platform=resource.platform,
            mime_type=resource.mime_type,
            text_chars=len(text),
        )
        if len(text) > MAX_INSPECTION_TEXT_CHARS:
            _log_connector_scan_diagnostics(
                stage="scan_start",
                resource_id=resource.resource_id,
                platform=resource.platform,
                mime_type=resource.mime_type,
                text_chars=len(text),
                error="content too large",
            )
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
            _log_connector_scan_diagnostics(
                stage="engine_prepare",
                resource_id=resource.resource_id,
                platform=resource.platform,
                mime_type=resource.mime_type,
                error="engine prepare exception",
                engine_status="exception",
            )
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

        _log_connector_scan_diagnostics(
            stage="engine_prepare",
            resource_id=resource.resource_id,
            platform=resource.platform,
            mime_type=resource.mime_type,
            text_chars=len(text),
            findings_count=sum(prepared.counts.values()) if prepared.counts else 0,
            category_counts=dict(prepared.counts) if prepared.counts else {},
            engine_status=str(prepared.status.value),
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
        _log_connector_scan_diagnostics(
            stage="scan_complete",
            resource_id=resource.resource_id,
            platform=resource.platform,
            mime_type=resource.mime_type,
            findings_count=sum(result.counts.values()) if result.counts else 0,
            category_counts=dict(result.counts) if result.counts else {},
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
