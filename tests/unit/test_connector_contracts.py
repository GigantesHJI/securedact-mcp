# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import sys

import pytest
from pydantic import ValidationError

from securedact_core.connectors import (
    ConnectorCapability,
    ConnectorResource,
    ConnectorScanner,
    ResourceKind,
    ScanContext,
    ScanResult,
    ScanSeverity,
    ScanStatus,
    extract_text,
    validate_resource_identifier,
)
from securedact_core.connectors.scan import ScanErrorCode
from securedact_core.production import build_production_engine


def _engine():
    return __import__("securedact_core").SecuredactEngine(
        build_production_engine(require_contextual=False)
    )


def _resource(**overrides) -> ConnectorResource:
    base = dict(
        resource_id="driveItem-abc123",
        platform="microsoft365",
        resource_kind=ResourceKind.FILE,
        org_id="org-1",
        tenant_id="tenant-A",
        name="notes.txt",
        mime_type="text/plain",
    )
    base.update(overrides)
    return ConnectorResource(**base)


def test_resource_kind_is_extensible_beyond_files() -> None:
    for kind in ResourceKind:
        assert isinstance(kind.value, str)
    assert {k.value for k in ResourceKind} >= {
        "file",
        "document",
        "message",
        "record",
        "issue",
        "page",
        "comment",
        "attachment",
        "repo_content",
    }


def test_capability_declaration_is_subset_only() -> None:
    supported = {ConnectorCapability.READ, ConnectorCapability.SCAN}
    assert ConnectorCapability.WRITE not in supported
    assert ConnectorCapability.QUARANTINE not in supported


def test_resource_serialization_round_trip() -> None:
    resource = _resource()
    payload = resource.model_dump(mode="json")
    assert payload["platform"] == "microsoft365"
    assert payload["resource_kind"] == "file"
    restored = ConnectorResource.model_validate(payload)
    assert restored == resource


def test_invalid_resource_identifier_rejected() -> None:
    with pytest.raises(ValidationError):
        _resource(resource_id="../evil")
    with pytest.raises(ValidationError):
        _resource(org_id="bad id with space")
    with pytest.raises(ValidationError):
        _resource(tenant_id="<script>")


def test_validate_resource_identifier_helper() -> None:
    with pytest.raises(ValueError):
        validate_resource_identifier("a b")
    with pytest.raises(ValueError):
        validate_resource_identifier("..")
    assert validate_resource_identifier("site-1/drive-2") == "site-1/drive-2"


def test_scan_request_and_result_serialization() -> None:
    resource = _resource(extracted_text="hello")
    request = __import__("securedact_core.connectors").connectors.scan.ScanRequest(
        resource=resource, context=ScanContext()
    )
    assert request.resource.resource_id == "driveItem-abc123"

    result = ScanResult(
        status=ScanStatus.COMPLETED,
        severity=ScanSeverity.LOW,
        resource_id=resource.resource_id,
        platform=resource.platform,
        org_id=resource.org_id,
        tenant_id=resource.tenant_id,
        findings=[],
    )
    dumped = result.model_dump(mode="json", exclude_none=True)
    assert dumped["status"] == "completed"
    assert "extracted_text" not in dumped


def test_importing_connector_contracts_does_not_pull_microsoft() -> None:
    import securedact_core.connectors as connectors

    assert connectors is not None
    for forbidden in ("msal", "msgraph", "requests_oauthlib", "azure"):
        assert forbidden not in sys.modules


def test_extract_text_supports_text_formats_only() -> None:
    assert extract_text(b"hello world", mime_type="text/plain") is not None
    assert extract_text(b"hello world", name="report.md") is not None
    assert extract_text(b"\x00\x01\x02\xff", mime_type="application/pdf") is None
    assert extract_text(b"not really utf8 \xff\xfe", mime_type="text/plain") is None


def test_scanner_maps_ok_result() -> None:
    resource = _resource(extracted_text="Contact alex.canary@example.test")
    result = ConnectorScanner(_engine()).scan(resource, ScanContext())
    assert result.status == ScanStatus.COMPLETED
    assert result.severity == ScanSeverity.MEDIUM
    assert "email" in result.counts
    assert result.redaction_available is True
    assert result.supported_action == "redact"


def test_scanner_never_reports_false_success_on_blocked() -> None:
    resource = _resource(extracted_text="Authorization: Bearer syntheticTokenValue123456")
    result = ConnectorScanner(_engine()).scan(resource, ScanContext())
    assert result.status == ScanStatus.BLOCKED
    assert result.redaction_available is False
    assert result.supported_action == "none"


def test_scanner_reports_unsupported_format_as_error() -> None:
    resource = _resource(extracted_text=None)
    result = ConnectorScanner(_engine()).scan(resource, ScanContext())
    assert result.status == ScanStatus.ERROR
    assert result.error is not None
    assert result.error.code == ScanErrorCode.UNSUPPORTED_FORMAT
    assert result.severity == ScanSeverity.NONE


def test_scanner_enforces_size_limit_without_silent_truncation() -> None:
    resource = _resource(extracted_text="x" * (1_000_001))
    result = ConnectorScanner(_engine()).scan(resource, ScanContext())
    assert result.status == ScanStatus.ERROR
    assert result.error is not None
    assert result.error.code == ScanErrorCode.CONTENT_TOO_LARGE
