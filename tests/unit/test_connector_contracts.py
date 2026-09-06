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
    is_extractable_format,
    is_scannable_format,
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
    # Only check for Microsoft-specific SDKs, not general HTTP/OAuth libraries
    for forbidden in ("msal", "msgraph", "azure.identity", "azure.mgmt"):
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


def _make_docx(document_xml: str) -> bytes:
    """Create a minimal DOCX file with the given document.xml content."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""",
        )
        zf.writestr(
            "_rels/.rels",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>""",
        )
        zf.writestr("word/document.xml", document_xml)
        zf.writestr(
            "word/_rels/document.xml.rels",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>""",
        )
    return buf.getvalue()


def test_is_extractable_format_recognizes_docx() -> None:
    assert is_extractable_format(
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert is_extractable_format(name="test.docx")
    assert is_extractable_format(name="document.DOCX")
    assert not is_extractable_format(mime_type="application/pdf")
    assert not is_extractable_format(name="test.pdf")


def test_is_scannable_format_includes_docx() -> None:
    assert is_scannable_format(mime_type="text/plain")
    assert is_scannable_format(
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert is_scannable_format(name="test.docx")
    assert not is_scannable_format(mime_type="application/pdf")


def test_extract_text_docx_contiguous_email_and_phone() -> None:
    """Email and phone in a single run should be extracted and detected."""
    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Contact Jane Doe at jane.doe@example.com or +31 6 12345678.</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"""
    docx_bytes = _make_docx(doc_xml)
    result = extract_text(
        docx_bytes,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        name="test.docx",
    )
    assert result is not None
    assert "jane.doe@example.com" in result.text
    assert "+31 6 12345678" in result.text
    # Engine should detect both
    from securedact_core import SecuredactEngine
    from securedact_core.api import RedactionRequest, ResponseMode
    from securedact_core.production import build_production_engine

    engine = SecuredactEngine(build_production_engine(require_contextual=False))
    request = RedactionRequest(
        text=result.text,
        policy="strict_external_ai",
        language="en",
        response_mode=ResponseMode.REVIEW,
    )
    engine_result = engine.prepare(request)
    assert engine_result.counts.get("email", 0) == 1
    assert engine_result.counts.get("phone", 0) == 1


def test_extract_text_docx_email_split_across_runs_no_space() -> None:
    """Email split across runs WITHOUT space should be joined correctly."""
    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Contact Jane Doe at jane.doe</w:t>
      </w:r>
      <w:r>
        <w:t>@example.com</w:t>
      </w:r>
      <w:r>
        <w:t> or +31 6 12345678.</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"""
    docx_bytes = _make_docx(doc_xml)
    result = extract_text(
        docx_bytes,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        name="test.docx",
    )
    assert result is not None
    assert "jane.doe@example.com" in result.text
    assert "+31 6 12345678" in result.text


def test_extract_text_docx_email_split_across_runs_with_space_preserved() -> None:
    """Email split across runs WITH space in first run - space is preserved (valid DOCX behavior)."""
    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Contact Jane Doe at jane.doe </w:t>
      </w:r>
      <w:r>
        <w:t>@example.com</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"""
    docx_bytes = _make_docx(doc_xml)
    result = extract_text(
        docx_bytes,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        name="test.docx",
    )
    assert result is not None
    # Space is preserved from the XML - this is correct behavior
    assert "jane.doe @example.com" in result.text


def test_extract_text_docx_phone_split_across_runs() -> None:
    """Phone number split across runs should work."""
    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Call me at +31 </w:t>
      </w:r>
      <w:r>
        <w:t>6 12345678</w:t>
      </w:r>
      <w:r>
        <w:t>.</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"""
    docx_bytes = _make_docx(doc_xml)
    result = extract_text(
        docx_bytes,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        name="test.docx",
    )
    assert result is not None
    assert "+31 6 12345678" in result.text


def test_extract_text_docx_multiple_paragraphs_separated() -> None:
    """Multiple paragraphs should be separated by newlines, not concatenated."""
    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>First paragraph with jane.doe@example.com</w:t>
      </w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:t>Second paragraph with +31 6 12345678</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"""
    docx_bytes = _make_docx(doc_xml)
    result = extract_text(
        docx_bytes,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        name="test.docx",
    )
    assert result is not None
    assert "\n" in result.text
    # Email should not merge with next paragraph
    assert "jane.doe@example.comSecond" not in result.text
    assert "jane.doe@example.com\nSecond" in result.text


def test_extract_text_docx_preserve_space_attribute() -> None:
    """xml:space='preserve' should be respected for leading/trailing spaces."""
    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t xml:space="preserve">Contact Jane Doe at </w:t>
      </w:r>
      <w:r>
        <w:t>jane.doe@example.com</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"""
    docx_bytes = _make_docx(doc_xml)
    result = extract_text(
        docx_bytes,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        name="test.docx",
    )
    assert result is not None
    assert "Contact Jane Doe at jane.doe@example.com" in result.text


def test_extract_text_docx_real_world_style() -> None:
    """Real-world style: Email split across runs with space in label, phone in next paragraph."""
    doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Email: </w:t>
      </w:r>
      <w:r>
        <w:t>test.person@example.com</w:t>
      </w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:t>Phone: +31 6 12345678</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>"""
    docx_bytes = _make_docx(doc_xml)
    result = extract_text(
        docx_bytes,
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        name="test.docx",
    )
    assert result is not None
    assert "Email: test.person@example.com" in result.text
    assert "Phone: +31 6 12345678" in result.text
    assert "\n" in result.text  # Paragraph separation


def test_extract_text_docx_unsupported_zip_rejected() -> None:
    """Arbitrary ZIP files (application/zip) should not be extractable."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", "hello")
    zip_bytes = buf.getvalue()
    # Not DOCX MIME type, not .docx extension
    result = extract_text(zip_bytes, mime_type="application/zip", name="test.zip")
    assert result is None
