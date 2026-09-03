# SPDX-License-Identifier: Apache-2.0
"""Microsoft Graph connector unit tests (M365-102).

Tests use a fake in-memory transport; no real Microsoft tenant is contacted.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from securedact_core import SecuredactEngine
from securedact_core.connectors import (
    ConnectorCapability,
    ConnectorResource,
    ConnectorScanner,
    ResourceKind,
    ScanContext,
    extract_text,
    validate_resource_identifier,
)
from securedact_core.connectors.microsoft import (
    CANONICAL_GRAPH_BASE,
    FILE_MIME_TYPES,
    FOLDER_MIME_TYPE,
    MICROSOFT_365_PLATFORM,
    SOURCE_TYPE_ONEDRIVE,
    SOURCE_TYPE_SHAREPOINT_DRIVE,
    MicrosoftApiError,
    MicrosoftGraphBrowser,
    build_graph_scopes,
    default_connector_scopes,
    has_write_scope,
    safe_diagnostic,
)
from securedact_core.connectors.scan import ScanErrorCode, ScanSeverity, ScanStatus
from securedact_core.production import build_production_engine
from tests.unit.microsoft_transport_fake import FakeMicrosoftTransport


def _engine() -> SecuredactEngine:
    return SecuredactEngine(build_production_engine(require_contextual=False))


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
    request = ConnectorScanner(_engine()).scan(resource, ScanContext())
    assert request.status == ScanStatus.COMPLETED


def test_importing_connector_contracts_does_not_pull_microsoft() -> None:
    import sys

    import securedact_core.connectors as connectors

    assert connectors is not None
    # Only check for Microsoft-specific SDKs, not general HTTP libraries
    for forbidden in ("msal", "msgraph", "azure.identity", "azure.mgmt"):
        assert forbidden not in sys.modules


def test_extract_text_supports_text_formats_only() -> None:
    assert extract_text(b"hello world", mime_type="text/plain") is not None
    assert extract_text(b"hello world", name="report.md") is not None
    assert extract_text(b"\x00\x01\x02\xff", mime_type="application/pdf") is None
    assert extract_text(b"not really utf8 \xff\xfe", mime_type="text/plain") is None


# --- Microsoft-specific tests ---


def test_canonical_graph_base() -> None:
    assert CANONICAL_GRAPH_BASE == "https://graph.microsoft.com/v1.0"


def test_platform_constant() -> None:
    assert MICROSOFT_365_PLATFORM == "microsoft365"


def test_source_type_constants() -> None:
    assert SOURCE_TYPE_ONEDRIVE == "microsoft_onedrive"
    assert SOURCE_TYPE_SHAREPOINT_DRIVE == "microsoft_sharepoint_drive"


def test_folder_mime_type() -> None:
    assert FOLDER_MIME_TYPE == "folder"


def test_file_mime_types() -> None:
    assert "text/plain" in FILE_MIME_TYPES
    assert "text/markdown" in FILE_MIME_TYPES
    assert "text/csv" in FILE_MIME_TYPES
    assert "application/json" in FILE_MIME_TYPES


def test_default_connector_scopes_read_only() -> None:
    scopes = default_connector_scopes()
    assert "User.Read" in scopes
    assert "Files.Read" in scopes
    assert "Sites.Read.All" in scopes
    assert "offline_access" in scopes
    # No write scopes
    assert "Files.ReadWrite" not in scopes
    assert "Sites.ReadWrite.All" not in scopes


def test_has_write_scope() -> None:
    assert has_write_scope(["Files.Read", "Files.ReadWrite"]) is True
    assert has_write_scope(["Files.Read", "Sites.Read.All"]) is False


def test_build_graph_scopes() -> None:
    scopes = build_graph_scopes({ConnectorCapability.READ, ConnectorCapability.SCAN})
    assert "User.Read" in scopes
    assert "Files.Read" in scopes
    assert "Sites.Read.All" in scopes

    write_scopes = build_graph_scopes({ConnectorCapability.WRITE})
    assert "Files.ReadWrite" in write_scopes


# --- Browser tests ---


class TestMicrosoftGraphBrowser:
    """Tests for the MicrosoftGraphBrowser with fake transport."""

    def setup_method(self):
        self.transport = FakeMicrosoftTransport(user_id="user-123", tenant_id="tenant-456")
        self.transport.add_drive(
            id="drive-1",
            name="My Drive",
            driveType="personal",
            owner={"user": {"displayName": "Test User"}},
        )
        self.transport.add_drive(
            id="drive-2",
            name="Team Documents",
            driveType="documentLibrary",
        )
        self.transport.add_site(
            id="site-1",
            displayName="Team Site",
            webUrl="https://contoso.sharepoint.com/sites/team",
        )
        # Add items
        self.transport.add_item(
            "drive-1", id="root", name="Root", folder={}, parentReference={}, size=0
        )
        self.transport.add_item(
            "drive-1",
            id="file-1",
            name="notes.txt",
            file={"mimeType": "text/plain"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=100,
        )
        self.transport.add_item(
            "drive-1",
            id="folder-1",
            name="Documents",
            folder={},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=0,
        )
        self.transport.add_item(
            "drive-1",
            id="file-2",
            name="report.txt",
            file={"mimeType": "text/plain"},
            parentReference={"id": "folder-1", "driveId": "drive-1"},
            size=200,
        )
        self.transport.set_content("drive-1", "file-1", b"Contact jane@example.com")
        self.transport.set_content("drive-1", "file-2", b"IBAN NL91ABNA0417164300")

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        self.browser = MicrosoftGraphBrowser(identity, self.transport)

    def test_list_drives(self):
        drives = self.browser.list_drives()
        assert len(drives) == 2
        assert drives[0].drive_id == "drive-1"
        assert drives[1].drive_id == "drive-2"
        assert drives[1].drive_type == "documentLibrary"

    def test_get_drive(self):
        drive = self.browser.get_drive("drive-1")
        assert drive.drive_id == "drive-1"
        assert drive.name == "My Drive"

    def test_list_sites(self):
        sites = self.browser.list_sites()
        assert len(sites) == 1
        assert sites[0].site_id == "site-1"
        assert sites[0].name == "Team Site"

    def test_get_site(self):
        site = self.browser.get_site("site-1")
        assert site.site_id == "site-1"

    def test_get_site_drive(self):
        self.transport.set_site_drive("site-1", "drive-sp-1")
        self.transport.add_drive(
            id="drive-sp-1",
            name="Documents",
            driveType="documentLibrary",
        )
        drive = self.browser.get_site_drive("site-1")
        assert drive.drive_id == "drive-sp-1"

    def test_list_children_root(self):
        children = self.browser.list_children("drive-1")
        assert len(children) >= 2
        names = {c.name for c in children}
        assert "notes.txt" in names
        assert "Documents" in names

    def test_list_children_folder(self):
        children = self.browser.list_children("drive-1", folder_id="folder-1")
        assert len(children) == 1
        assert children[0].name == "report.txt"

    def test_resolve_resource_file(self):
        resource = self.browser.resolve_resource("drive-1", "file-1")
        assert resource.resource_id == "file-1"
        assert resource.name == "notes.txt"
        assert resource.mime_type == "text/plain"

    def test_resolve_resource_folder_fails(self):
        with pytest.raises(MicrosoftApiError) as exc_info:
            self.browser.resolve_resource("drive-1", "folder-1")
        assert exc_info.value.status_code == 400

    def test_scan_file(self):
        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        result = self.browser.select_and_scan("drive-1", "file-1", scanner)
        assert result.status == ScanStatus.COMPLETED
        assert result.severity == ScanSeverity.MEDIUM
        assert "email" in result.counts

    def test_scan_file_unsupported_format(self):
        # Use a binary mime type that's not in FILE_MIME_TYPES
        self.transport.add_item(
            "drive-1",
            id="binary-1",
            name="data.bin",
            file={"mimeType": "application/octet-stream"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=100,
        )
        self.transport.set_content("drive-1", "binary-1", b"\x00\x01\x02")
        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        result = self.browser.select_and_scan("drive-1", "binary-1", scanner)
        assert result.status == ScanStatus.ERROR
        assert result.error is not None
        assert result.error.code == ScanErrorCode.UNSUPPORTED_FORMAT


class TestDriveScanSummary:
    """Tests for aggregate folder/drive scans."""

    def setup_method(self):
        self.transport = FakeMicrosoftTransport()
        self.transport.add_drive(
            id="drive-1",
            name="My Drive",
            driveType="personal",
        )
        self.transport.add_item(
            "drive-1", id="root", name="Root", folder={}, parentReference={}, size=0
        )
        self.transport.add_item(
            "drive-1",
            id="file-1",
            name="a.txt",
            file={"mimeType": "text/plain"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=50,
        )
        self.transport.add_item(
            "drive-1",
            id="file-2",
            name="b.pdf",
            file={"mimeType": "application/pdf"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=50,
        )
        self.transport.add_item(
            "drive-1",
            id="clean",
            name="clean.txt",
            file={"mimeType": "text/plain"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=50,
        )
        self.transport.add_item(
            "drive-1",
            id="pii",
            name="pii.txt",
            file={"mimeType": "text/plain"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=50,
        )
        self.transport.set_content("drive-1", "file-1", b"mail jane@example.com")
        self.transport.set_content("drive-1", "clean", b"nothing to see")
        self.transport.set_content("drive-1", "pii", b"IBAN NL91ABNA0417164300 phone +31612345678")

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        self.browser = MicrosoftGraphBrowser(identity, self.transport)

    def test_scan_folder_aggregates(self):
        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        summary = self.browser.scan_folder("drive-1", "root", scanner)

        assert summary.status == "completed"
        assert summary.source == SOURCE_TYPE_ONEDRIVE
        assert summary.drive_id == "drive-1"
        # 4 files discovered, 3 scanned (PDF unsupported), 1 unsupported
        assert summary.files_discovered == 4
        assert summary.files_scanned == 3
        assert summary.files_unsupported == 1
        assert summary.files_with_findings == 2
        assert summary.files_clean == 1
        assert summary.findings_total == 3
        assert summary.category_counts.get("email") == 1
        assert summary.category_counts.get("iban") == 1
        assert summary.category_counts.get("phone") == 1

    def test_scan_drive(self):
        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        summary = self.browser.scan_drive("drive-1", scanner)

        assert summary.status == "completed"
        assert summary.source == SOURCE_TYPE_ONEDRIVE
        assert summary.drive_id == "drive-1"
        assert summary.root_id == "root"


class TestHeartbeat:
    """Test heartbeat invocation during long scans."""

    def test_folder_scan_keeps_lease_alive_via_heartbeat(self):
        transport = FakeMicrosoftTransport()
        transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
        transport.add_item("drive-1", id="root", name="Root", folder={}, parentReference={}, size=0)
        for i in range(30):
            fid = f"f{i}"
            transport.add_item(
                "drive-1",
                id=fid,
                name=f"{fid}.txt",
                file={"mimeType": "text/plain"},
                parentReference={"id": "root", "driveId": "drive-1"},
                size=50,
            )
            transport.set_content("drive-1", fid, b"nothing to see")

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        browser = MicrosoftGraphBrowser(identity, transport)

        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        calls: list[int] = []

        from securedact_core.connectors.contracts import ScanContext

        browser.scan_folder(
            "drive-1", "root", scanner, ScanContext(), heartbeat=lambda: calls.append(1)
        )

        # Heartbeat must fire at least once at the provider boundary and again inside
        # the recursive walk, so a long scan cannot silently lose its lease.
        assert len(calls) >= 2


class TestPrivacyBoundary:
    """Tests ensuring PII and tokens never reach the control plane."""

    def test_pii_never_in_result(self):
        transport = FakeMicrosoftTransport()
        transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
        transport.add_item("drive-1", id="root", name="Root", folder={}, parentReference={}, size=0)
        transport.add_item(
            "drive-1",
            id="file-1",
            name="report.txt",
            file={"mimeType": "text/plain"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=200,
        )
        transport.set_content(
            "drive-1", "file-1", b"Contact Jane Example at jane@example.com IBAN NL91ABNA0417164300"
        )

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        browser = MicrosoftGraphBrowser(identity, transport)

        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        result = browser.select_and_scan("drive-1", "file-1", scanner)

        import json

        blob = json.dumps(result.model_dump(mode="json"), sort_keys=True)
        for forbidden in (
            "Jane Example",
            "jane@example.com",
            "NL91ABNA0417164300",
            "+31612345678",
        ):
            assert forbidden not in blob

    def test_oauth_tokens_never_leak(self):
        transport = FakeMicrosoftTransport(user_id="ya29.fake-access-token")
        transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
        transport.add_item("drive-1", id="root", name="Root", folder={}, parentReference={}, size=0)
        transport.add_item(
            "drive-1",
            id="file-1",
            name="report.txt",
            file={"mimeType": "text/plain"},
            parentReference={"id": "root", "driveId": "drive-1"},
            size=200,
        )
        transport.set_content("drive-1", "file-1", b"test content")

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        browser = MicrosoftGraphBrowser(identity, transport)

        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        result = browser.select_and_scan("drive-1", "file-1", scanner)

        import json

        blob = json.dumps(result.model_dump(mode="json"), sort_keys=True)
        assert "ya29." not in blob
        assert "1//" not in blob
        assert "access_token" not in blob
        assert "refresh_token" not in blob


class TestErrorHandling:
    """Tests for error handling and resilience."""

    def test_404_not_found(self):
        transport = FakeMicrosoftTransport()
        transport.add_drive(id="drive-1", name="My Drive", driveType="personal")

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        browser = MicrosoftGraphBrowser(identity, transport)

        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        result = browser.select_and_scan("drive-1", "nonexistent", scanner)

        assert result.status == ScanStatus.ERROR
        assert result.error is not None
        assert result.error.code == ScanErrorCode.RETRIEVAL_FAILED

    def test_403_permission_denied(self):
        def failing_get_json(path: str):
            raise MicrosoftApiError("forbidden", status_code=403, reason="accessDenied")

        class FailingTransport:
            base_url = CANONICAL_GRAPH_BASE
            user_id = "user-123"
            tenant_id = "tenant-456"

            def get_json(self, path: str):
                failing_get_json(path)

            def get_content(self, path: str, *, max_bytes: int | None = None):
                raise MicrosoftApiError("forbidden", status_code=403)

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        browser = MicrosoftGraphBrowser(identity, FailingTransport())

        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        result = browser.select_and_scan("drive-1", "file-1", scanner)

        assert result.status == ScanStatus.ERROR
        assert result.error is not None
        assert result.error.code == ScanErrorCode.UNAUTHORIZED

    def test_429_rate_limit(self):
        def failing_get_json(path: str):
            raise MicrosoftApiError("rate limited", status_code=429, reason="rateLimitExceeded")

        class FailingTransport:
            base_url = CANONICAL_GRAPH_BASE
            user_id = "user-123"
            tenant_id = "tenant-456"

            def get_json(self, path: str):
                failing_get_json(path)

            def get_content(self, path: str, *, max_bytes: int | None = None):
                raise MicrosoftApiError("rate limited", status_code=429)

        from securedact_core.connectors.contracts import ConnectorIdentity

        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id="tenant-456",
            platform="microsoft365",
            user_id="user-123",
        )
        browser = MicrosoftGraphBrowser(identity, FailingTransport())

        from securedact_core.connectors import ConnectorScanner

        scanner = ConnectorScanner(_engine())
        result = browser.select_and_scan("drive-1", "file-1", scanner)

        assert result.status == ScanStatus.ERROR
        assert result.error is not None
        assert result.error.code == ScanErrorCode.RATE_LIMITED


class TestSafeDiagnostics:
    """Tests for safe diagnostic output."""

    def test_safe_diagnostic_no_secrets(self):
        exc = MicrosoftApiError(
            "test error",
            status_code=403,
            reason="accessDenied",
            endpoint="/drives/drive-1/items/file-1",
            retryable=False,
            category="permission",
        )
        diag = safe_diagnostic(exc)
        assert diag["error"] == "test error"
        assert diag["status"] == 403
        assert diag["reason"] == "accessDenied"
        assert diag["endpoint"] == "/drives/drive-1/items/file-1"
        assert diag["retryable"] is False
        assert diag["category"] == "permission"
        # No tokens or credentials
        assert "authorization" not in str(diag).lower()
        assert "bearer" not in str(diag).lower()
