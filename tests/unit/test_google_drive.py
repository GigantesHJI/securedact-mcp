# SPDX-License-Identifier: Apache-2.0
"""Tests for the Google Drive read-only connector (GWS-110).

All Google API behavior is faked through :class:`MockGoogleTransport` -- no live
Google account, SDK, or network is used. The tests prove that Google content is
fed through the *real* SecuRedact detection/policy/audit pipeline and that the
connector stays read-only and least-privilege.
"""

from __future__ import annotations

import re
import sys
from urllib.parse import unquote

import pytest

from securedact_core import SecuredactEngine
from securedact_core.connectors import ConnectorScanner, ScanContext
from securedact_core.connectors.contracts import ConnectorCapability, ConnectorIdentity
from securedact_core.connectors.google import (
    CANONICAL_DRIVE_BASE,
    DRIVE_READONLY_SCOPE,
    GoogleApiError,
    GoogleAuthError,
    GoogleDriveBrowser,
    build_drive_scopes,
    default_connector_scopes,
    has_write_scope,
    safe_diagnostic,
)
from securedact_core.connectors.scan import ScanErrorCode, ScanStatus
from securedact_core.production import build_production_engine

DOCS = "application/vnd.google-apps.document"
SHEETS = "application/vnd.google-apps.spreadsheet"
SLIDES = "application/vnd.google-apps.presentation"
FOLDER = "application/vnd.google-apps.folder"
SHORTCUT = "application/vnd.google-apps.shortcut"


def _engine() -> SecuredactEngine:
    return SecuredactEngine(build_production_engine(require_contextual=False))


def _identity(tenant_id: str = "user-123") -> ConnectorIdentity:
    return ConnectorIdentity(
        org_id="google",
        integration_id="google_workspace",
        tenant_id=tenant_id,
        platform="google_workspace",
        user_id=tenant_id,
    )


class MockGoogleTransport:
    """In-memory Google Drive v3 double implementing :class:`GoogleDriveTransport`."""

    def __init__(self, user_id: str = "user-123") -> None:
        self.base_url = CANONICAL_DRIVE_BASE
        self.user_id = user_id
        self.drives: list[dict] = []
        self.by_id: dict[str, dict] = {}
        self.exports: dict[str, bytes] = {}
        self.media: dict[str, bytes] = {}
        self.fail: dict[str, int] = {}
        self.fail_content: dict[str, int] = {}
        self.paginate = False
        self.calls: list[tuple[str, str]] = []

    def add_file(self, **kwargs: object) -> dict:
        item = dict(kwargs)
        self.by_id[item["id"]] = item
        return item

    def get_json(self, path: str) -> dict:
        self.calls.append(("json", path))
        path = unquote(path)
        if path.startswith("drives"):
            return {"drives": self.drives}
        m = re.match(r"files/([^?]+)\?fields=", path)
        if m:
            fid = m.group(1)
            if fid in self.fail:
                raise GoogleApiError("metadata failed", status_code=self.fail[fid])
            item = self.by_id.get(fid)
            if item is None:
                raise GoogleApiError("not found", status_code=404)
            return item
        if path.startswith("files?q="):
            folder_id = None
            mm = re.search(r"'([^']+)' in parents", path)
            if mm and mm.group(1) != "root":
                folder_id = mm.group(1)
            drive_id = None
            dm = re.search(r"driveId=([^&]+)", path)
            if dm:
                drive_id = dm.group(1)
            items = self._children(folder_id, drive_id)
            if self.paginate and len(items) > 1:
                if "pageToken=" in path:
                    return {"files": items[1:]}
                return {"files": items[:1], "nextPageToken": "tok"}
            return {"files": items}
        raise GoogleApiError("unexpected path", status_code=400)

    def _children(self, folder_id: str | None, drive_id: str | None) -> list[dict]:
        out: list[dict] = []
        for item in self.by_id.values():
            if item.get("trashed"):
                continue
            parents = item.get("parents") or []
            if drive_id is not None and item.get("driveId") != drive_id:
                continue
            if folder_id is None:
                if "root" in parents or (not parents and drive_id is None):
                    out.append(item)
            elif folder_id in parents:
                out.append(item)
        return out

    def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
        self.calls.append(("content", path))
        if "/export?mimeType=" in path:
            fid = re.match(r"files/([^/]+)/export", path).group(1)
            if fid in self.fail_content:
                raise GoogleApiError("export failed", status_code=self.fail_content[fid])
            data = self.exports.get(fid)
        elif "alt=media" in path:
            fid = re.match(r"files/([^?]+)\?alt=media", path).group(1)
            if fid in self.fail_content:
                raise GoogleApiError("media failed", status_code=self.fail_content[fid])
            data = self.media.get(fid)
        else:
            raise GoogleApiError("unexpected content path", status_code=400)
        if data is None:
            raise GoogleApiError("not found", status_code=404)
        if max_bytes is not None and len(data) > max_bytes:
            raise GoogleApiError("too large", status_code=413)
        return data


def _browser(transport: MockGoogleTransport, **kw) -> GoogleDriveBrowser:
    return GoogleDriveBrowser(_identity(), transport, **kw)


# --- Scope / auth -------------------------------------------------------------


def test_default_scopes_are_read_only() -> None:
    assert default_connector_scopes() == [DRIVE_READONLY_SCOPE]
    assert "https://www.googleapis.com/auth/drive" not in default_connector_scopes()
    assert "https://www.googleapis.com/auth/drive.file" not in default_connector_scopes()


def test_capability_driven_scope_construction() -> None:
    assert build_drive_scopes({ConnectorCapability.READ}) == [DRIVE_READONLY_SCOPE]
    assert build_drive_scopes({ConnectorCapability.LIST, ConnectorCapability.SCAN}) == [
        DRIVE_READONLY_SCOPE
    ]
    assert not has_write_scope(build_drive_scopes({ConnectorCapability.READ}))


def test_has_write_scope_detects_expanded_scopes() -> None:
    assert has_write_scope(["https://www.googleapis.com/auth/drive"])
    assert has_write_scope(["https://www.googleapis.com/auth/drive.file"])
    assert not has_write_scope([DRIVE_READONLY_SCOPE])


def test_core_import_does_not_pull_google_sdk() -> None:
    import securedact_core.connectors.google as g

    assert g is not None
    assert "google" not in sys.modules
    assert "google_auth_oauthlib" not in sys.modules


def test_fixed_drive_host_is_enforced() -> None:
    class WrongHost:
        @property
        def base_url(self) -> str:
            return "https://evil.example.com/drive/v3"

        @property
        def user_id(self) -> str:
            return "x"

        def get_json(self, path: str) -> dict:
            raise AssertionError("should not be called")

        def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
            raise AssertionError("should not be called")

    with pytest.raises(GoogleApiError):
        _browser(WrongHost())  # type: ignore[arg-type]


# --- Discovery ----------------------------------------------------------------


def test_list_my_drive_root() -> None:
    t = MockGoogleTransport()
    t.add_file(id="f1", name="notes.txt", mimeType="text/plain", parents=["root"], size=10)
    t.add_file(id="f2", name="Folder", mimeType=FOLDER, parents=["root"])
    browser = _browser(t)
    items = browser.list_children()
    assert {i.file_id for i in items} == {"f1", "f2"}


def test_pagination_is_bounded_and_complete() -> None:
    t = MockGoogleTransport()
    t.paginate = True
    for i in range(3):
        t.add_file(id=f"f{i}", name=f"f{i}.txt", mimeType="text/plain", parents=["root"])
    browser = _browser(t, max_pages=5)
    items = browser.list_children()
    assert len(items) == 3


def test_nested_folders() -> None:
    t = MockGoogleTransport()
    t.add_file(id="top", name="Top", mimeType=FOLDER, parents=["root"])
    t.add_file(id="mid", name="Mid", mimeType=FOLDER, parents=["top"])
    t.add_file(id="leaf", name="leaf.txt", mimeType="text/plain", parents=["mid"])
    browser = _browser(t)
    top_children = browser.list_children("top")
    assert {i.file_id for i in top_children} == {"mid"}
    mid_children = browser.list_children("mid")
    assert {i.file_id for i in mid_children} == {"leaf"}


def test_shared_drives_discovery_and_listing() -> None:
    t = MockGoogleTransport()
    t.drives = [{"id": "d1", "name": "Team Drive"}]
    t.add_file(id="s1", name="shared.txt", mimeType="text/plain", parents=["root"], driveId="d1")
    browser = _browser(t)
    drives = browser.list_shared_drives()
    assert drives[0].drive_id == "d1"
    children = browser.list_children(drive_id="d1")
    assert {i.file_id for i in children} == {"s1"}
    assert children[0].is_shared_drive


def test_empty_drive_returns_no_items() -> None:
    t = MockGoogleTransport()
    browser = _browser(t)
    assert browser.list_children() == []
    assert browser.list_shared_drives() == []


def test_inaccessible_file_maps_to_safe_error() -> None:
    t = MockGoogleTransport()
    t.add_file(id="secret", name="secret.txt", mimeType="text/plain", parents=["root"])
    t.fail["secret"] = 403
    browser = _browser(t)
    result = browser.select_and_scan("secret", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.ERROR
    assert result.error is not None
    assert result.error.code == ScanErrorCode.UNAUTHORIZED


def test_trashed_items_excluded_from_listing() -> None:
    t = MockGoogleTransport()
    t.add_file(id="live", name="live.txt", mimeType="text/plain", parents=["root"])
    t.add_file(id="gone", name="gone.txt", mimeType="text/plain", parents=["root"], trashed=True)
    browser = _browser(t)
    assert {i.file_id for i in browser.list_children()} == {"live"}


def test_shortcut_resolves_once_and_avoids_duplicate_scan() -> None:
    t = MockGoogleTransport()
    t.add_file(id="real", name="real.txt", mimeType="text/plain", parents=["root"], size=20)
    t.add_file(
        id="sc1",
        name="link1",
        mimeType=SHORTCUT,
        parents=["root"],
        shortcutDetails={"targetId": "real"},
    )
    t.add_file(
        id="sc2",
        name="link2",
        mimeType=SHORTCUT,
        parents=["root"],
        shortcutDetails={"targetId": "real"},
    )
    t.media["real"] = b"jan@example.test"
    browser = _browser(t)
    summary = browser.scan_drive(ConnectorScanner(_engine()), ScanContext())
    # real + two shortcuts, but the underlying file is scanned only once.
    assert summary.files_discovered == 3
    assert summary.files_scanned == 1
    assert summary.files_with_findings == 1


# --- Content / detection -------------------------------------------------------


def test_scan_google_doc_through_real_engine() -> None:
    t = MockGoogleTransport()
    t.add_file(id="doc1", name="Report", mimeType=DOCS, parents=["root"])
    t.exports["doc1"] = b"Contact jan@example.test about the contract"
    browser = _browser(t)
    result = browser.select_and_scan("doc1", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.COMPLETED
    assert result.counts.get("email", 0) >= 1


def test_scan_google_sheet_preserves_structure() -> None:
    t = MockGoogleTransport()
    t.add_file(id="sh1", name="Roster", mimeType=SHEETS, parents=["root"])
    t.exports["sh1"] = (
        b"Name,Email,Medical condition\nJan,jan@example.test,asthma\nBo,bob@example.test,null"
    )
    browser = _browser(t)
    result = browser.select_and_scan("sh1", ConnectorScanner(_engine()), ScanContext())
    # Health column ("asthma") is a special category, so the policy may require
    # review rather than silently completing -- both are valid detections.
    assert result.status in (ScanStatus.COMPLETED, ScanStatus.REVIEW_REQUIRED)
    assert result.counts.get("email", 0) >= 2


def test_scan_google_slides() -> None:
    t = MockGoogleTransport()
    t.add_file(id="sl1", name="Deck", mimeType=SLIDES, parents=["root"])
    t.exports["sl1"] = b"Slide 1 title\nContact win@example.test"
    browser = _browser(t)
    result = browser.select_and_scan("sl1", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.COMPLETED
    assert result.counts.get("email", 0) >= 1


def test_scan_ordinary_text_file() -> None:
    t = MockGoogleTransport()
    t.add_file(id="t1", name="notes.txt", mimeType="text/plain", parents=["root"], size=30)
    t.media["t1"] = b"Reach mia@example.test for details"
    browser = _browser(t)
    result = browser.select_and_scan("t1", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.COMPLETED
    assert result.counts.get("email", 0) >= 1


def test_unsupported_mime_reported_cleanly() -> None:
    t = MockGoogleTransport()
    t.add_file(id="pdf1", name="scan.pdf", mimeType="application/pdf", parents=["root"], size=100)
    browser = _browser(t)
    result = browser.select_and_scan("pdf1", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.ERROR
    assert result.error is not None
    assert result.error.code == ScanErrorCode.UNSUPPORTED_FORMAT


def test_zero_byte_file_handled_without_crash() -> None:
    t = MockGoogleTransport()
    t.add_file(id="z", name="empty.txt", mimeType="text/plain", parents=["root"], size=0)
    t.media["z"] = b""
    browser = _browser(t)
    result = browser.select_and_scan("z", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.COMPLETED
    assert result.findings == []


def test_oversized_content_blocked_not_truncated() -> None:
    t = MockGoogleTransport()
    t.add_file(id="big", name="big.txt", mimeType="text/plain", parents=["root"])
    t.media["big"] = ("x" * 1_500_000).encode()
    browser = _browser(t)
    result = browser.select_and_scan("big", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.ERROR
    assert result.error is not None
    assert result.error.code == ScanErrorCode.CONTENT_TOO_LARGE


def test_secret_content_is_blocked_by_policy() -> None:
    t = MockGoogleTransport()
    t.add_file(id="sec", name="config.txt", mimeType="text/plain", parents=["root"])
    t.media["sec"] = b"Authorization: Bearer syntheticTokenValue123456"
    browser = _browser(t)
    result = browser.select_and_scan("sec", ConnectorScanner(_engine()), ScanContext())
    assert result.status == ScanStatus.BLOCKED


# --- Bulk scans ----------------------------------------------------------------


def test_scan_folder_aggregate_counts() -> None:
    t = MockGoogleTransport()
    t.add_file(id="folder", name="Folder", mimeType=FOLDER, parents=["root"])
    t.add_file(id="a", name="a.txt", mimeType="text/plain", parents=["folder"], size=10)
    t.add_file(id="b", name="b.pdf", mimeType="application/pdf", parents=["folder"], size=10)
    t.media["a"] = b"mail jan@example.test"
    browser = _browser(t)
    summary = browser.scan_folder("folder", ConnectorScanner(_engine()), ScanContext())
    assert summary.files_discovered == 2
    assert summary.files_scanned == 1
    assert summary.files_with_findings == 1
    assert summary.files_unsupported == 1
    assert summary.findings_total >= 1


def test_scan_drive_aggregate_my_drive() -> None:
    t = MockGoogleTransport()
    t.add_file(id="a", name="a.txt", mimeType="text/plain", parents=["root"], size=10)
    t.add_file(id="b", name="b.txt", mimeType="text/plain", parents=["root"], size=10)
    t.media["a"] = b"jan@example.test"
    t.media["b"] = b"no findings here"
    browser = _browser(t)
    summary = browser.scan_drive(ConnectorScanner(_engine()), ScanContext())
    assert summary.files_discovered == 2
    assert summary.files_scanned == 2
    assert summary.files_with_findings == 1
    assert summary.files_clean == 1


def test_scan_shared_drive_propagates_drive_id() -> None:
    t = MockGoogleTransport()
    t.drives = [{"id": "d9", "name": "Legal"}]
    t.add_file(id="x", name="x.txt", mimeType="text/plain", parents=["root"], driveId="d9", size=10)
    t.media["x"] = b"lean@example.test"
    browser = _browser(t)
    summary = browser.scan_drive(ConnectorScanner(_engine()), ScanContext(), drive_id="d9")
    assert summary.drive_id == "d9"
    assert summary.files_scanned == 1


# --- Audit / firewall ----------------------------------------------------------


def test_audit_events_emitted_and_free_of_tokens() -> None:
    from securedact_core.audit import capture_audit_events

    t = MockGoogleTransport()
    t.add_file(id="doc", name="Report", mimeType=DOCS, parents=["root"])
    t.exports["doc"] = b"jan@example.test"
    browser = _browser(t)
    with capture_audit_events() as collector:
        browser.select_and_scan("doc", ConnectorScanner(_engine()), ScanContext())
    events = collector.serialized()
    assert any(e["event_type"] == "CONNECTOR_RESOURCE_ACCESSED" for e in events)
    assert any(e["event_type"] == "CONNECTOR_SCAN_STARTED" for e in events)
    # No token/secret material can appear in serialized audit output.
    blob = str(events)
    assert "Bearer" not in blob
    assert "refresh_token" not in blob


def test_google_read_audit_is_classified_as_network_read() -> None:
    from securedact_core.audit import AuditEventType, capture_audit_events

    t = MockGoogleTransport()
    t.add_file(id="doc", name="Report", mimeType=DOCS, parents=["root"])
    t.exports["doc"] = b"jan@example.test"
    browser = _browser(t)
    with capture_audit_events() as collector:
        browser.select_and_scan("doc", ConnectorScanner(_engine()), ScanContext())
    accessed = [
        e
        for e in collector.serialized()
        if e["event_type"] == AuditEventType.CONNECTOR_RESOURCE_ACCESSED.value
    ]
    assert accessed
    assert accessed[0]["operation"] == "network_read"


# --- Control-plane config (read-only enforcement) -----------------------------


def test_google_disabled_by_default(monkeypatch) -> None:
    from securedact_mcp.connectors.google.config import GoogleConfigError, load_google_config

    monkeypatch.delenv("SECUREDACT_GOOGLE_ENABLED", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_SCOPES", raising=False)
    config = load_google_config()
    assert config.enabled is False
    with pytest.raises(GoogleConfigError):
        load_google_config(require_enabled=True)


def test_write_scope_configuration_fails_closed(monkeypatch) -> None:
    from securedact_mcp.connectors.google.config import GoogleConfigError, load_google_config

    monkeypatch.setenv("SECUREDACT_GOOGLE_ENABLED", "1")
    monkeypatch.setenv(
        "SECUREDACT_GOOGLE_SCOPES",
        "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive",
    )
    with pytest.raises(GoogleConfigError):
        load_google_config()


def test_credential_store_encrypts_at_rest(tmp_path) -> None:
    from securedact_mcp.connectors.google.storage import GoogleCredentialStore

    store = GoogleCredentialStore(tmp_path / "tok.enc", tmp_path / "tok.key")
    token = {"token": "sensitive-value", "refresh_token": "also-sensitive"}
    store.save_token(token)
    # The on-disk file must not contain the raw token value.
    raw = (tmp_path / "tok.enc").read_text(encoding="utf-8", errors="ignore")
    assert "sensitive-value" not in raw
    assert store.load_token() == token
    store.delete_token()
    assert store.load_token() is None


# --- Field-selection correctness (GWS-110 live root cause) --------------------
#
# The real Drive API v3 rejects a bare ``fields=id,name,...`` for ``files.list``
# ("Invalid field selection id") because the response is a collection and the
# field mask must be wrapped as ``files(...)``. Likewise ``drives.list`` returns
# the collection under ``drives`` (not ``items``). These tests pin the exact
# request shape so the connector keeps talking to the real API.


def test_files_list_fields_are_collection_wrapped() -> None:
    t = MockGoogleTransport()
    t.add_file(id="f1", name="a.txt", mimeType="text/plain", parents=["root"])
    browser = _browser(t)
    browser.list_children()
    list_calls = [p for kind, p in t.calls if kind == "json" and p.startswith("files?")]
    assert list_calls, "expected a files.list call"
    # Field selection must be wrapped as files(...) -- the connector percent
    # encodes it, so the literal wire form is ``fields=files%28...``.
    assert "fields=files%28" in list_calls[0]
    # The bare (unwrapped) form must never be sent to files.list.
    assert "fields=id%2C" not in list_calls[0]


def test_files_get_uses_bare_fields_not_wrapped() -> None:
    t = MockGoogleTransport()
    t.add_file(id="doc1", name="Report", mimeType="text/plain", parents=["root"])
    browser = _browser(t)
    browser.resolve_resource("doc1")
    get_calls = [p for kind, p in t.calls if kind == "json" and p.startswith("files/doc1")]
    assert get_calls, "expected a files.get call"
    # A single-file get returns a file object, so fields must NOT be wrapped.
    assert "fields=files(" not in get_calls[0]
    assert "fields=id" in get_calls[0]


def test_shared_drives_fields_use_drives_collection() -> None:
    t = MockGoogleTransport()
    t.drives = [{"id": "d1", "name": "Team Drive"}]
    browser = _browser(t)
    browser.list_shared_drives()
    drives_calls = [p for kind, p in t.calls if kind == "json" and p.startswith("drives")]
    assert drives_calls, "expected a drives.list call"
    assert "fields=drives%28" in drives_calls[0]


def test_my_drive_listing_does_not_send_shared_drive_params() -> None:
    t = MockGoogleTransport()
    t.add_file(id="f1", name="a.txt", mimeType="text/plain", parents=["root"])
    browser = _browser(t)
    browser.list_children()
    list_calls = [p for kind, p in t.calls if kind == "json" and p.startswith("files?")]
    assert "driveId=" not in list_calls[0]
    assert "corpora=" not in list_calls[0]


# --- Safe provider diagnostics ------------------------------------------------


def test_safe_diagnostic_exposes_metadata_without_secrets() -> None:
    exc = GoogleApiError(
        "Google Drive request failed",
        status_code=403,
        reason="insufficientPermissions",
        endpoint="files/secret-id?fields=...",
        retryable=False,
        category="permission",
    )
    diag = safe_diagnostic(exc)
    assert diag["error"] == "Google Drive request failed"
    assert diag["status"] == 403
    assert diag["reason"] == "insufficientPermissions"
    assert diag["retryable"] is False
    assert diag["category"] == "permission"
    # The endpoint must have its query string stripped (no id/params leak).
    assert diag["endpoint"] == "files/secret-id"


def test_auth_error_is_a_google_api_error() -> None:
    assert issubclass(GoogleAuthError, GoogleApiError)
    exc = GoogleAuthError("boom", status_code=401, category="auth")
    assert isinstance(exc, GoogleApiError)
    assert safe_diagnostic(exc)["category"] == "auth"


def test_safe_diagnostic_omits_unspecified_fields() -> None:
    diag = safe_diagnostic(GoogleApiError("plain failure"))
    assert diag == {"error": "plain failure"}
    assert "status" not in diag
    assert "reason" not in diag
