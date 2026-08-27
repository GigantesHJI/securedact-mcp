# SPDX-License-Identifier: Apache-2.0
"""Google Drive / Google Workspace read-only connector (GWS-110).

This is the *core-side, transport-agnostic* implementation of the Google Drive
browsing + scanning milestone. It deliberately contains **no Google SDK import**
(``google-auth`` / ``google-api-python-client`` / ``google-auth-oauthlib`` are
never referenced here) so the privacy core stays Google-free, mirroring the
Microsoft :mod:`securedact_core.connectors.microsoft` design.

The browser consumes Google Drive **v3 REST JSON** through an injected
:class:`GoogleDriveTransport`. The concrete transport -- which owns the OAuth
token, HTTPS session, host pinning and the verified user identity -- lives in
the control plane (``securedact_mcp.connectors.google``) and is injected here.
That keeps the security/data plane (``securedact_core``) reusable and unit
testable with a mock transport.

Scope (GWS-110, exact):
  * ``GET /drives`` (Shared Drive discovery)
  * ``GET /files`` (My Drive root + folder children, with corpora/driveId)
  * ``GET /files/{id}`` (metadata)
  * ``GET /files/{id}?alt=media`` (binary/text download)
  * ``GET /files/{id}/export?mimeType=...`` (Google Docs/Sheets/Slides export)

Security invariants:
  * Fixed Drive host (transport ``base_url`` must equal the canonical v3 base).
  * Least-privilege scope construction: read-only scanning requests
    ``drive.readonly`` only. No write scope (``drive``, ``drive.file``) is ever
    requested by this milestone.
  * Server-resolved identity: ``org_id``/``tenant_id`` come from the
    server-resolved :class:`ConnectorIdentity`, never from browser input.
  * Identifier validation: every Google id used to build a path is validated.
  * Shortcuts are resolved to their target exactly once; the same underlying
    file is never scanned twice.
  * Trashed items are excluded by default.
  * No raw resource ids or tokens are written to logs.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field

from ...audit import (
    AuditEventType,
    build_audit_event,
    emit_audit_event,
)
from ...firewall import MAX_INSPECTION_TEXT_CHARS
from ..base import ConnectorScanner, extract_text, is_text_format
from ..contracts import (
    ConnectorCapability,
    ConnectorIdentity,
    ConnectorResource,
    NormalizedContent,
    ResourceKind,
    ScanContext,
    validate_resource_identifier,
)
from ..scan import ScanError, ScanErrorCode, ScanResult, ScanSeverity, ScanStatus

logger = logging.getLogger(__name__)

DRIVE_HOST = "https://www.googleapis.com"
DRIVE_API_VERSION = "v3"
CANONICAL_DRIVE_BASE = f"{DRIVE_HOST}/drive/{DRIVE_API_VERSION}"

GOOGLE_WORKSPACE_PLATFORM = "google_workspace"
SOURCE_TYPE_DRIVE = "google_drive"
SOURCE_TYPE_SHARED_DRIVE = "google_shared_drive"
SOURCE_TYPE_MY_DRIVE = "google_my_drive"

# Google Workspace MIME types (native, exportable).
GOOGLE_DOCS_MIME = "application/vnd.google-apps.document"
GOOGLE_SHEETS_MIME = "application/vnd.google-apps.spreadsheet"
GOOGLE_SLIDES_MIME = "application/vnd.google-apps.presentation"
GOOGLE_FOLDER_MIME = "application/vnd.google-apps.folder"
GOOGLE_SHORTCUT_MIME = "application/vnd.google-apps.shortcut"

# Drive export target MIME types. We deliberately use Drive *export* (covered by
# the ``drive.readonly`` scope) rather than the separate Docs/Sheets/Slides
# read-only scopes, so this milestone requests no redundant scopes.
DOCS_EXPORT_MIME = "text/plain"
SLIDES_EXPORT_MIME = "text/plain"
SHEETS_EXPORT_MIME = "text/csv"

# OAuth scopes (least privilege for this milestone).
DRIVE_READONLY_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
# Documented for the future, explicitly NOT requested by GWS-110:
_DRIVE_FULL_SCOPE = "https://www.googleapis.com/auth/drive"
_DRIVE_FILE_SCOPE = "https://www.googleapis.com/auth/drive.file"
_SPREADSHEETS_READONLY_SCOPE = "https://www.googleapis.com/auth/spreadsheets.readonly"

# Bounds that keep a single browse/scan operation from walking unboundedly
# (DoS / throttling containment).
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_DEPTH = 20
DEFAULT_PAGE_SIZE = 200
DEFAULT_MAX_FILES = 1000
# Invoke the execution-lease heartbeat at most once per this many scanned files
# during a recursive folder/Drive walk (no concurrent threads are used).
_HEARTBEAT_EVERY_FILES = 25
# Remote retrieval uses a memory guard larger than the inspection cap so the
# exact character limit (FW-041) is enforced by :class:`ConnectorScanner`, never
# by an unbounded download. The scanner rejects content above
# ``MAX_INSPECTION_TEXT_CHARS`` rather than truncating it.
DEFAULT_MAX_DOWNLOAD_BYTES = MAX_INSPECTION_TEXT_CHARS * 4

_SELECT_FIELDS = "id,name,mimeType,size,parents,driveId,webViewLink,trashed,shortcutDetails"


class GoogleApiError(Exception):
    """Raised when the Drive transport returns an unexpected/error response.

    Carries *safe* diagnostic metadata only. No token, Authorization header,
    client secret, or credential material is ever stored on the exception.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        reason: str | None = None,
        endpoint: str | None = None,
        retryable: bool | None = None,
        category: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.reason = reason
        self.endpoint = endpoint
        self.retryable = retryable
        self.category = category


class GoogleAuthError(GoogleApiError):
    """Raised when credentials are missing, revoked, expired, or insufficient."""


@runtime_checkable
class GoogleDriveTransport(Protocol):
    """Minimal, host-pinned Drive read surface injected by the control plane.

    Implementations must talk only to ``https://www.googleapis.com/drive/v3`` and
    must surface the verified user identity (``sub``/email from the resolved
    token) so the browser can attribute operations. No Google SDK is required to
    satisfy this protocol -- a test double can implement it directly.
    """

    @property
    def base_url(self) -> str:
        """The canonical Drive base URL this transport targets (v3)."""
        ...

    @property
    def user_id(self) -> str:
        """The verified Google user identity (``sub``) of the resolved token."""
        ...

    def get_json(self, path: str) -> dict[str, Any]:
        """Perform a delegated ``GET`` against ``<base_url>/<path>`` and return JSON."""
        ...

    def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
        """Perform a delegated ``GET`` against ``<base_url>/<path>`` and return bytes.

        Implementations must raise :class:`GoogleApiError` on HTTP errors and may
        raise a bounded error if the response exceeds ``max_bytes`` rather than
        buffering it all in memory.
        """
        ...


class GoogleDriveItem(BaseModel):
    """A normalized view of a Drive ``file`` (file, folder, or shortcut)."""

    model_config = ConfigDict(extra="forbid")

    file_id: str
    name: str
    is_folder: bool
    mime_type: str | None = None
    size: int | None = None
    drive_id: str | None = None
    parent_id: str | None = None
    web_url: str | None = None
    source_type: str = SOURCE_TYPE_DRIVE
    is_shared_drive: bool = False
    is_shortcut: bool = False
    shortcut_target_id: str | None = None
    trashed: bool = False


class SharedDrive(BaseModel):
    """A discovered Shared Drive (Workspace only)."""

    model_config = ConfigDict(extra="forbid")

    drive_id: str
    name: str


class DriveScanSummary(BaseModel):
    """Aggregate outcome of a folder/Drive scan (GWS-110)."""

    model_config = ConfigDict(extra="forbid")

    status: str = "completed"
    source: str
    drive_id: str | None = None
    root_id: str | None = None
    files_discovered: int = 0
    files_scanned: int = 0
    files_with_findings: int = 0
    files_clean: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    files_unsupported: int = 0
    findings_total: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)
    errors: list[ScanError] = Field(default_factory=list)


def build_drive_scopes(capabilities: set[ConnectorCapability]) -> list[str]:
    """Return the minimum Drive scopes required by the declared capabilities.

    Read-only scanning needs only ``drive.readonly``. Write capabilities would add
    ``drive`` -- but this milestone declares read/list/scan only and never
    requests a write scope. Capability-driven so a future write milestone can add
    exactly the scope it needs rather than one permanently oversized set.
    """

    scopes: set[str] = set()
    if {
        ConnectorCapability.READ,
        ConnectorCapability.LIST,
        ConnectorCapability.SCAN,
    } & capabilities:
        scopes.add(DRIVE_READONLY_SCOPE)
    if ConnectorCapability.WRITE in capabilities:
        # Documented, not exercised by GWS-110.
        scopes.add(_DRIVE_FULL_SCOPE)
    return sorted(scopes)


def default_connector_scopes() -> list[str]:
    """The least-privilege default scope set for the GWS-110 connector."""

    return build_drive_scopes(
        {ConnectorCapability.READ, ConnectorCapability.LIST, ConnectorCapability.SCAN}
    )


def has_write_scope(scopes: list[str]) -> bool:
    """Return whether any write/expanded Drive scope is present.

    Used to fail closed if a configuration requests more than read-only.
    """

    return bool({_DRIVE_FULL_SCOPE, _DRIVE_FILE_SCOPE} & set(scopes))


def _parse_item(item: dict[str, Any], *, is_shared_drive: bool = False) -> GoogleDriveItem:
    """Map a Drive ``file`` JSON object into a :class:`GoogleDriveItem`."""

    file_id = str(item.get("id", ""))
    if not file_id:
        raise GoogleApiError("Drive file is missing an id")
    validate_resource_identifier(file_id, field="file_id")

    mime_type = item.get("mimeType")
    is_folder = mime_type == GOOGLE_FOLDER_MIME
    is_shortcut = mime_type == GOOGLE_SHORTCUT_MIME

    parents = item.get("parents") or []
    parent_id = str(parents[0]) if parents else None
    if parent_id is not None:
        validate_resource_identifier(parent_id, field="parent_id")

    shortcut_target: str | None = None
    if is_shortcut:
        details = item.get("shortcutDetails") or {}
        target = details.get("targetId")
        if target:
            shortcut_target = str(target)
            validate_resource_identifier(shortcut_target, field="shortcut_target_id")

    size = item.get("size")
    return GoogleDriveItem(
        file_id=file_id,
        name=str(item.get("name", "")),
        is_folder=is_folder,
        mime_type=mime_type,
        size=int(size) if isinstance(size, (int, str)) and str(size).isdigit() else None,
        drive_id=item.get("driveId"),
        parent_id=parent_id,
        web_url=item.get("webViewLink"),
        source_type=SOURCE_TYPE_SHARED_DRIVE if is_shared_drive else SOURCE_TYPE_DRIVE,
        is_shared_drive=is_shared_drive,
        is_shortcut=is_shortcut,
        shortcut_target_id=shortcut_target,
        trashed=bool(item.get("trashed", False)),
    )


class GoogleDriveBrowser:
    """Browse and scan a user's Google Drive (My Drive + Shared Drives) by id.

    The browser never constructs Drive URLs from untrusted client input: every
    identifier is validated, and the host/token are owned by the injected
    transport. Selection produces a :class:`ConnectorResource` (and, via the
    injected :class:`ConnectorScanner`, findings) reusing the existing scan
    pipeline.
    """

    def __init__(
        self,
        identity: ConnectorIdentity,
        transport: GoogleDriveTransport,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        page_size: int = 0,
        max_files: int = DEFAULT_MAX_FILES,
        max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    ) -> None:
        if transport.base_url != CANONICAL_DRIVE_BASE:
            raise GoogleApiError(
                f"Drive transport must target the canonical {CANONICAL_DRIVE_BASE} host"
            )
        self._identity = identity
        self._transport = transport
        self._max_pages = max_pages
        self._max_depth = max_depth
        self._page_size = page_size
        self._max_files = max_files
        self._max_download_bytes = max_download_bytes

    def capabilities(self) -> frozenset[ConnectorCapability]:
        """Declared capability set -- read/list/scan (scan is delegated)."""

        return frozenset(
            {ConnectorCapability.READ, ConnectorCapability.LIST, ConnectorCapability.SCAN}
        )

    # --- Discovery ------------------------------------------------------------

    def list_shared_drives(self) -> list[SharedDrive]:
        """Discover Shared Drives the authenticated principal may read."""

        # Drive API v3 returns the Shared Drive collection under the top-level
        # ``drives`` key (not ``items``), so the field selection must be wrapped:
        # ``fields=drives(id,name)``.
        relative = "drives?fields=" + _quote("drives(id,name)")
        if self._page_size:
            relative += f"&pageSize={self._page_size}"
        drives: list[SharedDrive] = []
        pages = 0
        base_relative: str | None = relative
        while base_relative is not None:
            data = self._transport.get_json(base_relative)
            for entry in data.get("drives", []) or []:
                drive_id = str(entry.get("id", ""))
                if not drive_id:
                    continue
                validate_resource_identifier(drive_id, field="drive_id")
                drives.append(SharedDrive(drive_id=drive_id, name=str(entry.get("name", ""))))
            base_relative = self._page_token_url(relative, data)
            pages += 1
            if pages >= self._max_pages:
                break
        return drives

    def list_children(
        self,
        folder_id: str | None = None,
        *,
        drive_id: str | None = None,
        corpora: str | None = None,
    ) -> list[GoogleDriveItem]:
        """List the direct children of a folder (or My Drive root).

        ``folder_id`` is a Drive ``file`` id of a folder, or ``None`` for the My
        Drive root. ``drive_id`` selects a Shared Drive. Results are paginated up
        to ``max_pages`` and trashed items are excluded.
        """

        if folder_id is None:
            relative = "files?q=" + _quote("'root' in parents and trashed = false")
        else:
            validate_resource_identifier(folder_id, field="folder_id")
            relative = "files?q=" + _quote(f"'{folder_id}' in parents and trashed = false")
        # The ``files.list`` response is a *collection*; field selection must be
        # wrapped in ``files(...)`` or the API rejects every bare field name
        # (e.g. ``Invalid field selection id``). The single-file ``files.get``
        # response is a file object, so it uses bare ``fields=...`` (see
        # ``_fetch_item``).
        relative += f"&fields={_quote('files(' + _SELECT_FIELDS + ')')}"
        if drive_id is not None:
            validate_resource_identifier(drive_id, field="drive_id")
            relative += f"&driveId={_quote(drive_id)}&corpora=drive"
        elif corpora is not None:
            relative += f"&corpora={_quote(corpora)}"
        if self._page_size:
            relative += f"&pageSize={self._page_size}"

        items: list[GoogleDriveItem] = []
        pages = 0
        base_relative: str | None = relative
        while base_relative is not None:
            data = self._transport.get_json(base_relative)
            for entry in data.get("files", []) or []:
                items.append(_parse_item(entry, is_shared_drive=drive_id is not None))
            base_relative = self._page_token_url(relative, data)
            pages += 1
            if pages >= self._max_pages:
                logger.debug("Drive browse reached max_pages bound (%d)", self._max_pages)
                break
        return items

    # --- Resolution -----------------------------------------------------------

    def resolve_resource(self, file_id: str) -> ConnectorResource:
        """Build a metadata-only :class:`ConnectorResource` for a selected file.

        Folders and shortcuts-to-folders cannot be scanned as a single file.
        ``org_id``/``tenant_id`` are taken from the server-resolved identity.
        """

        validate_resource_identifier(file_id, field="file_id")
        item = self._fetch_item(file_id)
        if item.is_folder:
            raise GoogleApiError(
                "selected Drive item is a folder and cannot be scanned directly",
                status_code=400,
            )
        return self._to_resource(item)

    def select_and_scan(
        self,
        file_id: str,
        scanner: ConnectorScanner,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
    ) -> ScanResult:
        """Resolve a selected file and run it through the existing scan pipeline.

        Reuses the single :class:`ConnectorScanner` -- it does not introduce a
        second scanner. Google-native content is exported to a deterministic text
        representation first.
        """

        validate_resource_identifier(file_id, field="file_id")
        try:
            item = self._fetch_item(file_id)
        except GoogleApiError as exc:
            return self._error_result(file_id, _map_error_code(exc), _safe_message(exc))
        if item.is_folder:
            return self._unsupported(
                item,
                scanner,
                context,
                integration_id,
                "selected Drive item is a folder and cannot be scanned directly",
            )

        content = self._retrieve_content(item)
        if content is None:
            return self._unsupported(
                item,
                scanner,
                context,
                integration_id,
                "Drive item content could not be retrieved or exported",
            )
        return self._scan_bytes(item, content, scanner, context, integration_id, user_id)

    # --- Bulk scan ------------------------------------------------------------

    def scan_folder(
        self,
        folder_id: str,
        scanner: ConnectorScanner,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
        drive_id: str | None = None,
        max_files: int = 0,
        visited: set[str] | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        """Recursively scan an authorized folder, returning aggregate counts.

        ``heartbeat`` is invoked periodically (per folder level and every
        ``_HEARTBEAT_EVERY_FILES`` files) so that long recursive scans keep the
        execution lease alive without any concurrent threads.
        """

        validate_resource_identifier(folder_id, field="folder_id")
        summary = DriveScanSummary(
            source=SOURCE_TYPE_SHARED_DRIVE if drive_id else SOURCE_TYPE_DRIVE,
            drive_id=drive_id,
            root_id=folder_id,
        )
        visited = visited if visited is not None else set()
        limit = max_files if max_files > 0 else self._max_files
        self._walk(
            folder_id,
            scanner,
            context,
            integration_id,
            user_id,
            drive_id,
            summary,
            visited,
            0,
            limit,
            heartbeat,
        )
        return summary

    def scan_drive(
        self,
        scanner: ConnectorScanner,
        context: ScanContext | None = None,
        *,
        drive_id: str | None = None,
        integration_id: str | None = None,
        user_id: str | None = None,
        max_files: int = 0,
        visited: set[str] | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        """Scan My Drive (``drive_id=None``) or a Shared Drive root recursively.

        ``heartbeat`` is threaded into the walk (see :meth:`scan_folder`).
        """

        root_id: str | None = None
        if drive_id is not None:
            validate_resource_identifier(drive_id, field="drive_id")
            root_id = drive_id
        summary = DriveScanSummary(
            source=SOURCE_TYPE_MY_DRIVE if drive_id is None else SOURCE_TYPE_SHARED_DRIVE,
            drive_id=drive_id,
            root_id=root_id,
        )
        visited = visited if visited is not None else set()
        limit = max_files if max_files > 0 else self._max_files
        self._walk(
            None,
            scanner,
            context,
            integration_id,
            user_id,
            drive_id,
            summary,
            visited,
            0,
            limit,
            heartbeat,
        )
        return summary

    # --- Internals ------------------------------------------------------------

    def _walk(
        self,
        folder_id: str | None,
        scanner: ConnectorScanner,
        context: ScanContext | None,
        integration_id: str | None,
        user_id: str | None,
        drive_id: str | None,
        summary: DriveScanSummary,
        visited: set[str],
        depth: int,
        max_files: int = DEFAULT_MAX_FILES,
        heartbeat: Callable[[], None] | None = None,
    ) -> None:
        if heartbeat is not None:
            heartbeat()
        if depth >= self._max_depth:
            logger.debug("Drive walk reached max_depth bound (%d)", self._max_depth)
            return
        if summary.files_discovered >= max_files:
            summary.status = "partial"
            return
        try:
            children = self.list_children(folder_id, drive_id=drive_id)
        except GoogleApiError as exc:
            summary.files_failed += 1
            summary.errors.append(ScanError(code=_map_error_code(exc), message=_safe_message(exc)))
            summary.status = "partial"
            return

        for child in children:
            if summary.files_discovered >= max_files:
                summary.status = "partial"
                break
            summary.files_discovered += 1

            # De-duplicate shortcuts and the same underlying file reached via
            # multiple paths. The visited key is the resolved file id.
            resolved_id = child.shortcut_target_id or child.file_id
            if resolved_id in visited:
                continue
            visited.add(resolved_id)

            if child.is_folder:
                self._walk(
                    child.file_id,
                    scanner,
                    context,
                    integration_id,
                    user_id,
                    drive_id,
                    summary,
                    visited,
                    depth + 1,
                    max_files,
                    heartbeat,
                )
                continue

            result = self._scan_one(resolved_id, scanner, context, integration_id, user_id)
            self._accumulate(summary, result)
            if heartbeat is not None and summary.files_discovered % _HEARTBEAT_EVERY_FILES == 0:
                heartbeat()

    def _scan_one(
        self,
        file_id: str,
        scanner: ConnectorScanner,
        context: ScanContext | None,
        integration_id: str | None,
        user_id: str | None,
    ) -> ScanResult:
        try:
            item = self._fetch_item(file_id)
        except GoogleApiError as exc:
            return self._error_result(file_id, _map_error_code(exc), _safe_message(exc))
        if item.is_folder:
            return self._error_result(file_id, ScanErrorCode.UNSUPPORTED_FORMAT, "item is a folder")
        content = self._retrieve_content(item)
        if content is None:
            return self._error_result(
                file_id,
                ScanErrorCode.UNSUPPORTED_FORMAT,
                "content could not be retrieved or exported",
            )
        return self._scan_bytes(item, content, scanner, context, integration_id, user_id)

    def _scan_bytes(
        self,
        item: GoogleDriveItem,
        raw: bytes,
        scanner: ConnectorScanner,
        context: ScanContext | None,
        integration_id: str | None,
        user_id: str | None,
    ) -> ScanResult:
        normalized = _normalize_content(item.mime_type, item.name, raw)
        if normalized is None:
            return self._unsupported(
                item,
                scanner,
                context,
                integration_id,
                "Drive item format cannot be scanned by the SecuRedact pipeline",
            )
        resource = self._to_resource(item, extracted_text=normalized.text)
        return scanner.scan(resource, context, integration_id=integration_id, user_id=user_id)

    def _accumulate(self, summary: DriveScanSummary, result: ScanResult) -> None:
        if result.status == ScanStatus.ERROR:
            if result.error is not None and result.error.code == ScanErrorCode.UNSUPPORTED_FORMAT:
                summary.files_unsupported += 1
            else:
                summary.files_failed += 1
                if result.error is not None and len(summary.errors) < 25:
                    summary.errors.append(result.error)
            return
        summary.files_scanned += 1
        if result.severity == ScanSeverity.NONE and not result.counts:
            summary.files_clean += 1
        else:
            summary.files_with_findings += 1
        summary.findings_total += sum(result.counts.values())
        # Aggregate per-category counts so the control-plane-safe summary can
        # report which kinds of findings were detected (never the values).
        for entity_type, count in (result.counts or {}).items():
            summary.category_counts[entity_type] = summary.category_counts.get(
                entity_type, 0
            ) + int(count)

    def _unsupported(
        self,
        item: GoogleDriveItem,
        scanner: ConnectorScanner,
        context: ScanContext | None,
        integration_id: str | None,
        message: str,
    ) -> ScanResult:
        resource = self._to_resource(item, extracted_text=None)
        return ScanResult(
            status=ScanStatus.ERROR,
            resource_id=resource.resource_id,
            platform=resource.platform,
            org_id=resource.org_id,
            tenant_id=resource.tenant_id,
            integration_id=integration_id,
            error=ScanError(code=ScanErrorCode.UNSUPPORTED_FORMAT, message=message),
            correlation_id=(context or ScanContext()).correlation_id,
        )

    def _error_result(self, file_id: str, code: ScanErrorCode, message: str) -> ScanResult:
        return ScanResult(
            status=ScanStatus.ERROR,
            resource_id=file_id,
            platform=GOOGLE_WORKSPACE_PLATFORM,
            org_id=self._identity.org_id,
            tenant_id=self._identity.tenant_id,
            error=ScanError(code=code, message=message),
        )

    def _retrieve_content(self, item: GoogleDriveItem) -> bytes | None:
        """Retrieve/export bytes for a file, or ``None`` if unsupported.

        Google-native Docs/Sheets/Slides are exported to a deterministic text
        MIME type (covered by ``drive.readonly``). Other text formats are
        downloaded with ``alt=media``. Binary Office/PDF formats are not yet
        supported by the SecuRedact extraction pipeline (CONN-003) and return
        ``None`` so the caller can report ``UNSUPPORTED_FORMAT``.
        """

        if item.is_shortcut and item.shortcut_target_id:
            try:
                target = self._fetch_item(item.shortcut_target_id)
            except GoogleApiError:
                return None
            return self._retrieve_content(target)

        if item.mime_type == GOOGLE_DOCS_MIME:
            return self._export(item, DOCS_EXPORT_MIME)
        if item.mime_type == GOOGLE_SLIDES_MIME:
            return self._export(item, SLIDES_EXPORT_MIME)
        if item.mime_type == GOOGLE_SHEETS_MIME:
            return self._export(item, SHEETS_EXPORT_MIME)
        if item.mime_type == GOOGLE_FOLDER_MIME:
            return None
        if item.size is not None and item.size > self._max_download_bytes:
            return None
        if is_text_format(mime_type=item.mime_type, name=item.name):
            try:
                return self._transport.get_content(
                    f"files/{item.file_id}?alt=media",
                    max_bytes=self._max_download_bytes,
                )
            except GoogleApiError:
                return None
        # Binary formats not supported by the existing pipeline.
        return None

    def _export(self, item: GoogleDriveItem, export_mime: str) -> bytes | None:
        path = f"files/{item.file_id}/export?mimeType={_quote(export_mime)}"
        try:
            return self._transport.get_content(path, max_bytes=self._max_download_bytes)
        except GoogleApiError:
            return None

    def _fetch_item(self, file_id: str) -> GoogleDriveItem:
        data = self._transport.get_json(f"files/{file_id}?fields={_quote(_SELECT_FIELDS)}")
        return _parse_item(data)

    def _to_resource(
        self, item: GoogleDriveItem, *, extracted_text: str | None = None
    ) -> ConnectorResource:
        self._emit_access(item)
        return ConnectorResource(
            resource_id=item.shortcut_target_id or item.file_id,
            platform=GOOGLE_WORKSPACE_PLATFORM,
            resource_kind=ResourceKind.FILE,
            org_id=self._identity.org_id,
            tenant_id=self._identity.tenant_id,
            parent_id=item.parent_id,
            name=item.name,
            mime_type=item.mime_type,
            size_bytes=item.size,
            external_url=item.web_url,
            content_ref=item.file_id,
            metadata={
                "source_type": item.source_type,
                "drive_id": item.drive_id,
                "is_folder": item.is_folder,
                "is_shared_drive": item.is_shared_drive,
                "is_shortcut": item.is_shortcut,
                "mime_type": item.mime_type,
            },
            extracted_text=extracted_text,
        )

    def _emit_access(self, item: GoogleDriveItem) -> None:
        emit_audit_event(
            build_audit_event(
                AuditEventType.CONNECTOR_RESOURCE_ACCESSED,
                action="read",
                operation="network_read",
                source=item.file_id,
                provider=GOOGLE_WORKSPACE_PLATFORM,
                policy_name="",
                entity_types=tuple(),
                count=0,
                event_id=None,
                timestamp_utc=_now(),
                metadata={
                    "org_id": self._identity.org_id,
                    "tenant_id": self._identity.tenant_id,
                    "resource_kind": ResourceKind.FILE.value,
                    "source_type": item.source_type,
                },
            )
        )

    @staticmethod
    def _page_token_url(base_relative: str, data: dict[str, Any]) -> str | None:
        token = data.get("nextPageToken")
        if not token:
            return None
        sep = "&" if "?" in base_relative else "?"
        return f"{base_relative}{sep}pageToken={_quote(str(token))}"


def _normalize_content(mime_type: str | None, name: str, raw: bytes) -> NormalizedContent | None:
    """Return :class:`NormalizedContent` for a supported format, else ``None``."""

    if mime_type == GOOGLE_SHEETS_MIME:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        # Preserve sheet context (CSV export yields the active sheet); prepend a
        # deterministic header so detection has structural context.
        prefixed = f"Sheet: {name}\n{text}"
        return NormalizedContent(
            text=prefixed, source_format="google_sheets", char_count=len(prefixed)
        )
    if mime_type in (GOOGLE_DOCS_MIME, GOOGLE_SLIDES_MIME):
        source = "google_docs" if mime_type == GOOGLE_DOCS_MIME else "google_slides"
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return NormalizedContent(text=text, source_format=source, char_count=len(text))
    # Other text formats go through the shared extractor.
    return extract_text(raw, mime_type=mime_type, name=name)


def _map_error_code(exc: GoogleApiError) -> ScanErrorCode:
    if exc.status_code in (401, 403):
        return ScanErrorCode.UNAUTHORIZED
    if exc.status_code == 404:
        return ScanErrorCode.RETRIEVAL_FAILED
    if exc.status_code == 429:
        return ScanErrorCode.RATE_LIMITED
    return ScanErrorCode.RETRIEVAL_FAILED


def _safe_message(exc: GoogleApiError) -> str:
    # Never embed token/exception internals; keep a stable, safe summary.
    if exc.status_code == 401:
        return "Google authorization failed or token was revoked"
    if exc.status_code == 403:
        return "Google refused the request (insufficient scope or API disabled)"
    if exc.status_code == 404:
        return "Google Drive item was not found"
    if exc.status_code == 429:
        return "Google rate limit exceeded; retry later"
    return "Google Drive request failed"


def safe_diagnostic(exc: GoogleApiError) -> dict[str, object]:
    """Return provider-safe diagnostic metadata for an error (no secrets).

    Only non-credential fields are included: a stable safe message, the HTTP
    status, the Google error ``reason`` token, a safe endpoint/path (query
    string stripped), whether the failure is retryable, and a coarse category.
    Never includes tokens, Authorization headers, client secrets, or response
    bodies.
    """

    diag: dict[str, object] = {"error": exc.message}
    if exc.status_code is not None:
        diag["status"] = exc.status_code
    if exc.reason is not None:
        diag["reason"] = exc.reason
    if exc.endpoint is not None:
        # Strip any query string so file ids/parameters do not leak into logs.
        diag["endpoint"] = exc.endpoint.split("?")[0]
    if exc.retryable is not None:
        diag["retryable"] = exc.retryable
    if exc.category is not None:
        diag["category"] = exc.category
    return diag


def _quote(value: str) -> str:
    return quote(value, safe="")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
