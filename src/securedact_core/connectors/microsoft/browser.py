# SPDX-License-Identifier: Apache-2.0
"""Microsoft Graph browser implementation (M365-102).

Transport-agnostic core browser that consumes Microsoft Graph v1.0 REST JSON
through an injected :class:`MicrosoftGraphTransport`. Mirrors the Google
:class:`GoogleDriveBrowser` architecture.
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
from ..fingerprint import (
    FingerprintConfig,
    ResourceType,
    compute_resource_fingerprint,
)
from ..scan import ScanError, ScanErrorCode, ScanResult, ScanSeverity, ScanStatus

logger = logging.getLogger(__name__)

GRAPH_HOST = "https://graph.microsoft.com"
GRAPH_API_VERSION = "v1.0"
CANONICAL_GRAPH_BASE = f"{GRAPH_HOST}/{GRAPH_API_VERSION}"

MICROSOFT_365_PLATFORM = "microsoft365"
SOURCE_TYPE_ONEDRIVE = "microsoft_onedrive"
SOURCE_TYPE_SHAREPOINT_DRIVE = "microsoft_sharepoint_drive"
SOURCE_TYPE_SHAREPOINT_SITE = "microsoft_sharepoint_site"

# Microsoft 365 / Graph MIME types
FOLDER_MIME_TYPE = "folder"

# Common text-based MIME types supported for scanning
FILE_MIME_TYPES = frozenset({
    "text/plain",
    "text/markdown",
    "text/csv",
    "application/json",
    "text/html",
    "application/xml",
    "text/xml",
})

# OAuth scopes (least privilege for this milestone)
USER_READ_SCOPE = "User.Read"
FILES_READ_SCOPE = "Files.Read"
SITES_READ_ALL_SCOPE = "Sites.Read.All"
OFFLINE_ACCESS_SCOPE = "offline_access"

# Documented for the future, explicitly NOT requested by M365-102:
_FILES_READ_WRITE_SCOPE = "Files.ReadWrite"
_SITES_READ_WRITE_ALL_SCOPE = "Sites.ReadWrite.All"

# Bounds that keep a single browse/scan operation from walking unboundedly
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_DEPTH = 20
DEFAULT_PAGE_SIZE = 200
DEFAULT_MAX_FILES = 1000
# Invoke the execution-lease heartbeat at most once per this many scanned files
# during a recursive folder/drive walk (no concurrent threads are used).
_HEARTBEAT_EVERY_FILES = 25
# Remote retrieval uses a memory guard larger than the inspection cap so the
# exact character limit (FW-041) is enforced by :class:`ConnectorScanner`, never
# by an unbounded download. The scanner rejects content above
# ``MAX_INSPECTION_TEXT_CHARS`` rather than truncating it.
DEFAULT_MAX_DOWNLOAD_BYTES = MAX_INSPECTION_TEXT_CHARS * 4

# Graph fields to select for drive items
_SELECT_FIELDS = "id,name,file,folder,size,parentReference,webUrl,@microsoft.graph.downloadUrl,fileSystemInfo"


class MicrosoftApiError(Exception):
    """Raised when the Graph transport returns an unexpected/error response.

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


class MicrosoftAuthError(MicrosoftApiError):
    """Raised when credentials are missing, revoked, expired, or insufficient."""


@runtime_checkable
class MicrosoftGraphTransport(Protocol):
    """Minimal, host-pinned Graph read surface injected by the control plane.

    Implementations must talk only to ``https://graph.microsoft.com/v1.0`` and
    must surface the verified user identity (``sub``/email from the resolved
    token) so the browser can attribute operations. No Microsoft SDK is required
    to satisfy this protocol -- a test double can implement it directly.
    """

    @property
    def base_url(self) -> str:
        """The canonical Graph base URL this transport targets (v1.0)."""
        ...

    @property
    def user_id(self) -> str:
        """The verified Microsoft user identity (``sub``) of the resolved token."""
        ...

    @property
    def tenant_id(self) -> str:
        """The verified Microsoft tenant identity (``tid``) of the resolved token."""
        ...

    def get_json(self, path: str) -> dict[str, Any]:
        """Perform a delegated ``GET`` against ``<base_url>/<path>`` and return JSON."""
        ...

    def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
        """Perform a delegated ``GET`` against ``<base_url>/<path>`` and return bytes.

        Implementations must raise :class:`MicrosoftApiError` on HTTP errors and may
        raise a bounded error if the response exceeds ``max_bytes`` rather than
        buffering it all in memory.
        """
        ...


class MicrosoftGraphItem(BaseModel):
    """A normalized view of a Graph ``driveItem`` (file or folder)."""

    model_config = ConfigDict(extra="forbid")

    item_id: str
    name: str
    is_folder: bool
    mime_type: str | None = None
    size: int | None = None
    drive_id: str | None = None
    parent_id: str | None = None
    web_url: str | None = None
    source_type: str = SOURCE_TYPE_ONEDRIVE
    download_url: str | None = None
    created_date_time: str | None = None
    last_modified_date_time: str | None = None
    e_tag: str | None = None


class MicrosoftDrive(BaseModel):
    """A discovered Drive (OneDrive or SharePoint document library)."""

    model_config = ConfigDict(extra="forbid")

    drive_id: str
    name: str
    drive_type: str  # "personal" | "documentLibrary"
    owner: str | None = None


class MicrosoftSite(BaseModel):
    """A discovered SharePoint site."""

    model_config = ConfigDict(extra="forbid")

    site_id: str
    name: str
    web_url: str | None = None


class DriveScanSummary(BaseModel):
    """Aggregate outcome of a folder/Drive scan (M365-102)."""

    model_config = ConfigDict(extra="forbid")

    status: str = "completed"
    source: str
    drive_id: str | None = None
    site_id: str | None = None
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


def build_graph_scopes(capabilities: set[ConnectorCapability]) -> list[str]:
    """Return the minimum Graph scopes required by the declared capabilities.

    Read-only scanning needs only ``Files.Read``, ``Sites.Read.All``, ``User.Read``.
    Write capabilities would add ``Files.ReadWrite`` -- but this milestone declares
    read/list/scan only and never requests a write scope. Capability-driven so a
    future write milestone can add exactly the scope it needs rather than one
    permanently oversized set.
    """

    scopes: set[str] = set()
    if {
        ConnectorCapability.READ,
        ConnectorCapability.LIST,
        ConnectorCapability.SCAN,
    } & capabilities:
        scopes.add(USER_READ_SCOPE)
        scopes.add(FILES_READ_SCOPE)
        scopes.add(SITES_READ_ALL_SCOPE)
    if ConnectorCapability.WRITE in capabilities:
        # Documented, not exercised by M365-102.
        scopes.add(_FILES_READ_WRITE_SCOPE)
    scopes.add(OFFLINE_ACCESS_SCOPE)
    return sorted(scopes)


def default_connector_scopes() -> list[str]:
    """The least-privilege default scope set for the M365-102 connector."""

    return build_graph_scopes(
        {ConnectorCapability.READ, ConnectorCapability.LIST, ConnectorCapability.SCAN}
    )


def has_write_scope(scopes: list[str]) -> bool:
    """Return whether any write/expanded Graph scope is present.

    Used to fail closed if a configuration requests more than read-only.
    """

    return bool(
        {_FILES_READ_WRITE_SCOPE, _SITES_READ_WRITE_ALL_SCOPE} & set(scopes)
    )


def _parse_item(item: dict[str, Any], *, source_type: str = SOURCE_TYPE_ONEDRIVE) -> MicrosoftGraphItem:
    """Map a Graph ``driveItem`` JSON object into a :class:`MicrosoftGraphItem`."""

    item_id = str(item.get("id", ""))
    if not item_id:
        raise MicrosoftApiError("Graph driveItem is missing an id")
    validate_resource_identifier(item_id, field="item_id")

    # Determine if it's a folder
    is_folder = "folder" in item
    mime_type = None
    if "file" in item:
        mime = item.get("file", {}).get("mimeType")
        if mime:
            mime_type = str(mime)

    parent_ref = item.get("parentReference") or {}
    parent_id = parent_ref.get("id")
    drive_id = parent_ref.get("driveId")
    if parent_id:
        validate_resource_identifier(str(parent_id), field="parent_id")
    if drive_id:
        validate_resource_identifier(str(drive_id), field="drive_id")

    size = item.get("size")
    download_url = item.get("@microsoft.graph.downloadUrl")
    created = item.get("createdDateTime")
    modified = item.get("lastModifiedDateTime")
    e_tag = item.get("eTag")

    return MicrosoftGraphItem(
        item_id=item_id,
        name=str(item.get("name", "")),
        is_folder=is_folder,
        mime_type=mime_type,
        size=int(size) if isinstance(size, (int, str)) and str(size).isdigit() else None,
        drive_id=str(drive_id) if drive_id else None,
        parent_id=str(parent_id) if parent_id else None,
        web_url=item.get("webUrl"),
        source_type=source_type,
        download_url=download_url,
        created_date_time=created,
        last_modified_date_time=modified,
        e_tag=str(e_tag) if e_tag else None,
    )


def _parse_drive(drive: dict[str, Any]) -> MicrosoftDrive:
    """Map a Graph ``drive`` JSON object into a :class:`MicrosoftDrive`."""

    drive_id = str(drive.get("id", ""))
    if not drive_id:
        raise MicrosoftApiError("Graph drive is missing an id")
    validate_resource_identifier(drive_id, field="drive_id")

    drive_type = drive.get("driveType", "")
    owner = None
    if "owner" in drive:
        owner_info = drive.get("owner") or {}
        owner = owner_info.get("user", {}).get("displayName")

    return MicrosoftDrive(
        drive_id=drive_id,
        name=str(drive.get("name", "")),
        drive_type=drive_type,
        owner=owner,
    )


def _parse_site(site: dict[str, Any]) -> MicrosoftSite:
    """Map a Graph ``site`` JSON object into a :class:`MicrosoftSite`."""

    site_id = str(site.get("id", ""))
    if not site_id:
        raise MicrosoftApiError("Graph site is missing an id")
    validate_resource_identifier(site_id, field="site_id")

    return MicrosoftSite(
        site_id=site_id,
        name=str(site.get("displayName", "")),
        web_url=site.get("webUrl"),
    )


class MicrosoftGraphBrowser:
    """Browse and scan a user's Microsoft 365 (OneDrive + SharePoint) by id.

    The browser never constructs Graph URLs from untrusted client input: every
    identifier is validated, and the host/token are owned by the injected
    transport. Selection produces a :class:`ConnectorResource` (and, via the
    injected :class:`ConnectorScanner`, findings) reusing the existing scan
    pipeline.

    Privacy-safe resource fingerprints are used in place of raw Microsoft Graph
    identifiers in all control-plane payloads. Raw IDs are retained locally for
    Graph API calls but never leave the machine.
    """

    def __init__(
        self,
        identity: ConnectorIdentity,
        transport: MicrosoftGraphTransport,
        fingerprint_config: FingerprintConfig | None = None,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        page_size: int = 0,
        max_files: int = DEFAULT_MAX_FILES,
        max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    ) -> None:
        if transport.base_url != CANONICAL_GRAPH_BASE:
            raise MicrosoftApiError(
                f"Graph transport must target the canonical {CANONICAL_GRAPH_BASE} host"
            )
        self._identity = identity
        self._transport = transport
        self._fingerprint_config = fingerprint_config
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

    def list_drives(self) -> list[MicrosoftDrive]:
        """Discover drives the authenticated principal may read."""

        relative = "drives?$select=id,name,driveType,owner"
        if self._page_size:
            relative += f"&$top={self._page_size}"
        drives: list[MicrosoftDrive] = []
        pages = 0
        base_relative: str | None = relative
        while base_relative is not None:
            data = self._transport.get_json(base_relative)
            for entry in data.get("value", []) or []:
                drives.append(_parse_drive(entry))
            base_relative = self._next_link_url(base_relative, data)
            pages += 1
            if pages >= self._max_pages:
                break
        return drives

    def get_drive(self, drive_id: str) -> MicrosoftDrive:
        """Get a specific drive by ID."""

        validate_resource_identifier(drive_id, field="drive_id")
        data = self._transport.get_json(f"drives/{drive_id}?$select=id,name,driveType,owner")
        return _parse_drive(data)

    def list_sites(self) -> list[MicrosoftSite]:
        """Discover SharePoint sites the authenticated principal may read."""

        relative = "sites?$select=id,displayName,webUrl"
        if self._page_size:
            relative += f"&$top={self._page_size}"
        sites: list[MicrosoftSite] = []
        pages = 0
        base_relative: str | None = relative
        while base_relative is not None:
            data = self._transport.get_json(base_relative)
            for entry in data.get("value", []) or []:
                sites.append(_parse_site(entry))
            base_relative = self._next_link_url(base_relative, data)
            pages += 1
            if pages >= self._max_pages:
                break
        return sites

    def get_site(self, site_id: str) -> MicrosoftSite:
        """Get a specific site by ID."""

        validate_resource_identifier(site_id, field="site_id")
        data = self._transport.get_json(f"sites/{site_id}?$select=id,displayName,webUrl")
        return _parse_site(data)

    def get_site_drive(self, site_id: str) -> MicrosoftDrive:
        """Get the default document library (drive) for a SharePoint site."""

        validate_resource_identifier(site_id, field="site_id")
        data = self._transport.get_json(f"sites/{site_id}/drive?$select=id,name,driveType,owner")
        return _parse_drive(data)

    def list_children(
        self,
        drive_id: str,
        folder_id: str | None = None,
    ) -> list[MicrosoftGraphItem]:
        """List the direct children of a folder (or drive root).

        ``folder_id`` is a driveItem id of a folder, or ``None`` for the drive root.
        Results are paginated up to ``max_pages``.
        """

        validate_resource_identifier(drive_id, field="drive_id")
        if folder_id is None:
            relative = f"drives/{drive_id}/root/children"
        else:
            validate_resource_identifier(folder_id, field="folder_id")
            relative = f"drives/{drive_id}/items/{folder_id}/children"

        relative += f"?$select={_quote(_SELECT_FIELDS)}"
        if self._page_size:
            relative += f"&$top={self._page_size}"

        items: list[MicrosoftGraphItem] = []
        pages = 0
        base_relative: str | None = relative
        while base_relative is not None:
            data = self._transport.get_json(base_relative)
            for entry in data.get("value", []) or []:
                items.append(_parse_item(entry))
            base_relative = self._next_link_url(base_relative, data)
            pages += 1
            if pages >= self._max_pages:
                logger.debug("Graph browse reached max_pages bound (%d)", self._max_pages)
                break
        return items

    # --- Resolution -----------------------------------------------------------

    def resolve_resource(self, drive_id: str, item_id: str) -> ConnectorResource:
        """Build a metadata-only :class:`ConnectorResource` for a selected file.

        Folders cannot be scanned as a single file.
        ``org_id``/``tenant_id`` are taken from the server-resolved identity.
        """

        validate_resource_identifier(drive_id, field="drive_id")
        validate_resource_identifier(item_id, field="item_id")
        item = self._fetch_item(drive_id, item_id)
        if item.is_folder:
            raise MicrosoftApiError(
                "selected Graph item is a folder and cannot be scanned directly",
                status_code=400,
            )
        return self._to_resource(item)

    def select_and_scan(
        self,
        drive_id: str,
        item_id: str,
        scanner: ConnectorScanner,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
    ) -> ScanResult:
        """Resolve a selected file and run it through the existing scan pipeline.

        Reuses the single :class:`ConnectorScanner` -- it does not introduce a
        second scanner. Microsoft 365 content is downloaded and processed.
        """

        validate_resource_identifier(drive_id, field="drive_id")
        validate_resource_identifier(item_id, field="item_id")
        try:
            item = self._fetch_item(drive_id, item_id)
        except MicrosoftApiError as exc:
            return self._error_result(item_id, _map_error_code(exc), _safe_message(exc))
        if item.is_folder:
            return self._unsupported(
                item,
                scanner,
                context,
                integration_id,
                "selected Graph item is a folder and cannot be scanned directly",
            )

        content = self._retrieve_content(item)
        if content is None:
            return self._unsupported(
                item,
                scanner,
                context,
                integration_id,
                "Graph item content could not be retrieved",
            )
        return self._scan_bytes(item, content, scanner, context, integration_id, user_id)

    # --- Bulk scan ------------------------------------------------------------

    def scan_folder(
        self,
        drive_id: str,
        folder_id: str,
        scanner: ConnectorScanner,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
        site_id: str | None = None,
        max_files: int = 0,
        visited: set[str] | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        """Recursively scan an authorized folder, returning aggregate counts.

        ``heartbeat`` is invoked periodically (per folder level and every
        ``_HEARTBEAT_EVERY_FILES`` files) so that long recursive scans keep the
        execution lease alive without any concurrent threads.
        """

        validate_resource_identifier(drive_id, field="drive_id")
        validate_resource_identifier(folder_id, field="folder_id")
        source_type = SOURCE_TYPE_SHAREPOINT_DRIVE if site_id else SOURCE_TYPE_ONEDRIVE
        summary = DriveScanSummary(
            source=source_type,
            drive_id=drive_id,
            site_id=site_id,
            root_id=folder_id,
        )
        visited = visited if visited is not None else set()
        limit = max_files if max_files > 0 else self._max_files
        self._walk(
            drive_id,
            folder_id,
            scanner,
            context,
            integration_id,
            user_id,
            site_id,
            summary,
            visited,
            0,
            limit,
            heartbeat,
        )
        return summary

    def scan_drive(
        self,
        drive_id: str,
        scanner: ConnectorScanner,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
        site_id: str | None = None,
        max_files: int = 0,
        visited: set[str] | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        """Scan a drive root recursively (OneDrive or SharePoint document library).

        ``heartbeat`` is threaded into the walk (see :meth:`scan_folder`).
        """

        validate_resource_identifier(drive_id, field="drive_id")
        source_type = SOURCE_TYPE_SHAREPOINT_DRIVE if site_id else SOURCE_TYPE_ONEDRIVE
        summary = DriveScanSummary(
            source=source_type,
            drive_id=drive_id,
            site_id=site_id,
            root_id="root",
        )
        visited = visited if visited is not None else set()
        limit = max_files if max_files > 0 else self._max_files
        self._walk(
            drive_id,
            None,
            scanner,
            context,
            integration_id,
            user_id,
            site_id,
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
        drive_id: str,
        folder_id: str | None,
        scanner: ConnectorScanner,
        context: ScanContext | None,
        integration_id: str | None,
        user_id: str | None,
        site_id: str | None,
        summary: DriveScanSummary,
        visited: set[str],
        depth: int,
        max_files: int = DEFAULT_MAX_FILES,
        heartbeat: Callable[[], None] | None = None,
    ) -> None:
        if heartbeat is not None:
            heartbeat()
        if depth >= self._max_depth:
            logger.debug("Graph walk reached max_depth bound (%d)", self._max_depth)
            return
        if summary.files_discovered >= max_files:
            summary.status = "partial"
            return
        try:
            children = self.list_children(drive_id, folder_id)
        except MicrosoftApiError as exc:
            summary.files_failed += 1
            summary.errors.append(ScanError(code=_map_error_code(exc), message=_safe_message(exc)))
            summary.status = "partial"
            return

        for child in children:
            if summary.files_discovered >= max_files:
                summary.status = "partial"
                break
            summary.files_discovered += 1

            if child.is_folder:
                self._walk(
                    drive_id,
                    child.item_id,
                    scanner,
                    context,
                    integration_id,
                    user_id,
                    site_id,
                    summary,
                    visited,
                    depth + 1,
                    max_files,
                    heartbeat,
                )
                continue

            result = self._scan_one(drive_id, child.item_id, scanner, context, integration_id, user_id)
            self._accumulate(summary, result)
            if heartbeat is not None and summary.files_discovered % _HEARTBEAT_EVERY_FILES == 0:
                heartbeat()

    def _scan_one(
        self,
        drive_id: str,
        item_id: str,
        scanner: ConnectorScanner,
        context: ScanContext | None,
        integration_id: str | None,
        user_id: str | None,
    ) -> ScanResult:
        try:
            item = self._fetch_item(drive_id, item_id)
        except MicrosoftApiError as exc:
            return self._error_result(item_id, _map_error_code(exc), _safe_message(exc))
        if item.is_folder:
            return self._error_result(item_id, ScanErrorCode.UNSUPPORTED_FORMAT, "item is a folder")
        content = self._retrieve_content(item)
        if content is None:
            return self._error_result(
                item_id,
                ScanErrorCode.UNSUPPORTED_FORMAT,
                "content could not be retrieved",
            )
        return self._scan_bytes(item, content, scanner, context, integration_id, user_id)

    def _scan_bytes(
        self,
        item: MicrosoftGraphItem,
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
                "Graph item format cannot be scanned by the SecuRedact pipeline",
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
        item: MicrosoftGraphItem,
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

    def _error_result(self, item_id: str, code: ScanErrorCode, message: str) -> ScanResult:
        # Use a fingerprint for the resource_id even in error cases
        fingerprint = self._compute_fingerprint("driveItem", item_id)
        return ScanResult(
            status=ScanStatus.ERROR,
            resource_id=fingerprint or item_id,
            platform=MICROSOFT_365_PLATFORM,
            org_id=self._identity.org_id,
            tenant_id=self._identity.tenant_id,
            error=ScanError(code=code, message=message),
        )

    def _retrieve_content(self, item: MicrosoftGraphItem) -> bytes | None:
        """Retrieve bytes for a file, or ``None`` if unsupported/unretrievable.

        Text formats are downloaded with the ``@microsoft.graph.downloadUrl``.
        Binary formats not supported by the existing pipeline return ``None``.
        """

        if item.is_folder:
            return None

        if item.size is not None and item.size > self._max_download_bytes:
            return None

        if item.mime_type and is_text_format(mime_type=item.mime_type, name=item.name):
            if item.download_url:
                try:
                    return self._transport.get_content(
                        item.download_url,
                        max_bytes=self._max_download_bytes,
                    )
                except MicrosoftApiError:
                    return None
            # Fallback to Graph content endpoint
            try:
                return self._transport.get_content(
                    f"drives/{item.drive_id}/items/{item.item_id}/content",
                    max_bytes=self._max_download_bytes,
                )
            except MicrosoftApiError:
                return None

        # Binary formats not supported by the existing pipeline.
        return None

    def _fetch_item(self, drive_id: str, item_id: str) -> MicrosoftGraphItem:
        data = self._transport.get_json(
            f"drives/{drive_id}/items/{item_id}?$select={_quote(_SELECT_FIELDS)}"
        )
        return _parse_item(data)

    def _compute_fingerprint(self, resource_type: ResourceType, resource_id: str | None) -> str | None:
        """Compute a privacy-safe fingerprint for a resource.

        Returns None if fingerprinting is not configured or resource_id is None.
        """
        if self._fingerprint_config is None or resource_id is None:
            return None
        return compute_resource_fingerprint(self._fingerprint_config, resource_type, resource_id)

    def _to_resource(
        self, item: MicrosoftGraphItem, *, extracted_text: str | None = None
    ) -> ConnectorResource:
        self._emit_access(item)
        # Use privacy-safe fingerprint as resource_id instead of raw Graph ID
        resource_fingerprint = self._compute_fingerprint("driveItem", item.item_id)
        parent_fingerprint = self._compute_fingerprint("folder", item.parent_id) if item.parent_id else None
        drive_fingerprint = self._compute_fingerprint("drive", item.drive_id) if item.drive_id else None
        site_fingerprint = self._compute_fingerprint("site", getattr(self, "_current_site_id", None)) if getattr(self, "_current_site_id", None) else None

        return ConnectorResource(
            resource_id=resource_fingerprint or item.item_id,
            platform=MICROSOFT_365_PLATFORM,
            resource_kind=ResourceKind.FILE,
            org_id=self._identity.org_id,
            tenant_id=self._identity.tenant_id,
            parent_id=parent_fingerprint,
            name=item.name,
            mime_type=item.mime_type,
            size_bytes=item.size,
            external_url=None,  # web_url contains path info - don't send to control plane
            content_ref=resource_fingerprint,
            metadata={
                "source_type": item.source_type,
                "drive_fingerprint": drive_fingerprint,
                "site_fingerprint": site_fingerprint,
                "is_folder": item.is_folder,
                "mime_type": item.mime_type,
                "created_date_time": item.created_date_time,
                "last_modified_date_time": item.last_modified_date_time,
                "e_tag": item.e_tag,
            },
            extracted_text=extracted_text,
        )

    def _emit_access(self, item: MicrosoftGraphItem) -> None:
        # Use fingerprint in audit log, not raw ID
        resource_fingerprint = self._compute_fingerprint("driveItem", item.item_id)
        emit_audit_event(
            build_audit_event(
                AuditEventType.CONNECTOR_RESOURCE_ACCESSED,
                action="read",
                operation="network_read",
                source=resource_fingerprint or item.item_id,
                provider=MICROSOFT_365_PLATFORM,
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
                    "drive_fingerprint": self._compute_fingerprint("drive", item.drive_id) if item.drive_id else None,
                },
            )
        )

    @staticmethod
    def _next_link_url(base_relative: str, data: dict[str, Any]) -> str | None:
        # Graph uses @odata.nextLink for pagination
        next_link = data.get("@odata.nextLink")
        if not next_link:
            return None
        # Convert absolute URL to relative path
        if next_link.startswith(CANONICAL_GRAPH_BASE):
            return next_link[len(CANONICAL_GRAPH_BASE) + 1:]
        return None

    @property
    def _current_site_id(self) -> str | None:
        # Used by _to_resource for metadata; set during scan operations
        return getattr(self, "__current_site_id", None)

    @_current_site_id.setter
    def _current_site_id(self, value: str | None) -> None:
        self.__current_site_id = value


def _normalize_content(mime_type: str | None, name: str, raw: bytes) -> NormalizedContent | None:
    """Return :class:`NormalizedContent` for a supported format, else ``None``."""

    if mime_type in FILE_MIME_TYPES:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return NormalizedContent(text=text, source_format=mime_type, char_count=len(text))

    # Other text formats go through the shared extractor.
    return extract_text(raw, mime_type=mime_type, name=name)


def _map_error_code(exc: MicrosoftApiError) -> ScanErrorCode:
    if exc.status_code in (401, 403):
        return ScanErrorCode.UNAUTHORIZED
    if exc.status_code == 404:
        return ScanErrorCode.RETRIEVAL_FAILED
    if exc.status_code == 429:
        return ScanErrorCode.RATE_LIMITED
    return ScanErrorCode.RETRIEVAL_FAILED


def _safe_message(exc: MicrosoftApiError) -> str:
    # Never embed token/exception internals; keep a stable, safe summary.
    if exc.status_code == 401:
        return "Microsoft authorization failed or token was revoked"
    if exc.status_code == 403:
        return "Microsoft Graph refused the request (insufficient scope or API disabled)"
    if exc.status_code == 404:
        return "Microsoft Graph item was not found"
    if exc.status_code == 429:
        return "Microsoft Graph rate limit exceeded; retry later"
    return "Microsoft Graph request failed"


def safe_diagnostic(exc: MicrosoftApiError) -> dict[str, object]:
    """Return provider-safe diagnostic metadata for an error (no secrets).

    Only non-credential fields are included: a stable safe message, the HTTP
    status, the Graph error ``reason`` token, a safe endpoint/path (query
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