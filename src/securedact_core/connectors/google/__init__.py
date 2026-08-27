# SPDX-License-Identifier: Apache-2.0
"""Google Workspace / Drive read-only connector (GWS-110) -- public surface.

Like the Microsoft subpackage, this stays free of any Google SDK so the privacy
core never pulls Google dependencies. The concrete OAuth/HTTP transport lives in
``securedact_mcp.connectors.google`` (the control plane) and is injected into
:class:`GoogleDriveBrowser`.
"""

from __future__ import annotations

from .drive import (
    CANONICAL_DRIVE_BASE,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_DOWNLOAD_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_PAGES,
    DEFAULT_PAGE_SIZE,
    DRIVE_API_VERSION,
    DRIVE_HOST,
    DRIVE_READONLY_SCOPE,
    GOOGLE_DOCS_MIME,
    GOOGLE_FOLDER_MIME,
    GOOGLE_SHEETS_MIME,
    GOOGLE_SHORTCUT_MIME,
    GOOGLE_SLIDES_MIME,
    GOOGLE_WORKSPACE_PLATFORM,
    SOURCE_TYPE_DRIVE,
    SOURCE_TYPE_MY_DRIVE,
    SOURCE_TYPE_SHARED_DRIVE,
    DriveScanSummary,
    GoogleApiError,
    GoogleAuthError,
    GoogleDriveBrowser,
    GoogleDriveItem,
    GoogleDriveTransport,
    SharedDrive,
    build_drive_scopes,
    default_connector_scopes,
    has_write_scope,
    safe_diagnostic,
)

__all__ = [
    "CANONICAL_DRIVE_BASE",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_DOWNLOAD_BYTES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_PAGES",
    "DEFAULT_PAGE_SIZE",
    "DRIVE_API_VERSION",
    "DRIVE_HOST",
    "DRIVE_READONLY_SCOPE",
    "GOOGLE_DOCS_MIME",
    "GOOGLE_FOLDER_MIME",
    "GOOGLE_SHEETS_MIME",
    "GOOGLE_SHORTCUT_MIME",
    "GOOGLE_SLIDES_MIME",
    "GOOGLE_WORKSPACE_PLATFORM",
    "SOURCE_TYPE_DRIVE",
    "SOURCE_TYPE_MY_DRIVE",
    "SOURCE_TYPE_SHARED_DRIVE",
    "DriveScanSummary",
    "GoogleApiError",
    "GoogleAuthError",
    "GoogleDriveBrowser",
    "GoogleDriveItem",
    "GoogleDriveTransport",
    "SharedDrive",
    "build_drive_scopes",
    "default_connector_scopes",
    "has_write_scope",
    "safe_diagnostic",
]
