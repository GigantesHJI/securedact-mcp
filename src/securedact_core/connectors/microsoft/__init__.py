# SPDX-License-Identifier: Apache-2.0
"""Microsoft 365 / Microsoft Graph read-only connector (M365-102).

This is the *core-side, transport-agnostic* implementation of the Microsoft 365
browsing + scanning milestone. It deliberately contains **no Microsoft SDK import**
(``msal`` / ``msgraph-sdk`` are never referenced here) so the privacy core stays
Microsoft-free, mirroring the Google :mod:`securedact_core.connectors.google` design.

The browser consumes Microsoft Graph **v1.0 REST JSON** through an injected
:class:`MicrosoftGraphTransport`. The concrete transport -- which owns the OAuth
token, HTTPS session, host pinning and the verified user identity -- lives in
the control plane (``securedact_mcp.connectors.microsoft``) and is injected here.
That keeps the security/data plane (``securedact_core``) reusable and unit
testable with a mock transport.

Scope (M365-102, exact):
  * ``GET /me/drive`` (My Drive / OneDrive root)
  * ``GET /drives`` (Drive discovery)
  * ``GET /sites/{site-id}/drive`` (SharePoint document library)
  * ``GET /drives/{drive-id}/root/children`` (folder children)
  * ``GET /drives/{drive-id}/items/{item-id}/children`` (folder children by item)
  * ``GET /drives/{drive-id}/items/{item-id}`` (metadata)
  * ``GET /drives/{drive-id}/items/{item-id}/content`` (binary/text download)

Security invariants:
  * Fixed Graph host (transport ``base_url`` must equal the canonical v1.0 base).
  * Least-privilege scope construction: read-only scanning requests
    ``Files.Read``, ``Sites.Read.All``, ``User.Read`` only. No write scope
    (``Files.ReadWrite``, ``Sites.ReadWrite.All``) is ever requested by this milestone.
  * Server-resolved identity: ``org_id``/``tenant_id`` come from the
    server-resolved :class:`ConnectorIdentity`, never from browser input.
  * Identifier validation: every Microsoft id used to build a path is validated.
  * Trashed/deleted items are excluded by default.
  * No raw resource ids or tokens are written to logs.
"""

from __future__ import annotations

from .browser import (
    _HEARTBEAT_EVERY_FILES,
    CANONICAL_GRAPH_BASE,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_DOWNLOAD_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_PAGES,
    DEFAULT_PAGE_SIZE,
    FILE_MIME_TYPES,
    FOLDER_MIME_TYPE,
    GRAPH_API_VERSION,
    GRAPH_HOST,
    MICROSOFT_365_PLATFORM,
    SOURCE_TYPE_ONEDRIVE,
    SOURCE_TYPE_SHAREPOINT_DRIVE,
    SOURCE_TYPE_SHAREPOINT_SITE,
    DriveScanSummary,
    MicrosoftApiError,
    MicrosoftAuthError,
    MicrosoftDrive,
    MicrosoftGraphBrowser,
    MicrosoftGraphItem,
    MicrosoftGraphTransport,
    MicrosoftSite,
    build_graph_scopes,
    default_connector_scopes,
    has_write_scope,
    safe_diagnostic,
)

__all__ = [
    "CANONICAL_GRAPH_BASE",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_DOWNLOAD_BYTES",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_PAGES",
    "DEFAULT_PAGE_SIZE",
    "FILE_MIME_TYPES",
    "FOLDER_MIME_TYPE",
    "GRAPH_API_VERSION",
    "GRAPH_HOST",
    "MICROSOFT_365_PLATFORM",
    "SOURCE_TYPE_ONEDRIVE",
    "SOURCE_TYPE_SHAREPOINT_DRIVE",
    "SOURCE_TYPE_SHAREPOINT_SITE",
    "_HEARTBEAT_EVERY_FILES",
    "DriveScanSummary",
    "MicrosoftApiError",
    "MicrosoftAuthError",
    "MicrosoftDrive",
    "MicrosoftGraphBrowser",
    "MicrosoftGraphItem",
    "MicrosoftGraphTransport",
    "MicrosoftSite",
    "build_graph_scopes",
    "default_connector_scopes",
    "has_write_scope",
    "safe_diagnostic",
]
