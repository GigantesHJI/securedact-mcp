# SPDX-License-Identifier: Apache-2.0
"""High-level Google connector client (control plane, GWS-110).

Wires configuration, credential storage, OAuth, the concrete transport, the
core :class:`GoogleDriveBrowser`, and the :class:`ConnectorScanner` into a
single facade used by the CLI. Keeps the MCP server and existing integrations
untouched; Google is an additive, opt-in capability.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from securedact_core.connectors import ConnectorScanner
from securedact_core.connectors.contracts import (
    ConnectorCapability,
    ConnectorIdentity,
    ScanContext,
)
from securedact_core.connectors.google import (
    DriveScanSummary,
    GoogleApiError,
    GoogleDriveBrowser,
    GoogleDriveItem,
    SharedDrive,
    default_connector_scopes,
    has_write_scope,
)
from securedact_core.connectors.scan import ScanResult

from .auth import require_valid_credentials
from .config import GoogleConfigError, GoogleConnectorConfig


def _assert_readonly(config: GoogleConnectorConfig) -> None:
    if has_write_scope(config.scopes):
        raise GoogleConfigError("Google connector is configured with a write scope")


class GoogleConnectorClient:
    """End-user facade for the read-only Google Drive connector."""

    def __init__(
        self,
        config: GoogleConnectorConfig,
        engine: Any,
        *,
        transport: Any = None,
        user_id: str | None = None,
    ) -> None:
        _assert_readonly(config)
        self._config = config
        self._engine = engine
        self._browser: GoogleDriveBrowser | None = None
        self._transport = transport
        self._user_id_override = user_id

    def _ensure_browser(self) -> GoogleDriveBrowser:
        if self._browser is not None:
            return self._browser
        _assert_readonly(self._config)
        # A transport may be injected (e.g. by tests or a recorded-replay smoke
        # run). When it is, the live OAuth credential lookup is bypassed and the
        # injected transport's verified identity is used. The default production
        # path still resolves real local credentials and the real HTTP transport.
        if self._transport is None:
            from .transport import GoogleApiTransport

            credentials = require_valid_credentials(self._config)
            transport = GoogleApiTransport(credentials)
        else:
            transport = self._transport
        user_id = self._user_id_override or transport.user_id
        identity = ConnectorIdentity(
            org_id="google",
            integration_id="google_workspace",
            tenant_id=user_id,
            platform="google_workspace",
            user_id=user_id,
        )
        self._transport = transport
        self._browser = GoogleDriveBrowser(identity, transport)
        return self._browser

    def capabilities(self) -> frozenset[ConnectorCapability]:
        return self._ensure_browser().capabilities()

    def list_shared_drives(self) -> list[SharedDrive]:
        return self._ensure_browser().list_shared_drives()

    def list_children(
        self, folder_id: str | None = None, *, drive_id: str | None = None
    ) -> list[GoogleDriveItem]:
        return self._ensure_browser().list_children(folder_id, drive_id=drive_id)

    def scan_file(
        self,
        file_id: str,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
    ) -> ScanResult:
        scanner = ConnectorScanner(self._engine)
        return self._ensure_browser().select_and_scan(
            file_id, scanner, context, integration_id=integration_id, user_id=user_id
        )

    def scan_folder(
        self,
        folder_id: str,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
        drive_id: str | None = None,
        max_files: int = 0,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        scanner = ConnectorScanner(self._engine)
        return self._ensure_browser().scan_folder(
            folder_id,
            scanner,
            context,
            integration_id=integration_id,
            user_id=user_id,
            drive_id=drive_id,
            max_files=max_files,
            heartbeat=heartbeat,
        )

    def scan_drive(
        self,
        context: ScanContext | None = None,
        *,
        drive_id: str | None = None,
        integration_id: str | None = None,
        user_id: str | None = None,
        max_files: int = 0,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        scanner = ConnectorScanner(self._engine)
        return self._ensure_browser().scan_drive(
            scanner,
            context,
            drive_id=drive_id,
            integration_id=integration_id,
            user_id=user_id,
            max_files=max_files,
            heartbeat=heartbeat,
        )


def build_client(
    config: GoogleConnectorConfig,
    engine: Any,
    *,
    transport: Any = None,
    user_id: str | None = None,
) -> GoogleConnectorClient:
    return GoogleConnectorClient(config, engine, transport=transport, user_id=user_id)


__all__ = [
    "GoogleApiError",
    "GoogleConfigError",
    "GoogleConnectorClient",
    "GoogleConnectorConfig",
    "build_client",
    "default_connector_scopes",
]
