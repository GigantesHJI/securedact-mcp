# SPDX-License-Identifier: Apache-2.0
"""CLI surface for the Google Workspace / Drive connector (GWS-110).

Provides ``securedact-mcp google auth|status|list|scan``. Every command fails closed
when Google is not enabled or configured. Credentials/tokens are never printed.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any, TextIO

from securedact_core import SecuredactEngine
from securedact_core.connectors.contracts import ScanContext
from securedact_core.connectors.google import GoogleApiError, safe_diagnostic
from securedact_core.production import build_production_engine

from . import auth as google_auth
from .client import GoogleConnectorClient
from .config import GoogleConfigError, GoogleConnectorConfig, load_google_config


def _engine() -> SecuredactEngine:
    # Regex-only deterministic engine is sufficient for connector scanning and
    # avoids requiring a contextual model download just to run the CLI.
    return SecuredactEngine(build_production_engine(require_contextual=False))


def _client(config: GoogleConnectorConfig | None = None) -> GoogleConnectorClient:
    cfg = config or load_google_config(require_enabled=True)
    return GoogleConnectorClient(cfg, _engine())


def cmd_auth(
    *,
    code: str | None = None,
    revoke: bool = False,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
) -> int:
    try:
        config = load_google_config(require_enabled=True)
    except GoogleConfigError as exc:
        print(f"Google connector error: {exc}", file=output)
        return 2

    if revoke:
        google_auth.revoke_credentials(config)
        print("Google authorization revoked and local token removed.", file=output)
        return 0

    url, state = google_auth.get_authorization_url(config)
    print("Open the following URL in a browser and authorize SecuRedact:", file=output)
    print(url, file=output)
    print(file=output)
    if code is None:
        raw = input_fn("Paste the 'code' value (or the full redirect URL): ").strip()
        code = _extract_code(raw)
    if not code:
        print("No authorization code provided.", file=output)
        return 2
    try:
        google_auth.exchange_code(config, code, state=state)
    except Exception as exc:
        print(f"Google authorization failed: {exc}", file=output)
        return 2
    print(
        "Google authorization stored securely. You can now run 'securedact-mcp google list'.",
        file=output,
    )
    return 0


def _extract_code(raw: str) -> str:
    if "code=" in raw:
        return raw.split("code=", 1)[1].split("&")[0].strip()
    return raw.strip()


def cmd_status(
    *,
    output: TextIO = sys.stdout,
    profile: str = "default",
    data_dir: str | Path | None = None,
) -> int:
    try:
        config = load_google_config(require_enabled=False, profile=profile, data_dir=data_dir)
    except GoogleConfigError as exc:
        print(json.dumps({"provider_enabled": False, "error": str(exc)}), file=output)
        return 2

    creds = google_auth.load_credentials(config)

    # Determine OAuth client configuration status
    oauth_client_configured = False
    oauth_client_source = "none"
    if config.managed:
        oauth_client_configured = bool(config.client_id and config.client_secret)
        oauth_client_source = "managed"
    elif config.client_id and config.client_secret:
        oauth_client_configured = True
        oauth_client_source = "byo"
    elif config.client_id and not config.client_secret:
        # Installed app without secret (public client)
        oauth_client_configured = True
        oauth_client_source = "installed_no_secret"

    # Check if machine runtime has Google dependencies (agent_healthy)
    # This is a lightweight check - just try to import the modules
    agent_healthy = False
    try:
        import google.auth
        import google.oauth2.credentials
        import google_auth_oauthlib.flow
        import requests
        agent_healthy = True
    except ImportError:
        agent_healthy = False

    user_authorized = creds is not None
    ready_to_scan = (
        config.enabled
        and oauth_client_configured
        and user_authorized
        and agent_healthy
    )

    status = {
        "provider_enabled": config.enabled,
        "oauth_client_configured": oauth_client_configured,
        "oauth_client_source": oauth_client_source,
        "user_authorized": user_authorized,
        "agent_healthy": agent_healthy,
        "ready_to_scan": ready_to_scan,
        "redirect_uri": config.redirect_uri,
        "scopes": config.scopes,
        "read_only": not _has_write(config.scopes),
        "managed_app": config.managed,
        "client_type": config.client_type,
        "token_path": str(config.token_path),
    }
    print(json.dumps(status, indent=2), file=output)
    return 0


def _has_write(scopes: list[str]) -> bool:
    from securedact_core.connectors.google import has_write_scope

    return has_write_scope(scopes)


def cmd_list(
    *,
    drive_id: str | None = None,
    folder_id: str | None = None,
    output: TextIO = sys.stdout,
) -> int:
    try:
        client = _client()
        assert client is not None
    except GoogleConfigError as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    try:
        shared = [d.model_dump() for d in client.list_shared_drives()]
        children = [c.model_dump() for c in client.list_children(folder_id, drive_id=drive_id)]
    except GoogleApiError as exc:
        print(json.dumps(safe_diagnostic(exc)), file=output)
        return 2
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    print(json.dumps({"shared_drives": shared, "children": children}, indent=2), file=output)
    return 0


def cmd_scan(
    *,
    file_id: str | None = None,
    folder_id: str | None = None,
    drive_id: str | None = None,
    policy: str = "strict_external_ai",
    max_files: int = 0,
    output: TextIO = sys.stdout,
) -> int:
    try:
        client = _client()
        assert client is not None
    except GoogleConfigError as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    context = ScanContext(policy=policy)
    result: object
    try:
        if file_id:
            result = client.scan_file(file_id, context)
        elif folder_id:
            result = client.scan_folder(
                folder_id,
                context,
                drive_id=drive_id,
                max_files=max_files,
            )
        else:
            result = client.scan_drive(
                context,
                drive_id=drive_id,
                max_files=max_files,
            )
    except GoogleApiError as exc:
        print(json.dumps(safe_diagnostic(exc)), file=output)
        return 2
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    print(json.dumps(_safe_dump(result), indent=2), file=output)
    return 0


def _safe_dump(obj: object) -> object:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", exclude_none=True)
    return str(obj)


def build_google_parser(subparsers: Any) -> None:
    google = subparsers.add_parser("google", help="Google Workspace / Drive read-only connector")
    google_commands = google.add_subparsers(dest="google_command", required=True)

    auth = google_commands.add_parser("auth", help="authorize SecuRedact with Google")
    auth.add_argument("--code", help="authorization code from the redirect URL")
    auth.add_argument("--revoke", action="store_true", help="revoke and forget tokens")

    status_parser = google_commands.add_parser("status", help="show Google connector status")
    status_parser.add_argument("--profile", default="default", help="OAuth token profile (default: default)")
    status_parser.add_argument("--data-dir", help="machine data directory (default: SECUREDACT_APP_DATA_DIR)")

    list_cmd = google_commands.add_parser("list", help="list Shared Drives and Drive items")
    list_cmd.add_argument("--drive-id", help="Shared Drive id")
    list_cmd.add_argument("--folder-id", help="folder file id")

    scan = google_commands.add_parser("scan", help="scan a Drive file/folder/drive")
    scan.add_argument("--file-id", help="scan a single file by id")
    scan.add_argument("--folder-id", help="recursively scan a folder by id")
    scan.add_argument("--drive-id", help="scan a Shared Drive (omit for My Drive)")
    scan.add_argument("--policy", default="strict_external_ai")
    scan.add_argument("--max-files", type=int, default=0)


def run_google(
    arguments: Any,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
) -> int:
    command = arguments.google_command
    if command == "auth":
        return cmd_auth(
            code=getattr(arguments, "code", None),
            revoke=bool(getattr(arguments, "revoke", False)),
            input_fn=input_fn,
            output=output,
        )
    if command == "status":
        return cmd_status(
            output=output,
            profile=getattr(arguments, "profile", "default"),
            data_dir=getattr(arguments, "data_dir", None),
        )
    if command == "list":
        return cmd_list(
            drive_id=getattr(arguments, "drive_id", None),
            folder_id=getattr(arguments, "folder_id", None),
            output=output,
        )
    if command == "scan":
        return cmd_scan(
            file_id=getattr(arguments, "file_id", None),
            folder_id=getattr(arguments, "folder_id", None),
            drive_id=getattr(arguments, "drive_id", None),
            policy=getattr(arguments, "policy", "strict_external_ai"),
            max_files=getattr(arguments, "max_files", 0) or 0,
            output=output,
        )
    return 2
