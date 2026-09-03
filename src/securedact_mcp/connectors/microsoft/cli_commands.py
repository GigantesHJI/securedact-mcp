# SPDX-License-Identifier: Apache-2.0
"""CLI surface for the Microsoft 365 / Graph connector (M365-102).

Provides ``securedact-mcp microsoft setup|auth|status|list|scan|targets``.
Every command fails closed when Microsoft is not enabled or configured.
Credentials/tokens are never printed.

The ``setup`` command persists the Microsoft Entra client (app) configuration
encrypted under the machine data root via :class:`MicrosoftClientConfigStore`
(the same store used by the SYSTEM-run scheduled task). The ``auth`` command
performs the local loopback OAuth flow using PKCE for a public client
(no client secret required for Desktop / Public-client apps), or with the
configured client secret for confidential clients.
"""

from __future__ import annotations

import getpass
import json
import sys
from collections.abc import Callable
from typing import Any, TextIO

from securedact_core import SecuredactEngine
from securedact_core.connectors.contracts import ScanContext
from securedact_core.connectors.microsoft import MicrosoftApiError, safe_diagnostic
from securedact_core.production import build_production_engine

from . import auth as microsoft_auth
from . import target_registry as microsoft_targets_registry
from .client import MicrosoftConnectorClient
from .config import (
    MicrosoftConfigError,
    MicrosoftConnectorConfig,
    load_microsoft_config,
)


def _engine() -> SecuredactEngine:
    # Regex-only deterministic engine is sufficient for connector scanning and
    # avoids requiring a contextual model download just to run the CLI.
    return SecuredactEngine(build_production_engine(require_contextual=False))


def _client(config: MicrosoftConnectorConfig | None = None) -> MicrosoftConnectorClient:
    cfg = config or load_microsoft_config(require_enabled=True)
    return MicrosoftConnectorClient(cfg, _engine())


# ---------------------------------------------------------------------------
# setup / auth / status
# ---------------------------------------------------------------------------


def cmd_setup(
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    tenant_id: str | None = None,
    no_secret: bool = False,
    input_fn: Callable[[str], str] = input,
    secret_input_fn: Callable[[str], str] = getpass.getpass,
    output: TextIO = sys.stderr,
) -> int:
    """Persist the Microsoft Entra client config encrypted on the machine.

    For Desktop / Public-client apps the client secret is intentionally NOT
    required: PKCE protects the authorization-code exchange. Pass ``--no-secret``
    (or simply leave the secret prompt empty) to skip the secret.

    For confidential-client apps supply both ``--client-id`` and the secret at
    the prompt.
    """

    from securedact_core.app_paths import SecuredactPaths

    from .client_config_store import MicrosoftClientConfigStore

    data_dir = SecuredactPaths.resolve().root

    if not client_id:
        try:
            raw = input_fn("Microsoft Entra client (application) id: ").strip()
        except EOFError:
            print("No client id provided.", file=output)
            return 2
        client_id = raw or None
    if not client_id:
        print("Microsoft client id is required.", file=output)
        return 2

    if not tenant_id:
        try:
            raw = input_fn("Microsoft Entra tenant id (press Enter for 'common'): ").strip()
        except EOFError:
            raw = ""
        tenant_id = raw or "common"

    secret: str | None = None
    if not no_secret and client_secret is None:
        try:
            typed = secret_input_fn(
                "Microsoft Entra client secret (Enter to skip for public-client / PKCE): "
            ).strip()
        except Exception:
            typed = ""
        secret = typed or None
    elif client_secret:
        secret = client_secret

    try:
        MicrosoftClientConfigStore(data_dir).save(
            client_id,
            secret,
            tenant_id=tenant_id,
        )
    except Exception as exc:
        print(f"Microsoft setup failed: {type(exc).__name__}", file=output)
        return 2

    print(
        "Microsoft setup stored. Enable the connector in this shell: "
        "$env:SECUREDACT_MICROSOFT_ENABLED='1'",
        file=output,
    )
    print("Next: securedact-mcp microsoft auth", file=output)
    return 0


def cmd_auth(
    *,
    revoke: bool = False,
    timeout_seconds: float = 300.0,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
) -> int:
    """Run the local Microsoft Graph OAuth loopback flow and persist the token.

    The flow uses PKCE for public-client apps and falls back to the
    confidential-client flow only when a client secret is configured.
    """

    try:
        config = load_microsoft_config(require_enabled=True)
    except MicrosoftConfigError as exc:
        print(f"Microsoft connector error: {exc}", file=output)
        return 2

    if revoke:
        try:
            microsoft_auth.revoke_credentials(config)
            print("Microsoft authorization revoked and local token removed.", file=output)
        except Exception as exc:
            print(f"Microsoft revocation failed: {type(exc).__name__}", file=output)
        return 0

    outcome = microsoft_auth.run_local_oauth(
        config,
        open_browser=True,
        timeout_seconds=timeout_seconds,
    )
    payload = outcome.to_payload()
    print(json.dumps(payload), file=output)
    if not outcome.authorized:
        return 2
    print(
        "Microsoft authorization stored securely. Next: securedact-mcp microsoft status",
        file=output,
    )
    return 0


def cmd_status(
    *,
    output: TextIO = sys.stdout,
) -> int:
    try:
        config = load_microsoft_config(require_enabled=True)
    except MicrosoftConfigError as exc:
        print(json.dumps({"enabled": False, "error": str(exc)}), file=output)
        return 2

    creds = microsoft_auth.load_credentials(config)
    status = {
        "enabled": config.enabled,
        "client_configured": bool(config.client_id),
        "client_secret_configured": bool(config.client_secret),
        "tenant_id": config.tenant_id,
        "redirect_uri": config.redirect_uri,
        "scopes": config.scopes,
        "read_only": not _has_write(config.scopes),
        "token_present": creds is not None,
    }
    print(json.dumps(status, indent=2), file=output)
    return 0


def _has_write(scopes: list[str]) -> bool:
    from securedact_core.connectors.microsoft import has_write_scope

    return has_write_scope(scopes)


# ---------------------------------------------------------------------------
# list / scan
# ---------------------------------------------------------------------------


def cmd_list(
    *,
    drive_id: str | None = None,
    folder_id: str | None = None,
    site_id: str | None = None,
    output: TextIO = sys.stdout,
) -> int:
    try:
        client = _client()
        assert client is not None
    except MicrosoftConfigError as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    try:
        drives = [d.model_dump() for d in client.list_drives()]
        sites = [s.model_dump() for s in client.list_sites()]
        children = []
        if drive_id:
            children = [c.model_dump() for c in client.list_children(drive_id, folder_id)]
        if site_id:
            site_drive = client.get_site_drive(site_id)
            children = [
                c.model_dump() for c in client.list_children(site_drive.drive_id, folder_id)
            ]
    except MicrosoftApiError as exc:
        print(json.dumps(safe_diagnostic(exc)), file=output)
        return 2
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    print(
        json.dumps({"drives": drives, "sites": sites, "children": children}, indent=2), file=output
    )
    return 0


def cmd_scan(
    *,
    drive_id: str | None = None,
    item_id: str | None = None,
    folder_id: str | None = None,
    site_id: str | None = None,
    policy: str = "strict_external_ai",
    max_files: int = 0,
    output: TextIO = sys.stdout,
) -> int:
    try:
        client = _client()
        assert client is not None
    except MicrosoftConfigError as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    context = ScanContext(policy=policy)
    result: object
    try:
        if item_id and drive_id:
            result = client.scan_file(drive_id, item_id, context)
        elif folder_id and drive_id:
            result = client.scan_folder(
                drive_id,
                folder_id,
                context,
                site_id=site_id,
                max_files=max_files,
            )
        elif drive_id:
            result = client.scan_drive(
                drive_id,
                context,
                site_id=site_id,
                max_files=max_files,
            )
        else:
            print(
                json.dumps(
                    {
                        "error": "specify --drive-id (and optionally --item-id, --folder-id, --site-id)"
                    }
                ),
                file=output,
            )
            return 2
    except MicrosoftApiError as exc:
        print(json.dumps(safe_diagnostic(exc)), file=output)
        return 2
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=output)
        return 2
    print(json.dumps(_safe_dump(result), indent=2), file=output)
    return 0


# ---------------------------------------------------------------------------
# targets (privacy-safe local target registry)
# ---------------------------------------------------------------------------


def cmd_targets_list(
    *,
    integration_id: str | None = None,
    output: TextIO = sys.stdout,
) -> int:
    """List locally registered Microsoft targets (opaque ids + display labels)."""

    from securedact_core.app_paths import SecuredactPaths

    store = microsoft_targets_registry.TargetRegistryStore(SecuredactPaths.resolve().root)
    try:
        items = store.list(integration_id=integration_id)
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}), file=output)
        return 2

    # Show operator-friendly labels ONLY. Raw Graph ids are not emitted in the
    # CLI output by design; they never leave the local machine.
    safe = [
        {
            "target_id": item.target_id,
            "kind": item.kind,
            "integration_id": item.integration_id,
            "label": item.label,
            "drive_fingerprint": item.drive_fingerprint,
            "folder_fingerprint": item.folder_fingerprint,
            "site_fingerprint": item.site_fingerprint,
            "created_at": item.created_at,
        }
        for item in items
    ]
    print(json.dumps({"targets": safe}, indent=2), file=output)
    return 0


def cmd_targets_add(
    *,
    drive_id: str | None = None,
    folder_id: str | None = None,
    site_id: str | None = None,
    folder_name: str | None = None,
    integration_id: str | None = None,
    label: str | None = None,
    output: TextIO = sys.stdout,
) -> int:
    """Register a Microsoft target and return its opaque target_id.

    Resolution precedence:

    * if ``folder_name`` is supplied and ``drive_id`` is supplied, walk the
      bounded list_children tree to find the folder whose name matches; this
      is what customers should use for the OneDrive folder smoke test.
    * otherwise the caller must supply the raw Graph ids, which the operator
      obtained locally from ``microsoft list``.

    Either way, only opaque identifiers and the human-readable label are
    returned; raw Graph ids are persisted encrypted under the machine root
    and never sent to the control plane.
    """

    from securedact_core.app_paths import SecuredactPaths

    if not integration_id:
        print(
            json.dumps({"error": "--integration-id is required"}),
            file=output,
        )
        return 2

    if folder_name and drive_id and not folder_id:
        try:
            client = _client()
        except MicrosoftConfigError as exc:
            print(json.dumps({"error": str(exc)}), file=output)
            return 2
        resolved = _find_folder_by_name(client, drive_id, folder_name, site_id=site_id)
        if resolved is None:
            print(
                json.dumps({"error": "folder not found by name; run microsoft list to verify"}),
                file=output,
            )
            return 2
        drive_id = resolved.drive_id
        folder_id = resolved.item_id

    if not drive_id or not folder_id:
        print(
            json.dumps(
                {
                    "error": (
                        "specify --drive-id and (--folder-id or --folder-name) "
                        "or supply --site-id --drive-id --folder-id for SharePoint"
                    ),
                }
            ),
            file=output,
        )
        return 2

    store = microsoft_targets_registry.TargetRegistryStore(SecuredactPaths.resolve().root)
    record = microsoft_targets_registry.LocalTargetRecord.new_one_drive_folder(
        integration_id=integration_id,
        drive_id=drive_id,
        folder_id=folder_id,
        site_id=site_id,
        label=label or folder_name,
    )
    try:
        store.add(record)
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}), file=output)
        return 2

    # Operator-visible output: only the opaque target_id + label. Raw Graph ids
    # are intentionally NOT echoed; they live in the encrypted local store.
    print(
        json.dumps(
            {
                "target_id": record.target_id,
                "kind": record.kind,
                "integration_id": record.integration_id,
                "label": record.label,
                "drive_fingerprint": record.drive_fingerprint,
                "folder_fingerprint": record.folder_fingerprint,
                "site_fingerprint": record.site_fingerprint,
            },
            indent=2,
        ),
        file=output,
    )
    return 0


def cmd_targets_remove(
    *,
    target_id: str,
    output: TextIO = sys.stdout,
) -> int:
    from securedact_core.app_paths import SecuredactPaths

    store = microsoft_targets_registry.TargetRegistryStore(SecuredactPaths.resolve().root)
    removed = store.remove(target_id)
    print(json.dumps({"removed": removed, "target_id": target_id}, indent=2), file=output)
    return 0 if removed else 2


def _find_folder_by_name(
    client: MicrosoftConnectorClient,
    drive_id: str,
    folder_name: str,
    *,
    site_id: str | None,
    max_depth: int = 6,
    max_items: int = 5000,
) -> Any:
    """Bounded local walk of a drive to find a folder by exact name.

    Returns the matching :class:`MicrosoftGraphItem` or ``None``. The walk is
    bounded so a single discovery call cannot walk unbounded customer data.
    """

    seen: set[str] = set()
    queue: list[tuple[str | None, int]] = [(None, 0)]
    visited = 0
    while queue:
        folder_id, depth = queue.pop(0)
        if visited >= max_items:
            return None
        if depth > max_depth:
            continue
        try:
            children = client.list_children(drive_id, folder_id)
        except MicrosoftApiError:
            return None
        visited += 1
        for child in children:
            if child.item_id in seen:
                continue
            seen.add(child.item_id)
            if child.is_folder:
                if child.name == folder_name:
                    return child
                queue.append((child.item_id, depth + 1))
    return None


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _safe_dump(obj: object) -> object:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", exclude_none=True)
    return str(obj)


def build_microsoft_parser(subparsers: Any) -> None:
    microsoft = subparsers.add_parser("microsoft", help="Microsoft 365 / Graph read-only connector")
    microsoft_commands = microsoft.add_subparsers(dest="microsoft_command", required=True)

    setup = microsoft_commands.add_parser(
        "setup", help="store Microsoft Entra client config encrypted on this machine"
    )
    setup.add_argument("--client-id", help="Entra client (application) id")
    setup.add_argument(
        "--client-secret", help="Entra client secret (omit for public-client / PKCE)"
    )
    setup.add_argument("--tenant-id", help="Entra tenant id (defaults to 'common')")
    setup.add_argument(
        "--no-secret",
        action="store_true",
        help="explicitly skip the client secret prompt (public-client / PKCE flow)",
    )

    auth = microsoft_commands.add_parser("auth", help="authorize SecuRedact with Microsoft 365")
    auth.add_argument(
        "--revoke",
        action="store_true",
        help="revoke and forget tokens",
    )
    auth.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="loopback OAuth timeout in seconds (default: 300)",
    )

    microsoft_commands.add_parser("status", help="show Microsoft connector status")

    list_cmd = microsoft_commands.add_parser("list", help="list Drives, Sites, and Drive items")
    list_cmd.add_argument("--drive-id", help="Drive id (OneDrive or SharePoint library)")
    list_cmd.add_argument("--folder-id", help="folder item id")
    list_cmd.add_argument("--site-id", help="SharePoint site id")

    scan = microsoft_commands.add_parser("scan", help="scan a Drive file/folder/drive")
    scan.add_argument("--drive-id", help="Drive id (required)", required=True)
    scan.add_argument("--item-id", help="scan a single file by item id")
    scan.add_argument("--folder-id", help="recursively scan a folder by item id")
    scan.add_argument("--site-id", help="SharePoint site id (for SharePoint libraries)")
    scan.add_argument("--policy", default="strict_external_ai")
    scan.add_argument("--max-files", type=int, default=0)

    targets = microsoft_commands.add_parser(
        "targets", help="manage locally-registered, opaque Microsoft scan targets"
    )
    targets_cmds = targets.add_subparsers(dest="targets_command", required=True)

    t_list = targets_cmds.add_parser("list", help="list registered Microsoft targets")
    t_list.add_argument(
        "--integration-id",
        help="restrict to a single control-plane integration_id",
    )

    t_add = targets_cmds.add_parser(
        "add", help="register a Microsoft target and obtain its opaque id"
    )
    t_add.add_argument("--integration-id", required=True)
    t_add.add_argument("--drive-id", help="Drive id (OneDrive or SharePoint library)")
    t_add.add_argument("--folder-id", help="folder item id")
    t_add.add_argument("--site-id", help="SharePoint site id (SharePoint only)")
    t_add.add_argument(
        "--folder-name",
        help="resolve a folder by name (bounded local list_children walk)",
    )
    t_add.add_argument("--label", help="operator-visible label for the registered target")

    t_remove = targets_cmds.add_parser("remove", help="remove a registered target")
    t_remove.add_argument("--target-id", required=True)


def run_microsoft(
    arguments: Any,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
) -> int:
    command = arguments.microsoft_command
    if command == "setup":
        return cmd_setup(
            client_id=getattr(arguments, "client_id", None),
            client_secret=getattr(arguments, "client_secret", None),
            tenant_id=getattr(arguments, "tenant_id", None),
            no_secret=bool(getattr(arguments, "no_secret", False)),
            input_fn=input_fn,
            output=output,
        )
    if command == "auth":
        return cmd_auth(
            revoke=bool(getattr(arguments, "revoke", False)),
            timeout_seconds=float(getattr(arguments, "timeout", 300.0) or 300.0),
            input_fn=input_fn,
            output=output,
        )
    if command == "status":
        return cmd_status(output=output)
    if command == "list":
        return cmd_list(
            drive_id=getattr(arguments, "drive_id", None),
            folder_id=getattr(arguments, "folder_id", None),
            site_id=getattr(arguments, "site_id", None),
            output=output,
        )
    if command == "scan":
        return cmd_scan(
            drive_id=getattr(arguments, "drive_id", None),
            item_id=getattr(arguments, "item_id", None),
            folder_id=getattr(arguments, "folder_id", None),
            site_id=getattr(arguments, "site_id", None),
            policy=getattr(arguments, "policy", "strict_external_ai"),
            max_files=getattr(arguments, "max_files", 0) or 0,
            output=output,
        )
    if command == "targets":
        sub = arguments.targets_command
        if sub == "list":
            return cmd_targets_list(
                integration_id=getattr(arguments, "integration_id", None),
                output=output,
            )
        if sub == "add":
            return cmd_targets_add(
                drive_id=getattr(arguments, "drive_id", None),
                folder_id=getattr(arguments, "folder_id", None),
                site_id=getattr(arguments, "site_id", None),
                folder_name=getattr(arguments, "folder_name", None),
                integration_id=getattr(arguments, "integration_id", None),
                label=getattr(arguments, "label", None),
                output=output,
            )
        if sub == "remove":
            return cmd_targets_remove(
                target_id=getattr(arguments, "target_id", None),
                output=output,
            )
        return 2
    return 2
