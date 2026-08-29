# SPDX-License-Identifier: Apache-2.0
"""First-class Google Workspace onboarding for the managed agent.

This module turns the manual "copy a user's OAuth token into the machine store"
workaround into a supported ``securedact-mcp setup`` step. Google access is
authorized **locally on the machine** against the machine data root
(``C:\\ProgramData\\Securedact`` on Windows); the resulting encrypted OAuth token
is persisted directly to that root. OAuth material is never sent to the control
plane and never placed on the command line, in the environment, or in logs.

If a valid machine-local Google token already exists it is reused idempotently.
A user-profile token is never silently migrated; the operator is offered the
local authorization flow instead.

Both behaviours are fully injectable (config loader, auth flow, input reader,
output stream) so the policy is testable without Windows or network access.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

from .config import AgentConfig, AgentFiles
from .connectors import ConnectorBinding, ConnectorBindingStore
from .errors import AgentError
from .safe_log import scrub

GOOGLE_CONNECTOR_PLATFORM = "google_workspace"


class _GoogleConfigModule(Protocol):
    """Narrow boundary over the optional Google connector config loader."""

    def load_google_config(
        self,
        *,
        require_enabled: bool = ...,
        profile: str = ...,
        data_dir: str | Path | None = ...,
    ) -> Any: ...


class _GoogleAuthModule(Protocol):
    """Narrow boundary over the optional Google OAuth flow."""

    def get_authorization_url(self, config: Any) -> tuple[str, str]: ...
    def exchange_code(
        self, config: Any, code: str, *, state: str | None = ...
    ) -> dict[str, Any]: ...
    def load_credentials(self, config: Any) -> Any | None: ...


def _extract_code(raw: str) -> str:
    """Normalize a pasted redirect URL or bare ``code`` value to the code."""

    if "code=" in raw:
        return raw.split("code=", 1)[1].split("&")[0].strip()
    return raw.strip()


def authorize_google_machine(
    data_dir: Path | str,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
    config_module: _GoogleConfigModule | None = None,
    auth_module: _GoogleAuthModule | None = None,
    non_interactive: bool = False,
) -> bool:
    """Authorize Google locally on the machine (or reuse a valid machine token).

    Returns ``True`` when a valid machine-local Google credential exists or was
    just created. Returns ``False`` when Google is not enabled/configured, or when
    an interactive authorization could not be completed (e.g. non-interactive run).

    The OAuth token is written only to ``<data_dir>/google`` via the injected
    config's credential store; no OAuth material is ever placed on argv, in the
    environment, or in logs. A pre-existing valid machine token is reused
    idempotently; this function never reads or migrates a user-profile token.
    """

    from ..connectors.google import auth as default_auth
    from ..connectors.google.config import GoogleConfigError, load_google_config

    cfg_module = config_module or cast("_GoogleConfigModule", load_google_config)
    auth_mod = auth_module or default_auth

    machine_data = Path(data_dir)
    try:
        config = cfg_module.load_google_config(require_enabled=True, data_dir=machine_data)
    except GoogleConfigError as exc:
        print(f"Google Workspace is not enabled/configured: {scrub(str(exc))}", file=output)
        return False

    # Idempotent reuse: a valid machine-local token already exists.
    try:
        creds = auth_mod.load_credentials(config)
    except Exception:
        creds = None
    if creds is not None:
        print("Local Google authorization valid; reusing it.", file=output)
        return True

    if non_interactive:
        print(
            "Google authorization requires an interactive browser login. Re-run this "
            "step interactively (or run 'securedact-mcp google auth') to complete it.",
            file=output,
        )
        return False

    # First-class local authorization against the machine data root.
    try:
        url, state = auth_mod.get_authorization_url(config)
    except Exception as exc:
        print(f"Could not start Google authorization: {scrub(str(exc))}", file=output)
        return False
    print("Open a browser to authorize SecuRedact with Google Drive (read-only):", file=output)
    print(url, file=output)
    print(file=output)
    try:
        raw = input_fn("Paste the 'code' value (or the full redirect URL): ").strip()
    except (EOFError, StopIteration):
        print("No authorization code provided; Google authorization skipped.", file=output)
        return False
    code = _extract_code(raw)
    if not code:
        print("No authorization code provided; Google authorization skipped.", file=output)
        return False
    try:
        auth_mod.exchange_code(config, code, state=state)
    except Exception as exc:
        print(f"Google authorization failed: {scrub(str(exc))}", file=output)
        return False
    print("Authorized.", file=output)
    return True


def bind_google_machine(
    config: AgentConfig,
    integration_id: str,
    *,
    files: AgentFiles | None = None,
    profile: str = "default",
    binding_store_cls: type[ConnectorBindingStore] = ConnectorBindingStore,
) -> ConnectorBinding:
    """Create (or idempotently reuse/repair) the machine-local Google binding.

    The integration id is supplied by the operator from the SecuRedact dashboard
    (the control plane never supplies OAuth material). An existing valid binding
    for the same integration id + profile is reused; a stale binding (wrong
    platform/profile) is repaired; the store is keyed by integration id so no
    duplicate records are ever written. Uses the shipped binding mechanism.
    """

    from . import agent_runner

    if not integration_id:
        raise AgentError("a Google Workspace integration_id is required to create a local binding")
    store = binding_store_cls(files)
    existing = store.get(integration_id)
    if (
        existing is not None
        and existing.platform == GOOGLE_CONNECTOR_PLATFORM
        and existing.local_profile == profile
    ):
        # Idempotent reuse: the binding already matches exactly.
        return existing
    # Create or repair via the existing shipped binding mechanism.
    return agent_runner.bind_connector(
        config,
        integration_id,
        GOOGLE_CONNECTOR_PLATFORM,
        profile=profile,
        files=files,
    )


def _setx_exe() -> str:
    """Return an absolute path to ``setx.exe`` (avoids S607 partial-path use)."""

    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    return str(Path(sysroot) / "System32" / "setx.exe")


def _set_machine_env_var(key: str, value: str) -> None:
    """Publish a single non-secret variable at machine scope via ``setx /M``.

    Only non-secret operational variables are ever published this way. No OAuth
    token, client secret, lease secret, or entitlement JWT is ever written here.
    """

    setx = _setx_exe()
    if os.environ.get(key) == value:
        return
    try:
        import subprocess

        subprocess.run(  # noqa: S603 - absolute binary + literal args
            [setx, "/M", key, value],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - defensive
        print(f"could not set machine env {key}: {scrub(str(exc))}", file=sys.stderr)


def apply_google_machine_env(data_dir: Path | str) -> None:
    """Persist non-secret Google config at machine scope; encrypt the client secret.

    The OAuth client secret (and client id) are stored encrypted under the machine
    data root via :class:`GoogleClientConfigStore` so the SYSTEM-run scheduled task
    can load them after the setup PowerShell session closes and after a reboot -- without
    ever placing the secret in a machine-wide environment variable, argv, logs, or the
    control plane. Only the non-secret enable flag is published at machine scope (it is
    inherited by the SYSTEM-run scheduled task); the client id/secret are NOT written to
    the machine environment.

    Invariants preserved:
      * OAuth access/refresh tokens remain machine-local (separate token vault).
      * client secret remains machine-local (encrypted under the machine data root).
      * no secret in argv, no secret in logs, no secret sent to the control plane.
      * non-secret configuration (the enable flag) may remain in the machine environment.
    """

    from ..connectors.google.storage import GoogleClientConfigStore

    data_dir = Path(data_dir)
    env_client_id = os.environ.get("SECUREDACT_GOOGLE_CLIENT_ID")
    env_client_secret = os.environ.get("SECUREDACT_GOOGLE_CLIENT_SECRET")

    # Persist the client (app) config encrypted under the machine data root. This
    # is what lets the background task obtain the secret after reboot, without it
    # ever becoming a machine-wide environment variable.
    if env_client_id or env_client_secret:
        try:
            GoogleClientConfigStore(data_dir).save(env_client_id, env_client_secret)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"could not persist google client config: {scrub(str(exc))}", file=sys.stderr)

    # Only the non-secret enable flag is published at machine scope.
    if os.environ.get("SECUREDACT_GOOGLE_ENABLED") == "1":
        _set_machine_env_var("SECUREDACT_GOOGLE_ENABLED", "1")
