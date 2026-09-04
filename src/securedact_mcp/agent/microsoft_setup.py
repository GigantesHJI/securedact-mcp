# SPDX-License-Identifier: Apache-2.0
"""Machine-local Microsoft 365 onboarding for ``securedact-mcp setup`` (M365-102).

Mirrors :mod:`securedact_mcp.agent.google_setup` so the Microsoft and Google
onboarding flows have a single, consistent UX surface and the same machine-only
data-root discipline. The agent wizard (and the standalone ``microsoft setup``
command) share every helper defined here, so behavior cannot drift between the
two entry points.

The module is **onboarding glue** — it owns the prompt sequence, machine-state
inspection, and machine-scope publication of the non-secret enable flag. The
actual authorization and connector-binding logic lives in
:mod:`securedact_mcp.connectors.microsoft.auth` and the existing
:mod:`securedact_mcp.agent.agent_runner`. This file is the single source of
truth for "Microsoft 365 onboarding" UX.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

from ..connectors.microsoft import auth as microsoft_auth
from ..connectors.microsoft import config as microsoft_config
from ..connectors.microsoft.config import MicrosoftConfigError
from ..connectors.microsoft.managed import (
    MANAGED_MICROSOFT_CLIENT_ID_ENV,
    is_managed_microsoft_available,
)
from .agent_runner import bind_connector
from .config import AgentConfig, AgentFiles
from .connectors import ConnectorBinding, ConnectorBindingStore
from .errors import AgentError
from .google_setup import _set_machine_env_var, machine_agent_files, normalize_integration_id
from .safe_log import scrub

# ---------------------------------------------------------------------------
# Constants (mirror the Google onboarding constants for the Microsoft surface)
# ---------------------------------------------------------------------------

# Connector platform name used in the agent's ``ConnectorBinding`` table.
# Must match ``MicrosoftScanProvider._resolve_local_profile`` / the platform
# value MicrosoftScanProvider expects.
MICROSOFT_CONNECTOR_PLATFORM = "microsoft365"

# Non-secret operational enable flag. Mirrors the Google env var. Published at
# machine scope via ``setx /M`` so the SYSTEM-run scheduled task inherits it.
MICROSOFT_ENABLED_ENV = "SECUREDACT_MICROSOFT_ENABLED"

# Non-secret override for an operator-supplied Microsoft Entra (app) client id.
# Public by design; the Desktop / public-client flow never carries a secret.
MICROSOFT_CLIENT_ID_ENV = "MICROSOFT_ENTRA_CLIENT_ID"
# Non-secret override for an operator-supplied client secret (only required for
# the rare confidential-client flow; public-client PKCE does not need one).
MICROSOFT_CLIENT_SECRET_ENV = "MICROSOFT_ENTRA_CLIENT_SECRET"  # noqa: S105 - env name
# Non-secret override for an operator-supplied tenant id (defaults to "common").
MICROSOFT_TENANT_ID_ENV = "MICROSOFT_ENTRA_TENANT_ID"

# Non-secret override to opt into the BYO (bring-your-own) Microsoft Entra app
# flow. Normal customers go through the SecuRedact-managed app and never need
# this flag.
MICROSOFT_BYO_ENV = "SECUREDACT_MICROSOFT_BYO"

# Human-facing label used in the wizard. Human-facing language; never expose the
# internal ``microsoft_graph`` capability name.
NORMAL_MICROSOFT_LABEL = "Connect Microsoft 365"
BYO_MICROSOFT_LABEL = "Use your own Microsoft Entra application"

# One-line prompt shown in the main setup wizard when Microsoft 365 is not yet
# configured. The default is "no" so an accidental Enter during a quick setup
# run does not silently turn the connector on.
MICROSOFT_SELECTION_PROMPT = "Configure Microsoft 365 (OneDrive and SharePoint) now? [y/N] "

# Hint shown when the wizard needs the user to paste an integration id from the
# dashboard. Kept as a single constant so the message is identical across paths.
MICROSOFT_INTEGRATION_ID_ADVANCED_HINT = (
    "Microsoft 365 is configured locally. Connect Microsoft 365 in the SecuRedact "
    "dashboard, then bind this machine when prompted."
)

# Microsoft always uses these read-only Graph scopes; no write scope may be
# requested. Mirrors the Google ``default_connector_scopes`` constant.
MICROSOFT_DEFAULT_SCOPES: tuple[str, ...] = (
    "User.Read",
    "Files.Read.All",
    "Sites.Read.All",
    "offline_access",
)


# ---------------------------------------------------------------------------
# Module-level protocol types (mirror the Google setup module)
# ---------------------------------------------------------------------------


class _MicrosoftConfigModule(Protocol):
    def load_microsoft_config(
        self, *, require_enabled: bool = ..., profile: str = ..., data_dir: Any = ...
    ) -> Any: ...

    MicrosoftConfigError: type[Exception]


class _MicrosoftAuthModule(Protocol):
    def load_credentials(self, config: Any) -> Any | None: ...
    def run_local_oauth(
        self,
        config: Any,
        *,
        open_browser: bool = ...,
        timeout_seconds: float = ...,
    ) -> Any: ...
    def has_pending_authorization(self, state: str | None) -> bool: ...


# ---------------------------------------------------------------------------
# Microsoft machine-state inspection (mirrors inspect_google_machine)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MicrosoftMachineState:
    """Evidence that Microsoft 365 is configured on this machine."""

    client_configured: bool = False
    token_present: bool = False
    binding_integration_id: str | None = None
    enabled: bool = False

    @property
    def configured(self) -> bool:
        """True when this machine already carries Microsoft configuration."""

        return bool(self.client_configured or self.token_present or self.binding_integration_id)


def inspect_microsoft_machine(
    data_dir: Path | str,
    *,
    files: AgentFiles | None = None,
    env: Mapping[str, str] | None = None,
) -> MicrosoftMachineState:
    """Detect machine-local Microsoft 365 configuration (no network, no prompts).

    Reads only non-secret presence signals: whether an OAuth client (app) config is
    resolvable, whether a machine-local OAuth token file exists, and whether a
    Microsoft connector binding is already recorded under the machine root. Never
    decrypts or logs any secret value.
    """

    from ..connectors.microsoft.client_config_store import MicrosoftClientConfigStore

    environ = os.environ if env is None else env
    root = Path(data_dir)

    # The managed app is the default production path; treat its presence as a valid
    # client configuration (normal customers never have to type a client id).
    try:
        managed_configured = _is_managed_client_configured(environ)
    except Exception:
        managed_configured = False

    env_client_id = environ.get(MICROSOFT_CLIENT_ID_ENV)
    env_client_secret = environ.get(MICROSOFT_CLIENT_SECRET_ENV)
    env_client_present = bool(env_client_id and env_client_secret)
    client_configured = env_client_present or managed_configured

    if not client_configured:
        try:
            stored_cid, stored_secret, _stored_tid = MicrosoftClientConfigStore(root).load_full()
            client_configured = bool(stored_cid and stored_secret)
        except Exception:
            client_configured = False

    token_present = (root / "microsoft" / "token.json.enc").is_file()

    binding_integration_id: str | None = None
    try:
        for binding in ConnectorBindingStore(machine_agent_files(root, files)).list():
            if binding.platform == MICROSOFT_CONNECTOR_PLATFORM:
                binding_integration_id = binding.integration_id
                break
    except Exception:
        binding_integration_id = None

    enabled = environ.get(MICROSOFT_ENABLED_ENV) == "1" or client_configured

    return MicrosoftMachineState(
        client_configured=client_configured,
        token_present=token_present,
        binding_integration_id=binding_integration_id,
        enabled=enabled,
    )


# ---------------------------------------------------------------------------
# Microsoft selection (mirrors resolve_google_selection)
# ---------------------------------------------------------------------------


def resolve_microsoft_selection(
    data_dir: Path | str,
    *,
    microsoft: str | None = None,
    non_interactive: bool = False,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
    files: AgentFiles | None = None,
    env: Mapping[str, str] | None = None,
    state: MicrosoftMachineState | None = None,
) -> bool:
    """Decide whether the wizard must perform Microsoft 365 onboarding.

    Resolution order (the interactive wizard never requires a hidden env flag):

    1. an explicit ``--microsoft no`` always wins (Microsoft is skipped);
    2. an explicit ``--microsoft yes`` always wins (including a value forwarded to
       the elevated continuation on argv);
    3. the non-secret ``SECUREDACT_MICROSOFT_ENABLED=1`` operational override;
    4. *detected* machine-local Microsoft configuration that shows the customer
       already chose/connected Microsoft: a stored OAuth token, an existing
       machine binding, or a stored client config. The packaged managed app is
       NOT, by itself, a detection signal -- a fresh machine still asks
       "Connect Microsoft 365?" (defaulting to no).
    5. an explicit interactive question, defaulting to "no";
    6. a non-interactive run with none of the above skips Microsoft safely.
    """

    if microsoft == "no":
        return False
    if microsoft == "yes":
        return True

    environ = os.environ if env is None else env
    if environ.get(MICROSOFT_ENABLED_ENV) == "1":
        return True

    detected = (
        state if state is not None else inspect_microsoft_machine(data_dir, files=files, env=env)
    )
    if detected.token_present or detected.binding_integration_id or detected.client_configured:
        print(
            "Microsoft 365 configuration detected on this computer; "
            "verifying the machine-local Microsoft onboarding.",
            file=output,
        )
        return True

    if non_interactive:
        print(
            "Microsoft 365 onboarding was not selected (non-interactive run). "
            "Re-run 'securedact-mcp setup --agent --microsoft yes' to connect one.",
            file=output,
        )
        return False

    print(file=output)
    print(
        "SecuRedact can scan a Microsoft 365 (OneDrive / SharePoint) integration "
        "from this computer. Files and detected values never leave the machine.",
        file=output,
    )
    try:
        answer = input_fn(MICROSOFT_SELECTION_PROMPT).strip().casefold()
    except (EOFError, StopIteration):
        answer = "n"
    return answer in {"y", "yes"}


# ---------------------------------------------------------------------------
# Microsoft client (app) configuration (mirrors prompt_google_client_config)
# ---------------------------------------------------------------------------


def prompt_microsoft_client_config(
    data_dir: Path | str,
    *,
    input_fn: Callable[[str], str] = input,
    secret_input_fn: Callable[[str], str] | None = None,
    output: TextIO = sys.stderr,
    non_interactive: bool = False,
    env: Mapping[str, str] | None = None,
    save_fn: Callable[..., None] | None = None,
    byo: bool = False,
) -> bool:
    """Collect + persist the Microsoft Entra client (app) config when it is missing.

    Returns ``True`` only when a NEW client id/secret/tenant was collected and
    persisted, so the caller may retry authorization exactly once. Returns
    ``False`` when a client config is already available (nothing to do) or when
    it could not be collected (non-interactive run, or the operator declined).

    For the **public-client / Desktop** app model used by normal customers, only
    the client id (and an optional tenant id) is required. The client secret is
    optional: PKCE protects the token exchange. Confidential-client installs
    (rare for the managed agent) can supply a secret.

    The client secret is read with a non-echoing prompt and persisted encrypted
    under the machine data root. It is never placed in the process environment,
    in a machine-wide environment variable, on argv, in logs, or sent to the
    control plane.

    In normal (non-BYO) mode, the SecuRedact-managed public-client app is used
    automatically and no client configuration prompt is shown.
    """

    root = Path(data_dir)
    state = inspect_microsoft_machine(root, env=env)
    if state.client_configured:
        return False

    # In normal (non-BYO) mode, the managed app is used automatically.
    # Only prompt for BYO configuration.
    if not byo:
        if is_managed_microsoft_available():
            print(
                "Using SecuRedact-managed Microsoft Entra public-client application "
                "(no client ID or secret required).",
                file=output,
            )
            return True
        if non_interactive:
            print(
                "Microsoft Entra client id is required for machine-local "
                "authorization; re-run this step interactively to supply it.",
                file=output,
            )
            return False
        print(
            "No managed Microsoft Entra application is available. "
            "Re-run with --microsoft-byo to use your own Entra app, "
            "or ensure the package includes the managed app configuration.",
            file=output,
        )
        return False

    if non_interactive:
        print(
            "Microsoft Entra client id is required for machine-local "
            "authorization; re-run this step interactively to supply it.",
            file=output,
        )
        return False

    import getpass

    read_secret = secret_input_fn or getpass.getpass

    print(file=output)
    print(
        "Microsoft 365 requires an Entra application (public client for Desktop, "
        "with PKCE) to authorize Graph read-only access on this computer.",
        file=output,
    )
    print(
        "Find the public-client application id in the Entra admin center, then "
        "paste it below. A client secret is NOT required (PKCE protects the "
        "exchange). Leave the secret empty for a public-client / Desktop app.",
        file=output,
    )
    try:
        client_id = input_fn("Microsoft Entra client (application) id: ").strip()
        tenant_id = input_fn("Tenant id (press Enter for 'common'): ").strip()
        client_secret: str | None = read_secret(
            "Microsoft Entra client secret (Enter to skip for public-client / PKCE): "
        ).strip()
        client_secret = client_secret or None
    except (EOFError, StopIteration):
        print("No Microsoft Entra client supplied; skipping.", file=output)
        return False
    if not client_id:
        print("No Microsoft Entra client supplied; skipping.", file=output)
        return False
    tenant_id = tenant_id or "common"

    try:
        if save_fn is not None:
            save_fn(root, client_id, client_secret, tenant_id)
        else:
            from ..connectors.microsoft.client_config_store import (
                MicrosoftClientConfigStore,
            )

            MicrosoftClientConfigStore(root).save(client_id, client_secret, tenant_id=tenant_id)
    except Exception as exc:
        print(f"Could not persist Microsoft client config: {scrub(str(exc))}", file=output)
        return False

    print(
        "Microsoft Entra client stored encrypted under the machine data root.",
        file=output,
    )
    return True


# ---------------------------------------------------------------------------
# Microsoft machine authorization (mirrors authorize_google_machine)
# ---------------------------------------------------------------------------


def authorize_microsoft_machine(
    data_dir: Path | str,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
    config_module: _MicrosoftConfigModule | None = None,
    auth_module: _MicrosoftAuthModule | None = None,
    non_interactive: bool = False,
    require_enabled: bool = True,
) -> bool:
    """Authorize Microsoft 365 locally on the machine (or reuse a valid token).

    Returns ``True`` when a valid machine-local Microsoft credential exists or was
    just created. Returns ``False`` when Microsoft is not enabled/configured, or
    when an interactive authorization could not be completed.

    ``require_enabled`` controls whether the non-secret
    ``SECUREDACT_MICROSOFT_ENABLED`` flag must be present. The setup wizard passes
    ``False`` because an explicit Microsoft selection (``--microsoft yes``,
    detected machine configuration, or the interactive question) *is* the
    enablement signal -- the operator must never need to know a hidden env flag.
    Direct/CLI callers keep the fail-closed default.

    The OAuth token is written only to ``<data_dir>/microsoft`` via the injected
    config's credential store; no OAuth material is ever placed on argv, in the
    environment, or in logs. A pre-existing valid machine token is reused
    idempotently; this function never reads or migrates a user-profile token.
    """

    cfg_module = config_module or cast("_MicrosoftConfigModule", microsoft_config)
    auth_mod = auth_module or cast("_MicrosoftAuthModule", microsoft_auth)

    machine_data = Path(data_dir)
    try:
        config = cfg_module.load_microsoft_config(
            require_enabled=require_enabled, data_dir=machine_data
        )
    except MicrosoftConfigError as exc:
        print(
            f"Microsoft 365 is not enabled/configured: {scrub(str(exc))}",
            file=output,
        )
        return False

    # Idempotent reuse: a valid machine-local token already exists.
    try:
        creds = auth_mod.load_credentials(config)
    except Exception:
        creds = None
    if creds is not None:
        print("Local Microsoft authorization valid; reusing it.", file=output)
        return True

    if non_interactive:
        print(
            "Microsoft authorization requires an interactive browser login. Re-run "
            "this step interactively (or run 'securedact-mcp microsoft auth') to complete it.",
            file=output,
        )
        return False

    # First-class local authorization against the machine data root.
    try:
        outcome = auth_mod.run_local_oauth(config)
    except Exception as exc:
        print(
            f"Could not start Microsoft authorization: {scrub(str(exc))}",
            file=output,
        )
        return False
    if not outcome.authorized:
        print(
            "Microsoft authorization could not be completed automatically. "
            "Re-run 'securedact-mcp microsoft auth' interactively.",
            file=output,
        )
        return False
    print("Authorized.", file=output)
    return True


# ---------------------------------------------------------------------------
# Microsoft machine binding (mirrors bind_google_machine)
# ---------------------------------------------------------------------------


def bind_microsoft_machine(
    config: AgentConfig,
    integration_id: str,
    *,
    files: AgentFiles | None = None,
    profile: str = "default",
    binding_store_cls: type[ConnectorBindingStore] = ConnectorBindingStore,
) -> ConnectorBinding:
    """Create (or idempotently reuse/repair) the machine-local Microsoft binding.

    The integration id is supplied by the operator from the SecuRedact dashboard
    (the control plane never supplies OAuth material). An existing valid binding
    for the same integration id + profile is reused; a stale binding (wrong
    platform/profile) is repaired; the store is keyed by integration id so no
    duplicate records are ever written.
    """

    resolved_id = normalize_integration_id(integration_id)
    if not resolved_id:
        raise AgentError("a Microsoft 365 integration_id is required to create a local binding")
    store = binding_store_cls(files)
    existing = store.get(resolved_id)
    if (
        existing is not None
        and existing.platform == MICROSOFT_CONNECTOR_PLATFORM
        and existing.local_profile == profile
    ):
        return existing
    return bind_connector(
        config,
        resolved_id,
        MICROSOFT_CONNECTOR_PLATFORM,
        profile=profile,
        files=files,
    )


# ---------------------------------------------------------------------------
# Microsoft machine env publication (mirrors apply_google_machine_env)
# ---------------------------------------------------------------------------


def apply_microsoft_machine_env(
    data_dir: Path | str,
    *,
    enabled: bool | None = None,
) -> None:
    """Persist non-secret Microsoft config at machine scope; encrypt the client secret.

    The OAuth client secret (and client id) are stored encrypted under the machine
    data root via :class:`MicrosoftClientConfigStore` so the SYSTEM-run scheduled
    task can load them after reboot -- without ever placing the secret in a
    machine-wide environment variable, argv, logs, or the control plane. Only
    the non-secret enable flag is published at machine scope.

    ``enabled`` lets the setup wizard publish the non-secret enable flag when
    Microsoft was selected interactively, so an operator never has to know
    ``SECUREDACT_MICROSOFT_ENABLED``. When it is ``None`` the pre-existing
    environment value decides.
    """

    from ..connectors.microsoft.client_config_store import MicrosoftClientConfigStore

    data_dir = Path(data_dir)
    env_client_id = os.environ.get(MICROSOFT_CLIENT_ID_ENV)
    env_client_secret = os.environ.get(MICROSOFT_CLIENT_SECRET_ENV)

    if env_client_id or env_client_secret:
        try:
            MicrosoftClientConfigStore(data_dir).save(env_client_id, env_client_secret)
        except Exception as exc:  # pragma: no cover - defensive
            print(
                f"could not persist microsoft client config: {scrub(str(exc))}",
                file=sys.stderr,
            )

    publish = enabled if enabled is not None else os.environ.get(MICROSOFT_ENABLED_ENV) == "1"
    if publish:
        _set_machine_env_var(MICROSOFT_ENABLED_ENV, "1")


# ---------------------------------------------------------------------------
# Microsoft onboarding outcome + orchestrator (mirrors Google)
# ---------------------------------------------------------------------------
#
# ``MicrosoftMachineAuthResult`` mirrors :class:`google_setup.GoogleMachineAuthResult`
# and carries the structured ``stage``/``error_code`` surfaced by the machine
# runtime so the setup CLI can report an actionable, safe message.
#


@dataclass(frozen=True, slots=True)
class MicrosoftMachineAuthResult:
    """Bounded result of machine-local Microsoft authorization (no secret material).

    Carries the structured ``stage``/``error_code`` surfaced by the machine
    runtime so the setup CLI can report an actionable, safe message (and never
    misreport a post-callback failure as "managed Microsoft Entra app unavailable").
    """

    authorized: bool
    stage: str | None = None
    error_code: str | None = None
    error: str | None = None
    # Microsoft's RFC 6749 ``error`` token from the token endpoint (e.g.
    # ``invalid_grant``, ``redirect_uri_mismatch``), present only when Microsoft
    # actually answered. This names the real rejection instead of the generic
    # stage code.
    oauth_error: str | None = None
    # Bounded, credential-free rendering of Microsoft's ``error_description``.
    error_description: str | None = None


@dataclass(frozen=True, slots=True)
class MicrosoftOnboardingOutcome:
    """Result of the machine-local Microsoft 365 onboarding step."""

    selected: bool
    deps_ready: bool = False
    authorized: bool = False
    integration_id: str | None = None
    binding_verified: bool = False
    auth_stage: str | None = None
    auth_error_code: str | None = None
    auth_error: str | None = None

    @property
    def ready(self) -> bool:
        """True only when every Microsoft readiness pre-condition is satisfied."""

        if not self.selected:
            return True
        return bool(
            self.deps_ready and self.authorized and self.integration_id and self.binding_verified
        )


# ---------------------------------------------------------------------------
# Microsoft auth failure reporting (mirrors _report_google_auth_failure)
# ---------------------------------------------------------------------------


def _report_microsoft_auth_failure(
    outcome: MicrosoftOnboardingOutcome, output: Any, microsoft_byo: bool
) -> None:
    """Report an actionable, safe message for a post-callback OAuth failure.

    Mirrors :func:`_report_google_auth_failure`. ``outcome`` carries only a
    bounded ``stage`` / ``error_code`` (never any token, code, verifier, or
    secret). This is the exact path that must NOT print the managed-OAuth-
    unavailable message: the managed public client was resolved and Microsoft
    accepted the OAuth client, so the failure is downstream (state validation,
    token exchange, or persistence).
    """

    stage = outcome.auth_stage
    error_code = outcome.auth_error_code
    if stage or error_code:
        msg = "Microsoft authorization failed after the browser returned to SecuRedact"
        if stage:
            msg += f" (stage: {stage})"
        if error_code:
            msg += f" [code: {error_code}]"
        msg += (
            ". Finish the machine-local OAuth with 'securedact-mcp setup --agent --microsoft yes'."
        )
        if microsoft_byo:
            msg += (
                " For BYO, verify the Microsoft Entra OAuth client id/secret and the "
                "authorized redirect URI."
            )
        print(msg, file=output)
    else:
        print(
            "Microsoft authorization could not be completed locally. Re-run setup with "
            "'securedact-mcp setup --agent --microsoft yes' (or --microsoft-byo for your own "
            "Microsoft Entra OAuth app).",
            file=output,
        )


def run_microsoft_machine_onboarding(
    *,
    data_dir: Path,
    output: Any,
    input_fn: Callable[[str], str],
    secret_input_fn: Callable[[str], str],
    non_interactive: bool = False,
    microsoft_integration_id: str | None = None,
    runtime_path: Path | str | None = None,
    command_runner: Any | None = None,
    authorize_microsoft_fn: Callable[..., bool] | None = None,
    bind_microsoft_fn: Callable[..., Any] | None = None,
    apply_microsoft_env_fn: Callable[..., None] | None = None,
    verify_binding_fn: Callable[..., bool] | None = None,
    client_config_fn: Callable[..., bool] | None = None,
    deps_ready_fn: Callable[[Path | None], bool] | None = None,
    microsoft_selection_fn: Callable[..., bool] | None = None,
    microsoft_byo: bool = False,
) -> MicrosoftOnboardingOutcome:
    """Perform the machine-local Microsoft 365 onboarding and prove its post-conditions.

    Order (each step is a hard pre-condition of the next):

    1. the machine runtime can import the Microsoft connector modules;
    2. Microsoft is authorized locally against the machine data root (an existing
       valid machine token is reused; a missing client id is collected once and
       persisted encrypted, then authorization is retried exactly once);
    3. the dashboard integration id is resolved (existing binding, non-secret env
       override, or interactive question);
    4. the machine-local connector binding is created/reused; and
    5. the binding is re-read from ``<machine root>/agent/connector-bindings.json``
       and proven to record exactly that integration id.
    """

    _apply_env = apply_microsoft_env_fn or apply_microsoft_machine_env
    _verify = verify_binding_fn or verify_microsoft_binding
    _client_config = client_config_fn or (
        lambda data_dir, **kwargs: prompt_microsoft_client_config(
            data_dir, **kwargs, byo=microsoft_byo
        )
    )
    _bind = bind_microsoft_fn or bind_microsoft_machine
    _deps_ready = deps_ready_fn or _default_microsoft_deps_ready
    _select_microsoft = microsoft_selection_fn or resolve_microsoft_selection

    # First, decide if Microsoft 365 should be configured (mirrors Google logic)
    microsoft_enabled = bool(
        _select_microsoft(
            data_dir,
            microsoft=None,
            non_interactive=non_interactive,
            input_fn=input_fn,
            output=output,
        )
    )
    if not microsoft_enabled:
        return MicrosoftOnboardingOutcome(selected=False)

    outcome = MicrosoftOnboardingOutcome(selected=True)

    print(file=output)
    print("[Microsoft 365]", file=output)

    # Resolve the runtime python FIRST so we print the correct interpreter
    from .deploy import resolve_machine_runtime_python

    runtime_python = resolve_machine_runtime_python(runtime_path)
    print(
        "Machine runtime interpreter: "
        + (str(runtime_python) if runtime_python is not None else "not available"),
        file=output,
    )

    outcome = MicrosoftOnboardingOutcome(
        selected=True,
        deps_ready=bool(_deps_ready(runtime_python)),
    )
    if not outcome.deps_ready:
        print(
            "The current interpreter cannot perform Microsoft 365 work (missing "
            "Microsoft connector modules, or a stale runtime). Re-run setup so the "
            "current agent build is installed into the machine runtime, then check "
            "'securedact-mcp microsoft status'.",
            file=output,
        )
        return outcome

    try:
        _apply_env(data_dir, enabled=True)
    except Exception as exc:  # pragma: no cover - non-fatal best-effort
        print(f"Microsoft machine env not applied: {scrub(str(exc))}", file=output)

    print("Authorizing Microsoft 365 locally against the machine data root...", file=output)

    # Use the runtime-based authorization (mirrors Google's _authorize_google_machine).
    # This runs the OAuth flow inside the machine-owned runtime interpreter so that
    # the Microsoft extra (msal, requests) that the scheduled agent uses is the one
    # that authorizes. The setup CLI's own interpreter (which lacks the Microsoft
    # extra) is never used for the actual OAuth flow.
    from .deploy import _authorize_microsoft_machine

    auth_result = _authorize_microsoft_machine(
        data_dir=data_dir,
        runtime_python=runtime_python,
        command_runner=command_runner,
        input_fn=input_fn,
        output=output,
        non_interactive=non_interactive,
        secret_input_fn=secret_input_fn,
        authorize_microsoft_fn=authorize_microsoft_fn,
        microsoft_byo=microsoft_byo,
    )
    outcome = MicrosoftOnboardingOutcome(
        selected=True,
        deps_ready=outcome.deps_ready,
        authorized=auth_result.authorized,
        auth_stage=auth_result.stage,
        auth_error_code=auth_result.error_code,
        auth_error=auth_result.error,
    )
    if not outcome.authorized:
        # On the normal (managed) path, only the genuine absence of a managed client
        # warrants the "managed Microsoft Entra app unavailable" message. A failure that
        # happens *after* the browser OAuth flow started (state validation, token
        # exchange, or persistence) must never be misreported as managed-app absence.
        # A normal released build always has the packaged managed app, so normal
        # customers are never told to create an Entra app or set a machine
        # environment variable.
        if microsoft_byo:
            collected = bool(
                _client_config(
                    data_dir,
                    input_fn=input_fn,
                    secret_input_fn=secret_input_fn,
                    output=output,
                    non_interactive=non_interactive,
                )
            )
            if collected:
                auth_result = _authorize_microsoft_machine(
                    data_dir=data_dir,
                    runtime_python=runtime_python,
                    command_runner=command_runner,
                    input_fn=input_fn,
                    output=output,
                    non_interactive=non_interactive,
                    secret_input_fn=secret_input_fn,
                    authorize_microsoft_fn=authorize_microsoft_fn,
                    microsoft_byo=microsoft_byo,
                )
                outcome = MicrosoftOnboardingOutcome(
                    selected=True,
                    deps_ready=outcome.deps_ready,
                    authorized=auth_result.authorized,
                    auth_stage=auth_result.stage,
                    auth_error_code=auth_result.error_code,
                    auth_error=auth_result.error,
                )
        if not outcome.authorized:
            if not microsoft_byo and not is_managed_microsoft_available():
                from ..connectors.microsoft import managed as microsoft_managed

                print(microsoft_managed.MANAGED_CLIENT_NOT_CONFIGURED_MSG, file=output)
            else:
                _report_microsoft_auth_failure(outcome, output, microsoft_byo)
            print(
                "Microsoft authorization was not completed. No Microsoft job can run until "
                "it is (finish it with 'securedact-mcp setup --agent --microsoft yes', "
                "or --microsoft-byo to use your own Microsoft Entra OAuth app).",
                file=output,
            )
            return outcome

    # Resolve the dashboard integration id: reuse an existing binding if present,
    # otherwise the caller must supply it via --microsoft-integration-id (advanced).
    resolved_id: str | None = None
    if microsoft_integration_id:
        resolved_id = normalize_integration_id(microsoft_integration_id)
    else:
        try:
            for binding in ConnectorBindingStore(machine_agent_files(data_dir)).list():
                if binding.platform == MICROSOFT_CONNECTOR_PLATFORM:
                    resolved_id = binding.integration_id
                    break
        except Exception:
            resolved_id = None

    if not resolved_id:
        print(file=output)
        print("Microsoft authorization complete.", file=output)
        print(file=output)
        print(MICROSOFT_INTEGRATION_ID_ADVANCED_HINT, file=output)
        print(
            "Finish it with: securedact-mcp setup --agent --microsoft yes "
            "--microsoft-integration-id <dashboard integration ID>",
            file=output,
        )
        return outcome

    outcome = MicrosoftOnboardingOutcome(
        selected=True,
        deps_ready=outcome.deps_ready,
        authorized=outcome.authorized,
        integration_id=resolved_id,
    )

    from .config import load_config as load_agent_config

    files = AgentFiles.resolve(root=Path(data_dir) / "agent")
    try:
        registered = load_agent_config(files)
    except Exception:
        registered = None
    if registered is None:
        print(
            "Agent is not registered locally; complete registration before "
            "binding the Microsoft 365 integration.",
            file=output,
        )
        return outcome
    try:
        binding = _bind(registered, resolved_id, files=files)
    except AgentError as exc:
        print(f"Microsoft connector binding failed: {scrub(str(exc))}", file=output)
        return outcome
    except Exception as exc:
        print(f"Microsoft connector binding failed safely: {scrub(str(exc))}", file=output)
        return outcome

    outcome = MicrosoftOnboardingOutcome(
        selected=True,
        deps_ready=outcome.deps_ready,
        authorized=outcome.authorized,
        integration_id=outcome.integration_id,
        binding_verified=bool(_verify(data_dir, resolved_id, files=files)),
    )
    if not outcome.binding_verified:
        print(
            "The Microsoft connector binding could not be verified under "
            f"{files.connector_bindings}; refusing to report the agent as ready.",
            file=output,
        )
        return outcome
    print(
        f"Local connector bound: {binding.integration_id} -> {binding.platform}",
        file=output,
    )
    print(f"Binding file: {files.connector_bindings}", file=output)
    return outcome


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_managed_client_configured(environ: Mapping[str, str] | None = None) -> bool:
    """True only when a managed (owned) Microsoft Entra client id is available."""

    try:
        from ..connectors.microsoft.managed import is_managed_microsoft_available
    except Exception:
        return False
    return is_managed_microsoft_available()


def _default_microsoft_deps_ready(runtime_python: Path | None = None) -> bool:
    """Readiness gate: the machine runtime can actually perform Microsoft 365 work.

    ``runtime_python`` is the interpreter resolved by
    :func:`resolve_machine_runtime_python` — i.e. *exactly* the interpreter that
    :func:`authorize_microsoft_machine` will use. Probing anything else is what made
    setup report "Microsoft dependencies: available" while authorization died with
    ``No module named 'msal'`` in a different interpreter.

    Both the provider imports *and* the runtime's ``microsoft-auth`` bootstrap
    capability must hold. When there is no runtime interpreter at all there is
    nothing to probe (the provisioning gate owns that case), so it does not block.
    """

    if runtime_python is None:
        return True
    from .deploy import (
        _default_runner,
        _runtime_has_microsoft_imports,
        _runtime_root_for_python,
        _runtime_supports_microsoft_auth,
    )

    runtime = _runtime_root_for_python(Path(runtime_python))
    runner = _default_runner
    return _runtime_has_microsoft_imports(runtime, runner) and _runtime_supports_microsoft_auth(
        runtime, runner
    )


# ---------------------------------------------------------------------------
# Microsoft runtime authorization verification (mirrors Google)
# ---------------------------------------------------------------------------
#
# These functions are designed to be invoked inside the *machine-owned runtime*
# interpreter via ``securedact_mcp.agent.runtime_bootstrap microsoft-auth``.
# They run the exact same Microsoft auth flow as the in-process version, but
# inside the interpreter that actually carries the ``microsoft`` extra (msal,
# requests, etc.). This prevents the RC defect where the setup CLI's own Python
# lacks the Microsoft extra and fails with ``No module named 'msal'`` while the
# readiness probe (which defaults to ProgramData) reports "available".


MICROSOFT_AUTH_RUNTIME_MODULES = (
    "msal",
    "requests",
)


def verify_microsoft_authorization_runtime(data_dir: Path | str) -> dict[str, Any]:
    """Prove *this* interpreter can perform the machine-local Microsoft OAuth flow.

    Mirrors :func:`google_setup.verify_google_authorization_runtime`. Executes
    every step of the real loopback authorization except the two that need a
    human/Microsoft: it does not open a browser, does not wait for a redirect,
    and never obtains or stores a token. Concretely it:

    1. imports the exact Microsoft modules the flow uses (``msal`` & friends)
       **in this interpreter**;
    2. resolves the machine-local Microsoft configuration from ``data_dir``;
    3. binds the temporary ``127.0.0.1`` loopback listener on a random port; and
    4. builds the PKCE consent URL for that redirect URI (pure local construction).

    Returns a JSON-safe dict whose ``verified`` flag is the fail-closed signal,
    plus ``interpreter`` (``sys.executable``) so the operator can see exactly
    which Python was proven. The consent URL, OAuth state, client secret, and
    token are never included in the payload.
    """

    import dataclasses
    import importlib

    payload: dict[str, Any] = {
        "verified": False,
        "interpreter": sys.executable,
        "data_dir": str(data_dir),
        "imports": {},
        "imports_ok": False,
        "client_configured": False,
        "loopback_bound": False,
        "loopback_host": None,
        "loopback_port": None,
        "consent_url_built": False,
        "token_required": False,
        "browser_opened": False,
    }

    # 1. Imports — the exact failure mode being regression-tested.
    for module in MICROSOFT_AUTH_RUNTIME_MODULES:
        try:
            importlib.import_module(module)
            payload["imports"][module] = True
        except Exception as exc:
            payload["imports"][module] = False
            payload["error"] = scrub(f"{module}: {exc}")
    payload["imports_ok"] = all(payload["imports"].values())
    if not payload["imports_ok"]:
        return payload

    from ..connectors.microsoft import auth as default_auth
    from ..connectors.microsoft import config as default_config

    # 2. Machine-local configuration (managed app by default, BYO from the store).
    try:
        config = default_config.load_microsoft_config(
            require_enabled=False, data_dir=Path(data_dir)
        )
    except Exception as exc:
        payload["error"] = scrub(str(exc))
        return payload
    payload["client_configured"] = bool(config.client_id)

    # 3./4. Loopback listener + PKCE consent URL, then release everything.
    server = default_auth.LoopbackOAuthServer(expected_state="", timeout=0.01)
    try:
        payload["loopback_bound"] = True
        payload["loopback_host"] = default_auth.LOOPBACK_HOST
        payload["loopback_port"] = int(server.port)
        loopback_config = dataclasses.replace(config, redirect_uri=server.redirect_uri)
        try:
            url, state = default_auth.build_authorization_url(loopback_config, pkce=True)
        except Exception as exc:
            payload["error"] = scrub(str(exc))
            return payload
        # Never emit the consent URL / CSRF state, and do not retain the pending
        # flow (this is a verification, not an authorization).
        payload["consent_url_built"] = bool(url) and bool(state)
        default_auth._FLOW_STATE.pop(state, None)
    finally:
        server.shutdown()

    payload["verified"] = True
    return payload


def run_microsoft_loopback_authorization(
    data_dir: Path | str, *, byo: bool = False
) -> dict[str, object]:
    """Run the full local loopback OAuth flow inside the machine-owned runtime.

    Mirrors :func:`google_setup.run_google_loopback_authorization`. Returns a
    bounded, machine-readable result (``authorized`` plus a safe
    ``stage``/``error_code`` on failure). No OAuth code/token/client secret/verifier
    is ever placed on argv, in a command file, in the environment, or in logs.
    When the managed client is genuinely absent the result carries
    ``stage="config"`` with the safe ``microsoft_config_missing`` code (the only
    correct place to report that).
    """

    from ..connectors.microsoft import auth as default_auth
    from ..connectors.microsoft import config as default_config
    from ..connectors.microsoft.config import MicrosoftConfigError

    try:
        config = default_config.load_microsoft_config(
            require_enabled=False, data_dir=Path(data_dir)
        )
    except MicrosoftConfigError as exc:
        return {
            "authorized": False,
            "stage": "config",
            "error_code": "microsoft_config_missing",
            "error": scrub(str(exc)),
        }
    outcome = default_auth.run_local_oauth(config)
    return outcome.to_payload()


def verify_microsoft_binding(
    data_dir: Path | str,
    integration_id: str,
    *,
    files: AgentFiles | None = None,
    profile: str = "default",
) -> bool:
    """Fail-closed proof that the machine-local Microsoft binding really exists."""

    resolved = machine_agent_files(data_dir, files)
    if not resolved.connector_bindings.is_file():
        return False
    try:
        binding = ConnectorBindingStore(resolved).get(integration_id)
    except Exception:
        return False
    if binding is None:
        return False
    return (
        binding.platform == MICROSOFT_CONNECTOR_PLATFORM
        and (binding.local_profile or "default") == profile
    )


# ---------------------------------------------------------------------------
# Re-exports for the wizard / tests
# ---------------------------------------------------------------------------

__all__ = [
    "BYO_MICROSOFT_LABEL",
    "MANAGED_MICROSOFT_CLIENT_ID_ENV",
    "MICROSOFT_BYO_ENV",
    "MICROSOFT_CLIENT_ID_ENV",
    "MICROSOFT_CLIENT_SECRET_ENV",
    "MICROSOFT_CONNECTOR_PLATFORM",
    "MICROSOFT_DEFAULT_SCOPES",
    "MICROSOFT_ENABLED_ENV",
    "MICROSOFT_INTEGRATION_ID_ADVANCED_HINT",
    "MICROSOFT_SELECTION_PROMPT",
    "MICROSOFT_TENANT_ID_ENV",
    "NORMAL_MICROSOFT_LABEL",
    "MicrosoftMachineAuthResult",
    "MicrosoftMachineState",
    "MicrosoftOnboardingOutcome",
    "apply_microsoft_machine_env",
    "authorize_microsoft_machine",
    "bind_microsoft_machine",
    "inspect_microsoft_machine",
    "prompt_microsoft_client_config",
    "resolve_microsoft_selection",
    "run_microsoft_loopback_authorization",
    "run_microsoft_machine_onboarding",
    "verify_microsoft_authorization_runtime",
    "verify_microsoft_binding",
]
