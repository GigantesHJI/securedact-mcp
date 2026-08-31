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

The onboarding is *selected by the wizard itself*, not by hidden environment
flags: :func:`resolve_google_selection` honours an explicit ``--google`` choice,
the non-secret ``SECUREDACT_GOOGLE_ENABLED`` override, machine-local evidence that
Google is already configured, and otherwise asks the operator a plain question.
:func:`verify_machine_binding` is the fail-closed post-condition the wizard checks
before it may report the Managed Agent as ready.

Both behaviours are fully injectable (config loader, auth flow, input reader,
output stream) so the policy is testable without Windows or network access.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TextIO, cast

from .config import AgentConfig, AgentFiles
from .connectors import ConnectorBinding, ConnectorBindingStore
from .errors import AgentError
from .safe_log import scrub

GOOGLE_CONNECTOR_PLATFORM = "google_workspace"

# Non-secret operational environment overrides. They are *additional* discovery
# sources only: the setup wizard must never require an operator to know them (see
# :func:`resolve_google_selection`).
GOOGLE_ENABLED_ENV = "SECUREDACT_GOOGLE_ENABLED"
GOOGLE_CLIENT_ID_ENV = "SECUREDACT_GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET_ENV = "SECUREDACT_GOOGLE_CLIENT_SECRET"  # noqa: S105 - env name, not a secret

# Bring the SecuRedact-managed (owned) Google OAuth application resolution into
# scope. When it is configured (env override or packaged default), normal
# customers connect through SecuRedact's own app and never need to create their
# own Google Cloud project / OAuth client.
from ..connectors.google import managed as google_managed  # noqa: E402

GOOGLE_BYO_ENV = "SECUREDACT_GOOGLE_BYO"

# A dashboard integration id is a non-secret opaque identifier. It is validated
# before it is ever stored, or forwarded on the elevated continuation's argv, so a
# malformed / injected value can never reach a command line or the binding store.
_INTEGRATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

GOOGLE_SELECTION_PROMPT = (
    "Connect a Google Workspace integration to this computer's managed agent? [y/N] "
)

# The raw dashboard integration id is an internal implementation detail. Normal
# customers must never be asked to find/paste it (see :func:`resolve_google_integration`
# and the RC setup UX). The only supported interactive surface for a manual id is the
# explicit advanced/enterprise flag ``--google-integration-id``; it is intentionally
# NOT surfaced as a routine wizard question.
GOOGLE_INTEGRATION_ID_ADVANCED_HINT = (
    "For advanced/manual setup, rerun with:\n"
    "  securedact-mcp setup --agent --google yes --google-integration-id <id>"
)

# Conceptual control-plane capability the dashboard/webapp must eventually provide.
# It is NOT implemented in this task; the resolver accepts an injected source so the
# future endpoint can plug in without changing the wizard. See the roadmap note in
# docs/managed-agent.md ("tenant-scoped eligible integration discovery").
#
# Response shape (future, agent-authenticated, tenant-scoped, safe metadata only):
#   {"integrations": [{"id": "...", "platform": "google_workspace",
#                      "display_name": "My Workspace"}, ...]}
CONTROL_PLANE_INTEGRATIONS_PATH = "/v1/agents/integrations/eligible"


@dataclass
class GoogleMachineAuthResult:
    """Bounded result of machine-local Google authorization (no secret material).

    Carries the structured ``stage``/``error_code`` surfaced by the machine runtime so
    the setup CLI can report an actionable, safe message (and never misreport a
    post-callback failure as "managed OAuth application unavailable").
    """

    authorized: bool
    stage: str | None = None
    error_code: str | None = None
    error: str | None = None
    # Google's RFC 6749 ``error`` token from the token endpoint (e.g. ``invalid_grant``,
    # ``redirect_uri_mismatch``), present only when Google actually answered. This is
    # what names the real rejection instead of the generic stage code.
    oauth_error: str | None = None
    # Bounded, credential-free rendering of Google's ``error_description``.
    error_description: str | None = None


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


# ---------------------------------------------------------------------------
# Machine-local Google state detection + first-class wizard selection
# ---------------------------------------------------------------------------


def normalize_integration_id(raw: str | None) -> str | None:
    """Return a validated dashboard integration id, or ``None`` when absent.

    Fail-closed on anything that is not an opaque identifier: the value is stored
    in the machine binding store and may be forwarded on the elevated
    continuation's command line, so shell metacharacters/whitespace are rejected.
    """

    text = (raw or "").strip()
    if not text:
        return None
    if not _INTEGRATION_ID_RE.match(text):
        raise AgentError(
            "invalid Google Workspace integration ID; copy it exactly from the "
            "SecuRedact dashboard (letters, digits, '-', '_', '.', ':')"
        )
    return text


# ---------------------------------------------------------------------------
# Internal integration-resolution abstraction (single source of truth)
# ---------------------------------------------------------------------------
#
# Integration selection must live in ONE place instead of being scattered through
# the wizard. This resolver implements the supported precedence and is the only
# component that decides *which* dashboard Google Workspace integration a machine
# should bind to. It is deliberately ready for a future tenant-scoped control-plane
# lookup without inventing that endpoint now.


class GoogleIntegrationResolutionState(StrEnum):
    """Outcome of :func:`resolve_google_integration`."""

    RESOLVED_EXPLICIT = "resolved_explicit"
    RESOLVED_EXISTING_BINDING = "resolved_existing_binding"
    RESOLVED_CONTROL_PLANE = "resolved_control_plane"
    UNAVAILABLE = "unavailable"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class GoogleIntegrationCandidate:
    """Safe, credential-free metadata about an eligible Google Workspace integration."""

    id: str
    platform: str
    display_name: str | None = None

    def label(self) -> str:
        return self.display_name or self.id


class ControlPlaneIntegrationSource(Protocol):
    """Future agent-authenticated, tenant-scoped integration discovery (NOT implemented).

    The resolver accepts an injected source so the eventual dashboard/webapp endpoint
    can plug in without changing the wizard. It must be tenant-scoped, authenticated
    with the registered managed-agent credential, and return ONLY safe metadata (never
    an OAuth token, client secret, Drive content, or customer PII).
    """

    def list_eligible_google_integrations(
        self, *, agent_identity: str | None = ...
    ) -> list[GoogleIntegrationCandidate]: ...


@dataclass(slots=True)
class GoogleIntegrationResolution:
    """Structured result of integration resolution (no secrets)."""

    state: GoogleIntegrationResolutionState
    integration_id: str | None = None
    candidates: list[GoogleIntegrationCandidate] | None = None
    message: str | None = None

    @property
    def resolved(self) -> bool:
        return self.integration_id is not None


def resolve_google_integration(
    *,
    explicit_id: str | None = None,
    data_dir: Path | str | None = None,
    files: AgentFiles | None = None,
    env: Mapping[str, str] | None = None,
    state: GoogleMachineState | None = None,
    control_plane_client: ControlPlaneIntegrationSource | None = None,
    agent_identity: str | None = None,
    interactive: bool = True,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
) -> GoogleIntegrationResolution:
    """Resolve the Google Workspace integration id to bind on this machine.

    Precedence (single source of truth for integration selection):

    1. explicit ``--google-integration-id`` -> ``resolved_explicit`` (advanced/manual
       override; validated before use);
    2. an existing valid machine-local Google binding -> ``resolved_existing_binding``
       (reused idempotently, never prompted);
    3. a tenant-scoped control-plane lookup, IF a source is supplied:
         * exactly one eligible integration -> ``resolved_control_plane``;
         * more than one -> ``ambiguous`` (human-readable selection when interactive);
         * none -> ``unavailable``;
    4. otherwise -> ``unavailable`` (no automatic resolution in this build).

    The normal wizard must NEVER present a raw integration id prompt to a customer.
    The only interactive surface for a manual id is the explicit advanced flag; when
    automatic resolution is unavailable the caller reports the advisory + escape hatch.
    """

    # 1. Explicit advanced/manual override (validated; fails safe on malformed input).
    try:
        normalized_explicit = normalize_integration_id(explicit_id)
    except AgentError:
        return GoogleIntegrationResolution(
            state=GoogleIntegrationResolutionState.UNAVAILABLE,
            message=(
                "The provided --google-integration-id is invalid. Use the exact id "
                "from your SecuRedact dashboard, or create an integration there first."
            ),
        )
    if normalized_explicit:
        return GoogleIntegrationResolution(
            state=GoogleIntegrationResolutionState.RESOLVED_EXPLICIT,
            integration_id=normalized_explicit,
        )

    # 2. Reuse an existing valid machine-local Google binding (no prompt).
    detected = (
        state
        if state is not None
        else (
            inspect_google_machine(data_dir, files=files, env=env) if data_dir is not None else None
        )
    )
    if detected is not None and detected.binding_integration_id:
        return GoogleIntegrationResolution(
            state=GoogleIntegrationResolutionState.RESOLVED_EXISTING_BINDING,
            integration_id=detected.binding_integration_id,
        )

    # 3. Future tenant-scoped control-plane lookup (only when a source is injected).
    if control_plane_client is not None:
        try:
            candidates = control_plane_client.list_eligible_google_integrations(
                agent_identity=agent_identity
            )
        except Exception as exc:  # a control-plane failure never invents an id
            return GoogleIntegrationResolution(
                state=GoogleIntegrationResolutionState.UNAVAILABLE,
                message=f"Could not look up eligible integrations: {scrub(str(exc))}",
            )
        candidates = [c for c in candidates if c.platform == GOOGLE_CONNECTOR_PLATFORM]
        if len(candidates) == 1:
            return GoogleIntegrationResolution(
                state=GoogleIntegrationResolutionState.RESOLVED_CONTROL_PLANE,
                integration_id=candidates[0].id,
                candidates=candidates,
            )
        if len(candidates) > 1:
            if interactive:
                print(
                    "Which Google Workspace integration should this computer use?",
                    file=output,
                )
                for index, candidate in enumerate(candidates, 1):
                    print(f"  {index}. {candidate.label()}", file=output)
                try:
                    raw = input_fn("Selection: ").strip()
                except (EOFError, StopIteration):
                    raw = ""
                if raw.isdigit() and 1 <= int(raw) <= len(candidates):
                    picked = candidates[int(raw) - 1]
                    return GoogleIntegrationResolution(
                        state=GoogleIntegrationResolutionState.RESOLVED_CONTROL_PLANE,
                        integration_id=picked.id,
                        candidates=candidates,
                    )
            return GoogleIntegrationResolution(
                state=GoogleIntegrationResolutionState.AMBIGUOUS,
                candidates=candidates,
                message=(
                    "Multiple Google Workspace integrations are available in your "
                    "SecuRedact account; select one explicitly with --google-integration-id."
                ),
            )

    # 4. No automatic resolution available in this build.
    return GoogleIntegrationResolution(
        state=GoogleIntegrationResolutionState.UNAVAILABLE,
        message=(
            "SecuRedact could not automatically determine which dashboard Google "
            "Workspace integration should be bound to this machine."
        ),
    )


def machine_agent_files(data_dir: Path | str, files: AgentFiles | None = None) -> AgentFiles:
    """Return the agent file layout rooted at the *machine* data root.

    All managed-agent state (registration, bindings) lives under
    ``<machine data root>/agent`` -- e.g. ``C:\\ProgramData\\Securedact\\agent`` --
    never in the interactive user's profile.
    """

    return files or AgentFiles.resolve(root=Path(data_dir) / "agent")


@dataclass(frozen=True, slots=True)
class GoogleMachineState:
    """Evidence that Google Workspace managed scanning is configured here."""

    client_configured: bool = False
    token_present: bool = False
    binding_integration_id: str | None = None

    @property
    def configured(self) -> bool:
        """True when this machine already carries Google Workspace configuration."""

        return bool(self.client_configured or self.token_present or self.binding_integration_id)


def inspect_google_machine(
    data_dir: Path | str,
    *,
    files: AgentFiles | None = None,
    env: Mapping[str, str] | None = None,
) -> GoogleMachineState:
    """Detect machine-local Google Workspace configuration (no network, no prompts).

    Reads only non-secret presence signals: whether an OAuth client (app) config is
    resolvable, whether a machine-local OAuth token file exists, and whether a
    Google connector binding is already recorded under the machine root. Never
    decrypts or logs any secret value.
    """

    environ = os.environ if env is None else env
    root = Path(data_dir)

    client_configured = bool(
        environ.get(GOOGLE_CLIENT_ID_ENV) and environ.get(GOOGLE_CLIENT_SECRET_ENV)
    )
    # A SecuRedact-managed (owned) OAuth app is also a valid client config: it is
    # the default production path, so its presence means Google can authorize
    # without the customer creating their own Google Cloud project. The managed
    # app is configured whenever the env override is set OR the packaged default
    # is present (a normal released build), so a normal customer is treated as
    # fully configured and is never prompted for an OAuth client id/secret.
    managed_configured = google_managed.is_managed_client_configured()
    if not client_configured and not managed_configured:
        try:
            from ..connectors.google.storage import GoogleClientConfigStore

            stored_id, stored_secret = GoogleClientConfigStore(root).load()
            client_configured = bool(stored_id and stored_secret)
        except Exception:
            client_configured = False
    # A managed app (env override or packaged default) alone is sufficient client
    # configuration.
    client_configured = client_configured or managed_configured

    token_present = (root / "google" / "token.json.enc").is_file()

    binding_integration_id: str | None = None
    try:
        for binding in ConnectorBindingStore(machine_agent_files(root, files)).list():
            if binding.platform == GOOGLE_CONNECTOR_PLATFORM:
                binding_integration_id = binding.integration_id
                break
    except Exception:
        binding_integration_id = None

    return GoogleMachineState(
        client_configured=client_configured,
        token_present=token_present,
        binding_integration_id=binding_integration_id,
    )


def resolve_google_selection(
    data_dir: Path | str,
    *,
    google: str | None = None,
    non_interactive: bool = False,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
    files: AgentFiles | None = None,
    env: Mapping[str, str] | None = None,
    state: GoogleMachineState | None = None,
) -> bool:
    """Decide whether the wizard must perform Google Workspace onboarding.

    Resolution order (the interactive wizard never requires a hidden env flag):

    1. an explicit ``--google no`` always wins (Google onboarding is skipped);
    2. an explicit ``--google yes`` always wins (including a value forwarded to the
       elevated continuation on argv);
    3. the non-secret ``SECUREDACT_GOOGLE_ENABLED=1`` operational override;
    4. *detected* machine-local Google configuration that shows the customer already
       chose/connected Google: a stored OAuth token, an existing machine binding, or
       an explicit ``SECUREDACT_GOOGLE_MANAGED_CLIENT_ID`` environment override. The
       packaged managed app is always present (the default production path) and is
       therefore NOT, by itself, a detection signal -- a fresh machine still asks
       "Connect Google Workspace?"; an idempotent rerun re-verifies existing state.
    5. an explicit interactive question, defaulting to "no";
    6. a non-interactive run with none of the above skips Google safely.
    """

    if google == "no":
        return False
    if google == "yes":
        return True

    environ = os.environ if env is None else env
    if environ.get(GOOGLE_ENABLED_ENV) == "1":
        return True

    detected = (
        state if state is not None else inspect_google_machine(data_dir, files=files, env=env)
    )
    # Auto-select only on genuine customer evidence: a stored token, an existing
    # binding, or an explicit managed-app environment override. The packaged managed
    # app is always present (the default production path), so it alone must NOT force
    # Google onboarding on a fresh machine -- the customer is still asked "Connect
    # Google Workspace?" (defaulting to no). An explicit override is a deliberate
    # packaging/operator decision and is treated as detected configuration.
    managed_env_override = bool(environ.get(google_managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV))
    if detected.token_present or detected.binding_integration_id or managed_env_override:
        print(
            "Google Workspace configuration detected on this computer; "
            "verifying the machine-local Google onboarding.",
            file=output,
        )
        return True

    if non_interactive:
        print(
            "Google Workspace onboarding was not selected (non-interactive run). "
            "Re-run 'securedact-mcp setup --agent --google yes' to connect one.",
            file=output,
        )
        return False

    print(file=output)
    print(
        "SecuRedact can scan a Google Workspace (Drive) integration from this "
        "computer. Files and detected values never leave the machine.",
        file=output,
    )
    try:
        answer = input_fn(GOOGLE_SELECTION_PROMPT).strip().casefold()
    except (EOFError, StopIteration):
        answer = "n"
    return answer in {"y", "yes"}


def prompt_google_client_config(
    data_dir: Path | str,
    *,
    input_fn: Callable[[str], str] = input,
    secret_input_fn: Callable[[str], str] | None = None,
    output: TextIO = sys.stderr,
    non_interactive: bool = False,
    env: Mapping[str, str] | None = None,
    save_fn: Callable[[Path | str, str | None, str | None], None] | None = None,
) -> bool:
    """Collect + persist the Google OAuth client (app) config when it is missing.

    Returns ``True`` only when a NEW client id/secret was collected and persisted,
    so the caller may retry authorization exactly once. Returns ``False`` when a
    client config is already available (nothing to do) or when it could not be
    collected (non-interactive run, or the operator declined).

    The client secret is read with a non-echoing prompt and persisted encrypted
    under the machine data root. It is never placed in the process environment, in
    a machine-wide environment variable, on argv, in logs, or sent to the control
    plane.
    """

    root = Path(data_dir)
    state = inspect_google_machine(root, env=env)
    if state.client_configured:
        return False
    if non_interactive:
        print(
            "A Google OAuth client id/secret is required for machine-local "
            "authorization; re-run this step interactively to supply it.",
            file=output,
        )
        return False

    import getpass

    read_secret = secret_input_fn or getpass.getpass
    print(file=output)
    print(
        "Google requires an OAuth client (from your Google Cloud project) to "
        "authorize Drive read-only access on this computer.",
        file=output,
    )
    try:
        client_id = input_fn("Google OAuth client ID: ").strip()
        client_secret = read_secret("Google OAuth client secret: ").strip()
    except (EOFError, StopIteration):
        print("No Google OAuth client supplied; skipping.", file=output)
        return False
    if not client_id or not client_secret:
        print("No Google OAuth client supplied; skipping.", file=output)
        return False

    if save_fn is not None:
        save_fn(root, client_id, client_secret)
    else:
        from ..connectors.google.config import save_google_client_config

        save_google_client_config(root, client_id, client_secret)
    print("Google OAuth client stored encrypted under the machine data root.", file=output)
    return True


def verify_machine_binding(
    data_dir: Path | str,
    integration_id: str,
    *,
    files: AgentFiles | None = None,
    profile: str = "default",
) -> bool:
    """Fail-closed proof that the machine-local Google binding really exists.

    Re-reads ``<machine data root>/agent/connector-bindings.json`` from disk and
    confirms it records exactly the resolved integration id on the
    ``google_workspace`` platform. This is the post-condition the wizard checks
    before it may report the Managed Agent as ready.
    """

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
        binding.platform == GOOGLE_CONNECTOR_PLATFORM
        and (binding.local_profile or "default") == profile
    )


def authorize_google_machine(
    data_dir: Path | str,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
    config_module: _GoogleConfigModule | None = None,
    auth_module: _GoogleAuthModule | None = None,
    non_interactive: bool = False,
    require_enabled: bool = True,
) -> bool:
    """Authorize Google locally on the machine (or reuse a valid machine token).

    Returns ``True`` when a valid machine-local Google credential exists or was
    just created. Returns ``False`` when Google is not enabled/configured, or when
    an interactive authorization could not be completed (e.g. non-interactive run).

    ``require_enabled`` controls whether the non-secret ``SECUREDACT_GOOGLE_ENABLED``
    operational flag must be present. The setup wizard passes ``False`` because an
    explicit Google selection (``--google yes``, detected machine configuration, or
    the interactive question) *is* the enablement signal -- the operator must never
    need to know a hidden environment flag. Direct/CLI callers keep the fail-closed
    default.

    The OAuth token is written only to ``<data_dir>/google`` via the injected
    config's credential store; no OAuth material is ever placed on argv, in the
    environment, or in logs. A pre-existing valid machine token is reused
    idempotently; this function never reads or migrates a user-profile token.
    """

    from ..connectors.google import auth as default_auth
    from ..connectors.google import config as default_config
    from ..connectors.google.config import GoogleConfigError

    # The fallback must be the config *module* (it is called as
    # ``cfg_module.load_google_config(...)``); binding the bare function here made
    # every real, non-injected call raise ``AttributeError: 'function' object has
    # no attribute 'load_google_config'`` instead of authorizing.
    cfg_module = config_module or cast("_GoogleConfigModule", default_config)
    auth_mod = auth_module or default_auth

    machine_data = Path(data_dir)
    try:
        config = cfg_module.load_google_config(
            require_enabled=require_enabled, data_dir=machine_data
        )
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
        # Name the *exact* interpreter that failed. A ``No module named
        # 'google_auth_oauthlib'`` here means this in-process path ran in an
        # interpreter without the Google extra (the setup CLI's own Python) instead
        # of the machine-owned runtime, which is precisely the RC defect this
        # diagnostic makes unmistakable.
        print(
            f"Could not start Google authorization in {sys.executable}: {scrub(str(exc))}",
            file=output,
        )
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

    resolved_id = normalize_integration_id(integration_id)
    if not resolved_id:
        raise AgentError("a Google Workspace integration_id is required to create a local binding")
    store = binding_store_cls(files)
    existing = store.get(resolved_id)
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
        resolved_id,
        GOOGLE_CONNECTOR_PLATFORM,
        profile=profile,
        files=files,
    )


def begin_google_authorization(data_dir: Path | str) -> tuple[str, str]:
    """Start a machine-local Google OAuth flow; return ``(url, state)``.

    Runs inside the *machine-owned runtime* (which carries the Google extra), so
    it never depends on the setup CLI's interpreter having ``google_auth_oauthlib``.

    This is the two-phase copy/paste flow: the consent URL is issued here and the code
    is exchanged by a *separate* runtime invocation. A PKCE ``code_verifier`` cannot
    survive that process boundary, so PKCE is genuinely disabled for both legs. The
    preferred path remains :func:`run_google_loopback_authorization`, which stays
    in-process and therefore keeps PKCE.
    """

    from ..connectors.google import auth as default_auth
    from ..connectors.google import config as default_config

    config = default_config.load_google_config(require_enabled=False, data_dir=Path(data_dir))
    return default_auth.get_authorization_url(config, pkce=False)


def complete_google_authorization(
    data_dir: Path | str, code: str, state: str | None = None
) -> bool:
    """Exchange an authorization code for a machine-local token; return success.

    Runs inside the *machine-owned runtime*. The token is persisted encrypted under
    the machine data root; no OAuth material is returned to the caller.

    ``state`` can only locate a pending authorization inside the process that issued
    the consent URL. When it cannot (the two-phase flow above), the exchange runs
    without a pending flow, which matches the PKCE-free consent URL that was issued.
    """

    from ..connectors.google import auth as default_auth
    from ..connectors.google import config as default_config

    config = default_config.load_google_config(require_enabled=False, data_dir=Path(data_dir))
    pending_state = state if default_auth.has_pending_authorization(state) else None
    default_auth.exchange_code(config, code, state=pending_state)
    return True


def run_google_loopback_authorization(data_dir: Path | str) -> dict[str, object]:
    """Run the full local loopback OAuth flow inside the machine-owned runtime.

    Returns a bounded, machine-readable result (``authorized`` plus a safe
    ``stage``/``error_code`` on failure). No OAuth code/token/client secret/verifier
    is ever placed on argv, in a command file, in the environment, or in logs. When
    the managed client is genuinely absent the result carries ``stage="config"`` with
    the safe ``google_config_missing`` code (the only correct place to report that).
    """

    from ..connectors.google import auth as default_auth
    from ..connectors.google import config as default_config
    from ..connectors.google.config import GoogleConfigError

    try:
        config = default_config.load_google_config(require_enabled=False, data_dir=Path(data_dir))
    except GoogleConfigError as exc:
        return {
            "authorized": False,
            "stage": "config",
            "error_code": "google_config_missing",
            "error": scrub(str(exc)),
        }
    outcome = default_auth.run_local_oauth(config)
    return outcome.to_payload()


# Concrete modules the machine-local Google OAuth flow imports. Kept here (next to
# the flow) so the runtime self-verification asserts exactly what the real
# authorization needs — including ``google_auth_oauthlib``, the import whose absence
# produced the RC ``No module named 'google_auth_oauthlib'`` failure.
GOOGLE_AUTH_RUNTIME_MODULES = (
    "google.auth",
    "google.oauth2.credentials",
    "google_auth_oauthlib.flow",
    "requests",
)


def verify_google_authorization_runtime(data_dir: Path | str) -> dict[str, Any]:
    """Prove *this* interpreter can perform the machine-local Google OAuth flow.

    Executes every step of the real loopback authorization except the two that
    need a human/Google: it does not open a browser, does not wait for a redirect,
    and never obtains or stores a token. Concretely it

    1. imports the exact Google modules the flow uses (``google_auth_oauthlib`` &
       friends) **in this interpreter**;
    2. resolves the machine-local Google configuration from ``data_dir``;
    3. binds the temporary ``127.0.0.1`` loopback listener on a random port; and
    4. builds the PKCE consent URL for that redirect URI (pure local construction).

    Returns a JSON-safe dict whose ``verified`` flag is the fail-closed signal, plus
    ``interpreter`` (``sys.executable``) so the operator can see exactly which
    Python was proven. The consent URL, OAuth state, client secret, and token are
    never included in the payload.
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
    for module in GOOGLE_AUTH_RUNTIME_MODULES:
        try:
            importlib.import_module(module)
            payload["imports"][module] = True
        except Exception as exc:
            payload["imports"][module] = False
            payload["error"] = scrub(f"{module}: {exc}")
    payload["imports_ok"] = all(payload["imports"].values())
    if not payload["imports_ok"]:
        return payload

    from ..connectors.google import auth as default_auth
    from ..connectors.google import config as default_config

    # 2. Machine-local configuration (managed app by default, BYO from the store).
    try:
        config = default_config.load_google_config(require_enabled=False, data_dir=Path(data_dir))
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
            url, state = default_auth.get_authorization_url(loopback_config, pkce=True)
        except Exception as exc:
            payload["error"] = scrub(str(exc))
            return payload
        # Never emit the consent URL / CSRF state, and do not retain the pending
        # flow (this is a verification, not an authorization).
        payload["consent_url_built"] = bool(url) and bool(state)
        default_auth._FLOW_STATE.pop(state, None)
    finally:
        server.shutdown()

    payload["verified"] = bool(
        payload["imports_ok"]
        and payload["client_configured"]
        and payload["loopback_bound"]
        and payload["consent_url_built"]
    )
    return payload


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


def apply_google_machine_env(data_dir: Path | str, *, enabled: bool | None = None) -> None:
    """Persist non-secret Google config at machine scope; encrypt the client secret.

    The OAuth client secret (and client id) are stored encrypted under the machine
    data root via :class:`GoogleClientConfigStore` so the SYSTEM-run scheduled task
    can load them after the setup PowerShell session closes and after a reboot -- without
    ever placing the secret in a machine-wide environment variable, argv, logs, or the
    control plane. Only the non-secret enable flag is published at machine scope (it is
    inherited by the SYSTEM-run scheduled task); the client id/secret are NOT written to
    the machine environment.

    ``enabled`` lets the setup wizard publish the non-secret enable flag when Google
    was selected interactively, so an operator never has to know
    ``SECUREDACT_GOOGLE_ENABLED``. When it is ``None`` the pre-existing environment
    value decides.

    Invariants preserved:
      * OAuth access/refresh tokens remain machine-local (separate token vault).
      * client secret remains machine-local (encrypted under the machine data root).
      * no secret in argv, no secret in logs, no secret sent to the control plane.
      * non-secret configuration (the enable flag) may remain in the machine environment.
    """

    from ..connectors.google.storage import GoogleClientConfigStore

    data_dir = Path(data_dir)
    env_client_id = os.environ.get(GOOGLE_CLIENT_ID_ENV)
    env_client_secret = os.environ.get(GOOGLE_CLIENT_SECRET_ENV)

    # Persist the client (app) config encrypted under the machine data root. This
    # is what lets the background task obtain the secret after reboot, without it
    # ever becoming a machine-wide environment variable.
    if env_client_id or env_client_secret:
        try:
            GoogleClientConfigStore(data_dir).save(env_client_id, env_client_secret)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"could not persist google client config: {scrub(str(exc))}", file=sys.stderr)

    # Only the non-secret enable flag is published at machine scope.
    publish = enabled if enabled is not None else os.environ.get(GOOGLE_ENABLED_ENV) == "1"
    if publish:
        _set_machine_env_var(GOOGLE_ENABLED_ENV, "1")
