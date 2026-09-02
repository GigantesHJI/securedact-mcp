# SPDX-License-Identifier: Apache-2.0
"""Agent orchestration: registration, heartbeat loop, claim/execute/submit (AGENT-016).

This module wires the protocol client, entitlement manager, credential store,
policy resolver, scan provider, and reducer into the managed-agent lifecycle. It
is local-first and fail-closed: any policy/entitlement/execution problem that
cannot be safely resolved becomes a ``failed`` result (or a safe skip), never a
silent success that leaks or misreports.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from securedact_core.api import SecuredactEngine
from securedact_core.policies import Policy

from .capabilities import AgentCapabilities, agent_version, runtime_platform
from .client import ControlPlaneClient
from .config import (
    CONTROL_PLANE_URL_ENV,
    DEFAULT_CONTROL_PLANE_URL,
    AgentConfig,
    AgentFiles,
    generate_display_name,
    normalize_control_plane_url,
    save_config,
)
from .connectors import ConnectorBinding, ConnectorBindingStore
from .credentials import AgentCredential, AgentCredentialStore
from .entitlement import Entitlement, EntitlementManager
from .errors import (
    AgentCredentialError,
    AgentRevokedError,
    ControlPlaneError,
    EntitlementError,
    JobExecutionError,
    LeaseError,
    PolicyValidationError,
    TransportError,
)
from .executor import JobClaim, ScanProvider, execute_job
from .policy import ResolvedPolicy, resolve_policy
from .provider_google import GoogleScanProvider
from .reducer import (
    ExecutionResult,
    build_safe_result_dict,
    validate_safe_result,
)
from .safe_log import scrub
from .state import AgentStateStore

logger = logging.getLogger(__name__)

_HEARTBEAT_RENEW_SECONDS = 300


def build_provider(platform: str, *, files: AgentFiles | None = None) -> ScanProvider | None:
    """Return a local scan provider for a platform, or ``None`` if unsupported."""

    if platform == "google_workspace":
        return GoogleScanProvider(files=files)
    return None


# ---------------------------------------------------------------------------
# Registration / credential lifecycle
# ---------------------------------------------------------------------------


def register_agent(
    registration_token: str,
    *,
    control_plane_url: str | None = None,
    display_name: str | None = None,
    transport: Any = None,
    files: AgentFiles | None = None,
) -> AgentConfig:
    """Register the local agent and persist its config + issued credential."""

    files = files or AgentFiles.resolve()
    cp_url = normalize_control_plane_url(
        control_plane_url or os.getenv(CONTROL_PLANE_URL_ENV) or DEFAULT_CONTROL_PLANE_URL
    )
    client = ControlPlaneClient(cp_url, credential_provider=lambda: None, transport=transport)
    caps = AgentCapabilities.default()
    name = display_name or generate_display_name()
    resp = client.register(
        registration_token,
        display_name=name,
        agent_version=agent_version(),
        platform=runtime_platform(),
        capabilities=caps,
    )
    config = AgentConfig.create(
        control_plane_url=resp.control_plane_url or cp_url,
        agent_id=resp.agent_id,
        display_name=name,
        runtime_platform=runtime_platform(),
        agent_version=agent_version(),
        capabilities=caps,
    )
    save_config(config, files)
    store = AgentCredentialStore(config.agent_id, root=files.root)
    store.save(resp.credential)
    logger.info("agent registered: %s", scrub(config.agent_id))
    return config


def rotate_credential(
    config: AgentConfig, *, transport: Any = None, files: AgentFiles | None = None
) -> AgentCredential:
    """Rotate the agent credential and atomically replace local storage."""

    files = files or AgentFiles.resolve()
    store = AgentCredentialStore(config.agent_id, root=files.root)
    client = ControlPlaneClient(
        config.control_plane_url, credential_provider=store.get, transport=transport
    )
    new_raw = client.rotate_credential()
    return store.rotate(new_raw)


def refresh_entitlement(
    config: AgentConfig, *, transport: Any = None, files: AgentFiles | None = None
) -> Entitlement:
    """Activate (re-issue online) the agent entitlement and return it."""

    files = files or AgentFiles.resolve()
    store = AgentCredentialStore(config.agent_id, root=files.root)
    client = ControlPlaneClient(
        config.control_plane_url, credential_provider=store.get, transport=transport
    )
    manager = EntitlementManager(client)
    return manager.activate()


# ---------------------------------------------------------------------------
# Connector bindings
# ---------------------------------------------------------------------------


def bind_connector(
    config: AgentConfig,
    integration_id: str,
    platform: str,
    *,
    profile: str | None = None,
    display_name: str | None = None,
    files: AgentFiles | None = None,
) -> ConnectorBinding:
    store = ConnectorBindingStore(files)
    binding = ConnectorBinding(
        integration_id=integration_id,
        platform=platform,
        local_profile=profile or "default",
        display_name=display_name,
    )
    store.bind(binding)
    return binding


def list_connectors(
    config: AgentConfig, *, files: AgentFiles | None = None
) -> list[ConnectorBinding]:
    return ConnectorBindingStore(files).list()


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AgentStatus:
    agent_id: str
    registered: bool
    credential_present: bool
    control_plane_url: str
    display_name: str
    runtime_platform: str
    agent_version: str
    supported_platforms: list[str]
    last_heartbeat_at: float | None = None
    entitlement_expires_at: float | None = None
    current_job_id: str | None = None
    last_error: str | None = None
    bindings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "registered": self.registered,
            "credential_present": self.credential_present,
            "control_plane_url": self.control_plane_url,
            "display_name": self.display_name,
            "runtime_platform": self.runtime_platform,
            "agent_version": self.agent_version,
            "supported_platforms": self.supported_platforms,
            "last_heartbeat_at": self.last_heartbeat_at,
            "entitlement_expires_at": self.entitlement_expires_at,
            "current_job_id": self.current_job_id,
            "last_error": self.last_error,
            "bindings": self.bindings,
        }


def agent_status(config: AgentConfig, *, files: AgentFiles | None = None) -> AgentStatus:
    files = files or AgentFiles.resolve()
    store = AgentCredentialStore(config.agent_id, root=files.root)
    state = AgentStateStore(files).load()
    bindings = [b.to_dict() for b in ConnectorBindingStore(files).list()]
    return AgentStatus(
        agent_id=config.agent_id,
        registered=True,
        credential_present=store.get() is not None,
        control_plane_url=config.control_plane_url,
        display_name=config.display_name,
        runtime_platform=config.runtime_platform,
        agent_version=config.agent_version,
        supported_platforms=sorted(config.capabilities.supported_platforms),
        last_heartbeat_at=state.last_heartbeat_at,
        entitlement_expires_at=state.entitlement_expires_at,
        current_job_id=state.current_job_id,
        last_error=state.last_error,
        bindings=bindings,
    )


# ---------------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------------


def _heartbeat(
    config: AgentConfig,
    client: ControlPlaneClient,
    state_store: AgentStateStore,
    *,
    clock: Callable[[], float] = time.time,
) -> None:
    try:
        client.heartbeat(agent_version=config.agent_version, capabilities=config.capabilities)
    except Exception as exc:
        # A heartbeat failure is a genuine control-plane comms error; record it.
        state_store.update(last_heartbeat_at=clock(), last_error=scrub(str(exc)))
        raise
    # A successful routine heartbeat must NOT erase a meaningful prior error
    # (e.g. a job execution fault or control-plane rejection). It only refreshes
    # its own timestamp so transient faults stay visible until the next handled
    # job clears them.
    state_store.update(last_heartbeat_at=clock())
    logger.info("heartbeat ok agent_id=%s", scrub(config.agent_id))


def _job_heartbeat(
    client: ControlPlaneClient, claim: JobClaim, *, clock: Callable[[], float]
) -> None:
    try:
        client.job_heartbeat(
            claim.job_id,
            lease_secret=claim.lease_secret,
            lease_generation=claim.lease_generation,
            renew_seconds=_HEARTBEAT_RENEW_SECONDS,
        )
    except Exception:  # noqa: S110  # best-effort job heartbeat renewal; failures are non-fatal and surfaced by the outer job loop
        pass


def _failed_result(policy: ResolvedPolicy, safe_error_code: str) -> ExecutionResult:
    return ExecutionResult(
        status="failed",
        severity="none",
        categories=[],
        counts={},
        review_required=True,
        policy_decision="review",
        supported_action="none",
        safe_error_code=safe_error_code,
        resources_scanned=0,
        duration_ms=0,
        policy_version_id=policy.policy_version_id,
        policy_digest=policy.content_digest,
    )


def _submit_result(
    client: ControlPlaneClient,
    claim: JobClaim,
    result: ExecutionResult,
    *,
    warnings: list[str] | None = None,
    clock: Callable[[], float] = time.time,
) -> None:
    result_dict = build_safe_result_dict(result, warnings=warnings)
    # Defense-in-depth: even before the allowlist validator runs, reject any
    # leaked sensitive substring (PII values, OAuth tokens, content keys).
    from .reducer import assert_no_forbidden_substrings

    assert_no_forbidden_substrings(result_dict)
    try:
        validate_safe_result(result_dict)
    except ValueError:
        result_dict = build_safe_result_dict(
            _failed_result(
                ResolvedPolicy(
                    policy=__resolve_dummy_policy(),
                    policy_version_id=result.policy_version_id,
                    content_digest=result.policy_digest,
                ),
                "internal_error",
            )
        )
        validate_safe_result(result_dict)
    client.submit_result(
        claim.job_id,
        lease_secret=claim.lease_secret,
        lease_generation=claim.lease_generation,
        result=result_dict,
    )


def __resolve_dummy_policy() -> Policy:  # pragma: no cover - defensive only
    from securedact_core.policies import STRICT_EXTERNAL_AI_POLICY

    return STRICT_EXTERNAL_AI_POLICY


def _finalize_job(
    state_store: AgentStateStore,
    client: ControlPlaneClient,
    claim: JobClaim,
    exe_result: ExecutionResult,
    *,
    clock: Callable[[], float] = time.time,
) -> None:
    """Submit a (possibly failed) result and record terminal state.

    Even if result submission fails (e.g. the control plane is unreachable), the
    failure is recorded as ``last_error`` and never erased by a later routine
    heartbeat, so the job is never silently stranded as a success.
    """

    try:
        _submit_result(client, claim, exe_result, clock=clock)
    except Exception as exc:
        logger.warning("job %s result submission failed: %s", claim.job_id, scrub(str(exc)))
        state_store.update(current_job_id=None, last_error=scrub(str(exc)))
        return
    state_store.update(current_job_id=None, last_successful_result_at=clock(), last_error=None)
    if exe_result.status == "failed":
        logger.info(
            "job failed job_id=%s safe_error_code=%s", claim.job_id, exe_result.safe_error_code
        )
    else:
        logger.info("job completed job_id=%s", claim.job_id)


def _run_one_job(
    claim_dict: dict[str, Any],
    client: ControlPlaneClient,
    config: AgentConfig,
    state_store: AgentStateStore,
    *,
    clock: Callable[[], float] = time.time,
    files: AgentFiles | None = None,
) -> None:
    try:
        claim = JobClaim.from_claim(claim_dict)
    except LeaseError as exc:
        # A malformed claim (e.g. missing one-time lease secret) cannot be acted
        # on or reported back; surface it persistently rather than vanishing.
        logger.error("job claim rejected: %s", scrub(str(exc)))
        state_store.update(current_job_id=None, last_error=scrub(str(exc)))
        return

    state_store.update(current_job_id=claim.job_id)
    logger.info("job claimed job_id=%s", claim.job_id)
    try:
        policy = resolve_policy(claim.policy)
    except PolicyValidationError as exc:
        logger.warning("job %s policy rejected: %s", claim.job_id, scrub(str(exc)))
        _finalize_job(
            state_store,
            client,
            claim,
            _failed_result(policy_placeholder(), "policy_invalid"),
            clock=clock,
        )
        return

    provider = build_provider(claim.platform, files=files)
    if provider is None:
        _finalize_job(
            state_store, client, claim, _failed_result(policy, "unsupported_target"), clock=clock
        )
        return

    try:
        engine = SecuredactEngine.from_environment()
    except Exception as exc:
        logger.warning("privacy engine unavailable: %s", scrub(str(exc)))
        engine = None

    if engine is None:
        _finalize_job(
            state_store,
            client,
            claim,
            _failed_result(policy, "engine_unavailable_local"),
            clock=clock,
        )
        return

    def _heartbeat_callback() -> None:
        _job_heartbeat(client, claim, clock=clock)

    try:
        exe_result = execute_job(
            claim, engine, provider, policy, heartbeat=_heartbeat_callback, clock=clock
        )
    except LeaseError as exc:
        # The lease expired (or was already invalid) before/during execution.
        # The job is already claimed, so we still submit a safe failed result so
        # the control plane can move it to its terminal/retry state instead of
        # stranding it in "claimed" until the lease lapses.
        logger.warning("job %s lease invalid: %s", claim.job_id, scrub(str(exc)))
        exe_result = _failed_result(policy, "lease_invalid")
    except JobExecutionError as exc:
        logger.warning("job %s execution error: %s", claim.job_id, scrub(str(exc)))
        # Use the specific error code from the exception if available,
        # otherwise fall back to the message-based heuristic.
        code = exc.code or (
            "connector_unavailable"
            if "unavailable" in str(exc).lower() or "google connector" in str(exc).lower()
            else "agent_execution_error"
        )
        exe_result = _failed_result(policy, code)
    except Exception as exc:
        # Any other unexpected local failure must still reach the control plane
        # as a safe failed result rather than silently stranding the job.
        logger.exception("job %s unexpected execution failure: %s", claim.job_id, scrub(str(exc)))
        exe_result = _failed_result(policy, "agent_execution_error")

    _finalize_job(state_store, client, claim, exe_result, clock=clock)


def policy_placeholder() -> ResolvedPolicy:
    from securedact_core.policies import STRICT_EXTERNAL_AI_POLICY

    return ResolvedPolicy(
        policy=STRICT_EXTERNAL_AI_POLICY, policy_version_id=None, content_digest=None
    )


def run_agent_loop(
    config: AgentConfig,
    *,
    transport: Any = None,
    idle_sleep: float = 30.0,
    max_iterations: int | None = None,
    clock: Callable[[], float] = time.time,
    stop: Callable[[], bool] | None = None,
    files: AgentFiles | None = None,
) -> int:
    """Run the managed-agent pull loop until stopped or ``max_iterations`` reached."""

    files = files or AgentFiles.resolve()
    store = AgentCredentialStore(config.agent_id, root=files.root)
    client = ControlPlaneClient(
        config.control_plane_url, credential_provider=store.get, transport=transport
    )
    manager = EntitlementManager(client)
    state_store = AgentStateStore(files)

    try:
        ent = manager.activate()
        state_store.update(
            entitlement_expires_at=ent.expires_at, entitlement_not_before=ent.not_before
        )
    except EntitlementError as exc:
        logger.warning("entitlement activation deferred (offline grace): %s", scrub(str(exc)))

    iterations = 0
    logger.info(
        "agent loop starting agent_id=%s version=%s idle_sleep=%s",
        scrub(config.agent_id),
        config.agent_version,
        idle_sleep,
    )
    while True:
        if stop is not None and stop():
            break
        if max_iterations is not None and iterations >= max_iterations:
            break
        iterations += 1
        try:
            _heartbeat(config, client, state_store, clock=clock)
            try:
                manager.ensure_valid()
            except EntitlementError as exc:
                logger.debug("entitlement refresh unavailable: %s", scrub(str(exc)))
            claim = client.claim_job()
        except AgentRevokedError as exc:
            state_store.update(last_error=scrub(str(exc)))
            logger.error("agent revoked; stopping loop: %s", scrub(str(exc)))
            break
        except (ControlPlaneError, TransportError, AgentCredentialError) as exc:
            state_store.update(last_error=scrub(str(exc)))
            logger.warning("control plane error; backing off: %s", scrub(str(exc)))
            time.sleep(idle_sleep)
            continue

        if claim is None:
            time.sleep(idle_sleep)
            continue

        try:
            _run_one_job(claim, client, config, state_store, clock=clock, files=files)
        except AgentRevokedError:
            break
        except Exception as exc:
            state_store.update(last_error=scrub(str(exc)))
            logger.exception("unexpected error handling job: %s", scrub(str(exc)))

    return iterations
