# SPDX-License-Identifier: Apache-2.0
"""Control-plane client (AGENT-006).

Implements the agent-facing protocol surface used by the managed runtime:
registration, heartbeat, credential rotation, entitlement activate/refresh, JWKS
retrieval, and the pull-job lifecycle (claim -> job heartbeat -> result). Every
authenticated request carries ``Authorization: Bearer <sra_...>``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .capabilities import AgentCapabilities
from .credentials import AgentCredential
from .errors import (
    AgentCredentialError,
    AgentRegistrationError,
    AgentRevokedError,
    ControlPlaneError,
    TransportError,
)
from .transport import HTTPResponse, HTTPTransport


@dataclass(frozen=True, slots=True)
class RegisterResponse:
    agent_id: str
    credential: str
    control_plane_url: str
    heartbeat_interval_seconds: int


@dataclass(frozen=True, slots=True)
class HeartbeatResponse:
    server_time: str
    agent_id: str
    recommended_heartbeat_seconds: int
    config_refresh_required: bool
    entitlement_refresh_required: bool


USER_AGENT = "securedact-mcp-agent"


class ControlPlaneClient:
    """Typed client for the SecuRedact control plane."""

    def __init__(
        self,
        base_url: str,
        *,
        credential_provider: Callable[[], AgentCredential | None],
        transport: HTTPTransport | None = None,
        user_agent: str = USER_AGENT,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._credential_provider = credential_provider
        self._transport = transport or HTTPTransport()
        self._user_agent = user_agent

    # --- low level ------------------------------------------------------------

    def _post(
        self,
        path: str,
        *,
        auth: bool,
        json_body: dict[str, Any] | None,
    ) -> HTTPResponse:
        headers = {"User-Agent": self._user_agent}
        if auth:
            cred = self._credential_provider()
            if cred is None:
                raise AgentCredentialError("no agent credential available (register first)")
            headers["Authorization"] = cred.authorization_header
        try:
            return self._transport.post(f"{self._base}{path}", headers=headers, json_body=json_body)
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(f"control plane request failed: {exc}") from exc

    def _ok(self, resp: HTTPResponse, expected: int, what: str) -> dict[str, Any]:
        if resp.status == expected:
            return resp.body or {}
        code, message = _error_of(resp)
        if resp.status == 401 and code in (None, "agent_credential_invalid"):
            raise AgentCredentialError(message or "agent credential invalid")
        if resp.status == 403 and code == "agent_revoked":
            raise AgentRevokedError(message or "agent revoked")
        raise ControlPlaneError(
            message or f"{what} failed",
            code=code,
            status=resp.status,
            retryable=resp.status in {429, 500, 502, 503, 504},
        )

    # --- endpoints ------------------------------------------------------------

    def register(
        self,
        registration_token: str,
        *,
        display_name: str,
        agent_version: str,
        platform: str,
        capabilities: AgentCapabilities,
    ) -> RegisterResponse:
        resp = self._post(
            "/v1/agents/register",
            auth=False,
            json_body={
                "registration_token": registration_token,
                "display_name": display_name,
                "agent_version": agent_version,
                "platform": platform,
                "capabilities": capabilities.to_registration_payload(),
            },
        )
        if resp.status != 201:
            code, message = _error_of(resp)
            raise AgentRegistrationError(
                message or "registration failed",
                code=code,
                status=resp.status,
            )
        body = resp.body or {}
        cred = body.get("credential")
        if not cred or not isinstance(cred, str):
            raise AgentRegistrationError("control plane did not return a credential")
        return RegisterResponse(
            agent_id=str(body.get("agent_id", "")),
            credential=cred,
            control_plane_url=str(body.get("control_plane_url") or self._base),
            heartbeat_interval_seconds=int(body.get("heartbeat_interval_seconds", 60)),
        )

    def heartbeat(
        self,
        *,
        agent_version: str,
        capabilities: AgentCapabilities,
        connector_bindings: list[dict[str, str]] | None = None,
    ) -> HeartbeatResponse:
        body: dict[str, Any] = {
            "agent_version": agent_version,
            "capabilities": capabilities.to_registration_payload(),
        }
        if connector_bindings is not None:
            body["connector_bindings"] = connector_bindings
        resp = self._post("/v1/agents/heartbeat", auth=True, json_body=body)
        body = self._ok(resp, 200, "heartbeat")
        return HeartbeatResponse(
            server_time=str(body.get("server_time", "")),
            agent_id=str(body.get("agent_id", "")),
            recommended_heartbeat_seconds=int(body.get("recommended_heartbeat_seconds", 60)),
            config_refresh_required=bool(body.get("config_refresh_required", False)),
            entitlement_refresh_required=bool(body.get("entitlement_refresh_required", False)),
        )

    def rotate_credential(self) -> str:
        resp = self._post("/v1/agents/credentials/rotate", auth=True, json_body={})
        body = self._ok(resp, 200, "credential rotation")
        cred = body.get("credential")
        if not isinstance(cred, str) or not cred:
            raise AgentCredentialError("rotation did not return a credential")
        return cred

    def activate_entitlement(self) -> str:
        resp = self._post("/v1/entitlements/activate", auth=True, json_body={})
        body = self._ok(resp, 200, "entitlement activation")
        return _require_jwt(body, "activation")

    def refresh_entitlement(self) -> str:
        resp = self._post("/v1/entitlements/refresh", auth=True, json_body={})
        body = self._ok(resp, 200, "entitlement refresh")
        return _require_jwt(body, "refresh")

    def get_jwks(self) -> dict[str, Any]:
        # The JWKS endpoint is a public, unauthenticated GET resource. It must
        # never carry the agent credential, only a User-Agent.
        try:
            resp = self._transport.get(
                f"{self._base}/.well-known/jwks.json",
                headers={"User-Agent": self._user_agent},
            )
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(f"jwks request failed: {exc}") from exc
        if resp.status != 200 or not isinstance(resp.body, dict):
            raise ControlPlaneError(
                "jwks unavailable", status=resp.status, retryable=resp.status >= 500
            )
        return resp.body

    def claim_job(self) -> dict[str, Any] | None:
        resp = self._post("/v1/agents/jobs/claim", auth=True, json_body={})
        if resp.status == 204:
            return None
        body = self._ok(resp, 200, "job claim")
        return body

    def job_heartbeat(
        self,
        job_id: str,
        *,
        lease_secret: str,
        lease_generation: int,
        renew_seconds: int,
    ) -> dict[str, Any]:
        resp = self._post(
            f"/v1/agents/jobs/{job_id}/heartbeat",
            auth=True,
            json_body={
                "lease_secret": lease_secret,
                "lease_generation": lease_generation,
                "renew_seconds": renew_seconds,
            },
        )
        return self._ok(resp, 200, "job heartbeat")

    def submit_result(
        self,
        job_id: str,
        *,
        lease_secret: str,
        lease_generation: int,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        # The safe scan-result object is nested under ``result`` so the
        # transport/authorization metadata (lease_secret, lease_generation) is
        # never part of the validated payload. validate_safe_result only ever
        # sees the nested object.
        body = {
            "lease_secret": lease_secret,
            "lease_generation": lease_generation,
            "result": result,
        }
        resp = self._post(f"/v1/agents/jobs/{job_id}/result", auth=True, json_body=body)
        return self._ok(resp, 200, "result submission")

    def list_eligible_google_integrations(
        self, *, agent_identity: str | None = None
    ) -> list[dict[str, Any]]:
        """Return eligible Google Workspace integrations for the agent's organization.

        Calls ``GET /v1/agents/integrations/eligible`` which requires agent
        authentication. Returns a list of integration objects with ``id``,
        ``platform``, and ``display_name``.
        """
        cred = self._credential_provider()
        if cred is None:
            raise AgentCredentialError("no agent credential available (register first)")
        resp = self._transport.get(
            f"{self._base}/v1/agents/integrations/eligible",
            headers={
                "User-Agent": self._user_agent,
                "Authorization": cred.authorization_header,
            },
        )
        if resp.status == 401:
            raise AgentCredentialError("agent credential invalid")
        if resp.status != 200:
            raise ControlPlaneError(
                "failed to list eligible integrations",
                status=resp.status,
                retryable=resp.status >= 500,
            )
        body = resp.body or {}
        integrations = body.get("integrations", [])
        if not isinstance(integrations, list):
            return []
        return integrations


def _require_jwt(body: dict[str, Any], what: str) -> str:
    token = body.get("entitlement")
    if not isinstance(token, str) or not token:
        raise ControlPlaneError(f"entitlement {what} did not return a token")
    return token


def _error_of(resp: HTTPResponse) -> tuple[str | None, str]:
    body = resp.body
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return err.get("code"), err.get("message") or "control plane error"
    return None, "control plane error"
