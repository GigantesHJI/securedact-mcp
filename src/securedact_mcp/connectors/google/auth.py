# SPDX-License-Identifier: Apache-2.0
"""Google OAuth 2.0 authorization (control plane, GWS-110).

Implements the read-only OAuth flow with ``google-auth-oauthlib``. All Google
imports are lazy so this module loads without the optional ``google`` extra.
The flow requests only the least-privilege scopes from configuration, sets
``access_type=offline`` (refresh token) and ``prompt=consent`` so a refresh
token is returned, and persists the resulting token encrypted via
:class:`GoogleCredentialStore`. Tokens are never returned through logs or
error messages.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from securedact_core.connectors.google import GoogleAuthError

from .config import GoogleConfigError, GoogleConnectorConfig
from .storage import GoogleCredentialStore

logger = logging.getLogger(__name__)


def build_flow(config: GoogleConnectorConfig) -> Any:
    """Build an installed-app OAuth flow for the configured client/scopes."""

    from google_auth_oauthlib.flow import Flow

    client_id, client_secret = config.require_credentials()
    client_config = {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [config.redirect_uri],
        }
    }
    return Flow.from_client_config(
        client_config,
        scopes=list(config.scopes),
        redirect_uri=config.redirect_uri,
    )


def get_authorization_url(config: GoogleConnectorConfig) -> tuple[str, str]:
    """Return the consent-screen URL and CSRF ``state`` for the flow."""

    flow = build_flow(config)
    url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent"
    )
    # Stash the flow's state for later exchange (rebuilt flow matches by state).
    _FLOW_STATE[state] = flow
    return url, state


# Module-level flow cache keyed by CSRF state (single-process CLI use only).
_FLOW_STATE: dict[str, Any] = {}


def exchange_code(
    config: GoogleConnectorConfig, code: str, *, state: str | None = None
) -> dict[str, Any]:
    """Exchange an authorization code for tokens, persist them, return the dict."""

    if state is not None and state in _FLOW_STATE:
        flow = _FLOW_STATE.pop(state)
    else:
        flow = build_flow(config)
    try:
        flow.fetch_token(code=code)
    except Exception as exc:  # network / invalid code / revoked consent
        raise GoogleAuthError(f"Google authorization failed: {type(exc).__name__}") from exc
    return _persist(config, flow.credentials)


def _persist(config: GoogleConnectorConfig, credentials: Any) -> dict[str, Any]:
    store: GoogleCredentialStore = config.credential_store()
    token = _credentials_to_dict(credentials)
    store.save_token(token)
    return token


def _credentials_to_dict(credentials: Any) -> dict[str, Any]:
    import json as _json

    return cast("dict[str, Any]", _json.loads(credentials.to_json()))


def load_credentials(config: GoogleConnectorConfig) -> Any | None:
    """Load and refresh persisted credentials, or ``None`` if absent/revoked."""

    store: GoogleCredentialStore = config.credential_store()
    token = store.load_token()
    if token is None:
        return None
    try:
        return _build_credentials(token)
    except GoogleAuthError:
        return None


def _build_credentials(token: dict[str, Any]) -> Any:
    from google.oauth2.credentials import Credentials

    try:
        creds = Credentials.from_authorized_user_info(token)
    except Exception as exc:
        raise GoogleAuthError("Google stored credentials are invalid") from exc
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(_request_adapter())
        except Exception as exc:
            raise GoogleAuthError("Google refresh token was rejected or revoked") from exc
    if not creds.valid:
        raise GoogleAuthError("Google credentials are not valid")
    return creds


def _request_adapter() -> Any:
    from google.auth.transport.requests import Request

    return Request()


def revoke_credentials(config: GoogleConnectorConfig) -> None:
    """Best-effort revocation + local token deletion."""

    store: GoogleCredentialStore = config.credential_store()
    token = store.load_token()
    if token is not None and token.get("refresh_token"):
        # Use the documented revoke endpoint directly (no extra SDK surface).
        try:
            import requests

            requests.post(
                "https://oauth2.googleapis.com/revoke",
                data={"token": token["refresh_token"]},
                timeout=10,
            )
        except Exception as exc:
            logger.debug("Google token revocation request failed: %s", type(exc).__name__)
    store.delete_token()


def require_valid_credentials(config: GoogleConnectorConfig) -> Any:
    """Return valid credentials or raise (fail closed)."""

    creds = load_credentials(config)
    if creds is None:
        raise GoogleConfigError(
            "No valid Google authorization found. Run: securedact-mcp google auth"
        )
    return creds
