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

import dataclasses
import logging
import socket
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol, cast

from securedact_core.connectors.google import GoogleAuthError

from .config import GoogleConfigError, GoogleConnectorConfig
from .storage import GoogleCredentialStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Safe, bounded post-callback diagnostics (no secret material)
# ---------------------------------------------------------------------------
#
# Every post-callback failure used to collapse to ``{"authorized": false}``,
# hiding the real stage from the setup CLI and the operator. The runtime now returns
# a bounded, machine-readable outcome that names only the stage and a safe error code
# (never the authorization code, token, verifier, client secret, or any part of the
# OAuth token response).

# Post-callback stages, in execution order. None of these ever carries secret data.
LOOPBACK_STAGE_CALLBACK = "callback"
LOOPBACK_STAGE_STATE_VALIDATION = "state_validation"
LOOPBACK_STAGE_CALLBACK_ERROR = "callback_error"
LOOPBACK_STAGE_MISSING_CODE = "missing_code"
LOOPBACK_STAGE_TOKEN_EXCHANGE = "token_exchange"  # noqa: S105 - safe stage name
LOOPBACK_STAGE_PERSISTENCE = "persistence"
LOOPBACK_STAGE_COMPLETE = "complete"

# Safe error codes (bounded vocabulary, no PII / secrets).
ERR_STATE_MISMATCH = "google_loopback_state_mismatch"
ERR_GOOGLE_CALLBACK_ERROR = "google_callback_error"
ERR_MISSING_CODE = "google_loopback_missing_code"
ERR_TOKEN_EXCHANGE_FAILED = "google_token_exchange_failed"  # noqa: S105 - safe code
ERR_PERSISTENCE_FAILED = "google_token_persistence_failed"
ERR_UNEXPECTED = "google_loopback_unexpected_error"
ERR_CONFIG_MISSING = "google_config_missing"


@dataclasses.dataclass
class GoogleLoopbackOutcome:
    """Bounded result of a local loopback OAuth attempt (no secret material)."""

    authorized: bool
    stage: str | None = None
    error_code: str | None = None
    error: str | None = None

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {"authorized": self.authorized}
        if self.stage is not None:
            payload["stage"] = self.stage
        if self.error_code is not None:
            payload["error_code"] = self.error_code
        if self.error is not None:
            # Only stage names / exception types are ever reported here.
            payload["error"] = str(self.error)
        return payload


def _loopback_failure(
    stage: str, error_code: str, exc: BaseException | None = None
) -> GoogleLoopbackOutcome:
    """Build a fail-closed outcome that names only the stage and a safe code."""

    detail = type(exc).__name__ if exc is not None else stage
    return GoogleLoopbackOutcome(
        authorized=False,
        stage=stage,
        error_code=error_code,
        error=f"{stage}: {detail}",
    )


class _GoogleCredentials(Protocol):
    """Narrow surface of ``google.oauth2.credentials.Credentials`` consumed here."""

    expired: bool
    valid: bool
    refresh_token: str | None

    def refresh(self, request: Any) -> None: ...


def build_flow(config: GoogleConnectorConfig) -> Any:
    """Build an OAuth flow for the configured client/scopes.

    Uses the Desktop/Installed application client type when no client secret is
    present (a SecuRedact-managed public client), or the confidential ``web`` type
    when a secret is supplied (BYO/enterprise). A public client requires no secret.
    """

    from google_auth_oauthlib.flow import Flow

    client_id, client_secret = config.require_credentials()
    if config.client_type == "web" and client_secret:
        client_config = {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [config.redirect_uri],
            }
        }
    else:
        # Desktop / Installed application: no client secret required (public client).
        client_config = {
            "installed": {
                "client_id": client_id,
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


def get_authorization_url(config: GoogleConnectorConfig, *, pkce: bool = True) -> tuple[str, str]:
    """Return the consent-screen URL and CSRF ``state`` for the flow.

    When ``pkce`` is true (the default, used by the loopback flow which keeps the
    flow in-process) a PKCE ``code_verifier`` is attached; the manual copy/paste
    fallback disables PKCE because the verifier cannot survive the process boundary.
    """

    flow = build_flow(config)
    try:
        url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            pkce="S256" if pkce else None,
        )
    except TypeError:
        # Extremely old google-auth-oauthlib without the pkce kwarg: fall back.
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

    credentials = _exchange_token_only(config, code, state=state)
    return _persist_credentials(config, credentials)


def _exchange_token_only(
    config: GoogleConnectorConfig, code: str, *, state: str | None = None
) -> Any:
    """Exchange the authorization code for credentials without persisting them.

    PKCE is honored because the in-process flow that built the consent URL left its
    ``code_verifier`` on the flow object (keyed by CSRF ``state`` in ``_FLOW_STATE``).
    Any network / invalid-code / revoked-consent failure raises :class:`GoogleAuthError`
    carrying only the exception type (no token material).
    """

    if state is not None and state in _FLOW_STATE:
        flow = _FLOW_STATE.pop(state)
    else:
        flow = build_flow(config)
    try:
        flow.fetch_token(code=code)
    except Exception as exc:  # network / invalid code / revoked consent
        raise GoogleAuthError(f"Google token exchange failed: {type(exc).__name__}") from exc
    return flow.credentials


def _persist_credentials(config: GoogleConnectorConfig, credentials: Any) -> dict[str, Any]:
    """Encrypt and persist credentials, raising on any storage failure."""

    store: GoogleCredentialStore = config.credential_store()
    token = _credentials_to_dict(credentials)
    try:
        store.save_token(token)
    except Exception as exc:
        raise GoogleAuthError(f"Google token persistence failed: {type(exc).__name__}") from exc
    return token


def _persist(config: GoogleConnectorConfig, credentials: Any) -> dict[str, Any]:
    # Retained for backwards compatibility with older callers/tests.
    return _persist_credentials(config, credentials)


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
        # Narrow typed boundary over the optional, untyped third-party classmethod
        # so strict mypy is satisfied whether or not google-auth is installed.
        build_credentials = cast(
            "Callable[[dict[str, Any]], _GoogleCredentials]",
            Credentials.from_authorized_user_info,
        )
        creds = build_credentials(token)
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


# ---------------------------------------------------------------------------
# Local-only loopback OAuth receiver (Desktop / Installed application flow)
# ---------------------------------------------------------------------------
#
# The preferred production path uses a temporary HTTP listener bound to
# 127.0.0.1 on a random available port. The browser redirects the authorization
# code back to that listener, which validates the OAuth ``state`` (CSRF) and
# exchanges the code in-process (so PKCE works). No authorization code, token, or
# client secret is ever placed on argv, in a command file, in the environment, or
# in logs.

# Bind only to the loopback interface (never 0.0.0.0 / a routable address).
LOOPBACK_HOST = "127.0.0.1"
# HTML shown to the user after the OAuth redirect is *received*. It deliberately does
# NOT claim the authorization is complete: state validation, the token exchange against
# Google, and encrypted persistence all happen in the parent flow AFTER this handler
# returns. No code/token/verifier/secret is ever embedded in this page.
LOOPBACK_CALLBACK_HTML = (
    "<html><body><h2>SecuRedact</h2>"
    "<p>Google authorization received. Finishing setup locally...</p>"
    "</body></html>"
)
# Upper bound on how long the listener waits for the browser redirect before the
# authorization fails safely.
LOOPBACK_TIMEOUT_SECONDS = 300.0


def pick_loopback_port() -> int:
    """Reserve and return a free loopback port (ephemeral).

    Binds to ``127.0.0.1:0`` so the OS assigns an unused port, then releases the
    socket. Callers must bind the listener to the returned port immediately after,
    which is what :class:`LoopbackOAuthServer` does internally (no callers bind
    separately, so there is no persistent double-bind).
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK_HOST, 0))
        return int(sock.getsockname()[1])


def loopback_redirect_uri(port: int) -> str:
    """Return the loopback redirect URI for ``port`` (Google desktop-app form)."""

    return f"http://{LOOPBACK_HOST}:{port}/"


class LoopbackAuthError(Exception):
    """Raised on a fatal loopback OAuth defect (not on a user-declined consent)."""


class _LoopbackResult:
    """Thread-safe outcome of the loopback callback."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self.code: str | None = None
        self.error: str | None = None
        self.state: str | None = None

    def set(self, *, code: str | None, error: str | None, state: str | None) -> None:
        self.code = code
        self.error = error
        self.state = state
        self._event.set()

    def wait(self, timeout: float) -> None:
        """Block until the callback arrives or ``timeout`` elapses.

        Raises :class:`LoopbackAuthError` on timeout so callers fail closed.
        """

        if not self._event.wait(timeout=timeout):
            raise LoopbackAuthError("loopback OAuth callback timed out")


class LoopbackOAuthServer:
    """Temporary loopback listener that captures the OAuth redirect.

    Binds **only** to ``127.0.0.1`` on a freshly-allocated port. Validates the
    returned ``state`` against the expected CSRF value and stores the authorization
    ``code`` (or the Google ``error``). Never logs the code/token. The listener is
    shut down as soon as a callback is processed or on cancellation/timeout.
    """

    def __init__(self, *, expected_state: str, timeout: float = LOOPBACK_TIMEOUT_SECONDS) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self._result = _LoopbackResult()
        self.port = pick_loopback_port()
        self._httpd = ThreadingHTTPServer((LOOPBACK_HOST, self.port), self._make_handler())
        self._thread: threading.Thread | None = None
        # Whether serve_forever is actually running. ``shutdown()`` must only call
        # ``httpd.shutdown()`` (which blocks until the serve loop exits) when the
        # loop was started; otherwise it would hang forever.
        self._serving = False

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class _Handler(BaseHTTPRequestHandler):
            # The redirect lands on "/" by construction.
            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                code = params.get("code", [""])[0]
                error = params.get("error", [""])[0]
                state = params.get("state", [""])[0]

                if parsed.path != "/":
                    self.send_response(404)
                    self.end_headers()
                    return
                # CSRF / state validation: a mismatch fails closed (no exchange).
                if state != server.expected_state:
                    server._result.set(code=None, error="state_mismatch", state=state)
                else:
                    server._result.set(code=code, error=error, state=state)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                # The callback has only just been *received* here. State validation,
                # the token exchange against Google, and encrypted persistence all
                # happen in the parent flow AFTER this handler returns. Claiming
                # "complete" here would falsely report success before any of that has
                # run, so we only acknowledge receipt and let the local flow finish.
                self.wfile.write(LOOPBACK_CALLBACK_HTML.encode("utf-8"))
                # Stop serving once a callback (valid or not) has been handled.
                threading.Thread(target=server._httpd.shutdown, daemon=True).start()

            # Never emit codes/tokens to stderr via the base class logger.
            def log_message(self, *args: object) -> None:
                return

        return _Handler

    @property
    def redirect_uri(self) -> str:
        return loopback_redirect_uri(self.port)

    def start(self) -> None:
        """Begin serving the loopback listener on a background thread."""

        self._serving = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def wait_for_callback(self) -> _LoopbackResult:
        """Block until the callback is handled or the timeout elapses.

        Returns the result (which carries ``code`` or ``error``). On timeout the
        listener is closed and a :class:`LoopbackAuthError` propagates so the caller
        fails closed and reports a safe message.
        """

        try:
            self._result.wait(self.timeout)
        finally:
            self.shutdown()
        return self._result

    def shutdown(self) -> None:
        """Close the listener (idempotent)."""

        # ``httpd.shutdown()`` blocks until the serve loop exits, so only call it
        # when we actually started serving (otherwise it would hang forever).
        if getattr(self, "_serving", False):
            try:
                self._httpd.shutdown()
            except Exception:  # noqa: S110 - pragma: no cover - defensive
                pass
        try:
            self._httpd.server_close()
        except Exception:  # noqa: S110 - pragma: no cover - defensive
            pass


def run_local_oauth(
    config: GoogleConnectorConfig,
    *,
    open_browser: bool = True,
    timeout_seconds: float = LOOPBACK_TIMEOUT_SECONDS,
    _exchange_fn: Callable[..., object] | None = None,
    _browser_open: Callable[[str], None] | None = None,
    _server_cls: type[LoopbackOAuthServer] | None = None,
) -> GoogleLoopbackOutcome:
    """Perform the full local loopback OAuth flow and persist the token.

    Picks a random loopback port, builds the (PKCE) consent URL, starts the
    listener, opens the browser, waits for the redirect, validates ``state``, and
    exchanges the code in-process. Returns ``True`` only when a token was stored.
    Any failure (timeout, state mismatch, consent error, exchange error) returns
    ``False`` after shutting down the listener -- no secret/code/token leaks.

    Injectable boundaries (``_exchange_fn`` / ``_browser_open`` / ``_server_cls``)
    make the flow unit-testable without a real browser or network.
    """

    server_cls = _server_cls or LoopbackOAuthServer
    server = server_cls(expected_state="", timeout=timeout_seconds)
    # Bind the flow to the exact loopback redirect URI the listener will receive.
    loopback_config = dataclasses.replace(config, redirect_uri=server.redirect_uri)
    try:
        url, state = get_authorization_url(loopback_config, pkce=True)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_CALLBACK, ERR_UNEXPECTED, exc)
    server.expected_state = state
    server.start()

    if _browser_open is not None:
        _browser_open(url)
    elif open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: S110 - browser launch is best-effort
            pass

    try:
        result = server.wait_for_callback()
    except LoopbackAuthError as exc:
        return _loopback_failure(LOOPBACK_STAGE_CALLBACK, ERR_UNEXPECTED, exc)

    # CSRF / state validation failure: fail closed (no exchange, no token).
    if result.error == "state_mismatch":
        return _loopback_failure(LOOPBACK_STAGE_STATE_VALIDATION, ERR_STATE_MISMATCH)
    # Google returned an OAuth error (e.g. access_denied) in the redirect.
    if result.error:
        return _loopback_failure(LOOPBACK_STAGE_CALLBACK_ERROR, ERR_GOOGLE_CALLBACK_ERROR)
    # A callback without a code cannot be exchanged (fail closed).
    if not result.code:
        return _loopback_failure(LOOPBACK_STAGE_MISSING_CODE, ERR_MISSING_CODE)

    # Injected boundary performs the full exchange + persist (tests / dev). The real
    # path splits token exchange and persistence so the exact post-callback stage is
    # reported instead of a generic ``authorized=false``.
    if _exchange_fn is not None:
        try:
            _exchange_fn(loopback_config, result.code, state=state)
        except Exception as exc:
            return _loopback_failure(LOOPBACK_STAGE_TOKEN_EXCHANGE, ERR_TOKEN_EXCHANGE_FAILED, exc)
        return GoogleLoopbackOutcome(authorized=True, stage=LOOPBACK_STAGE_COMPLETE)

    try:
        credentials = _exchange_token_only(loopback_config, result.code, state=state)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_TOKEN_EXCHANGE, ERR_TOKEN_EXCHANGE_FAILED, exc)
    try:
        _persist_credentials(loopback_config, credentials)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_PERSISTENCE, ERR_PERSISTENCE_FAILED, exc)
    return GoogleLoopbackOutcome(authorized=True, stage=LOOPBACK_STAGE_COMPLETE)
