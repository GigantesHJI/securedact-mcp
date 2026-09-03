# SPDX-License-Identifier: Apache-2.0
"""Microsoft Graph OAuth 2.0 authorization (control plane, M365-102).

Implements the read-only OAuth flow with ``msal``. All Microsoft imports are lazy so
this module loads without the optional ``microsoft`` extra. The flow requests only
the least-privilege scopes from configuration, sets ``access_type=offline``
(refresh token) and returns a refresh token, and persists the resulting token
encrypted via :class:`MicrosoftCredentialStore`. Tokens are never returned through
logs or error messages.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import re
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from securedact_core.connectors.microsoft import MicrosoftAuthError

from .config import MicrosoftConfigError, MicrosoftConnectorConfig
from .storage import MicrosoftCredentialStore

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Safe, bounded post-callback diagnostics (no secret material)
# ---------------------------------------------------------------------------

LOOPBACK_STAGE_CALLBACK = "callback"
LOOPBACK_STAGE_STATE_VALIDATION = "state_validation"
LOOPBACK_STAGE_CALLBACK_ERROR = "callback_error"
LOOPBACK_STAGE_MISSING_CODE = "missing_code"
LOOPBACK_STAGE_TOKEN_EXCHANGE = "token_exchange"  # noqa: S105
LOOPBACK_STAGE_PERSISTENCE = "persistence"
LOOPBACK_STAGE_COMPLETE = "complete"
LOOPBACK_STAGE_PRE_AUTHORIZATION = "pre_authorization"

# Safe error codes (bounded vocabulary, no PII / secrets).
ERR_STATE_MISMATCH = "microsoft_loopback_state_mismatch"
ERR_GOOGLE_CALLBACK_ERROR = "microsoft_callback_error"
ERR_MISSING_CODE = "microsoft_loopback_missing_code"
ERR_TOKEN_EXCHANGE_FAILED = "microsoft_token_exchange_failed"  # noqa: S105
ERR_PERSISTENCE_FAILED = "microsoft_token_persistence_failed"
ERR_UNEXPECTED = "microsoft_loopback_unexpected_error"
ERR_CONFIG_MISSING = "microsoft_config_missing"
ERR_MANAGED_CLIENT_SECRET_MISSING = "microsoft_managed_client_secret_missing"  # noqa: S105

# Local (pre-network) structural defects in the token exchange.
ERR_LOCAL_REDIRECT_URI_MISMATCH = "microsoft_local_redirect_uri_mismatch"
ERR_LOCAL_CLIENT_ID_MISMATCH = "microsoft_local_client_id_mismatch"
ERR_LOCAL_PKCE_MISMATCH = "microsoft_local_pkce_verifier_mismatch"
ERR_LOCAL_PENDING_MISSING = "microsoft_local_pending_authorization_missing"


# ---------------------------------------------------------------------------
# Bounded sanitization of Microsoft's token-endpoint error response
# ---------------------------------------------------------------------------

_OAUTH_ERROR_CODE_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_.\-]{0,63}\Z")
MAX_OAUTH_ERROR_DESCRIPTION = 200
_OPAQUE_RUN_MIN_LENGTH = 32
_OPAQUE_RUN_RE = re.compile(rf"[A-Za-z0-9_\-./+=~]{{{_OPAQUE_RUN_MIN_LENGTH},}}")
_DESCRIPTION_DISALLOWED_RE = re.compile(r"[^A-Za-z0-9 ._:,;'\"()\[\]\-]+")


def safe_oauth_error_code(raw: object) -> str | None:
    """Return an RFC 6749 ``error`` token, or ``None`` when it is not a bare token."""

    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or not _OAUTH_ERROR_CODE_RE.match(text):
        return None
    return text


def safe_oauth_error_description(raw: object) -> str | None:
    """Return a bounded, credential-free rendering of ``error_description``."""

    if not isinstance(raw, str) or not raw.strip():
        return None
    text = " ".join(raw.split())
    text = _OPAQUE_RUN_RE.sub("[redacted]", text)
    text = _DESCRIPTION_DISALLOWED_RE.sub(" ", text)
    text = " ".join(text.split())[:MAX_OAUTH_ERROR_DESCRIPTION].strip()
    return text or None


class MicrosoftTokenExchangeError(MicrosoftAuthError):
    """A failed token exchange, carrying only bounded non-secret diagnostics."""

    def __init__(
        self,
        message: str,
        *,
        oauth_error: str | None = None,
        error_description: str | None = None,
        cause_type: str | None = None,
        reached_microsoft: bool = False,
    ) -> None:
        super().__init__(message)
        self.oauth_error = oauth_error
        self.error_description = error_description
        self.cause_type = cause_type
        self.reached_microsoft = reached_microsoft


def _token_exchange_error(exc: BaseException) -> MicrosoftTokenExchangeError:
    """Wrap a token-exchange exception, preserving only safe fields."""

    oauth_error = safe_oauth_error_code(getattr(exc, "error", None))
    description = safe_oauth_error_description(getattr(exc, "description", None))
    cause_type = type(exc).__name__
    return MicrosoftTokenExchangeError(
        f"Microsoft token exchange failed: {oauth_error or cause_type}",
        oauth_error=oauth_error,
        error_description=description,
        cause_type=cause_type,
        reached_microsoft=oauth_error is not None,
    )


# Pre-network structural defects map to their own actionable code.
_LOCAL_EXCHANGE_ERROR_CODES = {
    "LocalRedirectUriMismatch": ERR_LOCAL_REDIRECT_URI_MISMATCH,
    "LocalClientIdMismatch": ERR_LOCAL_CLIENT_ID_MISMATCH,
    "LocalPkceVerifierMismatch": ERR_LOCAL_PKCE_MISMATCH,
    "LocalPendingAuthorizationMissing": ERR_LOCAL_PENDING_MISSING,
}


def _exchange_error_code(exc: BaseException) -> str:
    """Return the safe error code for a token-exchange failure."""

    if isinstance(exc, MicrosoftTokenExchangeError) and exc.cause_type is not None:
        return _LOCAL_EXCHANGE_ERROR_CODES.get(exc.cause_type, ERR_TOKEN_EXCHANGE_FAILED)
    return ERR_TOKEN_EXCHANGE_FAILED


# MSAL logs token details at DEBUG; suppress during exchange.
_TOKEN_EXCHANGE_SILENCED_LOGGERS = ("msal", "urllib3")


@contextlib.contextmanager
def _suppress_oauth_debug_logging() -> Iterator[None]:
    """Temporarily prevent third-party OAuth libraries from logging secret material."""

    restore: list[tuple[logging.Logger, int]] = []
    try:
        for name in _TOKEN_EXCHANGE_SILENCED_LOGGERS:
            third_party = logging.getLogger(name)
            if third_party.isEnabledFor(logging.DEBUG):
                restore.append((third_party, third_party.level))
                third_party.setLevel(logging.INFO)
        yield
    finally:
        for third_party, level in restore:
            third_party.setLevel(level)


@dataclasses.dataclass
class MicrosoftLoopbackOutcome:
    """Bounded result of a local loopback OAuth attempt (no secret material)."""

    authorized: bool
    stage: str | None = None
    error_code: str | None = None
    error: str | None = None
    oauth_error: str | None = None
    error_description: str | None = None

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {"authorized": self.authorized}
        if self.stage is not None:
            payload["stage"] = self.stage
        if self.error_code is not None:
            payload["error_code"] = self.error_code
        if self.oauth_error is not None:
            payload["oauth_error"] = self.oauth_error
        if self.error_description is not None:
            payload["error_description"] = self.error_description
        if self.error is not None:
            payload["error"] = str(self.error)
        return payload


def _loopback_failure(
    stage: str, error_code: str, exc: BaseException | None = None
) -> MicrosoftLoopbackOutcome:
    """Build a fail-closed outcome that names only the stage and a safe code."""

    oauth_error: str | None = None
    error_description: str | None = None
    if isinstance(exc, MicrosoftTokenExchangeError):
        oauth_error = exc.oauth_error
        error_description = exc.error_description
        detail = exc.oauth_error or exc.cause_type or stage
    elif exc is not None:
        detail = type(exc).__name__
    else:
        detail = stage
    return MicrosoftLoopbackOutcome(
        authorized=False,
        stage=stage,
        error_code=error_code,
        error=f"{stage}: {detail}",
        oauth_error=oauth_error,
        error_description=error_description,
    )


# Microsoft Entra endpoints
MICROSOFT_AUTH_URI = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_URI = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"  # noqa: S105
GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"


def build_authorization_url(
    config: MicrosoftConnectorConfig, *, pkce: bool = True
) -> tuple[str, str]:
    """Return the consent-screen URL and CSRF ``state`` for the flow."""

    from msal import (  # type: ignore[import-not-found]
        ConfidentialClientApplication,
        PublicClientApplication,
    )

    client_id, client_secret = config.require_credentials()

    # Determine if we're a public client (no secret) or confidential client (with secret)
    if config.managed or not client_secret:
        # Public client (SecuRedact-managed or BYO without secret)
        app = PublicClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{config.tenant_id}",
        )
    else:
        # Confidential client with secret
        app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{config.tenant_id}",
        )

    # Generate PKCE code verifier if requested
    code_verifier = None
    code_challenge = None
    if pkce:
        import base64
        import hashlib
        import secrets

        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        )
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    # Build auth URL
    auth_url = app.get_authorization_request_url(
        scopes=config.scopes,
        redirect_uri=config.redirect_uri,
        response_type="code",
        state=None,  # We'll generate our own
        prompt="consent",
        code_challenge=code_challenge,
        code_challenge_method="S256" if pkce else None,
    )

    # Generate our own state for CSRF
    import secrets

    state = secrets.token_urlsafe(32)

    # Store the pending authorization
    _FLOW_STATE[state] = _PendingAuthorization(
        app=app,
        code_verifier=code_verifier,
        redirect_uri=config.redirect_uri,
        client_id=client_id,
        state=state,
    )

    # Replace state in the URL
    parsed = urllib.parse.urlparse(auth_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query["state"] = [state]
    new_query = urllib.parse.urlencode(query, doseq=True)
    final_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

    return final_url, state


# Module-level pending-authorization cache keyed by CSRF state (single-process use).
# Entries are *popped* before the exchange, which is what makes an authorization code
# single-use: a second exchange for the same state finds nothing and fails closed.
_FLOW_STATE: dict[str, Any] = {}


@dataclasses.dataclass
class _PendingAuthorization:
    """One in-flight authorization transaction."""

    app: Any
    code_verifier: str | None
    redirect_uri: str
    client_id: str
    state: str


def has_pending_authorization(state: str | None) -> bool:
    """True when ``state`` names an authorization pending **in this process**."""

    return bool(state) and state in _FLOW_STATE


def exchange_code(
    config: MicrosoftConnectorConfig, code: str, *, state: str | None = None
) -> dict[str, Any]:
    """Exchange an authorization code for tokens, persist them, return the dict."""

    credentials = _exchange_token_only(config, code, state=state)
    return _persist_credentials(config, credentials)


def _exchange_token_only(
    config: MicrosoftConnectorConfig, code: str, *, state: str | None = None
) -> dict[str, Any]:
    """Exchange the authorization code for credentials without persisting them."""

    pending = _FLOW_STATE.pop(state, None) if state is not None else None
    if state is not None and pending is None:
        raise MicrosoftTokenExchangeError(
            "No pending Microsoft authorization for this state (already exchanged or expired)",
            cause_type="LocalPendingAuthorizationMissing",
        )

    if pending is not None:
        app = pending.app
        code_verifier = pending.code_verifier
        redirect_uri = pending.redirect_uri

        # Verify redirect_uri matches
        if redirect_uri != config.redirect_uri:
            raise MicrosoftTokenExchangeError(
                "Microsoft token exchange redirect_uri does not match the authorization request",
                cause_type="LocalRedirectUriMismatch",
            )
        # Verify client_id matches
        if pending.client_id != config.client_id:
            raise MicrosoftTokenExchangeError(
                "Microsoft token exchange client_id does not match the authorization request",
                cause_type="LocalClientIdMismatch",
            )
        # Verify PKCE
        if code_verifier and pending.app._code_challenge:
            import base64
            import hashlib

            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            if expected != pending.app._code_challenge:
                raise MicrosoftTokenExchangeError(
                    "Microsoft token exchange PKCE verifier does not match the sent code_challenge",
                    cause_type="LocalPkceVerifierMismatch",
                )
    else:
        # Legacy/no-state path: no challenge was recorded, so run without PKCE
        from msal import ConfidentialClientApplication, PublicClientApplication

        client_id, client_secret = config.require_credentials()
        if config.managed or not client_secret:
            app = PublicClientApplication(
                client_id=client_id,
                authority=f"https://login.microsoftonline.com/{config.tenant_id}",
            )
        else:
            app = ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=f"https://login.microsoftonline.com/{config.tenant_id}",
            )
        code_verifier = None

    client_id, client_secret = config.require_credentials()
    try:
        with _suppress_oauth_debug_logging():
            result = app.acquire_token_by_authorization_code(
                code=code,
                scopes=config.scopes,
                redirect_uri=config.redirect_uri,
                code_verifier=code_verifier,
            )
    except Exception as exc:
        raise _token_exchange_error(exc) from exc

    if "error" in result:
        raise MicrosoftTokenExchangeError(
            f"Microsoft token exchange failed: {result.get('error')}",
            oauth_error=result.get("error"),
            error_description=result.get("error_description"),
            reached_microsoft=True,
        )

    if not isinstance(result, dict):
        raise MicrosoftTokenExchangeError(
            "Microsoft token exchange returned unexpected type",
            cause_type="UnexpectedResultType",
        )
    return result


def _persist_credentials(
    config: MicrosoftConnectorConfig, credentials: dict[str, Any]
) -> dict[str, Any]:
    """Encrypt and persist credentials, raising on any storage failure."""

    store: MicrosoftCredentialStore = config.credential_store()
    try:
        store.save_token(credentials)
    except Exception as exc:
        raise MicrosoftAuthError(
            f"Microsoft token persistence failed: {type(exc).__name__}"
        ) from exc
    return credentials


def load_credentials(config: MicrosoftConnectorConfig) -> dict[str, Any] | None:
    """Load and refresh persisted credentials, or ``None`` if absent/revoked."""

    store: MicrosoftCredentialStore = config.credential_store()
    token = store.load_token()
    if token is None:
        return None
    try:
        return _refresh_if_needed(config, token)
    except MicrosoftAuthError:
        return None


def _refresh_if_needed(config: MicrosoftConnectorConfig, token: dict[str, Any]) -> dict[str, Any]:
    """Refresh the access token if expired, using MSAL's token cache."""

    from msal import ConfidentialClientApplication, PublicClientApplication

    client_id, client_secret = config.require_credentials()
    if config.managed or not client_secret:
        app = PublicClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{config.tenant_id}",
        )
    else:
        app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{config.tenant_id}",
        )

    # Try to get a valid access token from cache
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(config.scopes, account=accounts[0])
        if result and "access_token" in result:
            if not isinstance(result, dict):
                raise MicrosoftAuthError(
                    "Microsoft silent token acquisition returned unexpected type"
                )
            return result

    # If no cached token or silent acquire failed, try refresh token
    refresh_token = token.get("refresh_token")
    if refresh_token:
        try:
            with _suppress_oauth_debug_logging():
                result = app.acquire_token_by_refresh_token(refresh_token, scopes=config.scopes)
            if "error" in result:
                raise MicrosoftAuthError("Microsoft refresh token was rejected or revoked")
            # Persist the refreshed token
            _persist_credentials(config, result)
            if not isinstance(result, dict):
                raise MicrosoftAuthError(
                    "Microsoft refresh token exchange returned unexpected type"
                )
            return result
        except MicrosoftAuthError:
            raise
        except Exception as exc:
            raise MicrosoftAuthError("Microsoft refresh token was rejected or revoked") from exc

    raise MicrosoftAuthError("Microsoft credentials are not valid and could not be refreshed")


def revoke_credentials(config: MicrosoftConnectorConfig) -> None:
    """Best-effort revocation + local token deletion."""

    store: MicrosoftCredentialStore = config.credential_store()
    token = store.load_token()
    if token is not None and token.get("refresh_token"):
        # Use the documented revoke endpoint directly
        try:
            import requests

            requests.post(
                f"https://login.microsoftonline.com/{config.tenant_id}/oauth2/v2.0/revoke",
                data={"token": token["refresh_token"], "client_id": config.client_id},
                timeout=10,
            )
        except Exception as exc:
            logger.debug("Microsoft token revocation request failed: %s", type(exc).__name__)
    store.delete_token()


def require_valid_credentials(config: MicrosoftConnectorConfig) -> dict[str, Any]:
    """Return valid credentials or raise (fail closed)."""

    creds = load_credentials(config)
    if creds is None:
        raise MicrosoftConfigError(
            "No valid Microsoft authorization found. Run: securedact-mcp microsoft auth"
        )
    return creds


# ---------------------------------------------------------------------------
# Local-only loopback OAuth receiver (Desktop / Public client flow)
# ---------------------------------------------------------------------------

LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_CALLBACK_HTML = (
    "<html><body><h2>SecuRedact</h2>"
    "<p>Microsoft authorization received. Finishing setup locally...</p>"
    "</body></html>"
)
LOOPBACK_TIMEOUT_SECONDS = 300.0


def pick_loopback_port() -> int:
    """Reserve and return a free loopback port (ephemeral)."""

    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK_HOST, 0))
        return int(sock.getsockname()[1])


def loopback_redirect_uri(port: int) -> str:
    """Return the loopback redirect URI for ``port`` (Microsoft public client form)."""

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
        """Block until the callback arrives or ``timeout`` elapses."""

        if not self._event.wait(timeout=timeout):
            raise LoopbackAuthError("loopback OAuth callback timed out")


class LoopbackOAuthServer:
    """Temporary loopback listener that captures the OAuth redirect.

    Binds **only** to ``127.0.0.1`` on a freshly-allocated port. Validates the
    returned ``state`` against the expected CSRF value and stores the authorization
    ``code`` (or the Microsoft ``error``). Never logs the code/token. The listener is
    shut down as soon as a callback is processed or on cancellation/timeout.
    """

    def __init__(self, *, expected_state: str, timeout: float = LOOPBACK_TIMEOUT_SECONDS) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self._result = _LoopbackResult()
        self.port = pick_loopback_port()
        self._httpd = ThreadingHTTPServer((LOOPBACK_HOST, self.port), self._make_handler())
        self._thread: threading.Thread | None = None
        self._serving = False

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class _Handler(BaseHTTPRequestHandler):
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
                if state != server.expected_state:
                    server._result.set(code=None, error="state_mismatch", state=state)
                else:
                    server._result.set(code=code, error=error, state=state)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(LOOPBACK_CALLBACK_HTML.encode("utf-8"))
                threading.Thread(target=server._httpd.shutdown, daemon=True).start()

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
        """Block until the callback is handled or the timeout elapses."""

        try:
            self._result.wait(self.timeout)
        finally:
            self.shutdown()
        return self._result

    def shutdown(self) -> None:
        """Close the listener (idempotent)."""

        if getattr(self, "_serving", False):
            with contextlib.suppress(Exception):
                self._httpd.shutdown()
        with contextlib.suppress(Exception):
            self._httpd.server_close()


def run_local_oauth(
    config: MicrosoftConnectorConfig,
    *,
    open_browser: bool = True,
    timeout_seconds: float = LOOPBACK_TIMEOUT_SECONDS,
    _exchange_fn: Callable[..., object] | None = None,
    _browser_open: Callable[[str], None] | None = None,
    _server_cls: type[LoopbackOAuthServer] | None = None,
) -> MicrosoftLoopbackOutcome:
    """Perform the full local loopback OAuth flow and persist the token."""

    # Fail closed *before* any browser launch or Microsoft request: a managed
    # Microsoft Entra client requires the SecuRedact-managed client secret at token
    # exchange. If it is missing, opening the browser would only let the user
    # authorize and then be rejected by Microsoft.
    if config.managed and not config.client_secret:
        return _loopback_failure(
            LOOPBACK_STAGE_PRE_AUTHORIZATION, ERR_MANAGED_CLIENT_SECRET_MISSING
        )

    server_cls = _server_cls or LoopbackOAuthServer
    server = server_cls(expected_state="", timeout=timeout_seconds)
    loopback_config = dataclasses.replace(config, redirect_uri=server.redirect_uri)
    try:
        url, state = build_authorization_url(loopback_config, pkce=True)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_CALLBACK, ERR_UNEXPECTED, exc)
    server.expected_state = state
    server.start()
    try:
        return _run_local_oauth_after_authorize(
            loopback_config,
            server=server,
            url=url,
            state=state,
            open_browser=open_browser,
            _exchange_fn=_exchange_fn,
            _browser_open=_browser_open,
        )
    finally:
        _FLOW_STATE.pop(state, None)


def _run_local_oauth_after_authorize(
    loopback_config: MicrosoftConnectorConfig,
    *,
    server: LoopbackOAuthServer,
    url: str,
    state: str,
    open_browser: bool,
    _exchange_fn: Callable[..., object] | None,
    _browser_open: Callable[[str], None] | None,
) -> MicrosoftLoopbackOutcome:
    """Browser launch, callback wait, and the post-callback stages."""

    if _browser_open is not None:
        _browser_open(url)
    elif open_browser:
        with contextlib.suppress(Exception):
            webbrowser.open(url)

    try:
        result = server.wait_for_callback()
    except LoopbackAuthError as exc:
        return _loopback_failure(LOOPBACK_STAGE_CALLBACK, ERR_UNEXPECTED, exc)

    if result.error == "state_mismatch":
        return _loopback_failure(LOOPBACK_STAGE_STATE_VALIDATION, ERR_STATE_MISMATCH)
    if result.error:
        return _loopback_failure(LOOPBACK_STAGE_CALLBACK_ERROR, ERR_GOOGLE_CALLBACK_ERROR)
    if not result.code:
        return _loopback_failure(LOOPBACK_STAGE_MISSING_CODE, ERR_MISSING_CODE)

    if _exchange_fn is not None:
        try:
            _exchange_fn(loopback_config, result.code, state=state)
        except Exception as exc:
            return _loopback_failure(LOOPBACK_STAGE_TOKEN_EXCHANGE, _exchange_error_code(exc), exc)
        return MicrosoftLoopbackOutcome(authorized=True, stage=LOOPBACK_STAGE_COMPLETE)

    try:
        credentials = _exchange_token_only(loopback_config, result.code, state=state)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_TOKEN_EXCHANGE, _exchange_error_code(exc), exc)
    try:
        _persist_credentials(loopback_config, credentials)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_PERSISTENCE, ERR_PERSISTENCE_FAILED, exc)
    return MicrosoftLoopbackOutcome(authorized=True, stage=LOOPBACK_STAGE_COMPLETE)
