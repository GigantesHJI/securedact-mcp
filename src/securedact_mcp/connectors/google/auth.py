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

import base64
import contextlib
import dataclasses
import hashlib
import hmac
import logging
import re
import socket
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable, Iterator
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

# Local (pre-network) structural defects in the token exchange. These are raised
# *before* any request reaches Google, so they can never be confused with a real
# token-endpoint rejection.
ERR_LOCAL_REDIRECT_URI_MISMATCH = "google_local_redirect_uri_mismatch"
ERR_LOCAL_CLIENT_ID_MISMATCH = "google_local_client_id_mismatch"
ERR_LOCAL_PKCE_MISMATCH = "google_local_pkce_verifier_mismatch"
ERR_LOCAL_PENDING_MISSING = "google_local_pending_authorization_missing"

# ---------------------------------------------------------------------------
# Bounded sanitization of Google's token-endpoint error response
# ---------------------------------------------------------------------------
#
# Google's token endpoint answers a rejected exchange with an RFC 6749 error body
# (``{"error": "...", "error_description": "..."}``). oauthlib turns that into an
# exception carrying ``.error`` / ``.description``. Those two fields are the only
# thing we ever surface: the authorization code, access token, refresh token,
# client secret, PKCE verifier, and the full token response are never touched.

# An RFC 6749 ``error`` is a bare ASCII token. Anything not matching is dropped
# rather than echoed, so a malformed/hostile body cannot smuggle data out.
_OAUTH_ERROR_CODE_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_.\-]{0,63}\Z")

# ``error_description`` is free text, so it is triple-bounded: opaque runs that
# could be credential material are redacted, the charset is restricted to plain
# prose/punctuation, and the result is truncated.
MAX_OAUTH_ERROR_DESCRIPTION = 200
# Every OAuth secret we must never echo is far longer than this: authorization
# codes (~70+), access tokens (~100+), refresh tokens (~100+), PKCE verifiers
# (43-128 per RFC 7636), and Google client secrets (``GOCSPX-`` + 28 = 35). Any
# unbroken run of credential-shaped characters this long is redacted wholesale.
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
    """Return a bounded, credential-free rendering of ``error_description``.

    Redacts any credential-shaped opaque run, restricts the charset to plain
    prose, and truncates to :data:`MAX_OAUTH_ERROR_DESCRIPTION`. Returns ``None``
    when nothing safe and useful remains.
    """

    if not isinstance(raw, str) or not raw.strip():
        return None
    text = " ".join(raw.split())
    text = _OPAQUE_RUN_RE.sub("[redacted]", text)
    text = _DESCRIPTION_DISALLOWED_RE.sub(" ", text)
    text = " ".join(text.split())[:MAX_OAUTH_ERROR_DESCRIPTION].strip()
    return text or None


class GoogleTokenExchangeError(GoogleAuthError):
    """A failed token exchange, carrying only bounded non-secret diagnostics.

    ``oauth_error`` is Google's RFC 6749 error token (e.g. ``invalid_grant``) when
    the token endpoint actually answered; it is ``None`` when the exchange failed
    locally (a structural defect or transport error) and therefore never reached
    Google. ``cause_type`` is the underlying exception's class name, which is what
    makes a pre-network defect diagnosable instead of collapsing to a generic code.
    """

    def __init__(
        self,
        message: str,
        *,
        oauth_error: str | None = None,
        error_description: str | None = None,
        cause_type: str | None = None,
        reached_google: bool = False,
    ) -> None:
        super().__init__(message)
        self.oauth_error = oauth_error
        self.error_description = error_description
        self.cause_type = cause_type
        self.reached_google = reached_google


def _token_exchange_error(exc: BaseException) -> GoogleTokenExchangeError:
    """Wrap a token-exchange exception, preserving only safe fields.

    oauthlib raises ``OAuth2Error`` subclasses that expose ``.error`` (the RFC 6749
    token) and ``.description`` (Google's ``error_description``). Only those two are
    read; the response body, request body, and any credential material are ignored.
    """

    oauth_error = safe_oauth_error_code(getattr(exc, "error", None))
    description = safe_oauth_error_description(getattr(exc, "description", None))
    cause_type = type(exc).__name__
    return GoogleTokenExchangeError(
        f"Google token exchange failed: {oauth_error or cause_type}",
        oauth_error=oauth_error,
        error_description=description,
        cause_type=cause_type,
        reached_google=oauth_error is not None,
    )


# Pre-network structural defects map to their own actionable code, so a local bug is
# never reported as if Google had rejected the exchange.
_LOCAL_EXCHANGE_ERROR_CODES = {
    "LocalRedirectUriMismatch": ERR_LOCAL_REDIRECT_URI_MISMATCH,
    "LocalClientIdMismatch": ERR_LOCAL_CLIENT_ID_MISMATCH,
    "LocalPkceVerifierMismatch": ERR_LOCAL_PKCE_MISMATCH,
    "LocalPendingAuthorizationMissing": ERR_LOCAL_PENDING_MISSING,
}


def _exchange_error_code(exc: BaseException) -> str:
    """Return the safe error code for a token-exchange failure."""

    if isinstance(exc, GoogleTokenExchangeError) and exc.cause_type is not None:
        return _LOCAL_EXCHANGE_ERROR_CODES.get(exc.cause_type, ERR_TOKEN_EXCHANGE_FAILED)
    return ERR_TOKEN_EXCHANGE_FAILED


# ``requests_oauthlib`` and ``oauthlib`` log the *full* token request body (which
# carries the authorization code and the PKCE verifier) and the *full* token response
# (access + refresh tokens) at DEBUG level, unconditionally evaluating those log
# arguments. SecuRedact must never write that material anywhere, so these loggers are
# pinned above DEBUG for the duration of the exchange regardless of how the ambient
# process configured logging.
_TOKEN_EXCHANGE_SILENCED_LOGGERS = ("requests_oauthlib", "oauthlib", "urllib3")


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
class GoogleLoopbackOutcome:
    """Bounded result of a local loopback OAuth attempt (no secret material)."""

    authorized: bool
    stage: str | None = None
    error_code: str | None = None
    error: str | None = None
    # Google's RFC 6749 ``error`` token from the token endpoint (e.g.
    # ``invalid_grant`` / ``redirect_uri_mismatch``), present only when Google
    # actually answered. This is the field that names the real rejection.
    oauth_error: str | None = None
    # Bounded, credential-free rendering of Google's ``error_description``.
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
            # Only stage names / exception types are ever reported here.
            payload["error"] = str(self.error)
        return payload


def _loopback_failure(
    stage: str, error_code: str, exc: BaseException | None = None
) -> GoogleLoopbackOutcome:
    """Build a fail-closed outcome that names only the stage and a safe code.

    When ``exc`` is a :class:`GoogleTokenExchangeError` the bounded Google error
    token/description ride along, and ``error`` names the *underlying* exception
    type rather than the wrapper -- otherwise a purely local defect (for example a
    ``KeyError`` raised before any request left the machine) is indistinguishable
    from a genuine Google rejection.
    """

    oauth_error: str | None = None
    error_description: str | None = None
    if isinstance(exc, GoogleTokenExchangeError):
        oauth_error = exc.oauth_error
        error_description = exc.error_description
        detail = exc.oauth_error or exc.cause_type or stage
    elif exc is not None:
        detail = type(exc).__name__
    else:
        detail = stage
    return GoogleLoopbackOutcome(
        authorized=False,
        stage=stage,
        error_code=error_code,
        error=f"{stage}: {detail}",
        oauth_error=oauth_error,
        error_description=error_description,
    )


# ---------------------------------------------------------------------------
# PKCE (RFC 7636) helpers -- pure, and they never emit the verifier
# ---------------------------------------------------------------------------

PKCE_METHOD_S256 = "S256"

# Google's documented Desktop/Installed application endpoints.
GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - public endpoint URL
GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"


def pkce_challenge_for(verifier: str) -> str:
    """Return ``BASE64URL(SHA256(verifier))`` with the ``=`` padding stripped.

    This is exactly the RFC 7636 ``S256`` transformation Google requires. The
    challenge is public (it travels in the consent URL); the verifier is not and is
    never returned, logged, or persisted by this module.
    """

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_pkce_pair(verifier: str, challenge: str) -> bool:
    """True when ``challenge`` is the unpadded ``S256`` transform of ``verifier``.

    Compared in constant time and returns only a boolean, so calling this can never
    disclose the verifier.
    """

    return hmac.compare_digest(pkce_challenge_for(verifier), challenge)


@dataclasses.dataclass(frozen=True, slots=True)
class GoogleAuthorizeRecord:
    """Non-secret snapshot of the values actually sent to the authorization endpoint.

    Captured by parsing the generated consent URL, so it is the literal wire content
    of step 1. The token exchange is checked against it to guarantee the two legs of
    the transaction agree. It deliberately holds **no** PKCE verifier, authorization
    code, token, or client secret -- ``code_challenge`` is public by construction.
    """

    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scopes: tuple[str, ...]
    response_type: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoogleTokenRequestRecord:
    """Non-secret description of the token request (presence flags only, no values)."""

    client_id: str
    redirect_uri: str
    grant_type: str
    code_challenge_method: str
    sent_code: bool
    sent_code_verifier: bool
    sent_client_secret: bool
    client_id_in_body: bool


@dataclasses.dataclass(slots=True)
class _PendingAuthorization:
    """One in-flight authorization transaction: its flow plus the step-1 record."""

    flow: Any
    record: GoogleAuthorizeRecord


def _authorize_record_from_url(url: str) -> GoogleAuthorizeRecord:
    """Parse the generated consent URL into a non-secret step-1 record."""

    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)

    def _one(name: str) -> str:
        values = query.get(name) or [""]
        return values[0]

    return GoogleAuthorizeRecord(
        client_id=_one("client_id"),
        redirect_uri=_one("redirect_uri"),
        code_challenge=_one("code_challenge"),
        code_challenge_method=_one("code_challenge_method"),
        scopes=tuple(_one("scope").split()),
        response_type=_one("response_type"),
    )


class _GoogleCredentials(Protocol):
    """Narrow surface of ``google.oauth2.credentials.Credentials`` consumed here."""

    expired: bool
    valid: bool
    refresh_token: str | None

    def refresh(self, request: Any) -> None: ...


def build_flow(config: GoogleConnectorConfig, *, use_pkce: bool = True) -> Any:
    """Build an OAuth flow for the configured client/scopes.

    Uses the Desktop/Installed application client type when no client secret is
    present (a SecuRedact-managed public client), or the confidential ``web`` type
    when a secret is supplied (BYO/enterprise). A public client requires no secret.

    The ``client_secret`` key is **always present** in the client config, empty for a
    public Desktop client. ``google_auth_oauthlib.flow.Flow.fetch_token`` reads it
    with a hard ``self.client_config["client_secret"]`` subscript, so omitting the
    key raised ``KeyError: 'client_secret'`` *before any request left the machine* --
    which surfaced as a bogus ``google_token_exchange_failed``. An empty value keeps
    the Desktop secret optional (it is dropped from the request, never required).

    ``use_pkce`` drives ``autogenerate_code_verifier``, which is the only supported
    way to turn PKCE on/off in this library. ``authorization_url`` forwards unknown
    keyword arguments straight into the consent URL's query string, so a ``pkce=``
    argument does not control PKCE at all -- it just appends a junk query parameter.
    """

    from google_auth_oauthlib.flow import Flow

    client_id, client_secret = config.require_credentials()
    endpoints = {
        "client_id": client_id,
        # Always present; empty for a public Desktop/Installed client.
        "client_secret": client_secret or "",
        "auth_uri": GOOGLE_AUTH_URI,
        "token_uri": GOOGLE_TOKEN_URI,
        "redirect_uris": [config.redirect_uri],
    }
    if config.client_type == "web" and client_secret:
        client_config = {"web": endpoints}
    else:
        # Desktop / Installed application: no client secret required (public client).
        client_config = {"installed": endpoints}
    return Flow.from_client_config(
        client_config,
        scopes=list(config.scopes),
        redirect_uri=config.redirect_uri,
        autogenerate_code_verifier=use_pkce,
    )


def get_authorization_url(config: GoogleConnectorConfig, *, pkce: bool = True) -> tuple[str, str]:
    """Return the consent-screen URL and CSRF ``state`` for the flow.

    When ``pkce`` is true (the default) the flow generates a ``code_verifier`` and
    sends ``code_challenge`` + ``code_challenge_method=S256``. The *same* flow object
    is retained under its CSRF ``state`` so the token exchange reuses that exact
    verifier; nothing else can satisfy the challenge. When ``pkce`` is false no
    verifier is generated and no challenge is sent, so the exchange is consistently
    PKCE-free (rather than sending a challenge that no later verifier can match).
    """

    flow = build_flow(config, use_pkce=pkce)
    url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    # Retain the *same* flow (and therefore the same code_verifier) plus a non-secret
    # snapshot of what step 1 actually sent, so the exchange can prove it matches.
    _FLOW_STATE[state] = _PendingAuthorization(flow=flow, record=_authorize_record_from_url(url))
    return url, state


# Module-level pending-authorization cache keyed by CSRF state (single-process use).
# Entries are *popped* before the exchange, which is what makes an authorization code
# single-use: a second exchange for the same state finds nothing and fails closed.
_FLOW_STATE: dict[str, Any] = {}


def has_pending_authorization(state: str | None) -> bool:
    """True when ``state`` names an authorization pending **in this process**.

    A PKCE ``code_verifier`` cannot cross a process boundary, so a two-phase flow
    that issues the consent URL in one process and exchanges the code in another must
    check this and treat a miss as "no PKCE transaction to continue" rather than
    rebuilding a flow whose fresh verifier could never satisfy the sent challenge.
    """

    return bool(state) and state in _FLOW_STATE


def exchange_code(
    config: GoogleConnectorConfig, code: str, *, state: str | None = None
) -> dict[str, Any]:
    """Exchange an authorization code for tokens, persist them, return the dict."""

    credentials = _exchange_token_only(config, code, state=state)
    return _persist_credentials(config, credentials)


def _assert_same_transaction(flow: Any, record: GoogleAuthorizeRecord) -> GoogleTokenRequestRecord:
    """Verify the pending token request reuses step 1's values, byte for byte.

    Google requires the token exchange to repeat the authorization transaction's
    ``client_id`` and ``redirect_uri`` exactly. ``flow.redirect_uri`` /
    ``flow.client_config["client_id"]`` are literally the values requests-oauthlib
    will put in the token POST body, and ``record`` is what the consent URL carried,
    so this compares the two legs directly and fails closed on any difference.
    """

    exchange_redirect_uri = str(flow.redirect_uri)
    exchange_client_id = str(flow.client_config.get("client_id") or "")
    if exchange_redirect_uri != record.redirect_uri:
        # Fail closed *locally*: never spend the code on a request Google must reject.
        raise GoogleTokenExchangeError(
            "Google token exchange redirect_uri does not match the authorization request",
            cause_type="LocalRedirectUriMismatch",
        )
    if exchange_client_id != record.client_id:
        raise GoogleTokenExchangeError(
            "Google token exchange client_id does not match the authorization request",
            cause_type="LocalClientIdMismatch",
        )
    verifier = getattr(flow, "code_verifier", None)
    if record.code_challenge:
        # A challenge was sent, so the exchange must carry the matching verifier.
        if not verifier or not verify_pkce_pair(verifier, record.code_challenge):
            raise GoogleTokenExchangeError(
                "Google token exchange PKCE verifier does not match the sent code_challenge",
                cause_type="LocalPkceVerifierMismatch",
            )
    return GoogleTokenRequestRecord(
        client_id=exchange_client_id,
        redirect_uri=exchange_redirect_uri,
        grant_type=GRANT_TYPE_AUTHORIZATION_CODE,
        code_challenge_method=record.code_challenge_method,
        sent_code=True,
        sent_code_verifier=bool(verifier),
        sent_client_secret=bool(flow.client_config.get("client_secret")),
        client_id_in_body=True,
    )


def _exchange_token_only(
    config: GoogleConnectorConfig, code: str, *, state: str | None = None
) -> Any:
    """Exchange the authorization code for credentials without persisting them.

    Uses ``google_auth_oauthlib``'s supported ``Flow.fetch_token`` rather than a
    hand-rolled POST, so ``grant_type=authorization_code``, ``code``,
    ``redirect_uri`` and ``code_verifier`` are assembled by the library from the same
    flow object that produced the consent URL.

    The pending flow is **popped** before the exchange, so a given authorization code
    is exchanged exactly once. When a ``state`` was issued but has no pending flow the
    call fails closed instead of silently rebuilding a flow with a fresh (and
    therefore wrong) PKCE verifier.

    Failures raise :class:`GoogleTokenExchangeError` carrying only Google's RFC 6749
    error token and a bounded description -- never the code, tokens, verifier, client
    secret, or the token response.
    """

    pending = _FLOW_STATE.pop(state, None) if state is not None else None
    if state is not None and pending is None:
        raise GoogleTokenExchangeError(
            "No pending Google authorization for this state (already exchanged or expired)",
            cause_type="LocalPendingAuthorizationMissing",
        )
    if pending is not None:
        flow = pending.flow
        _assert_same_transaction(flow, pending.record)
    else:
        # Legacy/no-state path: no challenge was recorded, so run without PKCE
        # rather than sending a verifier that cannot match anything.
        flow = build_flow(config, use_pkce=False)

    _client_id, client_secret = config.require_credentials()
    try:
        with _suppress_oauth_debug_logging():
            flow.fetch_token(
                code=code,
                # RFC 6749 s2.3.1 / RFC 8252: a public Desktop client authenticates by
                # sending ``client_id`` in the request body and no client secret at all.
                # ``include_client_id=True`` also suppresses the HTTP Basic header that
                # requests-oauthlib would otherwise build from an empty secret.
                client_secret=client_secret or None,
                include_client_id=True,
            )
    except Exception as exc:  # Google rejection / transport / local defect
        raise _token_exchange_error(exc) from exc
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
        # Never retain a pending authorization (and its PKCE verifier) past the
        # attempt, whatever the outcome. ``_exchange_token_only`` already pops it on
        # the success path, so this is the fail-closed cleanup for every other path.
        _FLOW_STATE.pop(state, None)


def _run_local_oauth_after_authorize(
    loopback_config: GoogleConnectorConfig,
    *,
    server: LoopbackOAuthServer,
    url: str,
    state: str,
    open_browser: bool,
    _exchange_fn: Callable[..., object] | None,
    _browser_open: Callable[[str], None] | None,
) -> GoogleLoopbackOutcome:
    """Browser launch, callback wait, and the post-callback stages (see caller)."""

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
            return _loopback_failure(LOOPBACK_STAGE_TOKEN_EXCHANGE, _exchange_error_code(exc), exc)
        return GoogleLoopbackOutcome(authorized=True, stage=LOOPBACK_STAGE_COMPLETE)

    try:
        credentials = _exchange_token_only(loopback_config, result.code, state=state)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_TOKEN_EXCHANGE, _exchange_error_code(exc), exc)
    try:
        _persist_credentials(loopback_config, credentials)
    except Exception as exc:
        return _loopback_failure(LOOPBACK_STAGE_PERSISTENCE, ERR_PERSISTENCE_FAILED, exc)
    return GoogleLoopbackOutcome(authorized=True, stage=LOOPBACK_STAGE_COMPLETE)
