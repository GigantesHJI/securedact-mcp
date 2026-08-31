# SPDX-License-Identifier: Apache-2.0
"""Hermetic structural tests for the Google Desktop/Installed token exchange (GWS-110).

These tests stand in for ``https://oauth2.googleapis.com/token`` and never touch the
network, a browser, or a real Google client. They exist because a clean-laptop run
reported ``google_token_exchange_failed`` / ``stage: token_exchange`` for a reason that
had nothing to do with Google: ``build_flow`` omitted the ``client_secret`` key from the
Desktop client config, and ``google_auth_oauthlib.flow.Flow.fetch_token`` reads it with a
hard ``self.client_config["client_secret"]`` subscript, so the exchange died with
``KeyError: 'client_secret'`` *before a single byte reached Google*.

What is asserted here:

* the Desktop/public client exchanges without any client secret (root-cause regression);
* ``redirect_uri`` is byte-for-byte identical in the authorization URL and token request;
* the PKCE verifier used at exchange is the exact one generated before browser launch;
* ``code_challenge_method=S256`` and ``code_challenge == BASE64URL(SHA256(verifier))``
  with no ``=`` padding;
* ``grant_type=authorization_code`` and the managed client id appear in both legs;
* an authorization code is exchanged exactly once (single-use, fail closed after);
* ``invalid_grant`` / ``redirect_uri_mismatch`` propagate as safe ``oauth_error`` values;
* no authorization code, access token, refresh token, client secret, PKCE verifier, or
  raw token response ever appears in diagnostics or logs.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import logging
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

_HAS_GOOGLE = importlib.util.find_spec("google_auth_oauthlib") is not None
requires_google = pytest.mark.skipif(not _HAS_GOOGLE, reason="google extra not installed")

from securedact_core.connectors.google import default_connector_scopes  # noqa: E402
from securedact_mcp.connectors.google import auth as google_auth  # noqa: E402
from securedact_mcp.connectors.google.config import GoogleConnectorConfig  # noqa: E402

# Synthetic values. Every one of these strings is asserted to be absent from any
# diagnostic payload or log record produced by the flow.
MANAGED_CLIENT_ID = "111111111111-manageddesktopclient.apps.googleusercontent.com"
OTHER_CLIENT_ID = "999999999999-someotherclient.apps.googleusercontent.com"
AUTH_CODE = "4/0AVMBsJgSYNTHETIC-authorization-code-value-never-log-me"
ACCESS_TOKEN = "ya29.SYNTHETIC-access-token-value-never-log-me-abcdefgh"  # noqa: S105
REFRESH_TOKEN = "1//0gSYNTHETIC-refresh-token-value-never-log-me-abcdefgh"  # noqa: S105
BYO_CLIENT_SECRET = "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value"  # noqa: S105
LOOPBACK_PORT = 49152
LOOPBACK_REDIRECT = f"http://127.0.0.1:{LOOPBACK_PORT}/"


def _config(
    tmp_path: Path,
    *,
    client_secret: str | None = None,
    client_id: str = MANAGED_CLIENT_ID,
    redirect_uri: str = LOOPBACK_REDIRECT,
) -> GoogleConnectorConfig:
    """A managed Desktop (public) client config by default; ``web`` when a secret is set."""

    return GoogleConnectorConfig(
        enabled=True,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scopes=default_connector_scopes(),
        token_path=tmp_path / "google" / "token.json.enc",
        key_path=tmp_path / "google" / "token.key",
        client_type="web" if client_secret else "installed",
    )


def _success_payload(scopes: list[str]) -> dict[str, object]:
    return {
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "expires_in": 3599,
        "scope": " ".join(scopes),
        "token_type": "Bearer",
    }


class _FakeTokenEndpoint:
    """Stands in for Google's token endpoint and records the exact request sent.

    Installed over ``flow.oauth2session.request``, i.e. below all of oauthlib's request
    assembly, so what it records is literally the wire content requests would send, and
    the response it returns is parsed by the *real* oauthlib error machinery.
    """

    def __init__(self, status: int, payload: dict[str, object]) -> None:
        self.status = status
        self.payload = payload
        self.calls: list[dict[str, Any]] = []

    def install(self, flow: Any) -> _FakeTokenEndpoint:
        def _request(**kwargs: Any) -> Any:
            self.calls.append(
                {
                    "url": kwargs.get("url"),
                    "body": dict(kwargs.get("data") or {}),
                    "auth": kwargs.get("auth"),
                    "headers": dict(kwargs.get("headers") or {}),
                }
            )
            return self._response()

        flow.oauth2session.request = _request
        return self

    def install_on_every_flow(self, monkeypatch: pytest.MonkeyPatch) -> _FakeTokenEndpoint:
        """Patch ``build_flow`` so any flow the module builds hits this fake endpoint."""

        real_build_flow = google_auth.build_flow

        def _wrapped(config: Any, *, use_pkce: bool = True) -> Any:
            flow = real_build_flow(config, use_pkce=use_pkce)
            self.install(flow)
            return flow

        monkeypatch.setattr(google_auth, "build_flow", _wrapped)
        return self

    def _response(self) -> Any:
        import requests

        response = requests.Response()
        response.status_code = self.status
        response._content = json.dumps(self.payload).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
        response.url = google_auth.GOOGLE_TOKEN_URI
        # ``requests_oauthlib`` eagerly reads ``r.request.{url,headers,body}``.
        prepared = requests.PreparedRequest()
        prepared.url = google_auth.GOOGLE_TOKEN_URI
        prepared.headers = requests.structures.CaseInsensitiveDict()
        prepared.body = None
        response.request = prepared
        return response

    @property
    def body(self) -> dict[str, Any]:
        assert self.calls, "the token endpoint was never called"
        return self.calls[-1]["body"]

    @property
    def headers(self) -> dict[str, Any]:
        return self.calls[-1]["headers"]


def _authorize(config: GoogleConnectorConfig) -> tuple[dict[str, str], str, Any]:
    """Run step 1 and return (consent-URL query params, state, pending authorization)."""

    url, state = google_auth.get_authorization_url(config, pkce=True)
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    params = {key: values[0] for key, values in query.items()}
    return params, state, google_auth._FLOW_STATE[state]


# ---------------------------------------------------------------------------
# Root cause: a Desktop/public client must exchange without any client secret
# ---------------------------------------------------------------------------


@requires_google
def test_desktop_client_exchanges_without_any_client_secret(tmp_path: Path) -> None:
    """Regression: the exchange must reach the token endpoint, not die on a KeyError.

    Before the fix this raised ``KeyError: 'client_secret'`` inside
    ``Flow.fetch_token`` and never issued a request at all.
    """

    config = _config(tmp_path)
    _params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)

    credentials = google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert credentials is not None
    # The request was actually issued to Google's documented token endpoint.
    assert len(endpoint.calls) == 1
    assert endpoint.calls[0]["url"] == google_auth.GOOGLE_TOKEN_URI
    # A public client sends no secret at all, and no HTTP Basic credentials either.
    assert "client_secret" not in endpoint.body
    assert endpoint.calls[0]["auth"] is None
    assert "Authorization" not in endpoint.headers


@requires_google
def test_build_flow_always_defines_client_secret_key(tmp_path: Path) -> None:
    """``Flow.fetch_token`` subscripts ``client_config['client_secret']`` unconditionally."""

    flow = google_auth.build_flow(_config(tmp_path))
    assert "client_secret" in flow.client_config
    assert flow.client_config["client_secret"] == ""


@requires_google
def test_web_client_still_sends_its_secret_in_the_body(tmp_path: Path) -> None:
    config = _config(tmp_path, client_secret=BYO_CLIENT_SECRET)
    _params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)

    google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert endpoint.body["client_secret"] == BYO_CLIENT_SECRET
    assert endpoint.body["client_id"] == MANAGED_CLIENT_ID


# ---------------------------------------------------------------------------
# redirect_uri equality between authorize and exchange
# ---------------------------------------------------------------------------


@requires_google
def test_redirect_uri_is_byte_identical_between_authorize_and_exchange(tmp_path: Path) -> None:
    config = _config(tmp_path)
    params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)

    google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    authorize_redirect = params["redirect_uri"]
    exchange_redirect = endpoint.body["redirect_uri"]
    # Byte-for-byte, not merely equivalent-after-normalization.
    assert authorize_redirect == LOOPBACK_REDIRECT
    assert exchange_redirect == authorize_redirect
    assert exchange_redirect.encode("utf-8") == authorize_redirect.encode("utf-8")


@requires_google
def test_local_redirect_uri_drift_fails_before_any_request(tmp_path: Path) -> None:
    """A redirect_uri that drifted after step 1 must not spend the code on Google."""

    config = _config(tmp_path)
    _params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)
    # Simulate the flow's redirect target changing between the two legs.
    pending.flow.redirect_uri = "http://127.0.0.1:1/"

    with pytest.raises(google_auth.GoogleTokenExchangeError) as caught:
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert caught.value.cause_type == "LocalRedirectUriMismatch"
    assert caught.value.oauth_error is None
    assert caught.value.reached_google is False
    # Fail closed *before* the network: the code was never presented to Google.
    assert endpoint.calls == []
    assert google_auth._exchange_error_code(caught.value) == (
        google_auth.ERR_LOCAL_REDIRECT_URI_MISMATCH
    )


@requires_google
def test_local_client_id_drift_fails_before_any_request(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)
    pending.flow.client_config["client_id"] = OTHER_CLIENT_ID

    with pytest.raises(google_auth.GoogleTokenExchangeError) as caught:
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert caught.value.cause_type == "LocalClientIdMismatch"
    assert endpoint.calls == []


# ---------------------------------------------------------------------------
# PKCE: verifier/challenge pairing and S256
# ---------------------------------------------------------------------------


@requires_google
def test_code_challenge_method_is_s256(tmp_path: Path) -> None:
    params, _state, _pending = _authorize(_config(tmp_path))
    assert params["code_challenge_method"] == "S256"
    assert google_auth.PKCE_METHOD_S256 == "S256"


@requires_google
def test_challenge_is_unpadded_base64url_sha256_of_the_verifier(tmp_path: Path) -> None:
    params, _state, pending = _authorize(_config(tmp_path))
    verifier = pending.flow.code_verifier
    challenge = params["code_challenge"]

    # Computed independently of the implementation under test.
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    assert challenge == expected
    assert "=" not in challenge
    assert "+" not in challenge and "/" not in challenge
    assert google_auth.pkce_challenge_for(verifier) == challenge
    assert google_auth.verify_pkce_pair(verifier, challenge) is True
    assert google_auth.verify_pkce_pair(verifier, "not-the-challenge") is False
    # RFC 7636 length bounds.
    assert 43 <= len(verifier) <= 128


@requires_google
def test_exchange_uses_the_verifier_generated_before_browser_launch(tmp_path: Path) -> None:
    config = _config(tmp_path)
    params, state, pending = _authorize(config)
    # Captured at the same moment the consent URL exists, i.e. before any browser.
    verifier_before_browser = pending.flow.code_verifier
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)

    google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert endpoint.body["code_verifier"] == verifier_before_browser
    # And it genuinely satisfies the challenge that was sent to Google in step 1.
    assert google_auth.verify_pkce_pair(endpoint.body["code_verifier"], params["code_challenge"])


@requires_google
def test_pkce_verifier_mismatch_fails_before_any_request(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)
    # A different verifier can never satisfy the already-sent challenge.
    pending.flow.code_verifier = "z" * 64

    with pytest.raises(google_auth.GoogleTokenExchangeError) as caught:
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert caught.value.cause_type == "LocalPkceVerifierMismatch"
    assert endpoint.calls == []


@requires_google
def test_consent_url_has_no_bogus_pkce_query_parameter(tmp_path: Path) -> None:
    """``Flow.authorization_url`` forwards unknown kwargs into the query string.

    Passing ``pkce="S256"`` therefore appended a junk ``pkce=S256`` parameter instead of
    configuring PKCE. PKCE must come from ``autogenerate_code_verifier``.
    """

    params, _state, _pending = _authorize(_config(tmp_path))
    assert "pkce" not in params
    assert params["code_challenge"]


@requires_google
def test_pkce_disabled_sends_no_challenge_and_no_verifier(tmp_path: Path) -> None:
    """With PKCE off, neither leg carries PKCE (rather than a challenge with no verifier)."""

    config = _config(tmp_path)
    url, state = google_auth.get_authorization_url(config, pkce=False)
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert "code_challenge" not in query
    assert "code_challenge_method" not in query

    pending = google_auth._FLOW_STATE[state]
    assert pending.flow.code_verifier is None
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)

    google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert "code_verifier" not in endpoint.body


# ---------------------------------------------------------------------------
# grant_type / client_id in both legs
# ---------------------------------------------------------------------------


@requires_google
def test_grant_type_and_client_id_are_correct_in_both_legs(tmp_path: Path) -> None:
    config = _config(tmp_path)
    params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)

    google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert params["response_type"] == "code"
    assert endpoint.body["grant_type"] == "authorization_code"
    assert google_auth.GRANT_TYPE_AUTHORIZATION_CODE == "authorization_code"
    # The managed Desktop client id, identical in both legs.
    assert params["client_id"] == MANAGED_CLIENT_ID
    assert endpoint.body["client_id"] == MANAGED_CLIENT_ID
    # The code itself is sent exactly as received, in the body (never on a URL).
    assert endpoint.body["code"] == AUTH_CODE
    assert "code=" not in str(endpoint.calls[0]["url"])


# ---------------------------------------------------------------------------
# Single-use authorization code
# ---------------------------------------------------------------------------


@requires_google
def test_authorization_code_is_exchanged_exactly_once(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes)).install(pending.flow)

    google_auth._exchange_token_only(config, AUTH_CODE, state=state)
    assert len(endpoint.calls) == 1
    # The pending authorization (and its verifier) is consumed, not left behind.
    assert state not in google_auth._FLOW_STATE

    # A replay must fail closed locally rather than presenting the code a second time.
    with pytest.raises(google_auth.GoogleTokenExchangeError) as caught:
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)
    assert caught.value.cause_type == "LocalPendingAuthorizationMissing"
    assert caught.value.oauth_error is None
    assert len(endpoint.calls) == 1


@requires_google
def test_failed_exchange_also_consumes_the_code(tmp_path: Path) -> None:
    """Even a rejected exchange burns the code; a retry must not silently re-POST it."""

    config = _config(tmp_path)
    _params, state, pending = _authorize(config)
    endpoint = _FakeTokenEndpoint(400, {"error": "invalid_grant"}).install(pending.flow)

    with pytest.raises(google_auth.GoogleTokenExchangeError):
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)
    assert len(endpoint.calls) == 1

    with pytest.raises(google_auth.GoogleTokenExchangeError) as caught:
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)
    assert caught.value.cause_type == "LocalPendingAuthorizationMissing"
    assert len(endpoint.calls) == 1


# ---------------------------------------------------------------------------
# Safe propagation of Google's token-endpoint errors
# ---------------------------------------------------------------------------


@requires_google
@pytest.mark.parametrize(
    ("oauth_error", "description"),
    [
        ("invalid_grant", "Bad Request"),
        ("redirect_uri_mismatch", "Bad Request"),
        ("invalid_client", "The OAuth client was not found."),
        ("unauthorized_client", "Unauthorized"),
        ("invalid_request", "Missing required parameter: code_verifier"),
    ],
)
def test_google_token_endpoint_error_propagates_safely(
    tmp_path: Path, oauth_error: str, description: str
) -> None:
    config = _config(tmp_path)
    _params, state, pending = _authorize(config)
    _FakeTokenEndpoint(400, {"error": oauth_error, "error_description": description}).install(
        pending.flow
    )

    with pytest.raises(google_auth.GoogleTokenExchangeError) as caught:
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    exc = caught.value
    assert exc.oauth_error == oauth_error
    assert exc.reached_google is True
    assert exc.error_description == description


@requires_google
def test_invalid_grant_outcome_payload_shape(tmp_path: Path, monkeypatch) -> None:
    """The full loopback flow reports the exact Google error in a bounded payload."""

    config = _config(tmp_path)
    _FakeTokenEndpoint(
        400, {"error": "invalid_grant", "error_description": "Bad Request"}
    ).install_on_every_flow(monkeypatch)

    outcome = google_auth.run_local_oauth(
        config, _server_cls=_CallbackServer, _browser_open=lambda _u: None
    )
    payload = outcome.to_payload()

    assert payload["authorized"] is False
    assert payload["stage"] == "token_exchange"
    assert payload["error_code"] == "google_token_exchange_failed"
    assert payload["oauth_error"] == "invalid_grant"
    assert payload["error_description"] == "Bad Request"


@requires_google
def test_redirect_uri_mismatch_outcome_payload_shape(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path)
    _FakeTokenEndpoint(400, {"error": "redirect_uri_mismatch"}).install_on_every_flow(monkeypatch)

    outcome = google_auth.run_local_oauth(
        config, _server_cls=_CallbackServer, _browser_open=lambda _u: None
    )
    payload = outcome.to_payload()

    assert payload["authorized"] is False
    assert payload["stage"] == "token_exchange"
    assert payload["error_code"] == "google_token_exchange_failed"
    assert payload["oauth_error"] == "redirect_uri_mismatch"
    # Absent fields are omitted rather than reported as empty/null.
    assert "error_description" not in payload


@requires_google
def test_transport_failure_reports_no_google_error(tmp_path: Path) -> None:
    """A failure that never reached Google must not claim a Google rejection."""

    import requests

    config = _config(tmp_path)
    _params, state, pending = _authorize(config)

    def _boom(**_kwargs: Any) -> Any:
        raise requests.ConnectionError("name resolution failed")

    pending.flow.oauth2session.request = _boom

    with pytest.raises(google_auth.GoogleTokenExchangeError) as caught:
        google_auth._exchange_token_only(config, AUTH_CODE, state=state)

    assert caught.value.oauth_error is None
    assert caught.value.reached_google is False
    assert caught.value.cause_type == "ConnectionError"


# ---------------------------------------------------------------------------
# No secrets in diagnostics or logs
# ---------------------------------------------------------------------------

SECRETS = (AUTH_CODE, ACCESS_TOKEN, REFRESH_TOKEN, BYO_CLIENT_SECRET)


@requires_google
def test_no_secrets_in_diagnostics_when_google_rejects(tmp_path: Path, monkeypatch) -> None:
    """A hostile/verbose token-endpoint body must not leak through diagnostics."""

    config = _config(tmp_path)
    # Google echoing credential material back is exactly what must be stripped.
    _FakeTokenEndpoint(
        400,
        {
            "error": "invalid_grant",
            "error_description": (
                f"code {AUTH_CODE} rejected; verifier mismatch; secret {BYO_CLIENT_SECRET}"
            ),
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
        },
    ).install_on_every_flow(monkeypatch)

    outcome = google_auth.run_local_oauth(
        config, _server_cls=_CallbackServer, _browser_open=lambda _u: None
    )
    blob = json.dumps(outcome.to_payload())

    assert outcome.oauth_error == "invalid_grant"
    for secret in SECRETS:
        assert secret not in blob
    # The opaque runs were redacted, not merely truncated away.
    assert "[redacted]" in str(outcome.error_description)
    # No part of the raw token response survives.
    assert "access_token" not in blob
    assert "refresh_token" not in blob


@requires_google
def test_no_secrets_in_diagnostics_or_logs_on_success(tmp_path: Path, monkeypatch, caplog) -> None:
    config = _config(tmp_path)
    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes))
    endpoint.install_on_every_flow(monkeypatch)

    with caplog.at_level(logging.DEBUG):
        outcome = google_auth.run_local_oauth(
            config, _server_cls=_CallbackServer, _browser_open=lambda _u: None
        )

    assert outcome.authorized is True
    blob = json.dumps(outcome.to_payload())
    verifier = endpoint.body["code_verifier"]
    for secret in (*SECRETS, verifier):
        assert secret not in blob
        # Third-party OAuth libraries log the request body and token response at
        # DEBUG; that must stay suppressed for the exchange.
        assert secret not in caplog.text


@requires_google
def test_verifier_is_never_recorded_in_the_authorize_record(tmp_path: Path) -> None:
    params, _state, pending = _authorize(_config(tmp_path))
    record = pending.record
    verifier = pending.flow.code_verifier

    assert verifier not in json.dumps(dataclass_as_dict(record))
    # Only the public challenge is retained, and it matches what was sent.
    assert record.code_challenge == params["code_challenge"]
    assert record.code_challenge_method == "S256"
    assert record.redirect_uri == LOOPBACK_REDIRECT
    assert record.client_id == MANAGED_CLIENT_ID


def dataclass_as_dict(record: Any) -> dict[str, Any]:
    import dataclasses

    return dataclasses.asdict(record)


@requires_google
def test_cross_process_two_phase_flow_is_consistently_pkce_free(tmp_path: Path) -> None:
    """The copy/paste flow spans processes, so neither leg may use PKCE.

    Previously the consent URL carried a ``code_challenge`` (the library generates a
    verifier by default) while the exchange happened in a second process with no
    verifier at all -- a guaranteed ``invalid_grant``.
    """

    config = _config(tmp_path)
    url, state = google_auth.get_authorization_url(config, pkce=False)
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert "code_challenge" not in query

    # Second "process": the pending flow is not reachable, so no state is forwarded.
    google_auth._FLOW_STATE.clear()
    assert google_auth.has_pending_authorization(state) is False

    endpoint = _FakeTokenEndpoint(200, _success_payload(config.scopes))
    real_build_flow = google_auth.build_flow
    built: list[Any] = []

    def _wrapped(cfg: Any, *, use_pkce: bool = True) -> Any:
        flow = real_build_flow(cfg, use_pkce=use_pkce)
        endpoint.install(flow)
        built.append(flow)
        return flow

    monkeypatched = pytest.MonkeyPatch()
    try:
        monkeypatched.setattr(google_auth, "build_flow", _wrapped)
        google_auth._exchange_token_only(config, AUTH_CODE, state=None)
    finally:
        monkeypatched.undo()

    assert "code_verifier" not in endpoint.body
    assert endpoint.body["grant_type"] == "authorization_code"
    assert endpoint.body["client_id"] == MANAGED_CLIENT_ID


@requires_google
def test_has_pending_authorization_tracks_the_in_process_flow(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _params, state, _pending = _authorize(config)
    assert google_auth.has_pending_authorization(state) is True
    assert google_auth.has_pending_authorization(None) is False
    assert google_auth.has_pending_authorization("not-a-real-state") is False
    google_auth._FLOW_STATE.pop(state, None)
    assert google_auth.has_pending_authorization(state) is False


# ---------------------------------------------------------------------------
# Bounded sanitization primitives
# ---------------------------------------------------------------------------


def test_safe_oauth_error_code_accepts_only_bare_tokens() -> None:
    assert google_auth.safe_oauth_error_code("invalid_grant") == "invalid_grant"
    assert google_auth.safe_oauth_error_code("redirect_uri_mismatch") == "redirect_uri_mismatch"
    assert google_auth.safe_oauth_error_code("  invalid_client  ") == "invalid_client"
    # Anything that is not a bare RFC 6749 token is dropped, never echoed.
    assert google_auth.safe_oauth_error_code("invalid grant") is None
    assert google_auth.safe_oauth_error_code('{"error": "x"}') is None
    assert google_auth.safe_oauth_error_code("a" * 200) is None
    assert google_auth.safe_oauth_error_code(None) is None
    assert google_auth.safe_oauth_error_code(b"invalid_grant") is None


def test_safe_error_description_redacts_credential_shaped_runs() -> None:
    description = google_auth.safe_oauth_error_description(
        f"Bad Request for code {AUTH_CODE} and token {ACCESS_TOKEN}"
    )
    assert description is not None
    assert AUTH_CODE not in description
    assert ACCESS_TOKEN not in description
    assert "[redacted]" in description
    assert description.startswith("Bad Request for code")


def test_safe_error_description_is_bounded_and_charset_restricted() -> None:
    long_prose = "word " * 200
    description = google_auth.safe_oauth_error_description(long_prose)
    assert description is not None
    assert len(description) <= google_auth.MAX_OAUTH_ERROR_DESCRIPTION

    cleaned = google_auth.safe_oauth_error_description("Bad\nRequest\t<script>x</script>")
    assert cleaned is not None
    assert "<" not in cleaned and ">" not in cleaned
    assert "\n" not in cleaned and "\t" not in cleaned

    assert google_auth.safe_oauth_error_description("") is None
    assert google_auth.safe_oauth_error_description("   ") is None
    assert google_auth.safe_oauth_error_description(None) is None


def test_pkce_helpers_match_rfc7636_appendix_b() -> None:
    """RFC 7636 Appendix B fixed vector."""

    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert google_auth.pkce_challenge_for(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert google_auth.verify_pkce_pair(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")


# ---------------------------------------------------------------------------
# Loopback server stub (no listener, no browser, no network)
# ---------------------------------------------------------------------------


class _CallbackServer(google_auth.LoopbackOAuthServer):
    """Replays a successful Google redirect without binding a socket."""

    def __init__(self, *, expected_state: str = "", timeout: float = 5.0) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self.port = LOOPBACK_PORT
        self._result = google_auth._LoopbackResult()

    def start(self) -> None:
        return None

    def wait_for_callback(self) -> Any:
        # ``run_local_oauth`` assigns the real CSRF state after construction.
        self._result.set(code=AUTH_CODE, error=None, state=self.expected_state)
        return self._result

    def shutdown(self) -> None:
        return None
