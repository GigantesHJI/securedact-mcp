# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the Microsoft auth_response contract.

Reproduces the real-machine defect where the Microsoft Entra browser flow
succeeded (consent, redirect, callback) but the token exchange returned::

    {
      "authorized": false,
      "stage": "token_exchange",
      "error_code": "microsoft_token_exchange_failed",
      "error": "token_exchange: AssertionError"
    }

Root cause: MSAL's
``PublicClientApplication.acquire_token_by_auth_code_flow`` (and the
underlying ``oauth2cli.oauth2.Client.obtain_token_by_auth_code_flow``)
asserts that ``auth_response`` is a ``dict`` -- specifically a mapping of
the callback query string (``{"code": ..., "state": ...}``). The previous
code passed the bare code string as ``auth_response=code``, violating
the contract:

    assert isinstance(auth_code_flow, dict) and isinstance(auth_response, dict)

Fix: build the ``auth_response`` dict from the callback's ``code`` and
``state`` fields and pass it to ``acquire_token_by_auth_code_flow``.
State is validated before the MSAL call so a CSRF mismatch is surfaced
as a clear, bounded diagnostic rather than an opaque MSAL ValueError.

These tests guard:

* ``auth_response`` is a dict (not a bare string) with ``code`` and ``state``;
* the same ``auth_code_flow`` dict from ``initiate_auth_code_flow`` reaches
  the exchange (PKCE verifier is preserved by MSAL);
* state validation: matching state succeeds, mismatched fails closed;
* missing state fails closed; missing code fails closed;
* the code and PKCE verifier are never logged;
* the real installed MSAL API is used (not a mock-only shape).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

from securedact_mcp.connectors.microsoft import auth as microsoft_auth
from securedact_mcp.connectors.microsoft import managed as microsoft_managed
from securedact_mcp.connectors.microsoft.config import MicrosoftConnectorConfig

_REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Inspect the real installed MSAL contract
# ---------------------------------------------------------------------------


def test_msal_auth_response_must_be_dict() -> None:
    """MSAL's obtain_token_by_auth_code_flow asserts auth_response is a dict."""

    import inspect

    from msal.oauth2cli.oauth2 import Client

    src = inspect.getsource(Client.obtain_token_by_auth_code_flow)
    assert "assert isinstance(auth_code_flow, dict) and isinstance(auth_response, dict)" in src, (
        "MSAL's auth_response contract changed; this test must be updated"
    )


def test_msal_auth_response_documented_as_dict() -> None:
    """The MSAL docstring for ``acquire_token_by_auth_code_flow`` documents
    ``auth_response`` as a dict, not a string."""

    import inspect

    src = inspect.getsource(
        __import__("msal").PublicClientApplication.acquire_token_by_auth_code_flow
    )
    assert ":param dict auth_response:" in src, (
        "MSAL PublicClientApplication.acquire_token_by_auth_code_flow docstring "
        "no longer documents auth_response as a dict; this test must be updated"
    )


def test_msal_state_mismatch_raises_value_error() -> None:
    """MSAL raises ``ValueError`` when ``auth_response["state"]`` does not
    match ``auth_code_flow["state"]``.

    We pre-check this in SecuRedact so the failure is a clear
    ``LocalStateMismatch`` diagnostic, not an opaque MSAL ``ValueError``.
    """

    import inspect

    from msal.oauth2cli.oauth2 import Client

    src = inspect.getsource(Client.obtain_token_by_auth_code_flow)
    assert "state mismatch" in src, "MSAL's state-mismatch check changed; this test must be updated"


# ---------------------------------------------------------------------------
# _exchange_token_only passes a dict auth_response
# ---------------------------------------------------------------------------


class _StrictMsalApp:
    """Mock that records the exact auth_response shape received."""

    def __init__(self, *args, **kwargs):
        self.last_initiate_kwargs: dict[str, object] = {}
        self.last_exchange_kwargs: dict[str, object] = {}
        self.last_auth_response: object = None
        self.last_auth_code_flow: object = None
        self._state = "test-state-strict"
        self._verifier = "test-verifier-strict-43-chars-abcdef0123456789"

    def initiate_auth_code_flow(self, *args, **kwargs):
        self.last_initiate_kwargs = dict(kwargs)
        return {
            "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?x=1",
            "state": self._state,
            "code_verifier": self._verifier,
            "redirect_uri": kwargs.get("redirect_uri", "http://localhost"),
        }

    def acquire_token_by_auth_code_flow(self, auth_code_flow, auth_response, scopes=None, **kwargs):
        # This is the exact assertion MSAL performs. We do the same check
        # here so the test fails if SecuRedact ever passes a wrong type.
        assert isinstance(auth_code_flow, dict) and isinstance(auth_response, dict), (
            f"MSAL contract violation: auth_code_flow={type(auth_code_flow).__name__}, "
            f"auth_response={type(auth_response).__name__}"
        )
        self.last_auth_response = dict(auth_response)
        self.last_auth_code_flow = dict(auth_code_flow)
        self.last_exchange_kwargs = {"scopes": list(scopes) if scopes else [], **kwargs}
        return {
            "access_token": "test-at",
            "refresh_token": "test-rt",
            "expires_in": 3600,
        }

    def get_accounts(self):
        return []


def _work_dir(name: str) -> Path:
    work = Path(r"C:\Users\User\AppData\Local\Temp\kilo\m365_auth_response_tests")
    if not work.is_dir():
        work.mkdir(parents=True, exist_ok=True)
    d = work / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    return d


def _make_config(work: Path, **overrides: object) -> MicrosoftConnectorConfig:
    kwargs: dict[str, object] = dict(
        enabled=True,
        client_id=microsoft_managed.MANAGED_MICROSOFT_CLIENT_ID,
        client_secret=None,
        tenant_id="common",
        redirect_uri="http://localhost",
        scopes=["User.Read", "Files.Read", "Sites.Read.All"],
        token_path=work / "token.json.enc",
        key_path=work / "token.key",
        managed=True,
    )
    kwargs.update(overrides)
    return MicrosoftConnectorConfig(**kwargs)  # type: ignore[arg-type]


def _patch_msal(monkeypatch, app_cls: type = _StrictMsalApp) -> _StrictMsalApp:
    """Patch ``sys.modules['msal']`` so both PublicClientApplication and
    ConfidentialClientApplication return a single instance of ``app_cls``
    that records its calls. Returns that instance.

    SecuRedact stores the MSAL app in the pending authorization record and
    uses the same instance for both the authorization request and the token
    exchange. The mock mirrors that contract by returning the same instance
    from every factory call.
    """

    instance = app_cls()
    # Make the instance callable as a class constructor too, so
    # ``PublicClientApplication(client_id=..., authority=...)`` works.
    instance_holder: list[_StrictMsalApp] = [instance]

    def factory(*args, **kwargs):
        instance_holder.append(instance)
        return instance

    class _FakeMsalModule:
        PublicClientApplication = factory
        ConfidentialClientApplication = factory

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})
    return instance


def test_exchange_token_only_passes_auth_response_as_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The token exchange must pass ``auth_response`` as a dict (not a string)."""

    work = _work_dir("auth_response_dict")
    config = _make_config(work)
    app = _patch_msal(monkeypatch)

    microsoft_auth.build_authorization_url(config, pkce=True)
    state = next(iter(microsoft_auth._FLOW_STATE.keys()))

    microsoft_auth._exchange_token_only(config, code="fake-code", state=state)

    auth_response = app.last_auth_response
    assert auth_response is not None
    assert isinstance(auth_response, dict), (
        f"auth_response was passed as {type(auth_response).__name__}; MSAL requires a dict"
    )
    assert auth_response.get("code") == "fake-code"
    assert auth_response.get("state") == state


def test_exchange_token_only_passes_same_auth_code_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same ``auth_code_flow`` dict from ``initiate_auth_code_flow`` reaches
    the exchange (PKCE verifier is preserved by MSAL).
    """

    work = _work_dir("same_flow")
    config = _make_config(work)
    app = _patch_msal(monkeypatch)

    _url, state = microsoft_auth.build_authorization_url(config, pkce=True)
    pending = microsoft_auth._FLOW_STATE[state]
    stored_flow = dict(pending.auth_code_flow)

    microsoft_auth._exchange_token_only(config, code="fake-code", state=state)

    assert app.last_auth_code_flow is not None
    # MSAL will not mutate the flow dict; the verifier should be identical.
    assert app.last_auth_code_flow.get("code_verifier") == stored_flow.get("code_verifier"), (
        "PKCE code_verifier was mutated between initiate and exchange"
    )
    assert app.last_auth_code_flow.get("state") == stored_flow.get("state")


# ---------------------------------------------------------------------------
# State validation
# ---------------------------------------------------------------------------


def test_exchange_token_only_state_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A state that does not match the pending flow's state must fail closed."""

    work = _work_dir("state_mismatch")
    config = _make_config(work)
    _patch_msal(monkeypatch)

    _url, stored_state = microsoft_auth.build_authorization_url(config, pkce=True)
    pending = microsoft_auth._FLOW_STATE[stored_state]
    # Replace the stored state with an attacker-controlled value so the
    # pending record exists but its state does not match the callback's.
    pending.state = "attacker-controlled-state"
    # Manually put it back (we will pop by the original key).
    microsoft_auth._FLOW_STATE[stored_state] = pending

    from securedact_mcp.connectors.microsoft.auth import MicrosoftTokenExchangeError

    with pytest.raises(MicrosoftTokenExchangeError) as exc_info:
        microsoft_auth._exchange_token_only(config, code="fake-code", state=stored_state)
    assert exc_info.value.cause_type == "LocalStateMismatch"
    # The stored state must not be echoed in the error message (no secret leak).
    assert "attacker-controlled-state" not in str(exc_info.value)
    assert stored_state not in str(exc_info.value)


def test_exchange_token_only_missing_code_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing code must fail closed."""

    work = _work_dir("missing_code")
    config = _make_config(work)
    _patch_msal(monkeypatch)

    microsoft_auth.build_authorization_url(config, pkce=True)
    state = next(iter(microsoft_auth._FLOW_STATE.keys()))

    from securedact_mcp.connectors.microsoft.auth import MicrosoftTokenExchangeError

    with pytest.raises(MicrosoftTokenExchangeError) as exc_info:
        microsoft_auth._exchange_token_only(config, code="", state=state)
    assert exc_info.value.cause_type == "LocalCodeMissing"


def test_exchange_token_only_missing_pending_flow_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A state with no pending flow must fail closed (replay protection)."""

    work = _work_dir("no_pending")
    config = _make_config(work)
    _patch_msal(monkeypatch)

    from securedact_mcp.connectors.microsoft.auth import MicrosoftTokenExchangeError

    with pytest.raises(MicrosoftTokenExchangeError) as exc_info:
        microsoft_auth._exchange_token_only(config, code="fake-code", state="never-issued-state")
    assert exc_info.value.cause_type == "LocalPendingAuthorizationMissing"


# ---------------------------------------------------------------------------
# No secret leakage
# ---------------------------------------------------------------------------


def test_exchange_token_only_does_not_log_code_or_verifier(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The exchange must not log the authorization code or PKCE verifier."""

    work = _work_dir("no_log_leak")
    config = _make_config(work)
    _patch_msal(monkeypatch)

    microsoft_auth.build_authorization_url(config, pkce=True)
    state = next(iter(microsoft_auth._FLOW_STATE.keys()))
    pending = microsoft_auth._FLOW_STATE[state]
    verifier = pending.auth_code_flow.get("code_verifier", "")

    caplog.clear()
    with caplog.at_level("DEBUG"):
        microsoft_auth._exchange_token_only(config, code="SECRET-CODE-123", state=state)

    all_logs = caplog.text
    assert "SECRET-CODE-123" not in all_logs, f"authorization code leaked into logs:\n{all_logs}"
    assert verifier not in all_logs, f"PKCE code_verifier leaked into logs:\n{all_logs}"


# ---------------------------------------------------------------------------
# Built-wheel subprocess regression
# ---------------------------------------------------------------------------


def _find_built_wheel() -> Path | None:
    dist = _REPO_ROOT / "dist"
    if not dist.is_dir():
        return None
    wheels = sorted(dist.glob("*.whl"))
    return wheels[-1] if wheels else None


def test_built_wheel_runtime_bootstrap_auth_response_dict_subprocess() -> None:
    """Built-wheel subprocess regression: the token exchange receives a dict
    ``auth_response`` (not a bare code string) and succeeds.
    """

    if shutil.which("uv") is None:
        pytest.skip("uv build unavailable")
    uv_exe = shutil.which("uv")
    assert uv_exe is not None

    work = Path(r"C:\Users\User\AppData\Local\Temp\kilo") / "m365_auth_response_subprocess"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    built = _find_built_wheel()
    if built is None:
        out = work / "dist"
        out.mkdir(exist_ok=True)
        result = subprocess.run(  # noqa: S603
            [uv_exe, "build", "--wheel", f"--out-dir={out}"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip(f"wheel build failed: {result.stderr[-500:]}")
        wheels = sorted(out.glob("*.whl"))
        if not wheels:
            pytest.skip("no wheel produced")
        built = wheels[-1]

    # Verify the built wheel passes a dict auth_response.
    with zipfile.ZipFile(built) as z:
        auth_content = z.read("securedact_mcp/connectors/microsoft/auth.py").decode()
        assert "auth_response=auth_response" in auth_content or (
            'auth_response={"code": code' in auth_content
        ), (
            "built wheel's auth.py does not pass a dict auth_response; "
            "check the _exchange_token_only implementation"
        )

    target = work / "wheel_install"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir()
    install = subprocess.run(  # noqa: S603
        [uv_exe, "pip", "install", "--no-deps", f"--target={target}", str(built)],
        capture_output=True,
        text=True,
        check=False,
    )
    if install.returncode != 0:
        pytest.skip(f"wheel install failed: {install.stderr[-500:]}")

    harness = work / "harness.py"
    harness.write_text(
        textwrap.dedent(
            """
            import json
            import sys
            from unittest.mock import patch

            sys.path.insert(0, sys.argv[1])
            from securedact_mcp.connectors.microsoft import auth as microsoft_auth
            from securedact_mcp.connectors.microsoft.config import MicrosoftConnectorConfig

            config = MicrosoftConnectorConfig(
                enabled=True,
                client_id="187e325c-7095-429c-9cb6-4feafda2d18d",
                client_secret=None,
                tenant_id="common",
                redirect_uri="http://localhost",
                scopes=["User.Read", "Files.Read", "Sites.Read.All"],
                token_path=__import__("pathlib").Path(sys.argv[2]) / "token.json.enc",
                key_path=__import__("pathlib").Path(sys.argv[2]) / "token.key",
                managed=True,
            )

            captured = {"auth_response_type": None, "auth_response_keys": None}

            class _FakePublicClient:
                def __init__(self, *a, **kw):
                    pass
                def initiate_auth_code_flow(self, *a, **kw):
                    return {
                        "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state=test-state",
                        "state": "test-state",
                        "code_verifier": "test-verifier",
                        "redirect_uri": "http://localhost",
                    }
                def acquire_token_by_auth_code_flow(self, auth_code_flow, auth_response, **kw):
                    # Record the exact shape SecuRedact passes.
                    captured["auth_response_type"] = type(auth_response).__name__
                    captured["auth_response_keys"] = (
                        list(auth_response.keys()) if hasattr(auth_response, "keys") else None
                    )
                    # Enforce the MSAL contract.
                    assert isinstance(auth_code_flow, dict) and isinstance(auth_response, dict), (
                        f"MSAL contract violated: auth_response is {type(auth_response).__name__}"
                    )
                    return {
                        "access_token": "test-at",
                        "refresh_token": "test-rt",
                        "expires_in": 3600,
                    }
                def get_accounts(self):
                    return []

            class _FakeMsalModule:
                PublicClientApplication = _FakePublicClient
                ConfidentialClientApplication = _FakePublicClient
            sys.modules["msal"] = _FakeMsalModule

            class _FakeLoopbackResult:
                def __init__(self):
                    self.code = None
                    self.error = None
                    self.state = None

            class _FakeLoopbackServer:
                def __init__(self, expected_state="", timeout=0):
                    self.expected_state = expected_state
                    self.timeout = timeout
                    self.redirect_uri = "http://localhost:12345/"
                    self.port = 12345
                def start(self): pass
                def shutdown(self): pass
                def wait_for_callback(self):
                    result = _FakeLoopbackResult()
                    result.code = "fake-auth-code"
                    result.state = self.expected_state
                    return result

            microsoft_auth.LoopbackOAuthServer = _FakeLoopbackServer
            microsoft_auth.LOOPBACK_TIMEOUT_SECONDS = 0.5

            with patch.object(microsoft_auth, "LoopbackOAuthServer", _FakeLoopbackServer):
                outcome = microsoft_auth.run_local_oauth(
                    config,
                    open_browser=False,
                    timeout_seconds=0.5,
                    _browser_open=lambda url: None,
                )

            print(json.dumps({
                "authorized": outcome.authorized,
                "stage": outcome.stage,
                "error_code": outcome.error_code,
                "error": outcome.error,
                "auth_response_type": captured["auth_response_type"],
                "auth_response_keys": captured["auth_response_keys"],
            }))
            """
        ),
        encoding="utf-8",
    )

    data_dir = work / "data"
    data_dir.mkdir(exist_ok=True)

    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(harness), str(target), str(data_dir)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert proc.stdout.strip(), f"harness produced no stdout; stderr:\n{proc.stderr[-2000:]}"
    payload = json.loads(proc.stdout)

    # The exact real-machine regression: the token exchange must succeed.
    assert payload.get("authorized") is True, f"token exchange failed in the built wheel: {payload}"
    assert payload.get("stage") == "complete", f"token exchange did not complete: {payload}"
    # auth_response must be a dict (not a bare string).
    assert payload.get("auth_response_type") == "dict", (
        f"auth_response was passed as {payload.get('auth_response_type')!r}; MSAL requires a dict"
    )
    assert "code" in payload.get("auth_response_keys", []), (
        f"auth_response dict is missing 'code' key: {payload}"
    )
    assert "state" in payload.get("auth_response_keys", []), (
        f"auth_response dict is missing 'state' key: {payload}"
    )
