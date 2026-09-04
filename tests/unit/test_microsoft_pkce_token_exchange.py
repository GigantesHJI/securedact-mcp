# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the Microsoft public-client PKCE token exchange.

Reproduces the real-machine defect where the Microsoft Entra browser flow
succeeded (consent, redirect, callback) but the token exchange returned::

    {
      "authorized": false,
      "stage": "token_exchange",
      "error_code": "microsoft_token_exchange_failed",
      "error": "token_exchange: AttributeError"
    }

Root cause: the token exchange was written for a confidential-client path:
it called the legacy MSAL method ``acquire_token_by_authorization_code``
(which does NOT accept a ``code_verifier``) and then tried to read
``pending.app._code_challenge`` -- a private MSAL internal attribute that
does not exist in MSAL 1.37.0. That ``AttributeError`` was caught by the
generic ``except Exception`` and surfaced as the opaque
``token_exchange: AttributeError`` message.

Fix: use the MSAL public-client PKCE-aware methods:
``initiate_auth_code_flow`` (returns a flow dict containing
``auth_uri``, ``state``, and ``code_verifier``) +
``acquire_token_by_auth_code_flow`` (consumes the flow dict, presenting
the stored ``code_verifier`` to Microsoft in the token request).

These tests guard:

* ``initiate_auth_code_flow`` is called (not the legacy
  ``get_authorization_request_url``);
* ``acquire_token_by_auth_code_flow`` is called (not the legacy
  ``acquire_token_by_authorization_code``);
* the ``code_verifier`` survives from the authorization request to the
  token exchange (PKCE proof);
* no MSAL private attribute (``_code_challenge`` etc.) is touched;
* the token exchange succeeds (no ``AttributeError``);
* the managed public-client path is used (no ``ConfidentialClientApplication``);
* diagnostics on failure are actionable (not just ``AttributeError``).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from pathlib import Path

import pytest

from securedact_mcp.connectors.microsoft import auth as microsoft_auth
from securedact_mcp.connectors.microsoft import managed as microsoft_managed
from securedact_mcp.connectors.microsoft.config import MicrosoftConnectorConfig

# msal is only required by the tests that actually inspect the real MSAL API.
# Those tests skip cleanly when the optional ``microsoft`` extra is not installed.
_HAS_MICROSOFT = importlib.util.find_spec("msal") is not None
requires_microsoft = pytest.mark.skipif(not _HAS_MICROSOFT, reason="microsoft extra not installed")

_REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Inspect the real installed MSAL API shape (proves we are not coding
# against a mocked shape that the real package does not expose).
# ---------------------------------------------------------------------------


@requires_microsoft
@requires_microsoft
def test_msal_public_client_has_initiate_auth_code_flow() -> None:
    """The installed MSAL package must expose ``initiate_auth_code_flow``."""

    import msal

    pca = msal.PublicClientApplication(
        client_id="test-client", authority="https://login.microsoftonline.com/common"
    )
    assert hasattr(pca, "initiate_auth_code_flow"), (
        "installed MSAL PublicClientApplication is missing "
        "initiate_auth_code_flow; the PKCE flow code requires MSAL >= 1.20"
    )


@requires_microsoft
def test_msal_public_client_has_acquire_token_by_auth_code_flow() -> None:
    """The installed MSAL package must expose ``acquire_token_by_auth_code_flow``."""

    import msal

    pca = msal.PublicClientApplication(
        client_id="test-client", authority="https://login.microsoftonline.com/common"
    )
    assert hasattr(pca, "acquire_token_by_auth_code_flow"), (
        "installed MSAL PublicClientApplication is missing "
        "acquire_token_by_auth_code_flow; the PKCE flow code requires MSAL >= 1.20"
    )


@requires_microsoft
def test_msal_public_client_initiate_returns_code_verifier() -> None:
    """``initiate_auth_code_flow`` must return a flow dict with ``code_verifier``."""

    import msal

    pca = msal.PublicClientApplication(
        client_id="test-client", authority="https://login.microsoftonline.com/common"
    )
    flow = pca.initiate_auth_code_flow(scopes=["User.Read"], redirect_uri="http://localhost")
    assert isinstance(flow, dict)
    assert "code_verifier" in flow, (
        f"MSAL initiate_auth_code_flow did not return code_verifier; got keys: {list(flow.keys())}"
    )
    assert flow["code_verifier"], "code_verifier is empty"
    assert "auth_uri" in flow
    assert "state" in flow


# ---------------------------------------------------------------------------
# build_authorization_url uses initiate_auth_code_flow (not the legacy API)
# ---------------------------------------------------------------------------


class _PKCEFlowPublicClient:
    """Mock that records the modern MSAL PKCE API calls."""

    def __init__(self, *args, **kwargs):
        self.initiate_called = False
        self.exchange_called = False
        self.last_initiate_kwargs: dict[str, object] = {}
        self.last_exchange_kwargs: dict[str, object] = {}
        self.last_exchange_flow: dict[str, object] | None = None
        self._state = "test-state-mock"
        self._verifier = "test-code-verifier-mock-43-chars-abcdef0123"

    def initiate_auth_code_flow(self, *args, **kwargs):
        self.initiate_called = True
        self.last_initiate_kwargs = dict(kwargs)
        return {
            "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state=test",
            "state": self._state,
            "code_verifier": self._verifier,
            "redirect_uri": kwargs.get("redirect_uri", "http://localhost"),
        }

    def acquire_token_by_auth_code_flow(self, *args, **kwargs):
        self.exchange_called = True
        self.last_exchange_kwargs = dict(kwargs)
        self.last_exchange_flow = (
            dict(kwargs.get("auth_code_flow", args[0] if args else {}))
            if kwargs.get("auth_code_flow") or (args and args[0])
            else None
        )
        # Verify the flow dict passed to the exchange contains the same
        # code_verifier that was generated in the authorization request.
        flow = kwargs.get("auth_code_flow", args[0] if args else {})
        assert flow.get("code_verifier") == self._verifier, (
            "PKCE code_verifier did not survive from initiate to exchange"
        )
        return {
            "access_token": "test-at",
            "refresh_token": "test-rt",
            "expires_in": 3600,
            "id_token": "test-id",
        }

    def get_accounts(self):
        return []

    # Legacy methods (should NOT be called by the new code)
    def get_authorization_request_url(self, *args, **kwargs):
        raise AssertionError(
            "build_authorization_url must not call the legacy "
            "get_authorization_request_url; use initiate_auth_code_flow"
        )

    def acquire_token_by_authorization_code(self, *args, **kwargs):
        raise AssertionError(
            "_exchange_token_only must not call the legacy "
            "acquire_token_by_authorization_code; use acquire_token_by_auth_code_flow"
        )


def _patch_msal_pkce(monkeypatch):
    class _FakeMsalModule:
        PublicClientApplication = _PKCEFlowPublicClient
        ConfidentialClientApplication = _PKCEFlowPublicClient

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})


def _work_dir(name: str) -> Path:
    work = Path(tempfile.gettempdir()) / "securedact_mcp_tests" / "m365_pkce_tests"
    if not work.is_dir():
        work.mkdir(parents=True, exist_ok=True)
    d = work / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    return d


def test_build_authorization_url_uses_initiate_auth_code_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``build_authorization_url`` must use ``initiate_auth_code_flow`` (PKCE)."""

    work = _work_dir("build_uses_initiate")
    config = MicrosoftConnectorConfig(
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

    captured: list[_PKCEFlowPublicClient] = []

    class _CapturingClient(_PKCEFlowPublicClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured.append(self)

    class _FakeMsalModule:
        PublicClientApplication = _CapturingClient
        ConfidentialClientApplication = _CapturingClient

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    url, state = microsoft_auth.build_authorization_url(config, pkce=True)

    assert len(captured) == 1
    assert captured[0].initiate_called, "initiate_auth_code_flow was not called"
    assert "login.microsoftonline.com" in url
    assert state == "test-state-mock"


def test_pkce_code_verifier_survives_from_initiate_to_exchange(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The PKCE code_verifier must be the same object from initiate to exchange.

    This is the exact defect the real machine hit: the old code used the
    legacy ``acquire_token_by_authorization_code`` (which does not accept a
    code_verifier) and tried to verify PKCE by reading
    ``pending.app._code_challenge`` (which does not exist), causing
    ``AttributeError``.
    """

    work = _work_dir("verifier_survives")
    config = MicrosoftConnectorConfig(
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

    _patch_msal_pkce(monkeypatch)

    # Build the authorization URL (initiate + store flow).
    _url, state = microsoft_auth.build_authorization_url(config, pkce=True)
    pending = microsoft_auth._FLOW_STATE[state]
    stored_verifier = pending.auth_code_flow.get("code_verifier")
    assert stored_verifier, "code_verifier was not stored in the pending flow"

    # Now exchange the code; the mock verifies the verifier matches.
    result = microsoft_auth._exchange_token_only(config, code="fake-auth-code", state=state)
    assert result.get("access_token") == "test-at"


def test_exchange_token_only_uses_acquire_token_by_auth_code_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_exchange_token_only`` must use ``acquire_token_by_auth_code_flow``."""

    work = _work_dir("exchange_uses_acquire_flow")
    config = MicrosoftConnectorConfig(
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

    # The MSAL app is instantiated during build_authorization_url and stored
    # in the pending authorization. We patch sys.modules['msal'] to capture
    # the instance, then verify the exchange method was called.
    captured_apps: list[_PKCEFlowPublicClient] = []

    class _CapturingClient(_PKCEFlowPublicClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured_apps.append(self)

    class _FakeMsalModule:
        PublicClientApplication = _CapturingClient
        ConfidentialClientApplication = _CapturingClient

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    microsoft_auth.build_authorization_url(config, pkce=True)
    state = next(iter(microsoft_auth._FLOW_STATE.keys()))

    microsoft_auth._exchange_token_only(config, code="fake-code", state=state)

    assert captured_apps, "MSAL app was not instantiated"
    # The same app instance is used for both initiate and exchange.
    assert any(app.exchange_called for app in captured_apps), (
        "acquire_token_by_auth_code_flow was not called by _exchange_token_only"
    )


def test_exchange_token_only_no_private_msal_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exchange must NOT read any private MSAL internal attributes.

    The old code read ``pending.app._code_challenge`` which does not exist in
    MSAL 1.37.0 (and never existed in a stable form). This test guards that
    the new code path never touches MSAL private attributes by running the
    full build+exchange cycle and asserting no AttributeError is raised.
    """

    work = _work_dir("no_private_msal_attrs")
    config = MicrosoftConnectorConfig(
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

    _patch_msal_pkce(monkeypatch)

    # Full round trip: build -> exchange. Must NOT raise AttributeError.
    _url, state = microsoft_auth.build_authorization_url(config, pkce=True)
    result = microsoft_auth._exchange_token_only(config, code="fake-code", state=state)
    assert result.get("access_token") == "test-at"


# ---------------------------------------------------------------------------
# Diagnostics: the exact real-machine error was "token_exchange: AttributeError"
# which is uninformative. The new diagnostics must be actionable.
# ---------------------------------------------------------------------------


def test_exchange_diagnostics_surfaces_cause_type() -> None:
    """When the exchange fails, the outcome must carry a useful cause_type,
    not just the raw ``AttributeError`` class name.

    Reproduces the real-machine scenario where the old code returned
    ``error: "token_exchange: AttributeError"`` with no actionable context.
    The new code's ``MicrosoftTokenExchangeError.cause_type`` is the
    class name of the inner exception, which is already more informative.
    """

    # Build a config and trigger an exchange with a bad code that will
    # cause MSAL to raise an exception (here, we just verify the error
    # path's shape via the loopback outcome).
    work = _work_dir("diagnostics")
    config = MicrosoftConnectorConfig(
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

    # No pending authorization -> should fail with a clear cause_type.
    from securedact_mcp.connectors.microsoft.auth import MicrosoftTokenExchangeError

    with pytest.raises(MicrosoftTokenExchangeError) as exc_info:
        microsoft_auth._exchange_token_only(config, code="orphan-code", state="orphan-state")
    assert exc_info.value.cause_type is not None
    assert exc_info.value.cause_type == "LocalPendingAuthorizationMissing"


# ---------------------------------------------------------------------------
# Built-wheel subprocess regression
# ---------------------------------------------------------------------------


def _find_built_wheel() -> Path | None:
    dist = _REPO_ROOT / "dist"
    if not dist.is_dir():
        return None
    wheels = sorted(dist.glob("*.whl"))
    return wheels[-1] if wheels else None


def test_built_wheel_runtime_bootstrap_token_exchange_subprocess() -> None:
    """Built-wheel subprocess regression: the token exchange must succeed.

    Runs a Python harness that mocks the loopback server (immediate callback
    with a fake code) and the MSAL ``acquire_token_by_auth_code_flow``
    method (returns a successful token response), then invokes
    ``run_local_oauth`` through the freshly built wheel. Asserts the
    token exchange succeeded (no ``AttributeError``, no
    ``microsoft_token_exchange_failed``).
    """

    if shutil.which("uv") is None:
        pytest.skip("uv build unavailable")
    uv_exe = shutil.which("uv")
    assert uv_exe is not None

    work = Path(tempfile.gettempdir()) / "securedact_mcp_tests" / "m365_token_exchange_subprocess"
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

    # Verify the built wheel uses the PKCE-aware MSAL API.
    with zipfile.ZipFile(built) as z:
        auth_content = z.read("securedact_mcp/connectors/microsoft/auth.py").decode()
        assert "initiate_auth_code_flow" in auth_content, (
            "built wheel's auth.py does not use initiate_auth_code_flow"
        )
        assert "acquire_token_by_auth_code_flow" in auth_content, (
            "built wheel's auth.py does not use acquire_token_by_auth_code_flow"
        )
        # The private MSAL attribute ``_code_challenge`` must not be
        # accessed in code (docstring mentions are fine; we only guard
        # against the old code that tried to read it as
        # ``pending.app._code_challenge``).
        import re

        code_only = re.sub(r'"""[\s\S]*?"""', "", auth_content)
        assert "_code_challenge" not in code_only, (
            "built wheel's auth.py code still references private MSAL attribute _code_challenge"
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
            import dataclasses
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

            from_msal = {"public": 0, "confidential": 0}
            pkce = {"initiate": False, "exchange": False, "verifier_survived": False}

            class _FakePublicClient:
                def __init__(self, *a, **kw):
                    from_msal["public"] += 1
                def initiate_auth_code_flow(self, *a, **kw):
                    pkce["initiate"] = True
                    return {
                        "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state=test-state",
                        "state": "test-state",
                        "code_verifier": "test-verifier-43-chars-abcdef0123456789",
                        "redirect_uri": "http://localhost",
                    }
                def acquire_token_by_auth_code_flow(self, auth_code_flow, auth_response, **kw):
                    pkce["exchange"] = True
                    if auth_code_flow.get("code_verifier") == "test-verifier-43-chars-abcdef0123456789":
                        pkce["verifier_survived"] = True
                    return {
                        "access_token": "test-at",
                        "refresh_token": "test-rt",
                        "expires_in": 3600,
                    }
                def get_accounts(self):
                    return []

            class _FakeConfidentialClient:
                def __init__(self, *a, **kw):
                    from_msal["confidential"] += 1

            class _FakeMsalModule:
                PublicClientApplication = _FakePublicClient
                ConfidentialClientApplication = _FakeConfidentialClient
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
                "public_used": from_msal["public"],
                "confidential_used": from_msal["confidential"],
                "pkce_initiate": pkce["initiate"],
                "pkce_exchange": pkce["exchange"],
                "verifier_survived": pkce["verifier_survived"],
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
    assert payload.get("stage") != "token_exchange", f"token exchange short-circuited: {payload}"
    assert payload.get("pkce_initiate") is True
    assert payload.get("pkce_exchange") is True
    assert payload.get("verifier_survived") is True
    # The public-client branch must have been taken.
    assert payload.get("public_used", 0) >= 1
    assert payload.get("confidential_used", 0) == 0
    # The error message must not contain "AttributeError" (the real-machine
    # regression symptom).
    assert "AttributeError" not in str(payload.get("error", "")), (
        f"token exchange surfaced AttributeError in the built wheel: {payload}"
    )
