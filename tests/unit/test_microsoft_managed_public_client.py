# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the Microsoft managed public-client OAuth path.

Reproduces the real-machine defect where ``--loopback`` on the ProgramData
machine runtime failed with::

    {
      "authorized": false,
      "stage": "pre_authorization",
      "error_code": "microsoft_managed_client_secret_missing",
      "error": "pre_authorization: pre_authorization"
    }

Root cause: a stale pre-authorization gate copied from the Google managed-app
flow incorrectly required a ``client_secret`` for the Microsoft managed path.
The SecuRedact-managed Microsoft Entra app is a **public/native Desktop
client** that uses PKCE -- no ``client_secret`` is required or used. Only the
BYO confidential-client path may carry a ``client_secret``.

These tests guard:

* ``get_managed_microsoft_config()`` returns ``client_secret is None``;
* ``run_local_oauth`` accepts ``client_secret=None`` in managed mode;
* ``build_authorization_url`` instantiates ``PublicClientApplication`` (not
  ``ConfidentialClientApplication``) for the managed path;
* ``microsoft_managed_client_secret_missing`` is never emitted;
* the loopback authorization reaches the browser/consent path under PKCE
  without requiring a client secret.
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
# Managed configuration: public client, no secret
# ---------------------------------------------------------------------------


def test_managed_microsoft_config_has_no_client_secret() -> None:
    """The SecuRedact-managed Microsoft Entra app must expose no client_secret.

    This is the architectural invariant the entire managed path depends on.
    """
    config = microsoft_managed.get_managed_microsoft_config()
    # client_secret is not part of ManagedMicrosoftConfig at all, but the
    # field exists on the broader MicrosoftConnectorConfig. For the managed
    # path the public-client design means client_secret is always None.
    assert microsoft_managed.MANAGED_MICROSOFT_CLIENT_ID == ("187e325c-7095-429c-9cb6-4feafda2d18d")
    # The managed config has no client_secret attribute -- it is intentionally
    # a public-client definition.
    assert not hasattr(config, "client_secret") or getattr(config, "client_secret", None) is None


def test_managed_microsoft_client_id_is_packaged() -> None:
    """The packaged managed client id is the exact production value."""
    assert microsoft_managed.MANAGED_MICROSOFT_CLIENT_ID == ("187e325c-7095-429c-9cb6-4feafda2d18d")


# ---------------------------------------------------------------------------
# Stale constants removed
# ---------------------------------------------------------------------------


def test_managed_microsoft_has_no_stale_secret_constants() -> None:
    """The stale "managed client secret missing" constants must be gone.

    The Microsoft managed app is a public client with PKCE -- the
    "client secret missing" diagnostic was a bug, not a feature. If any of
    these constants reappear, the stale pre-authorization gate is likely
    being reintroduced.
    """
    assert not hasattr(microsoft_managed, "MANAGED_CLIENT_SECRET_MISSING_CODE")
    assert not hasattr(microsoft_managed, "MANAGED_CLIENT_SECRET_NOT_CONFIGURED_MSG")
    assert not hasattr(microsoft_auth, "ERR_MANAGED_CLIENT_SECRET_MISSING")


# ---------------------------------------------------------------------------
# run_local_oauth accepts client_secret=None for managed path
# ---------------------------------------------------------------------------


class _RecordingMsalApp:
    """Captures the exact MSAL app class and scopes used by the auth path.

    Implements the modern MSAL public-client PKCE API:
    ``initiate_auth_code_flow`` + ``acquire_token_by_auth_code_flow``.
    """

    def __init__(self, *args, **kwargs):
        self._args = args
        self._kwargs = kwargs
        self.last_scopes: list[str] | None = None
        self.last_exchange_scopes: list[str] | None = None
        self.last_flow: dict[str, object] | None = None
        self.last_exchange_kwargs: dict[str, object] = {}
        self.authorization_url = (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?x=1"
        )
        # Stable state for tests that need to assert the callback matches.
        self.fake_state = "test-state-12345"
        self.fake_code_verifier = "test-code-verifier-67890"

    def initiate_auth_code_flow(self, *args, **kwargs):
        scopes = list(kwargs.get("scopes", args[0] if args else []))
        self.last_scopes = scopes
        return {
            "auth_uri": self.authorization_url,
            "state": self.fake_state,
            "code_verifier": self.fake_code_verifier,
            "redirect_uri": kwargs.get("redirect_uri", "http://localhost"),
            "scope": " ".join(scopes),
        }

    def acquire_token_by_auth_code_flow(self, *args, **kwargs):
        self.last_exchange_kwargs = dict(kwargs)
        # ``acquire_token_by_auth_code_flow(self, auth_code_flow, auth_response, scopes=None)``
        auth_code_flow = kwargs.get("auth_code_flow", args[0] if args else {})
        self.last_flow = dict(auth_code_flow) if auth_code_flow else None
        scopes = kwargs.get("scopes")
        if scopes is not None:
            self.last_exchange_scopes = list(scopes)
        return {"access_token": "test-at", "refresh_token": "test-rt", "expires_in": 3600}

    def get_accounts(self):
        return []

    def acquire_token_silent(self, *args, **kwargs):
        return None

    def acquire_token_by_refresh_token(self, *args, **kwargs):
        return {"access_token": "test-at", "refresh_token": "test-rt", "expires_in": 3600}


def _patch_msal(monkeypatch, *, app_cls=_RecordingMsalApp):
    """Patch ``sys.modules['msal']`` with a recording fake."""

    class _FakeMsalModule:
        PublicClientApplication = app_cls
        ConfidentialClientApplication = app_cls

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())


_TEST_WORK = Path(r"C:\Users\User\AppData\Local\Temp\kilo\m365_managed_tests")


def _work_dir(name: str) -> Path:
    """Create a stable scratch directory for test artifacts (tmp_path is
    flaky on this Windows host due to permission issues in the default
    pytest tmpdir location)."""
    if not _TEST_WORK.is_dir():
        _TEST_WORK.mkdir(parents=True, exist_ok=True)
    d = _TEST_WORK / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    return d


def test_run_local_oauth_managed_no_secret_reaches_browser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Managed mode with client_secret=None must reach the browser path.

    Before the fix, the stale pre-authorization gate returned
    ``microsoft_managed_client_secret_missing`` before any browser launch.
    After the fix, managed mode uses PublicClientApplication + PKCE and the
    loopback server starts, the consent URL is built, and the browser opener
    is invoked (mocked to avoid a real browser).
    """

    work = _work_dir("run_local_oauth_managed")

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

    captured = {"browser_called": False, "url": None}

    def fake_browser_open(url: str) -> None:
        captured["browser_called"] = True
        captured["url"] = url

    _patch_msal(monkeypatch)
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    outcome = microsoft_auth.run_local_oauth(
        config,
        open_browser=False,
        timeout_seconds=0.5,
        _browser_open=fake_browser_open,
    )

    assert outcome.error_code != "microsoft_managed_client_secret_missing"
    assert outcome.stage != "pre_authorization"
    assert captured["browser_called"], (
        "run_local_oauth never invoked the browser opener; the stale "
        "client_secret gate or another pre-authorization guard short-circuited"
    )
    assert captured["url"] is not None
    assert "login.microsoftonline.com" in captured["url"]


def test_run_local_oauth_emits_no_managed_secret_missing_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact regression: ``microsoft_managed_client_secret_missing`` must
    never appear in the loopback outcome for the managed public-client path."""

    work = _work_dir("emit_no_managed_secret_missing")

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

    def fake_browser_open(url: str) -> None:
        pass

    _patch_msal(monkeypatch)
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    outcome = microsoft_auth.run_local_oauth(
        config,
        open_browser=False,
        timeout_seconds=0.5,
        _browser_open=fake_browser_open,
    )

    assert outcome.error_code != "microsoft_managed_client_secret_missing"
    assert "client_secret" not in (outcome.error or "").lower()


# ---------------------------------------------------------------------------
# build_authorization_url uses PublicClientApplication for managed path
# ---------------------------------------------------------------------------


def test_build_authorization_url_managed_uses_public_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The consent-URL build for managed mode must use PublicClientApplication,
    not ConfidentialClientApplication."""

    work = _work_dir("build_managed")

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

    instantiations: list[str] = []

    class _TrackingPublicClient(_RecordingMsalApp):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instantiations.append("PublicClientApplication")

    class _TrackingConfidentialClient(_RecordingMsalApp):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instantiations.append("ConfidentialClientApplication")

    class _FakeMsalModule:
        PublicClientApplication = _TrackingPublicClient
        ConfidentialClientApplication = _TrackingConfidentialClient

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    url, _state = microsoft_auth.build_authorization_url(config, pkce=True)

    assert "PublicClientApplication" in instantiations
    assert "ConfidentialClientApplication" not in instantiations, (
        "build_authorization_url instantiated ConfidentialClientApplication "
        "for the managed public-client path"
    )
    assert "login.microsoftonline.com" in url


def test_build_authorization_url_byo_with_secret_uses_confidential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BYO with a client_secret must use ConfidentialClientApplication."""

    work = _work_dir("build_byo_with_secret")

    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="byo-client-id",
        client_secret="byo-secret-value",  # noqa: S106
        tenant_id="byo-tenant",
        redirect_uri="http://localhost",
        scopes=["User.Read", "Files.Read", "Sites.Read.All"],
        token_path=work / "token.json.enc",
        key_path=work / "token.key",
        managed=False,
    )

    instantiations: list[str] = []

    class _TrackingPublicClient(_RecordingMsalApp):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instantiations.append("PublicClientApplication")

    class _TrackingConfidentialClient(_RecordingMsalApp):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instantiations.append("ConfidentialClientApplication")

    class _FakeMsalModule:
        PublicClientApplication = _TrackingPublicClient
        ConfidentialClientApplication = _TrackingConfidentialClient

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    microsoft_auth.build_authorization_url(config, pkce=True)

    assert "ConfidentialClientApplication" in instantiations
    assert "PublicClientApplication" not in instantiations


def test_build_authorization_url_byo_without_secret_uses_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BYO without a client_secret must use PublicClientApplication (PKCE)."""

    work = _work_dir("build_byo_without_secret")

    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="byo-client-id",
        client_secret=None,
        tenant_id="byo-tenant",
        redirect_uri="http://localhost",
        scopes=["User.Read", "Files.Read", "Sites.Read.All"],
        token_path=work / "token.json.enc",
        key_path=work / "token.key",
        managed=False,
    )

    instantiations: list[str] = []

    class _TrackingPublicClient(_RecordingMsalApp):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instantiations.append("PublicClientApplication")

    class _TrackingConfidentialClient(_RecordingMsalApp):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instantiations.append("ConfidentialClientApplication")

    class _FakeMsalModule:
        PublicClientApplication = _TrackingPublicClient
        ConfidentialClientApplication = _TrackingConfidentialClient

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    microsoft_auth.build_authorization_url(config, pkce=True)

    assert "PublicClientApplication" in instantiations
    assert "ConfidentialClientApplication" not in instantiations


# ---------------------------------------------------------------------------
# PKCE code verifier / challenge present for managed path
# ---------------------------------------------------------------------------


def test_build_authorization_url_managed_includes_pkce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The managed public-client flow must include a PKCE code challenge.

    Uses MSAL's ``initiate_auth_code_flow`` which generates the
    ``code_verifier`` internally and returns a flow dict containing the
    ``auth_uri``, ``state``, and ``code_verifier``. The ``code_verifier``
    must be stored in the pending authorization record so the token
    exchange can use it.
    """

    work = _work_dir("build_pkce")

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

    captured_flow: dict[str, object] = {}

    class _CapturingPublicClient(_RecordingMsalApp):
        def initiate_auth_code_flow(self, *args, **kwargs):
            flow = super().initiate_auth_code_flow(*args, **kwargs)
            captured_flow.update(flow)
            return flow

    _patch_msal(monkeypatch, app_cls=_CapturingPublicClient)
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    url, state = microsoft_auth.build_authorization_url(config, pkce=True)

    # The consent URL must have been built.
    assert url.startswith("https://login.microsoftonline.com/")
    # The state must be non-empty.
    assert state
    # The flow dict must contain a PKCE code_verifier.
    assert captured_flow.get("code_verifier"), (
        "PKCE code_verifier was not present in the MSAL flow dict"
    )
    # The pending authorization must have been stored with the flow dict.
    pending = microsoft_auth._FLOW_STATE[state]
    assert pending.auth_code_flow.get("code_verifier") == captured_flow.get("code_verifier"), (
        "PKCE code_verifier did not survive from authorization request to exchange"
    )


# ---------------------------------------------------------------------------
# Built-wheel subprocess regression: --loopback reaches the public-client path
# ---------------------------------------------------------------------------


def _find_built_wheel() -> Path | None:
    dist = _REPO_ROOT / "dist"
    if not dist.is_dir():
        return None
    wheels = sorted(dist.glob("*.whl"))
    return wheels[-1] if wheels else None


def test_built_wheel_runtime_bootstrap_microsoft_auth_loopback_subprocess() -> None:
    """Built-wheel subprocess regression for ``microsoft-auth --loopback``.

    Runs a Python harness that monkey-patches ``LoopbackOAuthServer`` to
    immediately call back with a fake code, then invokes the real
    ``run_local_oauth`` through the freshly built wheel. Asserts the outcome
    is NOT the stale ``microsoft_managed_client_secret_missing`` error and
    that the public-client branch was reached.
    """

    if shutil.which("uv") is None:
        pytest.skip("uv build unavailable")
    uv_exe = shutil.which("uv")
    assert uv_exe is not None

    work = Path(r"C:\Users\User\AppData\Local\Temp\kilo") / "m365_loopback_subprocess"
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

    # Verify the wheel does NOT contain the stale gate.
    with zipfile.ZipFile(built) as z:
        auth_content = z.read("securedact_mcp/connectors/microsoft/auth.py").decode()
        assert "ERR_MANAGED_CLIENT_SECRET_MISSING" not in auth_content, (
            "built wheel's auth.py still contains ERR_MANAGED_CLIENT_SECRET_MISSING"
        )
        assert "microsoft_managed_client_secret_missing" not in auth_content, (
            "built wheel's auth.py still references the stale managed-client-secret error"
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

    # Write a harness that mocks the loopback server (immediate callback with
    # a fake code) and then invokes run_local_oauth. This proves the public-
    # client PKCE flow (initiate_auth_code_flow + acquire_token_by_auth_code_flow)
    # is reached without a client_secret in the built wheel.
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

            # Record which MSAL app class is used and whether the PKCE flow
            # methods are called correctly.
            from_msal = {"public": 0, "confidential": 0}
            pkce_flow = {"initiated": False, "exchanged": False, "verifier_survived": False}

            class _FakePublicClient:
                def __init__(self, *a, **kw):
                    from_msal["public"] += 1
                def initiate_auth_code_flow(self, *a, **kw):
                    pkce_flow["initiated"] = True
                    return {
                        "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state=harness-state&code_challenge=cc",
                        "state": "harness-state",
                        "code_verifier": "harness-code-verifier",
                        "redirect_uri": "http://localhost",
                    }
                def acquire_token_by_auth_code_flow(self, auth_code_flow, auth_response, **kw):
                    pkce_flow["exchanged"] = True
                    # Verify the code_verifier survived from initiation to exchange
                    if auth_code_flow.get("code_verifier") == "harness-code-verifier":
                        pkce_flow["verifier_survived"] = True
                    return {"access_token": "test-at", "refresh_token": "test-rt", "expires_in": 3600}
                def get_accounts(self):
                    return []

            class _FakeConfidentialClient:
                def __init__(self, *a, **kw):
                    from_msal["confidential"] += 1
                def initiate_auth_code_flow(self, *a, **kw):
                    return {"auth_uri": "", "state": "x", "code_verifier": "x", "redirect_uri": "x"}
                def acquire_token_by_auth_code_flow(self, *a, **kw):
                    return {"access_token": "test-at", "refresh_token": "test-rt", "expires_in": 3600}
                def get_accounts(self):
                    return []

            class _FakeMsalModule:
                PublicClientApplication = _FakePublicClient
                ConfidentialClientApplication = _FakeConfidentialClient

            sys.modules["msal"] = _FakeMsalModule

            # Mock the loopback server: capture the state it was given, then
            # call back immediately with a matching code.
            captured_state = {"state": None}

            class _FakeLoopbackResult:
                def __init__(self):
                    self.code = None
                    self.error = None
                    self.state = None

            class _FakeLoopbackServer:
                def __init__(self, expected_state="", timeout=0):
                    captured_state["state"] = expected_state
                    self.expected_state = expected_state
                    self.timeout = timeout
                    self.redirect_uri = "http://localhost:12345/"
                    self.port = 12345
                def start(self):
                    pass
                def shutdown(self):
                    pass
                def wait_for_callback(self):
                    result = _FakeLoopbackResult()
                    result.code = "fake-code"
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

            result = {
                "authorized": outcome.authorized,
                "stage": outcome.stage,
                "error_code": outcome.error_code,
                "error": outcome.error,
                "public_used": from_msal["public"],
                "confidential_used": from_msal["confidential"],
                "pkce_initiated": pkce_flow["initiated"],
                "pkce_exchanged": pkce_flow["exchanged"],
                "verifier_survived": pkce_flow["verifier_survived"],
            }
            print(json.dumps(result))
            """
        ),
        encoding="utf-8",
    )

    data_dir = work / "data"
    data_dir.mkdir(exist_ok=True)

    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(harness),
            str(target),
            str(data_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert proc.stdout.strip(), f"harness produced no stdout; stderr:\n{proc.stderr[-2000:]}"
    payload = json.loads(proc.stdout)

    # The exact regression: this error_code must never appear for the
    # managed public-client path.
    assert payload.get("error_code") != "microsoft_managed_client_secret_missing", (
        f"managed loopback returned the stale microsoft_managed_client_secret_missing "
        f"error: {payload}"
    )
    assert payload.get("stage") != "pre_authorization", (
        f"managed loopback short-circuited at pre_authorization: {payload}"
    )
    # No client_secret-related error at all.
    assert "client_secret" not in str(payload.get("error", "")).lower(), (
        f"managed loopback surfaced a client_secret error: {payload}"
    )
    # The public-client branch must have been taken.
    assert payload.get("public_used", 0) >= 1, (
        f"PublicClientApplication was never instantiated: {payload}"
    )
    assert payload.get("confidential_used", 0) == 0, (
        f"ConfidentialClientApplication was instantiated for the managed "
        f"public-client path: {payload}"
    )
    # The PKCE flow must have been used (initiate + exchange).
    assert payload.get("pkce_initiated") is True, (
        f"initiate_auth_code_flow was not called: {payload}"
    )
    assert payload.get("pkce_exchanged") is True, (
        f"acquire_token_by_auth_code_flow was not called: {payload}"
    )
    assert payload.get("verifier_survived") is True, (
        f"PKCE code_verifier did not survive from authorization to exchange: {payload}"
    )
    # The token exchange must have succeeded (no AttributeError, no token_exchange failure).
    assert payload.get("authorized") is True, (
        f"managed loopback did not complete successfully: {payload}"
    )
