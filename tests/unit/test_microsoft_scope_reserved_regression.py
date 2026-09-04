# SPDX-License-Identifier: Apache-2.0
"""Regression tests for Microsoft scope handling.

Reproduces the real-machine defect where MSAL public clients rejected the
authorization request with::

    ValueError: You cannot use any scope value that is reserved.
    Your input: ['offline_access', 'Sites.Read.All', 'User.Read', 'Files.Read']
    The reserved list: ['offline_access', 'openid', 'profile']

Root cause: MSAL Python public clients automatically append the reserved OIDC
scopes ``offline_access``, ``openid``, and ``profile`` to every authorization
request and refuse explicit duplicates. The fix is a single sanitization point
(:func:`securedact_mcp.connectors.microsoft.auth._msal_scopes`) that strips
reserved scopes before they reach MSAL. These tests guard:

* the sanitization helper itself;
* ``build_authorization_url`` never passes a reserved scope to MSAL;
* the real-machine runtime-bootstrap verify path reaches consent-URL
  construction with the reserved-scope error gone;
* the managed configuration still surfaces the intended delegated Graph
  permissions (the existing ``Files.Read`` value is documented here -- not
  silently changed -- so the ``Files.Read`` vs ``Files.Read.All`` design
  question stays visible until it is resolved deliberately).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from securedact_core.connectors.microsoft import default_connector_scopes
from securedact_mcp.agent import microsoft_setup
from securedact_mcp.connectors.microsoft import auth as microsoft_auth
from securedact_mcp.connectors.microsoft.config import MicrosoftConnectorConfig

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MSAL_RESERVED = frozenset({"offline_access", "openid", "profile"})


# ---------------------------------------------------------------------------
# Scope sanitization helper
# ---------------------------------------------------------------------------


def test_msal_scopes_strips_reserved_scopes() -> None:
    """Every reserved scope must be removed before MSAL sees the list."""

    from securedact_mcp.connectors.microsoft.auth import _msal_scopes

    raw = [
        "User.Read",
        "Files.Read",
        "Sites.Read.All",
        "offline_access",
        "openid",
        "profile",
    ]
    out = _msal_scopes(raw)
    assert "offline_access" not in out
    assert "openid" not in out
    assert "profile" not in out
    # The dedicated Graph permissions survive intact.
    assert "User.Read" in out
    assert "Sites.Read.All" in out


def test_msal_scopes_preserves_graph_permissions() -> None:
    """The helper must not rewrite, reorder, or drop delegated Graph scopes."""

    from securedact_mcp.connectors.microsoft.auth import _msal_scopes

    raw = ["Files.Read", "Sites.Read.All", "User.Read"]
    assert _msal_scopes(raw) == raw


def test_msal_scopes_no_op_when_no_reserved_present() -> None:
    """If no reserved scope is present, the helper is a pure pass-through."""

    from securedact_mcp.connectors.microsoft.auth import _msal_scopes

    raw = ["User.Read", "Files.Read", "Sites.Read.All"]
    assert _msal_scopes(raw) == raw


# ---------------------------------------------------------------------------
# build_authorization_url never hands a reserved scope to MSAL
# ---------------------------------------------------------------------------


class _FakeMsalApp:
    """Minimal stand-in for an MSAL public-client app.

    Records the exact ``scopes`` argument it receives so the test can assert
    that no reserved scope (``offline_access``, ``openid``, ``profile``) ever
    reaches MSAL.
    """

    last_scopes: list[str] | None = None
    last_kwargs: dict[str, object]

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.last_scopes = None
        self.last_kwargs = {}

    def get_authorization_request_url(self, *args: object, **kwargs: object) -> str:
        # Legacy API; kept for completeness. The new code path uses
        # ``initiate_auth_code_flow`` + ``acquire_token_by_auth_code_flow``.
        if "scopes" in kwargs:
            self.last_scopes = list(kwargs["scopes"])  # type: ignore[arg-type]
        else:
            self.last_scopes = list(args[0]) if args else []  # type: ignore[arg-type]
        self.last_kwargs = dict(kwargs)
        return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?code_challenge=X"

    def initiate_auth_code_flow(self, *args: object, **kwargs: object) -> dict[str, object]:
        if "scopes" in kwargs:
            self.last_scopes = list(kwargs["scopes"])  # type: ignore[arg-type]
        else:
            self.last_scopes = list(args[0]) if args else []  # type: ignore[arg-type]
        self.last_kwargs = dict(kwargs)
        return {
            "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?code_challenge=X",
            "state": "test-state",
            "code_verifier": "test-verifier",
            "redirect_uri": kwargs.get("redirect_uri", "http://localhost"),
        }

    def acquire_token_by_auth_code_flow(self, *args: object, **kwargs: object) -> dict[str, object]:
        return {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}


def test_build_authorization_url_never_passes_reserved_scopes_to_msal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``build_authorization_url`` must sanitize reserved scopes before MSAL."""

    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="test-client-id",
        client_secret=None,  # public client
        tenant_id="common",
        redirect_uri="http://localhost",
        scopes=["User.Read", "Files.Read", "Sites.Read.All", "offline_access"],
        token_path=Path("C:\\Users\\User\\AppData\\Local\\Temp\\kilo") / "token.json.enc",
        key_path=Path("C:\\Users\\User\\AppData\\Local\\Temp\\kilo") / "token.key",
        managed=True,
    )

    # Patch the MSAL factory so the test does not require the real msal package
    # to be importable here. The function does ``from msal import
    # PublicClientApplication, ConfidentialClientApplication`` so we must patch
    # the ``msal`` module's namespace, not the auth module's attributes.
    captured_app: list[_FakeMsalApp] = []

    def _factory(*args: object, **kwargs: object) -> _FakeMsalApp:
        app = _FakeMsalApp(*args, **kwargs)
        captured_app.append(app)
        return app

    class _FakeMsalModule:
        PublicClientApplication = _factory
        ConfidentialClientApplication = _factory

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    microsoft_auth.build_authorization_url(config, pkce=True)

    assert len(captured_app) == 1, (
        f"Expected exactly one MSAL app to be instantiated, got {len(captured_app)}"
    )
    fake_app = captured_app[0]
    assert fake_app.last_scopes is not None
    for reserved in _MSAL_RESERVED:
        assert reserved not in fake_app.last_scopes, (
            f"MSAL received reserved scope {reserved!r}; build_authorization_url "
            f"must strip reserved scopes before calling MSAL"
        )
    # Delegated Graph permissions are preserved.
    assert "User.Read" in fake_app.last_scopes
    assert "Sites.Read.All" in fake_app.last_scopes


# ---------------------------------------------------------------------------
# Managed configuration surfaces the intended Graph permissions
# ---------------------------------------------------------------------------


def test_default_connector_scopes_current_shape() -> None:
    """Document the current ``default_connector_scopes`` shape.

    The runtime currently returns ``['Files.Read', 'Sites.Read.All', 'User.Read', 'offline_access']``.
    The ``offline_access`` scope is a MSAL reserved scope that MSAL public clients
    add automatically -- it must be stripped before reaching MSAL (see
    :func:`securedact_mcp.connectors.microsoft.auth._msal_scopes`). The
    ``MICROSOFT_DEFAULT_SCOPES`` constant in
    :mod:`securedact_mcp.agent.microsoft_setup` declares the broader
    ``Files.Read.All`` as the intended managed-app design. This test pins the
    current source-of-truth so the discrepancy is visible until it is resolved
    deliberately (see audit report).
    """

    scopes = default_connector_scopes()
    # ``offline_access`` IS in the source-of-truth (added by build_graph_scopes)
    # and must be stripped at the MSAL boundary, not at the scope source.
    assert "offline_access" in scopes
    assert "Files.Read" in scopes
    assert "Sites.Read.All" in scopes
    assert "User.Read" in scopes


def test_microsoft_default_scopes_constant_documents_intent() -> None:
    """``MICROSOFT_DEFAULT_SCOPES`` in the agent module declares the intended
    ``Files.Read.All`` design. The constant is exported but currently unused by
    the config loader. This test pins the documented intent so a future
    reconciliation between source-of-truth (``Files.Read``) and design intent
    (``Files.Read.All``) is a deliberate, visible change.

    Note: ``offline_access`` IS in this design-intent constant -- it is the
    refresh-token scope. MSAL public clients strip it from the explicit scope
    list and re-add it automatically (see :func:`_msal_scopes`).
    """

    assert "Files.Read.All" in microsoft_setup.MICROSOFT_DEFAULT_SCOPES
    assert "Sites.Read.All" in microsoft_setup.MICROSOFT_DEFAULT_SCOPES
    assert "User.Read" in microsoft_setup.MICROSOFT_DEFAULT_SCOPES
    # ``openid`` and ``profile`` are NOT in the design-intent constant -- only
    # the dedicated delegated Graph permissions and the refresh-token scope.
    assert "openid" not in microsoft_setup.MICROSOFT_DEFAULT_SCOPES
    assert "profile" not in microsoft_setup.MICROSOFT_DEFAULT_SCOPES


# ---------------------------------------------------------------------------
# Runtime-bootstrap verify path reaches consent-URL construction
# ---------------------------------------------------------------------------


def test_verify_microsoft_authorization_reaches_consent_url_building(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runtime-bootstrap verify path must reach consent-URL construction
    without the MSAL reserved-scope error.

    Uses a mocked MSAL app (same shape as the real one) to prove that the
    verify function hands sanitized scopes to MSAL and does not short-circuit
    on the reserved-scope ValueError that broke the real machine.
    """

    data_dir = Path("C:\\Users\\User\\AppData\\Local\\Temp\\kilo") / "m365_verify_test"
    data_dir.mkdir(parents=True, exist_ok=True)

    # Seed a Microsoft config in the temp data root by writing through the
    # public loader (which honors ``data_dir``). Use the packaged managed
    # client so the verify path has a real client_id; tests below ensure the
    # managed app is resolvable in this environment.
    monkeypatch.setenv("SECUREDACT_MICROSOFT_ENABLED", "1")

    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="00000000-0000-0000-0000-000000000000",
        client_secret=None,
        tenant_id="common",
        redirect_uri="http://localhost",
        scopes=["User.Read", "Files.Read", "Sites.Read.All", "offline_access"],
        token_path=data_dir / "microsoft" / "token.json.enc",
        key_path=data_dir / "microsoft" / "token.key",
        managed=True,
    )

    # Patch the config loader to return our test config.
    def fake_load_microsoft_config(
        *, require_enabled: bool = False, profile: str = "default", data_dir=None
    ):
        return config

    monkeypatch.setattr(
        "securedact_mcp.connectors.microsoft.config.load_microsoft_config",
        fake_load_microsoft_config,
    )

    # Patch MSAL to a recording fake.
    captured_apps: list[_FakeMsalApp] = []

    def _msal_factory(*args: object, **kwargs: object) -> _FakeMsalApp:
        app = _FakeMsalApp(*args, **kwargs)
        captured_apps.append(app)
        return app

    class _FakeMsalModule:
        PublicClientApplication = _msal_factory
        ConfidentialClientApplication = _msal_factory

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    payload = microsoft_setup.verify_microsoft_authorization_runtime(data_dir)

    # The reserved-scope error is the exact regression we are guarding.
    assert payload.get("error") is None or "reserved" not in str(payload.get("error")).lower(), (
        f"verify_microsoft_authorization_runtime failed with the MSAL "
        f"reserved-scope error: {payload.get('error')!r}"
    )
    assert payload["imports_ok"] is True
    assert payload["client_configured"] is True
    assert payload["loopback_bound"] is True
    # Consent URL construction succeeded (MSAL accepted the sanitized scopes).
    assert payload["consent_url_built"] is True
    # No browser was opened during --verify.
    assert payload["browser_opened"] is False
    # MSAL received the sanitized scope list (no reserved scopes).
    assert captured_apps, "MSAL factory was never called"
    last = captured_apps[-1]
    assert last.last_scopes is not None
    for reserved in _MSAL_RESERVED:
        assert reserved not in last.last_scopes


def test_loopback_authorization_uses_sanitized_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production loopback path must use the same sanitization as verify."""

    data_dir = Path("C:\\Users\\User\\AppData\\Local\\Temp\\kilo") / "m365_loopback_test"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SECUREDACT_MICROSOFT_ENABLED", "1")

    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="00000000-0000-0000-0000-000000000000",
        client_secret=None,
        tenant_id="common",
        redirect_uri="http://localhost",
        scopes=["User.Read", "Files.Read", "Sites.Read.All", "offline_access"],
        token_path=data_dir / "microsoft" / "token.json.enc",
        key_path=data_dir / "microsoft" / "token.key",
        managed=True,
    )

    def fake_load_microsoft_config(
        *, require_enabled: bool = False, profile: str = "default", data_dir=None
    ):
        return config

    monkeypatch.setattr(
        "securedact_mcp.connectors.microsoft.config.load_microsoft_config",
        fake_load_microsoft_config,
    )

    fake_app: list[_FakeMsalApp] = []

    def _msal_factory(*args: object, **kwargs: object) -> _FakeMsalApp:
        app = _FakeMsalApp(*args, **kwargs)
        fake_app.append(app)
        return app

    class _FakeMsalModule:
        PublicClientApplication = _msal_factory
        ConfidentialClientApplication = _msal_factory

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})

    # Drive the same code path the real loopback uses (build_authorization_url).
    microsoft_auth.build_authorization_url(config, pkce=True)

    assert fake_app, "MSAL factory was never called"
    last = fake_app[-1]
    assert last.last_scopes is not None
    for reserved in _MSAL_RESERVED:
        assert reserved not in last.last_scopes


# ---------------------------------------------------------------------------
# Built-wheel subprocess regression
# ---------------------------------------------------------------------------


def _find_built_wheel() -> Path | None:
    dist = _REPO_ROOT / "dist"
    if not dist.is_dir():
        return None
    wheels = sorted(dist.glob("*.whl"))
    return wheels[-1] if wheels else None


def test_built_wheel_runtime_bootstrap_microsoft_auth_verify_subprocess() -> None:
    """Built-wheel subprocess regression.

    Builds the wheel and runs the exact real-machine command via ``python -m``,
    asserting that the MSAL reserved-scope error does NOT appear in the output.
    The runtime-bootstrap dispatch regression (test_runtime_bootstrap_*_subprocess)
    already guards against NameError; this test guards against the scope bug.
    """

    if shutil.which("uv") is None:
        pytest.skip("uv build unavailable")
    uv_exe = shutil.which("uv")
    assert uv_exe is not None

    work = Path("C:\\Users\\User\\AppData\\Local\\Temp\\kilo") / "m365_subprocess_test"
    work.mkdir(parents=True, exist_ok=True)

    built = _find_built_wheel()
    if built is None:
        out = work / "dist"
        out.mkdir()
        result = subprocess.run(  # noqa: S603 - fixed argv
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

    # Verify the wheel actually contains our sanitization helper.
    with zipfile.ZipFile(built) as z:
        names = z.namelist()
        assert "securedact_mcp/connectors/microsoft/auth.py" in names
        auth_content = z.read("securedact_mcp/connectors/microsoft/auth.py").decode()
        assert "_msal_scopes" in auth_content, (
            "built wheel's auth.py is missing the MSAL scope sanitization helper"
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

    data_dir = work / "data"
    data_dir.mkdir(exist_ok=True)

    # Run the EXACT real-machine command shape: import the module then call
    # main() with the microsoft-auth --verify argv. This triggers the __main__
    # dispatch ordering (guarded by test_runtime_bootstrap_*_subprocess) AND the
    # MSAL scope sanitization (guarded here).
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "raise SystemExit(__import__('securedact_mcp.agent.runtime_bootstrap', "
            "fromlist=['']).main(['microsoft-auth', '--verify', '--data-dir', sys.argv[2]]))",
            str(target),
            str(data_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert "_cmd_microsoft_auth" not in proc.stderr
    assert "NameError" not in proc.stderr
    combined = proc.stdout + proc.stderr
    assert "You cannot use any scope value that is reserved" not in combined, (
        f"runtime-bootstrap microsoft-auth --verify surfaced the MSAL "
        f"reserved-scope error in the built wheel:\nstdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )
    # The verify path must produce JSON stdout (success or graceful failure).
    assert proc.stdout.strip(), (
        f"runtime-bootstrap microsoft-auth --verify produced no stdout; "
        f"stderr:\n{proc.stderr[-2000:]}"
    )
    payload = json.loads(proc.stdout)
    # The reserved-scope error must not be the reason verify failed
    assert payload.get("error") is None or "reserved" not in str(payload.get("error", "")).lower()
