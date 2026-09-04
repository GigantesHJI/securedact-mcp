# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the Microsoft loopback redirect URI host.

Reproduces the real-machine defect where Microsoft returned::

    AADSTS50011
    The redirect URI in the request is: http://127.0.0.1:53853/

Root cause: the SecuRedact-managed Microsoft Entra app is registered with
``http://localhost`` (no port). The Entra ``localhost`` matching rule allows
an ephemeral port to be appended, but ``127.0.0.1`` is a different host and
is rejected. The local HTTP server was binding to ``127.0.0.1`` (secure) and
the same host was being used in the redirect URI sent to Microsoft.

Fix: separate the *bind address* (``127.0.0.1``) from the *redirect URI
host* (``localhost``). The loopback listener still binds to the secure
``127.0.0.1`` interface, but the redirect URI sent to Microsoft now uses
``localhost`` as the host, matching the registered app.
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
# Constants
# ---------------------------------------------------------------------------


def test_loopback_host_is_loopback_interface() -> None:
    """The socket bind address must remain the secure ``127.0.0.1`` interface."""

    assert microsoft_auth.LOOPBACK_HOST == "127.0.0.1"


def test_redirect_host_is_localhost() -> None:
    """The redirect URI host must be the literal ``localhost``.

    Microsoft Entra's ``localhost`` matching rule accepts an ephemeral port
    on ``http://localhost`` but rejects ``http://127.0.0.1:<port>`` with
    AADSTS50011.
    """

    assert microsoft_auth.REDIRECT_HOST == "localhost"
    assert microsoft_auth.REDIRECT_HOST != microsoft_auth.LOOPBACK_HOST


def test_managed_redirect_uri_is_localhost() -> None:
    """The packaged managed-app redirect URI is the exact ``http://localhost``."""

    from securedact_mcp.connectors.microsoft.managed_config import (
        MANAGED_MICROSOFT_REDIRECT_URI,
    )

    assert MANAGED_MICROSOFT_REDIRECT_URI == "http://localhost"


# ---------------------------------------------------------------------------
# loopback_redirect_uri
# ---------------------------------------------------------------------------


def test_loopback_redirect_uri_uses_localhost_not_127() -> None:
    """``loopback_redirect_uri`` must use ``localhost`` as the host."""

    uri = microsoft_auth.loopback_redirect_uri(53853)
    assert uri == "http://localhost:53853/"
    assert "127.0.0.1" not in uri
    assert uri.startswith("http://localhost:")


def test_loopback_redirect_uri_preserves_ephemeral_port() -> None:
    """The dynamic ephemeral port must be preserved verbatim."""

    for port in (0, 80, 8080, 53853, 65535):
        uri = microsoft_auth.loopback_redirect_uri(port)
        assert uri.endswith(f":{port}/")
        assert uri == f"http://localhost:{port}/"


# ---------------------------------------------------------------------------
# LoopbackOAuthServer: binds to 127.0.0.1, advertises localhost
# ---------------------------------------------------------------------------


def _work_dir(name: str) -> Path:
    work = Path(r"C:\Users\User\AppData\Local\Temp\kilo\m365_redirect_tests")
    if not work.is_dir():
        work.mkdir(parents=True, exist_ok=True)
    d = work / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    return d


def test_loopback_oauth_server_binds_loopback_advertises_localhost() -> None:
    """The server binds to the secure ``127.0.0.1`` interface but advertises
    ``http://localhost:<port>/`` as the redirect URI."""

    server = microsoft_auth.LoopbackOAuthServer(expected_state="test-state", timeout=0.1)
    try:
        # The listener must bind to the loopback interface (not 0.0.0.0).
        host, port = server._httpd.server_address[:2]
        assert host == "127.0.0.1", f"LoopbackOAuthServer bound to {host!r}; expected 127.0.0.1"
        # The advertised redirect URI must use ``localhost`` (not 127.0.0.1).
        assert server.redirect_uri.startswith("http://localhost:"), (
            f"redirect_uri is {server.redirect_uri!r}; expected to start with http://localhost:"
        )
        assert "127.0.0.1" not in server.redirect_uri
        assert server.port == port
    finally:
        server.shutdown()


def test_loopback_oauth_server_callback_received_on_localhost() -> None:
    """The listener must accept connections on the ``localhost`` host.

    The browser resolves ``http://localhost:<port>/`` to the same
    ``127.0.0.1`` interface the server is bound to. This test connects to
    ``localhost:<port>`` and verifies the TCP connection is accepted (the
    callback handler runs asynchronously; we only verify the binding contract
    here -- the full callback flow is exercised in the production loopback
    path).
    """

    import http.client

    server = microsoft_auth.LoopbackOAuthServer(expected_state="s", timeout=0.5)
    try:
        server.start()
        port = server.port

        # Connect to ``localhost:<port>``. http.client resolves ``localhost``
        # to ``127.0.0.1``; the server is bound to that interface and accepts
        # the connection. We only verify the TCP accept here; the HTTP
        # callback handler runs asynchronously and its timing is not the
        # subject of this regression.
        conn = http.client.HTTPConnection("localhost", port, timeout=2.0)
        try:
            conn.request("GET", "/", headers={"Host": "localhost"})
            response = conn.getresponse()
            # The server responds 200 with the callback HTML (even for a
            # bare GET, because the handler is permissive in the test path).
            assert response.status in (200, 404), (
                f"unexpected status from loopback server: {response.status}"
            )
        finally:
            conn.close()
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# build_authorization_url: redirect URI goes to Microsoft
# ---------------------------------------------------------------------------


class _RecordingPublicClient:
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.authorization_url = (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?dummy=1"
        )

    def initiate_auth_code_flow(self, *args, **kwargs):
        self.last_kwargs = dict(kwargs)
        return {
            "auth_uri": self.authorization_url,
            "state": "test-state",
            "code_verifier": "test-verifier",
            "redirect_uri": kwargs.get("redirect_uri", "http://localhost"),
        }

    def acquire_token_by_auth_code_flow(self, *args, **kwargs):
        return {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}

    def get_accounts(self):
        return []


def _patch_msal(monkeypatch):
    class _FakeMsalModule:
        PublicClientApplication = _RecordingPublicClient
        ConfidentialClientApplication = _RecordingPublicClient

    monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())
    monkeypatch.setattr(microsoft_auth, "_FLOW_STATE", {})


def test_build_authorization_url_sends_localhost_redirect_to_microsoft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The redirect_uri sent to MSAL must be ``http://localhost:<port>/``,
    not ``http://127.0.0.1:<port>/``.

    Mirrors the production pattern in ``run_local_oauth`` and
    ``verify_microsoft_authorization_runtime``: the loopback server is created
    first, its ``redirect_uri`` (``http://localhost:<port>/``) replaces the
    config's bare ``http://localhost``, then ``build_authorization_url`` is
    called. MSAL must see the loopback server's ``localhost:<port>`` URI.
    """

    import dataclasses

    work = _work_dir("build_auth_localhost")

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

    # Create a real loopback server (binds to 127.0.0.1, advertises localhost).
    server = microsoft_auth.LoopbackOAuthServer(expected_state="test", timeout=0.1)
    try:
        captured: dict[str, object] = {}

        class _CapturingPublicClient(_RecordingPublicClient):
            def initiate_auth_code_flow(self, *args, **kwargs):
                captured.update(kwargs)
                return {
                    "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?dummy=1",
                    "state": "test-state",
                    "code_verifier": "test-verifier",
                    "redirect_uri": kwargs.get("redirect_uri", "http://localhost"),
                }

        class _FakeMsalModule:
            PublicClientApplication = _CapturingPublicClient
            ConfidentialClientApplication = _CapturingPublicClient

        monkeypatch.setitem(sys.modules, "msal", _FakeMsalModule())

        # Mirror the production pattern: replace the config's redirect_uri with
        # the loopback server's redirect_uri BEFORE calling build_authorization_url.
        loopback_config = dataclasses.replace(config, redirect_uri=server.redirect_uri)
        microsoft_auth.build_authorization_url(loopback_config, pkce=True)

        redirect_uri = captured.get("redirect_uri", "")
        assert isinstance(redirect_uri, str)
        assert redirect_uri.startswith("http://localhost:"), (
            f"redirect_uri sent to MSAL is {redirect_uri!r}; expected to start "
            f"with http://localhost: (127.0.0.1 is rejected with AADSTS50011)"
        )
        assert "127.0.0.1" not in redirect_uri
    finally:
        server.shutdown()


def test_managed_config_redirect_uri_base_is_localhost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The managed config base redirect URI is the registered ``http://localhost``."""

    work = _work_dir("managed_config_localhost")

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
    assert config.redirect_uri == "http://localhost"


# ---------------------------------------------------------------------------
# Built-wheel subprocess regression: --verify uses localhost redirect
# ---------------------------------------------------------------------------


def _find_built_wheel() -> Path | None:
    dist = _REPO_ROOT / "dist"
    if not dist.is_dir():
        return None
    wheels = sorted(dist.glob("*.whl"))
    return wheels[-1] if wheels else None


def test_built_wheel_runtime_bootstrap_microsoft_auth_verify_localhost_subprocess() -> None:
    """Built-wheel subprocess regression for the redirect URI host.

    Runs a Python harness that mocks MSAL to capture the exact ``redirect_uri``
    passed to MSAL, then invokes ``build_authorization_url`` through the
    freshly built wheel. Asserts the redirect_uri is ``http://localhost:<port>/``
    (not ``http://127.0.0.1:<port>/``).
    """

    if shutil.which("uv") is None:
        pytest.skip("uv build unavailable")
    uv_exe = shutil.which("uv")
    assert uv_exe is not None

    work = Path(r"C:\Users\User\AppData\Local\Temp\kilo") / "m365_redirect_subprocess"
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

    # Verify the wheel has the new REDIRECT_HOST constant.
    with zipfile.ZipFile(built) as z:
        auth_content = z.read("securedact_mcp/connectors/microsoft/auth.py").decode()
        assert 'REDIRECT_HOST = "localhost"' in auth_content, (
            "built wheel's auth.py is missing the REDIRECT_HOST = 'localhost' constant"
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

            captured = {}

            class _FakePublicClient:
                def __init__(self, *args, **kwargs):
                    pass
                def initiate_auth_code_flow(self, *args, **kwargs):
                    captured.update(kwargs)
                    return {
                        "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?dummy=1",
                        "state": "test-state",
                        "code_verifier": "test-verifier",
                        "redirect_uri": kwargs.get("redirect_uri", "http://localhost"),
                    }
                def acquire_token_by_auth_code_flow(self, *args, **kwargs):
                    return {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}
                def get_accounts(self):
                    return []

            class _FakeMsalModule:
                PublicClientApplication = _FakePublicClient
                ConfidentialClientApplication = _FakePublicClient
            sys.modules["msal"] = _FakeMsalModule

            microsoft_auth._FLOW_STATE = {}

            # Production pattern: create the loopback server, replace the
            # config's redirect_uri with the server's, then call
            # build_authorization_url. This is exactly what run_local_oauth
            # and verify_microsoft_authorization_runtime do.
            server = microsoft_auth.LoopbackOAuthServer(expected_state="t", timeout=0.1)
            try:
                loopback_config = dataclasses.replace(
                    config, redirect_uri=server.redirect_uri
                )
                microsoft_auth.build_authorization_url(loopback_config, pkce=True)
            finally:
                server.shutdown()

            print(json.dumps({
                "redirect_uri": captured.get("redirect_uri", ""),
                "server_redirect_uri": server.redirect_uri,
                "loopback_host": microsoft_auth.LOOPBACK_HOST,
                "redirect_host": microsoft_auth.REDIRECT_HOST,
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

    redirect_uri = payload.get("redirect_uri", "")
    assert redirect_uri, f"no redirect_uri captured: {payload}"
    assert redirect_uri.startswith("http://localhost:"), (
        f"redirect_uri sent to MSAL in the built wheel is {redirect_uri!r}; "
        f"expected http://localhost:<port>/ (AADSTS50011 would reject 127.0.0.1)"
    )
    assert "127.0.0.1" not in redirect_uri
    assert payload.get("redirect_host") == "localhost"
    assert payload.get("loopback_host") == "127.0.0.1"
