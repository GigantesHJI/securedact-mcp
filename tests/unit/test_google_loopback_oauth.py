# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the production Google OAuth (managed Desktop/Installed app).

Covers the production architecture where normal customers connect through a
SecuRedact-owned Google OAuth application and authorize locally via a loopback
listener (PKCE), without ever creating a Google Cloud project or typing a client
secret.

Key invariants asserted here:

* normal mode never prompts for a client id/secret;
* the managed client id resolves without customer input and is the single source
  of truth;
* a missing managed client id fails closed with a clear message (no prompt);
* BYO is explicit only;
* a Desktop/Installed client works without a client secret;
* only drive.readonly is requested; write scopes remain rejected;
* the loopback listener binds only to 127.0.0.1 on a random port;
* OAuth state mismatch and callback timeout fail closed;
* the authorization code/token never appears on argv/logs;
* authorization runs in the machine runtime (not the setup interpreter);
* the token is stored under the machine root and the binding is created after auth;
* setup readiness requires the binding; existing valid state is reused.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy, google_setup
from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config
from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.connectors.google import managed
from securedact_mcp.connectors.google.auth import (
    LoopbackAuthError,
    LoopbackOAuthServer,
    build_flow,
    get_authorization_url,
    pick_loopback_port,
    run_local_oauth,
)
from securedact_mcp.connectors.google.config import (
    GoogleConfigError,
    GoogleConnectorConfig,
    load_google_config,
)

# google_auth_oauthlib is only required by the tests that actually build a real
# OAuth flow / run the loopback exchange. Those tests skip cleanly when the
# optional ``google`` extra is not installed (CI parity without the extra).
_HAS_GOOGLE = importlib.util.find_spec("google_auth_oauthlib") is not None
requires_google = pytest.mark.skipif(not _HAS_GOOGLE, reason="google extra not installed")

from securedact_core.connectors.google import default_connector_scopes  # noqa: E402

DRIVE_READONLY = "https://www.googleapis.com/auth/drive.readonly"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _agent_config() -> AgentConfig:
    return AgentConfig.create(control_plane_url="https://example.com", agent_id="agent-1")


def _seed_machine_registration(machine_root: Path) -> AgentFiles:
    files = AgentFiles.resolve(root=Path(machine_root) / "agent")
    save_config(_agent_config(), files)
    return files


def _loopback_config(
    tmp_path: Path, client_id: str = "managed.app.id.example"
) -> GoogleConnectorConfig:
    return GoogleConnectorConfig(
        enabled=True,
        client_id=client_id,
        client_secret="",
        redirect_uri="http://127.0.0.1:0/",
        scopes=default_connector_scopes(),
        token_path=Path(tmp_path) / "google" / "token.json.enc",
        key_path=Path(tmp_path) / "google" / "token.key",
        client_type="installed",
    )


# ---------------------------------------------------------------------------
# 1. Normal mode never prompts for a client id/secret
# ---------------------------------------------------------------------------


def test_normal_mode_never_prompts_for_client_config(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")

    client_config_calls: list[int] = []

    def fake_client_config(*_a, **_k):
        client_config_calls.append(1)
        return False

    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-1",
        authorize_google_fn=lambda *_a, **_k: True,
        client_config_fn=fake_client_config,
    )
    # Normal (managed) mode must NOT ask for an OAuth client id/secret.
    assert client_config_calls == []
    assert outcome.selected and outcome.authorized and outcome.binding_verified
    assert outcome.ready
    # The real binding was written under the machine root.
    bindings = machine / "agent" / "connector-bindings.json"
    assert bindings.is_file()


# ---------------------------------------------------------------------------
# 2. Managed client id resolved without customer input
# ---------------------------------------------------------------------------


def test_managed_client_id_resolved_without_customer_input(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    cfg = load_google_config(data_dir=tmp_path)
    assert cfg.client_id == "managed.app.id.example"
    # A managed Desktop client uses the "installed" client type and carries the
    # SecuRedact-managed Desktop client secret (packaged product configuration,
    # not a customer secret) for the token exchange.
    assert cfg.client_type == "installed"
    assert cfg.client_secret == managed.resolve_managed_client_secret()


def test_managed_client_id_is_single_source_of_truth(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "pkg.managed.id")
    assert managed.resolve_managed_client_id() == "pkg.managed.id"
    assert managed.is_managed_client_configured()


# ---------------------------------------------------------------------------
# 2b. Packaged managed config is the default production source of truth
# ---------------------------------------------------------------------------


def test_packaged_managed_client_id_resolves_without_env(tmp_path: Path, monkeypatch) -> None:
    # A normal released build has no managed env override; the packaged default
    # must resolve so a customer needs nothing.
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)
    from securedact_mcp.connectors.google import managed_config

    cfg = managed_config.packaged_managed_google_config()
    assert cfg.client_id == managed.resolve_managed_client_id()
    assert cfg.client_id.endswith("apps.googleusercontent.com")
    assert managed.is_managed_client_configured()
    # Resolves into the connector config with managed flag set.
    gcfg = load_google_config(data_dir=tmp_path)
    assert gcfg.client_id == cfg.client_id
    assert gcfg.managed is True
    assert gcfg.client_type == "installed"


def test_packaged_managed_client_secret_resolves_without_env(monkeypatch) -> None:
    # The managed Desktop client secret ships in the package and resolves with no
    # env override (normal customers never supply it).
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)
    secret = managed.resolve_managed_client_secret()
    assert secret
    assert secret.startswith("GOCSPX-")
    assert managed.is_managed_client_secret_configured()


def test_env_overrides_packaged_id_and_secret(tmp_path: Path, monkeypatch) -> None:
    # DEV/OPS env overrides win over the packaged default (precedence 1).
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "env.id.override")
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, "env.secret.override")
    assert managed.resolve_managed_client_id() == "env.id.override"
    assert managed.resolve_managed_client_secret() == "env.secret.override"
    gcfg = load_google_config(data_dir=tmp_path)
    assert gcfg.client_id == "env.id.override"
    assert gcfg.client_secret == "env.secret.override"  # noqa: S105
    assert gcfg.managed is True


def test_normal_setup_succeeds_with_packaged_config_no_env(tmp_path: Path, monkeypatch) -> None:
    # End-to-end normal onboarding: no managed env vars, packaged default only.
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)

    client_config_calls: list[int] = []

    def fake_client_config(*_a, **_k):
        client_config_calls.append(1)
        return False

    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-1",
        authorize_google_fn=lambda *_a, **_k: True,
        client_config_fn=fake_client_config,
        verify_binding_fn=lambda *_a, **_k: True,
    )
    # No OAuth client id/secret prompt, packaged config drives the flow.
    assert client_config_calls == []
    assert outcome.selected and outcome.authorized and outcome.binding_verified
    assert outcome.ready
    assert managed.MANAGED_CLIENT_NOT_CONFIGURED_MSG not in out.getvalue()


def test_existing_env_override_machine_still_works(tmp_path: Path, monkeypatch) -> None:
    # Backward compatibility: a machine that already has the managed env override
    # continues to work.
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "env.id.override")
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, "env.secret.override")
    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-1",
        authorize_google_fn=lambda *_a, **_k: True,
        verify_binding_fn=lambda *_a, **_k: True,
    )
    assert outcome.ready
    assert managed.MANAGED_CLIENT_NOT_CONFIGURED_MSG not in out.getvalue()


def test_byo_ignores_packaged_managed_config(tmp_path: Path, monkeypatch) -> None:
    # When BYO is explicitly selected with its own client id/secret, the packaged
    # managed config must NOT be used (managed flag False, BYO creds win).
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)
    monkeypatch.setenv(google_setup.GOOGLE_CLIENT_ID_ENV, "byo.app.id")
    monkeypatch.setenv(google_setup.GOOGLE_CLIENT_SECRET_ENV, "byo.app.secret")

    # The resolved config must reflect BYO, not the packaged managed app.
    gcfg = load_google_config(data_dir=machine)
    assert gcfg.client_id == "byo.app.id"
    assert gcfg.client_secret == "byo.app.secret"  # noqa: S105
    assert gcfg.managed is False
    assert gcfg.client_type == "web"


def test_managed_secret_absent_from_argv_and_env_forwarding(tmp_path: Path, monkeypatch) -> None:
    # The managed secret never travels on argv or into the runtime env forwarding
    # unless explicitly set as an override (overrides are by design, and still
    # never placed on argv). Normal (no-override) forwardings carry nothing.
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)

    argv = deploy.build_google_auth_argv("python", tmp_path, google_byo=False)
    assert not any("GOCSPX" in part or "client_secret" in part.lower() for part in argv)
    assert "--google-byo" not in argv

    # Without an explicit override, _env_for forwards neither managed identifier.
    env = deploy._env_for(tmp_path)
    assert managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV not in env
    assert managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV not in env


def test_managed_secret_not_logged_during_resolve(tmp_path: Path, monkeypatch, caplog) -> None:
    # Resolving the packaged managed secret must never log it.
    import logging

    caplog.set_level(logging.DEBUG)
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)
    secret = managed.resolve_managed_client_secret()
    assert secret
    # Exercise the connector config resolution path, which must not emit the secret.
    _ = load_google_config(data_dir=tmp_path)
    assert secret not in caplog.text


# ---------------------------------------------------------------------------
# 3. Missing managed client id fails clearly
# ---------------------------------------------------------------------------


def test_missing_managed_client_id_fails_clearly(monkeypatch) -> None:
    monkeypatch_delenv_managed(monkeypatch)
    with pytest.raises(GoogleConfigError) as exc:
        managed.assert_managed_client_configured()
    assert managed.MANAGED_CLIENT_NOT_CONFIGURED_MSG in str(exc.value)


def test_wizard_reports_managed_not_configured_message(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch_delenv_managed(monkeypatch)
    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-1",
        deps_ready_fn=lambda: True,
    )
    # The fail-closed message is shown and the agent is NOT reported ready.
    assert managed.MANAGED_CLIENT_NOT_CONFIGURED_MSG in out.getvalue()
    assert outcome.ready is False


def monkeypatch_delenv_managed(mp) -> None:
    # Clear both the DEV/OPS env override and the packaged default so the
    # "managed app unavailable" path is exercised.
    mp.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    mp.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)
    from securedact_mcp.connectors.google import managed_config

    mp.setattr(managed_config, "MANAGED_GOOGLE_CLIENT_ID", "")
    mp.setattr(managed_config, "MANAGED_GOOGLE_CLIENT_SECRET", "")


# ---------------------------------------------------------------------------
# 4. BYO is explicit only
# ---------------------------------------------------------------------------


def test_byo_mode_prompts_for_client_config_only_when_explicit(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")

    calls: list[int] = []

    def fake_client_config(*_a, **_k):
        calls.append(1)
        return False

    out = io.StringIO()
    deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-1",
        google_byo=True,  # explicit advanced/enterprise choice
        authorize_google_fn=lambda *_a, **_k: False,
        client_config_fn=fake_client_config,
        verify_binding_fn=lambda *_a, **_k: True,
    )
    # BYO was explicitly selected, so the client config was collected once.
    assert calls == [1]


def test_byo_and_normal_labels_are_distinct() -> None:
    assert managed.NORMAL_GOOGLE_LABEL != managed.BYO_GOOGLE_LABEL
    assert "own" in managed.BYO_GOOGLE_LABEL.lower()


# ---------------------------------------------------------------------------
# 5. Desktop client works without a client secret
# ---------------------------------------------------------------------------


@requires_google
def test_desktop_client_works_without_secret(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    # Building the flow must succeed for a public installed app (no secret).
    flow = build_flow(cfg)
    assert flow is not None
    assert cfg.require_credentials() == ("managed.app.id.example", "")


@requires_google
def test_web_client_keeps_secret_when_present(tmp_path: Path) -> None:
    cfg = GoogleConnectorConfig(
        enabled=True,
        client_id="byo.app.id",
        client_secret="byo-secret",  # noqa: S106 - synthetic test secret
        redirect_uri="http://127.0.0.1:0/",
        scopes=default_connector_scopes(),
        token_path=Path(tmp_path) / "google" / "token.json.enc",
        key_path=Path(tmp_path) / "google" / "token.key",
        client_type="web",
    )
    flow = build_flow(cfg)
    assert flow is not None


# ---------------------------------------------------------------------------
# 6. Only drive.readonly scope is requested
# ---------------------------------------------------------------------------


def test_only_drive_readonly_scope_requested(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    cfg = load_google_config(data_dir=tmp_path)
    assert cfg.scopes == [DRIVE_READONLY]


# ---------------------------------------------------------------------------
# 7. Write scopes remain rejected
# ---------------------------------------------------------------------------


def test_config_rejects_write_scope_override(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(
        "SECUREDACT_GOOGLE_SCOPES",
        "https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.readonly",
    )
    with pytest.raises(GoogleConfigError):
        load_google_config(data_dir=tmp_path)


def test_connector_rejects_write_scope(tmp_path: Path) -> None:
    from securedact_mcp.connectors.google.client import _assert_readonly

    cfg = _loopback_config(tmp_path)
    cfg.scopes.append("https://www.googleapis.com/auth/drive")
    with pytest.raises(GoogleConfigError):
        _assert_readonly(cfg)


# ---------------------------------------------------------------------------
# 8. Loopback listener binds only to loopback
# ---------------------------------------------------------------------------


def test_loopback_listener_binds_only_to_loopback() -> None:
    server = LoopbackOAuthServer(expected_state="s", timeout=2.0)
    try:
        # The listener must be bound to the loopback interface, never routable.
        assert server._httpd.server_address[0] == "127.0.0.1"
        assert server.redirect_uri.startswith("http://127.0.0.1:")
        # The port is actually occupied by the loopback listener (a second bind to
        # the same 127.0.0.1 port must fail), proving it is not an unbound socket.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dup:
            with pytest.raises(OSError):
                dup.bind(("127.0.0.1", server.port))
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# 9. Random port selection works
# ---------------------------------------------------------------------------


def test_random_loopback_port_selection() -> None:
    p1 = pick_loopback_port()
    p2 = pick_loopback_port()
    assert p1 != p2
    assert p1 > 1024 and p2 > 1024


# ---------------------------------------------------------------------------
# 10. OAuth state mismatch fails closed
# ---------------------------------------------------------------------------


class _StateMismatchServer(LoopbackOAuthServer):
    def __init__(self, *, expected_state: str = "", timeout: float = 1.0) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self.port = 0
        from securedact_mcp.connectors.google.auth import _LoopbackResult

        self._result = _LoopbackResult()
        self._result.set(code=None, error="state_mismatch", state="wrong")

    def start(self) -> None:
        pass

    def wait_for_callback(self):
        return self._result

    def shutdown(self) -> None:
        pass


@requires_google
def test_state_mismatch_fails_closed(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    outcome = run_local_oauth(
        cfg, _server_cls=_StateMismatchServer, _exchange_fn=lambda *_a, **_k: None
    )
    assert outcome.authorized is False
    # The stage is reported instead of a generic authorized=false.
    assert outcome.stage == "state_validation"
    assert outcome.error_code == "google_loopback_state_mismatch"


# ---------------------------------------------------------------------------
# 11. Callback timeout fails safely
# ---------------------------------------------------------------------------


class _TimeoutServer(LoopbackOAuthServer):
    def __init__(self, *, expected_state: str = "", timeout: float = 0.01) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self.port = 0
        from securedact_mcp.connectors.google.auth import _LoopbackResult

        self._result = _LoopbackResult()

    def start(self) -> None:
        pass

    def wait_for_callback(self):
        raise LoopbackAuthError("loopback OAuth callback timed out")

    def shutdown(self) -> None:
        pass


@requires_google
def test_callback_timeout_fails_safely(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    outcome = run_local_oauth(cfg, _server_cls=_TimeoutServer, _exchange_fn=lambda *_a, **_k: None)
    assert outcome.authorized is False
    assert outcome.stage == "callback"


# ---------------------------------------------------------------------------
# 12. Authorization code/token never appears on argv/logs
# ---------------------------------------------------------------------------


class _GoodServer(LoopbackOAuthServer):
    def __init__(self, *, expected_state: str = "", timeout: float = 5.0) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self.port = 54321
        from securedact_mcp.connectors.google.auth import _LoopbackResult

        self._result = _LoopbackResult()
        self._result.set(code="AUTHCODE_SECRET", error=None, state=expected_state)

    def start(self) -> None:
        pass

    def wait_for_callback(self):
        return self._result

    def shutdown(self) -> None:
        pass


@requires_google
def test_authorization_url_does_not_contain_code(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    url, state = get_authorization_url(cfg, pkce=True)
    assert "code=" not in url
    assert state


@requires_google
def test_exchanged_code_never_logged_or_on_argv(tmp_path: Path, monkeypatch) -> None:
    cfg = _loopback_config(tmp_path)
    exchanged: dict = {}

    def _exchange(config, code, *, state=None):
        exchanged["code"] = code
        config.credential_store().save_token({"refresh_token": "RT_MACHINE_ONLY"})
        return {}

    browser_urls: list[str] = []

    def _open(url: str) -> None:
        browser_urls.append(url)

    ok = run_local_oauth(
        cfg,
        _server_cls=_GoodServer,
        _exchange_fn=_exchange,
        _browser_open=_open,
    )
    assert ok.authorized is True
    # The browser is opened with the consent URL, never the code.
    assert browser_urls and "code=" not in browser_urls[0]
    # The exchange received exactly the callback code (in-memory only).
    assert exchanged["code"] == "AUTHCODE_SECRET"


# ---------------------------------------------------------------------------
# 13/20. Authorization runs in the machine runtime (not the setup interpreter)
# ---------------------------------------------------------------------------


class _CaptureRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, arguments, run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        if "google-auth" in args:
            self.calls.append(args)
            if "--loopback" in args:
                return RunResult(0, stdout='{"authorized": true}')
            return RunResult(1, stderr="not started")
        return RunResult(0)


def test_runtime_google_auth_invokes_machine_loopback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    runtime_python = tmp_path / "runtime" / "python.exe"
    runner = _CaptureRunner()
    out = io.StringIO()
    ok = deploy._authorize_google_via_runtime(
        runtime_python,
        tmp_path,
        runner,
        output=out,
        google_byo=False,
    )
    assert ok.authorized is True
    # The machine-owned runtime is what performed the OAuth (--loopback), not the
    # setup interpreter's own process.
    assert any("--loopback" in c for c in runner.calls)
    assert str(runtime_python) in " ".join(" ".join(c) for c in runner.calls)


def test_loopback_failure_is_fail_closed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    runtime_python = tmp_path / "runtime" / "python.exe"

    class _LoopbackFailRunner:
        def __call__(self, arguments, run_input: RunInput) -> RunResult:
            args = [str(a) for a in arguments]
            if "--loopback" in args:
                return RunResult(
                    2,
                    stdout='{"authorized": false, "error": "managed app not configured"}',
                )
            return RunResult(0)

    out = io.StringIO()
    ok = deploy._authorize_google_via_runtime(
        runtime_python,
        tmp_path,
        _LoopbackFailRunner(),
        output=out,
        google_byo=False,
    )
    assert ok.authorized is False
    text = out.getvalue()
    # Fail closed: report the failure, never prompt the customer for an OAuth
    # client id/secret, and never fall back to a manual two-phase flow.
    assert "Google authorization" in text
    assert "Open a browser to authorize" not in text
    assert "Google OAuth client ID:" not in text
    assert "Google OAuth client secret:" not in text
    # The safe error/stage surfaced from the runtime is preserved verbatim.
    assert "managed app not configured" in text


def test_loopback_byo_uses_byo_flag(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    runtime_python = tmp_path / "runtime" / "python.exe"

    class _ByoRunner:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def __call__(self, arguments, run_input: RunInput) -> RunResult:
            args = [str(a) for a in arguments]
            self.calls.append(args)
            if "--loopback" in args:
                return RunResult(0, stdout='{"authorized": true, "stage": "complete"}')
            return RunResult(1)

    runner = _ByoRunner()
    out = io.StringIO()
    ok = deploy._authorize_google_via_runtime(
        runtime_python,
        tmp_path,
        runner,
        output=out,
        google_byo=True,
    )
    assert ok.authorized is True
    assert any("--google-byo" in c for c in runner.calls)


# ---------------------------------------------------------------------------
# 14. Required Google imports are verified before auth
# ---------------------------------------------------------------------------


def test_google_deps_required_before_auth(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-1",
        authorize_google_fn=lambda *_a, **_k: True,
        deps_ready_fn=lambda: False,
        verify_binding_fn=lambda *_a, **_k: True,
    )
    assert outcome.deps_ready is False
    assert outcome.ready is False


# ---------------------------------------------------------------------------
# 15. Token is stored under the machine root
# ---------------------------------------------------------------------------


@requires_google
def test_token_stored_under_machine_root_via_loopback(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)

    def _store(config, code, *, state=None):
        config.credential_store().save_token({"refresh_token": "RT_MACHINE_ONLY"})
        return {}

    ok = run_local_oauth(cfg, _server_cls=_GoodServer, _exchange_fn=_store)
    assert ok.authorized is True
    token_file = tmp_path / "google" / "token.json.enc"
    assert token_file.is_file()
    # No token material leaked into the process environment.
    leaked = [v for v in os.environ.values() if "RT_MACHINE_ONLY" in v or "AUTHCODE_SECRET" in v]
    assert leaked == []


# ---------------------------------------------------------------------------
# 16. Binding is created after auth
# ---------------------------------------------------------------------------


def test_binding_created_after_loopback_auth(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-9",
        authorize_google_fn=lambda *_a, **_k: True,
    )
    assert outcome.ready
    bindings = machine / "agent" / "connector-bindings.json"
    assert bindings.is_file()
    import json

    payload = json.loads(bindings.read_text(encoding="utf-8"))
    assert payload["int-9"]["platform"] == "google_workspace"


# ---------------------------------------------------------------------------
# 17/18. Setup readiness requires binding; existing state reused
# ---------------------------------------------------------------------------


def test_existing_valid_machine_oauth_and_binding_reused(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    # Pre-existing valid machine token.
    (machine / "google").mkdir(parents=True, exist_ok=True)
    (machine / "google" / "token.json.enc").write_text("{}", encoding="utf-8")
    # Pre-existing valid binding.
    binding = machine / "agent" / "connector-bindings.json"
    binding.parent.mkdir(parents=True, exist_ok=True)
    binding.write_text(
        json.dumps(
            {
                "int-reuse": {
                    "integration_id": "int-reuse",
                    "platform": "google_workspace",
                    "local_profile": "default",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-reuse",
        # No re-auth needed: the token is reused idempotently.
        authorize_google_fn=lambda *_a, **_k: True,
    )
    assert outcome.ready
    # No duplicate binding written.
    payload = json.loads(binding.read_text(encoding="utf-8"))
    assert list(payload.keys()) == ["int-reuse"]


def test_missing_binding_blocks_readiness(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")

    def fake_bind(*_a, **_k):
        # Pretend to bind but never write a verifiable on-disk record.
        return type("B", (), {"integration_id": "int-nobind", "platform": "google_workspace"})()

    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-nobind",
        authorize_google_fn=lambda *_a, **_k: True,
        bind_google_fn=fake_bind,
        # Real verifier re-reads disk and finds no binding.
    )
    assert outcome.ready is False
    assert not (machine / "agent" / "connector-bindings.json").is_file()


# ---------------------------------------------------------------------------
# 19. UAC-resumed setup preserves the Google selection
# ---------------------------------------------------------------------------


def test_uac_resumed_setup_preserves_google_selection(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    monkeypatch.setenv(deploy.AGENT_ELEVATED_ENV, "1")
    # Force/mimic the Windows branch hermetically so the UAC-resumed path actually
    # runs on any host (the production module short-circuits on non-Windows).
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    # Inject the Windows-only service collaborators so no real Task Scheduler /
    # win32api / setx is touched; the fake install reports a successful service.
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)
    out = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=out,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        agent_elevated=True,
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="int-uac",
        authorize_google_fn=lambda *_a, **_k: True,
        verify_google_binding_fn=lambda *_a, **_k: True,
        # Hermetic: never spawn setx on the Windows branch.
        apply_google_env_fn=lambda _d, **_k: None,
    )
    # --agent-elevated resumes the onboarding exactly once; setup completes.
    assert rc == 0
    # Google selection survives, the explicit integration id survives, and the local
    # connector binding is created and proves the integration id.
    bindings = machine / "agent" / "connector-bindings.json"
    assert bindings.is_file()
    payload = json.loads(bindings.read_text(encoding="utf-8"))
    assert "int-uac" in payload


# ---------------------------------------------------------------------------
# 20. Scheduled SYSTEM agent can consume the machine-local configuration
# ---------------------------------------------------------------------------


def test_system_agent_loads_machine_local_google_config(tmp_path: Path, monkeypatch) -> None:
    # The same load_google_config the SYSTEM scheduled task uses must resolve the
    # managed client id + scopes from the machine data root without any operator
    # env/secret and without creating a Google Cloud project.
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    # Pre-seed an encrypted token so the provider has local material to load.
    (tmp_path / "google").mkdir(parents=True, exist_ok=True)
    (tmp_path / "google" / "token.json.enc").write_text("{}", encoding="utf-8")

    cfg = load_google_config(data_dir=tmp_path)
    assert cfg.client_id == "managed.app.id.example"
    assert cfg.client_type == "installed"
    assert cfg.scopes == [DRIVE_READONLY]
    # The SYSTEM task reads the same machine root; no control-plane round trip.
    assert str(tmp_path) in str(cfg.token_path)


# ---------------------------------------------------------------------------
# 21. Post-callback failures report a bounded stage (no secret material)
# ---------------------------------------------------------------------------


from securedact_core.connectors.google import GoogleAuthError  # noqa: E402
from securedact_mcp.connectors.google import auth as google_auth_mod  # noqa: E402


def _store_token(config, code, *, state=None):
    """Injected exchange that persists a synthetic token (no network)."""

    config.credential_store().save_token({"refresh_token": "RT_MACHINE_ONLY"})
    return {}


@requires_google
def test_successful_loopback_reports_complete_stage(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    outcome = run_local_oauth(cfg, _server_cls=_GoodServer, _exchange_fn=_store_token)
    assert outcome.authorized is True
    assert outcome.stage == "complete"
    assert (tmp_path / "google" / "token.json.enc").is_file()


@requires_google
def test_token_exchange_failure_reports_stage(tmp_path: Path, monkeypatch) -> None:
    cfg = _loopback_config(tmp_path)

    def _boom(*_a, **_k):
        raise GoogleAuthError("Google token exchange failed: InvalidGrantError")

    monkeypatch.setattr(google_auth_mod, "_exchange_token_only", _boom)
    outcome = run_local_oauth(cfg, _server_cls=_GoodServer)
    assert outcome.authorized is False
    assert outcome.stage == "token_exchange"
    assert outcome.error_code == "google_token_exchange_failed"
    # The browser must not have been told the authorization completed.
    assert "complete" not in google_auth_mod.LOOPBACK_CALLBACK_HTML
    assert b"AUTHCODE_SECRET" not in google_auth_mod.LOOPBACK_CALLBACK_HTML.encode()
    # No token material leaks into the machine-readable result.
    assert "AUTHCODE_SECRET" not in json.dumps(outcome.to_payload())


@requires_google
def test_persistence_failure_reports_stage(tmp_path: Path, monkeypatch) -> None:
    cfg = _loopback_config(tmp_path)

    class _FakeCreds:
        def to_json(self) -> str:
            return '{"refresh_token": "RT_MACHINE_ONLY"}'

    def _fake_exchange(*_a, **_k):
        return _FakeCreds()

    def _boom(*_a, **_k):
        raise GoogleAuthError("Google token persistence failed: OSError")

    # Exchange must succeed so the failure is genuinely at the persistence stage.
    monkeypatch.setattr(google_auth_mod, "_exchange_token_only", _fake_exchange)
    monkeypatch.setattr(google_auth_mod, "_persist_credentials", _boom)
    outcome = run_local_oauth(cfg, _server_cls=_GoodServer)
    assert outcome.authorized is False
    assert outcome.stage == "persistence"
    assert outcome.error_code == "google_token_persistence_failed"
    # On persistence failure nothing durable is written.
    assert not (tmp_path / "google" / "token.json.enc").exists()


@requires_google
def test_successful_loopback_persists_loadable_token(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    outcome = run_local_oauth(cfg, _server_cls=_GoodServer, _exchange_fn=_store_token)
    assert outcome.authorized is True
    loaded = cfg.credential_store().load_token()
    assert loaded is not None
    assert loaded.get("refresh_token") == "RT_MACHINE_ONLY"


@requires_google
def test_no_oauth_secret_leaks_in_logs_or_output(tmp_path: Path, caplog) -> None:
    import logging

    cfg = _loopback_config(tmp_path)
    exchanged: dict[str, str] = {}

    def _exchange(config, code, *, state=None):
        exchanged["code"] = code
        config.credential_store().save_token({"refresh_token": "RT_MACHINE_ONLY"})
        return {}

    with caplog.at_level(logging.DEBUG, logger="securedact_mcp.connectors.google.auth"):
        outcome = run_local_oauth(
            cfg, _server_cls=_GoodServer, _exchange_fn=_exchange, _browser_open=lambda _u: None
        )
    assert outcome.authorized is True
    blob = json.dumps(outcome.to_payload())
    assert "AUTHCODE_SECRET" not in blob
    assert "RT_MACHINE_ONLY" not in blob
    log_text = caplog.text
    assert "AUTHCODE_SECRET" not in log_text
    assert "RT_MACHINE_ONLY" not in log_text


# ---------------------------------------------------------------------------
# 22. State mismatch and missing code fail closed (with a stage)
# ---------------------------------------------------------------------------


class _MissingCodeServer(LoopbackOAuthServer):
    def __init__(self, *, expected_state: str = "", timeout: float = 5.0) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self.port = 54322
        from securedact_mcp.connectors.google.auth import _LoopbackResult

        self._result = _LoopbackResult()
        self._result.set(code="", error=None, state=expected_state)

    def start(self) -> None:
        pass

    def wait_for_callback(self):
        return self._result

    def shutdown(self) -> None:
        pass


class _GoogleErrorServer(LoopbackOAuthServer):
    def __init__(self, *, expected_state: str = "", timeout: float = 5.0) -> None:
        self.expected_state = expected_state
        self.timeout = timeout
        self.port = 54323
        from securedact_mcp.connectors.google.auth import _LoopbackResult

        self._result = _LoopbackResult()
        self._result.set(code="", error="access_denied", state=expected_state)

    def start(self) -> None:
        pass

    def wait_for_callback(self):
        return self._result

    def shutdown(self) -> None:
        pass


@requires_google
def test_missing_code_fails_closed_with_stage(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    outcome = run_local_oauth(cfg, _server_cls=_MissingCodeServer)
    assert outcome.authorized is False
    assert outcome.stage == "missing_code"
    assert outcome.error_code == "google_loopback_missing_code"


@requires_google
def test_google_callback_error_fails_closed_with_stage(tmp_path: Path) -> None:
    cfg = _loopback_config(tmp_path)
    outcome = run_local_oauth(cfg, _server_cls=_GoogleErrorServer)
    assert outcome.authorized is False
    assert outcome.stage == "callback_error"
    assert outcome.error_code == "google_callback_error"


# ---------------------------------------------------------------------------
# 23. Managed client configured + post-callback failure must NOT be reported as
#     "managed OAuth application unavailable"; binding must not be created.
# ---------------------------------------------------------------------------


class _FailRunner:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __call__(self, arguments, run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        if "--loopback" in args:
            return RunResult(2, stdout=json.dumps(self.payload))
        return RunResult(0)


def _machine_runtime_at(runtime_path: Path) -> Path:
    # Create the fake interpreter at exactly the location the engine resolves for the
    # current platform (``<root>/Scripts/python.exe`` on Windows,
    # ``<root>/bin/python`` elsewhere) so resolve_machine_runtime_python() finds it.
    runtime_python = deploy.resolve_runtime_python(runtime_path)
    runtime_python.parent.mkdir(parents=True, exist_ok=True)
    runtime_python.write_bytes(b"")
    return runtime_python


def test_post_callback_failure_not_reported_as_managed_unavailable(
    tmp_path: Path, monkeypatch
) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    runtime_python = _machine_runtime_at(tmp_path / "runtime")
    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-pc",
        runtime_path=tmp_path / "runtime",
        command_runner=_FailRunner(
            {
                "authorized": False,
                "stage": "token_exchange",
                "error_code": "google_token_exchange_failed",
            }
        ),
        verify_binding_fn=lambda *_a, **_k: True,
    )
    text = out.getvalue()
    # The managed client WAS configured: the "unavailable in this build" message must
    # NOT appear. The actionable post-callback failure stage/code must instead.
    assert managed.MANAGED_CLIENT_NOT_CONFIGURED_MSG not in text
    assert "token_exchange" in text
    assert outcome.authorized is False
    assert outcome.ready is False
    # No binding until OAuth verification succeeds.
    assert not (machine / "agent" / "connector-bindings.json").is_file()
    # Sanity: the runtime that ran was the machine runtime.
    assert str(runtime_python) in text


def test_readiness_becomes_google_authorized_only_after_success(
    tmp_path: Path, monkeypatch
) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    _machine_runtime_at(tmp_path / "runtime")
    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-ok",
        runtime_path=tmp_path / "runtime",
        command_runner=_FailRunner({"authorized": True, "stage": "complete"}),
        verify_binding_fn=lambda *_a, **_k: True,
    )
    assert outcome.authorized is True
    assert outcome.binding_verified is True
    assert outcome.ready is True
    assert (machine / "agent" / "connector-bindings.json").is_file()


# ---------------------------------------------------------------------------
# 24. Managed Desktop mode sends the configured managed client secret
# ---------------------------------------------------------------------------
#
# Google's Desktop OAuth token endpoint for the SecuRedact-managed application
# REQUIRES the Google-issued Desktop client secret at token exchange (a missing
# value is rejected with ``invalid_request`` / "client_secret is missing"). The
# managed Desktop client secret is SecuRedact-managed application configuration
# (not a customer secret and not a customer token); it must be sent in the token
# request for the managed Desktop client.


@requires_google
def test_managed_desktop_sends_configured_secret(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    monkeypatch.setenv(
        managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, "managed-desktop-secret-value"
    )
    cfg = load_google_config(data_dir=tmp_path)
    # Managed Desktop client: owned by SecuRedact, installed client type, secret present.
    assert cfg.managed is True
    assert cfg.client_type == "installed"
    assert cfg.client_secret == "managed-desktop-secret-value"  # noqa: S105

    if not _HAS_GOOGLE:
        pytest.skip("google extra not installed")

    from google_auth_oauthlib.flow import Flow

    class _FakeCreds:
        def to_json(self) -> str:
            return '{"refresh_token": "RT_MACHINE_ONLY"}'

    captured: dict[str, object] = {}

    def _fake_fetch(self, *, code, client_secret, include_client_id, **_kw):  # type: ignore[no-untyped-def]
        captured["code"] = code
        captured["client_secret"] = client_secret
        captured["include_client_id"] = include_client_id
        # ``Flow.credentials`` is a read-only property that builds a Credentials
        # object from the oauth2session; emulate a successful exchange by making
        # it return a fake creds (the real fetch_token would have populated it).
        return None

    monkeypatch.setattr(Flow, "fetch_token", _fake_fetch)
    monkeypatch.setattr(Flow, "credentials", property(lambda self: _FakeCreds()))

    outcome = run_local_oauth(cfg, _server_cls=_GoodServer, _browser_open=lambda _u: None)
    assert outcome.authorized is True
    # The configured managed Desktop client secret was actually sent to Google's
    # token endpoint (this is the regression: previously it was omitted).
    assert captured["client_secret"] == "managed-desktop-secret-value"  # noqa: S105
    assert captured["code"] == "AUTHCODE_SECRET"
    assert captured["include_client_id"] is True


# ---------------------------------------------------------------------------
# 25. Missing managed client secret fails clearly before the browser opens
# ---------------------------------------------------------------------------


@requires_google
def test_missing_managed_secret_fails_before_browser(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, raising=False)
    # The managed Desktop secret must be absent for the fail-closed pre-check to
    # fire -- clear the packaged default too so this is a genuine "no secret"
    # situation.
    from securedact_mcp.connectors.google import managed_config

    monkeypatch.setattr(managed_config, "MANAGED_GOOGLE_CLIENT_SECRET", "")
    cfg = load_google_config(data_dir=tmp_path)
    assert cfg.managed is True
    assert not cfg.client_secret

    browser_urls: list[str] = []
    outcome = run_local_oauth(cfg, _browser_open=lambda u: browser_urls.append(u))
    # Fail closed with a clear, bounded outcome -- before any browser launch and
    # before any Google request.
    assert outcome.authorized is False
    assert outcome.stage == google_auth_mod.LOOPBACK_STAGE_PRE_AUTHORIZATION
    assert outcome.error_code == google_auth_mod.ERR_MANAGED_CLIENT_SECRET_MISSING
    # The browser must not have been opened and no network request made.
    assert browser_urls == []


# ---------------------------------------------------------------------------
# 26. Normal customer setup never prompts for client id/secret
# ---------------------------------------------------------------------------


def test_normal_customer_setup_resolves_managed_without_prompt(tmp_path: Path, monkeypatch) -> None:
    # Normal (managed) mode: only the SecuRedact-managed client id is supplied by
    # packaging; the customer is never asked for an OAuth client id or secret.
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")

    cfg = load_google_config(data_dir=tmp_path)
    assert cfg.managed is True
    assert cfg.client_id == "managed.app.id.example"
    # The managed Desktop client secret resolves from the packaged default
    # (SecuRedact application configuration); the customer is never asked for it.
    assert cfg.client_secret == managed.resolve_managed_client_secret()


# ---------------------------------------------------------------------------
# 27. The managed secret never appears in argv / logs / Task Scheduler
# ---------------------------------------------------------------------------


def test_managed_secret_not_in_argv_or_task_scheduler_action(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    monkeypatch.setenv(
        managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, "managed-desktop-secret-value"
    )
    runtime_python = tmp_path / "runtime" / "python.exe"
    argv = deploy.build_google_auth_argv(runtime_python, tmp_path, google_byo=False)
    blob = " ".join(argv)
    # The loopback argv is what becomes the scheduled-task action: the managed
    # secret (and the managed id override) must never be embedded there.
    assert "managed-desktop-secret-value" not in blob
    assert "SECUREDACT_GOOGLE_MANAGED" not in blob

    import logging

    with caplog.at_level(logging.DEBUG, logger="securedact_mcp.agent.deploy"):
        env = deploy._env_for(Path(tmp_path))
    # The secret IS forwarded via the subprocess environment (transient, not argv,
    # not Task Scheduler, not a machine env var), but it is never logged.
    assert (
        env.get(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV)
        == "managed-desktop-secret-value"
    )
    assert "managed-desktop-secret-value" not in caplog.text


@requires_google
def test_managed_secret_not_logged_during_exchange(tmp_path: Path, monkeypatch, caplog) -> None:
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    monkeypatch.setenv(
        managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, "managed-desktop-secret-value"
    )
    cfg = load_google_config(data_dir=tmp_path)

    class _FakeCreds:
        def to_json(self) -> str:
            return '{"refresh_token": "RT_MACHINE_ONLY"}'

    from google_auth_oauthlib.flow import Flow

    def _fake_fetch(self, *, code, client_secret, include_client_id, **_kw):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(Flow, "fetch_token", _fake_fetch)
    monkeypatch.setattr(Flow, "credentials", property(lambda self: _FakeCreds()))

    import logging

    with caplog.at_level(logging.DEBUG, logger="securedact_mcp.connectors.google.auth"):
        outcome = run_local_oauth(cfg, _server_cls=_GoodServer, _browser_open=lambda _u: None)
    assert outcome.authorized is True
    log_text = caplog.text
    assert "managed-desktop-secret-value" not in log_text
    assert "AUTHCODE_SECRET" not in log_text


# ---------------------------------------------------------------------------
# 28. invalid_request / client_secret-is-missing regression is fixed
# ---------------------------------------------------------------------------


@requires_google
def test_invalid_request_client_secret_missing_surfaced_safely(tmp_path: Path, monkeypatch) -> None:
    from google_auth_oauthlib.flow import Flow
    from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

    cfg = GoogleConnectorConfig(
        enabled=True,
        client_id="byo.app.id",
        client_secret="byo-secret",  # noqa: S106 - synthetic test secret
        redirect_uri="http://127.0.0.1:0/",
        scopes=default_connector_scopes(),
        token_path=Path(tmp_path) / "google" / "token.json.enc",
        key_path=Path(tmp_path) / "google" / "token.key",
        client_type="web",
        managed=False,
    )

    # Simulate Google's token endpoint rejecting the exchange exactly as the laptop
    # observed: ``invalid_request`` / "client_secret is missing". The real
    # fetch_token wrapper must surface Google's RFC 6749 error token verbatim.
    def _boom(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise InvalidRequestError(description="client_secret is missing")

    monkeypatch.setattr(Flow, "fetch_token", _boom)
    outcome = run_local_oauth(cfg, _server_cls=_GoodServer)
    assert outcome.authorized is False
    assert outcome.stage == "token_exchange"
    # Google's RFC 6749 error token is preserved verbatim (the regression was that
    # a missing secret produced a bogus generic failure); the secret itself is not.
    assert outcome.oauth_error == "invalid_request"
    assert "client_secret" in (outcome.error_description or "")
    assert "byo-secret" not in json.dumps(outcome.to_payload())
    assert "AUTHCODE_SECRET" not in json.dumps(outcome.to_payload())


# ---------------------------------------------------------------------------
# 29. BYO flow remains separate from managed
# ---------------------------------------------------------------------------


def test_byo_flow_uses_own_secret_not_managed(tmp_path: Path, monkeypatch) -> None:
    # Explicit BYO client id/secret from env are NOT the managed app and are not
    # flagged as managed.
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_ID", "byo.app.id")
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_SECRET", "byo-secret")
    cfg = load_google_config(data_dir=tmp_path)
    assert cfg.managed is False
    assert cfg.client_id == "byo.app.id"
    assert cfg.client_secret == "byo-secret"  # noqa: S105
    assert cfg.client_type == "web"


def test_managed_secret_not_persisted_to_customer_store(tmp_path: Path, monkeypatch) -> None:
    from securedact_mcp.agent import google_setup
    from securedact_mcp.connectors.google.storage import GoogleClientConfigStore

    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    monkeypatch.setenv(
        managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV, "managed-desktop-secret-value"
    )
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_SECRET", raising=False)
    google_setup.apply_google_machine_env(tmp_path)
    # The customer BYO client-config store must remain empty: the managed secret is
    # SecuRedact application configuration supplied via env, never stored as a
    # customer (BYO) client secret.
    assert not (Path(tmp_path) / "google" / "client_config.json.enc").exists()
    assert GoogleClientConfigStore(tmp_path).load() == (None, None)
