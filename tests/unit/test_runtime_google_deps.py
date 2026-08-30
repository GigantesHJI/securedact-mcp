# SPDX-License-Identifier: Apache-2.0
"""Clean-runtime regression tests for Google onboarding dependencies (RC finding 1/2).

These prove the *machine-owned* runtime install path carries every Google
dependency the OAuth flow and Drive scan need, and that a missing runtime
dependency is treated as an INSTALLATION/readiness failure (never papered over by
asking the customer for OAuth credentials). They also pin the production OAuth
architecture: the default onboarding uses the SecuRedact-managed app, while
bring-your-own (BYO) Google Cloud OAuth is an explicit advanced/enterprise option.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy
from securedact_mcp.agent.deploy import GOOGLE_RUNTIME_IMPORTS, RunResult
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.agent.google_setup import GOOGLE_BYO_ENV, inspect_google_machine
from securedact_mcp.connectors.google.config import (
    GOOGLE_MANAGED_CLIENT_ID_ENV,
    load_google_config,
)
from tests.unit.test_agent_deploy import FakeRunner, safe_provider


@pytest.fixture(autouse=True)
def _elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    # Provisioning/upgrade require elevation; simulate it for happy paths.
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)


# ---------------------------------------------------------------------------
# Required Google dependencies (the exact set the OAuth flow imports)
# ---------------------------------------------------------------------------
REQUIRED_GOOGLE_RUNTIME_IMPORTS = (
    "google.auth",
    "google.oauth2.credentials",
    "google_auth_oauthlib.flow",
    "requests",
)


def test_google_runtime_import_probe_covers_required_modules() -> None:
    # The post-install readiness probe must assert exactly the modules the OAuth
    # flow and Drive scan import from the machine runtime. A regression that drops
    # one (e.g. google_auth_oauthlib) must fail this.
    assert set(REQUIRED_GOOGLE_RUNTIME_IMPORTS).issubset(set(GOOGLE_RUNTIME_IMPORTS))


def test_google_extra_install_target_pins_google_extra(monkeypatch) -> None:
    # Provisioning must install the SAME pinned version's Google extra into the
    # machine runtime -- never a bare ``securedact-mcp`` without the extra.
    import securedact_mcp

    monkeypatch.setattr(securedact_mcp, "__version__", "0.4.2")
    assert deploy._google_extra_install_target() == "securedact-mcp[google]==0.4.2"


def test_provision_installs_google_extra_when_enabled(tmp_path: Path) -> None:
    # Regression: selecting Google must cause the machine runtime to receive the
    # Google extra (google-auth, google-auth-oauthlib, requests).
    runtime = tmp_path / "runtime"
    runner = FakeRunner()
    deploy.provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        google_enabled=True,
    )
    pip_calls = [
        " ".join(str(a) for a in c[0])
        for c in runner.calls
        if "pip" in [str(a).lower() for a in c[0]]
    ]
    assert pip_calls
    assert any("securedact-mcp[google]==" in c for c in pip_calls)


def test_provision_google_fails_closed_when_imports_missing(tmp_path: Path) -> None:
    # If the Google extra installed but the import probe still fails, provisioning
    # must refuse (fail closed), not hand a broken runtime to the agent.

    class GooglelessRuntimeRunner(FakeRunner):
        def __call__(self, arguments, run_input):  # type: ignore[override]
            args = list(arguments)
            probe = "import " + ", ".join(deploy.GOOGLE_RUNTIME_IMPORTS)
            if len(args) >= 3 and args[1] == "-c" and args[2] == probe:
                return RunResult(1, stderr="ModuleNotFoundError: No module named 'google.auth'")
            return super().__call__(arguments, run_input)

    runtime = tmp_path / "runtime"
    with pytest.raises(AgentError) as exc:
        deploy.provision_machine_runtime(
            runtime_path=runtime,
            acl_provider=safe_provider,
            command_runner=GooglelessRuntimeRunner(),
            google_enabled=True,
        )
    assert "Google connector dependencies failed to import" in str(exc.value)


# ---------------------------------------------------------------------------
# Authorization runs INSIDE the machine-owned runtime (Finding 1 fix)
# ---------------------------------------------------------------------------


class RuntimeGoogleAuthRunner(FakeRunner):
    """Simulate the machine runtime executing ``runtime_bootstrap google-auth --loopback``.

    The import-probe (deps readiness) succeeds, and the loopback flow returns an
    ``authorized`` result. On success it also echoes a consent URL + code (as the
    real runtime would after completing the local redirect); on failure it reports
    ``authorized: false`` with an error.
    """

    def __init__(self, *, authorize_succeeds: bool = True) -> None:
        super().__init__()
        self.authorize_succeeds = authorize_succeeds
        self.loopback_seen = False

    def __call__(self, arguments, run_input):  # type: ignore[override]
        args = list(arguments)
        probe = "import " + ", ".join(deploy.GOOGLE_RUNTIME_IMPORTS)
        if len(args) >= 3 and args[1] == "-c" and args[2] == probe:
            return RunResult(0, stdout="")
        if "google-auth" in args and "--loopback" in args:
            self.loopback_seen = True
            payload = (
                {
                    "authorized": True,
                    "url": "https://accounts.google.com/x",
                    "code": "AUTHCODE_SECRET",
                }
                if self.authorize_succeeds
                else {"authorized": False, "error": "managed app not configured"}
            )
            return RunResult(0 if self.authorize_succeeds else 2, stdout=json.dumps(payload))
        return super().__call__(arguments, run_input)


def _machine_runtime(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    return runtime


def test_google_auth_runs_inside_machine_runtime(tmp_path: Path) -> None:
    # The OAuth step must execute via the machine-owned runtime python, so a
    # missing google_auth_oauthlib in the setup CLI's interpreter cannot break it.
    runtime = _machine_runtime(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    runner = RuntimeGoogleAuthRunner()
    in_process_calls: list[object] = []

    outcome = deploy.run_google_machine_onboarding(
        data_dir=data,
        output=io.StringIO(),
        input_fn=lambda _p: "code=ABC",
        secret_input_fn=lambda _p: "x",
        runtime_path=runtime,
        command_runner=runner,
        # In-process fallback must NOT be used when a machine runtime exists.
        authorize_google_fn=lambda *_a, **_k: in_process_calls.append(1) or True,
        apply_google_env_fn=lambda _d, **_k: None,
        verify_binding_fn=lambda *_a, **_k: True,
    )
    assert outcome.deps_ready is True
    assert outcome.authorized is True
    assert runner.loopback_seen
    assert in_process_calls == []  # runtime path used, not in-process


def test_google_auth_runtime_failure_is_fail_closed(tmp_path: Path) -> None:
    # When the machine runtime cannot start authorization (e.g. managed app not
    # configured -> build_flow ImportError), do NOT fall back to prompting the
    # customer for OAuth credentials. Report it and stop.
    runtime = _machine_runtime(tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    runner = RuntimeGoogleAuthRunner(authorize_succeeds=False)
    out = io.StringIO()

    outcome = deploy.run_google_machine_onboarding(
        data_dir=data,
        output=out,
        input_fn=lambda _p: "code=ABC",
        secret_input_fn=lambda _p: "x",
        runtime_path=runtime,
        command_runner=runner,
        google_byo=False,
        apply_google_env_fn=lambda _d, **_k: None,
        verify_binding_fn=lambda *_a, **_k: True,
    )
    text = out.getvalue()
    assert outcome.authorized is False
    # No credential prompt on the default (non-BYO) path.
    assert "Google OAuth client ID:" not in text
    assert "Google OAuth client secret:" not in text
    assert "SecuRedact-managed" in text


# ---------------------------------------------------------------------------
# Managed (SecuRedact-owned) OAuth app is the default; BYO is advanced
# ---------------------------------------------------------------------------


def test_load_google_config_uses_managed_client_id(monkeypatch) -> None:
    # When the SecuRedact-managed app id is set, config resolves to it (default
    # production path) without the customer supplying anything.
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_ENABLED", raising=False)
    monkeypatch.setenv(GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    config = load_google_config(require_enabled=False, data_dir=__import__("tempfile").mkdtemp())
    assert config.client_id == "managed.app.id.example"


def test_inspect_google_machine_detects_managed_client(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.setenv(GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")
    state = inspect_google_machine(tmp_path / "machine")
    assert state.client_configured is True


def test_byo_flag_defaults_false_without_env(monkeypatch) -> None:
    monkeypatch.delenv(GOOGLE_BYO_ENV, raising=False)
    assert os_getenv_byo() is False


def os_getenv_byo() -> bool:
    # Mirror the env resolution used by run_managed_agent_module.
    import os

    return os.getenv(GOOGLE_BYO_ENV) == "1"


def test_elevation_argv_forwards_google_byo_nonsecret_only() -> None:
    params = deploy.build_elevation_argv(google="yes", google_byo=True)
    assert "--google-byo" in params
    # No secret / token material on the elevated continuation's command line.
    assert not any("srr_" in p or "sra_" in p for p in params)
    assert not any("client_secret" in p or "refresh_token" in p for p in params)
