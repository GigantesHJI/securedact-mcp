# SPDX-License-Identifier: Apache-2.0
"""RC regression: which interpreter performs the machine-local Google OAuth.

The clean-laptop retest produced a contradictory setup report::

    [Google Workspace]
    Authorizing Google locally against the machine data root...
    Could not start Google authorization: No module named 'google_auth_oauthlib'

    Managed Agent: NOT ready
      Google dependencies: available
      Machine-local Google OAuth: not authorized

Two different Pythons were being talked about:

* the readiness probe defaulted to ``C:\\ProgramData\\Securedact\\runtime`` and
  correctly reported the Google extra as available there; while
* the authorization step received ``runtime_path=None`` (neither the CLI nor the
  wizard ever supplies one), decided "there is no machine runtime", and fell back
  to an **in-process** import inside the setup CLI's own interpreter — which does
  not carry the ``[google]`` extra.

These tests pin the fix:

1. the wizard threads the runtime it actually provisioned into the onboarding;
2. the readiness probe and the authorization always use the SAME interpreter;
3. nothing calls ``google_setup.authorize_google_machine`` in-process when a
   machine runtime exists;
4. with no machine runtime on Windows the step fails closed (no in-process Google
   import, no customer OAuth credential prompt);
5. the exact loopback argv is stable AND parseable by ``runtime_bootstrap``
   (including ``--google-byo``, which the bootstrap parser used to reject);
6. a stale runtime whose bootstrap has no ``google-auth`` command can never be
   reported ready; and
7. ``agent google-verify`` proves the runtime end-to-end with no browser/token.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy, google_setup, runtime_bootstrap
from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config
from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.connectors.google import managed
from tests.unit.test_agent_deploy import FakeRunner, safe_provider

_HAS_GOOGLE = importlib.util.find_spec("google_auth_oauthlib") is not None
requires_google = pytest.mark.skipif(not _HAS_GOOGLE, reason="google extra not installed")

DEPS_PROBE = "import " + ", ".join(deploy.GOOGLE_RUNTIME_IMPORTS)

# Captured before the autouse guard below replaces it, so the one test that needs
# the real in-process implementation (diagnosability) can still reach it.
_REAL_IN_PROCESS_AUTHORIZE = google_setup.authorize_google_machine


@pytest.fixture(autouse=True)
def _windows_and_elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    # The managed agent path is Windows-only; pin the Windows branch hermetically
    # so the runtime interpreter is ``<runtime>/Scripts/python.exe`` on every host.
    # Inject ``resolve_installing_user`` so the Windows-only ``win32api`` import is
    # never triggered on non-Windows CI (pure provisioning stays pywin32-free).
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    monkeypatch.setattr(
        deploy, "resolve_installing_user", lambda installing_user=None: installing_user or "alice"
    )


@pytest.fixture(autouse=True)
def _managed_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, "managed.app.id.example")


@pytest.fixture(autouse=True)
def _never_in_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the accidental in-process fallback loudly detectable in every test.

    ``google_setup.authorize_google_machine`` is the function that raised
    ``No module named 'google_auth_oauthlib'`` from the setup CLI's interpreter. No
    test in this module may reach it; individual tests re-enable it explicitly.
    """

    def _boom(*_a: object, **_k: object) -> bool:
        raise AssertionError(
            "in-process google_setup.authorize_google_machine was called; the "
            "machine-runtime interpreter must perform Google authorization"
        )

    monkeypatch.setattr(google_setup, "authorize_google_machine", _boom)


def _machine_runtime(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    py = deploy.resolve_runtime_python(runtime)
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text("", encoding="utf-8")
    return runtime


def _seed_machine_registration(machine_root: Path) -> AgentFiles:
    files = AgentFiles.resolve(root=Path(machine_root) / "agent")
    save_config(
        AgentConfig.create(control_plane_url="https://example.com", agent_id="agent-1"), files
    )
    return files


class RuntimeRunner:
    """Machine-runtime stand-in that records every argv it was asked to execute."""

    def __init__(
        self,
        *,
        deps_ok: bool = True,
        capability_ok: bool = True,
        authorized: bool = True,
        verified: bool = True,
    ) -> None:
        self.calls: list[list[str]] = []
        self.envs: list[dict[str, str]] = []
        self.deps_ok = deps_ok
        self.capability_ok = capability_ok
        self.authorized = authorized
        self.verified = verified

    def __call__(self, arguments, run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        self.calls.append(args)
        self.envs.append(dict(run_input.env or {}))
        if len(args) >= 3 and args[1] == "-c":
            code = args[2]
            if code == DEPS_PROBE:
                return RunResult(0 if self.deps_ok else 1, stderr="" if self.deps_ok else "no mod")
            if code == deploy.GOOGLE_AUTH_CAPABILITY_CHECK:
                return RunResult(0 if self.capability_ok else 1)
            if code == deploy.GOOGLE_RUNTIME_IMPORT_CHECK:
                return RunResult(
                    0 if self.deps_ok else 1,
                    stdout=deploy.GOOGLE_RUNTIME_OK_MARKER if self.deps_ok else "",
                )
            return RunResult(0)
        if "google-auth" in args and "--verify" in args:
            return RunResult(
                0 if self.verified else 2,
                stdout=json.dumps(
                    {
                        "verified": self.verified,
                        "interpreter": args[0],
                        "imports_ok": True,
                        "client_configured": True,
                        "loopback_bound": True,
                        "loopback_host": "127.0.0.1",
                        "loopback_port": 51234,
                        "consent_url_built": True,
                    }
                ),
            )
        if "google-auth" in args and "--loopback" in args:
            return RunResult(
                0 if self.authorized else 2,
                stdout=json.dumps(
                    {"authorized": self.authorized}
                    if self.authorized
                    else {"authorized": False, "error": "loopback did not complete"}
                ),
            )
        return RunResult(0, stdout="{}")

    def loopback_calls(self) -> list[list[str]]:
        return [c for c in self.calls if "google-auth" in c and "--verify" not in c]


# ---------------------------------------------------------------------------
# 1. The wizard threads the runtime it actually provisioned into the onboarding
# ---------------------------------------------------------------------------


def test_setup_authorizes_google_in_the_provisioned_machine_runtime(
    tmp_path: Path, monkeypatch
) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    runtime = _machine_runtime(tmp_path)
    runtime_python = deploy.resolve_runtime_python(runtime)

    # Production install now reports the runtime it provisioned; the wizard must use
    # THAT interpreter for Google authorization instead of dropping to in-process.
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **_k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
            "runtime_path": str(runtime),
            "runtime_python": str(runtime_python),
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **_k: True)

    runner = RuntimeRunner()
    out = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=out,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="int-rc1",
        command_runner=runner,
        apply_google_env_fn=lambda _d, **_k: None,
    )
    text = out.getvalue()
    assert rc == 0, text
    # The RC symptom must be gone.
    assert "No module named" not in text
    assert "NOT ready" not in text
    # Authorization ran in the machine-owned runtime interpreter.
    loopback = runner.loopback_calls()
    assert loopback, text
    assert loopback[0][0] == str(runtime_python)
    assert f"Google authorization interpreter: {runtime_python}" in text
    # ...and the machine-local binding really exists.
    assert (machine / "agent" / "connector-bindings.json").is_file()


def test_install_service_from_runtime_reports_the_provisioned_runtime(
    tmp_path: Path, monkeypatch
) -> None:
    # The wizard can only thread the runtime through if the install step reports it.
    runtime = _machine_runtime(tmp_path)
    monkeypatch.setattr(
        deploy.service,
        "install_service",
        lambda **_k: {"installed": True, "service_name": "SecuredactAgent", "agent_id": "agent-1"},
    )
    result = deploy.install_service_from_runtime(
        data_dir=tmp_path / "data",
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=FakeRunner(),
    )
    assert result["runtime_path"] == str(runtime)
    assert result["runtime_python"] == str(deploy.resolve_runtime_python(runtime))


# ---------------------------------------------------------------------------
# 2. The readiness probe and the authorization use ONE interpreter
# ---------------------------------------------------------------------------


def test_probe_and_authorization_use_the_same_interpreter(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    runtime = _machine_runtime(tmp_path)
    runtime_python = deploy.resolve_runtime_python(runtime)
    runner = RuntimeRunner()

    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-same",
        runtime_path=runtime,
        command_runner=runner,
        apply_google_env_fn=lambda _d, **_k: None,
    )
    assert outcome.ready, out.getvalue()
    # The interpreter is recorded, printed, and identical for every runtime call.
    assert outcome.runtime_python == runtime_python
    assert f"Machine runtime interpreter: {runtime_python}" in out.getvalue()
    interpreters = {c[0] for c in runner.calls}
    assert interpreters == {str(runtime_python)}
    # Both the deps probe and the capability probe really ran in it.
    assert [str(runtime_python), "-c", DEPS_PROBE] in runner.calls
    assert [str(runtime_python), "-c", deploy.GOOGLE_AUTH_CAPABILITY_CHECK] in runner.calls


def test_deps_probe_reports_on_the_interpreter_it_was_given(tmp_path: Path) -> None:
    # No interpreter -> nothing to probe (the provisioning gate owns that case), so
    # the probe can never claim "available" for an interpreter nobody will use.
    assert deploy._google_runtime_deps_ready(None, RuntimeRunner()) is True
    runtime_python = deploy.resolve_runtime_python(_machine_runtime(tmp_path))
    runner = RuntimeRunner()
    assert deploy._google_runtime_deps_ready(runtime_python, runner) is True
    assert all(c[0] == str(runtime_python) for c in runner.calls)


# ---------------------------------------------------------------------------
# 3. No in-process Google import when a machine runtime exists
# ---------------------------------------------------------------------------


def test_machine_runtime_wins_over_any_in_process_implementation(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    runtime = _machine_runtime(tmp_path)
    runner = RuntimeRunner()
    injected: list[int] = []

    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=io.StringIO(),
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-runtime",
        runtime_path=runtime,
        command_runner=runner,
        # Even an explicitly injected in-process implementation must not be used
        # while a machine runtime interpreter exists.
        authorize_google_fn=lambda *_a, **_k: injected.append(1) or True,
        apply_google_env_fn=lambda _d, **_k: None,
    )
    assert outcome.authorized is True
    assert injected == []
    assert runner.loopback_calls()
    # The autouse fixture would have raised had the in-process default been used.


def test_authorize_google_machine_never_imports_google_in_process(tmp_path: Path) -> None:
    runtime_python = deploy.resolve_runtime_python(_machine_runtime(tmp_path))
    runner = RuntimeRunner()
    ok = deploy._authorize_google_machine(
        data_dir=tmp_path,
        runtime_python=runtime_python,
        command_runner=runner,
        input_fn=lambda _p: "y",
        output=io.StringIO(),
        non_interactive=False,
        secret_input_fn=lambda _p: "x",
        authorize_google_fn=None,
        google_byo=False,
    )
    assert ok.authorized is True
    assert runner.loopback_calls()[0][0] == str(runtime_python)


# ---------------------------------------------------------------------------
# 4. No machine runtime on Windows -> fail closed (never in-process, never a prompt)
# ---------------------------------------------------------------------------


def test_missing_machine_runtime_fails_closed_without_credential_prompt(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    prompts: list[str] = []

    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda p: prompts.append(p) or "y",
        secret_input_fn=lambda p: prompts.append(p) or "x",
        google_integration_id="int-noruntime",
        runtime_path=None,  # nothing was provisioned / interpreter absent
        command_runner=RuntimeRunner(),
        apply_google_env_fn=lambda _d, **_k: None,
    )
    text = out.getvalue()
    assert outcome.authorized is False
    assert outcome.ready is False
    assert outcome.runtime_python is None
    # The failure names the interpreter the operator must provision, instead of a
    # confusing ModuleNotFoundError from a completely different Python.
    assert str(deploy.resolve_runtime_python(deploy.default_runtime_path())) in text
    assert "No module named" not in text
    # Fail-closed and silent about OAuth client material (managed app is default).
    assert "Google OAuth client ID:" not in text
    assert "Google OAuth client secret:" not in text
    assert not any("secret" in p.lower() for p in prompts)


def test_injected_implementation_still_serves_dev_when_no_runtime(tmp_path: Path) -> None:
    # Dev / embedder seam: an explicitly injected implementation is used when there
    # is no machine runtime, so this is never a silent in-process Google import.
    calls: list[int] = []
    ok = deploy._authorize_google_machine(
        data_dir=tmp_path,
        runtime_python=None,
        command_runner=None,
        input_fn=lambda _p: "y",
        output=io.StringIO(),
        non_interactive=False,
        secret_input_fn=lambda _p: "x",
        authorize_google_fn=lambda *_a, **_k: calls.append(1) or True,
        google_byo=False,
    )
    assert ok.authorized is True
    assert calls == [1]


# ---------------------------------------------------------------------------
# 5. Exact argv, and the bootstrap really accepts it
# ---------------------------------------------------------------------------


def test_exact_google_auth_argv(tmp_path: Path) -> None:
    runtime_python = deploy.resolve_runtime_python(_machine_runtime(tmp_path))
    data = Path(r"C:\ProgramData\Securedact")

    assert deploy.build_google_auth_argv(runtime_python, data) == [
        str(runtime_python),
        "-m",
        "securedact_mcp.agent.runtime_bootstrap",
        "google-auth",
        "--data-dir",
        str(data),
        "--loopback",
    ]
    assert (
        deploy.build_google_auth_argv(runtime_python, data, google_byo=True)[-1] == "--google-byo"
    )
    assert deploy.build_google_auth_argv(runtime_python, data, verify=True)[-1] == "--verify"
    # No OAuth material is ever placed on the command line.
    blob = " ".join(
        deploy.build_google_auth_argv(runtime_python, data, google_byo=True, verify=True)
    )
    for forbidden in ("client_secret", "refresh_token", "code=", "--token"):
        assert forbidden not in blob


@pytest.mark.parametrize("byo", [False, True])
@pytest.mark.parametrize("verify", [False, True])
def test_runtime_bootstrap_parses_the_exact_wizard_argv(tmp_path: Path, byo: bool, verify: bool):
    # Regression: the wizard appended ``--google-byo`` to the loopback argv while the
    # bootstrap parser did not accept it, so every BYO authorization died as an
    # argparse error ("unrecognized arguments: --google-byo").
    argv = deploy.build_google_auth_argv(
        deploy.resolve_runtime_python(_machine_runtime(tmp_path)),
        tmp_path,
        google_byo=byo,
        verify=verify,
    )
    parsed = runtime_bootstrap._build_parser().parse_args(argv[3:])
    assert parsed.cmd == "google-auth"
    assert parsed.data_dir == str(tmp_path)
    assert parsed.loopback is True
    assert parsed.google_byo is byo
    assert parsed.verify is verify


def test_loopback_child_env_pins_machine_data_root_and_no_user_site(tmp_path: Path) -> None:
    runtime_python = deploy.resolve_runtime_python(_machine_runtime(tmp_path))
    runner = RuntimeRunner()
    deploy._authorize_google_via_runtime(
        runtime_python, tmp_path / "machine", runner, io.StringIO(), google_byo=False
    )
    env = runner.envs[-1]
    assert env[deploy.DEFAULT_DATA_DIR_ENV] == str(tmp_path / "machine")
    assert env["PYTHONNOUSERSITE"] == "1"


# ---------------------------------------------------------------------------
# 6. A stale runtime bootstrap (no google-auth command) can never look ready
# ---------------------------------------------------------------------------


def test_bootstrap_capability_probe_passes_for_this_build() -> None:
    assert runtime_bootstrap.supports(*deploy.GOOGLE_AUTH_CAPABILITIES) is True
    assert runtime_bootstrap.supports("google-auth", "not-a-capability") is False
    # The probe SOURCE the provisioning runs must succeed in a current build...
    with pytest.raises(SystemExit) as exc:
        exec(deploy.GOOGLE_AUTH_CAPABILITY_CHECK, {})  # noqa: S102 - probe source under test
    assert exc.value.code == 0


def test_stale_runtime_without_google_auth_command_is_not_ready(tmp_path: Path) -> None:
    # The exact stale-runtime shape observed on the box: the Google extra imports
    # fine, but the installed bootstrap has no ``google-auth`` subcommand, so
    # routing authorization into it would answer "invalid choice: 'google-auth'".
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    runtime = _machine_runtime(tmp_path)
    runner = RuntimeRunner(deps_ok=True, capability_ok=False)

    out = io.StringIO()
    outcome = deploy.run_google_machine_onboarding(
        data_dir=machine,
        output=out,
        input_fn=lambda _p: "y",
        secret_input_fn=lambda _p: "x",
        google_integration_id="int-stale",
        runtime_path=runtime,
        command_runner=runner,
        apply_google_env_fn=lambda _d, **_k: None,
    )
    assert outcome.deps_ready is False
    assert outcome.ready is False
    assert "google-auth" in out.getvalue()
    # Fail closed BEFORE attempting any authorization.
    assert runner.loopback_calls() == []


def test_provision_fails_closed_on_stale_google_bootstrap(tmp_path: Path) -> None:
    class StaleGoogleBootstrapRunner(FakeRunner):
        def __call__(self, arguments, run_input):  # type: ignore[override]
            args = [str(a) for a in arguments]
            if (
                len(args) >= 3
                and args[1] == "-c"
                and args[2] == deploy.GOOGLE_AUTH_CAPABILITY_CHECK
            ):
                return RunResult(1, stderr="ImportError: cannot import name 'supports'")
            return super().__call__(arguments, run_input)

    with pytest.raises(AgentError) as exc:
        deploy.provision_machine_runtime(
            runtime_path=tmp_path / "runtime",
            acl_provider=safe_provider,
            command_runner=StaleGoogleBootstrapRunner(),
            google_enabled=True,
            # This test is about stale Google bootstrap detection, NOT Task Scheduler:
            # inject a hermetic agent-control collaborator so the real backend
            # (schtasks) is never consulted.
            _agent_control=lambda action: False,
        )
    message = str(exc.value)
    assert "google-auth" in message
    assert "stale" in message.lower()


@requires_google
def test_runtime_verification_needs_no_browser_or_token(tmp_path: Path, monkeypatch) -> None:
    # The in-runtime verification exercises the REAL loopback code path (imports,
    # config, 127.0.0.1 listener, PKCE consent URL) without opening a browser,
    # without a token, and without network access.
    import webbrowser

    monkeypatch.setattr(
        webbrowser, "open", lambda *_a, **_k: pytest.fail("verification must not open a browser")
    )
    payload = google_setup.verify_google_authorization_runtime(tmp_path)

    assert payload["verified"] is True
    assert payload["interpreter"] == sys.executable
    assert payload["imports_ok"] is True
    assert payload["imports"]["google_auth_oauthlib.flow"] is True
    assert payload["loopback_host"] == "127.0.0.1"
    assert int(payload["loopback_port"]) > 1024
    assert payload["consent_url_built"] is True
    # No token was created and no consent URL / CSRF state is leaked in the payload.
    assert not (tmp_path / "google" / "token.json.enc").exists()
    assert "url" not in payload and "state" not in payload
    assert json.dumps(payload)  # JSON-safe for the bootstrap contract


@requires_google
def test_runtime_verification_fails_closed_without_client(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(managed.SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV, raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_ID", raising=False)
    # The packaged managed default also counts as a configured client, so clear it
    # to exercise the genuine "no client configured" fail-closed path.
    from securedact_mcp.connectors.google import managed_config

    monkeypatch.setattr(managed_config, "MANAGED_GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(managed_config, "MANAGED_GOOGLE_CLIENT_SECRET", "")
    payload = google_setup.verify_google_authorization_runtime(tmp_path)
    assert payload["verified"] is False
    assert payload["imports_ok"] is True
    assert payload["client_configured"] is False


def test_bootstrap_verify_mode_emits_json_and_exit_code(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        google_setup,
        "verify_google_authorization_runtime",
        lambda data_dir: {"verified": True, "interpreter": sys.executable, "data_dir": data_dir},
    )
    rc = runtime_bootstrap.main(["google-auth", "--data-dir", "D:\\md", "--loopback", "--verify"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified"] is True
    assert payload["interpreter"] == sys.executable

    monkeypatch.setattr(
        google_setup,
        "verify_google_authorization_runtime",
        lambda data_dir: {"verified": False, "error": "missing extra"},
    )
    assert (
        runtime_bootstrap.main(["google-auth", "--data-dir", "D:\\md", "--loopback", "--verify"])
        == 2
    )
    assert json.loads(capsys.readouterr().out)["verified"] is False


def test_bootstrap_verify_mode_never_authorizes(monkeypatch, capsys) -> None:
    # ``--verify`` must never fall through into the real loopback authorization.
    monkeypatch.setattr(
        google_setup,
        "run_google_loopback_authorization",
        lambda _d: pytest.fail("verification must not run the real authorization"),
    )
    monkeypatch.setattr(
        google_setup, "verify_google_authorization_runtime", lambda _d: {"verified": True}
    )
    assert (
        runtime_bootstrap.main(["google-auth", "--data-dir", "D:\\md", "--loopback", "--verify"])
        == 0
    )
    capsys.readouterr()


# ---------------------------------------------------------------------------
# 8. Diagnosability: the in-process path names the interpreter that failed
# ---------------------------------------------------------------------------


def test_in_process_import_error_names_the_exact_interpreter(tmp_path: Path) -> None:
    class _Config:
        @staticmethod
        def load_google_config(*, require_enabled: bool, data_dir):
            return object()

    class _Auth:
        @staticmethod
        def load_credentials(_config):
            return None

        @staticmethod
        def get_authorization_url(_config):
            raise ModuleNotFoundError("No module named 'google_auth_oauthlib'")

    out = io.StringIO()
    ok = _REAL_IN_PROCESS_AUTHORIZE(
        tmp_path,
        input_fn=lambda _p: "",
        output=out,
        config_module=_Config(),
        auth_module=_Auth(),
        non_interactive=False,
        require_enabled=False,
    )
    assert ok is False
    text = out.getvalue()
    # The operator (and the RC triage) can see WHICH python lacked the extra.
    assert sys.executable in text
    assert "No module named 'google_auth_oauthlib'" in text
