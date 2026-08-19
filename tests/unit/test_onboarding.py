from __future__ import annotations

import io
import json
import os
from collections.abc import Sequence
from pathlib import Path

import pytest

from securedact_mcp.cli import run_guided_install
from securedact_mcp.model_store import ModelStore
from securedact_mcp.onboarding import CommandResult, HostState, inspect_host, run_setup
from tests.unit.model_install_helpers import store_at


class SetupHarness:
    def __init__(
        self,
        *,
        ready: bool = False,
        executables: tuple[str, ...] = (),
        configured: tuple[str, ...] = (),
        disabled: tuple[str, ...] = (),
    ) -> None:
        self.ready = ready
        self.executables = set(executables)
        self.configured = set(configured)
        self.disabled = set(disabled)
        self.install_calls: list[tuple[str | None, bool]] = []
        self.verify_calls = 0
        self.commands: list[tuple[tuple[str, ...], int, bool]] = []

    def find_executable(self, name: str) -> str | None:
        return f"C:/Program Files/{name}/{name}.exe" if name in self.executables else None

    @staticmethod
    def find_module(_name: str) -> object:
        return object()

    def verify(self, _store: ModelStore, _output: io.StringIO) -> int:
        self.verify_calls += 1
        return 0 if self.ready else 2

    def install(
        self,
        *,
        language: str | None,
        accept_upstream_terms: bool,
        input_fn,  # type: ignore[no-untyped-def]
        output,  # type: ignore[no-untyped-def]
        store: ModelStore | None = None,
    ) -> int:
        del input_fn, output, store
        self.install_calls.append((language, accept_upstream_terms))
        self.ready = True
        return 0

    def run_command(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: int,
        interactive: bool,
    ) -> CommandResult:
        command = tuple(arguments)
        self.commands.append((command, timeout_seconds, interactive))
        host = "claude" if "plugin" in command else "gemini"
        if command[-2:] == ("list", "--json"):
            payload = []
            if host in self.configured or host in self.disabled:
                payload.append(
                    {
                        "id": "securedact-enforced@securedact",
                        "enabled": host in self.configured,
                    }
                )
            return CommandResult(0, json.dumps(payload))
        if "--output-format" in command:
            payload = []
            if host in self.configured or host in self.disabled:
                payload.append(
                    {
                        "name": "securedact-enforced",
                        "isActive": host in self.configured,
                    }
                )
            return CommandResult(0, json.dumps(payload))
        if "install" in command or "enable" in command:
            self.configured.add(host)
            self.disabled.discard(host)
        return CommandResult(0)


def _answers(*values: str):
    remaining = iter(values)
    return lambda _prompt: next(remaining)


def _resources(tmp_path: Path) -> dict[str, Path]:
    claude = tmp_path / "provider assets" / "claude"
    gemini = tmp_path / "provider assets" / "gemini"
    claude.mkdir(parents=True, exist_ok=True)
    gemini.mkdir(parents=True, exist_ok=True)
    return {"claude": claude, "gemini": gemini}


def _run(
    tmp_path: Path,
    harness: SetupHarness,
    *,
    answers: tuple[str, ...] = (),
    host: str | None = None,
    language: str | None = None,
    accepted: bool = False,
    non_interactive: bool = False,
) -> tuple[int, str]:
    output = io.StringIO()
    result = run_setup(
        host=host,
        language=language,
        accept_upstream_terms=accepted,
        non_interactive=non_interactive,
        install_models=harness.install,
        verify_models=harness.verify,
        input_fn=_answers(*answers),
        output=output,
        store=store_at(tmp_path / "model state"),
        executable_finder=harness.find_executable,
        module_finder=harness.find_module,
        runner=harness.run_command,
        resource_roots=_resources(tmp_path),
    )
    return result, output.getvalue()


def test_interactive_setup_invokes_existing_model_flow_then_verifies(tmp_path: Path) -> None:
    harness = SetupHarness()

    result, output = _run(tmp_path, harness, answers=("y",))

    assert result == 0
    assert harness.install_calls == [(None, False)]
    assert harness.verify_calls >= 2
    assert "Models: installed and verified" in output
    assert "SecuRedact is ready." in output


def test_model_setup_skip_starts_no_download(tmp_path: Path) -> None:
    harness = SetupHarness()

    result, output = _run(tmp_path, harness, answers=("n",))

    assert result == 0
    assert harness.install_calls == []
    assert "no model download was started" in output
    assert "setup is incomplete" in output


def test_existing_verified_models_are_not_reinstalled(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True)

    result, output = _run(tmp_path, harness)

    assert result == 0
    assert harness.install_calls == []
    assert "Models: installed and verified" in output


def test_model_verification_failure_after_install_fails_safely(tmp_path: Path) -> None:
    harness = SetupHarness()

    def unsuccessful_install(**_kwargs: object) -> int:
        return 0

    output = io.StringIO()
    result = run_setup(
        host=None,
        language="english",
        accept_upstream_terms=True,
        non_interactive=True,
        install_models=unsuccessful_install,  # type: ignore[arg-type]
        verify_models=harness.verify,
        output=output,
        store=store_at(tmp_path),
        executable_finder=harness.find_executable,
        module_finder=harness.find_module,
        runner=harness.run_command,
        resource_roots=_resources(tmp_path),
    )

    assert result == 2
    assert "setup is incomplete" in output.getvalue()


def test_declined_existing_model_flow_still_allows_safe_host_setup(tmp_path: Path) -> None:
    harness = SetupHarness(executables=("claude",))

    def declined(**_kwargs: object) -> int:
        return 2

    output = io.StringIO()
    result = run_setup(
        host="claude",
        language=None,
        accept_upstream_terms=False,
        non_interactive=False,
        install_models=declined,  # type: ignore[arg-type]
        verify_models=harness.verify,
        input_fn=_answers("y"),
        output=output,
        store=store_at(tmp_path / "models"),
        executable_finder=harness.find_executable,
        module_finder=harness.find_module,
        runner=harness.run_command,
        resource_roots=_resources(tmp_path),
    )
    assert result == 2
    assert harness.configured == {"claude"}
    assert "Models: not installed or verification failed" in output.getvalue()


def test_noninteractive_does_not_imply_upstream_acceptance(tmp_path: Path) -> None:
    output = io.StringIO()

    result = run_setup(
        host=None,
        language="english",
        accept_upstream_terms=False,
        non_interactive=True,
        install_models=run_guided_install,
        verify_models=lambda _store, _output: 2,
        output=output,
        store=store_at(tmp_path),
        executable_finder=lambda _name: None,
        module_finder=lambda _name: object(),
        resource_roots=_resources(tmp_path),
    )

    assert result == 2
    assert "requires --accept-upstream-terms" in output.getvalue()
    assert not any((tmp_path / "models").glob("**/*"))


def test_acceptance_flag_requires_explicit_language(tmp_path: Path) -> None:
    harness = SetupHarness()
    result, output = _run(tmp_path, harness, accepted=True, non_interactive=True)
    assert result == 2
    assert "requires an explicit --language" in output
    assert harness.install_calls == []


def test_unsupported_python_reports_remediation_without_other_actions(tmp_path: Path) -> None:
    harness = SetupHarness()
    output = io.StringIO()
    result = run_setup(
        host=None,
        language=None,
        accept_upstream_terms=False,
        non_interactive=True,
        install_models=harness.install,
        verify_models=harness.verify,
        output=output,
        store=store_at(tmp_path),
        executable_finder=harness.find_executable,
        module_finder=harness.find_module,
        runner=harness.run_command,
        resource_roots=_resources(tmp_path),
        python_version=(3, 13, 1),
    )
    assert result == 2
    assert "requires Python >=3.12,<3.13" in output.getvalue()
    assert "securedact-mcp[ml]" in output.getvalue()
    assert harness.install_calls == []
    assert harness.commands == []


@pytest.mark.parametrize("host", ("claude", "gemini"))
def test_detected_host_is_configured_with_official_commands(tmp_path: Path, host: str) -> None:
    harness = SetupHarness(ready=True, executables=(host,))

    result, output = _run(tmp_path, harness, host=host)

    assert result == 0
    assert harness.configured == {host}
    assert f"{host.capitalize()}: configured" in output
    mutating = [command for command, _timeout, interactive in harness.commands if interactive]
    assert mutating
    assert all("settings" not in command for command in mutating)
    assert all("--consent" not in command for command in mutating)
    assert all(timeout <= 120 for _command, timeout, _interactive in harness.commands)
    assert all(
        command[1] in {"plugin", "extensions"}
        for command, _timeout, _interactive in harness.commands
    )


def test_gemini_install_uses_packaged_path_as_one_argument(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True, executables=("gemini",))
    resources = _resources(tmp_path)

    result, _output = _run(tmp_path, harness, host="gemini")

    assert result == 0
    install = next(
        command for command, _timeout, _interactive in harness.commands if "install" in command
    )
    assert install[-1] == str(resources["gemini"])
    assert " " in install[-1]


def test_noninteractive_targeted_host_requires_interactive_trust(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True, executables=("gemini",))

    result, output = _run(
        tmp_path,
        harness,
        host="gemini",
        non_interactive=True,
    )

    assert result == 2
    assert "provider trust was not assumed" in output
    assert not any(interactive for _command, _timeout, interactive in harness.commands)


def test_noninteractive_default_only_inspects_hosts(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True, executables=("claude", "gemini"))

    result, _output = _run(tmp_path, harness, non_interactive=True)

    assert result == 0
    assert harness.configured == set()
    assert not any(interactive for _command, _timeout, interactive in harness.commands)


def test_configured_hosts_make_rerun_idempotent(tmp_path: Path) -> None:
    harness = SetupHarness(
        ready=True,
        executables=("claude", "gemini"),
        configured=("claude", "gemini"),
    )

    result, _output = _run(tmp_path, harness, host="all")

    assert result == 0
    assert not any(interactive for _command, _timeout, interactive in harness.commands)


def test_provider_configuration_does_not_rewrite_unrelated_user_config(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True, executables=("claude", "gemini"))
    user_config = tmp_path / "user settings.json"
    original = '{"unrelatedPlugin": true, "credentialReference": "system-keychain"}\n'
    user_config.write_text(original, encoding="utf-8")

    result, _output = _run(tmp_path, harness, host="all")

    assert result == 0
    assert user_config.read_text(encoding="utf-8") == original


def test_disabled_host_is_enabled_without_reinstallation(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True, executables=("claude",), disabled=("claude",))

    result, _output = _run(tmp_path, harness, host="claude")

    assert result == 0
    interactive = [command for command, _timeout, active in harness.commands if active]
    assert interactive == [
        ("C:/Program Files/claude/claude.exe", "plugin", "enable", "securedact-enforced@securedact")
    ]


def test_unknown_or_unavailable_target_host_fails_without_changes(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True)

    result, output = _run(tmp_path, harness, host="claude")

    assert result == 2
    assert "not available on PATH" in output
    assert harness.commands == []


def test_malformed_provider_response_is_not_treated_as_configured(tmp_path: Path) -> None:
    harness = SetupHarness(ready=True, executables=("claude",))

    def malformed(
        arguments: Sequence[str], *, timeout_seconds: int, interactive: bool
    ) -> CommandResult:
        harness.commands.append((tuple(arguments), timeout_seconds, interactive))
        return CommandResult(0, "not-json")

    harness.run_command = malformed  # type: ignore[method-assign]
    result, output = _run(tmp_path, harness, host="claude")

    assert result == 2
    assert "state could not be verified" in output
    assert not any(interactive for _command, _timeout, interactive in harness.commands)


def test_missing_ml_dependencies_prevents_model_action(tmp_path: Path) -> None:
    harness = SetupHarness()
    output = io.StringIO()
    result = run_setup(
        host=None,
        language="english",
        accept_upstream_terms=True,
        non_interactive=True,
        install_models=harness.install,
        verify_models=harness.verify,
        output=output,
        store=store_at(tmp_path),
        executable_finder=harness.find_executable,
        module_finder=lambda _name: None,
        runner=harness.run_command,
        resource_roots=_resources(tmp_path),
    )
    assert result == 2
    assert harness.install_calls == []
    assert "ML dependencies: missing" in output.getvalue()


def test_setup_writes_status_only_to_supplied_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    harness = SetupHarness(ready=True)
    result, output = _run(tmp_path, harness, non_interactive=True)
    captured = capsys.readouterr()
    assert result == 0
    assert output
    assert captured.out == ""
    assert captured.err == ""


@pytest.mark.skipif(os.name != "nt", reason="Windows command-shim regression")
def test_windows_cmd_host_detection_accepts_json_written_to_stderr(tmp_path: Path) -> None:
    shim = tmp_path / "path with spaces" / "gemini.cmd"
    shim.parent.mkdir()
    shim.write_text(
        '@echo off\r\necho [{"name":"securedact-enforced","isActive":true}] 1>&2\r\n',
        encoding="ascii",
    )

    inspection = inspect_host("gemini", executable_finder=lambda _name: str(shim))

    assert inspection.state is HostState.CONFIGURED
