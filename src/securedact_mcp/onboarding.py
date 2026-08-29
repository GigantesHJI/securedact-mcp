# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Protocol, TextIO

from . import __version__
from .agent import deploy as agent_deploy
from .model_store import ModelConfigurationError, ModelPathError, ModelStore

SUPPORTED_PYTHON = (3, 12)
ML_DISTRIBUTIONS = ("flair", "huggingface_hub", "torch", "transformers")
HOSTS = ("claude", "gemini")
CLAUDE_PLUGIN_ID = "securedact-enforced@securedact"
GEMINI_EXTENSION_NAME = "securedact-enforced"
INSPECTION_TIMEOUT_SECONDS = 30
CONFIGURATION_TIMEOUT_SECONDS = 120

InputFunction = Callable[[str], str]
ExecutableFinder = Callable[[str], str | None]
ModuleFinder = Callable[[str], object | None]


class ModelInstallRunner(Protocol):
    def __call__(
        self,
        *,
        language: str | None,
        accept_upstream_terms: bool,
        input_fn: InputFunction,
        output: TextIO,
        store: ModelStore | None = None,
    ) -> int: ...


ModelVerifyRunner = Callable[[ModelStore, TextIO], int]


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def __call__(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: int,
        interactive: bool,
    ) -> CommandResult: ...


class HostState(StrEnum):
    ABSENT = "not detected"
    NOT_CONFIGURED = "detected; not configured"
    DISABLED = "installed; disabled"
    CONFIGURED = "configured"
    UNKNOWN = "detected; state unavailable"


class ModelState(StrEnum):
    READY = "installed and verified"
    SKIPPED = "disabled by local configuration"
    NOT_READY = "not installed or verification failed"


@dataclass(frozen=True, slots=True)
class HostInspection:
    name: str
    executable: str | None
    state: HostState


def _platform_command(arguments: Sequence[str]) -> list[str]:
    command = list(arguments)
    if os.name != "nt" or Path(command[0]).suffix.casefold() not in {".bat", ".cmd"}:
        return command
    command_processor = os.environ.get("COMSPEC")
    if not command_processor:
        raise OSError("Windows command processor is unavailable")
    for item in command:
        if any(character in item for character in "\r\n&|<>^%!"):
            raise OSError("Unsafe command argument")
        if ("(" in item or ")" in item) and not any(character.isspace() for character in item):
            raise OSError("Unsafe command argument")
    return [command_processor, "/d", "/s", "/c", "call", *command]


def _default_command_runner(
    arguments: Sequence[str],
    *,
    timeout_seconds: int,
    interactive: bool,
) -> CommandResult:
    try:
        platform_arguments = _platform_command(arguments)
        if interactive:
            interactive_result = subprocess.run(  # noqa: S603 - resolved with shutil.which
                platform_arguments,
                stdin=None,
                stdout=sys.stderr,
                stderr=sys.stderr,
                timeout=timeout_seconds,
                check=False,
            )
            return CommandResult(returncode=interactive_result.returncode)
        captured_result = subprocess.run(  # noqa: S603 - executable is resolved with shutil.which
            platform_arguments,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return CommandResult(
            returncode=captured_result.returncode,
            stdout=captured_result.stdout,
            stderr=captured_result.stderr,
        )
    except (OSError, subprocess.TimeoutExpired):
        return CommandResult(returncode=2)


def _confirm_default_yes(prompt: str, input_fn: InputFunction) -> bool:
    try:
        answer = input_fn(prompt).strip().casefold()
    except (EOFError, StopIteration):
        return False
    return answer in {"", "y", "yes"}


def _ml_dependencies_available(module_finder: ModuleFinder) -> bool:
    return all(module_finder(name) is not None for name in ML_DISTRIBUTIONS)


def _model_state(store: ModelStore, verify_models: ModelVerifyRunner) -> ModelState:
    try:
        configuration = store.read_configuration()
    except ModelConfigurationError:
        return ModelState.NOT_READY
    if configuration is not None and not configuration.enabled_languages:
        return ModelState.SKIPPED
    return ModelState.READY if verify_models(store, io.StringIO()) == 0 else ModelState.NOT_READY


def _parse_json_array(result: CommandResult) -> list[object] | None:
    if result.returncode != 0:
        return None
    serialized = result.stdout.strip() or result.stderr.strip()
    try:
        payload = json.loads(serialized)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, list) else None


def _inspect_claude(executable: str, runner: CommandRunner) -> HostState:
    payload = _parse_json_array(
        runner(
            [executable, "plugin", "list", "--json"],
            timeout_seconds=INSPECTION_TIMEOUT_SECONDS,
            interactive=False,
        )
    )
    if payload is None:
        return HostState.UNKNOWN
    for item in payload:
        if isinstance(item, dict) and item.get("id") == CLAUDE_PLUGIN_ID:
            return HostState.CONFIGURED if item.get("enabled") is True else HostState.DISABLED
    return HostState.NOT_CONFIGURED


def _inspect_gemini(executable: str, runner: CommandRunner) -> HostState:
    payload = _parse_json_array(
        runner(
            [executable, "extensions", "list", "--output-format", "json"],
            timeout_seconds=INSPECTION_TIMEOUT_SECONDS,
            interactive=False,
        )
    )
    if payload is None:
        return HostState.UNKNOWN
    for item in payload:
        if isinstance(item, dict) and item.get("name") == GEMINI_EXTENSION_NAME:
            return HostState.CONFIGURED if item.get("isActive") is True else HostState.DISABLED
    return HostState.NOT_CONFIGURED


def inspect_host(
    name: str,
    *,
    executable_finder: ExecutableFinder = shutil.which,
    runner: CommandRunner = _default_command_runner,
) -> HostInspection:
    executable = executable_finder(name)
    if executable is None:
        return HostInspection(name=name, executable=None, state=HostState.ABSENT)
    state = (
        _inspect_claude(executable, runner)
        if name == "claude"
        else _inspect_gemini(executable, runner)
    )
    return HostInspection(name=name, executable=executable, state=state)


@contextmanager
def integration_resource(name: str) -> Iterator[Path]:
    resource = resources.files("securedact_mcp.setup_assets").joinpath(name)
    with resources.as_file(resource) as path:
        yield path


def _run_host_command(
    arguments: Sequence[str],
    *,
    runner: CommandRunner,
    interactive: bool,
) -> bool:
    return (
        runner(
            arguments,
            timeout_seconds=CONFIGURATION_TIMEOUT_SECONDS,
            interactive=interactive,
        ).returncode
        == 0
    )


def _configure_claude(
    inspection: HostInspection,
    resource_root: Path,
    runner: CommandRunner,
) -> bool:
    assert inspection.executable is not None
    executable = inspection.executable
    if inspection.state is HostState.DISABLED:
        return _run_host_command(
            [executable, "plugin", "enable", CLAUDE_PLUGIN_ID],
            runner=runner,
            interactive=True,
        )
    if inspection.state is not HostState.NOT_CONFIGURED:
        return False
    commands = (
        [executable, "plugin", "validate", str(resource_root)],
        [executable, "plugin", "marketplace", "add", str(resource_root)],
        [executable, "plugin", "install", CLAUDE_PLUGIN_ID, "--scope", "user"],
    )
    return all(_run_host_command(command, runner=runner, interactive=True) for command in commands)


def _configure_gemini(
    inspection: HostInspection,
    resource_root: Path,
    runner: CommandRunner,
) -> bool:
    assert inspection.executable is not None
    executable = inspection.executable
    if inspection.state is HostState.DISABLED:
        return _run_host_command(
            [executable, "extensions", "enable", GEMINI_EXTENSION_NAME],
            runner=runner,
            interactive=True,
        )
    if inspection.state is not HostState.NOT_CONFIGURED:
        return False
    commands = (
        [executable, "extensions", "validate", str(resource_root)],
        [executable, "extensions", "install", str(resource_root)],
    )
    return all(_run_host_command(command, runner=runner, interactive=True) for command in commands)


def configure_host(
    inspection: HostInspection,
    *,
    resource_root: Path,
    runner: CommandRunner = _default_command_runner,
) -> bool:
    if inspection.name == "claude":
        return _configure_claude(inspection, resource_root, runner)
    if inspection.name == "gemini":
        return _configure_gemini(inspection, resource_root, runner)
    return False


def _selected_hosts(host: str | None, inspections: Mapping[str, HostInspection]) -> tuple[str, ...]:
    if host is None or host == "all":
        return tuple(name for name in HOSTS if inspections[name].state is not HostState.ABSENT)
    return (host,)


def _print_preflight(
    *,
    output: TextIO,
    version: str,
    python_version: tuple[int, int, int],
    ml_available: bool,
) -> None:
    print("SecuRedact setup", file=output)
    print(file=output)
    print(f"Package: {version}", file=output)
    print(f"Python: {python_version[0]}.{python_version[1]}.{python_version[2]}", file=output)
    print(f"ML dependencies: {'available' if ml_available else 'missing'}", file=output)


def run_setup(
    *,
    host: str | None,
    language: str | None,
    accept_upstream_terms: bool,
    non_interactive: bool,
    install_models: ModelInstallRunner,
    verify_models: ModelVerifyRunner,
    input_fn: InputFunction = input,
    output: TextIO = sys.stderr,
    store: ModelStore | None = None,
    executable_finder: ExecutableFinder = shutil.which,
    module_finder: ModuleFinder = importlib.util.find_spec,
    runner: CommandRunner = _default_command_runner,
    resource_roots: Mapping[str, Path] | None = None,
    python_version: tuple[int, int, int] | None = None,
    version: str = __version__,
    agent: str | None = None,
    agent_only: bool = False,
    google: str | None = None,
    google_integration_id: str | None = None,
    managed_agent_runner: Callable[..., int] | None = None,
) -> int:
    """Run the unified SecuRedact setup wizard.

    Modules are optional/selectable: ``core`` (preflight), ``models``,
    ``upstream terms`` (implicit in model download consent), ``plugins`` (host
    integrations), and ``managed agent`` (Windows background service). The managed
    agent module is skipped automatically on non-Windows and when the user declines
    or passes ``agent="no"``. ``agent_only=True`` runs just the agent module
    (idempotent rerun, e.g. ``securedact-mcp setup --agent``).
    """
    detected_python = python_version or (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    ml_available = _ml_dependencies_available(module_finder)
    _print_preflight(
        output=output,
        version=version,
        python_version=detected_python,
        ml_available=ml_available,
    )
    if detected_python[:2] != SUPPORTED_PYTHON:
        command = (
            'py -3.12 -m pip install "securedact-mcp[ml]"'
            if os.name == "nt"
            else 'python3.12 -m pip install "securedact-mcp[ml]"'
        )
        print("Unsupported Python; SecuRedact requires Python >=3.12,<3.13.", file=output)
        print(f"Install with: {command}", file=output)
        return 2
    if accept_upstream_terms and language is None:
        print(
            "--accept-upstream-terms requires an explicit --language selection.",
            file=output,
        )
        return 2

    if agent_only:
        # Rerun only the Managed Agent module (idempotent, e.g. `setup --agent`).
        agent_rc = 0
        try:
            agent_rc = (managed_agent_runner or agent_deploy.run_managed_agent_module)(
                input_fn=input_fn,
                output=output,
                agent=agent if agent is not None else "yes",
                non_interactive=non_interactive,
                google=google,
                google_integration_id=google_integration_id,
            )
        except agent_deploy._ElevationHandoff:
            # An elevated child process has taken over; this instance exits.
            return 0
        print(file=output)
        print("Readiness:", file=output)
        print(
            f"  Managed Agent: {'configured' if agent_rc == 0 else 'failed'}",
            file=output,
        )
        return 0 if agent_rc == 0 else 2

    try:
        model_store = store or ModelStore.resolve()
    except ModelPathError:
        print("Models: managed storage is unavailable", file=output)
        return 2

    model_result = 0
    initial_model_state = _model_state(model_store, verify_models)
    print(f"Models: {initial_model_state.value}", file=output)
    should_install = language is not None
    if language is None and initial_model_state is not ModelState.READY and not non_interactive:
        should_install = _confirm_default_yes(
            "Set up contextual models using the existing model installer? [Y/n] ",
            input_fn,
        )
    if should_install:
        if not ml_available and language != "none":
            print('Model setup requires `python -m pip install "securedact-mcp[ml]"`.', file=output)
            model_result = 2
        else:
            model_result = install_models(
                language=language,
                accept_upstream_terms=accept_upstream_terms,
                input_fn=input_fn,
                output=output,
                store=model_store,
            )
            if model_result == 0:
                model_result = verify_models(model_store, output)
    elif initial_model_state is not ModelState.READY:
        print("Model setup skipped; no model download was started.", file=output)

    final_model_state = _model_state(model_store, verify_models)
    inspections = {
        name: inspect_host(name, executable_finder=executable_finder, runner=runner)
        for name in HOSTS
    }
    print(file=output)
    print("Detected AI hosts:", file=output)
    for name in HOSTS:
        print(f"  {name.capitalize()}: {inspections[name].state.value}", file=output)

    host_result = 0
    for name in _selected_hosts(host, inspections):
        inspection = inspections[name]
        if inspection.state is HostState.ABSENT:
            print(f"{name.capitalize()} CLI is not available on PATH.", file=output)
            if host == name:
                host_result = 2
            continue
        if inspection.state is HostState.CONFIGURED:
            continue
        if inspection.state is HostState.UNKNOWN:
            print(
                f"{name.capitalize()} integration state could not be verified; no changes made.",
                file=output,
            )
            host_result = 2
            continue
        if non_interactive:
            print(
                f"{name.capitalize()} configuration requires an interactive setup run; "
                "provider trust was not assumed.",
                file=output,
            )
            if host is not None:
                host_result = 2
            continue
        requested = host is not None or _confirm_default_yes(
            f"Configure SecuRedact Enforced for {name.capitalize()}? [Y/n] ",
            input_fn,
        )
        if not requested:
            continue
        if resource_roots is not None:
            root = resource_roots[name]
            configured = configure_host(inspection, resource_root=root, runner=runner)
        else:
            with integration_resource(name) as root:
                configured = configure_host(inspection, resource_root=root, runner=runner)
        if not configured:
            print(f"{name.capitalize()} configuration failed safely.", file=output)
            host_result = 2
            continue
        inspections[name] = inspect_host(
            name,
            executable_finder=executable_finder,
            runner=runner,
        )
        if inspections[name].state is not HostState.CONFIGURED:
            print(f"{name.capitalize()} configuration could not be verified.", file=output)
            host_result = 2

    agent_rc = 0
    try:
        agent_rc = (managed_agent_runner or agent_deploy.run_managed_agent_module)(
            input_fn=input_fn,
            output=output,
            agent=agent,
            non_interactive=non_interactive,
            google=google,
            google_integration_id=google_integration_id,
        )
    except agent_deploy._ElevationHandoff:
        # An elevated child process has taken over the install; this instance exits.
        return 0

    print(file=output)
    print("Readiness:", file=output)
    print(f"  Package: {version}", file=output)
    print(f"  Python: {detected_python[0]}.{detected_python[1]}", file=output)
    print(f"  ML dependencies: {'available' if ml_available else 'missing'}", file=output)
    print(f"  Models: {final_model_state.value}", file=output)
    for name in HOSTS:
        print(f"  {name.capitalize()}: {inspections[name].state.value}", file=output)
    print(
        f"  Managed Agent: {'configured' if agent_rc == 0 else 'failed'}",
        file=output,
    )
    if all(
        (
            ml_available,
            final_model_state is ModelState.READY,
            model_result == 0,
            host_result == 0,
            agent_rc == 0,
        )
    ):
        print("SecuRedact is ready.", file=output)
    else:
        print(
            "SecuRedact setup is incomplete; rerun setup after resolving the items above.",
            file=output,
        )
    return 2 if (model_result != 0 or host_result != 0 or not ml_available or agent_rc != 0) else 0
    return 2 if model_result != 0 or host_result != 0 or not ml_available else 0
