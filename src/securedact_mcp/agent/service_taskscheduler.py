# SPDX-License-Identifier: Apache-2.0
"""Windows Task Scheduler backend for the managed-agent persistence layer.

This module replaces the previous ``pywin32`` / ``pythonservice.exe`` Windows
Service (``service_windows``) as the primary mechanism that keeps the managed
agent running in the background on Windows.

Why Task Scheduler
------------------
Empirically, the minimal pywin32 service failed to start on this real Windows
host with ``WinError 1053`` (the SCM timed out before the service reported
RUNNING), while the normal foreground agent command already works. Task
Scheduler launches the *same proven agent loop* (``python -m
securedact_mcp.agent.cli run``) as a normal, non-interactive process:

    Windows startup
      -> Task Scheduler launches the machine runtime Python
      -> securedact_mcp managed-agent loop starts
      -> heartbeat stays active
      -> dashboard shows Online
      -> scan job queued
      -> agent claims job
      -> content scanned locally
      -> only safe summary returned

Security invariants (unchanged from the rest of the agent)
----------------------------------------------------------
* No secret is ever placed on the task command line or in task metadata. The
  one-time registration token is delivered in-memory to ``register_agent`` (or,
  in the bootstrap path, over stdin). Agent credentials, OAuth tokens, lease
  secrets, and entitlement JWTs are loaded from the local vault at runtime.
* The identity used in this DEV baseline is the simplest one that reliably
  works on the host and can read the existing ``C:\\ProgramData\\Securedact``
  agent state: the built-in ``SYSTEM`` account (no password, no per-account
  ACLs, runs at startup whether or not a user is logged on). The vSA/ACL/
  runtime-integrity hardening from the old production path is intentionally
  NOT reintroduced here yet (see AGENTS.md / the task brief); it is added only
  after this Task Scheduler lifecycle is proven.
* The DEV baseline flag (``SECUREDACT_AGENT_SERVICE_DEV_BASELINE``) is honoured
  only as an explicit, non-security-impacting marker: it never weakens
  application/protocol security and can only be enabled by the exact value
  ``"1"`` (see :mod:`securedact_mcp.agent.service_security`).

The scheduled task
------------------
* Name: ``SecuRedact Managed Agent``.
* Trigger: at system startup (``BootTrigger``), runs whether or not an
  interactive PowerShell window is open.
* Executable: the machine-owned runtime interpreter
  (``C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe``), invoked with
  ``-m securedact_mcp.agent.cli run`` — the exact canonical equivalent of the
  working foreground command.
* Runs hidden / non-interactive, restarts on failure, and refuses to start a
  second instance while one is already running (single-instance lock is also
  enforced inside the agent loop itself).
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .config import AgentFiles
from .errors import AgentError
from .safe_log import scrub

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEDULED_TASK_NAME = "SecuRedact Managed Agent"
TASK_DESCRIPTION = (
    "SecuRedact local managed-agent daemon: heartbeats to the SecuRedact control "
    "plane and executes queued Google privacy scans locally. Runs hidden with no "
    "console window and starts automatically at system startup."
)
TASK_VERSION = "1.2"
DEFAULT_PRINCIPAL = "SYSTEM"
DEFAULT_RESTART_COUNT = 3
DEFAULT_RESTART_INTERVAL = "PT1M"  # 1 minute between restart attempts

# Resolve system executables by absolute path (repo convention: avoids the
# S607 partial-path lint and removes ambiguity about which binary runs).
_SYSTEM32 = os.path.expandvars("%SystemRoot%\\System32")


def _system_exe(name: str) -> str:
    return os.path.join(_SYSTEM32, name)


DEFAULT_RESTART_COUNT = 3
DEFAULT_RESTART_INTERVAL = "PT1M"  # 1 minute between restart attempts

# The scheduled task launches the machine-runtime interpreter (``python.exe``)
# directly against a small launcher script that lives INSIDE the runtime's
# ``Scripts`` directory. We deliberately avoid ``python -m securedact_mcp.agent.cli
# run``: on CPython 3.12 the ``-m`` form re-execs the process via
# ``sys._base_executable`` (the base interpreter, not the machine-owned runtime),
# which would run the agent loop outside the provisioned runtime. A direct
# ``python.exe <launcher>.py run`` invocation has no such re-exec and keeps the
# loop inside the machine runtime. The console-script form (``securedact-mcp.exe
# agent run``) is NOT used: Application Control on this host blocks that ``.exe``.
AGENT_LOOP_LAUNCHER = "securedact_agent_loop.py"

# Non-secret operational environment delivered to the background process. No
# credential, token, OAuth secret, lease secret, or entitlement JWT is ever
# included here.
ENV_SECUREDACT_REQUIRE_FLAIR = "0"
ENV_PYTHONNOUSERSITE = "1"


# ---------------------------------------------------------------------------
# Result type for the (injectable) schtasks command runner
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SchtasksResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


# The runner receives the schtasks *arguments* (without the ``schtasks`` binary)
# and returns a :class:`SchtasksResult`.
CommandRunner = Callable[[Sequence[str]], SchtasksResult]


# ---------------------------------------------------------------------------
# Task definition (pure, fully testable without Windows)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TaskDefinition:
    """Fully-resolved, secret-free scheduled-task definition."""

    name: str
    executable: Path
    arguments: str
    working_directory: Path
    data_dir: Path
    principal: str
    trigger: str
    restart_count: int
    restart_interval: str
    hidden: bool
    multiple_instances: str
    env: dict[str, str]
    description: str = TASK_DESCRIPTION


def _resolve_runtime_interpreter(runtime_python: Path | None = None) -> Path:
    """Return the machine-runtime Python interpreter for the agent loop.

    Prefers ``python.exe`` (the proven, Application-Control-friendly interpreter),
    then ``pythonw.exe`` (no console window) as a fallback, then the
    ``deploy``-resolved runtime interpreter. Never raises for a missing file
    here; callers fail closed.
    """

    if runtime_python is not None:
        return Path(runtime_python)
    from . import deploy

    runtime = deploy.default_runtime_path()
    for name in ("python.exe", "pythonw.exe"):
        candidate = runtime / "Scripts" / name
        if candidate.exists():
            return candidate
    return deploy.resolve_runtime_python(runtime)


def _launcher_script_path(interpreter: Path) -> Path:
    """Return the absolute path of the in-runtime launcher script."""

    return interpreter.parent / AGENT_LOOP_LAUNCHER


_LAUNCHER_SOURCE = '''"""Machine-runtime launcher for the SecuRedact managed-agent loop.

Invoked by the Windows Task Scheduler task as::

    <runtime>/Scripts/python.exe <runtime>/Scripts/securedact_agent_loop.py run

Using a direct script (rather than ``python -m securedact_mcp.agent.cli run``)
deliberately avoids CPython 3.12's runpy re-exec into ``sys._base_executable``,
which would otherwise run the loop under the base interpreter instead of the
machine-owned runtime.
"""

import sys

from securedact_mcp.agent.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
'''


def write_launcher_script(interpreter: Path) -> Path:
    """Idempotently write the in-runtime launcher script; return its path."""

    launcher = _launcher_script_path(interpreter)
    try:
        current = launcher.read_text(encoding="utf-8") if launcher.exists() else None
    except OSError:
        current = None
    if current != _LAUNCHER_SOURCE:
        launcher.write_text(_LAUNCHER_SOURCE, encoding="utf-8")
    return launcher


def build_task_env(data_dir: Path) -> dict[str, str]:
    """Build the (non-secret) environment for the background agent process."""

    return {
        "SECUREDACT_APP_DATA_DIR": str(data_dir),
        "SECUREDACT_AGENT_DATA_DIR": str(data_dir),
        "PYTHONNOUSERSITE": ENV_PYTHONNOUSERSITE,
        "SECUREDACT_REQUIRE_FLAIR": ENV_SECUREDACT_REQUIRE_FLAIR,
    }


def build_task_definition(
    *,
    data_dir: Path,
    runtime_python: Path | None = None,
    principal: str = DEFAULT_PRINCIPAL,
    restart_count: int = DEFAULT_RESTART_COUNT,
    restart_interval: str = DEFAULT_RESTART_INTERVAL,
    hidden: bool = True,
    multiple_instances: str = "IgnoreNew",
    trigger: str = "boot",
) -> TaskDefinition:
    """Construct the secret-free scheduled-task definition.

    The ``token`` / credentials are deliberately NOT part of this definition:
    registration (if required) is performed separately and in-memory, and all
    secrets are loaded from the local vault at runtime.
    """

    interpreter = _resolve_runtime_interpreter(runtime_python)
    launcher = _launcher_script_path(interpreter)
    return TaskDefinition(
        name=SCHEDULED_TASK_NAME,
        executable=interpreter,
        arguments=f'"{launcher}" run',
        working_directory=Path(data_dir),
        data_dir=Path(data_dir),
        principal=principal,
        trigger=trigger,
        restart_count=restart_count,
        restart_interval=restart_interval,
        hidden=hidden,
        multiple_instances=multiple_instances,
        env=build_task_env(Path(data_dir)),
        description=TASK_DESCRIPTION,
    )


# ---------------------------------------------------------------------------
# XML serialisation (pure, testable)
# ---------------------------------------------------------------------------

_TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _q(tag: str) -> str:
    return f"{{{_TASK_NS}}}{tag}"


def build_task_xml(definition: TaskDefinition) -> str:
    """Serialise a :class:`TaskDefinition` to a Task Scheduler 2.0 XML string.

    The XML is returned as a ``unicode`` string; the caller writes it as UTF-16
    (the encoding Windows Task Scheduler expects for ``.task`` files).
    """

    root = ET.Element(_q("Task"), attrib={"version": TASK_VERSION, "xmlns": _TASK_NS})

    reg = ET.SubElement(root, _q("RegistrationInfo"))
    ET.SubElement(reg, _q("Date")).text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    ET.SubElement(reg, _q("Author")).text = SCHEDULED_TASK_NAME
    ET.SubElement(reg, _q("Description")).text = definition.description

    triggers = ET.SubElement(root, _q("Triggers"))
    if definition.trigger == "boot":
        boot = ET.SubElement(triggers, _q("BootTrigger"))
        ET.SubElement(boot, _q("Enabled")).text = "true"
    else:  # pragma: no cover - only "boot" is used by the managed agent
        logon = ET.SubElement(triggers, _q("LogonTrigger"))
        ET.SubElement(logon, _q("Enabled")).text = "true"

    principals = ET.SubElement(root, _q("Principals"))
    principal = ET.SubElement(principals, _q("Principal"), attrib={"id": "Author"})
    ET.SubElement(principal, _q("UserId")).text = definition.principal
    # ``SYSTEM`` is a built-in service account; Task Scheduler accepts the
    # principal with only ``UserId`` set (LogonType/RunLevel are optional and
    # ``ServiceAccount`` is rejected for some built-in SIDs).

    settings = ET.SubElement(root, _q("Settings"))
    # Element order MUST follow the Task Scheduler 2.0 schema sequence.
    ET.SubElement(settings, _q("DisallowStartIfOnBatteries")).text = "false"
    ET.SubElement(settings, _q("StopIfGoingOnBatteries")).text = "false"
    ET.SubElement(settings, _q("MultipleInstancesPolicy")).text = definition.multiple_instances
    # Restart-on-failure is expressed as a ``RestartOnFailure`` element (the
    # flat ``RestartCount``/``RestartInterval`` form is rejected by this host's
    # schema validator), placed right after ``MultipleInstancesPolicy``.
    if definition.restart_count and definition.restart_count > 0:
        rof = ET.SubElement(settings, _q("RestartOnFailure"))
        ET.SubElement(rof, _q("Count")).text = str(definition.restart_count)
        ET.SubElement(rof, _q("Interval")).text = definition.restart_interval
    idle = ET.SubElement(settings, _q("IdleSettings"))
    ET.SubElement(idle, _q("StopOnIdleEnd")).text = "false"
    ET.SubElement(idle, _q("RestartOnIdle")).text = "false"
    ET.SubElement(settings, _q("AllowHardTerminate")).text = "true"
    ET.SubElement(settings, _q("StartWhenAvailable")).text = "true"
    ET.SubElement(settings, _q("RunOnlyIfNetworkAvailable")).text = "false"
    ET.SubElement(settings, _q("AllowStartOnDemand")).text = "true"
    ET.SubElement(settings, _q("Enabled")).text = "true"
    ET.SubElement(settings, _q("Hidden")).text = "true" if definition.hidden else "false"
    ET.SubElement(settings, _q("RunOnlyIfIdle")).text = "false"
    ET.SubElement(settings, _q("WakeToRun")).text = "false"
    ET.SubElement(settings, _q("ExecutionTimeLimit")).text = "PT0S"
    ET.SubElement(settings, _q("Priority")).text = "7"

    actions = ET.SubElement(root, _q("Actions"), attrib={"Context": "Author"})
    exec_action = ET.SubElement(actions, _q("Exec"))
    ET.SubElement(exec_action, _q("Command")).text = str(definition.executable)
    ET.SubElement(exec_action, _q("Arguments")).text = definition.arguments
    ET.SubElement(exec_action, _q("WorkingDirectory")).text = str(definition.working_directory)

    # NOTE: Windows Task Scheduler on this host rejects the ``EnvironmentVariables``
    # XML node entirely (``ERROR: The task XML contains an unexpected node``), so the
    # non-secret operational environment is NOT embedded in the task XML. Instead it
    # is applied at machine scope by :func:`_apply_service_env_vars` (inherited by the
    # SYSTEM-run task) — see :func:`install_windows_service`. The ``env`` field of
    # :class:`TaskDefinition` is still the authoritative, secret-free record and is
    # asserted by tests; it is simply delivered via the machine environment rather
    # than the (unsupported) XML node.

    return '<?xml version="1.0" encoding="UTF-16"?>\n' + ET.tostring(root, encoding="unicode")


# ---------------------------------------------------------------------------
# Non-secret operational environment (machine scope)
# ---------------------------------------------------------------------------

# This host's Task Scheduler cannot carry per-task environment via the XML
# ``EnvironmentVariables`` node, so we publish the (non-secret) operational
# variables at machine scope. They are inherited by the SYSTEM-run task and are
# never secrets: only the data-dir location, a usersite disable flag, and the
# dev-flavour flag that lets the local-first engine run without the contextual
# model. Credentials/OAuth/lease/JWT secrets are NOT touched here.
_SERIVCE_ENV_VARS = (
    "SECUREDACT_APP_DATA_DIR",
    "SECUREDACT_AGENT_DATA_DIR",
    "SECUREDACT_REQUIRE_FLAIR",
    "PYTHONNOUSERSITE",
)


def _apply_service_env_vars(data_dir: Path) -> None:
    """Publish the non-secret operational env vars at machine scope.

    Uses ``setx /M`` (requires elevation) so the SYSTEM-run scheduled task
    inherits them. Idempotent: an existing value is preserved when it already
    matches, so re-running install is a no-op for values already set.
    """

    desired = {
        "SECUREDACT_APP_DATA_DIR": str(data_dir),
        "SECUREDACT_AGENT_DATA_DIR": str(data_dir),
        # Local-first engine runs without the contextual model in this DEV baseline.
        "SECUREDACT_REQUIRE_FLAIR": ENV_SECUREDACT_REQUIRE_FLAIR,
        "PYTHONNOUSERSITE": ENV_PYTHONNOUSERSITE,
    }
    for key, value in desired.items():
        try:
            existing = os.environ.get(key)
        except Exception:  # best-effort; fall through to set
            existing = None
        if existing == value:
            continue
        try:
            subprocess.run(  # noqa: S603 - fixed binary + literal args
                [_system_exe("setx"), "/M", key, value],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("could not set machine env %s: %s", key, scrub(str(exc)))


# ---------------------------------------------------------------------------
# schtasks command runner (real + injectable)
# ---------------------------------------------------------------------------


def _default_schtasks_runner(arguments: Sequence[str]) -> SchtasksResult:
    """Run ``schtasks`` with the given arguments (real Windows execution)."""

    completed = subprocess.run(  # noqa: S603 - fixed binary, injected args
        [_system_exe("schtasks"), *[str(a) for a in arguments]],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return SchtasksResult(completed.returncode, completed.stdout, completed.stderr)


def _write_xml_file(xml: str) -> Path:
    handle = tempfile.NamedTemporaryFile(
        prefix="securedact-task-", suffix=".xml", delete=False, mode="w", encoding="utf-16"
    )
    try:
        handle.write(xml)
    finally:
        handle.close()
    return Path(handle.name)


def task_exists(name: str, runner: CommandRunner | None = None) -> bool:
    """Return True when a scheduled task with ``name`` already exists."""

    r = (runner or _default_schtasks_runner)(["/Query", "/TN", name])
    return r.returncode == 0


def _create_task(name: str, xml: str, runner: CommandRunner) -> None:
    path = _write_xml_file(xml)
    try:
        result = runner(["/Create", "/TN", name, "/XML", str(path), "/F"])
    finally:
        try:
            path.unlink()
        except OSError:  # pragma: no cover - best-effort cleanup
            pass
    if result.returncode != 0:
        raise AgentError(f"failed to create scheduled task '{name}': {scrub(result.stderr)}")


def _delete_task(name: str, runner: CommandRunner) -> None:
    runner(["/Delete", "/TN", name, "/F"])


def _start_task(name: str, runner: CommandRunner) -> None:
    runner(["/Run", "/TN", name])


def _stop_task(name: str, runner: CommandRunner) -> None:
    runner(["/End", "/TN", name])


def _parse_status(name: str, runner: CommandRunner) -> dict[str, object]:
    result = runner(["/Query", "/TN", name, "/FO", "JSON"])
    if result.returncode != 0:
        return {"installed": False, "service_name": name}
    try:
        payload = _parse_json_array(result.stdout)
    except Exception:
        payload = None
    if not payload:
        return {"installed": True, "service_name": name, "state": "unknown"}
    if not isinstance(payload, list) or not payload:
        return {"installed": True, "service_name": name, "state": "unknown"}
    entry = payload[0]
    if not isinstance(entry, dict):
        return {"installed": True, "service_name": name, "state": "unknown"}
    state = str(entry.get("Status", "unknown")).strip().lower() or "unknown"
    return {"installed": True, "service_name": name, "state": state}


def _parse_json_array(text: str) -> object | None:
    import json
    from typing import cast

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return cast("object", data)


# ---------------------------------------------------------------------------
# High-level lifecycle (Task Scheduler)
# ---------------------------------------------------------------------------


def install_windows_service(
    data_dir: str | Path | None = None,
    *,
    start: bool = True,
    control_plane_url: str | None = None,
    display_name: str | None = None,
    token: str | None = None,
    runtime_python: str | Path | None = None,
    command_runner: CommandRunner | None = None,
    register_fn: Callable[..., Any] | None = None,
) -> dict[str, object]:
    """Create (or replace) the SecuRedact Managed Agent scheduled task.

    If a one-time ``token`` is supplied, the agent is registered (token consumed
    in-memory only, never on the command line). Otherwise an existing valid
    registration is reused — no token is consumed. The task is then created and,
    unless ``start`` is False, started.
    """

    from . import agent_runner, service, service_security

    runner = command_runner or _default_schtasks_runner
    resolved = service.resolve_service_data_dir(data_dir)
    resolved.mkdir(parents=True, exist_ok=True)

    launcher = _resolve_runtime_interpreter(
        Path(runtime_python) if runtime_python is not None else None
    )
    if not launcher.exists():
        raise AgentError(
            f"machine runtime interpreter not found at {launcher}; run "
            "'securedact-mcp setup --agent' to provision it before installing the task"
        )

    dev_baseline = service_security.is_dev_baseline_enabled()

    # Optional, in-memory-only registration (never on the command line).
    agent_id: str | None = None
    if token:
        register = register_fn or agent_runner.register_agent
        try:
            # Register directly under the machine data root. The Task Scheduler
            # backend runs the agent as SYSTEM from this same root, so the
            # registration (config + credential vault) MUST be written here and
            # never to the interactive user's %LOCALAPPDATA% profile. We pass the
            # machine-root ``AgentFiles`` explicitly rather than relying on the
            # default (user-profile) resolution.
            config = register(
                token,
                control_plane_url=control_plane_url,
                display_name=display_name,
                files=AgentFiles.resolve(root=resolved / "agent"),
            )
        except AgentError as exc:
            raise AgentError(f"registration failed during task install: {exc}") from exc
        agent_id = config.agent_id

    # Materialise the in-runtime launcher script so the scheduled task invokes
    # the loop directly (no ``python -m`` re-exec into the base interpreter).
    write_launcher_script(launcher)

    definition = build_task_definition(
        data_dir=resolved, runtime_python=launcher, principal=DEFAULT_PRINCIPAL
    )
    xml = build_task_xml(definition)

    # Idempotent: remove any prior instance before (re)creating.
    if task_exists(SCHEDULED_TASK_NAME, runner):
        _delete_task(SCHEDULED_TASK_NAME, runner)
    _create_task(SCHEDULED_TASK_NAME, xml, runner)

    # Publish the non-secret operational environment at machine scope (inherited
    # by the SYSTEM-run task). This replaces the unsupported XML EnvironmentVariables
    # node on this host. No secret material is ever written here.
    _apply_service_env_vars(resolved)

    if start:
        _start_task(SCHEDULED_TASK_NAME, runner)

    result: dict[str, object] = {
        "installed": True,
        "service_name": SCHEDULED_TASK_NAME,
        "data_dir": str(resolved),
        "account": DEFAULT_PRINCIPAL,
        "executable": str(definition.executable),
        "arguments": definition.arguments,
        "trigger": "boot",
        "restart_count": DEFAULT_RESTART_COUNT,
        "running": start,
        "dev_baseline": dev_baseline,
        "agent_id": agent_id,
    }
    if dev_baseline:
        from .service_security import DEV_BASELINE_WARNING  # shared with the reference backend

        result["warning"] = DEV_BASELINE_WARNING
    logger.info(
        "scheduled task '%s' installed (executable=%s, data_dir=%s, start=%s)",
        SCHEDULED_TASK_NAME,
        launcher,
        resolved,
        start,
    )
    return result


def start_windows_service() -> dict[str, object]:
    if not task_exists(SCHEDULED_TASK_NAME):
        raise AgentError(
            f"scheduled task '{SCHEDULED_TASK_NAME}' is not installed; run "
            "'securedact-mcp agent service install' first"
        )
    _start_task(SCHEDULED_TASK_NAME, _default_schtasks_runner)
    return {"started": True, "service_name": SCHEDULED_TASK_NAME}


def stop_windows_service() -> dict[str, object]:
    if not task_exists(SCHEDULED_TASK_NAME):
        return {"stopped": False, "service_name": SCHEDULED_TASK_NAME, "reason": "not installed"}
    _stop_task(SCHEDULED_TASK_NAME, _default_schtasks_runner)
    return {"stopped": True, "service_name": SCHEDULED_TASK_NAME}


def uninstall_windows_service() -> dict[str, object]:
    if not task_exists(SCHEDULED_TASK_NAME):
        return {
            "uninstalled": False,
            "service_name": SCHEDULED_TASK_NAME,
            "reason": "not installed",
        }
    _delete_task(SCHEDULED_TASK_NAME, _default_schtasks_runner)
    return {"uninstalled": True, "service_name": SCHEDULED_TASK_NAME}


def query_windows_service() -> dict[str, object]:
    return _parse_status(SCHEDULED_TASK_NAME, _default_schtasks_runner)


def service_log_path(data_dir: str | Path | None = None) -> Path:
    from . import service

    root = service.resolve_service_data_dir(data_dir)
    return root / "logs" / "agent-service.log"
