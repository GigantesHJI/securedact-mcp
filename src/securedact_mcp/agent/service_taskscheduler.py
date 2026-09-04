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

import json
import logging
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

try:
    import win32com.client as win32com_client  # type: ignore[import-untyped]
except Exception:  # pragma: no cover - non-Windows / missing pywin32
    win32com_client = None

from .errors import AgentError
from .safe_log import scrub

logger = logging.getLogger(__name__)

# Legacy SCM service name that must be detected and migrated
LEGACY_SCM_SERVICE_NAME = "SecuredactAgent"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEDULED_TASK_NAME = "SecuRedact Managed Agent"
# Canonical Task Scheduler root-path form. ``schtasks`` accepts both the bare
# name and the leading-backslash root form, but querying with the bare name
# returns ``\SecuRedact Managed Agent`` in its output and JSON payload. We
# normalise the task name so existence/running detection never depends on the
# surface form passed in by callers or written back by schtasks itself.
SCHEDULED_TASK_FULL_PATH = "\\" + SCHEDULED_TASK_NAME
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


def _legacy_scm_service_exists() -> bool:
    """Return True if the legacy SecuredactAgent SCM service exists.

    This service uses the pywin32/pythonservice.exe host and is known to fail
    with WinError 1053 on this host. It should be migrated to the Task Scheduler
    backend.
    """
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(  # noqa: S603 - fixed binary
            [_system_exe("sc.exe"), "query", LEGACY_SCM_SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        # Return code 0 means service exists (even if STOPPED)
        # Return code 1060 (ERROR_SERVICE_DOES_NOT_EXIST) means it doesn't exist
        return result.returncode == 0
    except Exception:
        return False


def _legacy_scm_service_state() -> str | None:
    """Return the state of the legacy SCM service if it exists, else None."""
    if sys.platform != "win32":
        return None
    try:
        result = subprocess.run(  # noqa: S603 - fixed binary
            [_system_exe("sc.exe"), "query", LEGACY_SCM_SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("STATE"):
                # STATE : 1  STOPPED  (or RUNNING, etc.)
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2].lower()
        return "unknown"
    except Exception:
        return None


def _resolve_runtime_root(runtime_python: Path | None = None) -> Path | None:
    """Return the canonical machine-runtime root used for matching agent PIDs.

    The agent loop runs from ``<ProgramData>\\Securedact\\runtime`` (see
    :func:`securedact_mcp.agent.deploy.default_runtime_path`). We match on the
    *directory root* rather than the exact interpreter path so that any future
    interpreter swap (python.exe / pythonw.exe / patched version) inside the
    same runtime is still detected as "ours".
    """

    if runtime_python is not None:
        # runtime_python is the in-runtime interpreter; its parent chain
        # includes ``<runtime>`` (i.e. ``.../runtime/Scripts/python.exe``).
        # Walk up until the directory whose name is the runtime dirname.
        candidate = runtime_python.resolve().parent
        for _ in range(4):
            if candidate.name == "runtime" and candidate.parent.name == "Securedact":
                return candidate
            if candidate.parent == candidate:
                break
            candidate = candidate.parent
        # Fall through to the deploy-derived default.
    try:
        from . import deploy

        return deploy.default_runtime_path()
    except Exception:
        return None


def _is_managed_agent_process(
    executable_path: str, command_line: str, runtime_root: Path | None
) -> bool:
    """Return True iff ``(executable_path, command_line)`` matches the managed
    agent loop invocation contract.

    Conservative matching:

    * ``executable_path`` must lie inside the machine runtime root (when known).
      This excludes any non-SecuRedact python.exe (developer interpreters,
      system Python, CI helpers, foreground debug runs).
    * ``command_line`` must reference ``securedact_agent_loop.py`` — the
      launcher the scheduled task invokes. We deliberately do not match
      arbitrary python processes just because they happen to live under
      ``C:\\ProgramData\\Securedact`` (there are none, but the explicit
      command-line match future-proofs against accidentally sharing the
      runtime with another consumer).
    """

    if not executable_path or not command_line:
        return False
    if runtime_root is not None:
        try:
            runtime_prefix = str(runtime_root).lower()
        except Exception:
            runtime_prefix = ""
        if not runtime_prefix or not executable_path.lower().startswith(runtime_prefix):
            return False
    return "securedact_agent_loop.py" in command_line.lower()


def _find_agent_processes(runtime_python: Path | None = None) -> list[int]:
    """Return PIDs of running managed-agent loop processes.

    Detection is delegated to the Windows-native WMI provider
    (``Win32_Process``) via ``win32com``. The same provider is what
    ``Get-CimInstance Win32_Process`` uses, so it reaches processes running in
    other sessions (including the SYSTEM session that hosts the scheduled
    task) from a non-elevated caller. This replaces the previous
    ``wmic.exe``/``tasklist.exe`` approach, which both:

    * depended on the deprecated ``wmic.exe`` (removed from default Win11
      24H2+ installs), and
    * used localised / fragile English output parsing.

    The function is fail-safe: any exception (missing pywin32, COM init
    failure, WMI service unavailable, ACL changes, etc.) returns ``[]`` so
    that ``installed`` (driven by schtasks) is still authoritative and
    ``running`` simply reads false on a host where process inspection is
    unavailable. No command-line material is logged or returned beyond the
    list of integer PIDs.
    """
    if sys.platform != "win32":
        return []
    runtime_root = _resolve_runtime_root(runtime_python)

    if win32com_client is None:
        logger.debug("pywin32 not available; cannot enumerate agent processes")
        return []
    get_object = getattr(win32com_client, "GetObject", None)
    if get_object is None:
        return []

    query = (
        'SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process WHERE Name = "python.exe"'
    )

    try:
        wmi = get_object(r"winmgmts:\\.\root\cimv2")
    except Exception as exc:
        logger.debug("WMI connection failed: %s", scrub(str(exc)))
        return []

    try:
        procs = wmi.ExecQuery(query)
    except Exception as exc:
        logger.debug("WMI ExecQuery failed: %s", scrub(str(exc)))
        return []

    pids: list[int] = []
    try:
        for proc in procs:
            try:
                pid = int(proc.ProcessId)
                exe = str(proc.ExecutablePath or "")
                cmdline = str(proc.CommandLine or "")
            except Exception as exc:
                logger.debug("could not read WMI process record: %s", scrub(str(exc)))
                continue
            if _is_managed_agent_process(exe, cmdline, runtime_root):
                pids.append(pid)
    except Exception as exc:
        logger.debug("WMI result iteration failed: %s", scrub(str(exc)))
        return pids

    return pids


def _remove_legacy_scm_service() -> bool:
    """Stop and delete the legacy SecuredactAgent SCM service if it exists.

    Returns True if the legacy service was found and removal was attempted.
    Logs warnings but does not raise - the Task Scheduler backend is the
    canonical mechanism and legacy SCM cleanup is best-effort migration.
    """
    if sys.platform != "win32":
        return False
    if not _legacy_scm_service_exists():
        return False
    logger.warning(
        "legacy SCM service '%s' detected; removing it as part of migration to Task Scheduler",
        LEGACY_SCM_SERVICE_NAME,
    )
    try:
        # Stop the service first
        subprocess.run(  # noqa: S603 - fixed binary
            [_system_exe("sc.exe"), "stop", LEGACY_SCM_SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        # Delete the service
        result = subprocess.run(  # noqa: S603 - fixed binary
            [_system_exe("sc.exe"), "delete", LEGACY_SCM_SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            logger.info("legacy SCM service '%s' removed successfully", LEGACY_SCM_SERVICE_NAME)
        else:
            logger.warning(
                "failed to remove legacy SCM service '%s': %s",
                LEGACY_SCM_SERVICE_NAME,
                scrub(result.stderr),
            )
    except Exception as exc:
        logger.warning(
            "error removing legacy SCM service '%s': %s", LEGACY_SCM_SERVICE_NAME, scrub(str(exc))
        )
    return True


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

    # Machine-wide environment publication is a Windows (``setx /M``) operation.
    # On non-Windows there is no equivalent machine scope, so this is a safe no-op
    # and never attempts to spawn ``setx.exe``.
    if sys.platform != "win32":
        return
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
    """Return True when a scheduled task with ``name`` already exists.

    Existence is determined by the schtasks return code (``rc == 0``), not by
    parsing human-readable output. The task name is normalised so callers may
    pass either ``"SecuRedact Managed Agent"`` or the root-path form
    ``"\\SecuRedact Managed Agent"``.
    """
    r = (runner or _default_schtasks_runner)(["/Query", "/TN", _normalize_task_name(name)])
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


def _normalize_task_name(name: str) -> str:
    """Return the canonical Task Scheduler ``\\Name`` form for ``name``.

    ``schtasks.exe`` accepts both ``SecuRedact Managed Agent`` and
    ``\\SecuRedact Managed Agent`` and always emits the leading-backslash form
    in its output. We normalise here so existence detection does not depend on
    whichever surface form a caller happened to pass in.
    """
    n = name.strip().strip('"')
    if not n:
        return n
    if n.startswith("\\") or n.startswith("/"):
        return "\\" + n.lstrip("\\/").lstrip()
    return "\\" + n


def _parse_status(name: str, runner: CommandRunner) -> dict[str, object]:
    """Return the canonical status dict for a Task Scheduler task.

    Existence is determined exclusively by the process/query return code of
    ``schtasks /Query /TN <name>``. ``rc == 0`` means the task exists; any other
    code (including localised "not found" messages) means it does not. This is
    deliberately independent of /FO JSON output, which on some Windows builds
    returns non-zero even when the task is present and the default
    (``schtasks /Query``) form returns rc=0.

    Running state is determined independently by enumerating actual agent
    processes via ``tasklist`` (+ ``wmic`` for command-line verification when
    available). A host without ``wmic`` still reports ``installed=True`` for an
    existing task; only ``agent_pids`` becomes empty in that case.

    The optional ``state`` field ("ready"/"running"/"unknown") is best-effort
    and parsed from /FO JSON only. A parse failure NEVER flips ``installed`` to
    false — it merely leaves ``state`` as ``"unknown"``.
    """
    full_name = _normalize_task_name(name)

    # 1) Existence: ask schtasks in the default (TABLE) format. We deliberately
    # do NOT use ``/FO JSON`` here: on localised / older Windows builds schtasks
    # has historically returned non-zero rc for ``/FO JSON`` while the default
    # TABLE form returned rc=0 for the same task. Deciding existence from the
    # table-form return code removes that fragility entirely.
    existence = runner(["/Query", "/TN", full_name])
    installed = existence.returncode == 0

    # 2) Optional state extraction (best-effort). Only attempted when the task
    # exists. We do not depend on English human-readable fields such as
    # "Status" / "Scheduled Task State" because they are localised; the JSON
    # payload uses a stable key (``State``) but a parse failure here must not
    # affect ``installed``.
    state: str = "unknown"
    if installed:
        json_result = runner(["/Query", "/TN", full_name, "/FO", "JSON"])
        if json_result.returncode == 0 and json_result.stdout.strip():
            try:
                payload = json.loads(json_result.stdout)
            except (json.JSONDecodeError, TypeError, ValueError):
                payload = None
            if isinstance(payload, list) and payload:
                entry = payload[0]
                if isinstance(entry, dict):
                    raw = entry.get("State") or entry.get("Status")
                    if raw is not None:
                        cleaned = str(raw).strip().lower()
                        if cleaned:
                            state = cleaned

    # 3) Running detection: enumerate actual agent processes. This is fully
    # independent of the JSON payload and of ``wmic`` availability; on a host
    # without ``wmic`` we fall back to matching by image name only and
    # ``agent_pids`` is returned empty.
    from . import deploy

    runtime = deploy.default_runtime_path()
    runtime_python = runtime / "Scripts" / "python.exe"
    agent_pids = _find_agent_processes(runtime_python if runtime_python.exists() else None)

    legacy_exists = _legacy_scm_service_exists()
    legacy_state = _legacy_scm_service_state() if legacy_exists else None

    return {
        "installed": installed,
        "service_name": SCHEDULED_TASK_NAME,
        "state": state,
        "running": len(agent_pids) > 0,
        "agent_pids": agent_pids,
        "legacy_scm_service": legacy_exists,
        "legacy_scm_state": legacy_state,
    }


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
    from .config import AgentFiles, load_config

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

    # Migration: remove legacy SCM service if present (best-effort).
    # The Task Scheduler backend is the canonical mechanism; the legacy
    # pywin32/SCM service is known to fail with WinError 1053 on this host.
    _remove_legacy_scm_service()

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
    else:
        # Reuse existing registration: load agent_id from persisted config so
        # the result reports the correct agent identity instead of None.
        try:
            existing_config = load_config(AgentFiles.resolve(root=resolved / "agent"))
            agent_id = existing_config.agent_id
        except Exception:  # noqa: S110 - config missing is expected when no registration exists
            # If no config exists, agent_id remains None (caller will see this).
            pass

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
        "legacy_scm_removed": _legacy_scm_service_exists()
        is False,  # True if no legacy service remains
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
