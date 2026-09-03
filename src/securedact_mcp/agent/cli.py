# SPDX-License-Identifier: Apache-2.0
"""CLI surface for the managed local agent (AGENT-017).

Exposes ``securedact-mcp agent <subcommand>`` for registration, status, the
pull loop, credential rotation, entitlement verification, heartbeat, and local
connector binding. No credential secret or entitlement token is printed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from . import agent_runner, service
from .config import AgentConfig, AgentFiles, load_config
from .connectors import SUPPORTED_BINDING_PLATFORMS
from .credentials import AgentCredentialStore
from .errors import AgentError
from .safe_log import scrub


def build_agent_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    agent = subparsers.add_parser(
        "agent", help="managed local agent runtime for SecuRedact control plane"
    )
    commands = agent.add_subparsers(dest="agent_command", required=True)

    register = commands.add_parser("register", help="register this machine as a managed agent")
    register.add_argument("--token", required=True, help="registration token (srr_...)")
    register.add_argument("--control-plane-url", default=None)
    register.add_argument("--display-name", default=None)
    register.add_argument(
        "--install-service",
        action="store_true",
        help="register and also install+start the background Windows service",
    )

    commands.add_parser("status", help="show managed-agent status")

    run = commands.add_parser("run", help="run the managed-agent pull loop (foreground/debug)")
    run.add_argument("--max-iterations", type=int, default=None)
    run.add_argument("--idle-sleep", type=float, default=30.0)
    run.add_argument(
        "--no-lock",
        action="store_true",
        help="do not acquire the single-instance lock (allows running alongside the service)",
    )

    service_cmd = commands.add_parser(
        "service", help="install/manage the background Windows agent service"
    )
    service_cmds = service_cmd.add_subparsers(dest="service_command", required=True)
    svc_install = service_cmds.add_parser("install", help="install the background service")
    svc_install.add_argument("--data-dir", default=None, help="machine-wide agent data directory")
    svc_install.add_argument("--no-start", action="store_true", help="install but do not start")
    svc_install.add_argument(
        "--token",
        default=None,
        help="also register the agent with this token (equivalent to register --install-service)",
    )
    svc_install.add_argument("--control-plane-url", default=None)
    svc_install.add_argument("--display-name", default=None)
    service_cmds.add_parser("start", help="start the background service")
    service_cmds.add_parser("stop", help="stop the background service")
    service_cmds.add_parser("status", help="show background service status")
    service_cmds.add_parser("uninstall", help="remove the background service")
    upgrade = service_cmds.add_parser(
        "upgrade", help="securely upgrade the machine-owned agent runtime (preserves state)"
    )
    upgrade.add_argument("--data-dir", default=None, help="machine-wide agent data directory")
    upgrade.add_argument("--runtime-path", default=None, help="machine-owned runtime path")
    upgrade.add_argument(
        "--google",
        action="store_true",
        help="also (re)install the Google connector dependencies into the runtime",
    )
    service_cmds.add_parser("logs", help="show the background service log location")

    commands.add_parser("rotate-credential", help="rotate the agent credential")
    commands.add_parser("heartbeat", help="send a single heartbeat")

    entitlement = commands.add_parser("entitlement", help="entitlement operations")
    entitlement_cmds = entitlement.add_subparsers(dest="entitlement_command", required=True)
    entitlement_cmds.add_parser("status", help="activate/verify the entitlement")

    connectors = commands.add_parser("connectors", help="manage local connector bindings")
    connector_cmds = connectors.add_subparsers(dest="connector_command", required=True)
    bind = connector_cmds.add_parser("bind", help="bind a local integration")
    bind.add_argument("--integration-id", required=True)
    bind.add_argument(
        "--platform",
        required=True,
        choices=sorted(SUPPORTED_BINDING_PLATFORMS),
        help="managed-agent platform (choices derived from SUPPORTED_BINDING_PLATFORMS)",
    )
    bind.add_argument("--profile", default="default")
    connector_cmds.add_parser("list", help="list bound integrations")


def _emit(payload: dict[str, object], output: TextIO) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True), file=output)


def run_agent(
    arguments: argparse.Namespace,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
    clock: object = None,
) -> int:
    clock = clock or time.time
    command = arguments.agent_command

    if command == "register":
        try:
            config = agent_runner.register_agent(
                arguments.token,
                control_plane_url=getattr(arguments, "control_plane_url", None),
                display_name=arguments.display_name,
            )
        except AgentError as exc:
            print(f"registration failed safely: {scrub(str(exc))}", file=output)
            return 2
        _emit(
            {
                "registered": True,
                "agent_id": config.agent_id,
                "control_plane_url": config.control_plane_url,
                "display_name": config.display_name,
            },
            sys.stdout,
        )
        if getattr(arguments, "install_service", False):
            return _install_service_from_args(arguments, output)
        return 0

    if command == "service":
        return _dispatch_service(arguments, output)

    try:
        config = load_config()
    except AgentError as exc:
        print(f"agent not registered: {scrub(str(exc))}", file=output)
        return 2

    if command == "status":
        status = agent_runner.agent_status(config)
        _emit(status.to_dict(), sys.stdout)
        return 0

    if command == "rotate-credential":
        try:
            agent_runner.rotate_credential(config)
        except AgentError as exc:
            print(f"credential rotation failed: {scrub(str(exc))}", file=output)
            return 2
        print("agent credential rotated", file=sys.stdout)
        return 0

    if command == "heartbeat":
        files = AgentFiles.resolve()
        store = AgentCredentialStore(config.agent_id, root=files.root)
        from .client import ControlPlaneClient

        client = ControlPlaneClient(config.control_plane_url, credential_provider=store.get)
        try:
            resp = client.heartbeat(
                agent_version=config.agent_version, capabilities=config.capabilities
            )
        except AgentError as exc:
            print(f"heartbeat failed: {scrub(str(exc))}", file=output)
            return 2
        _emit(
            {
                "agent_id": resp.agent_id,
                "server_time": resp.server_time,
                "recommended_heartbeat_seconds": resp.recommended_heartbeat_seconds,
                "entitlement_refresh_required": resp.entitlement_refresh_required,
            },
            sys.stdout,
        )
        return 0

    if command == "entitlement":
        try:
            ent = agent_runner.refresh_entitlement(config)
        except AgentError as exc:
            print(f"entitlement unavailable: {scrub(str(exc))}", file=output)
            return 2
        _emit(
            {
                "verified": True,
                "kid": ent.kid,
                "not_before": ent.not_before,
                "expires_at": ent.expires_at,
                "issuer": ent.claims.get("iss"),
                "audience": ent.claims.get("aud"),
            },
            sys.stdout,
        )
        return 0

    if command == "connectors":
        sub = arguments.connector_command
        if sub == "bind":
            try:
                binding = agent_runner.bind_connector(
                    config, arguments.integration_id, arguments.platform, profile=arguments.profile
                )
            except AgentError as exc:
                print(f"connector bind failed: {scrub(str(exc))}", file=output)
                return 2
            _emit({"bound": True, **binding.to_dict()}, sys.stdout)
            return 0
        if sub == "list":
            bindings = agent_runner.list_connectors(config)
            _emit({"bindings": [b.to_dict() for b in bindings]}, sys.stdout)
            return 0

    if command == "run":
        # Ensure the background process logs to the machine data-dir log file so
        # the scheduled-task run is diagnosable even though it has no console.
        try:
            from . import service as _svc

            _svc.configure_service_logging(_svc.resolve_service_data_dir(None))
        except Exception:  # noqa: S110  # best-effort logging setup
            pass
        return _run_loop(config, arguments, clock, output)

    print(f"unknown agent command: {command}", file=output)
    return 2


def _run_loop(
    config: AgentConfig, arguments: argparse.Namespace, clock: object, output: TextIO
) -> int:
    files = AgentFiles.resolve()
    lock_path = files.root / "agent.lock"
    if not getattr(arguments, "no_lock", False):
        from .service_lock import agent_instance_lock

        with agent_instance_lock(lock_path) as acquired:
            if not acquired:
                print(
                    "refusing to start: another Securedact agent loop is already "
                    "running (single-instance lock held). Pass --no-lock to override "
                    "(not recommended while the service is active).",
                    file=output,
                )
                return 3
            return _run_loop_inner(config, arguments, clock)
    return _run_loop_inner(config, arguments, clock)


def _run_loop_inner(config: AgentConfig, arguments: argparse.Namespace, clock: object) -> int:
    try:
        agent_runner.run_agent_loop(
            config,
            max_iterations=arguments.max_iterations,
            idle_sleep=arguments.idle_sleep,
            clock=clock,  # type: ignore[arg-type]
        )
    except AgentError as exc:
        print(f"agent run stopped: {scrub(str(exc))}", file=sys.stderr)
        return 2
    return 0


def _install_service_from_args(arguments: argparse.Namespace, output: TextIO) -> int:
    try:
        result = service.install_service(
            data_dir=getattr(arguments, "data_dir", None),
            start=not getattr(arguments, "no_start", False),
            control_plane_url=getattr(arguments, "control_plane_url", None),
            display_name=arguments.display_name,
            token=arguments.token,
        )
    except AgentError as exc:
        print(f"service install failed: {scrub(str(exc))}", file=output)
        return 2
    _emit(
        {
            "service_installed": result.get("installed"),
            "service_name": result.get("service_name"),
            "data_dir": result.get("data_dir"),
            "account": result.get("account"),
            "running": result.get("running"),
            "dev_baseline": result.get("dev_baseline"),
        },
        sys.stdout,
    )
    return 0


def _dispatch_service(arguments: argparse.Namespace, output: TextIO) -> int:
    sub = arguments.service_command
    try:
        if sub == "install":
            result = service.install_service(
                data_dir=getattr(arguments, "data_dir", None),
                start=not getattr(arguments, "no_start", False),
                control_plane_url=getattr(arguments, "control_plane_url", None),
                display_name=arguments.display_name,
                token=getattr(arguments, "token", None),
            )
            result = {**result, "dev_baseline": result.get("dev_baseline")}
        elif sub == "start":
            result = service.start_service()
        elif sub == "stop":
            result = service.stop_service()
        elif sub == "status":
            result = service.query_service_status()
        elif sub == "uninstall":
            result = service.uninstall_service()
        elif sub == "upgrade":
            from . import deploy

            try:
                result = deploy.upgrade_runtime(
                    data_dir=getattr(arguments, "data_dir", None),
                    runtime_path=getattr(arguments, "runtime_path", None),
                    google_enabled=bool(getattr(arguments, "google", False)),
                )
            except AgentError as exc:
                print(f"service upgrade failed safely: {scrub(str(exc))}", file=output)
                return 2
            _emit(result, sys.stdout)
            return 0
        elif sub == "logs":
            path = service.service_log_path(getattr(arguments, "data_dir", None))
            tail = _tail_log(path)
            print(f"service log: {path}", file=output)
            if tail:
                print(tail, file=output)
            return 0
        else:
            print(f"unknown service command: {sub}", file=output)
            return 2
    except AgentError as exc:
        print(f"service {sub} failed: {scrub(str(exc))}", file=output)
        return 2
    _emit(result, sys.stdout)
    return 0


def _tail_log(path: Path, *, lines: int = 50) -> str:
    try:
        content = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    return "\n".join(content[-lines:])


def main(
    argv: Sequence[str] | None = None,
    *,
    input_fn: Callable[[str], str] = input,
    output: TextIO = sys.stderr,
    clock: object = None,
) -> int:
    """Entry point for ``python -m securedact_mcp.agent.cli``.

    Supports both the full ``agent <subcommand>`` surface and a direct ``run``
    alias so the Windows scheduled task can launch the proven agent loop with::

        python -m securedact_mcp.agent.cli run

    which is the exact canonical equivalent of the working foreground command
    ``securedact-mcp agent run``.
    """

    import argparse

    parser = argparse.ArgumentParser(prog="securedact_mcp.agent.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    build_agent_parser(sub)
    # Direct loop entry used by the scheduled task (no ``agent`` prefix).
    run_alias = sub.add_parser("run", help="run the managed-agent pull loop")
    run_alias.add_argument("--max-iterations", type=int, default=None)
    run_alias.add_argument("--idle-sleep", type=float, default=30.0)
    run_alias.add_argument("--no-lock", action="store_true")

    arguments = parser.parse_args(argv)
    if arguments.command == "run":
        # Delegate to the shared agent ``run`` handler (sets agent_command).
        arguments.agent_command = "run"
    return run_agent(arguments, input_fn=input_fn, output=output, clock=clock)


if __name__ == "__main__":
    raise SystemExit(main())
