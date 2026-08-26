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
from typing import Callable, TextIO

from . import agent_runner
from .config import AgentFiles, load_config
from .credentials import AgentCredentialStore
from .errors import AgentError
from .safe_log import scrub


def build_agent_parser(subparsers: argparse._SubParsersAction) -> None:  # noqa: ANN401
    agent = subparsers.add_parser(
        "agent", help="managed local agent runtime for SecuRedact control plane"
    )
    commands = agent.add_subparsers(dest="agent_command", required=True)

    register = commands.add_parser("register", help="register this machine as a managed agent")
    register.add_argument("--token", required=True, help="registration token (srr_...)")
    register.add_argument("--control-plane-url", default=None)
    register.add_argument("--display-name", default=None)

    commands.add_parser("status", help="show managed-agent status")

    run = commands.add_parser("run", help="run the managed-agent pull loop")
    run.add_argument("--max-iterations", type=int, default=None)
    run.add_argument("--idle-sleep", type=float, default=30.0)

    commands.add_parser("rotate-credential", help="rotate the agent credential")
    commands.add_parser("heartbeat", help="send a single heartbeat")

    entitlement = commands.add_parser("entitlement", help="entitlement operations")
    entitlement_cmds = entitlement.add_subparsers(dest="entitlement_command", required=True)
    entitlement_cmds.add_parser("status", help="activate/verify the entitlement")

    connectors = commands.add_parser("connectors", help="manage local connector bindings")
    connector_cmds = connectors.add_subparsers(dest="connector_command", required=True)
    bind = connector_cmds.add_parser("bind", help="bind a local integration")
    bind.add_argument("--integration-id", required=True)
    bind.add_argument("--platform", required=True, choices=["google_workspace"])
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
    clock = clock or time.time  # type: ignore[assignment]
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
        return 0

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
        try:
            agent_runner.run_agent_loop(
                config,
                max_iterations=arguments.max_iterations,
                idle_sleep=arguments.idle_sleep,
                clock=clock,  # type: ignore[arg-type]
            )
        except AgentError as exc:
            print(f"agent run stopped: {scrub(str(exc))}", file=output)
            return 2
        return 0

    print(f"unknown agent command: {command}", file=output)
    return 2
