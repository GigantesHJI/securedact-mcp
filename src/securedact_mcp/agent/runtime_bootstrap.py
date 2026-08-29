# SPDX-License-Identifier: Apache-2.0
"""Minimal entrypoint executed by the *machine-owned* runtime python.

``securedact-mcp setup --agent`` provisions a dedicated, admin-owned Python
environment under ``C:\\ProgramData\\Securedact\\runtime`` and then drives service
install/control through *that* interpreter. This module is the thin, safe shim the
secure runtime runs: it never places the registration token on the command line or
in the environment — the token is read from stdin (``--token-stdin``) and used
in-memory only.

The service account, data dir, and ACL hardening are performed by the active
Task Scheduler backend (:mod:`securedact_mcp.agent.service_taskscheduler`) via
:mod:`securedact_mcp.agent.service`; this module just routes the request into it
under the correct (machine-owned) interpreter. The legacy pywin32/SCM service
(``service_windows``) is a disabled reference and is not used here.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import service
from .safe_log import scrub


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securedact-mcp-agent-runtime-bootstrap")
    sub = parser.add_subparsers(dest="cmd", required=True)

    install = sub.add_parser(
        "install-from-runtime",
        help="install + register + start the service (token from stdin)",
    )
    install.add_argument("--data-dir")
    install.add_argument("--control-plane-url")
    install.add_argument("--display-name")
    install.add_argument(
        "--token-stdin",
        action="store_true",
        help="read the one-time registration token from the first stdin line",
    )

    for name in ("stop", "start", "status", "uninstall"):
        sub.add_parser(name, help=f"{name} the background service")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    arguments = _build_parser().parse_args(argv)

    if arguments.cmd == "install-from-runtime":
        token: str | None = None
        if arguments.token_stdin:
            token = sys.stdin.readline().strip()
        if not token:
            print(json.dumps({"error": "missing registration token on stdin"}))
            return 2
        try:
            result = service.install_service(
                data_dir=arguments.data_dir,
                start=True,
                control_plane_url=arguments.control_plane_url,
                display_name=arguments.display_name,
                token=token,
            )
        except Exception as exc:  # fail closed, surface safe message only
            print(json.dumps({"error": scrub(str(exc))}))
            return 2
        print(json.dumps(result))
        return 0

    handler = {
        "stop": service.stop_service,
        "start": service.start_service,
        "status": service.query_service_status,
        "uninstall": service.uninstall_service,
    }.get(arguments.cmd)
    if handler is None:
        print(json.dumps({"error": f"unknown command: {arguments.cmd}"}))
        return 2
    try:
        payload: dict[str, Any] = handler()
    except Exception as exc:
        print(json.dumps({"error": scrub(str(exc))}))
        return 2
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
