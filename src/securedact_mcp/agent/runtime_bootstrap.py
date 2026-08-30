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

# ---------------------------------------------------------------------------
# Build capabilities (staleness gate)
# ---------------------------------------------------------------------------
#
# The machine runtime is a *separately installed distribution*. A stale runtime can
# therefore import ``securedact_mcp.agent.runtime_bootstrap`` successfully while
# still lacking a subcommand the provisioning wizard is about to depend on (the
# real defect: a runtime whose bootstrap had no ``google-auth`` command at all, so
# routing authorization into it would have failed with
# ``invalid choice: 'google-auth'``). The provisioning probe asserts the exact
# capability it needs through :func:`supports`, which a stale build does not even
# expose — so the probe fails closed instead of "succeeding" against a runtime that
# cannot perform the operation.
BOOTSTRAP_CAPABILITIES = frozenset(
    {
        "google-auth",  # the ``google-auth`` subcommand exists
        "google-auth-loopback",  # ... with the in-runtime loopback flow
        "google-auth-verify",  # ... and the no-browser/no-token verification mode
        "google-auth-byo",  # ... and it accepts the non-secret --google-byo flag
    }
)


def supports(*capabilities: str) -> bool:
    """Return True when this bootstrap build exposes every named capability.

    Used by the machine-runtime provisioning/readiness probes. Calling it in a
    stale runtime raises ``AttributeError``/``ImportError`` in the child process,
    which the probes treat as "capability missing" (fail closed).
    """

    return all(capability in BOOTSTRAP_CAPABILITIES for capability in capabilities)


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

    # Machine-local Google OAuth authorization. Runs INSIDE the machine-owned
    # runtime (which carries the Google extra), so the same Google code that the
    # scheduled agent uses is what authorizes. The preferred production path is
    # ``--loopback``: a temporary listener bound to 127.0.0.1 on a random port
    # captures the redirect, validates state, and exchanges the code in-process
    # (PKCE). The manual two-phase fallback is ``--begin`` (consent URL + state as
    # JSON) followed by ``--code-stdin`` (reads the pasted code from stdin). No
    # OAuth secret/token/code is ever printed or placed on argv.
    google_auth = sub.add_parser(
        "google-auth", help="machine-local Google OAuth authorization (loopback or two-phase)"
    )
    google_auth.add_argument("--data-dir", required=True)
    google_auth.add_argument(
        "--loopback",
        action="store_true",
        help="run the full local loopback OAuth flow and store the token",
    )
    google_auth.add_argument(
        "--begin", action="store_true", help="print the consent URL + state as JSON"
    )
    google_auth.add_argument(
        "--code-stdin", action="store_true", help="read the authorization code from stdin"
    )
    google_auth.add_argument("--state", default="")
    google_auth.add_argument("--non-interactive", action="store_true")
    # Non-secret marker that the operator explicitly opted into their own Google
    # Cloud OAuth app (advanced/enterprise). The BYO client id/secret itself is
    # resolved from the encrypted machine-local client store / environment, never
    # from argv — this flag only records the selection. It MUST be accepted here
    # because the setup wizard appends it to the loopback argv; a bootstrap that
    # rejected it turned every BYO authorization into an argparse failure.
    google_auth.add_argument(
        "--google-byo",
        action="store_true",
        help="operator uses their own Google Cloud OAuth app (non-secret marker only)",
    )
    # Verification (dry-run) mode: prove THIS interpreter can perform the whole
    # machine-local loopback authorization — import the Google extra, resolve the
    # machine-local config, bind the 127.0.0.1 listener, and build the PKCE consent
    # URL — without opening a browser, without a real token, and without network.
    google_auth.add_argument(
        "--verify",
        action="store_true",
        help="verify this interpreter can authorize (no browser, no token, no network)",
    )
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

    if arguments.cmd == "google-auth":
        return _cmd_google_auth(arguments)

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


def _cmd_google_auth(arguments: Any) -> int:
    """Run a machine-local Google OAuth step inside the machine-owned runtime.

    ``--verify`` proves this interpreter can authorize (imports + config + loopback
    bind + consent URL) and exits without a browser/token. ``--loopback`` runs the
    real flow. ``--begin`` emits the consent URL + CSRF state (JSON). The exchange
    reads the code from stdin (``--code-stdin``) or an interactive prompt, persists
    the token encrypted under the machine data root, and emits
    ``{"authorized": bool}``. Any failure is reported as a safe JSON error; no
    secret/token is ever returned.
    """

    from . import google_setup

    try:
        if getattr(arguments, "verify", False):
            # No browser, no token, no network: a pure capability proof of the
            # interpreter that actually performs the authorization.
            payload = google_setup.verify_google_authorization_runtime(arguments.data_dir)
            print(json.dumps(payload))
            return 0 if payload.get("verified") else 2
        if arguments.loopback:
            payload = google_setup.run_google_loopback_authorization(arguments.data_dir)
            print(json.dumps(payload))
            return 0 if payload.get("authorized") else 2
        if arguments.begin:
            url, state = google_setup.begin_google_authorization(arguments.data_dir)
            print(json.dumps({"url": url, "state": state}))
            return 0
        code = sys.stdin.readline().strip() if arguments.code_stdin else None
        if code is None and not arguments.non_interactive:
            code = input("Paste the 'code' value (or the full redirect URL): ").strip()
        if not code:
            print(json.dumps({"authorized": False, "error": "no authorization code"}))
            return 2
        code = google_setup._extract_code(code)
        ok = google_setup.complete_google_authorization(arguments.data_dir, code, arguments.state)
        print(json.dumps({"authorized": bool(ok)}))
        return 0 if ok else 2
    except Exception as exc:  # fail closed; surface only a safe message
        payload = {
            "authorized": False,
            "stage": "google_auth_unexpected",
            "error_code": "google_auth_unexpected_error",
            "error": scrub(str(exc)),
            "interpreter": sys.executable,
        }
        if getattr(arguments, "verify", False):
            payload["verified"] = False
        print(json.dumps(payload))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
