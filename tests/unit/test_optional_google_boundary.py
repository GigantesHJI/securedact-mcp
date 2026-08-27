# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the optional Google connector typing boundary (AGENT-015/CI).

These prove the managed-agent code and base CLI never statically or eagerly
depend on the optional Google connector package, which is absent on a clean
checkout. The boundary is exercised by making the optional modules importable
only on demand (and failing closed when they are missing).
"""

from __future__ import annotations

import importlib
import io

import pytest

import securedact_mcp.agent.provider_google as provider_google
import securedact_mcp.cli as cli
from securedact_mcp.agent.provider_google import GoogleScanProvider

GOOGLE_PREFIX = "securedact_mcp.connectors.google"


def _make_google_absent(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Force every optional Google module import to fail, as on a clean checkout.

    Returns the list of attempted Google module names so tests can assert the
    import is attempted only at the Google-only execution path, never eagerly.
    """

    attempted: list[str] = []
    real_import_module = importlib.import_module

    def _fake_import_module(name: str, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name.startswith(GOOGLE_PREFIX):
            attempted.append(name)
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(cli.importlib, "import_module", _fake_import_module)
    monkeypatch.setattr(provider_google.importlib, "import_module", _fake_import_module)
    return attempted


def test_base_parser_builds_without_optional_google_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempted = _make_google_absent(monkeypatch)

    parser = cli.build_parser()

    # A normal base command still parses fine without the optional connector.
    args = parser.parse_args(["models", "list"])
    assert args.command == "models"
    # The optional Google loader reports absence (the dynamic import failed closed).
    assert cli._load_google_cli_commands() is None
    # The optional module was loaded dynamically (not statically), and absence was
    # handled at runtime without breaking the base parser.
    assert any(n.endswith("cli_commands") for n in attempted)


def test_agent_parser_builds_without_optional_google_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_google_absent(monkeypatch)

    parser = cli.build_parser()

    # The managed-agent command must be available and parseable without Google.
    args = parser.parse_args(["agent", "status"])
    assert args.command == "agent"
    assert args.agent_command == "status"
    assert cli._load_google_cli_commands() is None


def test_importing_provider_google_does_not_import_connector_eagerly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempted = _make_google_absent(monkeypatch)

    # Re-import to ensure no cached module masks the patch.
    import sys

    sys.modules.pop("securedact_mcp.agent.provider_google", None)
    # Clear any connector module left in sys.modules by an earlier test so this
    # assertion measures only what provider_google itself imports.
    for _name in list(sys.modules):
        if _name == GOOGLE_PREFIX or _name.startswith(f"{GOOGLE_PREFIX}."):
            sys.modules.pop(_name, None)
    importlib.import_module("securedact_mcp.agent.provider_google")

    # Importing the provider must not touch the optional package.
    assert GOOGLE_PREFIX not in sys.modules
    assert attempted == []

    # Constructing the provider is equally lazy.
    provider = GoogleScanProvider()
    assert attempted == []

    # Only when a scan is actually invoked does the provider attempt the import,
    # and it fails closed with a safe JobExecutionError (never ModuleNotFoundError).
    with pytest.raises(Exception) as exc_info:
        provider.scan(object(), object(), object())  # type: ignore[arg-type]
    assert attempted and all(n.startswith(GOOGLE_PREFIX) for n in attempted)
    assert type(exc_info.value).__name__ == "JobExecutionError"


def test_optional_google_module_return_is_int_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dynamic Google module is typed via a Protocol, so main() -> int is sound."""

    class _FakeGoogleCommands:
        def __init__(self) -> None:
            self.build_called = False

        def build_google_parser(self, subparsers: object) -> None:
            self.build_called = True
            # Register a minimal 'google' subcommand so the dispatch path is exercised.
            google = subparsers.add_parser("google")  # type: ignore[attr-defined]
            google_subs = google.add_subparsers(dest="google_command", required=True)
            google_subs.add_parser("status")

        def run_google(self, arguments: object, *, input_fn, output: io.TextIOBase) -> int:
            return 7

    fake = _FakeGoogleCommands()
    monkeypatch.setattr(cli, "_load_google_cli_commands", lambda: fake)

    cli.build_parser()
    assert fake.build_called is True

    result = cli.main(["google", "status"], output=io.StringIO())
    assert isinstance(result, int)
    assert result == 7


def test_google_subcommand_absent_from_base_parser_when_optional_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_google_absent(monkeypatch)

    parser = cli.build_parser()
    # argparse itself rejects the unregistered command with a safe exit (not a
    # ModuleNotFoundError), proving Google-specific functionality only fails when
    # actually invoked without its optional implementation.
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["google", "status"])
    assert exc_info.value.code == 2
