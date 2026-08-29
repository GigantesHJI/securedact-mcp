from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol, TextIO, cast

from .agent import cli as agent_cli
from .model_installer import (
    InstallationProgress,
    InstallerState,
    ModelDownloadError,
    ModelInstaller,
    offline_flair_load_test,
)
from .model_registry import (
    SUPPORTED_MODELS,
    SupportedModel,
    model_for_language,
    models_for_selection,
    runtime_components_for_model,
)
from .model_store import (
    ModelConfigurationError,
    ModelIntegrityError,
    ModelPathError,
    ModelStore,
)

InputFunction = Callable[[str], str]
InstallerFactory = Callable[[ModelStore, Callable[[InstallationProgress], None]], ModelInstaller]


class _GoogleCliCommands(Protocol):
    """Structural type for the optional Google connector CLI module."""

    def build_google_parser(self, subparsers: object) -> None: ...
    def run_google(self, arguments: object, *, input_fn: InputFunction, output: TextIO) -> int: ...


def _load_google_cli_commands() -> _GoogleCliCommands | None:
    """Dynamically load the optional Google connector CLI module.

    Returns ``None`` when the optional connector package is not installed so the
    base CLI and ``agent`` command work without it. The module is cast to the
    narrow :class:`_GoogleCliCommands` Protocol at this single boundary, so mypy
    never statically resolves the absent optional package on a clean checkout.
    """
    try:
        module = importlib.import_module("securedact_mcp.connectors.google.cli_commands")
    except ModuleNotFoundError:
        return None
    return cast(_GoogleCliCommands, module)


def _default_installer_factory(
    store: ModelStore,
    progress: Callable[[InstallationProgress], None],
) -> ModelInstaller:
    return ModelInstaller(store, progress=progress)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securedact-mcp",
        description="Securedact MCP local privacy server and model setup",
    )
    commands = parser.add_subparsers(dest="command")

    install = commands.add_parser("install", help="complete guided Securedact model setup")
    install.add_argument("--language", choices=("english", "dutch", "all", "none"))
    install.add_argument(
        "--accept-upstream-terms",
        action="store_true",
        help="explicitly accept third-party model terms for non-interactive download",
    )

    setup = commands.add_parser("setup", help="guide model and provider integration setup")
    setup.add_argument("--host", choices=("claude", "gemini", "all"))
    setup.add_argument("--language", choices=("english", "dutch", "all", "none"))
    setup.add_argument(
        "--accept-upstream-terms",
        action="store_true",
        help="reuse explicit upstream acceptance for a selected non-interactive model install",
    )
    setup.add_argument(
        "--non-interactive",
        action="store_true",
        help="report readiness without assuming model terms or provider trust",
    )
    setup.add_argument(
        "--agent",
        action="store_true",
        help="run only the Managed Agent module (idempotent rerun, e.g. after setup)",
    )
    setup.add_argument(
        "--agent-elevated",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    setup.add_argument(
        "--no-agent",
        action="store_true",
        help="skip the Managed Agent background-service module during setup",
    )
    setup.add_argument(
        "--google",
        choices=("yes", "no"),
        default=None,
        help="enable/disable Google Workspace onboarding during setup "
        "(default: auto-detect via SECUREDACT_GOOGLE_ENABLED)",
    )
    setup.add_argument(
        "--google-integration-id",
        default=None,
        help="Google Workspace integration ID from the SecuRedact dashboard to "
        "bind locally (skips the interactive prompt)",
    )

    models = commands.add_parser("models", help="inspect and maintain local contextual models")
    model_commands = models.add_subparsers(dest="model_command", required=True)
    model_commands.add_parser("list", help="list registry-supported models")
    model_commands.add_parser("status", help="show configured model states")
    model_commands.add_parser("verify", help="verify configured models and local hashes")
    model_commands.add_parser("diagnose", help="report safe managed-runtime readiness details")
    model_commands.add_parser("path", help="print the managed model directory")

    update = model_commands.add_parser("update", help="install the pinned registry revision")
    update.add_argument("language", choices=("english", "dutch"))
    update.add_argument("--accept-upstream-terms", action="store_true")

    repair = model_commands.add_parser(
        "repair",
        help="repair pinned runtime dependencies without redownloading valid checkpoints",
    )
    repair.add_argument("language", choices=("english", "dutch", "all"))
    repair.add_argument("--accept-upstream-terms", action="store_true")

    remove = model_commands.add_parser("remove", help="remove one managed model")
    remove.add_argument("language", choices=("english", "dutch"))
    remove.add_argument("--yes", action="store_true", help="confirm removal non-interactively")

    diagnostics = commands.add_parser(
        "diagnostics", help="report sanitized production-runtime readiness"
    )
    diagnostic_commands = diagnostics.add_subparsers(dest="diagnostic_command", required=True)
    diagnostic_commands.add_parser("runtime", help="inspect the production detector lifecycle")

    google_cli_commands = _load_google_cli_commands()
    if google_cli_commands is not None:
        google_cli_commands.build_google_parser(commands)
    agent_cli.build_agent_parser(commands)
    return parser


def _format_bytes(value: int | None) -> str:
    if value is None:
        return "unknown"
    return f"{value / (1024**3):.2f} GiB ({value:,} bytes)"


def _show_model_terms(model: SupportedModel, target: Path, output: TextIO) -> None:
    print(file=output)
    print(f"Model: {model.display_name}", file=output)
    print(f"Language: {model.language_name}", file=output)
    print(f"Official source: {model.official_url}", file=output)
    print(f"Revision: {model.upstream_revision}", file=output)
    print(f"Approximate download: {_format_bytes(model.approximate_size_bytes)}", file=output)
    print(f"Install location: {target}", file=output)
    print(file=output)
    print("Licensing note:", file=output)
    print(model.license_note or "No upstream model-weight license metadata was found.", file=output)
    if model.license_identifier:
        print(f"License identifier: {model.license_identifier}", file=output)
    print(file=output)
    print("Citation:", file=output)
    print(model.citation or "No citation supplied by the upstream model card.", file=output)
    for component in runtime_components_for_model(model):
        print(file=output)
        print(f"Required runtime component: {component.display_name}", file=output)
        print(f"Official source: {component.official_url}", file=output)
        print(f"Revision: {component.upstream_revision}", file=output)
        print(
            f"Approximate component download: {_format_bytes(component.approximate_size_bytes)}",
            file=output,
        )
        print(
            f"License: {component.license_identifier or 'not clearly specified'}",
            file=output,
        )
        if component.license_note:
            print(component.license_note, file=output)


def _choose_language(input_fn: InputFunction, output: TextIO) -> str:
    print("Securedact MCP requires a local contextual model.", file=output)
    print(file=output)
    print("Choose model support:", file=output)
    print("1. English", file=output)
    print("2. Dutch", file=output)
    print("3. English and Dutch", file=output)
    print("4. Continue without contextual models", file=output)
    try:
        choice = input_fn("Selection [1-4]: ").strip()
    except EOFError as exc:
        raise ValueError("No language selection was provided") from exc
    try:
        return {"1": "english", "2": "dutch", "3": "all", "4": "none"}[choice]
    except KeyError as exc:
        raise ValueError("Choose 1, 2, 3, or 4") from exc


def _confirm(prompt: str, input_fn: InputFunction) -> bool:
    try:
        answer = input_fn(prompt).strip().casefold()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _progress_printer(output: TextIO) -> Callable[[InstallationProgress], None]:
    def report(event: InstallationProgress) -> None:
        print(f"[{event.state.value}] {event.model_id}: {event.message}", file=output)

    return report


def run_guided_install(
    *,
    language: str | None,
    accept_upstream_terms: bool,
    input_fn: InputFunction = input,
    output: TextIO = sys.stderr,
    store: ModelStore | None = None,
    installer_factory: InstallerFactory = _default_installer_factory,
) -> int:
    model_store = store or ModelStore.resolve()
    interactive = language is None
    try:
        selection = _choose_language(input_fn, output) if interactive else language
        assert selection is not None
        selected = models_for_selection(selection)
        if not selected:
            model_store.configure_languages([])
            print(file=output)
            print("Contextual Flair detection is not installed.", file=output)
            print(
                "Securedact will fail closed when the selected policy requires it.",
                file=output,
            )
            print(file=output)
            print(
                "Reduced regex-only development mode must be enabled explicitly and is not "
                "recommended for real sensitive data.",
                file=output,
            )
            return 0

        if not interactive and not accept_upstream_terms:
            print(
                "Non-interactive model installation requires --accept-upstream-terms.",
                file=output,
            )
            return 2

        installer = installer_factory(model_store, _progress_printer(output))
        for model in selected:
            try:
                existing = model_store.verify_model(model)
            except ModelIntegrityError:
                existing = None
            _show_model_terms(model, model_store.model_path(model), output)
            if existing is None and not accept_upstream_terms:
                print(
                    f"[{InstallerState.AWAITING_CONSENT.value}] {model.id}: "
                    "awaiting explicit download consent",
                    file=output,
                )
                if not _confirm("Download and install this model now? [y/N] ", input_fn):
                    print("Model download cancelled; configuration was not changed.", file=output)
                    return 2
            installer.install(model)

        model_store.configure_languages([model.language for model in selected])
        print(file=output)
        print("Securedact MCP model setup is ready for offline runtime use.", file=output)
        return 0
    except (ValueError, ModelDownloadError, ModelIntegrityError, ModelConfigurationError) as exc:
        print(f"Installation failed safely: {exc}", file=output)
        return 2


def _models_list(output: TextIO) -> int:
    for model in SUPPORTED_MODELS:
        print(
            f"{model.id}\t{model.language}\t{model.upstream_repo}\t{model.upstream_revision}",
            file=output,
        )
    return 0


def _models_status(store: ModelStore, output: TextIO) -> int:
    try:
        state = store.load_managed_state()
    except ModelConfigurationError as exc:
        print(f"configuration\tcorrupt\t{exc}", file=output)
        return 2
    enabled = set(state.active_models) if state.configuration else {"en"}
    result = 0
    for model in SUPPORTED_MODELS:
        if model.language in state.active_models:
            verified = state.verified_models.get(model.language)
        else:
            try:
                verified = store.verify_model(model)
            except ModelIntegrityError:
                verified = None
        ready = False
        if verified is not None:
            try:
                offline_flair_load_test(
                    verified.entrypoint,
                    store.paths.runtime_cache_root,
                )
                ready = True
            except ModelDownloadError:
                ready = False
        if ready:
            model_state = InstallerState.READY
        else:
            model_state = InstallerState.NOT_INSTALLED
            if model.language in enabled:
                result = 2
        marker = "enabled" if model.language in enabled else "disabled"
        print(f"{model.language}\t{model.id}\t{model_state.value}\t{marker}", file=output)
    return result


def _models_verify(store: ModelStore, output: TextIO) -> int:
    try:
        state = store.load_managed_state()
    except ModelConfigurationError as exc:
        print(f"Model verification failed: {exc}", file=output)
        return 2
    configuration = state.configuration
    if configuration is not None and not configuration.enabled_languages:
        print("No contextual models are enabled; secure policies will fail closed.", file=output)
        return 0
    languages = list(state.active_models) if configuration else ["en"]
    for language in languages:
        model = model_for_language(language)
        try:
            verified = state.verified_models.get(language)
            if verified is None:
                if configuration is not None:
                    print(f"{model.id}: verification failed", file=output)
                    return 2
                verified = store.verify_model(model)
            offline_flair_load_test(verified.entrypoint, store.paths.runtime_cache_root)
        except (ModelDownloadError, ModelIntegrityError) as exc:
            print(f"{model.id}: verification failed: {exc}", file=output)
            return 2
        print(f"{model.id}: verified", file=output)
    return 0


def _models_diagnose(store: ModelStore, output: TextIO) -> int:
    from .server import runtime_diagnostics

    try:
        state = store.load_managed_state()
        details = runtime_diagnostics(store=store, managed_state=state)
    except ModelConfigurationError:
        details = {
            "config_found": store.paths.config_path.is_file(),
            "enabled_languages": [],
            "active_model_ids": {},
            "verified_model_states": {},
            "runtime_detector_states": [],
            "protocol_ready": False,
            "deterministic_detectors_ready": False,
            "regex_detector": "unknown",
            "email_rule": "unknown",
            "contextual_state": "failed",
            "language_states": {},
            "contextual_ready": False,
            "full_engine_ready": False,
            "final_failure_code": "contextual_model_manifest_invalid",
            "runtime_failure_code": "contextual_model_manifest_invalid",
        }
    print(json.dumps(details, indent=2, sort_keys=True), file=output)
    return 0 if details["final_failure_code"] is None else 2


def _models_update(
    language: str,
    *,
    accepted: bool,
    input_fn: InputFunction,
    output: TextIO,
    store: ModelStore,
    installer_factory: InstallerFactory,
) -> int:
    model = model_for_language(language)
    _show_model_terms(model, store.model_path(model), output)
    if not accepted:
        print(
            f"[{InstallerState.AWAITING_CONSENT.value}] {model.id}: "
            "awaiting explicit download consent",
            file=output,
        )
        if not _confirm("Download and install this pinned model now? [y/N] ", input_fn):
            print("Model update cancelled.", file=output)
            return 2
    try:
        installer_factory(store, _progress_printer(output)).install(model)
        configuration = store.read_configuration()
        enabled = set(configuration.enabled_languages if configuration else [])
        enabled.add(model.language)
        store.configure_languages(sorted(enabled))
    except (ModelDownloadError, ModelIntegrityError, ModelConfigurationError) as exc:
        print(f"Model update failed safely: {exc}", file=output)
        return 2
    return 0


def _models_repair(
    language: str,
    *,
    accepted: bool,
    input_fn: InputFunction,
    output: TextIO,
    store: ModelStore,
    installer_factory: InstallerFactory,
) -> int:
    selected = models_for_selection(language)
    if not accepted:
        for model in selected:
            _show_model_terms(model, store.model_path(model), output)
        print(
            f"[{InstallerState.AWAITING_CONSENT.value}] runtime dependencies: "
            "awaiting explicit download consent",
            file=output,
        )
        if not _confirm("Download and repair pinned runtime dependencies now? [y/N] ", input_fn):
            print("Model repair cancelled; existing checkpoints were not changed.", file=output)
            return 2
    installer = installer_factory(store, _progress_printer(output))
    try:
        for model in selected:
            installer.repair(model)
        configuration = store.read_configuration()
        enabled = set(configuration.enabled_languages if configuration else [])
        enabled.update(model.language for model in selected)
        store.configure_languages(sorted(enabled))
    except (ModelDownloadError, ModelIntegrityError, ModelConfigurationError) as exc:
        print(f"Model repair failed safely: {exc}", file=output)
        return 2
    return 0


def _models_remove(
    language: str,
    *,
    confirmed: bool,
    input_fn: InputFunction,
    output: TextIO,
    store: ModelStore,
) -> int:
    model = model_for_language(language)
    if not confirmed:
        if not _confirm(f"Remove the managed {model.language_name} model? [y/N] ", input_fn):
            print("Model removal cancelled.", file=output)
            return 2
    try:
        removed = store.remove_model(model)
    except (ModelConfigurationError, ModelIntegrityError) as exc:
        print(f"Model removal failed safely: {exc}", file=output)
        return 2
    print(f"{model.id}: {'removed' if removed else 'not installed'}", file=output)
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    input_fn: InputFunction = input,
    output: TextIO = sys.stderr,
) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command is None:
        from .server import main as server_main

        server_main()
        return 0
    if arguments.command == "install":
        return run_guided_install(
            language=arguments.language,
            accept_upstream_terms=arguments.accept_upstream_terms,
            input_fn=input_fn,
            output=output,
        )
    if arguments.command == "setup":
        from .onboarding import run_setup

        agent_mode = "no" if getattr(arguments, "no_agent", False) else None
        agent_only = bool(getattr(arguments, "agent", False))
        if agent_only and agent_mode is None:
            agent_mode = "yes"
        return run_setup(
            host=arguments.host,
            language=arguments.language,
            accept_upstream_terms=arguments.accept_upstream_terms,
            non_interactive=arguments.non_interactive,
            install_models=run_guided_install,
            verify_models=_models_verify,
            input_fn=input_fn,
            output=output,
            agent=agent_mode,
            agent_only=agent_only,
            agent_elevated=bool(getattr(arguments, "agent_elevated", False)),
            google=getattr(arguments, "google", None),
            google_integration_id=getattr(arguments, "google_integration_id", None),
        )

    diagnose_runtime = arguments.command == "diagnostics"

    if arguments.command == "google":
        google_cli_commands = _load_google_cli_commands()
        if google_cli_commands is None:
            print("The optional Google connector is not installed.", file=output)
            return 2
        return google_cli_commands.run_google(arguments, input_fn=input_fn, output=output)

    if arguments.command == "agent":
        return agent_cli.run_agent(arguments, input_fn=input_fn, output=output)

    try:
        store = ModelStore.resolve()
    except ModelPathError:
        if diagnose_runtime or getattr(arguments, "model_command", None) == "diagnose":
            print(
                json.dumps(
                    {
                        "config_found": False,
                        "enabled_languages": [],
                        "active_model_ids": {},
                        "verified_model_states": {},
                        "runtime_detector_states": [],
                        "protocol_ready": False,
                        "deterministic_detectors_ready": False,
                        "regex_detector": "unknown",
                        "email_rule": "unknown",
                        "contextual_state": "failed",
                        "language_states": {},
                        "contextual_ready": False,
                        "full_engine_ready": False,
                        "final_failure_code": "contextual_model_storage_invalid",
                        "runtime_failure_code": "contextual_model_storage_invalid",
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=output,
            )
            return 2
        print("The managed model storage location is not allowed.", file=output)
        return 2
    if diagnose_runtime:
        return _models_diagnose(store, output)
    if arguments.model_command == "list":
        return _models_list(output)
    if arguments.model_command == "status":
        return _models_status(store, output)
    if arguments.model_command == "verify":
        return _models_verify(store, output)
    if arguments.model_command == "diagnose":
        return _models_diagnose(store, output)
    if arguments.model_command == "path":
        print(store.paths.model_root, file=sys.stdout)
        return 0
    if arguments.model_command == "update":
        return _models_update(
            arguments.language,
            accepted=arguments.accept_upstream_terms,
            input_fn=input_fn,
            output=output,
            store=store,
            installer_factory=_default_installer_factory,
        )
    if arguments.model_command == "repair":
        return _models_repair(
            arguments.language,
            accepted=arguments.accept_upstream_terms,
            input_fn=input_fn,
            output=output,
            store=store,
            installer_factory=_default_installer_factory,
        )
    if arguments.model_command == "remove":
        return _models_remove(
            arguments.language,
            confirmed=arguments.yes,
            input_fn=input_fn,
            output=output,
            store=store,
        )
    raise AssertionError("unhandled command")


if __name__ == "__main__":
    raise SystemExit(main())
