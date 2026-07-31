from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from mcp.server.fastmcp import FastMCP

from securedact_core import (
    InstalledModel,
    ModelManager,
    PrivacyEngine,
    SecuredactPaths,
)
from securedact_core.detectors import (
    ContextualPrivacyDetector,
    FlairDetector,
    LanguageAwareFlairDetector,
    RegexDetector,
)
from securedact_core.engine import ReviewRequiredError, SendingBlockedError

from .model_registry import MODELS_BY_LANGUAGE
from .model_store import (
    ManagedModelState,
    ModelConfigurationError,
    ModelPathError,
    ModelStore,
)

DEFAULT_MAX_TEXT_CHARS = 1_000_000
SUPPORTED_SAFE_COPY_SUFFIXES = {".md", ".txt"}


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    engine: PrivacyEngine
    contextual_error: str | None = None
    contextual_failure_code: str | None = None


def _build_legacy_engine() -> PrivacyEngine:
    paths = SecuredactPaths.resolve()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ.setdefault("HF_HUB_CACHE", str(paths.models / ".huggingface-cache"))
    require_flair = os.getenv("SECUREDACT_REQUIRE_FLAIR", "1") != "0"
    manager = ModelManager(
        paths,
        configured_model_id=os.getenv("SECUREDACT_MODEL_ID"),
        require_flair=require_flair,
    )
    return PrivacyEngine(
        [RegexDetector(), ContextualPrivacyDetector()],
        require_contextual=require_flair,
        model_manager=manager,
    )


def _missing_model_message(languages: list[str]) -> str:
    names = [MODELS_BY_LANGUAGE[language].language_name for language in languages]
    if len(names) == 1:
        selection = names[0].casefold()
        return (
            f"The required {names[0]} contextual model is not installed.\n\n"
            f"Run:\nsecuredact-mcp install --language {selection}"
        )
    return (
        "The required English and Dutch contextual models are not installed.\n\n"
        "Run:\nsecuredact-mcp install --language all"
    )


def build_runtime(
    *,
    store: ModelStore | None = None,
    managed_state: ManagedModelState | None = None,
) -> RuntimeBundle:
    """Build an offline runtime from verified managed models without downloading."""
    require_flair = os.getenv("SECUREDACT_REQUIRE_FLAIR", "1") != "0"
    if not require_flair:
        return RuntimeBundle(
            PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector()],
                require_contextual=False,
            )
        )

    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    try:
        model_store = store or ModelStore.resolve()
        os.environ.setdefault("HF_HUB_CACHE", str(model_store.paths.model_root / ".runtime-cache"))
        state = managed_state or model_store.load_managed_state()

        # A valid managed configuration is authoritative. Legacy development
        # variables may remain in a parent process, but they must not divert a
        # fresh MCP server away from active managed models.
        if not state.active_models and (
            os.getenv("SECUREDACT_MODEL_PATH")
            or os.getenv("SECUREDACT_FLAIR_MODEL")
            or os.getenv("SECUREDACT_MODEL_ID")
        ):
            return RuntimeBundle(_build_legacy_engine())

        if state.configuration is None:
            engine = PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector()],
                require_contextual=True,
            )
            return RuntimeBundle(
                engine,
                _missing_model_message(["en"]),
                "contextual_model_not_installed",
            )
        if not state.active_models:
            engine = PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector()],
                require_contextual=True,
            )
            return RuntimeBundle(
                engine,
                "No contextual model is enabled.\n\nRun:\nsecuredact-mcp install",
                "contextual_model_not_enabled",
            )

        detectors: dict[str, FlairDetector] = {}
        for language in state.active_models:
            verified = state.verified_models.get(language)
            if verified is None:
                continue
            fingerprint = verified.manifest.files[verified.manifest.entrypoint].sha256
            detectors[language] = FlairDetector(
                verified.entrypoint,
                model_fingerprint=fingerprint,
            )
        if state.failed_languages:
            engine = PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector()],
                require_contextual=True,
            )
            return RuntimeBundle(
                engine,
                _missing_model_message(list(state.failed_languages)),
                "contextual_model_integrity_failed",
            )
        router = LanguageAwareFlairDetector(detectors)
        return RuntimeBundle(
            PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector(), router],
                require_contextual=True,
            )
        )
    except ModelConfigurationError:
        engine = PrivacyEngine(
            [RegexDetector(), ContextualPrivacyDetector()],
            require_contextual=True,
        )
        return RuntimeBundle(
            engine,
            "The contextual model configuration could not be validated.\n\n"
            "Run:\nsecuredact-mcp install",
            "contextual_model_configuration_invalid",
        )
    except ModelPathError:
        engine = PrivacyEngine(
            [RegexDetector(), ContextualPrivacyDetector()],
            require_contextual=True,
        )
        return RuntimeBundle(
            engine,
            "The contextual model storage location is not allowed.\n\n"
            "Run:\nsecuredact-mcp models path",
            "contextual_model_storage_invalid",
        )


def build_default_engine() -> PrivacyEngine:
    return build_runtime().engine


def _load_model(
    privacy_engine: PrivacyEngine,
    manager: ModelManager,
    model: InstalledModel,
) -> None:
    os.environ["HF_HUB_CACHE"] = str(model.tokenizer_root)
    entrypoint = next(
        item for item in model.manifest.files if item.path == model.manifest.entrypoint
    )
    for existing in privacy_engine.detectors:
        if (
            existing.contextual
            and getattr(existing, "ready", False)
            and getattr(existing, "model_fingerprint", None) == entrypoint.sha256
        ):
            manager.mark_ready()
            return
    detector = FlairDetector(
        model.entrypoint,
        model_fingerprint=entrypoint.sha256,
        on_loading=manager.mark_loading,
        on_ready=manager.mark_ready,
        on_failure=manager.mark_failed,
    )
    privacy_engine.replace_contextual_detector(detector)
    detector.load()


def load_configured_model(privacy_engine: PrivacyEngine, manager: ModelManager) -> None:
    """Load only a locally configured, integrity-checked model."""
    if not manager.require_flair:
        return
    try:
        development_override = os.getenv("SECUREDACT_MODEL_PATH") or os.getenv(
            "SECUREDACT_FLAIR_MODEL"
        )
        model = (
            manager.resolve_development_override(development_override)
            if development_override
            else manager.resolve_active_model()
        )
        if model is not None:
            _load_model(privacy_engine, manager, model)
    except Exception:
        manager.mark_failed()


def _max_text_chars() -> int:
    raw_value = os.getenv("SECUREDACT_MAX_TEXT_CHARS", str(DEFAULT_MAX_TEXT_CHARS))
    try:
        value = int(raw_value)
    except ValueError:
        return DEFAULT_MAX_TEXT_CHARS
    return max(1, min(value, DEFAULT_MAX_TEXT_CHARS))


def _validate_text(text: str) -> dict[str, str] | None:
    if len(text) > _max_text_chars():
        return {"status": "blocked", "reason": "input exceeds the configured size limit"}
    return None


def _contextual_block(reason: str, failure_code: str) -> dict[str, str]:
    return {
        "status": "blocked",
        "reason": reason,
        "failure_code": failure_code,
    }


def _valid_safe_copy_filename(filename: str) -> bool:
    if not filename or filename in {".", ".."}:
        return False
    if any(separator in filename for separator in ("/", "\\")) or ":" in filename:
        return False
    path = Path(filename)
    return path.name == filename and path.suffix.lower() in SUPPORTED_SAFE_COPY_SUFFIXES


def _start_runtime(
    runtime: RuntimeBundle,
    *,
    load_legacy_model: bool,
) -> tuple[str | None, str | None]:
    privacy_engine = runtime.engine
    privacy_engine.startup()
    if load_legacy_model and privacy_engine.model_manager is not None:
        load_configured_model(privacy_engine, privacy_engine.model_manager)
    contextual_error = runtime.contextual_error
    contextual_failure_code = runtime.contextual_failure_code
    if privacy_engine.require_contextual and not privacy_engine.contextual_ready():
        contextual_error = contextual_error or (
            "The required contextual model could not be loaded.\n\n"
            "Run:\nsecuredact-mcp models verify"
        )
        contextual_failure_code = (
            contextual_failure_code
            or privacy_engine.contextual_failure_code()
            or "contextual_model_not_ready"
        )
    return contextual_error, contextual_failure_code


def runtime_diagnostics(
    *,
    store: ModelStore | None = None,
    managed_state: ManagedModelState | None = None,
) -> dict[str, Any]:
    """Return non-sensitive managed configuration and runtime readiness details."""

    model_store = store or ModelStore.resolve()
    state = managed_state or model_store.load_managed_state()
    runtime = build_runtime(store=model_store, managed_state=state)
    contextual_error, failure_code = _start_runtime(runtime, load_legacy_model=True)

    detector_states: list[dict[str, Any]] = []
    for detector in runtime.engine.detectors:
        safe_state = getattr(detector, "safe_state", None)
        detector_state = (
            str(safe_state) if safe_state in {"discovered", "failed", "ready"} else "ready"
        )
        details: dict[str, Any] = {
            "name": detector.name,
            "contextual": detector.contextual,
            "state": detector_state,
        }
        children = getattr(detector, "detectors", None)
        if isinstance(children, dict):
            details["children"] = {
                language: (
                    str(child_state)
                    if (child_state := getattr(child, "safe_state", None))
                    in {"discovered", "failed", "ready"}
                    else ("ready" if getattr(child, "ready", False) else "failed")
                )
                for language, child in children.items()
            }
        detector_states.append(details)

    configuration = state.configuration
    return {
        "config_found": state.config_found,
        "enabled_languages": list(configuration.enabled_languages) if configuration else [],
        "active_model_ids": dict(configuration.active_models) if configuration else {},
        "verified_model_states": {
            model.id: ("ready" if language in state.verified_models else "failed")
            for language, model in state.active_models.items()
        },
        "runtime_detector_states": detector_states,
        "contextual_ready": runtime.engine.contextual_ready(),
        "final_failure_code": failure_code if contextual_error is not None else None,
    }


def create_server(engine: PrivacyEngine | None = None) -> FastMCP:
    runtime = RuntimeBundle(engine) if engine is not None else build_runtime()
    privacy_engine = runtime.engine
    contextual_error, contextual_failure_code = _start_runtime(
        runtime,
        load_legacy_model=engine is None,
    )
    server = FastMCP("Securedact", json_response=True)

    @server.tool()
    def analyze_text(text: str, policy: str = "default") -> dict[str, Any]:
        """Detect personal information locally without transmitting the text."""
        invalid = _validate_text(text)
        if invalid is not None:
            return invalid
        if contextual_error is not None:
            return _contextual_block(
                contextual_error,
                contextual_failure_code or "contextual_model_not_ready",
            )
        return privacy_engine.analyze(text, policy).model_dump(mode="json")

    @server.tool()
    def redact_text(text: str, policy: str = "default") -> dict[str, Any]:
        """Replace locally detected personal information with safe placeholders."""
        invalid = _validate_text(text)
        if invalid is not None:
            return invalid
        if contextual_error is not None:
            return _contextual_block(
                contextual_error,
                contextual_failure_code or "contextual_model_not_ready",
            )
        analysis = privacy_engine.analyze(text, policy)
        if not analysis.engine_ready:
            return _contextual_block(
                "The required contextual model is unavailable.",
                privacy_engine.contextual_failure_code() or "contextual_model_not_ready",
            )
        try:
            result = privacy_engine.redact(text, policy, analysis=analysis)
        except ReviewRequiredError as exc:
            return {
                "status": "review_required",
                "entities": [item.model_dump(mode="json") for item in exc.entities],
            }
        except SendingBlockedError:
            return {"status": "blocked", "reason": "policy blocked content"}
        residual = privacy_engine.scan_residual(text, result, analysis, policy)
        if not residual.safe_to_send:
            return {"status": "blocked", "reason": "residual validation failed"}
        return {"status": "ok", **result.model_dump(mode="json")}

    @server.tool()
    def restore_text(text: str, mapping: dict[str, str]) -> str:
        """Restore known Securedact placeholders locally."""
        if len(text) > _max_text_chars():
            raise ValueError("input exceeds the configured size limit")
        return privacy_engine.restore(text, mapping)

    @server.tool()
    def create_safe_copy(content: str, filename: str, policy: str = "default") -> dict[str, Any]:
        """Write sanitized content to the configured Safe Copies directory only."""
        invalid = _validate_text(content)
        if invalid is not None:
            return invalid
        safe_root_value = os.getenv("SECUREDACT_SAFE_COPY_DIR")
        if not safe_root_value:
            return {"status": "blocked", "reason": "safe copy directory is not configured"}
        if not _valid_safe_copy_filename(filename):
            return {"status": "blocked", "reason": "filename must be a .txt or .md basename"}
        outcome = cast(dict[str, Any], redact_text(content, policy))
        if outcome.get("status") != "ok":
            return outcome
        root = Path(safe_root_value).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        target = (root / filename).resolve()
        if target.parent != root:
            return {"status": "blocked", "reason": "invalid destination"}
        try:
            with target.open("x", encoding="utf-8", newline="\n") as output:
                output.write(str(outcome["sanitized_text"]))
        except FileExistsError:
            return {"status": "blocked", "reason": "destination already exists"}
        return {
            "status": "ok",
            "path": str(target),
            "entity_counts": outcome["entity_counts"],
        }

    return server


def main() -> None:
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
