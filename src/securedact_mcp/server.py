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
    ModelConfigurationError,
    ModelIntegrityError,
    ModelPathError,
    ModelStoragePaths,
    ModelStore,
)

DEFAULT_MAX_TEXT_CHARS = 1_000_000
SUPPORTED_SAFE_COPY_SUFFIXES = {".md", ".txt"}


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    engine: PrivacyEngine
    contextual_error: str | None = None


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


def build_runtime() -> RuntimeBundle:
    """Build an offline runtime from verified managed models without downloading."""
    require_flair = os.getenv("SECUREDACT_REQUIRE_FLAIR", "1") != "0"
    if not require_flair:
        return RuntimeBundle(
            PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector()],
                require_contextual=False,
            )
        )

    if (
        os.getenv("SECUREDACT_MODEL_PATH")
        or os.getenv("SECUREDACT_FLAIR_MODEL")
        or os.getenv("SECUREDACT_MODEL_ID")
    ):
        return RuntimeBundle(_build_legacy_engine())

    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    try:
        store = ModelStore(ModelStoragePaths.resolve())
        os.environ.setdefault("HF_HUB_CACHE", str(store.paths.model_root / ".runtime-cache"))
        configuration = store.load_or_recover_configuration()
        if configuration is None:
            installed = store.installed_models()
            if installed:
                configuration = store.configure_languages(sorted(installed))
            else:
                missing = ["en"]
                engine = PrivacyEngine(
                    [RegexDetector(), ContextualPrivacyDetector()],
                    require_contextual=True,
                )
                return RuntimeBundle(engine, _missing_model_message(missing))
        if not configuration.enabled_languages:
            engine = PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector()],
                require_contextual=True,
            )
            return RuntimeBundle(
                engine,
                "No contextual model is enabled.\n\nRun:\nsecuredact-mcp install",
            )

        detectors: dict[str, FlairDetector] = {}
        missing_languages: list[str] = []
        for language in configuration.enabled_languages:
            model = MODELS_BY_LANGUAGE[language]
            try:
                verified = store.verify_model(model)
            except ModelIntegrityError:
                missing_languages.append(language)
                continue
            fingerprint = verified.manifest.files[verified.manifest.entrypoint].sha256
            detectors[language] = FlairDetector(
                verified.entrypoint,
                model_fingerprint=fingerprint,
            )
        if missing_languages:
            engine = PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector()],
                require_contextual=True,
            )
            return RuntimeBundle(engine, _missing_model_message(missing_languages))
        router = LanguageAwareFlairDetector(detectors)
        return RuntimeBundle(
            PrivacyEngine(
                [RegexDetector(), ContextualPrivacyDetector(), router],
                require_contextual=True,
            )
        )
    except (ModelConfigurationError, ModelPathError) as exc:
        engine = PrivacyEngine(
            [RegexDetector(), ContextualPrivacyDetector()],
            require_contextual=True,
        )
        return RuntimeBundle(engine, str(exc))


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


def _valid_safe_copy_filename(filename: str) -> bool:
    if not filename or filename in {".", ".."}:
        return False
    if any(separator in filename for separator in ("/", "\\")) or ":" in filename:
        return False
    path = Path(filename)
    return path.name == filename and path.suffix.lower() in SUPPORTED_SAFE_COPY_SUFFIXES


def create_server(engine: PrivacyEngine | None = None) -> FastMCP:
    runtime = RuntimeBundle(engine) if engine is not None else build_runtime()
    privacy_engine = runtime.engine
    privacy_engine.startup()
    if engine is None and privacy_engine.model_manager is not None:
        load_configured_model(privacy_engine, privacy_engine.model_manager)
    contextual_error = runtime.contextual_error
    if privacy_engine.require_contextual and not privacy_engine.contextual_ready():
        contextual_error = contextual_error or (
            "The required contextual model could not be loaded.\n\n"
            "Run:\nsecuredact-mcp models verify"
        )
    server = FastMCP("Securedact", json_response=True)

    @server.tool()
    def analyze_text(text: str, policy: str = "default") -> dict[str, Any]:
        """Detect personal information locally without transmitting the text."""
        invalid = _validate_text(text)
        if invalid is not None:
            return invalid
        if contextual_error is not None:
            return {"status": "blocked", "reason": contextual_error}
        return privacy_engine.analyze(text, policy).model_dump(mode="json")

    @server.tool()
    def redact_text(text: str, policy: str = "default") -> dict[str, Any]:
        """Replace locally detected personal information with safe placeholders."""
        invalid = _validate_text(text)
        if invalid is not None:
            return invalid
        if contextual_error is not None:
            return {"status": "blocked", "reason": contextual_error}
        analysis = privacy_engine.analyze(text, policy)
        if not analysis.engine_ready:
            return {"status": "blocked", "reason": "contextual detector unavailable"}
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
