from __future__ import annotations

import inspect
import os
from collections import Counter
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, cast

import anyio
from mcp import types as mcp_types
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import ToolAnnotations
from pydantic import Field, ValidationError

from securedact_core import (
    InstalledModel,
    ModelManager,
    PolicyLoadError,
    PrivacyEngine,
    RedactionRequest,
    RestorationRequest,
    SafeReadError,
    SecuredactEngine,
    SecuredactPaths,
    build_production_engine,
    load_policy_registry_from_environment,
)
from securedact_core.detectors import (
    FlairDetector,
    LanguageAwareFlairDetector,
)
from securedact_core.engine import ReviewRequiredError, SendingBlockedError
from securedact_core.production import article9_ml_enabled_from_environment

from .model_registry import MODELS_BY_LANGUAGE
from .model_store import (
    ManagedModelState,
    ModelConfigurationError,
    ModelPathError,
    ModelStore,
)
from .runtime_environment import configure_managed_offline_environment
from .runtime_lifecycle import RuntimeLifecycle, RuntimeLoadFailure

DEFAULT_MAX_TEXT_CHARS = 1_000_000
SUPPORTED_SAFE_COPY_SUFFIXES = {".md", ".txt"}

# Optional external Article 9 ML layer (Bardsai). Default off; opt in per
# deployment via SECUREDACT_ARTICLE9_ML_ENABLED=1.
ARTICLE9_ML_ENABLED = article9_ml_enabled_from_environment()


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    engine: PrivacyEngine
    contextual_error: str | None = None
    contextual_failure_code: str | None = None
    enabled_languages: tuple[str, ...] = ()
    prepare_loader: Callable[[], None] | None = None


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
    return build_production_engine(
        require_contextual=require_flair,
        model_manager=manager,
        article9_ml_enabled=ARTICLE9_ML_ENABLED,
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
    """Discover configuration quickly; defer integrity checks and Flair loading."""
    require_flair = os.getenv("SECUREDACT_REQUIRE_FLAIR", "1") != "0"
    if not require_flair:
        return RuntimeBundle(build_production_engine(require_contextual=False))

    try:
        model_store = store or ModelStore.resolve()
        configure_managed_offline_environment(model_store.paths.runtime_cache_root)
        configuration = (
            managed_state.configuration
            if managed_state is not None
            else model_store.read_configuration()
        )
        active_models = (
            managed_state.active_models
            if managed_state is not None
            else (
                {language: MODELS_BY_LANGUAGE[language] for language in configuration.active_models}
                if configuration is not None
                else {}
            )
        )

        # A valid managed configuration is authoritative. Legacy development
        # variables may remain in a parent process, but they must not divert a
        # fresh MCP server away from active managed models.
        if not active_models and (
            os.getenv("SECUREDACT_MODEL_PATH")
            or os.getenv("SECUREDACT_FLAIR_MODEL")
            or os.getenv("SECUREDACT_MODEL_ID")
        ):
            engine = _build_legacy_engine()
            manager = engine.model_manager
            return RuntimeBundle(
                engine,
                prepare_loader=(
                    (lambda: load_configured_model(engine, manager))
                    if manager is not None
                    else None
                ),
            )

        if configuration is None:
            engine = build_production_engine(
                require_contextual=True,
                article9_ml_enabled=ARTICLE9_ML_ENABLED,
            )
            return RuntimeBundle(
                engine,
                _missing_model_message(["en"]),
                "contextual_model_not_installed",
            )
        enabled_languages = tuple(configuration.enabled_languages)
        if not active_models:
            engine = build_production_engine(
                require_contextual=True,
                article9_ml_enabled=ARTICLE9_ML_ENABLED,
            )
            return RuntimeBundle(
                engine,
                "No contextual model is enabled.\n\nRun:\nsecuredact-mcp install",
                "contextual_model_not_enabled",
                enabled_languages,
            )

        engine = build_production_engine(
            require_contextual=True,
            article9_ml_enabled=ARTICLE9_ML_ENABLED,
        )

        def prepare_managed_models() -> None:
            try:
                state = managed_state or model_store.load_managed_state()
            except ModelConfigurationError as exc:
                raise RuntimeLoadFailure(
                    "contextual_model_manifest_invalid",
                    "The contextual model configuration could not be validated.",
                ) from exc
            except ModelPathError as exc:
                raise RuntimeLoadFailure(
                    "contextual_model_storage_invalid",
                    "The contextual model storage location is not allowed.",
                ) from exc
            if state.failed_languages:
                failure_codes = getattr(state, "failure_codes", {})
                code = next(
                    (
                        failure_codes[language]
                        for language in state.failed_languages
                        if language in failure_codes
                    ),
                    "contextual_model_integrity_failed",
                )
                reason = (
                    "A required contextual model dependency is missing."
                    if code == "contextual_model_dependency_missing"
                    else "A required contextual model failed integrity validation."
                )
                raise RuntimeLoadFailure(code, reason)
            detectors: dict[str, FlairDetector] = {}
            for language in enabled_languages:
                verified = state.verified_models.get(language)
                if verified is None:
                    raise RuntimeLoadFailure(
                        "contextual_model_integrity_failed",
                        "A required contextual model failed integrity validation.",
                    )
                fingerprint = verified.manifest.files[verified.manifest.entrypoint].sha256
                detectors[language] = FlairDetector(
                    verified.entrypoint,
                    model_fingerprint=fingerprint,
                )
            engine.replace_contextual_detector(LanguageAwareFlairDetector(detectors))

        return RuntimeBundle(
            engine,
            enabled_languages=enabled_languages,
            prepare_loader=prepare_managed_models,
        )
    except ModelConfigurationError:
        engine = build_production_engine(
            require_contextual=True,
            article9_ml_enabled=ARTICLE9_ML_ENABLED,
        )
        return RuntimeBundle(
            engine,
            "The contextual model configuration could not be validated.\n\n"
            "Run:\nsecuredact-mcp install",
            "contextual_model_manifest_invalid",
        )
    except ModelPathError:
        engine = build_production_engine(
            require_contextual=True,
            article9_ml_enabled=ARTICLE9_ML_ENABLED,
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


def _safe_block(policy: str, failure_code: str) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "status": "blocked",
        "policy": policy,
        "counts": {},
        "failure_code": failure_code,
        "reason_codes": [failure_code],
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
    del load_legacy_model
    lifecycle = _runtime_lifecycle(runtime)
    lifecycle.start_background()
    lifecycle.wait_until_terminal(timeout=600.0)
    blocked = lifecycle.privacy_block()
    if blocked is None:
        return None, None
    return blocked["reason"], blocked["failure_code"]


def _runtime_lifecycle(runtime: RuntimeBundle) -> RuntimeLifecycle:
    return RuntimeLifecycle(
        runtime.engine,
        enabled_languages=runtime.enabled_languages,
        initial_error=runtime.contextual_error,
        initial_failure_code=runtime.contextual_failure_code,
        prepare_loader=runtime.prepare_loader,
    )


def runtime_diagnostics(
    *,
    store: ModelStore | None = None,
    managed_state: ManagedModelState | None = None,
) -> dict[str, Any]:
    """Return non-sensitive managed configuration and runtime readiness details."""

    model_store = store or ModelStore.resolve()
    state = managed_state or model_store.load_managed_state()
    runtime = build_runtime(store=model_store, managed_state=state)
    lifecycle = _runtime_lifecycle(runtime)
    lifecycle.mark_protocol_ready()
    lifecycle.start_background()
    lifecycle.wait_until_terminal(timeout=600.0)
    lifecycle.safe_debug_diagnostic()
    snapshot = lifecycle.snapshot()
    blocked = lifecycle.privacy_block()
    failure_code = blocked["failure_code"] if blocked is not None else None

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
    regex_detectors = [
        detector for detector in runtime.engine.detectors if detector.name == "regex"
    ]
    email_rule_enabled = any(
        any(getattr(rule, "name", None) == "email" for rule in getattr(detector, "rules", ()))
        for detector in regex_detectors
    )
    return {
        "config_found": state.config_found,
        "enabled_languages": list(configuration.enabled_languages) if configuration else [],
        "active_model_ids": dict(configuration.active_models) if configuration else {},
        "verified_model_states": {
            model.id: ("ready" if language in state.verified_models else "failed")
            for language, model in state.active_models.items()
        },
        "runtime_detector_states": detector_states,
        "protocol_ready": snapshot.protocol_ready,
        "deterministic_detectors_ready": snapshot.deterministic_detectors_ready,
        "regex_detector": "enabled" if regex_detectors else "disabled",
        "email_rule": "enabled" if email_rule_enabled else "disabled",
        "contextual_state": snapshot.contextual_state.value,
        "language_states": snapshot.language_states,
        "contextual_ready": runtime.engine.contextual_ready(),
        "full_engine_ready": runtime.engine.full_ready(),
        "final_failure_code": failure_code,
        "runtime_failure_code": failure_code,
    }


def create_server(engine: PrivacyEngine | None = None) -> FastMCP:
    runtime = RuntimeBundle(engine) if engine is not None else build_runtime()
    privacy_engine = runtime.engine
    lifecycle = _runtime_lifecycle(runtime)
    policy_configuration_error: str | None = None
    try:
        privacy_engine.policies = load_policy_registry_from_environment(privacy_engine.policies)
    except (PolicyLoadError, OSError, RuntimeError):
        policy_configuration_error = "policy_configuration_invalid"
    public_engine = SecuredactEngine(
        privacy_engine,
        debug_enabled=os.getenv("SECUREDACT_ENABLE_DEBUG_RESPONSES") == "1",
        configuration_error=policy_configuration_error,
    )

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[dict[str, object]]:
        try:
            yield {"runtime_lifecycle": lifecycle}
        finally:
            public_engine.close()
            await anyio.to_thread.run_sync(lifecycle.shutdown)

    server = FastMCP("Securedact", json_response=True, lifespan=lifespan)
    server._securedact_runtime_lifecycle = lifecycle  # type: ignore[attr-defined]

    async def protocol_initialized(_notification: mcp_types.InitializedNotification) -> None:
        lifecycle.mark_protocol_ready()
        lifecycle.start_background()

    # The SDK consumes initialize itself. Its standards-based initialized
    # notification is the first safe point at which heavyweight work may begin.
    server._mcp_server.notification_handlers[mcp_types.InitializedNotification] = (
        protocol_initialized
    )

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    def prepare_for_external_ai(
        text: Annotated[
            str,
            Field(
                description=(
                    "Free text to inspect and sanitize locally before it is sent to an external "
                    "AI service. All processing happens on this machine; this tool never transmits "
                    "the text to any provider."
                )
            ),
        ],
        policy: Annotated[
            str,
            Field(
                description=(
                    "Named redaction policy controlling which entity types are masked or blocked. "
                    "Defaults to 'strict_external_ai'. Common values include 'strict_external_ai' "
                    "and 'default'; other policies may be registered in your environment. An unknown "
                    "name returns a policy_not_found error."
                )
            ),
        ] = "strict_external_ai",
        language: Annotated[
            str,
            Field(
                description=(
                    "Hint for the contextual detection language. One of 'auto' (detect "
                    "automatically), 'en', or 'nl'. Defaults to 'auto'."
                )
            ),
        ] = "auto",
        response_mode: Annotated[
            str,
            Field(
                description=(
                    "Amount of detail returned. 'minimal' returns only the approved result and "
                    "counts; 'review' adds per-detection findings for human review; 'debug' adds "
                    "engine internals (only when debug responses are enabled); 'restore_capable' "
                    "additionally returns a local restoration_session for later trusted restore_text. "
                    "Defaults to 'minimal'."
                )
            ),
        ] = "minimal",
    ) -> dict[str, Any]:
        """Use this before sending user-supplied or potentially sensitive text to an external AI service.

        SecuRedact inspects and sanitizes the text locally and returns the policy-approved
        representation; this tool does not transmit the text externally. It is the recommended
        default for outbound AI workflows. Use analyze_text for inspection-only classifications,
        redact_text for the lower-level compatibility path, create_safe_copy when a sanitized file
        is required, and restore_text only to reverse a prior local session in a trusted context.

        Returns a JSON object with 'status' ('ok', 'review_required', or 'blocked'), 'sanitized_text'
        (present only when approved), 'counts', 'policy', and optionally 'restoration_session'
        (when response_mode is 'restore_capable').
        """
        lifecycle.mark_protocol_ready()
        invalid = _validate_text(text)
        if invalid is not None:
            return _safe_block(policy, "input_too_large")
        blocked = lifecycle.privacy_block()
        if blocked is not None:
            return _safe_block(
                policy,
                blocked.get("failure_code", "privacy_runtime_unavailable"),
            )
        try:
            request = RedactionRequest.model_validate(
                {
                    "text": text,
                    "policy": policy,
                    "language": language,
                    "response_mode": response_mode,
                }
            )
        except ValidationError:
            return _safe_block(policy, "request_invalid")
        return public_engine.prepare(request).model_dump(mode="json", exclude_none=True)

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    def analyze_text(
        text: Annotated[
            str,
            Field(
                description=(
                    "Free text to inspect locally for sensitive content. Processing is on this "
                    "machine only; the original text is never modified or transmitted."
                )
            ),
        ],
        policy: Annotated[
            str,
            Field(
                description=(
                    "Named analysis policy controlling which detectors and entity types apply. "
                    "Defaults to 'default'. Common values include 'default'; other policies may be "
                    "registered in your environment. An unknown name returns a policy_not_found error."
                )
            ),
        ] = "default",
        response_mode: Annotated[
            str,
            Field(
                description=(
                    "Level of detail returned. 'minimal' returns only status and entity-type counts; "
                    "'review' additionally returns a 'findings' list with spans and entity types; "
                    "'debug' additionally returns 'debug_details' (only when debug responses are "
                    "enabled). Defaults to 'minimal'."
                )
            ),
        ] = "minimal",
    ) -> dict[str, Any]:
        """Inspect text locally and report detected sensitive content without producing sanitized output.

        Use this when you need to understand what PII, secrets, or credentials are present (counts,
        entity types, and, with review/debug modes, positions) but do not need redacted text for
        transmission. The original text is not modified and no sanitized representation is returned.
        For a policy-approved, ready-to-send result use prepare_for_external_ai; for a sanitized file
        use create_safe_copy; for reversing a prior local session use restore_text.

        Returns a JSON object with 'status' ('ok', 'review_required', or 'blocked'), 'policy',
        'policy_version', 'policy_digest', 'counts' (entity-type tallies), and, when response_mode is
        'review' or 'debug', a 'findings' list. 'debug' additionally returns 'debug_details'."""
        lifecycle.mark_protocol_ready()
        invalid = _validate_text(text)
        if invalid is not None:
            return _safe_block(policy, "input_too_large")
        blocked = lifecycle.privacy_block()
        if blocked is not None:
            return _safe_block(
                policy,
                blocked.get("failure_code", "privacy_runtime_unavailable"),
            )
        if response_mode not in {"minimal", "review", "debug"}:
            return _safe_block(policy, "response_mode_invalid")
        if response_mode == "debug" and not public_engine.debug_enabled:
            return _safe_block(policy, "debug_mode_disabled")
        try:
            selected_policy = privacy_engine.policies.get(policy)
            analysis = privacy_engine.analyze(text, policy)
        except ValueError:
            return _safe_block(policy, "policy_not_found")
        if not analysis.engine_ready or any(
            warning.endswith("detector unavailable") for warning in analysis.warnings
        ):
            return _safe_block(
                policy,
                privacy_engine.readiness_failure_code() or "contextual_model_load_failed",
            )
        counts = dict(sorted(Counter(item.entity_type.value for item in analysis.entities).items()))
        status = (
            "blocked"
            if analysis.blocked
            else "review_required"
            if analysis.requires_review
            else "ok"
        )
        output: dict[str, Any] = {
            "schema_version": "1",
            "status": status,
            "policy": policy,
            "policy_version": selected_policy.schema_version,
            "policy_digest": selected_policy.digest,
            "counts": counts,
        }
        if response_mode in {"review", "debug"}:
            output["findings"] = [
                {
                    "start": item.start,
                    "end": item.end,
                    "entity_type": item.entity_type.value,
                    "action": item.action.value if item.action is not None else "review",
                    "confidence": item.confidence,
                    "source": item.source.value,
                    "reason_code": item.rationale_code,
                }
                for item in analysis.entities
            ]
        if response_mode == "debug":
            output["debug_details"] = analysis.model_dump(mode="json")
        return output

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    def redact_text(
        text: Annotated[
            str,
            Field(
                description=(
                    "Free text to redact locally. Processing is on this machine; nothing is "
                    "transmitted externally."
                )
            ),
        ],
        policy: Annotated[
            str,
            Field(
                description=(
                    "Named redaction policy controlling which entity types are masked or blocked. "
                    "Defaults to 'default'. Common values include 'default' and 'strict_external_ai'; "
                    "other policies may be registered. An unknown name returns a policy_not_found error."
                )
            ),
        ] = "default",
        response_mode: Annotated[
            str,
            Field(
                description=(
                    "Normal modes behave like prepare_for_external_ai: 'minimal', 'review', and "
                    "'debug' return the approved result with increasing detail. The special value "
                    "'legacy' returns raw local-review redaction internals (including a mapping that "
                    "reveals original values) under deprecation_code 'legacy_sensitive_response'; it "
                    "must never be sent to an external service. Defaults to 'minimal'."
                )
            ),
        ] = "minimal",
    ) -> dict[str, Any]:
        """Direct/lower-level redaction entry point; prefer prepare_for_external_ai for normal outbound workflows.

        In its normal modes this performs the same local sanitization as prepare_for_external_ai and
        returns the approved result, so most agents should call prepare_for_external_ai instead. Use
        redact_text when you specifically need this lower-level compatibility path, or the 'legacy'
        mode for local review of raw redaction internals. The 'legacy' mode returns potentially
        sensitive local-review details and is never selected by default.

        Returns, for normal modes, the same approved result as prepare_for_external_ai (status,
        sanitized_text, counts). For 'legacy' mode it returns a result with deprecation_code
        'legacy_sensitive_response' containing local-review redaction data."""
        lifecycle.mark_protocol_ready()
        invalid = _validate_text(text)
        if invalid is not None:
            return _safe_block(policy, "input_too_large")
        blocked = lifecycle.privacy_block()
        if blocked is not None:
            return _safe_block(
                policy,
                blocked.get("failure_code", "privacy_runtime_unavailable"),
            )
        if response_mode != "legacy":
            try:
                request = RedactionRequest.model_validate(
                    {
                        "text": text,
                        "policy": policy,
                        "response_mode": response_mode,
                    }
                )
            except ValidationError:
                return _safe_block(policy, "request_invalid")
            return public_engine.prepare(request).model_dump(mode="json", exclude_none=True)

        # Compatibility mode intentionally returns sensitive local-review data.
        # It is never selected by default and carries an explicit deprecation code.
        try:
            analysis = privacy_engine.analyze(text, policy)
        except ValueError:
            return _safe_block(policy, "policy_not_found")
        if not analysis.engine_ready:
            return _safe_block(
                policy,
                privacy_engine.readiness_failure_code() or "contextual_model_load_failed",
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
        return {
            "schema_version": "legacy-0",
            "status": "ok",
            "deprecation_code": "legacy_sensitive_response",
            **result.model_dump(mode="json"),
        }

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    def restore_text(
        text: Annotated[
            str,
            Field(
                description=(
                    "Text containing SecuRedact placeholders (or a prior protected representation) to "
                    "restore. Processed locally; never transmitted."
                )
            ),
        ],
        restoration_session: Annotated[
            str | None,
            Field(
                description=(
                    "Opaque session token previously returned by SecuRedact (for example from "
                    "prepare_for_external_ai with response_mode 'restore_capable'). It identifies the "
                    "trusted local vault entry used to reverse protection and recover the original "
                    "values. Required unless you supply 'mapping' together with trusted_local_review."
                )
            ),
        ] = None,
        mapping: Annotated[
            dict[str, str] | None,
            Field(
                description=(
                    "Legacy direct mapping from placeholder token to original value. Supplying this "
                    "bypasses the session vault and immediately reveals the original sensitive values. "
                    "It is only honored when 'trusted_local_review' is true and 'restoration_session' "
                    "is omitted."
                )
            ),
        ] = None,
        trusted_local_review: Annotated[
            bool,
            Field(
                description=(
                    "Explicit acknowledgment that you are in a trusted local review context and accept "
                    "that restoration reveals original sensitive values. Required (true) to use the "
                    "'mapping' form. It has no effect on the 'restoration_session' form."
                )
            ),
        ] = False,
    ) -> dict[str, Any]:
        """Reverse a prior SecuRedact protection step in a trusted, local-only context.

        Use this ONLY after you previously received a restoration_session from SecuRedact (for example
        from prepare_for_external_ai with response_mode 'restore_capable') and now need to reconstruct
        the original text locally for trusted review. Restoration can reveal the original sensitive
        values (PII, secrets, credentials); it is a trusted-local operation, not a step to prepare
        data for external transmission. Never call it to sanitize or prepare text for an external AI;
        for that use prepare_for_external_ai. Never call it on text you did not previously protect
        with SecuRedact.

        Security boundary: all processing is local and nothing leaves the machine. The 'mapping' form
        requires trusted_local_review=true and exposes raw originals, so its output must never be
        transmitted. Returns a JSON object with 'status' ('ok' or 'blocked'), 'restored_text'
        (present only on success), and 'reason_codes' describing any failure."""
        if len(text) > _max_text_chars():
            return {"schema_version": "1", "status": "blocked", "reason_codes": ["input_too_large"]}
        if restoration_session is not None and mapping is None:
            try:
                request = RestorationRequest(
                    text=text,
                    restoration_session=restoration_session,
                )
            except ValidationError:
                return {
                    "schema_version": "1",
                    "status": "blocked",
                    "reason_codes": ["restoration_request_invalid"],
                }
            return public_engine.restore(request).model_dump(mode="json", exclude_none=True)
        if mapping is not None and restoration_session is None and trusted_local_review:
            mapping_size = sum(
                len(key.encode("utf-8")) + len(value.encode("utf-8"))
                for key, value in mapping.items()
            )
            if mapping_size > 1024 * 1024:
                return {
                    "schema_version": "legacy-0",
                    "status": "blocked",
                    "reason_codes": ["legacy_mapping_too_large"],
                }
            return {
                "schema_version": "legacy-0",
                "status": "ok",
                "restored_text": privacy_engine.restore(text, mapping),
                "deprecation_code": "legacy_mapping_restore",
            }
        return {
            "schema_version": "1",
            "status": "blocked",
            "reason_codes": ["restoration_session_required"],
        }

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    def create_safe_copy(
        content: Annotated[
            str,
            Field(
                description=(
                    "Text to sanitize locally and write to disk. Processed on this machine; never "
                    "transmitted."
                )
            ),
        ],
        filename: Annotated[
            str,
            Field(
                description=(
                    "Bare target filename (no directory components) ending in '.txt' or '.md'. The "
                    "file is created inside the configured Safe Copies directory; an existing file is "
                    "never overwritten."
                )
            ),
        ],
        policy: Annotated[
            str,
            Field(
                description=(
                    "Named redaction policy applied before writing. Defaults to 'strict_external_ai'. "
                    "An unknown name returns a policy_not_found error."
                )
            ),
        ] = "strict_external_ai",
    ) -> dict[str, Any]:
        """Sanitize text locally and write the approved result to a new file in the Safe Copies directory.

        Use this when you need a sanitized on-disk copy (for storage, handoff, or archival) rather than
        an in-memory sanitized string. For the sanitized text only, use prepare_for_external_ai; for
        inspection-only use analyze_text; for reversing a prior session use restore_text.

        Side effects: a new file is written to the directory set by SECUREDACT_SAFE_COPY_DIR. The
        supplied 'content' is not modified and no existing file is overwritten. The filename must be a
        bare '.txt' or '.md' basename (no path separators or directory traversal). The operation
        blocks and reports 'blocked' if the directory is unconfigured, the filename is invalid, or
        policy blocks the content.

        Returns a JSON object with 'status' ('ok' or 'blocked'), 'filename', and 'counts'."""
        invalid = _validate_text(content)
        if invalid is not None:
            return invalid
        safe_root_value = os.getenv("SECUREDACT_SAFE_COPY_DIR")
        if not safe_root_value:
            return {"status": "blocked", "reason": "safe copy directory is not configured"}
        if not _valid_safe_copy_filename(filename):
            return {"status": "blocked", "reason": "filename must be a .txt or .md basename"}
        outcome = cast(
            dict[str, Any],
            prepare_for_external_ai(content, policy, "auto", "minimal"),
        )
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
            "schema_version": "1",
            "status": "ok",
            "filename": filename,
            "counts": outcome["counts"],
        }

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    def securedact_read_file(
        path: Annotated[
            str,
            Field(
                description=(
                    "Local filesystem path to read. It is resolved and defended against path traversal, "
                    "symlink/UNC escapes, and oversized or binary content (FW-011/012/013); sensitive "
                    "paths are blocked before any file content is read."
                )
            ),
        ],
        policy: Annotated[
            str,
            Field(
                description=(
                    "Named redaction policy applied to the file contents. Defaults to "
                    "'strict_external_ai'. An unknown name returns a policy_not_found error."
                )
            ),
        ] = "strict_external_ai",
        max_bytes: Annotated[
            int | None,
            Field(
                description=(
                    "Optional cap on the number of bytes read from the file. When omitted, the engine's "
                    "configured size limit applies."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Safely read a local file and return only its sanitized (PII/secrets removed) text.

        Use this when you must ingest a local file's contents for use with an external AI but want
        path-traversal, size, and binary defenses plus sanitization applied first. If the content is
        already in memory, use prepare_for_external_ai; for a sanitized file on disk, use
        create_safe_copy.

        Side effects: reads a file from local disk and never transmits it. Sensitive paths and escapes
        are blocked before any file content is read. The returned 'sanitized_text' is safe to forward.

        Returns a JSON object with 'status' ('ok' or 'blocked'), 'path', and 'sanitized_text'
        (present only when approved)."""
        lifecycle.mark_protocol_ready()
        blocked = lifecycle.privacy_block()
        if blocked is not None:
            return _safe_block(
                policy,
                blocked.get("failure_code", "privacy_runtime_unavailable"),
            )
        try:
            result = public_engine.read_file(
                path,
                redaction_policy=policy,
                max_bytes=max_bytes,
            )
        except SafeReadError as exc:
            return {
                "schema_version": "1",
                "status": "blocked",
                "reason": exc.reason,
                "reason_codes": [exc.code],
            }
        if not result.ok or result.sanitized_text is None:
            return {
                "schema_version": "1",
                "status": "blocked",
                "reason": result.reason or "file could not be read safely",
                "reason_codes": [result.reason_code or "read_failed"],
            }
        return {
            "schema_version": "1",
            "status": "ok",
            "path": result.path,
            "sanitized_text": result.sanitized_text,
        }

    # FastMCP derives each tool's description from its docstring verbatim, including
    # the indentation introduced by the function body. Normalize that whitespace so the
    # description exposed to MCP clients is clean and readable.
    for _registered in server._tool_manager._tools.values():
        if _registered.description:
            _registered.description = inspect.cleandoc(_registered.description)

    return server


def main() -> None:
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
