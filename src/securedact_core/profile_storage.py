from __future__ import annotations

import json
import os

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .app_paths import SecuredactPaths
from .models import EntityType, PrivacyAction
from .policies import PROFILE_SCHEMA_VERSION, PolicyRegistry


class PrivacyConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=PROFILE_SCHEMA_VERSION, ge=1, le=PROFILE_SCHEMA_VERSION)
    active_profile: str = "gdpr_strict"
    category_actions: dict[EntityType, PrivacyAction] = Field(default_factory=dict)
    advanced_unsafe_mode: bool = False


class PrivacyProfileStore:
    """Atomic non-secret profile storage with conservative corruption fallback."""

    def __init__(
        self,
        paths: SecuredactPaths | None = None,
        policies: PolicyRegistry | None = None,
    ) -> None:
        self.paths = paths or SecuredactPaths.resolve()
        self.policies = policies or PolicyRegistry()
        self.path = self.paths.root / "privacy-profile.json"

    def load(self) -> PrivacyConfiguration:
        try:
            configuration = PrivacyConfiguration.model_validate_json(
                self.path.read_text(encoding="utf-8")
            )
            self.policies.get(configuration.active_profile)
            return configuration
        except (OSError, ValueError, ValidationError, json.JSONDecodeError):
            return PrivacyConfiguration()

    def save(self, configuration: PrivacyConfiguration) -> PrivacyConfiguration:
        self.policies.get(configuration.active_profile)
        self.paths.root.mkdir(parents=True, exist_ok=True)
        temporary = self.paths.root / f".privacy-profile-{os.getpid()}.tmp"
        payload = configuration.model_dump_json(indent=2)
        try:
            temporary.write_text(payload, encoding="utf-8")
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        return configuration

    def reset(self) -> PrivacyConfiguration:
        configuration = PrivacyConfiguration()
        return self.save(configuration)

    @staticmethod
    def export_profile(configuration: PrivacyConfiguration) -> str:
        return configuration.model_dump_json(indent=2)

    def import_profile(self, payload: str) -> PrivacyConfiguration:
        configuration = PrivacyConfiguration.model_validate_json(payload)
        return self.save(configuration)
