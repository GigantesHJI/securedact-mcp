from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

REGISTRY_SCHEMA_VERSION = 1
OFFICIAL_HF_ENDPOINT = "https://huggingface.co"
IMMUTABLE_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MOVING_REVISIONS = {"main", "master", "latest", "HEAD"}

FLERT_CITATION = (
    "Schweter, Stefan and Alan Akbik. FLERT: Document-Level Features for Named "
    "Entity Recognition. arXiv:2011.06993, 2020."
)
UPSTREAM_LICENSE_NOTE = (
    "The upstream repository does not clearly state separate model-weight "
    "redistribution terms. Securedact downloads this model directly from its "
    "official upstream repository and does not redistribute it."
)


class ModelRegistryError(ValueError):
    """A supported-model entry violates the release allowlist."""


@dataclass(frozen=True, slots=True)
class SupportedModel:
    id: str
    language: str
    language_name: str
    display_name: str
    upstream_repo: str
    upstream_revision: str
    required_files: tuple[str, ...]
    optional_files: tuple[str, ...]
    approximate_size_bytes: int | None
    citation: str | None
    license_identifier: str | None
    license_note: str | None
    minimum_securedact_version: str
    required_file_sizes: tuple[tuple[str, int], ...]
    required_file_sha256: tuple[tuple[str, str], ...]

    @property
    def official_url(self) -> str:
        return f"{OFFICIAL_HF_ENDPOINT}/{self.upstream_repo}"

    @property
    def expected_sizes(self) -> dict[str, int]:
        return dict(self.required_file_sizes)

    @property
    def expected_hashes(self) -> dict[str, str]:
        return dict(self.required_file_sha256)


ENGLISH_MODEL = SupportedModel(
    id="english-large",
    language="en",
    language_name="English",
    display_name="Flair NER English Large",
    upstream_repo="flair/ner-english-large",
    upstream_revision="e2b1caabf7f9bac1e7829db73eac734df7e6ad7b",
    required_files=("pytorch_model.bin",),
    optional_files=(),
    approximate_size_bytes=2_239_866_761,
    citation=FLERT_CITATION,
    license_identifier=None,
    license_note=UPSTREAM_LICENSE_NOTE,
    minimum_securedact_version="0.1.0",
    required_file_sizes=(("pytorch_model.bin", 2_239_866_761),),
    required_file_sha256=(
        (
            "pytorch_model.bin",
            "1f59c05bbd3db05518b632f212b1aac7de1ff0b3914d6c0d587b6a68e214a287",
        ),
    ),
)

DUTCH_MODEL = SupportedModel(
    id="dutch-large",
    language="nl",
    language_name="Dutch",
    display_name="Flair NER Dutch Large",
    upstream_repo="flair/ner-dutch-large",
    upstream_revision="44c285912a9d6eec4d0858580f3cb13b7b8c9959",
    required_files=("pytorch_model.bin",),
    optional_files=(),
    approximate_size_bytes=2_239_866_697,
    citation=FLERT_CITATION,
    license_identifier=None,
    license_note=UPSTREAM_LICENSE_NOTE,
    minimum_securedact_version="0.1.0",
    required_file_sizes=(("pytorch_model.bin", 2_239_866_697),),
    required_file_sha256=(
        (
            "pytorch_model.bin",
            "69644e87635b92a84d0f23f67c0fce11eac39a3c9a0dae107e7e3e0d6ef20edd",
        ),
    ),
)

SUPPORTED_MODELS: tuple[SupportedModel, ...] = (ENGLISH_MODEL, DUTCH_MODEL)
ALLOWED_REPOSITORIES = frozenset(model.upstream_repo for model in SUPPORTED_MODELS)


def validate_registry(models: Iterable[SupportedModel]) -> tuple[SupportedModel, ...]:
    entries = tuple(models)
    seen_ids: set[str] = set()
    seen_languages: set[str] = set()
    for model in entries:
        if model.id in seen_ids:
            raise ModelRegistryError(f"duplicate model id: {model.id}")
        if model.language in seen_languages:
            raise ModelRegistryError(f"duplicate language assignment: {model.language}")
        seen_ids.add(model.id)
        seen_languages.add(model.language)
        if model.upstream_repo not in ALLOWED_REPOSITORIES:
            raise ModelRegistryError(f"repository is not allowlisted: {model.upstream_repo}")
        if model.upstream_revision in MOVING_REVISIONS or not IMMUTABLE_REVISION_PATTERN.fullmatch(
            model.upstream_revision
        ):
            raise ModelRegistryError(f"model revision is not immutable: {model.id}")
        if not model.required_files:
            raise ModelRegistryError(f"model has no required files: {model.id}")
        if set(model.required_files) != set(model.expected_sizes):
            raise ModelRegistryError(f"model size allowlist is incomplete: {model.id}")
        if set(model.required_files) != set(model.expected_hashes):
            raise ModelRegistryError(f"model hash allowlist is incomplete: {model.id}")
        for path in (*model.required_files, *model.optional_files):
            if not path or "/" in path or "\\" in path or path in {".", ".."}:
                raise ModelRegistryError(f"unsafe upstream file path: {model.id}")
        for digest in model.expected_hashes.values():
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ModelRegistryError(f"invalid upstream SHA-256: {model.id}")
    return entries


SUPPORTED_MODELS = validate_registry(SUPPORTED_MODELS)
MODELS_BY_ID = {model.id: model for model in SUPPORTED_MODELS}
MODELS_BY_LANGUAGE = {model.language: model for model in SUPPORTED_MODELS}

LANGUAGE_ALIASES = {
    "en": "en",
    "english": "en",
    "nl": "nl",
    "dutch": "nl",
}


def model_for_id(model_id: str) -> SupportedModel:
    try:
        return MODELS_BY_ID[model_id]
    except KeyError as exc:
        raise ModelRegistryError(f"unknown supported model: {model_id}") from exc


def model_for_language(language: str) -> SupportedModel:
    normalized = LANGUAGE_ALIASES.get(language.casefold())
    if normalized is None or normalized not in MODELS_BY_LANGUAGE:
        raise ModelRegistryError(f"unsupported model language: {language}")
    return MODELS_BY_LANGUAGE[normalized]


def models_for_selection(selection: str) -> tuple[SupportedModel, ...]:
    normalized = selection.casefold()
    if normalized == "all":
        return SUPPORTED_MODELS
    if normalized == "none":
        return ()
    return (model_for_language(normalized),)
