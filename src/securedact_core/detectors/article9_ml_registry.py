# SPDX-License-Identifier: Apache-2.0
"""Pinned registration for the optional external Article 9 ML model (Bardsai).

This module intentionally lives outside ``securedact_mcp/model_registry.py``. The
repository validator enforces that ``model_registry.py`` contains *exactly three*
immutable model/runtime revisions (the Flair NER checkpoints and their XLM-R
tokenizer). Adding a fourth revision there would fail CI parity. The external
Article 9 ML model therefore follows the same consent-based, pinned-revision
registration *pattern* in an isolated module that the validator does not count.

All weights remain in the Hugging Face cache (never embedded in the wheel) and
are loaded offline (``local_files_only=True``) after an explicit install.
"""

from __future__ import annotations

from dataclasses import dataclass

from securedact_core.models import EntityType

# Bardsai BIO label suffix -> SecuRedact EntityType. Only the seven Article 9
# labels the checkpoint emits are mapped; GENETIC_DATA and SEX_LIFE have no label
# in this checkpoint and are therefore never produced by the detector.
BARDSAI_SUFFIX_MAP: dict[str, EntityType] = {
    "BIOMETRIC_DATA": EntityType.BIOMETRIC_DATA,
    "HEALTH_DATA": EntityType.HEALTH_DATA,
    "ETHNIC_ORIGIN": EntityType.RACIAL_OR_ETHNIC_ORIGIN,
    "POLITICAL_OPINION": EntityType.POLITICAL_OPINION,
    "RELIGION_OR_BELIEF": EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
    "SEXUAL_ORIENTATION": EntityType.SEXUAL_ORIENTATION,
    "TRADE_UNION_MEMBERSHIP": EntityType.TRADE_UNION_MEMBERSHIP,
}

# Pinned checkpoint evaluated in the external-model benchmark (run-001). A future
# checkpoint is treated as a new experiment and must be re-pinned here.
BARDSAI_REVISION = "8e0b19766bb0dd4916d096b4f540dd46c138c760"

# Contained GLiNER component (frozen A9-SOTA-001 architecture). The research run
# used the moving ``main`` revision; the cached snapshot captured at research time
# is what is resolved offline.
GLINER_MODEL_ID = "urchade/gliner_multi_pii-v1"
GLINER_REVISION = "main"

# BGE-M3 zero-shot semantic proposer (frozen A9-SOTA-001 architecture).
BGE_M3_MODEL_ID = "MoritzLaurer/bge-m3-zeroshot-v2.0"
BGE_M3_REVISION = "9abf1c8aaeb82a2447809c20753ed0b106b76652"

# The frozen A9-SOTA-001 ``bard`` component uses the full Bardsai label set
# (all seven Article 9 labels the checkpoint emits). The production stack layers
# Bardsai as a UNION/FALLBACK additive instrument, so it is allowed to *add*
# detections for every covered category; all ML emissions route fail-closed to
# REVIEW, so adding recall here never auto-redacts.
ARTICLE9_ML_ADDITIVE_CATEGORIES: frozenset[EntityType] = frozenset(BARDSAI_SUFFIX_MAP.values())


@dataclass(frozen=True, slots=True)
class ExternalArticle9Model:
    """Pinned metadata for the optional external Article 9 ML checkpoint."""

    id: str
    display_name: str
    upstream_repo: str
    revision: str
    license_identifier: str
    license_note: str
    approximate_size_bytes: int
    languages: tuple[str, ...]
    covers: frozenset[EntityType]
    additive_categories: frozenset[EntityType]


ARTICLE9_ML_MODEL = ExternalArticle9Model(
    id="bardsai-article9",
    display_name="Bardsai EU-PII Article 9 (multilingual)",
    upstream_repo="bardsai/eu-pii-anonimization-multilang-v2-preview",
    revision=BARDSAI_REVISION,
    license_identifier="Apache-2.0",
    license_note=(
        "Apache-2.0 per the upstream model card. Weights are downloaded directly "
        "from the official Hugging Face repository into the local HF cache and are "
        "never redistributed by Securedact. Install is explicit and consent-based."
    ),
    approximate_size_bytes=1_130_000_000,
    languages=("en", "nl"),
    covers=frozenset(BARDSAI_SUFFIX_MAP.values()),
    additive_categories=ARTICLE9_ML_ADDITIVE_CATEGORIES,
)

# Contained GLiNER component. Emits all nine Article 9 categories as a
# zero-shot instrument; weights are read from the configured HF cache.
GLINER_ML_MODEL = ExternalArticle9Model(
    id="gliner-article9",
    display_name="GLiNER multilingual PII (contained Article 9)",
    upstream_repo=GLINER_MODEL_ID,
    revision=GLINER_REVISION,
    license_identifier="MIT",
    license_note=(
        "GLiNER is Apache-2.0; the urchade/gliner_multi_pii-v1 weights are MIT. "
        "Weights are read from the local HF cache and never redistributed. Install "
        "is explicit and consent-based."
    ),
    approximate_size_bytes=610_000_000,
    languages=("en", "nl"),
    covers=frozenset(BARDSAI_SUFFIX_MAP.values())
    | frozenset(
        {
            EntityType.RACIAL_OR_ETHNIC_ORIGIN,
            EntityType.SEXUAL_ORIENTATION,
        }
    ),
    additive_categories=frozenset(BARDSAI_SUFFIX_MAP.values())
    | frozenset(
        {
            EntityType.RACIAL_OR_ETHNIC_ORIGIN,
            EntityType.SEXUAL_ORIENTATION,
        }
    ),
)

# BGE-M3 zero-shot semantic proposer. Contributes the generic GEN4 proposals and
# the gated political/sex/genetic decompositions; it never emits the other five
# Article 9 categories.
BGE_M3_ML_MODEL = ExternalArticle9Model(
    id="bge-m3-article9",
    display_name="BGE-M3 zero-shot Article 9 proposer",
    upstream_repo=BGE_M3_MODEL_ID,
    revision=BGE_M3_REVISION,
    license_identifier="MIT",
    license_note=(
        "MIT per the upstream model card. Weights are read from the local HF cache "
        "and never redistributed. Install is explicit and consent-based."
    ),
    approximate_size_bytes=2_240_000_000,
    languages=("en", "nl"),
    covers=frozenset(ARTICLE9_ML_ADDITIVE_CATEGORIES)
    | frozenset(
        {
            EntityType.GENETIC_DATA,
            EntityType.SEX_LIFE,
        }
    ),
    additive_categories=frozenset(ARTICLE9_ML_ADDITIVE_CATEGORIES)
    | frozenset(
        {
            EntityType.GENETIC_DATA,
            EntityType.SEX_LIFE,
        }
    ),
)


def resolve_bardsai_label_map(id2label: dict[str, str]) -> dict[str, EntityType]:
    """Build the Bardsai BIO-label -> EntityType map from a runtime ``id2label``.

    Non-Article-9 labels (names, emails, IBAN, ...) are dropped so the detector
    can never leak ordinary PII/NER into special-category findings.
    """

    resolved: dict[str, EntityType] = {}
    for raw in id2label.values():
        label = raw.upper()
        suffix = label[2:] if label.startswith(("B-", "I-")) else label
        mapped = BARDSAI_SUFFIX_MAP.get(suffix)
        if mapped is not None:
            resolved[label] = mapped
    return resolved


def ensure_article9_ml_model(
    cache_dir: str | None = None,
    *,
    offline: bool = False,
) -> str:
    """Download (or locate offline) the pinned Bardsai checkpoint.

    Returns the local snapshot directory. This mirrors the consent-based install
    flow used for Flair: it requires an explicit caller and pulls only the pinned
    revision. Honors ``HF_HOME`` / an explicit ``cache_dir``.
    """

    from huggingface_hub import snapshot_download

    return str(
        snapshot_download(
            ARTICLE9_ML_MODEL.upstream_repo,
            revision=ARTICLE9_ML_MODEL.revision,
            cache_dir=cache_dir,
            local_files_only=offline,
            local_dir_use_symlinks=False,
        )
    )
