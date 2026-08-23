# SPDX-License-Identifier: Apache-2.0
"""Production BGE-M3 semantic proposer (optional Article 9 ML layer).

Promotes the frozen, research-validated BGE-M3 zero-shot proposer
(``MoritzLaurer/bge-m3-zeroshot-v2.0`` @ pinned revision) into production. It
scores the frozen generic Article 9 hypotheses and the political/sex/genetic
decompositions as NLI entailment. The frozen a9-sota-001 full system consumed a
decomposition-score file containing only the included genetic hypotheses, so the
validated full-system decision applies the gated GENETIC decomposition plus the
generic GEN4 proposals; political/sex-life derive from generic BGE plus the
detector stack. It is OPTIONAL (default off), lazy-loaded, and fails closed.

The heavy dependencies (``torch``/``transformers``) are imported lazily inside
``load()``/``_score_pairs()`` so importing this module never pulls them in.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Detection, DetectionSource, EntityType
from .article9_hypotheses import (
    DECOMPOSED_GENETIC_D,
    FROZEN_G,
    GEN4,
    GEN_DECOMP_EN,
    GEN_DECOMP_NL,
    GEN_HYP_EN,
    GEN_HYP_NL,
    GEN_KEYS,
    GENETIC_CONFUSION_PARTNERS,
    GENETIC_GUARD,
    POL_DECOMP_EN,
    POL_DECOMP_NL,
    SEX_DECOMP_EN,
    SEX_DECOMP_NL,
)

logger = logging.getLogger(__name__)

_BGE_MODEL_ID = "MoritzLaurer/bge-m3-zeroshot-v2.0"
_BGE_REVISION = "9abf1c8aaeb82a2447809c20753ed0b106b76652"
_BGE_MAX_LENGTH = 256  # frozen tokenizer length (NOT the NliVerifier default 512)
_BGE_BATCH_SIZE = 8

_ENTAIL_RE = re.compile(r"entail", re.I)
_CONTRA_RE = re.compile(r"contra", re.I)
_NEUTRAL_RE = re.compile(r"neutral", re.I)


class BgeM3Article9Proposer:
    """BGE-M3 zero-shot Article 9 semantic proposer."""

    name = "article9_bge"
    contextual = False

    def __init__(
        self,
        *,
        model_id: str | None = None,
        revision: str | None = None,
        device: str = "cpu",
        cache_dir: str | None = None,
        max_length: int = _BGE_MAX_LENGTH,
        batch_size: int = _BGE_BATCH_SIZE,
    ) -> None:
        self.model_id = model_id or _BGE_MODEL_ID
        self.revision = revision or _BGE_REVISION
        self.device = device
        self.cache_dir = cache_dir
        self.max_length = max_length
        self.batch_size = batch_size
        self._tokenizer = None
        self._model = None
        self._entail_index: int | None = None
        self._contra_index: int | None = None
        self._failed = False

    def load(self) -> None:
        if self._model is not None:
            return
        if self._failed:
            raise RuntimeError("article9_bge proposer unavailable")
        try:
            from huggingface_hub import snapshot_download
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            local = Path(
                snapshot_download(
                    self.model_id,
                    revision=self.revision,
                    cache_dir=self.cache_dir,
                    local_files_only=True,
                    local_dir_use_symlinks=False,
                )
            )
            tokenizer = AutoTokenizer.from_pretrained(local)  # type: ignore[no-untyped-call]
            model = AutoModelForSequenceClassification.from_pretrained(local)
            model.eval()
            id2label = {int(key): str(value) for key, value in model.config.id2label.items()}
            entail = [index for index, label in id2label.items() if _ENTAIL_RE.search(label)]
            contra = [index for index, label in id2label.items() if _CONTRA_RE.search(label)]
            if not entail:
                raise RuntimeError(f"no_entailment_label:{self.model_id}:{id2label}")
            self._entail_index = entail[0]
            if contra:
                self._contra_index = contra[0]
            else:
                others = [
                    index
                    for index in id2label
                    if index != self._entail_index and not _NEUTRAL_RE.search(id2label[index])
                ]
                self._contra_index = others[0] if others else None
            self._tokenizer = tokenizer
            self._model = model
        except Exception as exc:
            self._failed = True
            raise RuntimeError("article9_bge model could not be loaded") from exc

    @property
    def ready(self) -> bool:
        return self._model is not None and not self._failed

    @property
    def failure_code(self) -> str | None:
        return "article9_bge_load_failed" if self._failed else None

    # ------------------------------------------------------------------ scoring
    def _score_pairs(self, pairs: list[tuple[str, str]]) -> list[float]:
        import torch

        if self._model is None or self._tokenizer is None:
            raise RuntimeError("article9_bge proposer not loaded")
        out: list[float] = []
        for start in range(0, len(pairs), self.batch_size):
            chunk = pairs[start : start + self.batch_size]
            encoded = self._tokenizer(
                [premise for premise, _ in chunk],
                [hypothesis for _, hypothesis in chunk],
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=self.max_length,
            ).to(self.device)
            with torch.no_grad():
                logits = self._model(**encoded).logits
            if self._contra_index is None:
                probs = torch.softmax(logits, dim=-1)[:, self._entail_index]
            else:
                selected = logits[:, [self._entail_index, self._contra_index]]
                probs = torch.softmax(selected, dim=-1)[:, 0]
            out.extend(float(value) for value in probs.tolist())
        return out

    def compute_scores(
        self, text: str, language: str
    ) -> tuple[dict[EntityType, float], dict[str, float]]:
        """Return ``(gen, gen_dec)`` entailment scores for one document."""

        generic_table = GEN_HYP_NL if language == "nl" else GEN_HYP_EN
        generic_pairs = [(text, hypothesis) for hypothesis in generic_table.values()]
        generic_types = list(generic_table)

        pol_table = POL_DECOMP_NL if language == "nl" else POL_DECOMP_EN
        sex_table = SEX_DECOMP_NL if language == "nl" else SEX_DECOMP_EN
        gen_table = GEN_DECOMP_NL if language == "nl" else GEN_DECOMP_EN
        decomp_pairs = (
            [(text, hypothesis) for hypothesis in pol_table.values()]
            + [(text, hypothesis) for hypothesis in sex_table.values()]
            + [(text, hypothesis) for hypothesis in gen_table.values()]
        )
        decomp_keys = list(pol_table) + list(sex_table) + list(gen_table)

        generic_scores = self._score_pairs(generic_pairs)
        decomp_scores = self._score_pairs(decomp_pairs)

        gen = {
            entity_type: score
            for entity_type, score in zip(generic_types, generic_scores, strict=True)
        }
        gen_dec = {key: score for key, score in zip(decomp_keys, decomp_scores, strict=True)}
        return gen, gen_dec

    # ------------------------------------------------------------- propositions
    def _propose_additions(
        self,
        gen: dict[EntityType, float],
        gen_dec: dict[str, float],
        base_special: set[EntityType],
    ) -> set[EntityType]:
        """Return the Article 9 categories this proposer adds, given the stack.

        Mirrors ``sota/common.py:evaluate_securedact`` for the BGE contribution:
        generic GEN4 proposals at ``FROZEN_G`` plus the gated GENETIC
        decomposition. ``base_special`` is the union of categories already emitted
        by the base + BardsAI + GLiNER detectors (used by the confusion guard).

        The frozen a9-sota-001 full system consumed a decomposition-score file
        containing only the four included genetic hypotheses, so the
        political/sex-life decomposition booster was inactive in the validated
        artifact. Political/sex-life therefore derive from generic BGE (the GEN4
        contribution) plus the detector stack, exactly as the freeze manifest
        records. The frozen ``gen_dec`` lacked ``pol_*``/``sex_*`` keys, so those
        decomposition scores are intentionally not wired into the full-system
        decision here.
        """

        generic_gen4 = {category for category in GEN4 if gen.get(category, 0.0) >= FROZEN_G}
        prop: set[EntityType] = set()
        # Genetic decomposition (frozen guard). Political/sex-life decomposition
        # is intentionally not active (see module/function docstring).
        target, keys, spec, confusable = (
            EntityType.GENETIC_DATA,
            GEN_KEYS,
            (DECOMPOSED_GENETIC_D, GENETIC_GUARD, None),
            GENETIC_CONFUSION_PARTNERS,
        )
        threshold, guard, margin = spec
        stack = (base_special | generic_gen4) - {target}
        generic_hit = gen.get(target, 0.0) >= FROZEN_G
        best = max((gen_dec.get(key, 0.0) for key in keys), default=0.0)
        partner = max((gen.get(category, 0.0) for category in confusable), default=0.0)
        hard = set(confusable)
        decomp_hit = False
        if best >= threshold:
            if guard == "none":
                decomp_hit = True
            elif guard == "hard":
                decomp_hit = not (stack & hard)
            elif guard == "margin":
                decomp_hit = partner == 0.0 or best - partner >= (margin or 0.0)
            elif guard == "margin_hard":
                decomp_hit = (not (stack & hard)) and (
                    partner == 0.0 or best - partner >= (margin or 0.0)
                )
        if generic_hit or decomp_hit:
            prop.add(target)
        return (generic_gen4 | prop) - base_special

    def detect_with_context(self, text: str, context: dict[str, object]) -> list[Detection]:
        """Emit REVIEW-routed Article 9 detections for proposed categories.

        ``context`` must contain ``special_categories`` (the Article 9 categories
        already emitted by the base + BardsAI + GLiNER detectors) and optionally
        ``language`` (``en``/``nl``). Only categories NOT already present are
        emitted, preserving the fail-closed REVIEW posture.
        """

        if self._model is None:
            return []
        base_special = context.get("special_categories", set()) or set()
        language = context.get("language", "en")
        if language not in {"en", "nl"}:
            language = "en"
        gen, gen_dec = self.compute_scores(text, language)
        additions = self._propose_additions(gen, gen_dec, base_special)
        detections: list[Detection] = []
        for entity_type in additions:
            detections.append(
                Detection(
                    start=0,
                    end=len(text),
                    text=text,
                    entity_type=entity_type,
                    confidence=gen.get(entity_type, 1.0),
                    source=DetectionSource.ML_ARTICLE9,
                    rule="bge_article9_proposal",
                    precedence=40,
                    rationale_code="external_article9_bge",
                    requires_review=True,
                )
            )
        return detections

    def detect(self, text: str) -> list[Detection]:
        """Standalone entry point; delegates to the context-aware proposer.

        The BGE proposer needs the Article 9 categories already emitted by the
        base + BardsAI + GLiNER stack, so without that context it proposes only
        what generic BGE + the gated genetic decomposition contribute beyond an
        empty stack. This satisfies the ``Detector`` protocol while the engine
        normally drives it through ``detect_with_context``.
        """

        if self._model is None:
            return []
        gen, gen_dec = self.compute_scores(text, "en")
        additions = self._propose_additions(gen, gen_dec, set())
        detections: list[Detection] = []
        for entity_type in additions:
            detections.append(
                Detection(
                    start=0,
                    end=len(text),
                    text=text,
                    entity_type=entity_type,
                    confidence=gen.get(entity_type, 1.0),
                    source=DetectionSource.ML_ARTICLE9,
                    rule="bge_article9_proposal",
                    precedence=40,
                    rationale_code="external_article9_bge",
                    requires_review=True,
                )
            )
        return detections
