# SPDX-License-Identifier: Apache-2.0
"""Production Article 9 ML detector (Bardsai) as an optional semantic layer.

This promotes the experimental Bardsai adapter into the engine import graph
behind a clean ``Detector`` boundary. Heavy ML dependencies (``torch``,
``transformers``, ``huggingface_hub``) are imported lazily inside ``load()`` and
``_run_inference()`` so importing this module never pulls torch into the
production runtime.

Design posture (see the integration plan and the frozen A9-SOTA-001 freeze
manifest, which is authoritative for 0.4.0 parity):
- OPTIONAL. Enabled only when explicitly configured; default off.
- ADDITIVE (UNION/FALLBACK) for the FULL covered Bardsai Article 9 label set
  (seven categories: biometric, health, ethnic origin, political opinion,
  religion/belief, sexual orientation, trade-union membership). The frozen
  A9-SOTA-001 ``bard`` component used the full covered label set, so production
  aligns with it; all ML emissions route fail-closed to REVIEW, so adding recall
  here never auto-redacts.
- ABSENT for ``genetic_data`` / ``sex_life`` (no label in the checkpoint).
- REVIEW-biased: every emission is a special category, so the engine routes it to
  REVIEW by default. The detector never auto-redacts.
- Graceful failure: if the model is unavailable, ``load()``/``detect()`` raise and
  the engine records a warning and continues with the deterministic + contextual
  + Flair stack.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import (
    Detection,
    DetectionSource,
    EntityType,
    IndirectDisclosureRisk,
    SensitiveAssertion,
    TextSpan,
)
from .article9_ml_registry import (
    ARTICLE9_ML_MODEL,
    BARDSAI_SUFFIX_MAP,
    resolve_bardsai_label_map,
)
from .contextual_detector import NAME_PATTERN, ContextualPrivacyDetector

logger = logging.getLogger(__name__)

_PATIENT_PRONOUN = re.compile(
    r"\b(?:the patient|patient|de pati\xebnt)\b",
    re.IGNORECASE,
)
_SENTENCE_BOUNDARIES = ".?!\n"


@dataclass(frozen=True, slots=True)
class _TokenRun:
    category: EntityType
    start: int
    end: int
    confidence: float


class BardsaiArticle9Detector:
    """Token-classification detector for the Bardsai EU-PII multilingual model."""

    name = "article9_ml"
    contextual = False

    def __init__(
        self,
        *,
        model_id: str | None = None,
        revision: str | None = None,
        device: str = "cpu",
        threshold: float = 0.5,
        cache_dir: str | None = None,
        additive_categories: frozenset[EntityType] | None = None,
    ) -> None:
        self.model_id = model_id or ARTICLE9_ML_MODEL.upstream_repo
        self.revision = revision or ARTICLE9_ML_MODEL.revision
        self.device = device
        self.threshold = threshold
        self.cache_dir = cache_dir
        self.additive_categories = additive_categories or ARTICLE9_ML_MODEL.additive_categories
        # Suffix (after B-/I-) -> EntityType, built from the static map so the
        # detector works even before the model checkpoint is loaded. Refreshed
        # from the runtime id2label on load().
        self._suffix_to_type: dict[str, EntityType] = dict(BARDSAI_SUFFIX_MAP)
        self._tokenizer: Any = None
        self._model: Any = None
        self._failed = False

    # ------------------------------------------------------------------ loading
    def load(self) -> None:
        if self._model is not None:
            return
        if self._failed:
            raise RuntimeError("article9_ml detector unavailable")
        try:
            from huggingface_hub import snapshot_download
            from transformers import AutoModelForTokenClassification, AutoTokenizer

            local_dir = Path(
                snapshot_download(
                    self.model_id,
                    revision=self.revision,
                    cache_dir=self.cache_dir,
                    local_files_only=True,
                    # Windows lacks symlink privilege; copy files into the snapshot dir.
                    local_dir_use_symlinks=False,
                )
            )
            tokenizer = AutoTokenizer.from_pretrained(local_dir)
            model = AutoModelForTokenClassification.from_pretrained(local_dir)
            model.to(self.device)
            model.eval()
            self._tokenizer = tokenizer
            self._model = model
            resolved = resolve_bardsai_label_map(
                {str(key): value for key, value in model.config.id2label.items()}
            )
            self._suffix_to_type = {
                (full.split("-", 1)[1] if "-" in full else full): entity_type
                for full, entity_type in resolved.items()
            }
        except Exception as exc:
            self._failed = True
            raise RuntimeError("article9_ml model could not be loaded") from exc

    @property
    def ready(self) -> bool:
        return self._model is not None and not self._failed

    @property
    def failure_code(self) -> str | None:
        return "article9_ml_load_failed" if self._failed else None

    # ------------------------------------------------------------------- detect
    def detect(self, text: str) -> list[Detection]:
        runs = self._run_inference(text)
        detections: list[Detection] = []
        for run in runs:
            if run.category not in self.additive_categories:
                continue
            if run.confidence < self.threshold:
                continue
            detections.append(
                Detection(
                    start=run.start,
                    end=run.end,
                    text=text[run.start : run.end],
                    entity_type=run.category,
                    confidence=run.confidence,
                    source=DetectionSource.ML_ARTICLE9,
                    rule="bardsai_article9_token",
                    precedence=40,
                    rationale_code="external_article9_ml_token",
                )
            )
        return self._deduplicate(detections)

    def detect_assertions(self, text: str) -> list[SensitiveAssertion]:
        """Sentence-scoped review assertions for additive categories.

        Assertions are emitted only when a person/record-subject signal is present
        in the same sentence (the §8.2 subject/person linkage guard), limiting the
        hard-negative review burden. Evidence spans use the *sentence* bounds, not
        the token span, so the engine keeps the narrower ML token detection in
        REVIEW rather than treating it as auto-controlled.
        """

        runs = self._run_inference(text)
        assertions: list[SensitiveAssertion] = []
        for run in runs:
            if run.category not in self.additive_categories or run.confidence < self.threshold:
                continue
            sentence_start, sentence_end = self._sentence_span(text, run.start, run.end)
            if not self._has_subject_signal(text, sentence_start, sentence_end):
                continue
            assertions.append(
                SensitiveAssertion(
                    subject_entity_ids=["record-subject"],
                    category=run.category,
                    full_span_start=sentence_start,
                    full_span_end=sentence_end,
                    sentence_start=sentence_start,
                    sentence_end=sentence_end,
                    evidence_spans=[
                        TextSpan(
                            start=sentence_start,
                            end=sentence_end,
                            text=text[sentence_start:sentence_end],
                        )
                    ],
                    confidence=run.confidence,
                    detector=self.name,
                    requires_review=True,
                    rationale_code="external_article9_ml_assertion",
                    negated=False,
                    indirect_disclosure_risk=IndirectDisclosureRisk.POSSIBLE,
                )
            )
        return assertions

    # -------------------------------------------------------------- inference
    def _run_inference(self, text: str) -> list[_TokenRun]:
        self.load()
        import torch

        assert self._tokenizer is not None and self._model is not None
        tokenizer = self._tokenizer
        model = self._model
        inputs = tokenizer(
            text,
            return_tensors="pt",
            return_offsets_mapping=True,
            truncation=True,
            max_length=512,
        ).to(self.device)
        model_inputs = {key: value for key, value in inputs.items() if key != "offset_mapping"}
        with torch.no_grad():
            logits = model(**model_inputs).logits[0]
        predictions_ids = logits.argmax(-1).tolist()
        probabilities = torch.softmax(logits, dim=-1).tolist()
        offsets = inputs["offset_mapping"][0].tolist()
        word_ids = inputs.word_ids(0)
        id2label = model.config.id2label
        return self._assemble_runs(
            text, predictions_ids, probabilities, offsets, word_ids, id2label
        )

    def _assemble_runs(
        self,
        text: str,
        predictions_ids: list[int],
        probabilities: list[list[float]],
        offsets: list[list[int]],
        word_ids: list[int | None],
        id2label: dict[int, str],
    ) -> list[_TokenRun]:
        """Pure-Python assembly of token runs into Article 9 spans.

        Torch-free so it can be unit-tested with synthetic token predictions.
        Non-Article-9 labels are dropped here, guaranteeing no ordinary PII/NER
        leakage into special-category detections.
        """

        runs: list[_TokenRun] = []
        current: dict[str, Any] | None = None
        for index in range(len(predictions_ids)):
            wid = word_ids[index] if word_ids is not None else index
            if wid is None:
                continue
            start, end = offsets[index]
            if start == 0 and end == 0:
                continue
            label_id = predictions_ids[index]
            label = id2label[label_id]
            if label == "O":
                if current is not None:
                    runs.append(self._finalize(current))
                    current = None
                continue
            prefix, _, suffix = label.partition("-")
            mapped = self._suffix_to_type.get(suffix)
            if mapped is None:
                if current is not None:
                    runs.append(self._finalize(current))
                    current = None
                continue
            score = float(probabilities[index][label_id])
            if current is None:
                current = {
                    "type": mapped,
                    "start": start,
                    "end": end,
                    "scores": [score],
                }
            elif current["type"] == mapped and prefix in ("B", "I"):
                current["end"] = end
                current["scores"].append(score)
            else:
                runs.append(self._finalize(current))
                current = {
                    "type": mapped,
                    "start": start,
                    "end": end,
                    "scores": [score],
                }
        if current is not None:
            runs.append(self._finalize(current))
        return runs

    @staticmethod
    def _finalize(current: dict[str, Any]) -> _TokenRun:
        scores = current["scores"]
        confidence = sum(scores) / len(scores)
        return _TokenRun(
            category=current["type"],
            start=current["start"],
            end=current["end"],
            confidence=confidence,
        )

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _sentence_span(text: str, start: int, end: int) -> tuple[int, int]:
        left = [text.rfind(boundary, 0, start) for boundary in _SENTENCE_BOUNDARIES]
        sentence_start = (max(left) + 1) if left else 0
        right = [
            position
            for boundary in _SENTENCE_BOUNDARIES
            if (position := text.find(boundary, end)) >= 0
        ]
        sentence_end = min(right) if right else len(text)
        return sentence_start, sentence_end

    @classmethod
    def _has_subject_signal(cls, text: str, start: int, end: int) -> bool:
        sentence = text[start:end]
        if _PATIENT_PRONOUN.search(sentence):
            return True
        # A person name mid-sentence is a reliable subject signal; a sentence-initial
        # capitalized word (e.g. "This document ...") is not, and generic non-person
        # phrases are excluded to limit the hard-negative review burden.
        for match in NAME_PATTERN.finditer(sentence):
            if match.start() == 0:
                continue
            if ContextualPrivacyDetector._looks_like_non_person(match.group(0)):
                continue
            return True
        return False

    @staticmethod
    def _deduplicate(detections: list[Detection]) -> list[Detection]:
        unique: dict[tuple[int, int, EntityType], Detection] = {}
        for detection in detections:
            key = (detection.start, detection.end, detection.entity_type)
            existing = unique.get(key)
            if existing is None or detection.confidence > existing.confidence:
                unique[key] = detection
        return list(unique.values())
