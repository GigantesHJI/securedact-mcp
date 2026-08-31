# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from ..models import Detection, EntityType
from .base import Detector

logger = logging.getLogger(__name__)

HIPAA_FLAIR_DEFAULT_MODEL_ID = "flair/ner-english-large"
HIPAA_FLAIR_DEFAULT_REVISION = "e2b1caabf7f9bac1e7829db73eac734df7e6ad7b"
HIPAA_FLAIR_DEFAULT_THRESHOLD = 0.50
# HIPAA Safe Harbor Category A (Names) only. Geography (B), structured
# identifiers, and all other Flair labels are deliberately excluded.
HIPAA_FLAIR_GATED_CATEGORIES: tuple[str, ...] = ("A",)

_SNAPSHOT_RE = re.compile(r"^[0-9a-f]{40}$")


def _snapshot_revision_from_path(model_path: str | Path | None) -> str | None:
    if not model_path:
        return None
    parts = Path(model_path).parts
    if "snapshots" in parts:
        index = parts.index("snapshots")
        if index + 1 < len(parts) and _SNAPSHOT_RE.fullmatch(parts[index + 1]):
            return parts[index + 1]
    return None


def _resolve_local_flair_path(revision: str | None) -> str | None:
    """Locate a local ``flair/ner-english-large`` snapshot without network access.

    Searches the Hugging Face cache layout (``models--flair--ner-english-large/
    snapshots/<rev>``) across the standard cache roots. This is a local-first
    resolver only; it never downloads and never transmits text.
    """

    search_roots: list[Path] = []
    hf_home = os.getenv("HF_HOME")
    if hf_home:
        search_roots.append(Path(hf_home) / "hub")
    search_roots.append(Path.home() / ".cache" / "huggingface" / "hub")
    # Environment-specific local mirror locations used during validation.
    for extra in ("D:\\AI\\huggingface", "D:\\AI\\hf-real"):
        search_roots.append(Path(extra))
    snapshot_dir = Path("models--flair--ner-english-large") / "snapshots"
    found: list[Path] = []
    for root in search_roots:
        base = root / snapshot_dir
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir() and _SNAPSHOT_RE.fullmatch(child.name):
                found.append(child)
    if not found:
        return None
    if revision is not None:
        for candidate in found:
            if candidate.name == revision:
                return str(candidate)
    return str(found[0])


class HipaaFlairPersonDetector(Detector):
    """PERSON-only contextual gate for HIPAA Safe Harbor Category A (Names).

    This detector is a *supplementary* HIPAA aid. It wraps a Flair NER backend
    (lazy-loaded) and admits ONLY normalized ``PERSON`` entities whose confidence
    meets the configured threshold. Every other Flair label (LOCATION, GPE,
    ORGANIZATION, DATE, ...) is dropped at this boundary so the HIPAA ensemble
    never gains contextual geography or arbitrary entity types.

    The heavyweight tagger is loaded lazily: construction is cheap and no Flair
    import occurs until the first ``detect`` call. If the model is requested but
    unavailable, ``detect`` degrades gracefully to an empty result and records the
    fallback in metadata so callers can surface it explicitly.
    """

    name = "hipaa_flair_person"
    contextual = True

    def __init__(
        self,
        *,
        model_id: str = HIPAA_FLAIR_DEFAULT_MODEL_ID,
        revision: str | None = HIPAA_FLAIR_DEFAULT_REVISION,
        threshold: float = HIPAA_FLAIR_DEFAULT_THRESHOLD,
        raw_detector: Detector | None = None,
        model_path: str | Path | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("HIPAA Flair threshold must be between 0 and 1")
        self.model_id = model_id
        self.revision = revision
        self.threshold = float(threshold)
        self._raw = raw_detector
        self._model_path = str(model_path) if model_path is not None else None
        self._failed = False
        self._resolved_revision: str | None = None
        self._available: bool | None = None
        self._fallback = False

    # --- lifecycle -----------------------------------------------------------

    def load(self) -> None:
        if self._raw is not None:
            self._available = True
            return
        from .flair_detector import FlairDetector

        if self._model_path is None:
            self._model_path = _resolve_local_flair_path(self.revision)
        if self._model_path is None:
            self._failed = True
            self._available = False
            self._fallback = True
            raise RuntimeError("HIPAA Flair model is not available locally")
        try:
            self._raw = FlairDetector(self._model_path)
            self._raw.load()
        except Exception:  # pragma: no cover - defensive: degrade, don't crash
            logger.warning("HIPAA Flair model failed to load; falling back to deterministic")
            self._failed = True
            self._available = False
            self._fallback = True
            raise
        self._resolved_revision = _snapshot_revision_from_path(self._model_path)
        self._available = True

    @property
    def ready(self) -> bool:
        return bool(
            self._raw is not None and getattr(self._raw, "ready", True) and not self._failed
        )

    @property
    def failure_code(self) -> str | None:
        return "contextual_model_load_failed" if self._failed else None

    @property
    def safe_state(self) -> str:
        if self.ready:
            return "ready"
        return "failed" if self._failed else "discovered"

    def _ensure_loaded(self) -> None:
        if self._raw is not None:
            return
        try:
            self.load()
        except Exception:
            # Graceful deterministic fallback: no Flair contributions this run.
            self._fallback = True

    # --- detection (PERSON-only gate) ----------------------------------------

    def detect(self, text: str) -> list[Detection]:
        self._ensure_loaded()
        if self._raw is None:
            return []
        try:
            candidates = self._raw.detect(text)
        except Exception:  # pragma: no cover - defensive
            logger.warning("HIPAA Flair inference failed; falling back to deterministic")
            self._fallback = True
            return []
        return [
            detection
            for detection in candidates
            if detection.entity_type == EntityType.PERSON and detection.confidence >= self.threshold
        ]

    # --- metadata ------------------------------------------------------------

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        return self.ready

    @property
    def resolved_revision(self) -> str | None:
        return self._resolved_revision

    @property
    def fallback(self) -> bool:
        return self._fallback

    def metadata_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "requested_revision": self.revision,
            "resolved_revision": self._resolved_revision,
            "threshold": self.threshold,
            "gated_categories": HIPAA_FLAIR_GATED_CATEGORIES,
            "available": self.is_available(),
            "fallback": self._fallback,
        }


def create_hipaa_flair_detector(
    *,
    threshold: float | None = None,
    raw_detector: Detector | None = None,
    model_path: str | Path | None = None,
) -> HipaaFlairPersonDetector:
    """Construct the HIPAA Category A Flair person detector.

    Pass ``raw_detector`` to inject a backend (used by tests and the benchmark
    replay harness). Otherwise the detector resolves and lazily loads the local
    ``flair/ner-english-large`` checkpoint on first use.
    """

    return HipaaFlairPersonDetector(
        threshold=HIPAA_FLAIR_DEFAULT_THRESHOLD if threshold is None else threshold,
        raw_detector=raw_detector,
        model_path=model_path,
    )
