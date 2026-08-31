"""Production-path reproduction of the HIPAA contextual ensemble benchmark.

This reruns the frozen 202-case HIPAA adversarial corpus through the *actual*
production pipeline (``run_hipaa_safe_harbor``), not the old experimental adapter.

For the contextual NER mode it replays the recorded ``flair_predictions.json``
predictions (the exact outputs of ``flair/ner-english-large`` at the pinned
revision) through the real ``HipaaFlairPersonDetector`` gate. This exercises the
full production merge -> policy -> redaction -> residual path with the genuine
model outputs, so it measures the production ensemble end-to-end without
requiring the multi-minute model load in this environment. Set
``SECUREDACT_RUN_REAL_FLAIR=1`` (and have the weights installed) to run the real
tagger instead of the replay.

Usage:
    python scripts/benchmark_hipaa_contextual_production.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "experimental"))
sys.path.insert(0, str(ROOT / "src"))

import hipaa_compare as hc  # type: ignore[import-not-found]  # noqa: E402

from securedact_core.detectors import ContextualPrivacyDetector, RegexDetector  # noqa: E402
from securedact_core.detectors.hipaa_flair_detector import (  # noqa: E402
    HIPAA_FLAIR_DEFAULT_REVISION,
    HipaaFlairPersonDetector,
)
from securedact_core.engine import PrivacyEngine  # noqa: E402
from securedact_core.models import Detection, DetectionSource, EntityType  # noqa: E402

PREDICTIONS_PATH = Path(r"D:\SecuRedactData\hipaa-contextual-shootout\flair_predictions.json")

ENTITY_MAP = {
    "person": EntityType.PERSON,
    "per": EntityType.PERSON,
    "location": EntityType.LOCATION,
    "gpe": EntityType.LOCATION,
    "org": EntityType.ORGANIZATION,
    "organization": EntityType.ORGANIZATION,
    "address": EntityType.ADDRESS,
    "date": EntityType.DATE,
}


class ReplayRawFlairDetector:
    """Replays recorded Flair predictions for the 202-case corpus, in order."""

    name = "replay_flair"
    contextual = True

    def __init__(self, predictions_by_case: list[list[dict[str, Any]]]) -> None:
        self._queue = list(predictions_by_case)
        self._by_text: dict[str, list[dict[str, Any]]] = {}

    def load(self) -> None:
        return None

    @property
    def ready(self) -> bool:
        return True

    def detect(self, text: str) -> list[Detection]:
        case = self._by_text.get(text)
        if case is None:
            case = self._queue.pop(0) if self._queue else []
            self._by_text[text] = case
        detections: list[Detection] = []
        for pred in case:
            entity_type = ENTITY_MAP.get(pred.get("entity_type", "").lower())
            if entity_type is None:
                continue
            detections.append(
                Detection(
                    start=int(pred["start"]),
                    end=int(pred["end"]),
                    text=pred.get("text", text[int(pred["start"]) : int(pred["end"])]),
                    entity_type=entity_type,
                    confidence=float(pred["confidence"]),
                    source=DetectionSource.FLAIR,
                    rule="replay_flair",
                )
            )
        return detections


def _predictions_for_samples(samples: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    raw: dict[str, list[dict[str, Any]]] = {}
    if PREDICTIONS_PATH.exists():
        raw = json.loads(PREDICTIONS_PATH.read_text(encoding="utf-8"))["predictions"]
    return {s["id"]: raw.get(s["id"], []) for s in samples}


# The production engine merges overlapping detections to the most specific type
# (e.g. ``date_of_birth`` instead of ``date``, ``fax`` instead of ``phone``). The
# gold labels use the broader type. For fair benchmark scoring we credit the
# specific detection as satisfying the broader gold (this mirrors what the
# experimental adapter's raw output already contained). This normalisation only
# affects score mapping; it does not alter production detection behavior.
_BROADEN = {"date_of_birth": "date", "fax": "phone"}


def _broaden(types: set[str]) -> set[str]:
    return types | {_BROADEN[t] for t in types if t in _BROADEN}


def _run_mode(
    engine: PrivacyEngine,
    samples: list[dict[str, Any]],
    *,
    flair: HipaaFlairPersonDetector | None = None,
) -> dict[str, set[str]]:
    predictions: dict[str, set[str]] = {}
    for sample in samples:
        if flair is not None:
            # Build the HIPAA contextual engine (deterministic stack + Flair gate).
            deterministic = [d for d in engine.detectors if not d.contextual]
            hipaa_engine = PrivacyEngine(
                [*deterministic, flair], policies=engine.policies, require_contextual=False
            )
        else:
            hipaa_engine = engine
        analysis = hipaa_engine.analyze(sample["text"], "hipaa_safe_harbor")
        predictions[sample["id"]] = _broaden({f.entity_type.value for f in analysis.entities})
    return predictions


def _fmt(o: dict[str, Any]) -> str:
    return (
        f"TP={o['tp']} FP={o['fp']} FN={o['fn']} "
        f"P={o['precision']:.4f} R={o['recall']:.4f} F1={o['f1']:.4f}"
    )


def main() -> None:
    samples = hc.load_samples()
    flair_by_case = _predictions_for_samples(samples)
    replay = ReplayRawFlairDetector([flair_by_case[s["id"]] for s in samples])

    # Mode 1: deterministic only (regex).
    det_engine = PrivacyEngine(detectors=[RegexDetector()])
    det_pred = _run_mode(det_engine, samples)
    det_score = hc.evaluate(det_pred, samples)["overall"]

    # Mode 2: deterministic + contextual rules (production default stack).
    rules_engine = PrivacyEngine(detectors=[RegexDetector(), ContextualPrivacyDetector()])
    rules_pred = _run_mode(rules_engine, samples)
    rules_score = hc.evaluate(rules_pred, samples)["overall"]

    # Mode 3: deterministic + contextual rules + Flair PERSON (A) gate.
    if os.getenv("SECUREDACT_RUN_REAL_FLAIR") == "1":
        from securedact_core.detectors.hipaa_flair_detector import (
            create_hipaa_flair_detector,
        )

        flair_det = create_hipaa_flair_detector()
        print("(using REAL Flair tagger)")
    else:
        flair_det = HipaaFlairPersonDetector(raw_detector=replay)
        flair_det._resolved_revision = HIPAA_FLAIR_DEFAULT_REVISION
        print("(replaying recorded Flair predictions through the production gate)")
    ensemble_pred = _run_mode(rules_engine, samples, flair=flair_det)
    ensemble_score = hc.evaluate(ensemble_pred, samples)["overall"]

    print(f"\nLoaded {len(samples)} cases")
    print("\n=== Production deterministic only ===")
    print(_fmt(det_score))
    print("=== Production deterministic + contextual rules ===")
    print(_fmt(rules_score))
    print("=== Production deterministic + rules + Flair(A) ===")
    print(_fmt(ensemble_score))

    print("\n=== Targets vs reproduction ===")
    print(f"det        target P=1.0000 R=0.9091 F1=0.9524  got {_fmt(det_score)}")
    print(f"rules      target P=1.0000 R=0.9212 F1=0.9590  got {_fmt(rules_score)}")
    print(f"ensemble   target P=0.9937 R=0.9576 F1=0.9753  got {_fmt(ensemble_score)}")


if __name__ == "__main__":
    main()
