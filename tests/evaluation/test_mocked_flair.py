from __future__ import annotations

from pathlib import Path

from securedact_core import Detection, DetectionSource, EntityType, build_production_engine
from securedact_eval.quality import run_quality_evaluation

ROOT = Path(__file__).resolve().parents[2]


class TinyLocalFlair:
    name = "mocked_flair"
    contextual = True
    ready = True

    def load(self) -> None:
        return None

    def detect(self, text: str) -> list[Detection]:
        values = {
            "Example Research BV": EntityType.ORGANIZATION,
            "Den Haag": EntityType.LOCATION,
        }
        output: list[Detection] = []
        for value, entity_type in values.items():
            if value not in text:
                continue
            start = text.index(value)
            output.append(
                Detection(
                    start=start,
                    end=start + len(value),
                    text=value,
                    entity_type=entity_type,
                    confidence=0.99,
                    source=DetectionSource.FLAIR,
                    rule="tiny_local_test_model",
                )
            )
        return output


def test_mocked_flair_mode_is_comparable_without_downloading_models() -> None:
    deterministic = run_quality_evaluation(ROOT / "benchmarks" / "corpora")
    engine = build_production_engine([TinyLocalFlair()], require_contextual=True)
    engine.startup()
    mocked = run_quality_evaluation(
        ROOT / "benchmarks" / "corpora",
        mode="mocked_flair",
        engine=engine,
        model_identifier="tiny-local-test-model",
    )

    assert mocked.exact.recall == 1.0
    assert deterministic.exact.recall is not None
    assert mocked.exact.recall > deterministic.exact.recall
    assert mocked.metadata["model_identifier"] == "tiny-local-test-model"
