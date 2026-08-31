from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from securedact_core.detectors import RegexDetector  # noqa: E402
from securedact_core.hipaa import ENTITY_TO_LETTER  # noqa: E402
from securedact_core.models import EntityType  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
DATA = ROOT / "benchmarks" / "hipaa" / "hipaa_adversarial.json"
RESULTS = ROOT / "benchmarks" / "hipaa" / "hipaa_adversarial_results.json"

LETTER_TO_TYPES: dict[str, set[str]] = defaultdict(set)
for etype, letter in ENTITY_TO_LETTER.items():
    LETTER_TO_TYPES[letter].add(etype.value)

ALL_TYPES = {e.value for e in EntityType}

detector = RegexDetector()
data = json.loads(DATA.read_text(encoding="utf-8"))
samples = data["samples"]


def detected_types(text: str) -> set[str]:
    return {d.entity_type.value for d in detector.detect(text)}


per_cat: dict[str, dict] = defaultdict(
    lambda: {"tp": 0, "fp": 0, "fn": 0, "samples": 0,
             "known_missing": [], "known_extra": []}
)

for s in samples:
    letter = s["category"]
    if letter == "Q":
        scope = ALL_TYPES
    else:
        scope = LETTER_TO_TYPES.get(letter, set())
    gold = set(s["gold_present"]) & scope
    gold_absent = set(s["gold_absent"]) & scope
    det = detected_types(s["text"]) & scope

    if s.get("hard_negative") and not s["gold_present"]:
        # Expect nothing in scope to be detected.
        tp = set()
        fn = set()
        fp = det  # any detection in scope is a false positive
    else:
        tp = gold & det
        fn = gold - det
        fp = (det - gold) | (det & gold_absent)

    c = per_cat[letter]
    c["samples"] += 1
    c["tp"] += len(tp)
    c["fp"] += len(fp)
    c["fn"] += len(fn)
    if fn:
        c["known_missing"].append(
            {"id": s["id"], "domain": s["domain"], "missing": sorted(fn),
             "text": s["text"], "adversarial": s.get("adversarial", False),
             "rationale": s.get("rationale", "")}
        )
    if fp:
        c["known_extra"].append(
            {"id": s["id"], "domain": s["domain"], "extra": sorted(fp),
             "text": s["text"], "adversarial": s.get("adversarial", False),
             "rationale": s.get("rationale", "")}
        )

# Aggregate
tot_tp = tot_fp = tot_fn = 0
rows = []
for letter in sorted(per_cat):
    c = per_cat[letter]
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    tot_tp += tp
    tot_fp += fp
    tot_fn += fn
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    rows.append((letter, c["samples"], tp, fp, fn, prec, rec, f1,
                 len(c["known_missing"]), len(c["known_extra"])))

print(f"{'Cat':<4}{'N':>4}{'TP':>5}{'FP':>5}{'FN':>5}{'Prec':>8}{'Rec':>8}{'F1':>8}"
      f"{'kMiss':>7}{'kExtra':>8}")
overall_prec = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else 1.0
overall_rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 1.0
overall_f1 = (2 * overall_prec * overall_rec / (overall_prec + overall_rec)) \
    if (overall_prec + overall_rec) else 0.0
for letter, n, tp, fp, fn, prec, rec, f1, km, ke in rows:
    print(f"{letter:<4}{n:>4}{tp:>5}{fp:>5}{fn:>5}{prec:>8.3f}{rec:>8.3f}{f1:>8.3f}"
          f"{km:>7}{ke:>8}")
print("-" * 64)
print(f"{'ALL':<4}{sum(r[1] for r in rows):>4}{tot_tp:>5}{tot_fp:>5}{tot_fn:>5}"
      f"{overall_prec:>8.3f}{overall_rec:>8.3f}{overall_f1:>8.3f}")

summary = {
    "samples": len(samples),
    "overall": {
        "tp": tot_tp, "fp": tot_fp, "fn": tot_fn,
        "precision": overall_prec, "recall": overall_rec, "f1": overall_f1,
    },
    "by_category": {
        letter: {
            "samples": c["samples"], "tp": c["tp"], "fp": c["fp"], "fn": c["fn"],
            "known_missing": c["known_missing"], "known_extra": c["known_extra"],
        }
        for letter, c in sorted(per_cat.items())
    },
}
RESULTS.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"\nwrote results to {RESULTS}")
