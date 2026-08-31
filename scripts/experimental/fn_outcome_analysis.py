from __future__ import annotations

"""Per-FN outcome analysis + SecuRedact+Phileas union experiment (evaluation only).

Answers:
 * For each of SecuRedact deterministic's 15 false negatives, which system
   (SecuRedact contextual-rules, Phileas, SecuRedact det+ctx union,
   SecuRedact det+Phileas union) catches it.
 * The evaluation-only union of SecuRedact deterministic + Phileas detections.
"""
import importlib.util
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = Path(r"D:\SecuRedactData\hipaa-comparison")

spec = importlib.util.spec_from_file_location(
    "hipaa_compare", str(ROOT / "scripts" / "experimental" / "hipaa_compare.py")
)
hc = importlib.util.module_from_spec(spec)
import sys

sys.modules["hipaa_compare"] = hc
spec.loader.exec_module(hc)

from securedact_core.hipaa import ENTITY_TO_LETTER  # noqa: E402
from securedact_core.models import EntityType  # noqa: E402

LETTER_TO_TYPES = defaultdict(set)
for e, l in ENTITY_TO_LETTER.items():
    LETTER_TO_TYPES[l].add(e.value)
ALL = {e.value for e in EntityType}


def load_pred(name):
    return json.loads((OUT / name).read_text(encoding="utf-8"))


det = load_pred("predictions_securedact_deterministic.json")
ctx = load_pred("predictions_securedact_contextual_rules.json")
phil = load_pred("predictions_phileas.json")

samples = hc.load_samples()
by_id = {s["id"]: s for s in samples}


def scope_of(s):
    return ALL if s["category"] == "Q" else LETTER_TO_TYPES.get(s["category"], set())


# Identify the 15 deterministic FNs at the type level (a case may miss >1 type).
fn_units = []
for s in samples:
    sc = scope_of(s)
    gold = set(s.get("gold_present", [])) & sc
    d = set(det.get(s["id"], [])) & sc
    for g in sorted(gold - d):
        fn_units.append({"id": s["id"], "category": s["category"], "gold_type": g, "text": s["text"]})

print(f"Deterministic FN (type-level) count: {len(fn_units)}")
assert len(fn_units) == 15, len(fn_units)

# Systems: build prediction dicts for each combination.
ens_det_ctx = {cid: set(det.get(cid, [])) | set(ctx.get(cid, [])) for cid in det}
ens_det_phil = {cid: set(det.get(cid, [])) | set(phil.get(cid, [])) for cid in det}

systems = {
    "SecuRedact deterministic": det,
    "SecuRedact contextual (rules)": ctx,
    "Phileas": phil,
    "Ensemble det+ctx(rules)": ens_det_ctx,
    "Ensemble det+Phileas": ens_det_phil,
}

rows = []
for u in fn_units:
    cid = u["id"]
    sc = scope_of(by_id[cid])
    caught = {}
    for name, preds in systems.items():
        d = set(preds.get(cid, [])) & sc
        caught[name] = u["gold_type"] in d
    rows.append(
        {
            "id": cid,
            "category": u["category"],
            "gold_type": u["gold_type"],
            "text": u["text"],
            "caught": caught,
        }
    )

# Count how many of the 15 each system catches.
print("\n=== 15 FN outcomes (caught = system detects that gold identifier) ===")
for name in systems:
    n = sum(1 for r in rows if r["caught"][name])
    print(f"{name:<34} catches {n}/15")

print("\n=== Per-unit detail ===")
for r in rows:
    caught_str = ",".join(k.split()[0] for k, v in r["caught"].items() if v)
    print(f"{r['id']:<12} [{r['category']}] gold={r['gold_type']:<22} caught_by=[{caught_str}]")

# Save
fn_out = {
    "fn_count": len(fn_units),
    "systems_summary": {
        name: sum(1 for r in rows if r["caught"][name]) for name in systems
    },
    "cases": rows,
}
hc.write_json("fn_outcomes.json", fn_out)

# Evaluation-only union metrics: SecuRedact deterministic + Phileas.
union_sum = hc.evaluate(ens_det_phil, samples)
hc.write_json("ensemble_securedact_phileas_results.json", union_sum)
o = union_sum["overall"]
print(
    f"\n=== Ensemble (SecuRedact det + Phileas) union ===\n"
    f"TP={o['tp']} FP={o['fp']} FN={o['fn']} "
    f"P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f}"
)

# Precision-gated det + Phileas: keep Phileas only where it is strong/low-FP
# (category A names) to avoid importing Phileas's high-FP geography/license/URL noise.
def letter_of(t):
    try:
        return hc.letter_of(t)
    except Exception:
        return None


phil_gated = {
    cid: {t for t in phil.get(cid, []) if letter_of(t) in {"A"}}
    for cid in det
}
ens_gated = {cid: set(det.get(cid, [])) | phil_gated.get(cid, set()) for cid in det}
gated_sum = hc.evaluate(ens_gated, samples)
hc.write_json("ensemble_securedact_phileas_gated_results.json", gated_sum)
g = gated_sum["overall"]
print(
    f"\n=== Ensemble (SecuRedact det + Phileas gated to A) ===\n"
    f"TP={g['tp']} FP={g['fp']} FN={g['fn']} "
    f"P={g['precision']:.3f} R={g['recall']:.3f} F1={g['f1']:.3f}"
)
