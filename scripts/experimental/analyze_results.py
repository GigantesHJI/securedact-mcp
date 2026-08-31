from __future__ import annotations

"""Analysis/reporting over the HIPAA comparison result JSONs in
D:\\SecuRedactData\\hipaa-comparison\\. Prints comparison tables and the
per-FN outcome analysis used in the final report. Pure analysis, no detection."""
import json
from collections import defaultdict
from pathlib import Path

OUT = Path(r"D:\SecuRedactData\hipaa-comparison")

samples = json.loads(
    Path(r"C:\Users\User\Desktop\securedact\securedact-mcp\benchmarks\hipaa\hipaa_adversarial.json")
    .read_text(encoding="utf-8")
)["samples"]
by_id = {s["id"]: s for s in samples}


def load(name):
    return json.loads((OUT / name).read_text(encoding="utf-8"))


det = load("deterministic_results.json")
ctx = load("contextual_results.json")
ens = load("ensemble_results.json")
phil = load("phileas_results.json")

# Try model-based results if present (may be absent if torch blocked).
try:
    ctx_model = load("contextual_model_results.json")
    ens_model = load("ensemble_model_results.json")
    have_model = True
except FileNotFoundError:
    have_model = False


def line(cat, d, label):
    b = d["by_category"].get(cat, {"tp": 0, "fp": 0, "fn": 0, "precision": 0, "recall": 0, "f1": 0})
    print(f"{label:<22}{cat:<4}{b['tp']:>4}{b['fp']:>4}{b['fn']:>4}"
          f"{b['precision']:>8.3f}{b['recall']:>8.3f}{b['f1']:>8.3f}")


print("=== OVERALL ===")
for label, d in [("SecuRedact deterministic", det), ("SecuRedact contextual(rules)", ctx),
                ("Ensemble union (rules)", ens["union"]), ("Ensemble precision-gated(rules)", ens["precision_gated"]),
                ("Phileas", phil)]:
    o = d["overall"]
    print(f"{label:<34} TP={o['tp']:>4} FP={o['fp']:>3} FN={o['fn']:>4}"
          f" P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f}")
if have_model:
    print(f"{'SecuRedact contextual(MODEL)':<34} TP={ctx_model['overall']['tp']:>4} "
          f"FN={ctx_model['overall']['fn']:>4} P={ctx_model['overall']['precision']:.3f} "
          f"R={ctx_model['overall']['recall']:.3f} F1={ctx_model['overall']['f1']:.3f}")
    print(f"{'Ensemble union (model)':<34} TP={ens_model['union']['overall']['tp']:>4} "
          f"FN={ens_model['union']['overall']['fn']:>4} P={ens_model['union']['overall']['precision']:.3f} "
          f"R={ens_model['union']['overall']['recall']:.3f} F1={ens_model['union']['overall']['f1']:.3f}")

print("\n=== PER-CATEGORY (A-R) ===")
print(f"{'system':<34}{'cat':<4}{'TP':>4}{'FP':>4}{'FN':>4}{'P':>8}{'R':>8}{'F1':>8}")
for cat in "ABCDEFGHIJKLMNOPQR":
    line(cat, det, "SecuRedact deterministic")
    line(cat, phil, "Phileas")
    # one blank line between categories for readability when scanning
    if cat in "CF":
        print()

print("\n=== Phileas per-category detail ===")
for cat in "ABCDEFGHIJKLMNOPQR":
    b = phil["by_category"].get(cat, {})
    if b:
        print(f"{cat}: TP={b['tp']} FP={b['fp']} FN={b['fn']} P={b['precision']:.2f} "
              f"R={b['recall']:.2f} missed={b['missed_case_ids']}")

print("\n=== Phileas FP (extra) cases by category ===")
for cat in "ABCDEFGHIJKLMNOPQR":
    b = phil["by_category"].get(cat, {})
    if b.get("extra_case_ids"):
        print(f"{cat}: {b['extra_case_ids']}")

print("\n=== Observed Phileas filter types ===")
print(phil["config"]["observed_filter_types"])

# Persist a compact analysis json for the report
analysis = {
    "deterministic": det["overall"],
    "contextual_rules": ctx["overall"],
    "ensemble_union_rules": ens["union"]["overall"],
    "ensemble_pg_rules": ens["precision_gated"]["overall"],
    "phileas": phil["overall"],
}
if have_model:
    analysis["contextual_model"] = ctx_model["overall"]
    analysis["ensemble_union_model"] = ens_model["union"]["overall"]
    analysis["ensemble_pg_model"] = ens_model["precision_gated"]["overall"]
(OUT / "comparison_summary.json").write_text(json.dumps(analysis, indent=2))
print("\nwrote comparison_summary.json")
