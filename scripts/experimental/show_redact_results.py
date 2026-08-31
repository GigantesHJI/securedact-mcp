import json
from pathlib import Path

R = json.loads(Path("build/external-validation/run-redact-001/results.json").read_text(encoding="utf-8"))
res = R["results"]
meta = R["metadata"]
print("META:", json.dumps({k: meta[k] for k in ("device","threshold","dataset_source","dataset_revision","dataset_license","dataset_languages","dataset_covered_art9")}, ensure_ascii=False, indent=2))

def f3(x):
    return "n/a" if x is None else f"{x:.3f}"

def show(name):
    c = res[name]["classification"]
    o = c["overall"]
    print(f"\n=== {name} ===  P={f3(o['precision'])} R={f3(o['recall'])} F1={f3(o['f1'])}  TP={o['true_positives']} FP={o['false_positives']} FN={o['false_negatives']}")
    print("  per-category F1:")
    for cat, m in c["per_category"].items():
        if m["support"]:
            print(f"    {cat:38s} P={f3(m['precision'])} R={f3(m['recall'])} F1={f3(m['f1'])} (sup {m['support']})")
    print("  per-language:")
    for lang, m in c["per_language"].items():
        print(f"    {lang}: P={f3(m['precision'])} R={f3(m['recall'])} F1={f3(m['f1'])} (sup {m['support']})")
    neg = c["negative_controls"]
    print(f"  negative flag rate: {neg['negative_flag_rate']:.3f} ({neg['negative_documents_flagged']}/{neg['negative_documents']}); hard-neg flag rate: {neg['hard_negative_flag_rate']}")
    sp = res[name]["span_localization"]
    print(f"  span exact F1={sp['exact']['f1']:.3f}; relaxed F1={sp['relaxed']['f1']:.3f}")

for k in ("securedact","bardsai","combination"):
    show(k)

print("\n=== Disclosure stratification (combination) ===")
print(json.dumps(res.get("disclosure_stratification", {}), indent=2, ensure_ascii=False))
print("\n=== Complementarity sec vs bard ===")
cb = res["complementarity_sec_bard"]
print("counts:", cb["counts"])
print("complementary_tp (bard-only):", cb["complementary_tp"], "lost_securedact_tp:", cb["lost_securedact_tp"], "overlap:", cb["overlap_tp"])
print("oracle F1:", cb["oracle_metric"]["f1"], "incremental TP:", cb["oracle_incremental_tp"])
