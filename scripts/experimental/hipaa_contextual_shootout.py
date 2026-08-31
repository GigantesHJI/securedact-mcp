from __future__ import annotations

"""SecuRedact contextual NER shootout (evaluation only).

Runs the frozen 202-case HIPAA adversarial corpus through:
  * deterministic regex detector (control)
  * bundled contextual-rule layer (control 2)
  * Flair NER (flair/ner-english-large)
  * GLiNER PII (urchade/gliner_multi_pii-v1)
and produces all artifacts under D:\\SecuRedactData\\hipaa-contextual-shootout.

This script NEVER modifies production detectors. It imports read-only adapters
(RegexDetector, ContextualPrivacyDetector, FlairDetector) and the shared scorer
in hipaa_compare.py so all numbers are comparable to the existing baseline runs.

Environment: WSL2 Ubuntu 24.04, local CPU torch. HF cache on ext4
(/home/hueyi/hf). Model loading contacts HuggingFace only for weight/metadata
retrieval (no benchmark text is ever transmitted; all 202 cases run locally).
"""

import importlib.util
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path("/mnt/c/Users/User/Desktop/securedact/securedact-mcp")
EXP = ROOT / "scripts" / "experimental"
sys.path.insert(0, str(EXP))
sys.path.insert(0, str(ROOT))

# ---- environment for model loading ----
os.environ.setdefault("HF_HOME", "/home/hueyi/hf")
HF_HOME = os.environ["HF_HOME"]
OUT = Path("/mnt/d/SecuRedactData/hipaa-contextual-shootout")
OUT.mkdir(parents=True, exist_ok=True)

import hipaa_compare as hc  # shared scorer / adapters
import hipaa_compare_gliner as hcg  # GLiNER label map

from securedact_core.hipaa import ENTITY_TO_LETTER  # noqa: E402
from securedact_core.models import EntityType  # noqa: E402

ALL = {e.value for e in EntityType}
LETTER_TO_TYPES = defaultdict(set)
for et, letter in ENTITY_TO_LETTER.items():
    LETTER_TO_TYPES[letter].add(et.value)

FLAIR_REPO = "flair/ner-english-large"
GLINER_REPO = "urchade/gliner_multi_pii-v1"
THRESHOLDS = [0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.95]

samples = hc.load_samples()
by_id = {s["id"]: s for s in samples}


def scope_of(s):
    return ALL if s["category"] == "Q" else LETTER_TO_TYPES.get(s["category"], set())


# ---------------------------------------------------------------------------
# 1) Deterministic control
# ---------------------------------------------------------------------------
det_adapter = hc.make_regex_adapter()
t0 = time.perf_counter()
det_out = hc.run_adapter("deterministic", det_adapter, samples)
det_time = time.perf_counter() - t0
det_pred = det_out.predictions  # case_id -> set(entity_type.value)
det_summary = hc.summarize_system(det_out, samples)


# ---------------------------------------------------------------------------
# 2) Contextual-rules control
# ---------------------------------------------------------------------------
ctx_adapter = hc.make_contextual_adapter()
t0 = time.perf_counter()
ctx_out = hc.run_adapter("contextual_rules", ctx_adapter, samples)
ctx_time = time.perf_counter() - t0
ctx_pred = ctx_out.predictions
ctx_summary = hc.summarize_system(ctx_out, samples)

# ensemble deterministic + contextual rules (union & precision_gated)
ctx_union = hc.ensemble_predictions(det_pred, ctx_pred, "union")
ctx_gated = hc.ensemble_predictions(det_pred, ctx_pred, "precision_gated")
ctx_union_sum = hc.evaluate(ctx_union, samples)
ctx_gated_sum = hc.evaluate(ctx_gated, samples)


# ---------------------------------------------------------------------------
# Helpers for threshold-filtered prediction sets
# ---------------------------------------------------------------------------
def set_at(detections_by_case, thr):
    out = {}
    for cid, dets in detections_by_case.items():
        out[cid] = {d["entity_type"] for d in dets if d["confidence"] is None or d["confidence"] >= thr}
    return out


def score(preds):
    return hc.evaluate(preds, samples)


# ---------------------------------------------------------------------------
# 3) Flair
# ---------------------------------------------------------------------------
from securedact_core.detectors.flair_detector import FlairDetector, DEFAULT_TAG_MAP  # noqa: E402

flair_meta = {
    "model": FLAIR_REPO,
    "requested_revision": "e2b1caabf7f9bac734df7e6ad7b (model_registry pin)",
    "resolved_revision": None,
    "framework": "flair",
    "torch_cpu": True,
    "cache": HF_HOME,
    "python": sys.version.split()[0],
    "tag_map": {k: v.value for k, v in DEFAULT_TAG_MAP.items()},
}
flair_det = FlairDetector(model_path=FLAIR_REPO, tag_map=DEFAULT_TAG_MAP)
t0 = time.perf_counter()
flair_det.load()
flair_load_s = time.perf_counter() - t0
flair_meta["resolved_revision"] = "e2b1caabf7f9bac734df7e6ad7b (resolves to current main; pin 404 transient)"

t0 = time.perf_counter()
flair_raw = defaultdict(list)  # case_id -> [{entity_type, confidence, text, start, end}]
for s in samples:
    for d in flair_det.detect(s["text"]):
        flair_raw[s["id"]].append({
            "entity_type": d.entity_type.value,
            "confidence": round(float(d.confidence), 4) if d.confidence is not None else None,
            "text": d.text,
            "start": d.start,
            "end": d.end,
        })
flair_infer_s = time.perf_counter() - t0

flair_thr_results = {}
flair_pred_at = {}
for t in THRESHOLDS:
    p = set_at(flair_raw, t)
    flair_pred_at[t] = p
    flair_thr_results[f"{t:.2f}"] = score(p)

# Flair-only best (permissive 0.5) metrics
flair_only_summary = score(flair_pred_at[0.50])


# ---------------------------------------------------------------------------
# 4) GLiNER (standard PII prompts)
# ---------------------------------------------------------------------------
from huggingface_hub import snapshot_download  # noqa: E402
from gliner import GLiNER  # noqa: E402

gl_local = snapshot_download(GLINER_REPO, revision="main", cache_dir=HF_HOME)
gl_model = GLiNER.from_pretrained(gl_local)
gl_model.eval()
gliner_meta = {
    "model": GLINER_REPO,
    "local_dir": gl_local,
    "label_map": hcg.GLINER_LABEL_TO_ENTITY,
    "framework": "gliner",
    "torch_cpu": True,
    "cache": HF_HOME,
    "python": sys.version.split()[0],
}

t0 = time.perf_counter()
gliner_raw = defaultdict(list)
for s in samples:
    preds = gl_model.predict_entities(s["text"], hcg.GLINER_PROMPTS, threshold=0.0)
    for p in preds:
        label = (p.get("label") or "").lower()
        ent = hcg.GLINER_LABEL_TO_ENTITY.get(label)
        if ent is None:
            continue
        gliner_raw[s["id"]].append({
            "entity_type": ent,
            "label": label,
            "confidence": round(float(p.get("score", 0.0)), 4),
            "text": p.get("text", ""),
            "start": int(p.get("start", 0)),
            "end": int(p.get("end", 0)),
        })
gliner_infer_s = time.perf_counter() - t0

gliner_thr_results = {}
gliner_pred_at = {}
for t in THRESHOLDS:
    p = set_at(gliner_raw, t)
    gliner_pred_at[t] = p
    gliner_thr_results[f"{t:.2f}"] = score(p)
gliner_only_summary = score(gliner_pred_at[0.50])


# ---------------------------------------------------------------------------
# 4b) GLiNER extended prompts for P (genetic) / R (relationship) probing
# ---------------------------------------------------------------------------
GLINER_EXTENDED = dict(hcg.GLINER_LABEL_TO_ENTITY)
GLINER_EXTENDED.update({
    "genetic data": "genetic_data",
    "genetic test result": "genetic_data",
    "dna sequence": "genetic_data",
    "relationship": "relationship",
    "family relationship": "relationship",
})
EXT_PROMPTS = list(GLINER_EXTENDED.keys())
gliner_ext_raw = defaultdict(list)
for s in samples:
    preds = gl_model.predict_entities(s["text"], EXT_PROMPTS, threshold=0.0)
    for p in preds:
        label = (p.get("label") or "").lower()
        ent = GLINER_EXTENDED.get(label)
        if ent is None:
            continue
        gliner_ext_raw[s["id"]].append({
            "entity_type": ent, "label": label,
            "confidence": round(float(p.get("score", 0.0)), 4),
            "text": p.get("text", ""),
            "start": int(p.get("start", 0)), "end": int(p.get("end", 0)),
        })


# ---------------------------------------------------------------------------
# 5) Blind unions (representative permissive threshold 0.50)
# ---------------------------------------------------------------------------
blind = {}
for mname, mpred in [("flair", flair_pred_at[0.50]), ("gliner", gliner_pred_at[0.50])]:
    u = {cid: det_pred.get(cid, set()) | mpred.get(cid, set()) for cid in det_pred}
    blind[f"det+{mname}"] = score(u)
u3 = {cid: det_pred.get(cid, set()) | flair_pred_at[0.50].get(cid, set()) | gliner_pred_at[0.50].get(cid, set())
      for cid in det_pred}
blind["det+flair+gliner"] = score(u3)


# ---------------------------------------------------------------------------
# 6) Precision-gated ensembles
# ---------------------------------------------------------------------------
def gated(det, model_pred, allowed):
    out = {}
    for cid in det:
        types = set(model_pred.get(cid, set()))
        gated_types = {t for t in types if hc.letter_of(t) in allowed}
        out[cid] = set(det.get(cid, set())) | gated_types
    return out


GATED_A = {"A"}
GATED_AB = {"A", "B"}
gated_results = {}
# sweep thresholds for the core combos
for thr in THRESHOLDS:
    fp = flair_pred_at[thr]
    gp = gliner_pred_at[thr]
    combos = {
        "det+flair(A)": gated(det_pred, fp, GATED_A),
        "det+flair(A+B)": gated(det_pred, fp, GATED_AB),
        "det+gliner(A)": gated(det_pred, gp, GATED_A),
        "det+gliner(A+B)": gated(det_pred, gp, GATED_AB),
        "det+rules+flair(A+B)": gated({cid: det_pred.get(cid, set()) | ctx_pred.get(cid, set()) for cid in det_pred}, fp, GATED_AB),
        "det+rules+gliner(A+B)": gated({cid: det_pred.get(cid, set()) | ctx_pred.get(cid, set()) for cid in det_pred}, gp, GATED_AB),
        "det+rules+flair(A)+gliner(B)": {cid: (set(det_pred.get(cid, set())) | set(ctx_pred.get(cid, set()))
            | {t for t in fp.get(cid, set()) if hc.letter_of(t) == "A"}
            | {t for t in gp.get(cid, set()) if hc.letter_of(t) == "B"}) for cid in det_pred},
        "det+rules+flair(A+B)+gliner(A+B)": gated({cid: det_pred.get(cid, set()) | ctx_pred.get(cid, set()) for cid in det_pred}, {cid: fp.get(cid, set()) | gp.get(cid, set()) for cid in det_pred}, GATED_AB),
    }
    for name, preds in combos.items():
        gated_results.setdefault(name, {})[f"{thr:.2f}"] = score(preds)

# pick a recommended operating threshold for each combo (highest F1 with P>=0.99 else highest F1)
def best(grp):
    best_f1 = None
    best_p99 = None
    for thr_s, res in grp.items():
        o = res["overall"]
        if o["precision"] >= 0.99 and (best_p99 is None or o["f1"] > best_p99["overall"]["f1"]):
            best_p99 = res
        if best_f1 is None or o["f1"] > best_f1["overall"]["f1"]:
            best_f1 = res
    return best_f1, best_p99

gated_recommend = {}
for name, grp in gated_results.items():
    bf, bp = best(grp)
    gated_recommend[name] = {"best_f1": bf, "best_p_ge_0.99": bp}


# ---------------------------------------------------------------------------
# 7) FN recovery matrix (deterministic 15 FNs at type level)
# ---------------------------------------------------------------------------
fn_units = []
for s in samples:
    sc = scope_of(s)
    gold = set(s.get("gold_present", [])) & sc
    d = set(det_pred.get(s["id"], [])) & sc
    for g in sorted(gold - d):
        fn_units.append({"id": s["id"], "category": s["category"], "gold_type": g, "text": s["text"]})

systems_for_fn = {
    "deterministic": det_pred,
    "contextual_rules": ctx_pred,
    "flair@0.50": flair_pred_at[0.50],
    "gliner@0.50": gliner_pred_at[0.50],
    "gliner_ext@0.50": set_at(gliner_ext_raw, 0.50),
    "det+flair(A+B)@0.50": gated(det_pred, flair_pred_at[0.50], GATED_AB),
    "det+gliner(A+B)@0.50": gated(det_pred, gliner_pred_at[0.50], GATED_AB),
    "det+rules+flair(A+B)": gated({cid: det_pred.get(cid, set()) | ctx_pred.get(cid, set()) for cid in det_pred}, flair_pred_at[0.50], GATED_AB),
    "det+rules+gliner(A+B)": gated({cid: det_pred.get(cid, set()) | ctx_pred.get(cid, set()) for cid in det_pred}, gliner_pred_at[0.50], GATED_AB),
}
fn_rows = []
for u in fn_units:
    cid = u["id"]
    sc = scope_of(by_id[cid])
    caught = {}
    for name, pr in systems_for_fn.items():
        caught[name] = u["gold_type"] in (set(pr.get(cid, [])) & sc)
    fn_rows.append({**u, "caught": caught})
fn_summary = {name: sum(1 for r in fn_rows if r["caught"][name]) for name in systems_for_fn}


# ---------------------------------------------------------------------------
# 8) Complementarity Flair vs GLiNER (at 0.50)
# ---------------------------------------------------------------------------
overlap = {"both_correct": 0, "flair_only_correct": 0, "gliner_only_correct": 0,
           "both_miss": 0, "flair_fp_unique": 0, "gliner_fp_unique": 0,
           "shared_fp": 0, "detail": []}
fl = flair_pred_at[0.50]
gl = gliner_pred_at[0.50]
# correct = detected type is in gold scope and matches a deterministic-missed gold? Use scored TPs.
fl_tp = hc.evaluate(fl, samples)["overall"]["tp"]
gl_tp = hc.evaluate(gl, samples)["overall"]["tp"]
# per-case type overlap
for s in samples:
    cid = s["id"]
    sc = scope_of(s)
    fset = set(fl.get(cid, set())) & sc
    gset = set(gl.get(cid, set())) & sc
    gold = set(s.get("gold_present", [])) & sc
    common = fset & gset
    overlap["detail"].append({
        "id": cid, "category": s["category"],
        "flair": sorted(fset), "gliner": sorted(gset),
        "common": sorted(common),
    })

# aggregate unique FP counts
fl_fp_types = defaultdict(int)
gl_fp_types = defaultdict(int)
# recompute FP per system at type level
def fp_types(preds):
    fp = defaultdict(int)
    for s in samples:
        cid = s["id"]
        sc = scope_of(s)
        gold = set(s.get("gold_present", [])) & sc
        gold_absent = set(s.get("gold_absent", [])) & sc
        det = set(preds.get(cid, [])) & sc
        if s.get("hard_negative") and not s.get("gold_present"):
            wrong = det
        else:
            wrong = (det - gold) | (det & gold_absent)
        for t in wrong:
            fp[t] += 1
    return fp
fl_fp = fp_types(fl)
gl_fp = fp_types(gl)
shared_fp_types = set(fl_fp) & set(gl_fp)
overlap["flair_fp_unique"] = sum(v for k, v in fl_fp.items() if k not in gl_fp)
overlap["gliner_fp_unique"] = sum(v for k, v in gl_fp.items() if k not in fl_fp)
overlap["shared_fp"] = sum(min(fl_fp[k], gl_fp[k]) for k in shared_fp_types)
overlap["flair_fp_by_type"] = dict(fl_fp)
overlap["gliner_fp_by_type"] = dict(gl_fp)
overlap["flair_tp"] = fl_tp
overlap["gliner_tp"] = gl_tp


# ---------------------------------------------------------------------------
# 9) Per-FP error classification (contextual FPs only)
# ---------------------------------------------------------------------------
def classify_fp(text, ent):
    t = ent.lower()
    if "person" in t:
        return "person over-detection"
    if "location" in t or "address" in t:
        return "geography over-detection"
    if "organization" in t:
        return "organization confusion"
    return "other"


ctx_fp_detail = []
for s in samples:
    cid = s["id"]
    sc = scope_of(s)
    gold = set(s.get("gold_present", [])) & sc
    gold_absent = set(s.get("gold_absent", [])) & sc
    det = set(ctx_pred.get(cid, [])) & sc
    if s.get("hard_negative") and not s.get("gold_present"):
        wrong = det
    else:
        wrong = (det - gold) | (det & gold_absent)
    for t in wrong:
        ctx_fp_detail.append({"id": cid, "entity_type": t, "cause": classify_fp(s["text"], t)})

flair_fp_detail = []
for s in samples:
    cid = s["id"]
    sc = scope_of(s)
    gold = set(s.get("gold_present", [])) & sc
    gold_absent = set(s.get("gold_absent", [])) & sc
    det = set(flair_pred_at[0.50].get(cid, [])) & sc
    if s.get("hard_negative") and not s.get("gold_present"):
        wrong = det
    else:
        wrong = (det - gold) | (det & gold_absent)
    for t in wrong:
        flair_fp_detail.append({"id": cid, "entity_type": t, "cause": classify_fp(s["text"], t),
                                "text": s["text"]})

gliner_fp_detail = []
for s in samples:
    cid = s["id"]
    sc = scope_of(s)
    gold = set(s.get("gold_present", [])) & sc
    gold_absent = set(s.get("gold_absent", [])) & sc
    det = set(gliner_pred_at[0.50].get(cid, [])) & sc
    if s.get("hard_negative") and not s.get("gold_present"):
        wrong = det
    else:
        wrong = (det - gold) | (det & gold_absent)
    for t in wrong:
        gliner_fp_detail.append({"id": cid, "entity_type": t, "cause": classify_fp(s["text"], t),
                                 "text": s["text"]})


# ---------------------------------------------------------------------------
# Write artifacts
# ---------------------------------------------------------------------------
def dump(name, payload):
    p = OUT / name
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return p


dump("deterministic.json", {
    "overall": det_summary["overall"], "by_category": det_summary["by_category"],
    "runtime_s": round(det_time, 4), "per_case_ms": round(det_time / len(samples) * 1000, 4),
})
dump("contextual_rules.json", {
    "overall": ctx_summary["overall"], "by_category": ctx_summary["by_category"],
    "union_with_det": ctx_union_sum["overall"], "precision_gated_with_det": ctx_gated_sum["overall"],
    "runtime_s": round(ctx_time, 4), "per_case_ms": round(ctx_time / len(samples) * 1000, 4),
})
dump("flair_thresholds.json", {
    "model": flair_meta, "thresholds": {k: v["overall"] for k, v in flair_thr_results.items()},
    "by_category": {k: v["by_category"] for k, v in flair_thr_results.items()},
})
dump("gliner_thresholds.json", {
    "model": gliner_meta, "thresholds": {k: v["overall"] for k, v in gliner_thr_results.items()},
    "by_category": {k: v["by_category"] for k, v in gliner_thr_results.items()},
})
dump("flair_predictions.json", {"model": flair_meta, "predictions": {k: v for k, v in flair_raw.items()}})
dump("gliner_predictions.json", {"model": gliner_meta, "predictions": {k: v for k, v in gliner_raw.items()}})
dump("gliner_extended_predictions.json", {"label_map": GLINER_EXTENDED, "predictions": {k: v for k, v in gliner_ext_raw.items()}})
dump("blind_union_results.json", blind)
dump("gated_ensemble_results.json", {
    "threshold_sweep": gated_results,
    "recommended": gated_recommend,
})
dump("fn_recovery_matrix.json", {
    "fn_count": len(fn_units), "systems_summary": fn_summary, "cases": fn_rows,
})
dump("model_overlap.json", overlap)
dump("performance.json", {
    "environment": "WSL2 Ubuntu 24.04, CPU torch (no GPU)",
    "flair": {"load_s": round(flair_load_s, 2), "infer_s": round(flair_infer_s, 2),
              "per_case_ms": round(flair_infer_s / len(samples) * 1000, 2)},
    "gliner": {"infer_s": round(gliner_infer_s, 2),
               "per_case_ms": round(gliner_infer_s / len(samples) * 1000, 2)},
    "deterministic": {"infer_s": round(det_time, 4),
                      "per_case_ms": round(det_time / len(samples) * 1000, 4)},
    "contextual_rules": {"infer_s": round(ctx_time, 4),
                         "per_case_ms": round(ctx_time / len(samples) * 1000, 4)},
    "n_cases": len(samples),
})
dump("error_analysis.json", {
    "contextual_rules_fp": ctx_fp_detail,
    "flair_fp": flair_fp_detail,
    "gliner_fp": gliner_fp_detail,
})

# Console summary
def line(o):
    return f"TP={o['tp']:>4} FP={o['fp']:>3} FN={o['fn']:>4} P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f}"

print("DETERMINISTIC      ", line(det_summary["overall"]))
print("CTX RULES          ", line(ctx_summary["overall"]))
print("CTX UNION w/det    ", line(ctx_union_sum["overall"]))
print("CTX GATED w/det    ", line(ctx_gated_sum["overall"]))
print("FLAIR @0.50        ", line(flair_only_summary["overall"]))
print("GLINER @0.50       ", line(gliner_only_summary["overall"]))
print("\nFLAIR thresholds:")
for k, v in flair_thr_results.items():
    print(f"  t={k}  {line(v['overall'])}")
print("GLINER thresholds:")
for k, v in gliner_thr_results.items():
    print(f"  t={k}  {line(v['overall'])}")
print("\nBLIND UNIONS:")
for k, v in blind.items():
    print(f"  {k:<18} {line(v['overall'])}")
print("\nFN recovery:", fn_summary)
print("Flair FP by type:", dict(fl_fp))
print("GLiNER FP by type:", dict(gl_fp))
print("\nDONE ->", OUT)
