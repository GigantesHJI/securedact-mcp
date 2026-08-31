from __future__ import annotations

"""SecuRedact contextual / model detector baseline using the GLiNER PII weights
that SecuRedact already ships (urchade/gliner_multi_pii-v1, cached at
D:\\AI\\huggingface). This is the evaluation-only "contextual model" pass.

It loads the same cached model SecuRedact uses for its GLiNER layer, prompts it
with a general PII label set, maps each label to a SecuRedact EntityType via an
explicit table, and scores it against the 202-case corpus using the shared
scorer in hipaa_compare.py. It does NOT modify production code.
"""

import importlib.util
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HF_HOME = r"D:\AI\huggingface"
os.environ.setdefault("HF_HOME", HF_HOME)

# Load the shared harness (defines evaluate, SystemOutput, letter_of, etc.)
import sys

spec = importlib.util.spec_from_file_location(
    "hipaa_compare", str(ROOT / "scripts" / "experimental" / "hipaa_compare.py")
)
hc = importlib.util.module_from_spec(spec)
sys.modules["hipaa_compare"] = hc
spec.loader.exec_module(hc)

# GLiNER PII label -> SecuRedact EntityType.value. Only labels that map to an
# A-R Safe Harbor category are included; unmapped labels are ignored.
GLINER_LABEL_TO_ENTITY = {
    "person": "person",
    "full name": "person",
    "location": "location",
    "city": "location",
    "state": "location",
    "country": "location",
    "address": "street_address",
    "street address": "street_address",
    "zip code": "us_zip",
    "postal code": "us_zip",
    "email": "email",
    "phone number": "phone",
    "phone": "phone",
    "fax": "fax",
    "date of birth": "date_of_birth",
    "date": "date",
    "social security number": "ssn",
    "ssn": "ssn",
    "medical record number": "medical_record_number",
    "mrn": "medical_record_number",
    "driver license": "driving_licence_number",
    "driver license number": "driving_licence_number",
    "passport": "passport_number",
    "passport number": "passport_number",
    "patient id": "patient_number",
    "account number": "account_number",
    "credit card": "account_number",
    "vehicle identification number": "vehicle_identifier",
    "vin": "vehicle_identifier",
    "username": "free_text_sensitive_context",
    "ip address": "ipv4",
    "url": "url",
}
GLINER_PROMPTS = list(GLINER_LABEL_TO_ENTITY.keys())
THRESHOLD = 0.5


def main() -> None:
    from huggingface_hub import snapshot_download

    local = snapshot_download(
        "urchade/gliner_multi_pii-v1",
        revision="main",
        cache_dir=HF_HOME,
        local_files_only=True,
        local_dir_use_symlinks=False,
    )
    from gliner import GLiNER

    model = GLiNER.from_pretrained(str(local))
    model.eval()

    samples = hc.load_samples()

    predictions: dict[str, set[str]] = {}
    detailed: list[hc.Prediction] = {}
    detailed = []
    t0 = time.perf_counter()
    for s in samples:
        text = s["text"]
        preds = model.predict_entities(text, GLINER_PROMPTS, threshold=THRESHOLD)
        types: set[str] = set()
        for p in preds:
            label = (p.get("label") or "").lower()
            ent = GLINER_LABEL_TO_ENTITY.get(label)
            if ent is None:
                continue
            types.add(ent)
            span = p.get("text", "")
            detailed.append(
                hc.Prediction(
                    case_id=s["id"], letter=hc.letter_of(ent) or "",
                    entity_type=ent, text=span,
                    confidence=float(p.get("score", 0.0)),
                    source="securedact_contextual_gliner",
                )
            )
        predictions[s["id"]] = types
    elapsed = time.perf_counter() - t0

    out = hc.SystemOutput("securedact_contextual_model", predictions, detailed)
    summary = hc.summarize_system(out, samples)
    hc.write_json("contextual_model_results.json", summary)
    print("=== SecuRedact contextual MODEL (GLiNER PII) ===")
    o = summary["overall"]
    print(f"TP={o['tp']} FP={o['fp']} FN={o['fn']} "
          f"P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f}")
    print(f"model load+run total: {elapsed:.2f}s for {len(samples)} cases")

    # Ensemble: deterministic + contextual model (union and precision-gated)
    regex_fn = hc.make_regex_adapter()
    det_out = hc.run_adapter("securedact_deterministic", regex_fn, samples)
    union = hc.ensemble_predictions(det_out.predictions, predictions, "union")
    gated = hc.ensemble_predictions(det_out.predictions, predictions, "precision_gated")
    union_out = hc.SystemOutput("ensemble_union_model", union)
    gated_out = hc.SystemOutput("ensemble_precision_gated_model", gated)
    union_sum = hc.summarize_system(union_out, samples)
    gated_sum = hc.summarize_system(gated_out, samples)
    hc.write_json(
        "ensemble_model_results.json",
        {"union": union_sum, "precision_gated": gated_sum},
    )
    print("=== Ensemble deterministic + contextual MODEL (union) ===")
    uo = union_sum["overall"]
    print(f"TP={uo['tp']} FP={uo['fp']} FN={uo['fn']} "
          f"P={uo['precision']:.3f} R={uo['recall']:.3f} F1={uo['f1']:.3f}")
    print("=== Ensemble deterministic + contextual MODEL (precision-gated) ===")
    go = gated_sum["overall"]
    print(f"TP={go['tp']} FP={go['fp']} FN={go['fn']} "
          f"P={go['precision']:.3f} R={go['recall']:.3f} F1={go['f1']:.3f}")


if __name__ == "__main__":
    main()
