from __future__ import annotations

"""Common HIPAA adversarial evaluation harness for SecuRedact vs Phileas.

This is evaluation-only tooling. It does NOT modify production detectors.
It scores every system against the SAME 202-case gold corpus using the exact
scope-aware methodology from scripts/experimental/run_hipaa_adversarial.py so
that all numbers are comparable.

Each adapter normalises its output to a set of SecuRedact ``EntityType`` values
for scoring; a separate mapping table converts external (Phileas) PHI types to
the equivalent SecuRedact entity type so the same scorer applies.
"""

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parent.parent.parent
DATA = ROOT / "benchmarks" / "hipaa" / "hipaa_adversarial.json"
OUT_DIR = Path(r"D:\SecuRedactData\hipaa-comparison")

from securedact_core.hipaa import ENTITY_TO_LETTER  # noqa: E402
from securedact_core.models import EntityType  # noqa: E402

ALL_TYPES = {e.value for e in EntityType}

LETTER_TO_TYPES: dict[str, set[str]] = defaultdict(set)
for _etype, _letter in ENTITY_TO_LETTER.items():
    LETTER_TO_TYPES[_letter].add(_etype.value)

# Categories where contextual detection is allowed to add findings in the
# precision-gated ensemble (per mission: A Names, B Geography, R Relationship,
# P genetic/biometric). Contextual is never used to override validated
# deterministic identifiers.
GATED_CATEGORIES = {"A", "B", "R", "P"}


@dataclass
class Prediction:
    case_id: str
    letter: str
    entity_type: str
    text: str
    confidence: Optional[float]
    source: str


@dataclass
class SystemOutput:
    name: str
    predictions: dict[str, set[str]]  # case_id -> set of EntityType.value
    detailed: list[Prediction] = field(default_factory=list)
    note: str = ""


def load_samples() -> list[dict]:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    return data["samples"]


def letter_of(entity_value: str) -> Optional[str]:
    try:
        return ENTITY_TO_LETTER.get(EntityType(entity_value))
    except ValueError:
        return None


def evaluate(predictions: dict[str, set[str]], samples: list[dict]) -> dict:
    per_cat: dict[str, dict] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0, "samples": 0, "miss": [], "extra": []}
    )
    tot = {"tp": 0, "fp": 0, "fn": 0}
    for s in samples:
        letter = s["category"]
        scope = ALL_TYPES if letter == "Q" else LETTER_TO_TYPES.get(letter, set())
        gold = set(s.get("gold_present", [])) & scope
        gold_absent = set(s.get("gold_absent", [])) & scope
        det = predictions.get(s["id"], set()) & scope
        if s.get("hard_negative") and not s.get("gold_present"):
            tp = set()
            fn = set()
            fp = det
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
            c["miss"].append(
                {"id": s["id"], "missing": sorted(fn), "text": s["text"]}
            )
        if fp:
            c["extra"].append(
                {"id": s["id"], "extra": sorted(fp), "text": s["text"]}
            )
        tot["tp"] += len(tp)
        tot["fp"] += len(fp)
        tot["fn"] += len(fn)

    def metrics(tp, fp, fn):
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        return prec, rec, f1

    by_category = {}
    for letter in sorted(per_cat):
        c = per_cat[letter]
        p, r, f = metrics(c["tp"], c["fp"], c["fn"])
        by_category[letter] = {
            "samples": c["samples"],
            "tp": c["tp"],
            "fp": c["fp"],
            "fn": c["fn"],
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1": round(f, 4),
            "missed_case_ids": [m["id"] for m in c["miss"]],
            "extra_case_ids": [e["id"] for e in c["extra"]],
        }
    op, orc, of1 = metrics(tot["tp"], tot["fp"], tot["fn"])
    overall = {
        "tp": tot["tp"],
        "fp": tot["fp"],
        "fn": tot["fn"],
        "precision": round(op, 4),
        "recall": round(orc, 4),
        "f1": round(of1, 4),
    }
    return {"overall": overall, "by_category": by_category}


def run_adapter(
    name: str,
    adapter_fn: Callable[[str], tuple[set[str], list[Prediction]]],
    samples: list[dict],
    note: str = "",
) -> SystemOutput:
    predictions: dict[str, set[str]] = {}
    detailed: list[Prediction] = []
    for s in samples:
        types, preds = adapter_fn(s["text"])
        predictions[s["id"]] = types
        detailed.extend(preds)
    return SystemOutput(name=name, predictions=predictions, detailed=detailed, note=note)


# --- SecuRedact deterministic -------------------------------------------------


def make_regex_adapter():
    from securedact_core.detectors import RegexDetector

    det = RegexDetector()

    def fn(text: str) -> tuple[set[str], list[Prediction]]:
        types: set[str] = set()
        preds: list[Prediction] = []
        for d in det.detect(text):
            t = d.entity_type.value
            types.add(t)
            preds.append(
                Prediction(
                    case_id="", letter=letter_of(t) or "", entity_type=t,
                    text=d.text, confidence=None, source="securedact_regex",
                )
            )
        return types, preds

    return fn


# --- SecuRedact contextual (bundled rule/context layer) -----------------------


def make_contextual_adapter():
    from securedact_core.detectors import ContextualPrivacyDetector

    det = ContextualPrivacyDetector()

    def fn(text: str) -> tuple[set[str], list[Prediction]]:
        types: set[str] = set()
        preds: list[Prediction] = []
        for d in det.detect(text):
            t = d.entity_type.value
            types.add(t)
            preds.append(
                Prediction(
                    case_id="", letter=letter_of(t) or "", entity_type=t,
                    text=d.text, confidence=d.confidence, source="securedact_contextual",
                )
            )
        return types, preds

    return fn


# --- Ensemble ----------------------------------------------------------------


def ensemble_predictions(
    det_pred: dict[str, set[str]],
    ctx_pred: dict[str, set[str]],
    mode: str,
) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for cid in det_pred:
        d = set(det_pred.get(cid, set()))
        c = set(ctx_pred.get(cid, set()))
        if mode == "union":
            out[cid] = d | c
        elif mode == "precision_gated":
            gated = {t for t in c if letter_of(t) in GATED_CATEGORIES}
            out[cid] = d | gated
        else:
            raise ValueError(mode)
    return out


# --- Phileas mapping ---------------------------------------------------------

# Phileas/Philter PHI filter types -> SecuRedact EntityType.value used for
# scoring. Only types that map to an A-R Safe Harbor category are listed;
# unmapped types (e.g. ORGANIZATION) are ignored to avoid false credit.
PHILEAS_TYPE_TO_ENTITY: dict[str, str] = {
    "NAME": "person",
    "PERSON": "person",
    "PATIENT": "person",
    "DOCTOR": "person",
    "FAMILY_NAME": "person",
    "LOCATION": "location",
    "CITY": "location",
    "STATE": "location",
    "COUNTRY": "location",
    "STREET_ADDRESS": "street_address",
    "ZIP": "us_zip",
    "ZIP_CODE": "us_zip",
    "DATE": "date",
    "DATE_OF_BIRTH": "date_of_birth",
    "TIME": "time",
    "AGE": "age",
    "PHONE": "phone",
    "PHONE_NUMBER": "phone",
    "FAX": "fax",
    "EMAIL": "email",
    "SSN": "ssn",
    "MEDICAL_RECORD_NUMBER": "medical_record_number",
    "MRN": "medical_record_number",
    "HEALTH_PLAN": "health_plan_beneficiary",
    "BENEFICIARY": "health_plan_beneficiary",
    "MEMBER_ID": "health_plan_beneficiary",
    "ACCOUNT": "account_number",
    "ACCOUNT_NUMBER": "account_number",
    "BANK": "account_number",
    "CREDIT_CARD": "account_number",
    "LICENSE": "driving_licence_number",
    "DL": "driving_licence_number",
    "PASSPORT": "passport_number",
    "VEHICLE": "vehicle_identifier",
    "VIN": "vehicle_identifier",
    "LICENSE_PLATE": "vehicle_identifier",
    "DEVICE": "device_identifier",
    "URL": "url",
    "IP": "ipv4",
    "IP_ADDRESS": "ipv4",
    "RELATIONSHIP": "relationship",
    "ID": "patient_number",
    "IDENTIFIER": "patient_number",
    "CONTACT": "phone",
}


def phileas_adapter_factory(endpoint: str, profile: str):
    import urllib.request

    def fn(text: str) -> tuple[set[str], list[Prediction]]:
        types: set[str] = set()
        preds: list[Prediction] = []
        q = f"?c={profile}" if profile else ""
        url = f"{endpoint}/api/process{q}"
        data = text.encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "text/plain"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        # Philter returns {"filteredText": ..., "entities": [...]}
        for ent in body.get("entities", []):
            ptype = (ent.get("type") or "").upper()
            mapped = PHILEAS_TYPE_TO_ENTITY.get(ptype)
            if mapped is None:
                continue
            types.add(mapped)
            preds.append(
                Prediction(
                    case_id="", letter=letter_of(mapped) or "", entity_type=mapped,
                    text=ent.get("text", ""), confidence=None, source="phileas",
                )
            )
        return types, preds

    return fn


def write_json(name: str, payload: dict) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def summarize_system(out: SystemOutput, samples: list[dict]) -> dict:
    scored = evaluate(out.predictions, samples)
    return {
        "name": out.name,
        "note": out.note,
        "overall": scored["overall"],
        "by_category": scored["by_category"],
        "n_detailed": len(out.detailed),
    }


def main() -> None:
    samples = load_samples()
    print(f"loaded {len(samples)} cases")

    regex_fn = make_regex_adapter()
    ctx_fn = make_contextual_adapter()

    t0 = time.perf_counter()
    det_out = run_adapter("securedact_deterministic", regex_fn, samples)
    det_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    ctx_out = run_adapter("securedact_contextual", ctx_fn, samples)
    ctx_time = time.perf_counter() - t0

    union_pred = ensemble_predictions(det_out.predictions, ctx_out.predictions, "union")
    gated_pred = ensemble_predictions(det_out.predictions, ctx_out.predictions, "precision_gated")

    union_out = SystemOutput("ensemble_union", union_pred)
    gated_out = SystemOutput("ensemble_precision_gated", gated_pred)

    det_sum = summarize_system(det_out, samples)
    ctx_sum = summarize_system(ctx_out, samples)
    union_sum = summarize_system(union_out, samples)
    gated_sum = summarize_system(gated_out, samples)

    write_json("deterministic_results.json", det_sum)
    write_json("contextual_results.json", ctx_sum)
    write_json(
        "ensemble_results.json",
        {"union": union_sum, "precision_gated": gated_sum},
    )

    # Dump per-case predictions for downstream union / FN analysis.
    write_json(
        "predictions_securedact_deterministic.json",
        {k: sorted(v) for k, v in det_out.predictions.items()},
    )
    write_json(
        "predictions_securedact_contextual_rules.json",
        {k: sorted(v) for k, v in ctx_out.predictions.items()},
    )

    print("\n=== SecuRedact deterministic ===")
    print(_fmt(det_sum["overall"]))
    print("=== SecuRedact contextual ===")
    print(_fmt(ctx_sum["overall"]))
    print("=== Ensemble union ===")
    print(_fmt(union_sum["overall"]))
    print("=== Ensemble precision-gated ===")
    print(_fmt(gated_sum["overall"]))

    perf = {
        "deterministic_total_s": round(det_time, 4),
        "contextual_total_s": round(ctx_time, 4),
        "per_case_deterministic_ms": round(det_time / len(samples) * 1000, 4),
        "per_case_contextual_ms": round(ctx_time / len(samples) * 1000, 4),
        "n_cases": len(samples),
    }
    write_json("performance_results.json", perf)
    print("\nwrote results to", OUT_DIR)


def _fmt(o: dict) -> str:
    return (
        f"TP={o['tp']} FP={o['fp']} FN={o['fn']} "
        f"P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f}"
    )


if __name__ == "__main__":
    main()
