from __future__ import annotations

"""Phileas/Philter evaluation adapter for the 202-case HIPAA adversarial corpus.

Runs the official open-source Philter (Apache-2.0) de-identification service
inside a local Docker container (philterd/philter:3.4.1) and scores its
/api/explain output against the shared gold corpus.

Configuration applied (fair, not under-configured):
  * A custom policy ``hipaa-full`` enabling every PHI/PII filter Philter ships
    that maps to a Safe Harbor category (names NER + lexicon, SSN/TIN, dates,
    ages, emails, phones, URLs, VINs, IP, ZIP, cities/counties/states/hospitals,
    driver license, passport, credit card, bank routing, IBAN, MRN, tracking,
    bitcoin, MAC, physician NER).
  * Default REDACT strategy, no confidence gating (so we measure raw recall too).

This script never sends text to any third-party cloud; Philter runs locally.
"""

import importlib.util
import json
import ssl
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HF_HOME = r"D:\AI\huggingface"

spec = importlib.util.spec_from_file_location(
    "hipaa_compare", str(ROOT / "scripts" / "experimental" / "hipaa_compare.py")
)
hc = importlib.util.module_from_spec(spec)
import sys

sys.modules["hipaa_compare"] = hc
spec.loader.exec_module(hc)

PHILTER_URL = "https://localhost:8080"
API_KEY = "benchkey"
POLICY = "hipaa-bench"

# Working (singular) identifier keys observed to bind correctly in Philter 3.4.1;
# each strategy list key is the identifier key with its first letter upper-cased.
CANONICAL_IDENTIFIERS = [
    "emailAddress", "phoneNumber", "ssn", "date", "url", "vin", "ipAddress",
    "age", "zip", "city", "county", "state", "stateAbbreviation", "hospital",
    "hospitalAbbreviation", "firstName", "surname", "ner", "physician",
    "driversLicense", "passport", "creditCard", "bankRoutingNumber", "iban",
    "macAddress", "bitcoinAddress", "trackingNumber", "medicalRecordNumber",
]

# Philter filterType (uppercased) -> SecuRedact EntityType.value used for scoring.
PHILTER_TYPE_TO_ENTITY = {
    "FIRST_NAME": "person",
    "SURNAME": "person",
    "NER_ENTITY": "person",
    "PERSON": "person",
    "PHYSICIAN": "person",
    "SSN": "ssn",
    "TIN": "ssn",
    "DATE": "date",
    "DOB": "date_of_birth",
    "AGE": "age",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "PHONE_NUMBER_EXTENSION": "phone",
    "URL": "url",
    "VIN": "vehicle_identifier",
    "IP_ADDRESS": "ipv4",
    "IPV6_ADDRESS": "ipv6",
    "LOCATION_STATE": "location",
    "STATE_ABBREVIATION": "location",
    "CITY": "location",
    "COUNTY": "location",
    "HOSPITAL": "location",
    "HOSPITAL_ABBREVIATION": "location",
    "ZIP": "us_zip",
    "ZIP_CODE": "us_zip",
    "DRIVERS_LICENSE_NUMBER": "driving_licence_number",
    "PASSPORT_NUMBER": "passport_number",
    "PASSPORT": "passport_number",
    "CREDIT_CARD": "account_number",
    "BANK_ROUTING_NUMBER": "account_number",
    "IBAN": "account_number",
    "BITCOIN_ADDRESS": "account_number",
    "MEDICAL_RECORD_NUMBER": "medical_record_number",
    "TRACKING_NUMBER": "patient_number",
    "NATIONAL_ID": "national_id",
    "SECTION": None,  # structural; not a HIPAA identifier
    "MAC_ADDRESS": None,
    "ALREADY_REDACTED": None,
}


def _api(method: str, path: str, data=None, ctype="application/json"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"Authorization": f"Bearer {API_KEY}"}
    if data is not None:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(
        PHILTER_URL + path,
        data=data.encode() if isinstance(data, str) else data,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
        return resp.status, resp.read().decode()


def ensure_policy() -> None:
    policy = {
        "name": POLICY,
        "identifiers": {
            k: {
                f"{k[0].upper()}{k[1:]}FilterStrategies": [
                    {"strategy": "REDACT", "redactionFormat": "{{{REDACTED-%t}}}"}
                ]
            }
            for k in CANONICAL_IDENTIFIERS
        },
    }
    # Try create; tolerate already-exists.
    try:
        _api("POST", f"/api/policies?name={POLICY}", json.dumps(policy))
    except Exception as exc:  # noqa: BLE001
        print("policy create note:", exc)


def run() -> None:
    ensure_policy()
    samples = hc.load_samples()

    predictions: dict[str, set[str]] = {}
    detailed: list[hc.Prediction] = []
    observed_types: set[str] = set()
    conf_by_type: dict[str, list[float]] = {}

    t0 = time.perf_counter()
    per_case_ms: list[float] = []
    for s in samples:
        text = s["text"]
        tc = time.perf_counter()
        try:
            _, body = _api(
                "POST", f"/api/explain?p={POLICY}", text, ctype="text/plain"
            )
            resp = json.loads(body)
        except Exception as exc:  # noqa: BLE001
            print("explain error for", s["id"], exc)
            predictions[s["id"]] = set()
            per_case_ms.append((time.perf_counter() - tc) * 1000)
            continue
        types: set[str] = set()
        for sp in resp.get("explanation", {}).get("appliedSpans", []):
            ft = (sp.get("filterType") or "").upper()
            observed_types.add(ft)
            ent = PHILTER_TYPE_TO_ENTITY.get(ft)
            if ent is None:
                continue
            types.add(ent)
            conf = float(sp.get("confidence", 0.0) or 0.0)
            conf_by_type.setdefault(ft, []).append(conf)
            detailed.append(
                hc.Prediction(
                    case_id=s["id"],
                    letter=hc.letter_of(ent) or "",
                    entity_type=ent,
                    text=sp.get("text", ""),
                    confidence=conf,
                    source="phileas",
                )
            )
        predictions[s["id"]] = types
        per_case_ms.append((time.perf_counter() - tc) * 1000)
    elapsed = time.perf_counter() - t0

    out = hc.SystemOutput("phileas", predictions, detailed)
    summary = hc.summarize_system(out, samples)
    hc.write_json(
        "predictions_phileas.json",
        {k: sorted(v) for k, v in predictions.items()},
    )
    summary["config"] = {
        "engine": "Philter/Phileas (philterd/philter:3.4.1, Apache-2.0)",
        "policy": POLICY,
        "filters_enabled": CANONICAL_IDENTIFIERS,
        "strategy": "REDACT",
        "confidence_gating": "none (raw)",
        "endpoint": "/api/explain",
        "local": True,
        "observed_filter_types": sorted(observed_types),
    }
    hc.write_json("phileas_results.json", summary)

    o = summary["overall"]
    print("=== Phileas/Philter ===")
    print(f"TP={o['tp']} FP={o['fp']} FN={o['fn']} "
          f"P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f}")
    print(f"total {elapsed:.1f}s for {len(samples)} cases; "
          f"mean {sum(per_case_ms)/len(per_case_ms):.1f}ms/case "
          f"(min {min(per_case_ms):.1f}, max {max(per_case_ms):.1f})")

    perf = json.loads(
        (hc.OUT_DIR / "performance_results.json").read_text(encoding="utf-8")
    )
    perf["phileas"] = {
        "total_s": round(elapsed, 2),
        "mean_per_case_ms": round(sum(per_case_ms) / len(per_case_ms), 2),
        "min_per_case_ms": round(min(per_case_ms), 2),
        "max_per_case_ms": round(max(per_case_ms), 2),
    }
    hc.write_json("performance_results.json", perf)


if __name__ == "__main__":
    run()
