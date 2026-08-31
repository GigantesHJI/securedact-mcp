# HIPAA Safe Harbor Profile (`HIPAA_SAFE_HARBOR`)

**Status:** Implemented (mechanical de-identification aid). This document is
evidence-based and conservative. It does **not** certify HIPAA compliance.

**Regulatory source of truth:** 45 CFR §164.514(b)(2) and the HHS OCR
"Guidance Regarding Methods for De-identification of PHI" (2012).

**Engine used:** the existing profile/policy-driven pipeline
`analyze → redact → scan_residual`, reused verbatim. No parallel HIPAA detection
engine was created.

---

## 1. Scope and non-claims

SecuRedact assists with the *mechanical removal* of the 18 enumerated Safe Harbor
identifier categories from **text**. It is a local, fail-closed, residual-validated
pipeline. It MUST NOT be described as:

- HIPAA "compliant" or "certified";
- a replacement for the actual-knowledge prong (§164.514(b)(2)(ii));
- a replacement for Expert Determination (§164.514(b)(1));
- capable of de-identifying images, audio, or non-text content.

## 2. Safe Harbor vs Expert Determination

Safe Harbor (§164.514(b)(2)) requires removing 18 enumerated identifiers **plus** the
covered entity attesting it has no actual knowledge of re-identification risk. Expert
Determination (§164.514(b)(1)) requires a qualified expert applying accepted
statistical/scientific principles. SecuRedact provides only mechanical identifier
removal for textual content; it cannot perform or substitute for either prong beyond
(i).

## 3. Actual-knowledge limitation

The `(ii)` prong is organizational/legal. Software cannot determine whether a covered
entity "has knowledge" that remaining information could re-identify an individual.
`HipaaSafeHarborResult.actual_knowledge_note` states this explicitly on every run.

## 4. Category matrix (current)

| Letter | Identifier | Status | Contributing entity types |
| --- | --- | --- | --- |
| A | Names | PARTIAL | `person` (labels deterministic; free names need the optional contextual model) |
| B | Geographic < state | PARTIAL | `address`, `street_address`, `house_number`, `us_zip`, `location` (review) |
| C | Dates / ages > 89 | PARTIAL | `date`, `date_of_birth`, `time`, `appointment`, `age` (review) |
| D | Telephone | FULL | `phone` |
| E | Fax | FULL | `fax` |
| F | Email | FULL | `email` |
| G | SSN | FULL | `ssn` |
| H | Medical record number | PARTIAL | `medical_record_number` |
| I | Health plan beneficiary | PARTIAL | `health_plan_beneficiary` (labels/prefixes only) |
| J | Account number | PARTIAL | `bank_account_reference`, `account_number`, `payment_reference` (labels only) |
| K | Certificate/license | PARTIAL | `driving_licence_number`, `national_id`, `passport_number` |
| L | Vehicle identifier | PARTIAL | `vehicle_identifier` (VIN format-detected, no check-digit validation; plates labeled only) |
| M | Device identifier | FULL | `device_identifier` |
| N | Web URL | FULL | `url`, `sensitive_url_parameter`, `internal_url` |
| O | IP address | FULL | `ipv4`, `ipv6` |
| P | Biometric identifier | PARTIAL | `biometric_data`, `genetic_data` (text references only) |
| Q | Full-face photograph / image | UNSUPPORTED_REQUIRES_REVIEW | — (text-only engine) |
| R | Other unique identifier | PARTIAL | `patient_number`, `case_number`, `employee_id`, `customer_number`, `payroll_number`, `invoice_number`, `policy_number`, `unknown_sensitive`, `free_text_sensitive_context`, `relationship` |

Counts: **FULL 7, PARTIAL 10, UNSUPPORTED/REVIEW 1, NOT COVERED 0.**

## 5. Partial-category justification (why not FULL)

- **A Names:** unlabelled free-text names depend on the optional contextual/Flair
  model (opt-in per AGENTS.md). Labelled `name:` fields are detected deterministically.
- **H Medical record number:** labelled `medical record number` / `MRN` values, the `MRN-`
  prefix, and common synonyms (`record number`, `chart ID`, `patient record number`) are
  detected, including separator-less forms (`patient MRN is 558201`). Because generic
  `record number` phrasing can appear in non-medical contexts and some unlabelled MRN forms
  remain, H is kept PARTIAL rather than FULL.
- **B Geographic:** US ZIP and street-address patterns are detected; city/county names
  rely on the contextual model and are surfaced for review, not auto-redacted. States
  are intentionally retained.
- **C Dates:** ages over 89 are surfaced for review; the "except year" transform is not
  auto-applied (detected dates are reviewed rather than partially masked).
- **I Health plan beneficiary:** only labels (`member/subscriber/beneficiary ID`) and
  prefixes (`MBR`/`SUB`/`BEN`) are used; generic alphanumerics are not flagged to avoid
  false positives.
- **J Account:** only labelled account numbers; unlabelled generic numbers are missed.
- **K Certificate/license:** driver's-license, national ID, and passport numbers are
  covered; many professional/occupational certificates are not enumerated.
- **L Vehicle:** VINs are check-digit validated; license plates only from explicit
  labels. Arbitrary 17-character strings are not treated as VINs.
- **P Biometric:** textual references only; raw biometric artifacts are out of scope.
- **R Other:** union of specific identifiers plus contextual sensitive-context
  detection; no dangerous catch-all regex. The §164.514(c) re-id code exception is
  treated conservatively (codes removed by default).

## 6. Unsupported category (Q)

Full-face photographs and comparable images cannot be detected by the text-only
engine. `run_hipaa_safe_harbor` reports Q as `UNSUPPORTED_REQUIRES_REVIEW` and emits a
warning. **Absence of a Q finding does not mean a document is free of identifiable
imagery**; image/PDF inputs must be reviewed out of band.

## 7. Geographic / ZIP handling

- Street addresses, city/county context, and ZIP/ZIP+4 are redacted where detected.
- US states are **retained** (Safe Harbor permits state-level geography).
- **ZIP3 retention rule:** not applied. SecuRedact does not ship a versioned Census
  ZIP3 population dataset, so it cannot safely decide which ZIP3 prefixes may be kept.
  ZIPs are therefore redacted in full (conservative over-retention).
- A five-digit number is only treated as a US ZIP when it appears in a labeled field
  (`zip`/`postal code`) or adjacent to a USPS state token (`ZIP, ST` or `ST ZIP`).
  Bare five-digit numbers, European postcodes (e.g. `10115`), and arbitrary IDs are
  not misclassified as US ZIP.

## 8. Runtime / offline behavior

- All new detection is **deterministic** and **offline**; no network calls are made
  during analysis, redaction, or residual scanning.
- The `HIPAA_SAFE_HARBOR` policy is a built-in `Policy`; it composes with the existing
  `PrivacyEngine` and `engine.audit` flow.
- Residual scanning re-runs the deterministic detectors on the redacted output. A
  successful redaction pass does **not** mean Safe Harbor was satisfied; residual
  supported identifiers are reported explicitly.

## 9. Structured result

`run_hipaa_safe_harbor(engine, text)` returns `HipaaSafeHarborResult`:

- `categories_evaluated` (18), `categories_supported`, `categories_partial`,
  `categories_unsupported`;
- per-category `detected` / `redacted` / `residual` counts and `status`;
- `identifiers_detected`, `identifiers_redacted`, `residual_identifiers_detected`;
- `unsupported_category_warnings` (includes Q) and the `actual_knowledge_note` /
  `disclaimer`.

Counts are derived from the profile and the run; none are hard-coded.

## 10. Testing methodology

- `benchmarks/hipaa/hipaa_safe_harbor.json` — separate from the GDPR corpus — covers
  all 18 categories with positives, hard negatives (invalid SSNs, random 9-digit, bare
  5-digit, non-VIN 17-char, EU identifiers, age < 90), mixed records, and an image
  limitation sample.
- `tests/unit/test_hipaa_safe_harbor.py` asserts presence/absence on the corpus and
  checks the 18-category matrix, residual-scan behavior, and that no compliance claim
  language appears.
- Regression: the full unit suite passes; EU identifiers (BSN, NL
  postcode, IBAN) and unrelated numbers are confirmed not misclassified as US PHI.
- No expensive external model benchmark is required; contextual-name coverage is
  documented as a model-dependent PARTIAL, not tested against Flair.
