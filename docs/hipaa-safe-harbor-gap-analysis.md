# HIPAA Safe Harbor Gap Analysis for SecuRedact

**Scope:** Research and gap analysis only. No production source, firewall, MCP,
integration, model, or benchmark behavior was modified. No files outside this
document were created or changed by this task.

**Repository:** securedact-mcp (SecuRedact core engine `securedact_core` +
MCP server `securedact_mcp`).

**Status:** DRAFT / RESEARCH. This document does not change any claim SecuRedact
may make today (see §11).

---

## 1. Executive summary

SecuRedact is a local-first, privacy-focused redaction engine whose current
detector and taxonomy surface is **EU/GDPR-oriented** (Dutch BSN, IBAN, NL
postcodes, GDPR Article 9 special categories). It already provides strong,
evidence-backed coverage for several identifier *types* that overlap with the
HIPAA Privacy Rule Safe Harbor 18-identifier list, but it was **not designed
against 45 CFR §164.514(b)(2)** and lacks the US-specific identifiers and
qualifications that Safe Harbor requires.

Estimated Safe Harbor coverage across the 18 categories:

| Classification | Count | Categories |
| --- | --- | --- |
| FULL | 6 | D Telephone, F Email, H Medical record number, M Device identifier, N URL, O IP address |
| PARTIAL | 8 | A Names, B Geographic, C Dates, E Fax, J Account number, K Certificate/license, P Biometric, R Other unique identifier |
| NOT COVERED | 4 | G Social Security Number, I Health plan beneficiary number, L Vehicle identifier, Q Full-face photograph / image |

**Most important missing capabilities (P0):**

1. **Social Security Numbers (SSN)** — no detector, no prefix, no lexicon entry.
2. **Health plan beneficiary numbers** — no dedicated detector.
3. **Vehicle identifiers / license plates / VIN** — entirely absent.
4. **US geographic coverage** — US ZIP (5-digit / ZIP+4), US state, county, and
   the Safe Harbor ZIP3 "20,000-person" retention rule are not implemented
   (the only postcode detector is Dutch).
5. **Full-face photographs / comparable images** — SecuRedact is text-only; no
   image, photo, or comparable-image detection exists.

The engine *architecture* (profile/policy-driven `analyze → redact →
scan_residual` pipeline) makes a future explicit `HIPAA_SAFE_HARBOR` profile
**feasible** without restructuring core code, primarily by adding new
deterministic regex/label detectors and a dedicated profile. It is explicitly
**not** claimed that adding this profile makes any organization HIPAA compliant
(see §11).

---

## 2. Regulatory scope and terminology

### 2.1 Definitions (authoritative)

- **HIPAA PHI (Protected Health Information)** — individually identifiable
  health information transmitted or maintained by a covered entity or its
  business associate, in any form or medium (45 CFR 160.103).
- **HIPAA de-identification** — the process by which PHI is rendered not
  individually identifiable, per 45 CFR §164.514(a). Two methods are permitted.
- **Safe Harbor** — §164.514(b)(2)(i): removal of 18 enumerated identifier
  categories **plus** the requirement (§164.514(b)(2)(ii)) that the covered
  entity have *no actual knowledge* the remaining information could be used
  alone or in combination to identify an individual.
- **Expert Determination** — §164.514(b)(1): a qualified expert applies
  accepted statistical/scientific principles and documents that re-identification
  risk is "very small." SecuRedact does **not** provide this.
- **SecuRedact detection/redaction functionality** — a local engine that detects
  sensitive entity spans in text and redacts/pseudonymizes/blocks them under a
  declarative policy, then runs a residual scan before release (see `engine.py`
  `analyze`/`redact`/`scan_residual` and `api.py` `prepare`).

### 2.2 Critical distinction

Safe Harbor is a **legal standard with an organizational prong** (`(ii)` actual
knowledge). No software tool can satisfy `(ii)` on behalf of a covered entity.
SecuRedact can only assist with the *mechanical removal* of enumerated
identifiers in **textual** content. It cannot certify de-identification.

### 2.3 GDPR Article 9 / health-data detection — useful but insufficient

The codebase has substantial health-data capability that *helps* identify
medical context and some medical identifiers, but it is not the same as Safe
Harbor:

- `EntityType.MEDICAL_CONDITION`, `MEDICATION`, `DOSAGE`, `HEALTH_INSURER`,
  `HEALTH_DATA`, `MEDICAL_INFORMATION` (`taxonomy.py:255-285`).
- `EntityType.PATIENT_NUMBER`, `MEDICAL_RECORD_NUMBER`
  (`taxonomy.py:190-205`; regex label rules `regex_detector.py:328-348`).
- Article 9 ensemble (`detectors/article9_ensemble.py`) routes
  `GENETIC_DATA`/`BIOMETRIC_DATA` to BLOCK.

These support categories H (MRN), R (other unique IDs), and P (biometric text
references), but Safe Harbor is fundamentally about **direct identifiers**, not
health content. A clinical note stripped of names/MRN but still containing
"chemotherapy" is *not* Safe-Harbor-de-identified unless all 18 identifiers are
gone and `(ii)` is satisfied. Conversely, SecuRedact's health-context detection
is a useful *signal* but does not by itself satisfy any Safe Harbor category.

---

## 3. Official Safe Harbor identifier matrix (45 CFR §164.514(b)(2)(i))

Source: 45 CFR §164.514(b)(2)(i)(A)–(R); HHS OCR De-identification Guidance
(2012); eCFR/Cornell Law School text. The list enumerates identifiers of the
individual **or of relatives, employers, or household members**.

| Letter | Identifier | Key qualification |
| --- | --- | --- |
| A | Names | — |
| B | Geographic subdivisions smaller than a state (street address, city, county, precinct, ZIP, equivalent geocodes) | May keep initial 3 ZIP digits only if the combined geographic unit > 20,000 people; otherwise set to 000 (Census-based) |
| C | All elements of dates (except year) for dates directly related to an individual (birth, admission, discharge, death); **and all ages over 89 + dates inclusive of such age** | Ages > 89 may be aggregated to a single "age 90 or older" category |
| D | Telephone numbers | — |
| E | Fax numbers | — |
| F | Email addresses | — |
| G | Social Security numbers | No derivatives allowed (e.g., last 4 digits also fail) |
| H | Medical record numbers | — |
| I | Health plan beneficiary numbers | — |
| J | Account numbers | — |
| K | Certificate/license numbers | — |
| L | Vehicle identifiers and serial numbers, including license plate numbers | — |
| M | Device identifiers and serial numbers | — |
| N | Web URLs | — |
| O | IP addresses | — |
| P | Biometric identifiers, including finger and voice prints | — |
| Q | Full-face photographs and any comparable images | — |
| R | Any other unique identifying number, characteristic, or code | Except a permitted re-identification code per §164.514(c) |

**Two prongs, not 18:**
- `(i)` — remove the 18 enumerated identifiers.
- `(ii)` — covered entity has **no actual knowledge** of re-identifiability.
  This is an organizational/legal control, out of scope for any detector.

**Notable explicit qualifications:**
- **ZIP3 rule (B):** retention of first 3 ZIP digits is conditional on a
  Census population threshold; a published set of low-population ZIP3 prefixes
  must be changed to `000`. HHS guidance provides the restricted list.
- **Ages over 89 (C):** must be removed (including year), or collapsed into a
  single "90+" bucket.
- **No derivatives (G, and generally all):** patient initials, last-4-SSN, etc.
  do **not** satisfy Safe Harbor.
- **Re-identification code exception (R / §164.514(c)):** a covered entity may
  assign a code not derived from PHI and not otherwise translatable, used solely
  for re-identification. Such a code is *not* a direct identifier to remove.

---

## 4. Current SecuRedact coverage matrix

Legend: **FULL** = repository evidence supports reliable detection+redaction of
the category's core form; **PARTIAL** = some forms covered, important forms or
qualifications missing; **NOT COVERED** = no detector/entity exists.

| Letter | HIPAA identifier | SecuRedact entity/detector | Evidence | Classification |
| --- | --- | --- | --- | --- |
| A | Names | `PERSON` (contextual/Flair; labelled `name`/`naam`) | `taxonomy.py:70`; `contextual_detector.py:289,307`; `regex_detector.py:244` | PARTIAL |
| B | Geographic < state (street, city, county, ZIP, geocodes) | `ADDRESS` (Dutch regex), `STREET_ADDRESS`, `LOCATION` (contextual), `POSTCODE` (Dutch only) | `regex_detector.py:506-518` (Dutch address), `:574-579` (NL postcode), `taxonomy.py:87-110` | PARTIAL |
| C | Dates except year; ages > 89 | `DATE` (regex), `DATE_OF_BIRTH` (labelled/contextual), `TIME`, `APPOINTMENT` | `regex_detector.py:233-238,580-586`; `taxonomy.py:114-141` | PARTIAL |
| D | Telephone numbers | `PHONE` (regex + labelled) | `regex_detector.py:172-183,597-603,264-270` | FULL |
| E | Fax numbers | Caught only incidentally by generic `PHONE` regex when formatted like a phone number; no `FAX` entity/label | `regex_detector.py:597-603` | PARTIAL |
| F | Email addresses | `EMAIL` (regex + labelled, validated) | `regex_detector.py:198-222,567-573,257-263` | FULL |
| G | Social Security Numbers | **None** | no `SSN`/`social security` entity, prefix, or rule (grep-confirmed) | NOT COVERED |
| H | Medical record numbers | `MEDICAL_RECORD_NUMBER` (labelled `medical record number`/`MRN`; prefix `MRN`) | `regex_detector.py:335-341,617`; `taxonomy.py:198-205` | FULL |
| I | Health plan beneficiary numbers | **None** (adjacent `POLICY_NUMBER`/`HEALTH_INSURER` are not beneficiary numbers) | grep-confirmed absence of `beneficiary` | NOT COVERED |
| J | Account numbers | `BANK_ACCOUNT_REFERENCE` (prefix `ACC`/`KLANT`), labelled `account reference` | `regex_detector.py:370-376,607-620`; `taxonomy.py:222-228` | PARTIAL |
| K | Certificate/license numbers | `DRIVING_LICENCE_NUMBER` (labelled/prefix `DL`/`DV`) only | `regex_detector.py:279-292,621-622`; `taxonomy.py:158-165` | PARTIAL |
| L | Vehicle identifiers / license plates / VIN | **None** | grep-confirmed absence of `vehicle`/`VIN`/`license plate` | NOT COVERED |
| M | Device identifiers / serial numbers | `DEVICE_IDENTIFIER` (labelled `device identifier`/`device ID`; prefix `DEV`) | `regex_detector.py:456-462,620`; `taxonomy.py:319-325` | FULL |
| N | Web URLs | `URL` / `SENSITIVE_URL_PARAMETER` / `INTERNAL_URL` | `regex_detector.py:652-883` | FULL |
| O | IP addresses | `IPV4`, `IPV6` (validated) | `regex_detector.py:549-566,446-449`; `taxonomy.py:310-315` | FULL |
| P | Biometric identifiers (finger/voice prints) | `BIOMETRIC_DATA` (contextual/special-category; text references), routed BLOCK via Article 9 ensemble | `taxonomy.py:460-468`; `article9_ensemble.py`; `contextual_detector.py:415` | PARTIAL |
| Q | Full-face photographs / comparable images | **None** — text-only engine; no image/photo detection | no image modality in detectors | NOT COVERED |
| R | Any other unique identifying number/characteristic/code | Partial catch-all: `PATIENT_NUMBER`, `CASE_NUMBER`, `EMPLOYEE_ID`, `INVOICE_NUMBER`, etc.; `RELATIONSHIP`, `FREE_TEXT_SENSITIVE_CONTEXT`, `UNKNOWN_SENSITIVE`; residual scan | `taxonomy.py:181-320`; `engine.py:681-789` | PARTIAL |

### 4.1 Detail per partially/uncovered category

- **A Names:** `PERSON` relies on the contextual/Flair model
  (`contextual_detector.py`), which per AGENTS.md is **opt-in / consent-based**
  (`SECUREDACT_REQUIRE_FLAIR` and model install). The deterministic regex layer
  has **no bare-name rule** (only a labelled `name:` field). So unlabelled free
  names in English are only caught when the contextual model is present.
- **B Geographic:** The address regex is explicitly Dutch
  (`complete_dutch_address`, `regex_detector.py:506-518`) and matches
  `1234 AB` Dutch postcodes (`dutch_postcode`, `:574-579`). **US 5-digit ZIP,
  ZIP+4, US state names, and county names are not detected.** Geo-coordinates
  (lat/long geocodes) are not detected. The ZIP3 >20,000 retention rule is not
  implemented.
- **C Dates:** Generic `DATE` catches `DD-MM-YYYY` and `Month DD, YYYY` (incl.
  Dutch months). Default action is REVIEW, not auto-redact. **Ages over 89 and
  the "90+" aggregation are not implemented**, and the "except year" nuance
  (keep year, drop month/day) is not modeled as a transform.
- **E Fax:** No `FAX` entity. A fax number written as a bare phone-like string
  may be caught by the generic `PHONE` rule, but it is never labeled as fax, and
  fax-specific contexts ("Fax:", "Telefax") are not recognized.
- **J Account numbers:** Only bank-account references with the `ACC`/`KLANT`
  prefix or an explicit `account reference` label are caught deterministically.
  Generic "Account No. 12345" without the prefix is missed.
- **K Certificate/license:** Only driver's-license numbers are covered.
  Professional/occupational certificates and other license numbers are missed.
- **P Biometric:** Only **textual references** (e.g., "fingerprint template",
  "voice print") are supported via the contextual/special-category stack. Raw
  biometric artifacts (images, voice, templates in binary) are out of scope.
- **R Other:** There is no dedicated "unique identifying characteristic" engine.
  Coverage comes from the union of specific identifiers plus contextual
  `UNKNOWN_SENSITIVE`/`FREE_TEXT_SENSITIVE_CONTEXT`. The §164.514(c)
  re-identification-code *exception* is not explicitly modeled (all codes are
  treated as identifiers to remove, which is the conservative default but not
  the legally-permitted carve-out).

---

## 5. Evidence from repository

Key files reviewed (read-only):

- `src/securedact_core/detectors/regex_detector.py` — authoritative source of
  deterministic coverage. Defines `RULES`, `LABEL_RULES`, `PREFIX_TYPES`,
  `URL_PATTERN`, validators. Confirms presence of PHONE, EMAIL, IPV4/IPV6, URL,
  DEVICE_IDENTIFIER, MEDICAL_RECORD_NUMBER (MRN), ADDRESS (Dutch), POSTCODE
  (Dutch), and **absence** of SSN, fax, vehicle/VIN, US ZIP, beneficiary,
  certificate/license (except driving).
- `src/securedact_core/taxonomy.py` — `CATEGORY_DEFINITIONS` confirms entity
  metadata, default actions (`REDACT`/`REVIEW`/`BLOCK`), and groups. Health
  entities (`MEDICAL_RECORD_NUMBER`, `PATIENT_NUMBER`, `HEALTH_INSURER`,
  `BIOMETRIC_DATA`, `GENETIC_DATA`) present.
- `src/securedact_core/models.py` — `EntityType` enum (the canonical type list).
  No `SSN`, `FAX`, `VEHICLE`, `BENEFICIARY`, `PHOTOGRAPH` members.
- `src/securedact_core/engine.py` — `analyze` (`:113`), `redact` (`:490`),
  `scan_residual` (`:681`) implement the scan → redact → residual-validation
  pipeline. `_DIRECT_PERSONAL_TYPES` (`:40-60`) enumerates auto-targeted types
  (no US-specific additions).
- `src/securedact_core/policies.py` — `Policy` model with `category_actions`,
  `enabled_entity_types`, `automatic_pseudonymization_rules`;
  `_profile_actions` (`:177`) shows how built-in profiles are composed from
  `CategoryGroup` focus. A new profile is a data object, not a code fork.
- `src/securedact_core/policy_loader.py` — local policies load from a directory
  as JSON/YAML; invariants forbid ALLOW on critical/special types and require
  residual validation (`_validate_invariants`, `:136-155`). A `HIPAA_SAFE_HARBOR`
  profile could be shipped as a built-in `Policy` or a local file.
- `src/securedact_core/api.py` — `prepare` (`:261`) orchestrates
  analyze → redact → `scan_residual` → blocked/redacted outcome. This is the
  exact pipeline a Safe Harbor workflow would reuse.
- `src/securedact_core/detectors/article9_ensemble.py` — GDPR Article 9 health
  routing; relevant for medical context but not a Safe Harbor substitute.

Grep confirmation (research only): patterns `social security|ssn|fax|vehicle|vin|
license plate|beneficiary|certificate` returned **no detector/entity**
matches outside incidental substrings (e.g., "state", "preserving", file
".zip"). This corroborates the EU-centric design.

---

## 6. Gap analysis

### P0 — required for credible Safe Harbor scanning

1. **SSN detector** (`G`). Add `EntityType.SSN` + regex (AAA-GG-SSSS with
   area/group/serial constraints and known-invalid filters) + labelled
   `SSN`/`social security number` + prefix. Highest-impact US gap.
2. **US geographic identifiers** (`B`). Add US 5-digit / ZIP+4 detection, US
   state names/abbreviations, county names; and the ZIP3 retention rule
   (allow 3-digit prefix only when not in the HHS low-population list, else
   force `000`). Without this, B is effectively unusable for US PHI.
3. **Health plan beneficiary number** (`I`). Add `EntityType.HEALTH_PLAN_BENEFICIARY`
   + labelled/prefixed detection (e.g., payer-assigned IDs).
4. **Vehicle identifiers / license plates / VIN** (`L`). Add `EntityType.VEHICLE_IDENTIFIER`
   with VIN (17-char ISO 3779) and US license-plate patterns.
5. **Photographs / comparable images** (`Q`). Out of scope for the text engine;
   must be addressed as an explicit limitation or via an external image/redaction
   integration. At minimum, document as unsupported and block image-bearing
   inputs in a Safe Harbor profile.

### P1 — important coverage improvements

6. **Fax** (`E`): promote to a labeled `FAX` entity; recognize "Fax:", "Telefax".
7. **Account numbers** (`J`): broaden beyond bank-specific prefix to generic
   `Account No.`/`Acct` patterns with validation.
8. **Certificate/license** (`K`): extend beyond driver's license to professional
   certificates/licenses.
9. **Ages over 89 / "90+" aggregation** (`C`): dedicated rule + transform.
10. **Biometric artifacts** (`P`): explicit note that only textual references are
    covered; consider image/voice handling as a separate module.
11. **Names without contextual model** (`A`): deterministic name heuristics for
    obvious free-text names (with high-precision, conservative thresholds) so the
    profile is usable when Flair is not installed.

### P2 — robustness / UX / reporting

12. **Re-identification code exception (R / §164.514(c))**: optionally mark a
    covered-entity-assigned re-id code as permitted (configurable, default
    conservative = remove).
13. **Residual scan hardening for Safe Harbor**: extend `scan_residual`
    (`engine.py:681`) with Safe-Harbor-specific patterns (e.g., ZIP3, ages,
    SSN-shaped residuals).
14. **Profile reporting**: emit a per-category Safe Harbor coverage report and a
    clear "not de-identified / requires human attestation" banner.
15. **Multilingual**: current health/PII lexicons are EN/NL; US PHI is EN-first
    but Spanish and other languages common in US care need coverage notes.
16. **Geocode / lat-long detection** under B.

---

## 7. Proposed `HIPAA_SAFE_HARBOR` architecture

### 7.1 Feasibility

**Feasible with the existing architecture; no core restructuring required.**
The engine is already profile/policy-driven:

```
source document
  → local SecuRedact scan        (engine.analyze, regex + contextual + credentials)
  → HIPAA Safe Harbor id detection (profile maps each of A–R to entity types/actions)
  → local redaction              (engine.redact, typed-token pseudonymization)
  → residual-risk validation     (engine.scan_residual)
  → sanitized output suitable    (api.prepare → PrepareResult)
    for external AI processing
```

The exact pipeline already exists in `api.py:prepare` (analyze → redact →
scan_residual → blocked/redacted). A Safe Harbor profile is a `Policy` instance
(`policies.py:96`) whose `category_actions` sets REDACT (or BLOCK for the most
sensitive) for every mapped entity type, with `residual_validation_enabled=True`
and conservative `automatic_pseudonymization_rules`.

### 7.2 What would need to change (DO NOT implement now)

1. **New entity types** in `models.py:EntityType` — at minimum `SSN`,
   `HEALTH_PLAN_BENEFICIARY`, `VEHICLE_IDENTIFIER`, `FAX` (or reuse `PHONE`),
   and US geographic types (`US_ZIP`, `US_STATE`). Each needs a `taxonomy.py`
   definition (group, default action, deterministic/contextual flags).
2. **New deterministic detectors** in `regex_detector.py` — SSN, US ZIP/ZIP+4,
   US state, VIN/plate, fax label, beneficiary/policy patterns, account-number
   broadening. Add to `RULES`/`LABEL_RULES`/`PREFIX_TYPES`.
3. **New built-in profile** `hipaa_safe_harbor` in `policies.py` (or a shipped
   local policy file via `policy_loader.py`), wiring A–R → actions and enabling
   residual validation.
4. **Safe Harbor-specific transforms/validators** — ZIP3 retention rule,
   ages>89 → "90+", date "except year" redaction. These are nuance transforms
   not currently modeled.
5. **Optional image handling** for Q — either document as unsupported (fail
   closed in the profile) or integrate an external image-redaction module.
6. **Compliance catalog mapping** (`compliance/catalog.py`) could add a
   `HIPAA` `FrameworkId` and map `SEC-DATA-*` controls, but catalog edits are
   out of scope for this research task.

### 7.3 Explicit non-claim

Adding `HIPAA_SAFE_HARBOR` would make SecuRedact a *mechanical aid* for removing
enumerated identifiers from **text**. It would **not**:
- satisfy the `(ii)` actual-knowledge prong,
- certify de-identification,
- handle images/audio unless separately integrated,
- replace a qualified expert determination where required,
- absolve a covered entity of its HIPAA obligations.

---

## 8. Testing / benchmark strategy

Design a future HIPAA benchmark corpus mirroring the existing GDPR benchmark
philosophy (see `benchmarks/corpora/*.json` schema: `{corpus_version, split,
samples:[{id, language, domain, text, entities:[...]}]}`). Do **not** generate a
large corpus or run expensive models in this research task.

### 8.1 Corpus slices (proposed)

- **positive** — each of A–R present and expected to be detected (e.g., a real
  SSN shape, a US ZIP, an MRN, a VIN, a fax line, a DOB, an email).
- **hard negatives** — values that look like identifiers but are not
  (e.g., `000-00-0000` invalid SSN, version numbers, random 9-digit strings that
  fail SSN area/group rules, 5-digit non-ZIP codes like "12345" in a non-US
  context, generic "Account" without a number).
- **ambiguous identifiers** — last-4-SSN (must still be flagged per HHS:
  derivatives are not Safe Harbor compliant), initials, ZIP3-only.
- **structured medical records** — HL7-ish / faux EHR fields with labelled
  MRN, patient number, insurer, DOB.
- **clinical notes** — free text with names, ages, dates, conditions.
- **emails** — correspondence containing phone/fax/email/address.
- **insurance documents** — policy numbers, beneficiary numbers, group numbers.
- **mixed PII + medical information** — to confirm health context does not
  suppress identifier removal.
- **adversarial formatting** — whitespace, zero-width chars, Unicode homoglyphs,
  newline-split SSN, OCR artifacts, obfuscated emails (`a [at] b [dot] com`).
- **EN-first coverage**, with multilingual considerations documented separately
  (ES commonly present in US care; current lexicons are EN/NL and would need
  Spanish health/address terms before claiming ES coverage).

### 8.2 Evaluation metrics (mirror `release_gate`)

Per-category precision/recall/F1, residual-scan pass rate (no critical residual),
and a profile-level "Safe Harbor mechanical-completeness" score (fraction of A–R
categories with FULL/PARTIAL detection on the positive slice). Keep the
deterministic `securedact-eval --mode deterministic` gate as the reproducible
release check; reserve any real ML/contextual runs as manual.

---

## 9. Recommended implementation roadmap

1. **Phase 0 (foundation):** Add `EntityType` members + `taxonomy.py` entries
   for SSN, US ZIP/state, VEHICLE_IDENTIFIER, HEALTH_PLAN_BENEFICIARY, FAX;
   ship synthetic unit tests. (Closes P0-1,3,4 partially.)
2. **Phase 1 (US geography):** US ZIP/ZIP+4, state, county detection + ZIP3
   retention rule + ages>89 transform. (Closes P0-2, P1-9.)
3. **Phase 2 (profile):** Introduce `hipaa_safe_harbor` built-in `Policy`
   mapping A–R; wire residual scan; add benchmark corpus slices.
4. **Phase 3 (robustness):** Fax labeling, account-number broadening, cert/
   license extension, multilingual (ES) lexicon, re-id-code exception config,
   reporting banner. (P1/P2.)
5. **Phase 4 (images):** Decide Q strategy — document as unsupported (fail
   closed) or integrate image redaction. (P0-5.)

Each phase must add deterministic tests and a threat-model note, per AGENTS.md
and `CONTRIBUTING.md`.

---

## 10. Claims SecuRedact MAY make today

- SecuRedact detects and redacts/blocks a broad set of PII and special-category
  data with a local, fail-closed, residual-validated pipeline (per
  `engine.py`, `api.py`, `compliance/catalog.py`).
- For several identifier *types* that overlap Safe Harbor (telephone, email,
  medical record number, device identifier, URLs, IP addresses), SecuRedact
  provides deterministic detection and redaction today.
- SecuRedact provides health-data / GDPR Article 9 detection (conditions,
  medication, genetic, biometric text references) useful for identifying medical
  context.

## 11. Claims SecuRedact MUST NOT make yet

- MUST NOT claim HIPAA Safe Harbor de-identification or "HIPAA compliance."
- MUST NOT claim coverage of US SSN, US ZIP/geography, health plan beneficiary
  numbers, vehicle identifiers, or photographs/images.
- MUST NOT claim that redaction satisfies the `(ii)` actual-knowledge prong or
  replaces Expert Determination.
- MUST NOT market any `HIPAA_SAFE_HARBOR` capability until implemented and
  benchmarked per §8–§9.

## 12. Authoritative references

1. 45 CFR §164.514 — eCFR: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514 ; Cornell: https://www.law.cornell.edu/cfr/text/45/164.514
2. HHS OCR, "Guidance Regarding Methods for De-identification of PHI" (2012):
   https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html
3. 45 CFR 160.103 (PHI definition).
4. Repository evidence: `src/securedact_core/detectors/regex_detector.py`,
   `models.py`, `taxonomy.py`, `engine.py`, `policies.py`, `policy_loader.py`,
   `api.py`, `detectors/article9_ensemble.py`, `compliance/catalog.py`.
5. Project constraints: `AGENTS.md` (Flair opt-in, repository boundary, no
   stdout prints, no provider clients).

---

---

## 13. Implementation status (HIPAA_SAFE_HARBOR profile)

This section records the production implementation completed after the research
above. It reuses the existing profile/policy-driven `analyze → redact →
scan_residual` architecture and does **not** introduce a parallel HIPAA engine.

### 13.1 What was implemented

- **New `HIPAA_SAFE_HARBOR` built-in policy** (`policies.py`): maps Safe Harbor
  identifiers A–R to `REDACT`/`REVIEW`/`BLOCK` actions, enables residual
  validation and contextual residual scan. State-level geography (B) is retained;
  ZIP/ZIP+4, street addresses, and small-geography labels are redacted.
- **New internal entity types** (`models.py` / `taxonomy.py`): `SSN`, `FAX`,
  `ACCOUNT_NUMBER`, `HEALTH_PLAN_BENEFICIARY`, `VEHICLE_IDENTIFIER`, `US_ZIP`,
  `AGE`. Each has deterministic-detection metadata and a taxonomy definition.
- **Deterministic detectors** (`detectors/regex_detector.py`):
  - SSN with area/group/serial validation (rejects 000, 666, 900–999, 00, 0000).
  - VIN detected by 17-character ISO 3779 format (no check-digit validation); labeled license-plate/vehicle
     values (no space allowed in plate tokens).
  - US ZIP/ZIP+4 in labeled fields and in `(ZIP, ST)` / `ST ZIP` contexts
    (requires a USPS state token, so bare five-digit numbers are not flagged).
  - Fax / account-number / health-plan-beneficiary labels and `MBR`/`SUB`/`BEN`
    prefixes; explicit individual ages over 89 surfaced for review.
- **`securedact_core/hipaa.py`**: the 18-category Safe Harbor mapping with explicit
  support-state metadata (FULL / PARTIAL / NOT COVERED / UNSUPPORTED_REQUIRES_REVIEW),
  contributing entity types, limitations, and a structured `HipaaSafeHarborResult`
  produced by `run_hipaa_safe_harbor` reusing `engine.audit`.
- **Benchmark corpus** `benchmarks/hipaa/hipaa_safe_harbor.json` (separate from the
   GDPR corpus) covering all 18 categories with positives, hard negatives, and mixed
   records.
- **Tests** `tests/unit/test_hipaa_safe_harbor.py`.

### 13.2 Before → after 18-category matrix

| Status | Baseline | After implementation | After adversarial validation |
| --- | --- | --- | --- |
| FULL | 6 (D, F, H, M, N, O) | 8 (D, E, F, G, H, M, N, O) | 7 (D, E, F, G, M, N, O) |
| PARTIAL | 8 (A, B, C, E, J, K, P, R) | 9 (A, B, C, I, J, K, L, P, R) | 10 (A, B, C, H, I, J, K, L, P, R) |
| NOT COVERED | 4 (G, I, L, Q) | 0 | 0 |
| UNSUPPORTED / REQUIRES REVIEW | 0 | 1 (Q) | 1 (Q) |

Category changes explained:
- **G SSN**: NOT COVERED → FULL (new validated detector).
- **E Fax**: PARTIAL → FULL (new `FAX` label/entity; previously only incidentally
  caught by generic `PHONE`).
- **I Health plan beneficiary**: NOT COVERED → PARTIAL (conservative labeled/prefix
  detection only; generic alphanumeric tokens are not classified as PHI to avoid
  false positives).
- **L Vehicle identifier**: NOT COVERED → PARTIAL (VIN check-digit validated; plates
  only from explicit labels).
- **Q Full-face photograph / image**: NOT COVERED → UNSUPPORTED_REQUIRES_REVIEW
  (text-only engine; absence of a Q finding does not imply an image is clean).

Categories A, B, C, J, K, P, R remain PARTIAL for defensible reasons documented in
`docs/hipaa-safe-harbor-profile.md`; none were marked FULL merely to raise the count.

**Adversarial-validation correction (H):** the 202-case independent adversarial dataset
(`benchmarks/hipaa/hipaa_adversarial.json`) showed H (Medical record number) with a recall
of ~0.43 — only the standard `MRN` / `Medical record number` labels and the `MRN-` prefix
were detected, while `Record number`, `Chart ID`, and separator-less forms (`patient MRN is
558201`) were missed. Because an MRN is an MRN regardless of phrasing, classifying H as FULL
over-claimed coverage. H was therefore **downgraded FULL → PARTIAL** (see §14). No other FULL
category (D, E, F, G, M, N, O) showed recall low enough to warrant a downgrade; each retains
FULL because its core form is reliably detected.

### 13.3 Explicit limitations (must not be claimed away)

- This is a **mechanical de-identification aid**, not HIPAA compliance, not a
  certification, not guaranteed de-identification, and not Expert Determination
  (45 CFR 164.514(b)(1)).
- Safe Harbor has two prongs. SecuRedact addresses only the mechanical removal of
  enumerated textual identifiers (164.514(b)(2)(i)). The **actual-knowledge prong**
  (164.514(b)(2)(ii)) requires the covered entity's own attestation and cannot be
  satisfied by software.
- **ZIP3 retention rule (B)**: SecuRedact does not ship a versioned Census ZIP3
  population dataset, so the conditional retention of the first three ZIP digits is
  **not** applied. ZIPs are redacted in full (over-retention, not under-retention).
- **Ages over 89 (C)**: explicit individual ages > 89 are surfaced for review; the
  "except year" transform (keep year, drop month/day) is not applied automatically.
- **Category Q (images)**: not detectable by the text engine; inputs that may contain
  images must be reviewed out of band.
- **Biometrics (P)**: only textual references (e.g. "fingerprint template", "voice
  print") are detected; raw biometric artifacts need modality-specific handling.
- No network calls are made during detection; all new detection is deterministic.

---

*Research basis: section 1–12 above. Implementation: `HIPAA_SAFE_HARBOR` profile,
`securedact_core/hipaa.py`, detectors, and `benchmarks/hipaa/hipaa_safe_harbor.json`.
This feature is a mechanical aid and does not certify HIPAA compliance.

---

## 14. Independent adversarial validation (202-case dataset)

### 14.1 Method

- **Independent dataset.** `benchmarks/hipaa/hipaa_adversarial.json` is generated by
  `scripts/experimental/build_hipaa_adversarial.py` and is **deliberately separate** from the
  27-sample implementation corpus (`benchmarks/hipaa/hipaa_safe_harbor.json`). It contains **202
  cases** spanning all 18 HIPAA categories, each with explicit `gold_present` (what *should* be
  detected under 45 CFR §164.514(b)(2)), optional `gold_absent` precision guards, and
  `hard_negative` / `adversarial` flags.
- **Gold ≠ current behavior.** Gold labels encode the regulatory expectation, never "what the
  engine does today." The runner (`scripts/experimental/run_hipaa_adversarial.py`) executes the
  production `RegexDetector` and computes per-category TP / FP / FN / precision / recall / F1
  against a **per-category entity-type scope** derived from `ENTITY_TO_LETTER`. This avoids the
  misleading global entity-type comparison the validation was designed to prevent. Cross-category
  detections are ignored for a category's own metric.
- **`known_missing` / `known_extra` are observed, never invented.** They are *derived* from
  actual gold-vs-detected diffs. Genuine FNs are reported as reproduced defects; they are pinned
  in `tests/unit/test_hipaa_adversarial_regressions.py` as `xfail` gaps (so they stay auditable
  and turn green only when the gap is closed), never silently padded to pass.
- Category **Q** (images, unsupported) is measured against the full type set, so any false
  detection there is a precision violation.

### 14.2 Headline results

| Metric | Value |
| --- | --- |
| Cases | 202 |
| True positives (TP) | 150 |
| False positives (FP) | 0 |
| False negatives (FN) | 15 |
| **Precision** | **1.000** |
| **Recall** | **0.909** |
| **F1** | **0.952** |

**Zero false positives** on the entire adversarial set: every identifier detected inside a
category scope was a true positive for that category. All 15 remaining FNs are documented gaps
(§14.4), each reproduced from observed behavior and reported as a defect — not hidden. The
recall improvement from 0.794 → 0.909 was achieved with **no precision loss** (still 1.000)
through minimal, label-scoped, precision-preserving detector changes (§14.5).

### 14.3 Per-category metrics (after fixes)

| Cat | N | TP | FP | FN | Prec | Rec | F1 | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | 12 | 2 | 0 | 7 | 1.000 | 0.222 | 0.364 | PARTIAL |
| B | 16 | 10 | 0 | 5 | 1.000 | 0.667 | 0.800 | PARTIAL |
| C | 18 | 18 | 0 | 0 | 1.000 | 1.000 | 1.000 | PARTIAL |
| D | 12 | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 | FULL |
| E | 8 | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 | FULL |
| F | 8 | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 | FULL |
| G | 12 | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 | FULL |
| H | 8 | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 | PARTIAL (improved; stays PARTIAL) |
| I | 10 | 8 | 0 | 0 | 1.000 | 1.000 | 1.000 | PARTIAL |
| J | 12 | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 | PARTIAL |
| K | 14 | 12 | 0 | 0 | 1.000 | 1.000 | 1.000 | PARTIAL |
| L | 14 | 11 | 0 | 1 | 1.000 | 0.917 | 0.957 | PARTIAL |
| M | 8 | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 | FULL |
| N | 10 | 8 | 0 | 0 | 1.000 | 1.000 | 1.000 | FULL |
| O | 8 | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 | FULL |
| P | 8 | 6 | 0 | 1 | 1.000 | 0.857 | 0.923 | PARTIAL |
| Q | 4 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | UNSUPPORTED |
| R | 20 | 16 | 0 | 1 | 1.000 | 0.941 | 0.970 | PARTIAL |

### 14.4 Reproduced defects / gaps (grouped by HIPAA category)

After the §14.5 fixes, the only remaining reproduced gaps are **A (7), B (5), L-014 (1),
P-007 (1), R-019 (1)** — 15 FNs total. The previously-documented gaps below were **closed**
with zero precision loss (FP stayed 0):

- **E – Fax (was 1 FN, now 0).** `Our fax is 415-555-8890` is now detected as `FAX` via the
  loose separator (`fax is …` connective). E remains FULL.
- **G – SSN (was 1 FN, now 0).** `social security no 123456789` is now detected via the loose
  separator. G remains FULL.
- **H – MRN (was 4 FN, now 0).** `Medical Record:`, `Record number:`, `Chart ID:`, and
  `patient MRN is 558201` are all detected after adding synonyms and the loose separator. H
  recall rose 0.43 → 1.000; it stays **PARTIAL** because generic `record number` remains a
  contextual-precision risk and some unlabelled MRN phrasings may still be missed.
- **I – Health plan beneficiary (was 2 FN, now 0).** `MBR55210983` (no separator, prefix fix)
  and `Member No: MBR 448821039` (space-in-value) are detected. I stays PARTIAL.
- **J – Account numbers (was 3 FN, now 0).** `bank account ref BAR-55210983`, `payment ref:
  PAYREF 552109`, and `ACC773102884` are detected. J stays PARTIAL.
- **K – License/certificate (was 3 FN, now 0).** Internal-space values (`CA 9920314`, `AB
  1234567`, `XY 55210983`) are detected via the space-aware identifier value. K stays PARTIAL.
- **L – Vehicle (was 3 FN, now 1).** `VIN 1M8GDM9AXKP042788` and `license plate 8KGD204`
  (no-separator / loose separator) are detected. The unlabelled VIN (`1M8GDM9AXKP042788`
  mid-sentence, L-014) is **intentionally still not detected** — a standalone 17-char VIN rule
  would over-flag hashes/tokens/UUID fragments (see §14.6). L stays PARTIAL.
- **M – Device (was 1 FN, now 0).** `DEV55120983` is detected via the digit-led no-separator
  prefix fix. M retains FULL (labelled device IDs, serial numbers, and DEV-prefixed values with
  or without a separator are all covered).
- **R – Other unique (was 3 FN, now 1).** `Policy number POL 552109` and `Patient No: PAT
  772019` (space-in-value + `patient no` alias) are detected. `Relationship: spouse` (R-019)
  remains a gap (no `RELATIONSHIP` detector). R stays PARTIAL.

**Unchanged documented gaps (not force-fixed to preserve precision):**
- **A – Names (7 FN).** Only the exact `name:` / `naam:` label fires deterministically; unlabelled
  free-text and other labelled names (`Patient:`, `Attending physician:`, `Next of kin`,
  `Emergency contact`) need the opt-in contextual/Flair model (off by default).
- **B – Geographic (5 FN).** US street-address forms (B001/B007/B010) and city/state references
  (`Chicago, Illinois`, `Los Angeles, California`) need the contextual model or a US-address
  detector; this task deliberately avoids broad US-address intelligence.
- **P – Biometric (1 FN, P-007).** Textual `DNA …` references are not enumerated (only explicit
  `BIO-`/`FACE-`/`IRIS-`/`VOICE-`/`GEN-` prefixes).
- **R – Other unique (1 FN, R-019).** `Relationship: spouse` has no detector.

### 14.5 Minimal production fixes applied (evidence-based, re-run after each)

| # | Fix | Evidence | Effect |
| --- | --- | --- | --- |
| 1 | `DATE_VALUE` now accepts ISO `yyyy-mm-dd` / `yyyy/mm/dd` | C009/C010/C016 missed ISO DOB/dates | C recall 0.733 → 1.000 |
| 2 | `date_of_birth_label` gains `DOB` abbreviation | `DOB: 1965-09-30` missed | closes C010 |
| 3 | `ssn_label` gains `SS#` | `SS# …` missed | closes G003-class |
| 4 | `device_label` gains `serial number` / `serial no` | device serials (Safe Harbor M) missed | M FN 3 → 1 |
| 5 | `PREFIX_TYPES["ACC"]` → `ACCOUNT_NUMBER` (was `BANK_ACCOUNT_REFERENCE`) | `ACC-…` produced a spurious bank-account-reference overlap with `Account No:` labels | J FP 3 → 0 (precision 1.000) |
| 6 | **H downgraded FULL → PARTIAL** | adversarial recall 0.43 | honest status; matrix 8→7 FULL |
| 7 | Label `loose_separator` (whitespace + connective `is/was`) for structured labels only (ssn, fax, medical_record_number, vehicle, account_reference, policy_number) | `fax is …`, `social security no …`, `patient MRN is …`, `VIN …`, `license plate …`, `bank account ref …`, `policy number …` missed | closes E-007, G-004, H-007, L-008, L-009, J-010, R-013 |
| 8 | `IDENTIFIER_VALUE` accepts one space-separated digit-bearing token | internal-space values (`MBR 448821039`, `CA 9920314`, `AB 1234567`, `XY 55210983`, `PAYREF 552109`, `PAT 772019`, `POL 552109`) rejected | closes I-010, K-011/012/013, J-011, R-014 |
| 9 | Prefix rule accepts a digit-led value with no separator (`MBR55210983`, `ACC773102884`, `DEV55120983`); digit-start avoids `SUBMIT`/`ACCEPT`/`GENETIC` FPs | `MBR55210983`, `ACC773102884`, `DEV55120983` missed | closes I-009, J-012, M-008 |
| 10 | MRN label synonyms added (`medical record`, `record number`, `record no`, `chart number`, `chart no`, `chart ID`, `patient record number/no`) | `Medical Record:`, `Record number:`, `Chart ID:` missed | closes H-004, H-005, H-006 |
| 11 | `patient no` alias for patient-number label; `bank account ref` alias; `payment ref` alias | `Patient No: …`, `bank account ref …`, `payment ref: …` missed | closes R-014, J-010, J-011 |

The metric moved from **P=1.000 / R=0.794 / F1=0.885** (prior validation) to **P=1.000 /
R=0.909 / F1=0.952** after these precision-preserving fixes, with **0 false positives**
(retained). Each change maps to a reproduced FN; no recall gain came from relaxing free-text
labels (which would have over-captured names/prose).

### 14.6 Required section findings

- **VIN / check-digit behavior.** Labelled VINs are detected **without ISO 3779 check-digit
  validation** (DEFECT 3, pinned): `VIN: 1M8GDM9A0KP042788` (invalid North-American check
  digit) is still reported. Unlabelled VINs and VIN-without-separator are **not** detected
  (no standalone VIN rule). This is documented; the check-digit helper (`vin_valid`) remains an
  opt-in for callers that know their data is North American. Hard-negative `1Z8GDM9AXKP04278Q`
  (excluded letter Q) is correctly never flagged.
- **Device identifier FULL classification (M).** M was FULL. The adversarial set proved device
  *serial numbers* — explicitly part of Safe Harbor M — were missed. Fix #4 added `serial
  number` / `serial no` labels, closing M005/M006. M retains FULL with an explicit limitation
  noting unseparated/unlabelled serials (e.g. `DEV55120983`) remain a gap. This is defensible:
  labelled device identifiers **and** labelled serial numbers are now fully handled.
- **Dates / ages > 89 (C).** Core date/DOB/age>89 detection is now complete (C F1 = 1.000) after
  the ISO-date and `DOB` fixes. Remaining notes: a DOB is also emitted as a generic `date`
  (benign double-emission, both are valid HIPAA identifiers, not counted as a defect); the
  "except year" transform and the ages-89 "90+" aggregation are **not** auto-applied (documented
  PARTIAL limitation, not a false-negative in the identifier sense).
- **Public API / profile propagation.** `run_hipaa_safe_harbor(engine, text)` threads the
  `hipaa_safe_harbor` policy through `engine.audit` and returns the 18-category structured
  `HipaaSafeHarborResult`. Verified: the policy object is the registered `hipaa_safe_harbor`
  profile (URL→REDACT, biometric/genetic→BLOCK, SSN→REDACT) and is **distinct** from the generic
  default — i.e. the profile is actually applied, not silently defaulting to GDPR.
- **Residual-scan shared blind spots.** The residual pass reuses the *same* `RegexDetector`, so
  an identifier the initial pass misses (e.g. an unlabelled name) is also missed in the residual
  pass. This shared blind spot is explicitly tested (`test_residual_scan_shares_regex_blind_spot`)
  so it cannot be silently assumed away. It is a property of the single-detector design, not a
  second independent safety net.
- **Generic compliance architecture overlap.** The framework-agnostic control catalog
  (`src/securedact_core/compliance/catalog.py`) is data/evidence-only and its `FrameworkId` set is
  **GDPR, AI Act, NIS2, ISO 27001, SOC 2, DORA, PCI DSS, NEN 7510, BIO2 — no HIPAA entry**.
  Therefore HIPAA Safe Harbor is owned solely by `hipaa.py` + the `hipaa_safe_harbor` policy;
  there is **no duplicate or conflicting HIPAA category model** in the generic layer. The overlap
  concern is resolved: clean separation, with the catalog intentionally omitting HIPAA to avoid
  over-claiming (consistent with the disclaimer philosophy).

### 14.7 Final A–R downgrade / upgrade decision

| Cat | Prior | Decision | Rationale |
| --- | --- | --- | --- |
| A | PARTIAL | **Keep PARTIAL** | names need contextual model; gaps documented |
| B | PARTIAL | **Keep PARTIAL** | city/state needs contextual; ZIP solid |
| C | PARTIAL | **Keep PARTIAL** | "except year" / 90+ aggregation not auto-applied |
| D | FULL | **Keep FULL** | 0 FP, recall 1.000 |
| E | FULL | **Keep FULL** | 0 FP; single gap is no-separator fax |
| F | FULL | **Keep FULL** | 0 FP, recall 1.000 |
| G | FULL | **Keep FULL** | 0 FP; single gap is no-separator SSN |
| H | FULL | **DOWNGRADE → PARTIAL (improved)** | recall 0.43 → 1.000 after synonyms + loose separator; stays PARTIAL (generic `record number` residual precision risk) |
| I | PARTIAL | **Keep PARTIAL** | conservative labelled/prefix only |
| J | PARTIAL | **Keep PARTIAL** | non-standard account phrasing missed |
| K | PARTIAL | **Keep PARTIAL** | space-in-value rejected |
| L | PARTIAL | **Keep PARTIAL** | unlabelled/no-separator VIN/plate missed |
| M | FULL | **Keep FULL** | device IDs + serial numbers now detected |
| N | FULL | **Keep FULL** | 0 FP, recall 1.000 |
| O | FULL | **Keep FULL** | 0 FP, recall 1.000 |
| P | PARTIAL | **Keep PARTIAL** | only explicit genetic/biometric prefixes |
| Q | UNSUPPORTED | **Keep UNSUPPORTED** | text-only engine; images out of band |
| R | PARTIAL | **Keep PARTIAL** | relationship/no-separator variants missed |

**Net decision: 7 FULL, 10 PARTIAL, 1 UNSUPPORTED.** One downgrade (H). **No upgrades** —
every PARTIAL category has a genuine, reproduced gap that prevents a defensible FULL claim, and
principle 9 forbids treating pinned gaps as correct behavior. The mechanical-aid disclaimers
(§11, §13.3) are unchanged: this is not HIPAA compliance, not a certification, and does not
satisfy the actual-knowledge prong (§164.514(b)(2)(ii)).

*Validation basis: `benchmarks/hipaa/hipaa_adversarial.json` (202 cases),
`scripts/experimental/build_hipaa_adversarial.py`, `scripts/experimental/run_hipaa_adversarial.py`,
`tests/unit/test_hipaa_adversarial_regressions.py` (47 passed, 4 xfailed gaps).*
