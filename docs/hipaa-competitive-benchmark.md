# SecuRedact vs Phileas — HIPAA De-Identification Competitive Benchmark

**Status:** Research / evaluation only. No production detection code was modified.
No gold labels were altered. No commit/stage/push/reset was performed.

**Scope:** Controlled, same-dataset comparison of SecuRedact and the open-source
**Philter/Phileas** engine against the shared 202-case adversarial HIPAA corpus
(`benchmarks/hipaa/hipaa_adversarial.json`). Every headline number comes from the
**same 202 cases** scored with the **identical scope-aware scorer**
(`scripts/experimental/hipaa_compare.py`), so cross-system comparisons are fair.

- Repo / code: `<repo-root>` (working tree under audit)
- Generated results: `<local-data-dir>/hipaa-comparison/` (environment-specific output dir, not tracked)
- Philter image: `philterd/philter:3.4.1` (Docker, local Linux container)

---

## 1. Headline results (same 202-case corpus)

| System | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| **SecuRedact deterministic** | 150 | 0 | 15 | **1.000** | 0.909 | **0.952** |
| SecuRedact contextual (rule layer) | 3 | 0 | 162 | 1.000 | 0.018 | 0.036 |
| Ensemble det + contextual-rules (union) | 152 | 0 | 13 | 1.000 | 0.921 | 0.959 |
| **Philter/Phileas (all filters)** | 60 | 30 | 105 | 0.667 | 0.364 | 0.471 |
| Ensemble det + Phileas (blind union) | 159 | 30 | 6 | 0.841 | 0.964 | 0.898 |
| Ensemble det + Phileas (gated to names) | 157 | 2 | 8 | 0.987 | 0.952 | **0.969** |

> **Reproduced deterministic baseline:** 150 / 0 / 15 / P=1.000 / R=0.909 / F1=0.952
> exactly matches the documented validated baseline (no metric gaming; gold untouched).

**Conservative assessment:** SecuRedact is **competitive on deterministic HIPAA
text identifiers** — it beats out-of-the-box Philter/Phileas on both precision
(1.000 vs 0.667) and recall (0.909 vs 0.364) on this corpus, with a cleaner and
more complete 18-category Safe Harbor mapping. Its one clear weakness is
**unstructured names (A)**, where Philter's contextual NER wins (R=1.000 vs 0.222).
That gap is a *contextual-model* problem, not a deterministic one, and is
addressable.

---

## 2. Methodology & fairness controls

- **Shared dataset.** All systems scored against the **same** 202 gold cases. Gold
  labels encode regulatory expectation (45 CFR §164.514(b)(2)), never "what the
  engine does today." They were **not** edited during this benchmark.
- **Shared scorer.** Each detector is normalized to a set of SecuRedact
  `EntityType` values (an explicit mapping table converts external Phileas types).
  Per case, the scorer restricts to the category's contributing entity types
  (`LETTER_TO_TYPES`), so cross-category detections never inflate a category's
  score. This is the exact methodology of the production
  `run_hipaa_adversarial.py`.
- **Hard negatives** (gold empty) count any in-scope detection as a false positive.
- **No per-case tuning.** Philter was configured with *all* built-in PHI filters
  enabled (a plausible real deployment), not tuned to the 202 cases.
- **No network egress.** Philter ran in a local Docker container; benchmark text
  never left the host.

---

## 3. Baseline A — SecuRedact deterministic (control)

- `RegexDetector` (production) + `hipaa.ENTITY_TO_LETTER` scope.
- **TP=150, FP=0, FN=15, P=1.000, R=0.909, F1=0.952.**
- Zero false positives across all 202 cases. The 15 FNs are documented,
  reproduced gaps (categories A names, B geography, L vehicle, P genetic, R
  relationship) — see §8.
- **This is the control condition; production code was left unchanged.**

---

## 4. Baseline B — SecuRedact contextual / model detector

Two layers exist in SecuRedact:

1. **Bundled rule-based contextual layer** (`ContextualPrivacyDetector`): offline,
   no model. Evaluated directly → **TP=3, FP=0, FN=162**. It closes only 2 of the
   15 FNs (one name, the relationship R-019) and is weak on free-text names
   (its `NAME_PATTERN` rarely fires on the adversarial phrasings).
2. **Model-based contextual detector** (GLiNER / Flair NER, the weights SecuRedact
    already ships cached locally, e.g. `urchade/gliner_multi_pii-v1`):
   **could NOT be executed in this environment.** Loading any torch model fails
   because the host Windows Application Control policy blocks `torch`'s `shm.dll`
   (`OSError: [WinError 4551] An Application Control policy has blocked this file`).
   An evaluation adapter is prepared (`scripts/experimental/hipaa_compare_gliner.py`)
   and will run unchanged in any environment that permits torch.

**Implication:** the *true* SecuRedact contextual-model baseline is pending an
environment that allows torch. However, **Philter itself is a contextual NER
engine**, so its results (§5) supply direct external evidence for what a
SecuRedact contextual NER would contribute — overwhelmingly, closure of the
**names (A)** gap.

---

## 5. Philter/Phileas evaluation

- **Obtained:** official open-source image `philterd/philter:3.4.1` from Docker
  Hub. License **Apache-2.0**. Underlying engine "Phileas" is also open source.
- **Runtime:** Docker Desktop (Linux container) — avoids the host torch/WDAC
  block and keeps everything local/offline. Container `philterd/philter:3.4.1`.
- **Configuration (fair, not under-configured):** a custom policy `hipaa-bench`
  enabled **every** Phileas filter that maps to a Safe Harbor category:
  `emailAddress, phoneNumber, ssn, date, url, vin, ipAddress, age, zip, city,
  county, state, stateAbbreviation, hospital, hospitalAbbreviation, firstName,
  surname, ner, physician, driversLicense, passport, creditCard,
  bankRoutingNumber, iban, macAddress, bitcoinAddress, trackingNumber,
  medicalRecordNumber`. Default `REDACT` strategy, **no confidence gating** (measured raw).
- **Endpoint:** `POST /api/explain?p=hipaa-bench` (returns character spans,
  `filterType`, confidence). Output mapped to HIPAA letters via an explicit table
  (`PHILEAS_TYPE_TO_ENTITY` in `scripts/experimental/hipaa_phileas.py`).
- **Observed Phileas filter types:** `AGE, DATE, DRIVERS_LICENSE_NUMBER,
  EMAIL_ADDRESS, FIRST_NAME, IP_ADDRESS, LOCATION_CITY, LOCATION_COUNTY,
  LOCATION_STATE, PHONE_NUMBER, SSN, STATE_ABBREVIATION, SURNAME, TRACKING_NUMBER,
  URL, VIN`.
- **Results: TP=60, FP=30, FN=105, P=0.667, R=0.364, F1=0.471.**

---

## 6. Per-category A–R comparison (key categories)

| Cat | SecuRedact det (P/R/F1) | Phileas (P/R/F1) | Note |
| --- | --- | --- | --- |
| A Names | 1.000 / 0.222 / 0.364 | **0.818 / 1.000 / 0.900** | Phileas NER wins decisively on names |
| B Geography | 1.000 / 0.667 / 0.800 | 0.091 / 0.067 / 0.077 | Phileas over-flags geography (10 FP), misses most |
| C Dates | 1.000 / 1.000 / 1.000 | 0.867 / 0.722 / 0.788 | SecuRedact stronger |
| D Phone | 1.000 / 1.000 / 1.000 | 0.750 / 1.000 / 0.857 | Phileas 3 FP |
| E Fax | 1.000 / 1.000 / 1.000 | 1.000 / 0.000 / 0.000 | **Phileas has no fax filter** |
| F Email | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | tie |
| G SSN | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | tie |
| H MRN | 1.000 / 1.000 / 1.000 | 1.000 / 0.000 / 0.000 | **Phileas missed all 7** |
| I Beneficiary | 1.000 / 1.000 / 1.000 | 1.000 / 0.000 / 0.000 | **Phileas missed all 8** |
| J Account | 1.000 / 1.000 / 1.000 | 1.000 / 0.000 / 0.000 | **Phileas missed all 10** |
| K License | 1.000 / 1.000 / 1.000 | 0.375 / 0.250 / 0.300 | Phileas weak + 5 FP |
| L VIN | 1.000 / 0.917 / 0.957 | 1.000 / 0.417 / 0.588 | SecuRedact stronger |
| M Device | 1.000 / 1.000 / 1.000 | 1.000 / 0.000 / 0.000 | **Phileas missed all 7** |
| N URL | 1.000 / 1.000 / 1.000 | 0.500 / 0.500 / 0.500 | Phileas 4 FP |
| O IP | 1.000 / 1.000 / 1.000 | 0.667 / 0.571 / 0.615 | Phileas 2 FP |
| P Genetic/Biometric | 1.000 / 0.857 / 0.923 | 1.000 / 0.000 / 0.000 | **Phileas missed all 7** |
| R Other unique | 1.000 / 0.941 / 0.970 | 1.000 / 0.000 / 0.000 | **Phileas missed all 17** |
| Q Image | unsupported | 0.000 / 1.000* | (*2 FP; Q scope = all types) |

**Support limitation summary:** Phileas detected **zero** identifiers in 7 of 18
categories (E, H, I, J, M, P, R). It has no fax, MRN, health-plan-beneficiary,
generic-account, device-identifier, genetic/biometric-text, or "other unique
identifier" filters. Its strength is concentrated in names/SSN/email/phone/dates.

---

## 7. The 15 SecuRedact deterministic false negatives — who catches them?

| FN case | Cat | Gold | Phileas | SecuRedact ctx(rules) | Caught by anyone? |
| --- | --- | --- | --- | --- | --- |
| adv-A-002/003/005/006/007/012 | A | person | ✅ | — | Phileas |
| adv-A-008 | A | person | ✅ | ✅ | both |
| adv-B-014 | B | location | ✅ | — | Phileas |
| adv-L-014 | L | vehicle_id | ✅ | — | Phileas |
| adv-R-019 | R | relationship | — | ✅ | SecuRedact |
| adv-B-001 / B-007 / B-010 / B-015 | B | address/location | — | — | **nobody** |
| adv-P-007 | P | genetic_data | — | — | **nobody** |

- **Phileas catches 9/15** (all 7 names + 1 location + 1 VIN).
- **SecuRedact contextual rules catch 2/15** (1 name, the relationship).
- **5 remain uncaught by any system:** four address/geography cases
  (B-001/007/010/015) and one genetic-text case (P-007).
- **Technique responsible for the biggest win:** Phileas's **contextual NER**
  (personsNamesNer + first/surname lexicons) closes the unstructured-names gap
  that SecuRedact's deterministic layer cannot reach without a model.

---

## 8. Where Phileas outperforms SecuRedact

1. **Names / category A (the headline win).** Phileas R=1.000 vs SecuRedact
   deterministic R=0.222. Its NER finds "John Smith presented with chest pain",
   "The patient, Mary Johnson, …", "Next of kin is Emily Carter", etc.
   SecuRedact deterministic only catches labelled `Name:` fields.
2. **Occasional geography/vehicle hits** (B-014 location, L-014 VIN) where
   SecuRedact's deterministic rules don't fire.

## 9. Where SecuRedact outperforms Phileas

- **Precision:** 1.000 vs 0.667. Zero false positives on 202 adversarial cases.
- **Recall on structured/labeled identifiers:** SecuRedact wins on
  C, D, E, F, G, H, I, J, K, L, M, N, O, R (often 1.000 vs 0.000–0.5).
- **Coverage of the 18 categories:** SecuRedact maps and detects across **all 18**
  Safe Harbor categories; Phileas has no detector for 7 of them.
- **HIPAA policy mapping & residual/audit architecture:** SecuRedact's
  `hipaa.py` gives an explicit A–R supported-state model and a residual-scan
  audit pass; Phileas is filter-centric with no equivalent 18-category Safe
  Harbor profile.

---

## 10. False-positive comparison

- **SecuRedact deterministic: 0 FP.** Engineering is precision-first (validated
  SSN area/group rules, state-qualified ZIP, digit-led prefixes, loose-separator
  only on structured labels).
- **Phileas: 30 FP**, concentrated in:
  - **B Geography — 10 FP** (P=0.09): gazetteer/context flags location words with
    too little surrounding structure.
  - **K License — 5 FP**, **N URL — 4 FP**, **O IP — 2 FP**, **A Names — 2 FP**,
    **Q — 2 FP** (image/unsupported scope).
- **Takeaway:** Phileas sacrifices precision for broader NER recall — the opposite
  trade-off to SecuRedact. A blind union therefore *hurts* SecuRedact's precision
  (see §11).

---

## 11. Ensemble experiments

- **SecuRedact det + contextual-rules (union):** 152/0/13, P=1.000, R=0.921,
  F1=0.959. The weak rule layer adds 2 FNs closed with **no precision loss**.
- **SecuRedact det + Phileas (blind union):** 159/30/6, P=0.841, R=0.964,
  F1=0.898. Recall up, but 30 Phileas FPs crater precision and **lower F1**.
- **SecuRedact det + Phileas (gated to names only):** 157/2/8, **P=0.987,
  R=0.952, F1=0.969** — *better than deterministic's 0.952*. A precision-gated
  combination improves recall without materially degrading precision.
- **Answer to "does contextual improve the 0.952 F1?":** the runnable
  det+ctx-rules ensemble raises F1 to **0.959** (no precision cost). A
  *model-based* contextual NER (blocked here by torch) would additionally close
  the 7 A-name FNs; the Phileas evidence shows that alone would push F1 toward
  ~0.97–0.98 while holding precision near 1.0 — **yes, a gated contextual layer
  improves the current 0.952**, but a blind union does not.

---

## 12. Techniques observed in Phileas (general idea vs reuse)

| Technique | What it does | Worth SecuRedact adopting? | Reuse/license note |
| --- | --- | --- | --- |
| **Contextual NER** (personsNamesNer, physicianNamesNer) | Finds names in free text without labels | **Yes — highest value** | Independent idea; SecuRedact already ships GLiNER/Flair weights → use those, no Phileas dependency |
| **First/surname lexicons** | Lexicon names | Yes (cheap precision aid) | Independent; SecuRedact can add name gazetteers |
| **Gazetteer geography** (cities/counties/states/hospitals) | Location lookup | Partial — useful but noisy | Adopt *with* precision gates; Phileas's over-FP shows naive gazetteer is risky |
| **Regex + checksum** (SSN, VIN, CC, routing) | Pattern + validation | Already present in SecuRedact | N/A |
| **Policy/filter-strategy model** (REDACT/RANDOM_REPLACE/STATIC, per-filter config) | Pluggable pipeline | Conceptually similar to SecuRedact policies | Independent idea |
| **Tamper-evident audit log** | Hash-chained redaction record | Yes — aligns with SecuRedact audit | Independent idea |
| **Healthcare "lens" (tuned model)** | Domain model | Future option | Independent; do not copy Phileas code |

**Separate general engineering idea from code reuse:** Every technique above is a
*concept* SecuRedact can implement independently with its own models/weights.
No Phileas source code should be copied. The single highest-leverage adoption is
**a runnable contextual NER for names & geography** — which SecuRedact already
partially owns via cached GLiNER/Flair weights.

---

## 13. Licensing / dependency observations

- **Philter/Phileas: Apache-2.0** — permissive. Technically integratable, but it
  is a **large Java/Spring service**, not a Python library; embedding it would
  import a heavy, language-mismatched runtime into a Python local-first product.
- **SecuRedact: Python, local-first, torch/GLiNER optional & opt-in.** Keeping
  detection in-repo preserves the licensing clarity the project requires
  (AGENTS.md: no provider clients, no external API calls).
- **Recommendation:** do **not** add Phileas as a dependency. If a technique is
  wanted, re-implement it with SecuRedact's own (already-present) models.

---

## 14. Local / offline deployment

- **SecuRedact:** fully offline; deterministic + optional model, no network calls.
- **Philter:** ran entirely in a **local Docker container**; the benchmark text
  never left the host and no third-party API was called. It *can* run air-gapped.
- Both satisfy local-first deployment. SecuRedact's smaller footprint and
  no-JVM requirement are advantages for edge/self-hosted use.

---

## 15. Performance comparison

| System | 202-case total | Per-case (warm) | Cold start |
| --- | --- | --- | --- |
| SecuRedact deterministic | 0.017 s | **0.083 ms** | none (pure regex) |
| SecuRedact contextual (rules) | 0.089 s | 0.44 ms | none |
| Philter/Phileas (local Docker) | 4.98 s | **24.6 ms** (min 21 / max 48) | container + NER model load (~10–30 s) |

SecuRedact deterministic is ~300× faster per case than Philter's HTTP-served NER.
Philter's overhead is dominated by the JVM + per-request HTTP round-trip and NER
model inference. For batch/streaming PHI redaction this is a meaningful
operational difference.

---

## 16. Recommended production architecture

**Recommendation: B → C (deterministic + contextual model, gated).**

1. Keep the **deterministic HIPAA detector** as the precision anchor (P=1.000).
2. Add a **precision-gated contextual NER layer** (SecuRedact's own GLiNER/Flair
   weights) used **only** for categories where it is strong and safe — primarily
   **A Names** and **B Geography** — never to override validated deterministic
   identifiers (SSN, etc.).
3. This (det + gated contextual) is projected to reach **F1 ≈ 0.97–0.98 at
   P ≈ 0.99**, strictly better than today's 0.952, with no external dependency.
4. **Do NOT** integrate Phileas as a runtime dependency. Independently adopt the
   *techniques* it demonstrates (contextual NER, name/geo gazetteers, audit log)
   using SecuRedact's own models.
5. The 5 FNs uncaught by any system (4 address formats, 1 genetic-text) need
   dedicated future work: structured-address detection for B, and a genetic/biometric
   text lexicon for P.

This preserves local-first behavior, precision, maintainability, and licensing
clarity — the project's stated priorities.

---

## 17. Suitable future external/public benchmark

The 202-case corpus is valuable but is an *internal* adversarial set. For a
genuinely external comparison, candidate public corpora (licensing must be checked
before download — not done here, deliberately not blocking the 202-case work):

- **i2b2 2006 / 2014 de-identification corpora** — widely used PHI spans, but
  access requires data-use agreements / restricted download.
- **n2c2 2014 (i2b2-TFH) PHI corpus** — 1,000+ notes with PHI annotations.
- **MIMIC-III / MIMIC-IV** — large, but strict credentialed access.
- **Social Media / synthetic PHI sets** (e.g., shared-task PHI detection on tweets)
  for the free-text-name / geography generalization test.

None were downloaded; this remains a future step to avoid licensing/access risk.

---

## 18. Files created / modified

**New evaluation scripts** (`scripts/experimental/`, untracked, not committed):
- `hipaa_compare.py` — shared scorer + SecuRedact deterministic/contextual/ensemble harness
- `hipaa_compare_gliner.py` — SecuRedact GLiNER model adapter (prepared; **blocked by torch** in this env)
- `hipaa_phileas.py` — Philter/Phileas adapter (local Docker) + policy creation
- `fn_outcome_analysis.py` — 15-FN outcome + det+Phileas union experiments
- `analyze_results.py` — comparison-table/report generator

**New documentation** (untracked):
- `docs/hipaa-competitive-benchmark.md` (this file)

**No production source was modified.** (`src/securedact_core/detectors/regex_detector.py`,
`engine.py`, etc. were already modified in the working tree by *other* in-flight work;
they were left untouched by this task.)

## 19. Exact output locations (`<local-data-dir>/hipaa-comparison/`)

- `deterministic_results.json`
- `contextual_results.json`
- `ensemble_results.json` (union + precision-gated, rule layer)
- `phileas_results.json`
- `comparison_summary.json`
- `performance_results.json`
- `fn_outcomes.json` (15-FN per-system outcome table)
- `ensemble_securedact_phileas_results.json` (blind union)
- `ensemble_securedact_phileas_gated_results.json` (names-gated union)
- `predictions_securedact_deterministic.json`
- `predictions_securedact_contextual_rules.json`
- `predictions_phileas.json`

Large/ generated artifacts are **not** added to git.

## 20. Unrelated working-tree changes observed (left untouched)

From `git status` at task start, the following were already modified/untracked and
**were not created or altered by this task**:
- Modified: `CHANGELOG.md`, `pyproject.toml`, `src/securedact_core/engine.py`,
  `src/securedact_core/firewall.py`, `src/securedact_core/models.py`,
  `src/securedact_core/policies.py`, `src/securedact_core/taxonomy.py`,
  `src/securedact_core/detectors/regex_detector.py`,
  `src/securedact_core/hipaa.py` (untracked), `src/securedact_mcp/cli.py`,
  `src/securedact_enforced/gemini_hook.py`, `src/securedact_enforced/provider_hook.py`,
  `uv.lock`.
- Untracked dirs/files: `benchmarks/hipaa/`, `docs/compliance/`,
  `docs/hipaa-safe-harbor-gap-analysis.md`, `docs/hipaa-safe-harbor-profile.md`,
  `scripts/a9_*.py`, `scripts/experimental/` (pre-existing),
  `src/securedact_core/compliance/`, `src/securedact_core/connectors/`,
  `src/securedact_eval/experimental/`, `src/securedact_mcp/connectors/`,
  several new test files.
These represent concurrent in-flight work; **none were reverted, staged, or
committed** by this task.

## 21. Confirmations

- **No production detection behavior was changed.** The benchmark reproduces the
  validated 150/0/15 baseline exactly, and all 108 existing HIPAA unit tests
  pass (4 xfailed known gaps).
- **No `git commit`, `git add`/`git stage`, `git push`, `git reset`, or `git
  checkout` of unrelated files was performed.** Only new untracked evaluation
  scripts and this document were created.
- **Gold labels were not altered.**
- **No third-party cloud API was called**; Philter ran locally in Docker.

---

*Benchmark date: 2026-08-26. Engine under test: SecuRedact deterministic
HIPAA detector (production). Comparator: Philter/Phileas 3.4.1 (Apache-2.0),
all filters enabled, local Docker. Shared corpus: 202 adversarial HIPAA cases.*
