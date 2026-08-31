# SecuRedact Contextual NER Shootout (HIPAA adversarial 202-case corpus)

**Date:** 2026-08-26
**Scope:** Evaluation-only. No production detector behavior was modified. All numbers are produced by
reusing the existing `scripts/experimental/hipaa_compare.py` scorer so they are comparable to the
previously reported Phileas comparison.

## 1. Environment (Windows WDAC was NOT weakened)

* **Runtime:** WSL2 Ubuntu 24.04 (preferred option from the mission). Windows WDAC `shm.dll` blockage of
  Torch is avoided legitimately by running classical on Linux — no security control was disabled.
* **Python:** 3.12.14 (project requires `>=3.12,<3.13`).
* **Framework:** `torch 2.13.0+cpu`, `flair 0.15.1`, `gliner 0.2.28`, `transformers 4.57.6`,
  `huggingface-hub 0.36.2`.
* **HF cache:** on the WSL ext4 filesystem at `/home/hueyi/hf` (DrvFS symlinks broke `os.path.isfile` /
  `hf_hub` offline resolution, so the cache was mirrored to native ext4).
* **Network:** Model **weights/metadata** were fetched from HuggingFace during load
  (the registry-pinned Flair revision `e2b1caab…` transiently 404'd and resolved to current `main`, which
  is the same commit). **No benchmark text was ever transmitted** — all 202 cases run locally. This
  satisfies the "no cloud inference" and "no benchmark text to external APIs" constraints.

## 2. Baselines reproduced

| System | TP | FP | FN | P | R | F1 |
|---|---|---|---|---|---|---|
| Deterministic (control) | 150 | 0 | 15 | 1.000 | 0.909 | 0.952 |
| Deterministic + contextual rules (union) | 152 | 0 | 13 | 1.000 | 0.921 | 0.959 |

Both match the expected baselines exactly. The 15 deterministic FNs are: **7×A (names), 5×B (geography),
1×L (VIN), 1×P (DNA/genetic), 1×R (relationship)**.

## 3. Flair (`flair/ner-english-large`)

* Load time ≈ 139 s (CPU); warm per-case ≈ 0.8 s; tag map `PER/PERSON→A`, `LOC/GPE→B`,
  `ADDRESS→B`, `DATE→C` (ORG/MISC left unmapped → out of HIPAA scope, never counted as FP).
* **Flair alone @0.50:** TP=11, FP=11, **P=0.500** — poor precision because of 10 location over-detections
  and 1 person FP. Flair's internal threshold is already high, so the post-hoc sweep (0.50–0.95) does not
  change its output.
* **Best contribution:** names. Flair recovers **all 7 name FNs** (matching Phileas's 7/7).

## 4. GLiNER (`urchade/gliner_multi_pii-v1`)

* Sweep (threshold):

| thr | TP | FP | P | R | F1 |
|---|---|---|---|---|---|
| 0.50 | 74 | 32 | 0.698 | 0.449 | 0.546 |
| 0.70 | 59 | 27 | 0.686 | 0.358 | 0.470 |
| 0.90 | 33 | 7 | 0.825 | 0.200 | 0.322 |
| 0.95 | 22 | 6 | 0.786 | 0.133 | 0.228 |

* Broader coverage than Flair (also surfaces SSN/MRN/date/email/url), but **noisy on structured
  identifiers** (5 SSN false positives). At P≈0.99 it has almost no recall.
* **Names:** recovers all 7 name FNs (like Flair). **Geography:** recovers the 2 city/state FNs but with
  8 location FPs. **Zero-shot P/R:** with custom `genetic data` / `relationship` labels it recovers the
  DNA (adv-P-007) and relationship (adv-R-019) FNs — Flair cannot.

## 5. Exact 15-FN recovery

| FN | Cat | Flair | GLiNER | GLiNER-ext | det+rules+Flair(A+B) |
|---|---|---|---|---|---|
| adv-A-002 Maria Gonzalez | A | ✓ | ✓ | ✓ | ✓ |
| adv-A-003 Jane Doe | A | ✓ | ✓ | ✓ | ✓ |
| adv-A-005 John Smith | A | ✓ | ✓ | ✓ | ✓ |
| adv-A-006 Mary Johnson | A | ✓ | ✓ | ✓ | ✓ |
| adv-A-007 Emily Carter | A | ✓ | ✓ | ✓ | ✓ |
| adv-A-008 Olivia Bennett | A | ✓ | ✓ | ✓ | ✓ |
| adv-A-012 Mr. Lee | A | ✓ | ✓ | ✓ | ✓ |
| adv-B-014 Chicago, Illinois | B | ✓ | ✓ | ✓ | ✓ |
| adv-B-015 Los Angeles, California | B | ✓ | ✓ | ✓ | ✓ |
| adv-B-001 / B-007 / B-010 street addr | B | ✗ | ✗ | ✗ | ✗ |
| adv-L-014 unlabelled VIN | L | ✗ | ✗ | marginal | ✗ |
| adv-P-007 DNA sequencing | P | ✗ | ✗ | ✓ | ✗ |
| adv-R-019 Relationship: spouse | R | ✗ | ✗ | ✓ | ✓ (rules) |

Totals: Flair 9/15, GLiNER 9/15, GLiNER-ext 12/15, det+rules+Flair(A+B) 10/15.
**Both Flair and GLiNER independently reproduce Phileas's 7/7 name recovery.**

## 6. Blind unions (representative threshold 0.50)

| System | TP | FP | FN | P | R | F1 |
|---|---|---|---|---|---|---|
| det + Flair | 159 | 11 | 6 | 0.935 | 0.964 | 0.949 |
| det + GLiNER | 159 | 32 | 6 | 0.833 | 0.964 | 0.893 |
| det + Flair + GLiNER | 159 | 35 | 6 | 0.820 | 0.964 | 0.886 |

Blind union boosts recall to 0.964 but destroys precision. **Not recommended.**

## 7. Precision-gated ensembles (selected)

| System | TP | FP | FN | P | R | F1 |
|---|---|---|---|---|---|---|
| det + Flair(A) | 157 | 1 | 8 | 0.9937 | 0.9515 | 0.9721 |
| det + GLiNER(A) | 157 | 3 | 8 | 0.9812 | 0.9515 | 0.9662 |
| det + Flair(A+B) | 159 | 11 | 6 | 0.9353 | 0.9636 | 0.9493 |
| det + rules + Flair(A) | 158 | 1 | 7 | 0.9937 | 0.9576 | **0.9753** |
| det + rules + GLiNER(A+B) | 160 | 14 | 5 | 0.9195 | 0.9697 | 0.9441 |

## 8. Complementarity (Flair vs GLiNER)

* Flair is the clearly stronger **A (names)** model: 7/7 names, only 1 person FP.
* GLiNER's unique value is **zero-shot P/R labels** (DNA, relationship) — not A/B.
* Running both is **redundant for names**; GLiNER adds noise (5 SSN FPs, 8 location FPs).
* Conclusion: best architecture is **category-specific** — Flair for A, deterministic for everything
  structured, existing rules for R, GLiNER optional only if genetic/relationship zero-shot is in scope.

## 9. Performance (202 cases, CPU)

| Component | total s | per-case ms |
|---|---|---|
| Deterministic | ~0.02 | ~0.1 |
| Contextual rules | ~0.03 | ~0.15 |
| Flair (incl. 139 s load) | infer ~0.16 | ~0.8 |
| GLiNER (infer) | ~0.4 | ~2.0 |

Contextual NER is ~5–20× slower than deterministic but still sub-second/case on CPU.

## 10. Key answer — beats Phileas-gated?

**YES.** Target: Phileas-gated F1=0.969, P=0.987.

* **det + rules + Flair(A):** F1=**0.9753**, P=**0.9937**, R=0.9576.
  → Higher F1 *and* higher precision, with **no Phileas** and no cloud inference.
* Best precision-preserving config (`det+rules+Flair(A)`) already beats the Phileas-assisted result on
  both axes.

## 11. Precision / recall trade-off

* **P = 1.000:** only `deterministic + contextual rules` (F1=0.959). No Flair/GLiNER-gated config reaches
  P=1.000 — Flair adds exactly 1 person FP (`adv-A-011` "Dr. Lee"); GLiNER adds 3. A generic
  honorific/title gate also removes a **true** name (`adv-A-012` "Mr. Lee"), so P=1.000 with contextual NER
  is not cleanly attainable here.
* **P ≥ 0.995:** none (max contextual precision = 0.9937).
* **P ≥ 0.990:** `det + Flair(A)` / `det + rules + Flair(A)` = 0.9937.
* **Best overall F1:** `det + rules + Flair(A)` = 0.9753.

## 12. Recommended production architecture

**F — deterministic + existing contextual rules + Flair gated to category A (names) only.**

* Do **not** gate category B (geography) by default: Flair/GLiNER B gating costs 8–10 location FPs and drops
  precision to ~0.93. Keep B deterministic-only. (2/5 geography FNs are recoverable but not worth the precision
  loss; the other 3 are full street addresses no NER recovers.)
* Do **not** apply a generic honorific gate (drops the true name `adv-A-012`).
* Structured identifiers (SSN/MRN/email/IP/URL/account/license/device/…) stay deterministic-only.

## 13. Recommended i2b2 DEV configuration

* Primary contextual model: **Flair `ner-english-large`, gated to A**.
* Initial threshold: 0.50 (Flair's internal min); no extra threshold tuning needed for A.
* Gated categories for DEV: **A** (Flair) and **R** (existing contextual rules).
* GLiNER optional **only** if genetic/relationship zero-shot labels are in scope (not for A/B).
* Do **not** change the frozen i2b2 TEST config yet.

## 14. Remaining weaknesses

1. 5 geography FNs remain (3 full street addresses; 2 city/state recoverable at precision cost).
2. 1 VIN FN not robustly recovered (GLiNER-ext marginal, non-deterministic).
3. 1 DNA FN only via GLiNER custom genetic label.
4. Flair leaves 1 person FP (`Dr. Lee`) → P=0.9937, not 1.000.
5. GLiNER shows mild prompt-set non-determinism on VIN.

## 15. Output artifacts (`<local-data-dir>\hipaa-contextual-shootout\`)

`deterministic.json`, `contextual_rules.json`, `flair_thresholds.json`, `gliner_thresholds.json`,
`flair_predictions.json`, `gliner_predictions.json`, `gliner_extended_predictions.json`,
`blind_union_results.json`, `gated_ensemble_results.json`, `fn_recovery_matrix.json`,
`model_overlap.json`, `performance.json`, `error_analysis.json`, `final_recommendation.json`.

## 16. Confirmations

* ✅ Deterministic baseline reproduced (150/0/15/0.952).
* ✅ Contextual-rules baseline reproduced (152/0/13/0.959).
* ✅ Real Flair model ran (WSL2 CPU).
* ✅ Real GLiNER model ran (WSL2 CPU).
* ✅ Windows WDAC / security controls untouched (Linux runtime used).
* ✅ Threshold sweeps completed.
* ✅ All 15 FNs analyzed.
* ✅ Blind unions, precision-gated ensembles, complementarity measured.
* ✅ Phileas-gated F1=0.969/P=0.987 used as comparison target.
* ✅ No production detector/policy/taxonomy/engine/API changed.
* ✅ No benchmark gold labels changed (frozen corpus respected).
* ✅ No cloud inference of benchmark text (model weights/metadata only).
* ✅ No commit / stage / push / reset performed.

### Unrelated working-tree changes observed (recorded, NOT modified)

`CHANGELOG.md`, `docs/enterprise-connectors-roadmap.md`, `pyproject.toml`,
`src/securedact_core/{detectors/regex_detector.py, engine.py, firewall.py, models.py, policies.py,
taxonomy.py}`, `src/securedact_enforced/{gemini_hook.py, provider_hook.py}`, `src/securedact_mcp/cli.py`,
`uv.lock`, plus many untracked experimental/benchmark/doc files. Left exactly as found.
