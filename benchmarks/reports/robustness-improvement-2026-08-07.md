# Robustness improvement report — 2026-08-07

## Outcome

The detector has a substantially better robustness baseline without weakening privacy behavior or changing release thresholds. On the frozen corrected smoke corpus, deterministic exact F1 rose from **0.5662 to 0.7775** and real bilingual Flair exact F1 rose from **0.6261 to 0.8406**. No approved `status: ok` output retained an expected sensitive value in any final or fresh-seed run.

The originally reported exact P/R/F1 of **0.2646 / 0.2261 / 0.2438** was not a valid primary quality score. The dominant precision failure was a confirmed generator defect: numeric record suffixes created 151 accidental phone detections. It was not primarily caused by deliberately unsupported transformations.

All data and examples are synthetic. The complete machine-readable group tables and synthetic record-level taxonomy are in `build/improvement/after/adversarial-audit.json`; the rendered full audit is in `build/improvement/after/adversarial-audit.md`. The committed JSON beside this report is aggregate-only by repository policy.

## Frozen before/after result

| Mode | Phase | Support | TP | FP | FN | Exact F1 | Relaxed F1 | Residual leak |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Deterministic | Before | 261 | 109 | 15 | 152 | 0.5662 | 0.6182 | 0.0000 |
| Deterministic | After | 261 | 166 | 0 | 95 | 0.7775 | 0.7775 | 0.0000 |
| Real Flair EN+NL | Before | 261 | 144 | 55 | 117 | 0.6261 | 0.7478 | 0.0000 |
| Real Flair EN+NL | After | 261 | 203 | 19 | 58 | 0.8406 | 0.8654 | 0.0000 |
| Mocked contextual | After | 261 | 229 | 0 | 32 | 0.9347 | 0.9347 | 0.0000 |

Mocked contextual mode is annotation-backed test plumbing and is **not quality evidence**. Real Flair used the locally registered `english-large@e2b1caab+dutch-large@44c28591` checkpoints in offline mode.

## Release-score groups

Unsupported challenges remain visible and informational. Only standard clean and supported adversarial groups are eligible for release thresholds; thresholds were not changed.

### Deterministic-only

| Group | Phase | Support | TP | FP | FN | Exact F1 | Relaxed F1 | Unsafe-doc detection | Leak rate |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Standard clean | Before | 12 | 8 | 1 | 4 | 0.7619 | 0.8571 | 1.0000 | n/a |
| Standard clean | After | 12 | 9 | 0 | 3 | 0.8571 | 0.8571 | 1.0000 | n/a |
| Negative controls | Before | 0 | 0 | 0 | 0 | n/a | n/a | 1.0000 | 0.0000 |
| Negative controls | After | 0 | 0 | 0 | 0 | n/a | n/a | 1.0000 | 0.0000 |
| Supported adversarial | Before | 84 | 49 | 1 | 35 | 0.7313 | 0.7463 | 0.8333 | n/a |
| Supported adversarial | After | 84 | 59 | 0 | 25 | 0.8252 | 0.8252 | 0.9762 | n/a |
| Partially supported | Before | 117 | 34 | 13 | 83 | 0.4146 | 0.5122 | 0.5893 | n/a |
| Partially supported | After | 117 | 69 | 0 | 48 | 0.7419 | 0.7419 | 0.9107 | n/a |
| Unsupported challenge | Before | 48 | 18 | 0 | 30 | 0.5455 | 0.5455 | 0.7500 | n/a |
| Unsupported challenge | After | 48 | 29 | 0 | 19 | 0.7532 | 0.7532 | 1.0000 | n/a |

The separate curated clean reference stayed exactly unchanged at TP 30, FP 1, FN 2, exact/relaxed F1 **0.9524**.

### Real bilingual Flair

| Group | Phase | Support | TP | FP | FN | Exact F1 | Relaxed F1 | Unsafe-doc detection | Leak rate |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Standard clean | Before | 12 | 11 | 1 | 1 | 0.9167 | 1.0000 | 1.0000 | n/a |
| Standard clean | After | 12 | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | n/a |
| Negative controls | Before | 0 | 0 | 3 | 0 | n/a | n/a | 0.9063 | 0.0000 |
| Negative controls | After | 0 | 0 | 0 | 0 | n/a | n/a | 1.0000 | 0.0000 |
| Supported adversarial | Before | 84 | 66 | 12 | 18 | 0.8148 | 0.9012 | 0.9524 | n/a |
| Supported adversarial | After | 84 | 73 | 8 | 11 | 0.8848 | 0.9455 | 0.9762 | n/a |
| Partially supported | Before | 117 | 49 | 32 | 68 | 0.4949 | 0.6667 | 0.9107 | n/a |
| Partially supported | After | 117 | 89 | 8 | 28 | 0.8318 | 0.8411 | 0.9464 | n/a |
| Unsupported challenge | Before | 48 | 18 | 7 | 30 | 0.4932 | 0.5753 | 0.9167 | n/a |
| Unsupported challenge | After | 48 | 29 | 3 | 19 | 0.7250 | 0.7250 | 1.0000 | n/a |

The separate curated clean reference also stayed unchanged: TP 32, FP 4, FN 0, exact/relaxed F1 **0.9412**. That reference is below the desired 0.95 exact-F1 target because of four unchanged contextual false positives; it is not a regression. The standard-clean release group is 1.0000 after the work.

## Languages and principal errors

Final real-model English exact/relaxed F1 is **0.8347 / 0.8512** (support 131, TP 101, FP 10, FN 30). Dutch is **0.8465 / 0.8797** (support 130, TP 102, FP 9, FN 28). Both have a residual-leak rate of 0.

The largest real-model false-positive categories are organization (9), person (8), and location (2). The largest false-negative categories are person (26), email (18), unknown-sensitive (5), and IBAN (2). The final real-mode failure taxonomy contains 33 missed-entity, 29 normalization-failure, 21 overlap-conflict, 15 wrong-category, 6 oversized-span, 2 unexpected-false-positive, and 19 unsupported-transformation classifications; records may have more than one classification.

Representative synthetic cases in the full report include a fictional accented person name missed in deterministic mode, punctuation around a synthetic identifier causing an oversized span, a broad phone-shaped match overlapping a narrower annotation, and an obfuscated `example.test` email. No real personal data is included.

## Transformations

Real Flair is exact on apostrophe, fullwidth, HTML-entity, original, and split-phone records. Supported failures that remain genuine are casing (0.8333 exact F1), Unicode normalization (0.8333), and exact-boundary behavior for Dutch surname prefixes (0.7500 exact versus 1.0000 relaxed), line wrapping (0.9167 versus 1.0000), and punctuation spacing (0.9167 versus 1.0000). The supported real-group exact-to-relaxed gap of **0.0606** is material; deterministic after-results have no exact/relaxed gap.

Partially supported weaknesses remain explicitly separate: email obfuscation 0.6667, initials 0.8421 exact/0.9474 relaxed, whitespace insertion 0.3158, and whitespace removal 0.7273. Unsupported challenge results remain informational: homoglyph 0.6000, OCR-like 0.6667, and zero-width 0.9167.

The full audit reports all metrics for every entity category, domain, transformation, language, release group, record class, and entity-mix group. There are 128 mixed-entity positive documents and 32 negative documents in this corpus; there are no single-entity documents, which is reported as zero support rather than silently omitted.

## Fresh unseen seed

Seed `20260807` was generated only after implementation and was not used for tuning: 160 synthetic documents, 261 entities, balanced 80 English / 80 Dutch. Deterministic exact/relaxed F1 is **0.7710 / 0.7757** (TP 165, FP 2, FN 96); real Flair is **0.8247 / 0.8577** (TP 200, FP 24, FN 61). Both residual-leak rates are 0. This close reproduction argues against benchmark-specific overfitting.

MultiCoNER EN/NL is registered as an approved external source but its files are not available locally. No download was attempted, so external validation is reported as unavailable rather than substituted or silently skipped.

## Performance and operational limits

On this Windows/Intel CPU-only host, deterministic warm p95 increased from **3.0090 ms to 5.1831 ms**. Medium median increased from 41.9938 ms to 65.8550 ms; long median increased from 707.2293 ms to 764.9629 ms. RSS increased from 39,735,296 to 52,973,568 bytes. The normalization implementation caches document views and avoids the initially observed unbounded per-entity recomputation.

Real Flair is operationally expensive without a GPU: cold start 44.33 s, warm p95 433.50 ms, medium median 2.44 s, long median 38.31 s, and observed RSS 7.20 GB. CUDA was unavailable, so no GPU comparison could be produced.

## Integrity, validation, and conclusions

The frozen audit revalidated source substrings, Unicode code-point offsets, transformation annotations and semantics, negative controls, support labels, mutually exclusive release groups, exact/relaxed math, mixed-document counting, duplicate suppression, taxonomy mappings, and policy actions. Confirmed benchmark/evaluator defects have regression tests. No further corpus, annotation, evaluator, or threshold change was made during detector improvement.

Validation completed with **530 passed, 2 skipped**, Ruff passing, strict mypy passing across 47 source files, release-artifact validation passing, and `twine check` passing. The wheel and source archive contain the normalization module and detector lexicon.

Required answers:

1. Normal clean performance did **not** regress.
2. The low original F1 was **not** primarily caused by unsupported transformations; generator contamination dominated the precision collapse.
3. Exact scoring is materially below relaxed scoring for supported real-Flair records, but not for deterministic after-results.
4. Remaining supported failures are casing, Unicode normalization, and exact boundaries for Dutch surname prefixes, line wrapping, and punctuation spacing.
5. Organization, person, and location generate the most false positives in real mode; deterministic mode has none on the smoke corpus.
6. Person, email, unknown-sensitive, and IBAN generate the most false negatives.
7. No `status: ok` result contains an expected sensitive value.
8. Benchmark and evaluator defects were found, corrected, and covered by regression tests.
9. Later priorities should be Flair person/category calibration, partially supported email and whitespace obfuscation, unknown-sensitive handling, and long-input contextual performance.

No tag, push, or release was performed.
