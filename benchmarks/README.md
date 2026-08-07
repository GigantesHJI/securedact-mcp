# Securedact evaluation smoke corpus and benchmark framework

This directory contains the local evaluation framework, schemas, deterministic generators,
source approvals, adapters, small fixtures, and aggregate baselines. The committed 160-document
fixture is an **evaluation smoke corpus**, not the complete benchmark and not evidence of GDPR
compliance. The 5,000- and 20,000-document profiles are generated outside Git.

## Data boundary and tiers

- **Public** data is fictional or explicitly reusable. Only small public fixtures may be committed.
- **External** data is retrieved manually from an exact approved source, verified, adapted locally,
  and scored separately. Raw records never enter Git or a public report.
- **Restricted** data is supplied by an authorized maintainer through an explicit local path. It is
  never downloaded, committed, run in public CI, uploaded, or included in record-level reports.

The evaluator rejects mixed-tier runs so public, external, and restricted data cannot be collapsed
into one headline score. Restricted sample results are always suppressed.

Set `SECUREDACT_BENCHMARK_DATA_DIR` to an absolute directory outside the checkout. Defaults are
`%LOCALAPPDATA%\Securedact\benchmark-data` on Windows and
`~/.local/share/securedact/benchmark-data` on Linux. The tool creates separate `generated`,
`external`, `restricted`, `private-holdout`, `cache`, `reports`, and `manifests` directories. It
rejects repository-contained paths and linked/reparse-point ancestors and never deletes restricted
content.

## Profiles and commands

```powershell
uv sync --frozen --extra benchmark
uv run securedact-eval workspace
uv run securedact-eval generate --profile smoke --output benchmarks\fixtures\smoke --allow-repository-output
uv run securedact-eval generate --profile public-medium
uv run securedact-eval generate --profile benchmark-v0.2
uv run securedact-eval validate --dataset "$env:SECUREDACT_BENCHMARK_DATA_DIR\generated\benchmark-v0.2"
uv run securedact-eval quality --corpus "$env:SECUREDACT_BENCHMARK_DATA_DIR\generated\benchmark-v0.2" --aggregate-only
uv run securedact-eval audit --corpus benchmarks\fixtures\smoke --clean-corpus benchmarks\corpora --thresholds benchmarks\adversarial_thresholds.json --output-dir build\adversarial-audit
```

`smoke` has 160 committed records. `public-medium` has 5,000 generated records.
`benchmark-v0.2` has 20,000 records, at least 30,000 annotations, and 45% Dutch documents.
`external-full` and `restricted-local` are adapter-only and fail closed until explicit local inputs
are provisioned. Generated manifests record the generator and pinned Faker versions, seed, lock
digest, file hashes, languages, categories, domains, sources, splits, assertion contexts,
transformations, and template families. A matching code revision, lockfile, profile, and seed yields
byte-identical JSONL and hashes.

## Adversarial release scores

The adversarial audit keeps the overall aggregate as a diagnostic only. The primary report has
five mutually exclusive groups: `standard_clean`, `negative_controls`, `supported_adversarial`,
`partially_supported_adversarial`, and `unsupported_challenge`. Unsupported records are always
reported and are informational only. Partial support remains visible but is not silently mixed into
a release gate.

`adversarial_thresholds.json` gates only the curated standard-clean reference and the supported
adversarial group. Its initial values were recorded after measuring the corrected generator 2.6.0
baseline; they were not lowered to reinterpret unsupported challenges as supported behavior. A
locally configured real Flair model is reported separately. The annotation-backed contextual mock
only verifies evaluation plumbing and is prominently marked as non-quality evidence.

## Coverage and integrity

The synthetic families include email, HR, healthcare, education, legal/case notes, support, chat,
meetings, prose, source code, configuration, logs, forms, CSV, JSON, YAML, XML, Markdown, and
invoices. They include ordinary identifiers, clearly fictional credentials, mixed entities, all
supported Article 9 concept categories, realistic negatives, and labelled transformations. Current,
negated, uncertain, hypothetical, quoted, historical, family-history, general-discussion,
organization-level, and near-miss contexts are separate from entity category. Unsupported
transformations remain in reports.

Integrity checks cover IDs, exact substrings and Unicode offsets, provenance, nested/partial
overlaps, manifests, exact/normalized/approximate duplicates, and cross-split source-record,
source-document, template, seed, entity-value, and transformation-parent leakage. The private
release-gate schema and maintainer process are public; its records and membership are not.

## Sources and adapters

`registry/sources.yml` is fail closed. Enabled entries require an exact version, official locations,
reviewed licence and use/redistribution rights, tier approval, attribution, access restrictions,
review date, reviewer placeholder, and expected size plus digest. The MultiCoNER 1 English/Dutch
adapter maps only defensible person, location, group, and corporation labels, reports unmapped
labels, and emits attribution. Its official single-part S3 ETags are change detectors rather than
cryptographic authentication. The Dutch open-government entry is deliberately disabled: each exact
dataset needs its own licence and hash review. Faker is locked to 40.35.0 with locale, seed,
provider, field, and fictional provenance.

AI4Privacy, MultiNERD, SoNaR, MIMIC, i2b2/n2c2, WikiANN, Universal NER constituent datasets,
customer data, and private holdouts are neither bundled nor automatically retrieved.

## Repository limits

`scripts/validate_repository_size.py` rejects individual benchmark files above 5 MiB, fixture
corpora above 25 MiB total, committed reports above 10 MiB, tracked raw/external/restricted/private
paths, and private-holdout records. Large per-record output, source archives, model weights, and the
complete generated corpus remain outside Git.
