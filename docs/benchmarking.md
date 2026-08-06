# Quality and performance benchmarking

The migration-ready architecture, data tiers, profiles, workspace, source approvals, integrity
rules, and generation commands are documented in [the benchmark README](../benchmarks/README.md).

The benchmark corpus is synthetic and divided into development, validation,
frozen release-gate, adversarial, and negative files. `manifest.json` pins every
corpus file by SHA-256 so frozen data cannot change unnoticed. Do not tune rules
against release-gate cases without recording the resulting bias and refreshing a
reviewed baseline.

The corpus covers English and Dutch across general prose, email, HR, healthcare,
education, legal notes, customer support, meeting notes, source code,
configuration, and application logs. It includes ordinary identifiers,
credentials, all nine GDPR Article 9 concept groups in the supported taxonomy,
difficult negatives, and structured/adversarial formats. Synthetic data can be
cleaner and less varied than real documents; results do not prove GDPR compliance
or universal disclosure prevention.

```powershell
python -m securedact_eval quality --mode deterministic
python -m securedact_eval quality --mode flair
python -m securedact_eval performance --mode deterministic --gate
python -m securedact_eval performance --mode flair
python -m securedact_eval report `
  --deterministic results\quality-deterministic.json `
  --flair results\quality-flair.json
```

Quality output includes JSON, CSV detail, and Markdown. Metrics include TP, FP,
document-level TN where defined, FN, precision, recall, F1, false-positive rate,
false-negative rate, support, micro/macro/weighted averages, exact and relaxed
span matching, category/action accuracy, document unsafe/block/review decisions, residual sensitive
values and approved-output leaks, per entity/language/domain/source/tier/format/assertion/
transformation/mixedness/text-length/split, and a
deterministic bootstrap 95% recall interval. Undefined denominators serialize as
`null`, never a fabricated zero or one.

The committed thresholds use the current deterministic result as a regression
baseline with explicit tolerances. High-risk identifiers and credentials have a
stricter minimum than ambiguous organization/location detection. Hardware-bound
performance values use a broad warm-p95 ceiling; hardware/resource values and
input-scaling timings remain reporting-only. Tightening thresholds requires a
reviewed baseline update and representative CI evidence.

Performance uses `time.perf_counter_ns`, a fresh subprocess for cold process,
separate model initialization and first inference, warmups, median/p95/min/max,
requests per second, input scaling, observed RSS, CPU, and optional `nvidia-smi`
GPU metrics. Unsupported GPU or process metrics are `null`/unavailable, not zero.
Results vary by hardware and are not universal guarantees.

Ordinary CI runs deterministic and tiny injected/mock-Flair evaluation without
downloading real weights. Real Flair evaluation requires
`SECUREDACT_EVAL_FLAIR_MODEL` and the manual pre-provisioned runner workflow. Do
not describe mocked results as real-model performance.
