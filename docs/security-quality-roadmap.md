# Securedact MCP — Security & Quality Roadmap

> Package version: **0.3.0**
> Status: documentation-only roadmap. No fixes are implemented in this document.
> This roadmap is an engineering plan for future agents. It is **not** a
> vulnerability admission. It records findings, prioritized work, verified
> correct behavior to preserve, and closed/disproven theories.

---

## 1. Status

- This document captures the post-`0.2.1` independent audit conclusions.
- No code changes accompany this document. Implementation is deferred to the
  phased plan in section 9 and the recommended first batch in section 10.
- All file/function references were checked against the repository at the time
  of writing. Where a reference could not be confirmed it is marked.
- Roadmap IDs are stable and should be referenced by ID in commits, PRs, and
  changelog entries.

---

## 2. Priority definitions

- **P0 — Privacy & release trust.** Issues that, if exploited or shipped,
  undermine the core privacy guarantee or the release/trust boundary. Must be
  resolved before a release that claims privacy readiness.
- **P1 — Detection & evaluation correctness.** Correctness of detectors and the
  deterministic evaluation gate. Some are behavior-sensitive and require
  before/after benchmarking.
- **P2 — Quality, performance, adoption.** Improvements that broaden coverage,
  reduce friction, or improve adoption. Non-privacy-blocking.
- **P3 — Hardening & cleanup.** Defensive guards, error normalization, docs, and
  small correctness/hygiene items.

Items explicitly marked **[SPECULATIVE]** are hypotheses that require
confirmation (measurement or investigation) before work is scheduled.

---

## 3. P0 — Privacy & release trust

### ROAD-001 — `finding_id` is derived from plaintext and can act as a brute-force oracle

- **status:** open
- **severity:** high (privacy-adjacent; conditional on exposure of low-entropy
  sensitive values)
- **implementation risk:** low-to-moderate. The change is localized to ID
  derivation but the ID is used as a stable correlation key across
  `review_decisions`, MCP responses, and re-submission flows, so the fix must
  preserve in-process/session review usability.
- **evidence:**
  - `src/securedact_core/models.py:170-172` — `Detection.id` seed is
    `f"{self.start}:{self.end}:{self.entity_type}:{self.source}:{self.text}"`.
    The seed includes `self.text`, i.e. the raw sensitive value.
  - The derived `id` is a 16-char `sha256` prefix and is exposed as
    `finding_id` in `SafeFinding` (`src/securedact_core/api.py:484`, `:520`) and
    consumed by `ReviewDecision.detection_id`
    (`src/securedact_core/api.py:92`, `src/securedact_core/models.py:187`).
  - `SensitiveAssertion.id` (`src/securedact_core/models.py:251-253`) is derived
    from span/category/detector only and does **not** include plaintext text;
    this finding is specific to `Detection`-level findings (entity values).
- **affected files/functions:**
  - `src/securedact_core/models.py` `Detection.validate_span` (`id` derivation)
  - `src/securedact_core/api.py` `to_findings` / `ReviewDecision` wiring
  - consumers of `finding_id` in `src/securedact_mcp/server.py` tools and the
    public Python API path used for `review_decisions`.
- **impact:** An observer who can see `finding_id` values (e.g. over the MCP
  protocol response, logs that violate stdout hygiene, or a host that persists
  responses) and who knows the non-text seed components (span offsets, entity
  type, source) can brute-force low-entropy sensitive values. Real-world risk
  is bounded by entropy of the value and by who can observe the IDs, but the
  property is undesirable for a privacy tool.
- **scope/preconditions:** Exploitability requires (a) exposure of `finding_id`
  outside the process and (b) a low-entropy value (short token, enum-like value)
  at a known span/type/source. High-entropy secrets are not meaningfully
  brute-forceable. The oracle is per-seed-component; it is not a global secret
  recovery.
- **recommended fix:** Replace plaintext-derivation with a keyed, per-process
  (or per-session) identifier that is not value-nonderivable by an external
  observer. Preferred direction: keyed HMAC over the seed using a process-local
  random key, truncated to a stable length, while preserving
  review/re-submission usability within the process/session. Alternatively, an
  opaque process-local counter/UUID map keyed by the internal detection, exposed
  only as a correlation handle.
- **acceptance criteria:**
  - `finding_id` cannot be inverted to recover `text` without the process-local
    key/state.
  - Within a process/session, identical detections still correlate (same
    `finding_id`) so `review_decisions` and re-submission continue to work.
  - No raw `text` appears in the seed in any observable or derivable form.
- **validation/tests:**
  - Unit test asserting `finding_id` does not equal a function of
    `(start, end, entity_type, source, text)` reconstructible without a secret.
  - Property test: given two distinct `text` values at identical
    non-text seed components, IDs must not be trivially distinguishable by an
    offline attacker without the key.
  - Regression test for `review_decisions` round-trip (accept/ignore/block by
    `detection_id`) to confirm usability is preserved.
- **dependencies:** none.

### ROAD-002 — `block_on_unreviewed` is policy-file-settable but missing from fail-closed loader invariants

- **status:** open
- **severity:** medium (public Python API invariant violation; normal MCP
  `prepare_for_external_ai` is not directly exposed to the
  `review_decisions` required-review path, but the public engine invariant is
  still violated)
- **implementation risk:** low. Additive invariant in the loader.
- **evidence:**
  - `src/securedact_core/policies.py:138` — `block_on_unreviewed: bool = True`.
  - `src/securedact_core/engine.py:625` — `if unresolved and policy.block_on_unreviewed:`
    enforces blocking on unreviewed critical items.
  - `src/securedact_core/policy_loader.py:135-149` `_validate_invariants` enforces
    a fail-closed set of invariants (protected-type ALLOW banned, residual
    validation enabled, `residual_on_failure == "block"`, no raw-value/mapping
    exposure, low-confidence review types) but does **not** include
    `block_on_unreviewed`.
  - A local policy file can therefore set `block_on_unreviewed: false`, which the
    loader accepts even though it weakens the required-review guarantee.
- **affected files/functions:**
  - `src/securedact_core/policy_loader.py` `LocalPolicyLoader._validate_invariants`
  - `src/securedact_core/policies.py` `Policy.block_on_unreviewed`
  - `src/securedact_core/engine.py` review-resolution path
- **impact:** A loaded policy can disable the fail-closed block-on-unreviewed
  behavior, contradicting the stated invariant that unreviewed protected
  findings are not released. The MCP `prepare_for_external_ai` flow is not
  directly gated by `review_decisions`, so the live MCP path is not the primary
  exposure; the public Python API review path is where the invariant matters.
- **scope/preconditions:** Requires a malicious or mistaken local policy file
  under the configured `SECUREDACT_POLICY_DIR` (or default `policies/`). No
  network or remote trigger.
- **recommended fix:** Add `block_on_unreviewed` to the fail-closed invariants in
  `policy_loader._validate_invariants` (require it to be `True` for policies that
  can gate protected data), or document and enforce a canonical "review required"
  invariant independent of the flag. Align with the existing invariant checks at
  `policy_loader.py:142-149`.
- **acceptance criteria:**
  - A policy file with `block_on_unreviewed: false` is rejected with
    `INVARIANT_VIOLATION`.
  - Existing built-in policies and tests that rely on the default `True` continue
    to pass.
- **validation/tests:**
  - Add a `test_policy_loader` case asserting rejection of
    `block_on_unreviewed: false`.
  - Existing `tests/unit/test_policy_loader.py` invariants must still pass.
- **dependencies:** none.

### ROAD-003 — `SECURITY.md` supported-version text is stale

- **status:** open
- **severity:** low (release-trust/docs accuracy)
- **implementation risk:** trivial.
- **evidence:**
  - `SECURITY.md:5-6` — still states "No Securedact MCP server version has been
    released ... The current `0.1.0` package is an unreleased alpha pending
    repository review." The shipped package version is `0.2.1`
    (see `.claude-plugin/marketplace.json:8` and `.claude-plugin/marketplace.json:15`).
- **affected files/functions:** `SECURITY.md` "Supported versions" section.
- **impact:** Misleading security-support statement for a released version;
  erodes trust and complicates vulnerability reporting expectations.
- **scope/preconditions:** documentation only.
- **recommended fix:** Update "Supported versions" to describe the released
  `0.2.1` and the supported-version security-update policy. Keep the
  reporting-contact and model-review sections intact.
- **acceptance criteria:** `SECURITY.md` no longer references `0.1.0` as
  unreleased and accurately states the supported released version.
- **validation/tests:** doc review; optionally a stale-string lint if one exists.
- **dependencies:** none.

### ROAD-004 — stale `.agents/plugins/marketplace.json` references removed Codex enforced plugin path

- **status:** open
- **severity:** low (shipped-artifact correctness; not a privacy issue)
- **implementation risk:** trivial.
- **evidence:**
  - `.agents/plugins/marketplace.json:11` — `"path": "./integrations/codex-enforced/securedact-enforced"`.
  - The path `integrations/codex-enforced` does **not** exist. The
    `integrations/` directory contains `claude-code-enforced`, `codex`,
    `cursor`, `gemini-enforced`, `windsurf` (no `codex-enforced`).
  - The canonical Claude marketplace uses
    `./integrations/claude-code-enforced/securedact-enforced`
    (`.claude-plugin/marketplace.json:12`).
  - The repository validator (`scripts/validate_repo.py`,
    `scripts/validate_release_artifacts.py`) does not currently catch this stale
    reference, so it can ship undetected.
- **affected files/functions:** `.agents/plugins/marketplace.json`;
  `scripts/validate_repo.py` / release artifact validation (gap).
- **impact:** A marketplace/manifest points at a non-existent plugin path; the
  referenced Codex enforced integration was removed. Broken onboarding for any
  tool consuming `.agents/plugins/marketplace.json`.
- **scope/preconditions:** Affects only the `.agents` plugin marketplace
  metadata; the Claude marketplace (` .claude-plugin/marketplace.json`) is
  correct.
- **recommended fix:** Either correct the path to the current Codex integration
  (`integrations/codex/...` if that is the intended shipping target) or remove
  the stale `.agents/plugins/marketplace.json` entry/path. Extend
  `validate_release_artifacts.py` (and/or `validate_repo.py`) to assert that
  every `marketplace.json` plugin `source.path` resolves to an existing
  directory under the repo.
- **acceptance criteria:**
  - Every plugin `source.path` in shipped marketplace manifests resolves to a
    real path, or the stale manifest is removed.
  - New validator check fails the build if a referenced plugin path is missing.
- **validation/tests:**
  - Add a validation test over `.agents/plugins/marketplace.json` and
    `.claude-plugin/marketplace.json` asserting path existence.
- **dependencies:** none.

---

## 4. P1 — Detection & evaluation correctness

### ROAD-101 — Dutch "de patiënt" mojibake in contextual detector causes a recall bug

- **status:** open
- **severity:** medium (recall regression for Dutch patient-subject references)
- **implementation risk:** low, but needs a regression corpus/test to lock in.
- **evidence:**
  - `src/securedact_core/detectors/contextual_detector.py:43` declares the
    correct token `de patiënt` (UTF-8 `ë`).
  - `src/securedact_core/detectors/contextual_detector.py:235` matches the
    mojibake form `de patiÃ«nt` (UTF-8 `ë` decoded as Latin-1), which will not
    match the correctly encoded input `de patiënt`.
  - This is the `record_subject_reference` heuristic used to link pronouns to a
    patient subject. The mismatch drops patient-subject linkage recall when the
    correct UTF-8 spelling is present.
- **affected files/functions:**
  - `src/securedact_core/detectors/contextual_detector.py` `PRONOUN_PATTERN`
    usage and `record_subject_reference` regex at line 235.
- **impact:** Dutch clinical text using "de patiënt" may lose subject-reference
  linkage, reducing recall of associated sensitive assertions.
- **scope/preconditions:** Dutch language path; requires the contextual detector
  active (Flair/contextual required per policy). English unaffected.
- **recommended fix:** Normalize the subject-reference matching to match both the
  correct `de patiënt` and treat the mojibake form as a bug to fix (not a
  feature). Add a Dutch regression corpus entry with correctly encoded
  "de patiënt" and a pronoun-linked sensitive assertion.
- **acceptance criteria:**
  - Correctly encoded `de patiënt` links pronouns to the patient subject.
  - Mojibake input is handled defensively without introducing false positives.
- **validation/tests:**
  - New `tests/unit` or privacy-corpus case for Dutch patient-subject linkage.
  - Re-run `securedact_eval quality --mode deterministic` Dutch recall to confirm
    no regression.
- **dependencies:** none.

### ROAD-102 — deterministic high-risk gate lacks password/private_key coverage

- **status:** open
- **severity:** medium (gate does not actually enforce high-risk recall for these
  entity types in deterministic mode)
- **implementation risk:** low; depends on eval fixture coverage.
- **evidence:**
  - `benchmarks/thresholds.json:12` lists
    `"high_risk_entities": ["email", "api_token", "access_token", "private_key", "password"]`,
    so the *intent* to cover `password`/`private_key` is present.
  - `src/securedact_eval/gates.py:58-63` iterates `thresholds.high_risk_entities`
    and looks up `report.per_entity.get(name)`. If the metric is `None` or has no
    support (`not metric.exact.support`), the entity is **skipped**
    (`continue`) rather than enforced.
  - Therefore, unless the deterministic corpus/fixtures assert expected
    `password`/`private_key` entities, the gate silently does not enforce
    high-risk recall for them. The credentials detector does define
    `password`/`private_key` rules
    (`src/securedact_core/detectors/credentials_detector.py:69,99,499`), but
    eval coverage is the gap.
- **affected files/functions:**
  - `src/securedact_eval/gates.py` `evaluate_quality_gate` high-risk loop
  - `benchmarks/thresholds.json`
  - deterministic eval corpus/fixtures (coverage)
- **impact:** A regression that dropped `password`/`private_key` recall in
  deterministic mode would not fail the gate if no fixtures assert those
  entities.
- **scope/preconditions:** Deterministic eval (`--mode deterministic`); depends
  on fixture support.
- **recommended fix:** Add deterministic-mode fixtures asserting expected
  `password` and `private_key` entities so the gate enforces them, or change the
  gate to fail (not skip) when a high-risk entity is listed but absent from the
  report. Decide deliberately; skipping-with-warning may be acceptable if
  documented.
- **acceptance criteria:**
  - `password`/`private_key` high-risk recall is enforced in deterministic mode.
  - A deliberate drop in their recall fails the gate.
- **validation/tests:**
  - Extend deterministic corpus with password/private_key cases.
  - Gate unit test asserting enforcement when `per_entity` support exists.
- **dependencies:** ROAD-103 (gate wiring) for end-to-end effect.

### ROAD-103 — deterministic quality/performance `--gate` is not wired into main verification/CI path

- **status:** open
- **severity:** medium (release gate not actually enforced by `verify.py`)
- **implementation risk:** low.
- **evidence:**
  - `src/securedact_eval/cli.py:40,43,57,103,114,149,154` exposes `--gate` for
    `quality` and `performance`.
  - `scripts/verify.py:43-53` runs `securedact_eval quality --corpus ... --aggregate-only`
    (no `--gate`), and does not run the performance gate at all. So the
    deterministic `--gate` is available but not part of the primary
    network-free CI/verification path.
- **affected files/functions:**
  - `scripts/verify.py` verification command list
  - `src/securedact_eval/cli.py` gate flags
- **impact:** Release-quality gates are optional and can be bypassed by the
  default `verify.py` path; regressions are not blocked automatically.
- **scope/preconditions:** CI / release verification.
- **recommended fix:** Wire the deterministic quality `quality --gate` (and
  performance `performance --gate`) into `scripts/verify.py` using the committed
  `benchmarks/thresholds.json`, failing the build on gate failure. Keep
  Flair/real-model runs manual-only.
- **acceptance criteria:**
  - `verify.py` fails when the deterministic gate fails.
  - Flair/heavy gates remain excluded from the network-free path.
- **validation/tests:**
  - Run `uv run python scripts/verify.py` after wiring; confirm gate executes.
- **dependencies:** ROAD-102 (so the gate has meaningful coverage).

### ROAD-104 — contextual/statistical categories lack a residual-validation backstop

- **status:** open
- **severity:** medium (behavior-sensitive; benchmark before/after)
- **implementation risk:** moderate (changes residual-scan surface; must measure
  false-positive impact).
- **evidence:**
  - `src/securedact_core/engine.py:669` `scan_residual` reruns credentials and
    contextual rules (`contextual_residual_scan` at `:745`) but contextual/
    statistical categories other than the explicit residual rerun may not have a
    dedicated residual backstop comparable to credentials.
  - Residual scan is the final fail-closed check before `safe_to_send`
    (`engine.py:769`, `api.py:336-342`, `server.py:597-599`).
- **affected files/functions:**
  - `src/securedact_core/engine.py` `scan_residual`
  - `src/securedact_core/policies.py` `contextual_residual_scan`
- **impact:** Some contextual/statistical categories could pass the sanitized
  payload without a residual backstop, weakening the "exact residual validation"
  guarantee for those categories.
- **scope/preconditions:** Behavior-sensitive; affects residual-scan recall and
  FP rate. Requires benchmarking.
- **recommended fix:** Add a residual backstop pass for the uncovered
  contextual/statistical categories, gated behind `contextual_residual_scan`,
  with before/after benchmark to confirm recall gains without unacceptable FP
  increases.
- **acceptance criteria:**
  - Residual scan covers the previously uncovered categories.
  - Benchmark shows improved recall with bounded FP change.
- **validation/tests:**
  - Privacy corpus residual cases for the new categories.
  - Before/after `securedact_eval quality` runs.
- **dependencies:** none; measure first.

### ROAD-105 — arbitrary bracketed user text may trigger `residual_validation_failed`

- **status:** open
- **severity:** low-to-medium (false-positive/usability; behavior-sensitive)
- **implementation risk:** moderate (distinguishing legitimate pseudonym tokens
  from user-typed bracketed text is ambiguous).
- **evidence:**
  - Pseudonym replacement tokens use the pattern `\[[A-Z][A-Z0-9_]*_\d+\]`
    (`src/securedact_core/models.py:176`).
  - Residual scan inspects the sanitized output for retained/encoded sensitive
    values (`engine.py:669-774`); bracketed tokens resemble the replacement
    format, so arbitrary user text wrapped in brackets could be misread as a
    leaked placeholder or malformed token and fail residual validation.
- **affected files/functions:**
  - `src/securedact_core/engine.py` `scan_residual`
  - `src/securedact_core/models.py` replacement token pattern
- **impact:** Legitimate user content containing bracketed text may be blocked
  as `residual_validation_failed`, reducing usability and causing confusion.
- **scope/preconditions:** Behavior-sensitive; depends on exact residual
  matching rules.
- **recommended fix:** Tighten residual matching to only react to tokens that
  correspond to actual issued placeholders / malformed placeholder patterns,
  not arbitrary bracketed prose. Add tests covering benign bracketed user text.
- **acceptance criteria:**
  - Benign `[...]` user text does not trigger `residual_validation_failed`.
  - Genuine residual leaks / malformed placeholders still fail closed.
- **validation/tests:**
  - New residual-scan test with arbitrary bracketed input.
- **dependencies:** none.

### ROAD-106 — merge precedence can drop the uncovered remainder of an overlapping longer candidate

- **status:** open
- **severity:** medium (recall; behavior-sensitive)
- **implementation risk:** moderate (changing merge must preserve precedence and
  non-overlap guarantees).
- **evidence:**
  - `src/securedact_core/merge.py:79-91` `merge_detections` selects the
    highest-precedence non-overlapping span; if a **longer** candidate overlaps an
    already-selected shorter/higher-precedence candidate, the longer one is
    skipped entirely (`continue` at line 89). Its non-overlapping remainder is
    dropped rather than split out.
  - Precedence values confirm overlap-sensitive ordering
    (`src/securedact_core/merge.py:69`, detectors set explicit `precedence`).
- **affected files/functions:**
  - `src/securedact_core/merge.py` `merge_detections`
  - detector `precedence` fields
- **impact:** A longer sensitive span partially overlapping a higher-precedence
  shorter span can lose its uncovered tail, reducing recall of the tail entity.
- **scope/preconditions:** Behavior-sensitive; only when overlapping candidates
  of differing length/precedence occur.
- **recommended fix:** Split overlapping candidates so the non-overlapping
  remainder of a longer candidate is retained (subject to precedence), or
  explicitly document the winner-take-all behavior as intended. Benchmark
  before/after.
- **acceptance criteria:**
  - Non-overlapping remainders of longer candidates are preserved when
    precedence allows.
  - No new overlaps are introduced; `test_merge.py` order-independence holds.
- **validation/tests:**
  - Extend `tests/unit/test_merge.py` with overlapping-different-length cases.
  - Before/after privacy corpus recall.
- **dependencies:** none; measure first.

---

## 5. P2 — Quality, performance, adoption

- **ROAD-201 — medical condition/medication lexicon expansion.**
  Broaden contextual medical lexicon (conditions, medications) for EN/NL.
  Reference `src/securedact_core/detectors/contextual_detector.py`. Add synthetic
  corpus coverage; benchmark recall/FP.

- **ROAD-202 — email edge cases.**
  Improve email detector edge cases (subaddressing, quoted local parts,
  IDN/display-name confusion, terminal boundaries). Reference
  `src/securedact_core/detectors/regex_detector.py` email rules and
  `tests/unit/test_email_detector.py` (terminal-boundary fix already verified
  correct — do not regress).

- **ROAD-203 — lowercase-name/person handling without Flair.**
  Improve person/name recall when the contextual model (Flair) is absent, using
  deterministic heuristics, without unacceptable FP. Behavior-sensitive.

- **ROAD-204 — optional Flair confidence-floor investigation [SPECULATIVE].**
  Hypothesized: a tunable confidence floor on Flair detections could cut FP.
  Requires measurement before scheduling; not yet confirmed beneficial.

- **ROAD-205 — SANITIZED-result caching.**
  Cache sanitized results for repeated identical inputs within a process to
  reduce latency. Must not cache across distinct policies/sessions; respect
  fail-closed semantics.

- **ROAD-206 — unsupported/ambiguous language routing cost.**
  Measure and reduce cost of language-routing decisions for unsupported or
  ambiguous input; handle conservatively per `SECURITY.md` residual section.

- **ROAD-207 — restoration-vault expiry cleanup.**
  Ensure expired/consumed restoration-vault sessions are reclaimed promptly.
  Reference `src/securedact_core/restoration.py` and vault expiry
  (`SECURITY.md` placeholder/restoration section).

- **ROAD-208 — timeout tuning [SPECULATIVE].**
  Hypothesized: per-tool/inference timeouts could be tuned. Requires profiling;
  local inference has no internal deadline per `SECURITY.md` DoS section.

- **ROAD-209 — Python `>=3.12,<3.13` adoption friction.**
  The strict interpreter bound excludes `3.13+`. Track upstream compatibility to
  reduce adoption friction; do not relax without testing.

- **ROAD-210 — large contextual-model download / first-run friction.**
  First-run model download (consent-based, `securedact-mcp setup`) is heavy.
  Improve progress/UX and document expectations; never download at startup.

- **ROAD-211 — setup auto-detection limited to Claude/Gemini.**
  `setup`/onboarding auto-detects Claude and Gemini hosts
  (`src/securedact_enforced/`). Extend detection to other supported hosts
  (Cursor, Windsurf, Codex) where applicable.

- **ROAD-212 — clearer Claude marketplace/plugin onboarding.**
  Improve Claude Code marketplace/plugin onboarding docs using
  `.claude-plugin/marketplace.json` as the source of truth.

- **ROAD-213 — clearer deterministic-only mode positioning.**
  Document the deterministic-only mode as the reproducible release gate and
  clarify how it relates to Flair/manual evaluation.

---

## 6. P3 — Hardening & cleanup

- **ROAD-301 — generic-geography ALLOW ordering vs explicit BLOCK.**
  Review precedence/ordering when a generic geography rule is ALLOW while a more
  specific entity is BLOCK. Ensure specific blocks win. Reference
  `src/securedact_core/policies.py` action precedence and detectors.

- **ROAD-302 — `reduced_detection_coverage` reason code.**
  Ensure a stable reason code (`reduced_detection_coverage`) is emitted when
  coverage is reduced (e.g. required detector absent but failed closed
  differently). Reference `src/securedact_core/api.py` error codes.

- **ROAD-303 — per-tool unexpected-exception guard.**
  Wrap each MCP tool (`src/securedact_mcp/server.py`) so an unexpected exception
  returns a stable safe error code rather than an unhandled failure; never leak
  content via stderr/stdout.

- **ROAD-304 — `restore_text` invalid-request ambiguity.**
  Disambiguate invalid `restore_text` requests (unknown/expired/malformed handle)
  with distinct stable codes. Reference
  `src/securedact_core/restoration.py` and `server.py` `restore_text`.

- **ROAD-305 — gate legacy redact/restore sensitive modes.**
  Confirm legacy redact/restore sensitive modes are guarded by the same
  fail-closed invariants as the primary path.

- **ROAD-306 — README path/wording fixes.**
  Correct stale paths/wording in `README.md`. Documentation only.

- **ROAD-307 — AGENTS.md path correction.**
  Correct any stale paths in `AGENTS.md`. Documentation only.

- **ROAD-308 — plugin-version drift validation.**
  Validate that plugin/marketplace `version` fields stay in sync with the
  package version (`0.2.1`) in CI; extend `scripts/validate_release_artifacts.py`.

- **ROAD-309 — restoration error normalization.**
  Normalize restoration error descriptions to stable codes/sanitized text across
  hosts.

- **ROAD-310 — restoration-vault expiry docs/sweep.**
  Document vault expiry/sweep behavior and ensure periodic sweep exists.

- **ROAD-311 — performance measurement test coverage.**
  Add/extend tests that assert performance measurement correctness
  (`src/securedact_eval/performance.py`, `tests/evaluation`).

- **ROAD-312 — indirect-disclosure pattern duplication.**
  De-duplicate indirect-disclosure pattern logic shared across detectors/residual
  scan to avoid drift.

- **ROAD-313 — stale `__pycache__` artifact.**
  Ensure build/check tooling ignores or cleans stale `__pycache__` (e.g. under
  `build/`) so artifact validation is not confused. Reference
  `scripts/validate_release_artifacts.py`.

---

## 7. Verified Correct / Do Not Regress

These behaviors were verified as correct and must be preserved by every future
change. They are explicitly captured so cleanup/refactors do not accidentally
weaken them.

- **Claude PreToolUse warmed-runtime reuse** — warmed runtime is reused across
  tool calls (`src/securedact_enforced/claude_runtime.py`); do not rebuild per
  call.
- **daemon timeout/failure fail-closed behavior** — daemon timeout or failure
  blocks rather than degrading privacy.
- **missing/empty `session_id` fail-closed behavior** — requests without a valid
  `session_id` fail closed.
- **malformed daemon-response handling** — malformed daemon responses are
  handled safely and fail closed.
- **nested payload inspection** — nested model payloads are inspected, not
  skipped.
- **Codex enforced integration removed from shipped source/integrations** — the
  removed `integrations/codex-enforced` path is gone (see ROAD-004 for the stale
  marketplace reference that still points at it).
- **Claude/Gemini plugin version intent** — plugin versions track the package
  version (`0.2.1`) per `.claude-plugin/marketplace.json`.
- **email terminal-boundary fix** — email detector respects terminal boundaries
  (verified in `tests/unit/test_email_detector.py`); do not regress.
- **stdout hygiene** — MCP server stdout is reserved for protocol only; no raw
  values/content to stdout (`SECURITY.md` protocol section; `AGENTS.md`).
- **minimal response privacy boundary** — minimal responses never return raw
  sensitive values or mappings.
- **structural residual validation cannot be disabled through policy** —
  `policy_loader._validate_invariants` enforces
  `residual_validation_enabled` and `residual_on_failure == "block"`
  (`src/securedact_core/policy_loader.py:142-149`).
- **no regex-only production fallback when contextual model is required** —
  production fails closed (`privacy_detector_stack_incomplete`) rather than
  silently falling back to regex-only.
- **`strict_external_ai` blocks credentials/special-category data** — verified
  blocking behavior; do not regress.

---

## 8. Disproven / Closed

These theories were investigated and found not to hold. Recorded to prevent
re-litigation.

- **MCP stdout corruption** — not observed; stdout hygiene holds.
- **minimal responses leaking raw values** — disproven; minimal boundary intact.
- **real Flair evaluation running in ordinary CI** — disproven; real Flair runs
  are manual-only by design.
- **residual validation being policy-disableable** — disproven; enforced by
  loader invariants.
- **Claude rebuilding runtime per tool call** — disproven; warmed-runtime reuse
  confirmed.
- **workflows being absent** — disproven; workflows exist and are validated.
- **production silently falling back to regex-only** — disproven; fails closed.
- **`strict_external_ai` failing to block credentials/special-category data** —
  disproven; blocking verified.

---

## 9. Phased execution plan

- **Phase A: P0 privacy/release trust.** ROAD-001, ROAD-002, ROAD-003, ROAD-004.
  Privacy and release-trust fixes; must land before any privacy-readiness
  release.
- **Phase B: low-risk detection/eval.** ROAD-101, ROAD-102. Localized detector
  and gate-coverage fixes with clear regression tests.
- **Phase C: behavior-sensitive detection/merge/residual.** ROAD-103, ROAD-104,
  ROAD-105, ROAD-106. Each requires before/after benchmarking; gate behind
  measurement.
- **Phase D: adoption/performance.** ROAD-201 through ROAD-213 (P2). Non-blocking
  quality/adoption work.
- **Phase E: cleanup/hardening.** ROAD-301 through ROAD-313 (P3). Defensive and
  documentation hygiene.

---

## 10. Exact recommended first implementation batch

Implement in this order as the first batch:

1. **ROAD-001** — keyed/opaque `finding_id` derivation (privacy oracle).
2. **ROAD-002** — add `block_on_unreviewed` to fail-closed loader invariants.
3. **ROAD-003** — fix stale `SECURITY.md` supported-version text.
4. **ROAD-004** — fix stale `.agents/plugins/marketplace.json` Codex path + add
   validator check.
5. **ROAD-101** — Dutch "de patiënt" mojibake recall fix + regression corpus.
6. **ROAD-102** — deterministic high-risk gate password/private_key coverage
   (fixtures/enforcement).

These six items are the highest-trust-impact, lowest-risk-to-correctness changes
and establish the foundation (including gate wiring context for ROAD-103) for
later phases.
