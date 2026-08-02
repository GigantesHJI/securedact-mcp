# Privacy Model

## Principle

Securedact MCP processes sensitive input locally and returns structured privacy
decisions or policy-approved sanitized content.

MCP does not transparently intercept every prompt. The host client or agent
workflow must invoke Securedact and use only approved sanitized output.

## Secure workflow

```text
analyze_text
  -> apply policy
  -> resolve review or stop on block
  -> redact_text
  -> require status == "ok"
  -> use sanitized_text only
```

Missing, malformed, review-required, blocked, model-unavailable, or residual-risk
results are not approved for downstream use.

## Implemented local boundary

- Detection, assertion analysis, policy evaluation, redaction, residual checks,
  and restoration run in-process.
- The package contains no provider adapter.
- The MCP server opens no network listener.
- The separately invoked installer contacts only registry-approved official
  Hugging Face repositories after consent.
- MCP runtime model libraries are placed in offline, telemetry-disabled mode.
- Standard output is reserved for MCP messages.
- Input length is bounded.

## Results containing raw values

`analyze_text` returns raw detected spans and context for local review.
`redact_text` returns entities and a placeholder mapping in addition to
`sanitized_text`. Those fields remain sensitive.

The host must forward only `sanitized_text` after checking `status == "ok"`.
It must not forward entities, context, mappings, or the original input.

## Placeholder mappings

Repeated identical values receive one stable typed placeholder within a
redaction result. `restore_text` uses only the mapping supplied by the caller;
the MCP server does not retain a server-side session or mapping vault.

Consequences:

- mappings stay under host control;
- unknown placeholders remain unchanged;
- anyone holding a mapping can restore its values;
- the host must isolate, expire, and protect mappings;
- restoration must never happen before provider-bound use.

## Residual disclosure

Before `redact_text` returns an approved result, the engine checks the proposed
sanitized text for exact, normalized, partial, deterministic, URL-decoded,
placeholder, and supported indirect-disclosure risks.

Residual validation reduces risk but cannot prove that every semantic,
transformed, encoded, visual, or indirect disclosure is absent.

## Model behavior

The secure default requires a configured local Flair model. Guided setup offers
English, Dutch, both, or no contextual model. The selected checkpoint and its
shared XLM-RoBERTa tokenizer/configuration component are fetched directly from
their official Hugging Face repositories at immutable revisions; Securedact
never redistributes these artifacts.

Before activation, the installer validates the registry identity, exact file
layout, byte size, locally computed SHA-256, compatibility, and an isolated
fresh-process offline Flair load test. Every runtime file has component-level
provenance in the local integrity manifest. Runtime re-verifies that manifest,
uses only the managed cache, and never downloads. An ambient cache hit is not
installation proof. If required contextual capability is unavailable, corrupt,
incompatible, or ambiguous in a way that cannot be handled conservatively,
redaction approval is blocked.

With English and Dutch installed, language selection is local. Clear input uses
the matching model; uncertain input is conservatively analyzed by both. With one
model enabled, uncertain language never silently disables contextual analysis.

`SECUREDACT_REQUIRE_FLAIR=0` explicitly permits deterministic and curated
rule-based operation. This mode has reduced statistical coverage.

The production engine is built by one shared factory. It requires the validated
regex layer and deterministic contextual-rule layer in addition to any enabled
Flair router. Missing either deterministic component keeps `engine_ready` false
and returns `privacy_detector_stack_incomplete`; a contextual model can never
compensate for a missing email or identifier detector.

Detections are merged without overlapping replacements. Policy-selected full
assertions take precedence, followed by labelled deterministic fields, validated
regex spans, deterministic contextual rules, and Flair. Longer spans and
confidence break ties only within the applicable precedence. Non-overlapping
person and email findings are both retained, and exact duplicates create one
stable placeholder.

`securedact-mcp install --language none` does not automatically enable that
reduced mode. It records the absence of contextual support and the secure runtime
continues to fail closed where contextual detection is required.

## Safe copies

`create_safe_copy` accepts a content string and basename. It does not read an
arbitrary source path. It sanitizes first, then creates a `.txt` or `.md` file
under the configured root without overwrite.

## User and host responsibility

Users and host maintainers must:

- configure and invoke the server locally;
- enforce the secure tool sequence;
- stop on review, block, model, or residual failures;
- prevent raw input from being reused after sanitization;
- protect mappings and analysis results;
- trust and verify software/model dependencies;
- use only synthetic data in tests and public reports.

## Limitations

No detector is universally complete. Risks include ambiguous language, new
identifier formats, unsupported languages, images, archives, encrypted content,
obfuscation, prompt injection, host misuse, and inference from remaining
context. Current curated contextual coverage focuses on English and Dutch.
Release metrics describe a versioned synthetic corpus, not perfect detection.

MCP protocol readiness is intentionally separate from privacy-engine readiness.
Initialize completes before heavyweight model work. Tool calls during validation
or loading return `contextual_model_initializing` and are discarded after that
response; no input queue or automatic replay exists. Full readiness requires all
languages enabled in the active configuration.
