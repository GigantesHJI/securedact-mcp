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
English, Dutch, both, or no contextual model. The selected checkpoint is fetched
directly from its official Hugging Face repository at an immutable revision;
Securedact never redistributes weights.

Before activation, the installer validates the registry identity, exact file
layout, byte size, locally computed SHA-256, compatibility, and an offline Flair
load test. It writes a local integrity manifest and activates atomically. Runtime
re-verifies that manifest and never downloads. If required contextual capability
is unavailable, corrupt, incompatible, or ambiguous in a way that cannot be
handled conservatively, redaction approval is blocked.

With English and Dutch installed, language selection is local. Clear input uses
the matching model; uncertain input is conservatively analyzed by both. With one
model enabled, uncertain language never silently disables contextual analysis.

`SECUREDACT_REQUIRE_FLAIR=0` explicitly permits deterministic and curated
rule-based operation. This mode has reduced statistical coverage.

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
