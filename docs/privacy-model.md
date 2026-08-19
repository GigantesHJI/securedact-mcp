# Privacy model

Securedact processes supplied text locally and returns a policy decision. It is
not a transparent proxy: the MCP host must invoke it, require `status == "ok"`,
and send only `sanitized_text` to an external AI.

```text
raw local text
  -> prepare_for_external_ai(policy="strict_external_ai")
     -> ok/allow: use unchanged sanitized_text only
     -> ok/pseudonymized: use transformed sanitized_text only
     -> review_required: keep everything local and review or stop
     -> blocked: stop
```

Malformed requests, unknown/unsafe policy configuration, unavailable required
detectors, oversized input, policy blocks, unresolved review, and residual risk
all fail closed. Review and blocked results never contain sanitized output.

## Data minimization

The default `minimal` response excludes raw findings, local context, placeholder
mappings, and paths. It contains aggregate category counts and stable reason
codes. `review` adds locations and classification metadata without copying raw
substrings. Process-gated `debug` is intentionally sensitive and must stay in a
trusted local review surface.

Use `restore_capable` only when local restoration is actually needed. Its opaque
single-use handle refers to a short-lived bounded in-memory mapping; the mapping
never appears in the result. Restoration must happen only after the external
workflow has ended and must never be logged or sent to a provider.

## Detection and policy

The production stack combines deterministic credentials, validated identifiers,
curated English/Dutch context rules, and optional local Flair NER. Results are
merged with stable precedence and lexical tie-breakers so detector order cannot
change the outcome. Overlapping spans are resolved once; non-overlapping spans
survive; repeated exact values receive stable typed placeholders within one
result.

Confidence-aware automatic pseudonymization is configured per entity category
and detector source; scores from different detector families are not treated as
one calibrated scale. See [Confidence-aware pseudonymization](confidence-pseudonymization.md).

`strict_external_ai` is the recommended policy. It blocks credentials and GDPR
special-category findings, reviews high-risk ambiguity, redacts accepted direct
identifiers, and runs contextual residual validation. Other profiles support
GDPR-oriented review, identifiers-only workflows, and review of all contextual
findings. A GDPR-related profile is detection behavior, not legal advice or a
compliance certification.

## Residual validation

Before approval, Securedact checks exact, normalized, partial, deterministic,
URL-decoded, placeholder, and supported indirect-disclosure risks. This reduces
risk but cannot prove universal anonymity. New formats, unsupported languages,
images, archives, encrypted content, deliberate obfuscation, prompt injection,
and inference from remaining context remain limitations.

## Local model boundary

The MCP runtime never downloads. Contextual checkpoints are installed only by a
separate explicit command with consent, allowlisted identities, immutable
revisions, exact hashes, offline smoke tests, and atomic activation. Missing or
invalid required coverage blocks approval. `SECUREDACT_REQUIRE_FLAIR=0` is an
explicit reduced-coverage development setting, not the secure default.

## Host responsibilities

- Route every intended external-AI payload through the high-level tool.
- Stop on any result other than `ok`; never reuse the raw input as a fallback.
- Forward only `sanitized_text`, never the complete tool response.
- Keep review/debug/restoration material local and access-controlled.
- Use synthetic data in issues, tests, reports, and support requests.
- Treat benchmark scores as measured coverage of the named corpus and mode,
  not a claim of perfect privacy.
