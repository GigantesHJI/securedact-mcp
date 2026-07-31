# MCP Tools

Securedact MCP registers exactly four local tools. None contacts an AI provider.
All examples use synthetic values.

## Shared policy input

Tools that accept `policy` default to `default`. Implemented profiles include:

- `default`
- `gdpr_strict`
- `personal_data`
- `financial_data`
- `medical_data`
- `credentials_and_secrets`
- `business_confidential`
- `special_category_strict`
- `custom`

An unknown policy causes a sanitized MCP tool error.

Text input is limited by `SECUREDACT_MAX_TEXT_CHARS`, which defaults to and is
clamped at a maximum of 1,000,000 characters.

## `analyze_text`

### Purpose

Detect and classify sensitive spans locally without transmitting input.

### Input schema

```json
{
  "text": "string, required",
  "policy": "string, optional, default: default"
}
```

### Output shape

Normal output is an analysis object:

```json
{
  "entities": [
    {
      "id": "stable finding identifier",
      "start": 8,
      "end": 33,
      "text": "alex.example@example.test",
      "entity_type": "email",
      "confidence": 1.0,
      "source": "regex",
      "rule": "email",
      "requires_review": false,
      "context": "Contact ⟦alex.example@example.test⟧",
      "action": "redact",
      "severity": "high",
      "masked_preview": "a••••••••••••••••••••••t",
      "rationale_code": null,
      "precedence": 80
    }
  ],
  "assertions": [],
  "requires_review": false,
  "blocked": false,
  "engine_ready": true,
  "warnings": []
}
```

Oversized input returns:

```json
{
  "status": "blocked",
  "reason": "input exceeds the configured size limit"
}
```

### Failure cases

- missing or malformed parameters: MCP validation error;
- unknown policy: sanitized tool error;
- oversized text: blocked result;
- unavailable required model: `engine_ready` is false and downstream redaction
  approval will fail closed.

### Privacy behavior

Analysis is local and performs no provider or file I/O. Findings intentionally
include raw detected text and local context for review. The host must treat the
result as sensitive and must not forward it to a provider.

### Example call

```json
{
  "text": "Contact alex.example@example.test",
  "policy": "default"
}
```

The response follows the analysis shape above.

## `redact_text`

### Purpose

Analyze text, apply the selected policy, replace approved spans with stable typed
placeholders, and run residual validation before returning approved sanitized
output.

### Input schema

```json
{
  "text": "string, required",
  "policy": "string, optional, default: default"
}
```

### Successful output

```json
{
  "status": "ok",
  "sanitized_text": "Contact [EMAIL_1] twice: [EMAIL_1]",
  "mapping": {
    "[EMAIL_1]": "alex.example@example.test"
  },
  "entities": [
    {
      "entity_type": "email",
      "text": "alex.example@example.test",
      "source": "regex",
      "action": "redact"
    }
  ],
  "entity_counts": {
    "email": 2
  }
}
```

The actual `entities` array contains complete detection metadata for each span.

### Non-success output

Review:

```json
{
  "status": "review_required",
  "entities": [
    {
      "entity_type": "religious_or_philosophical_belief",
      "text": "Example belief",
      "requires_review": true
    }
  ]
}
```

Blocked:

```json
{
  "status": "blocked",
  "reason": "policy blocked content"
}
```

Required model unavailable:

```json
{
  "status": "blocked",
  "reason": "The required English contextual model is not installed.\n\nRun:\nsecuredact-mcp install --language english",
  "failure_code": "contextual_model_not_installed"
}
```

Contextual startup failures include a stable, non-sensitive `failure_code` such
as `contextual_model_load_failed`. The response never includes model paths or
underlying exception text.

Residual validation failure:

```json
{
  "status": "blocked",
  "reason": "residual validation failed"
}
```

### Failure cases

- missing or malformed parameters;
- unknown policy;
- oversized input;
- unresolved review;
- policy block;
- critical residual disclosure;
- unavailable required contextual model.

Only `status: "ok"` includes approved `sanitized_text`.

### Privacy behavior

All processing is local. The response's `mapping` and `entities` contain raw
sensitive values for local restoration and review. They must not be sent
downstream. Use only `sanitized_text` after confirming `status == "ok"`.

### Example call

```json
{
  "text": "Contact alex.example@example.test twice: alex.example@example.test",
  "policy": "default"
}
```

The successful output above demonstrates repeated-placeholder stability.

## `restore_text`

### Purpose

Restore known placeholders using a mapping supplied by the caller.

### Input schema

```json
{
  "text": "string, required",
  "mapping": {
    "[EMAIL_1]": "alex.example@example.test"
  }
}
```

`mapping` is a required string-to-string object.

### Output shape

The output is a plain string:

```json
"Contact alex.example@example.test; [UNKNOWN_9] remains unchanged."
```

### Failure cases

- missing or malformed mapping: MCP validation error;
- oversized text: sanitized tool error;
- unknown placeholders: preserved unchanged.

### Privacy behavior

Restoration is local and has no provider or file I/O. The server does not persist
or isolate mapping sessions: the caller supplies the complete mapping on each
call. Anyone holding a mapping can restore its values, so mappings must be
treated as secrets. Never restore text before sending it downstream.

### Example call

```json
{
  "text": "Contact [EMAIL_1]; [UNKNOWN_9] remains unchanged.",
  "mapping": {
    "[EMAIL_1]": "alex.example@example.test"
  }
}
```

## `create_safe_copy`

### Purpose

Sanitize supplied text and write the approved result as a new `.txt` or `.md`
file inside `SECUREDACT_SAFE_COPY_DIR`.

### Input schema

```json
{
  "content": "string, required",
  "filename": "safe-note.md",
  "policy": "string, optional, default: default"
}
```

`filename` must be a basename. Absolute paths, separators, drive prefixes,
traversal, unsupported extensions, and existing destinations are rejected.

### Successful output

```json
{
  "status": "ok",
  "path": "C:\\SafeCopies\\safe-note.md",
  "entity_counts": {
    "email": 1
  }
}
```

### Failure cases

- safe-copy directory not configured;
- invalid or unsupported filename;
- destination already exists;
- oversized input;
- review-required, blocked, residual-risk, or model-unavailable redaction result;
- local filesystem permission error, returned as an MCP tool error.

### Privacy behavior

The tool writes only sanitized content and does not return a mapping. It creates
the configured root if needed, resolves the final path, requires the target's
parent to equal the resolved root, supports only `.txt` and `.md`, and uses
exclusive creation to prevent overwrite.

The returned local path may itself be operationally sensitive and should not be
sent to an external provider unnecessarily.

### Example call

```json
{
  "content": "Contact alex.example@example.test",
  "filename": "safe-note.md",
  "policy": "default"
}
```

The file content is:

```text
Contact [EMAIL_1]
```

## Host enforcement

Tool registration or required server startup does not automatically route every
prompt through Securedact. Host workflows must inspect status and use only the
approved `sanitized_text` or safe-copy content.
