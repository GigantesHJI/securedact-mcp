# MCP tools

The local `stdio` server registers five tools. None calls an AI provider.

## `prepare_for_external_ai`

Recommended complete workflow. Input:

```json
{
  "text": "Contact alex@example.test",
  "policy": "strict_external_ai",
  "language": "auto",
  "response_mode": "minimal"
}
```

Approved minimal result:

```json
{
  "schema_version": "1",
  "status": "ok",
  "policy": "strict_external_ai",
  "policy_version": 1,
  "policy_digest": "<sha256>",
  "counts": {"email": 1},
  "sanitized_text": "Contact [EMAIL_1]"
}
```

`review_required` and `blocked` results contain `reason_codes` and no
`sanitized_text`. Runtime compatibility may also include a non-sensitive
`failure_code` equal to the primary reason code.

Response modes:

- `minimal` is the default and returns no raw values or mappings.
- `review` adds offsets, type, action, confidence, source, and reason code; it
  does not copy the detected substring.
- `restore_capable` stores the mapping locally and returns an opaque,
  single-use `restoration_session` on success.
- `debug` may contain raw detector details and works only when the server was
  started with `SECUREDACT_ENABLE_DEBUG_RESPONSES=1`.

## `analyze_text`

Lower-level local analysis for review integrations. It accepts `text`, `policy`,
and `response_mode` (`minimal`, `review`, or process-gated `debug`). Minimal
output contains only status and aggregate counts. Prefer the high-level tool
when preparing content for external use.

## `redact_text`

Lower-level compatibility operation. It accepts `text`, `policy`, and
`response_mode`. Minimal behavior follows the high-level safe response contract.
An explicit `response_mode: "legacy"` returns raw entities and a mapping, is
sensitive, and includes a deprecation code. Do not forward that response.

## `restore_text`

Preferred input consumes a session created by `restore_capable`:

```json
{"text": "Contact [EMAIL_1]", "restoration_session": "<opaque handle>"}
```

Success returns `status: "ok"` and `restored_text`. A malformed, unknown,
expired, or consumed handle returns a stable blocked reason code. Sessions are
single-use. Direct mappings remain only for migration and require both a
mapping and `trusted_local_review: true`; that result contains a deprecation
code. Unknown placeholders are left unchanged.

## `create_safe_copy`

Input contains `content`, a `.txt` or `.md` basename, and an optional policy
(default `strict_external_ai`). The tool prepares the content using the safe
minimal workflow and creates it under `SECUREDACT_SAFE_COPY_DIR` without
overwrite. Success returns status, filename, and aggregate counts—never a
mapping or absolute path.

## Failure and size behavior

Text is bounded by `SECUREDACT_MAX_TEXT_CHARS`, defaulting to and clamped at
1,000,000. Invalid requests, unknown policy, invalid local policy files,
required-model loading/failure, incomplete detector stack, review, policy
block, and residual validation use stable non-sensitive codes. Input is not
queued or replayed while the model loads; submit a new call after readiness.

## Host enforcement

Tool registration cannot force invocation. A host must call
`prepare_for_external_ai`, require `status == "ok"`, and copy only
`sanitized_text` into a provider-bound request. See
[Integration compatibility](compatibility.md) and the packages under
`integrations/`.
