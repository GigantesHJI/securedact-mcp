# Codex MCP integration

Status: configuration schema and MCP protocol harness tested on 2026-08-06;
the Codex host application itself was not installed in automated tests.

Copy `config.toml` into the location supported by your Codex version. Replace
`<ABSOLUTE_PATH_TO_PYTHON>` with the absolute interpreter path from the
Securedact environment. Install and verify the configured local model before
starting the host. `required = true` checks server initialization; it does not
force every prompt through a tool.

Expected tools are `prepare_for_external_ai`, `analyze_text`, `redact_text`,
`restore_text`, and `create_safe_copy`.

Persistent workflow instructions should require:

1. Call `prepare_for_external_ai` before potentially sensitive text enters an
   external workflow.
2. Continue only when `status == "ok"`.
3. Use only `sanitized_text`; never copy the original text downstream.
4. Stop and request trusted local review for `review_required`.
5. Stop for `blocked`.
6. Never request debug or legacy mapping responses in ordinary workflows.

Synthetic test request:

```json
{"text":"Contact alex.codex@example.test","policy":"strict_external_ai"}
```

Expected safe shape: `status` is `ok`, `sanitized_text` is
`Contact [EMAIL_1]`, and the original address and mapping are absent.

Troubleshooting: use `securedact-mcp diagnostics runtime` locally and check the
host's MCP tool list. Never paste prompts, mappings, model paths, or credentials
into support reports. A configured MCP server cannot prevent a misconfigured or
malicious host from bypassing it; it cannot guarantee every prompt is
intercepted.
