# Windsurf MCP integration

Status: template parsing and MCP protocol harness tested on 2026-08-06; the
Windsurf host application itself was not installed in automated tests.

Copy `mcp_config.json` to the MCP configuration location supported by your
Windsurf version. Replace `<ABSOLUTE_PATH_TO_PYTHON>` with the absolute
interpreter path from the Securedact environment. Organization allowlists may
also control MCP availability.

Expected tools are `prepare_for_external_ai`, `analyze_text`, `redact_text`,
`restore_text`, `create_safe_copy`, and `securedact_read_file`.

Persistent workflow instructions should require:

1. Call `prepare_for_external_ai` before potentially sensitive text enters an
   external workflow.
2. Continue only for `status == "ok"` and pass only `sanitized_text`.
3. Never copy the original text downstream.
4. Stop and request trusted local review for `review_required`; stop for
   `blocked`.
5. Never request debug or legacy mapping responses in ordinary workflows.

Synthetic request: `{"text":"Contact alex.windsurf@example.test"}`. Expect an
approved `Contact [EMAIL_1]` and no source value or mapping.

If startup fails, verify the absolute path and run `securedact-mcp diagnostics
runtime`. Keep all diagnostics synthetic. A configured MCP server cannot force
host routing and cannot guarantee that every prompt is intercepted.
