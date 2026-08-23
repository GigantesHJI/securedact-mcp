# Cursor MCP integration

Status: template parsing and MCP protocol harness tested on 2026-08-06; the
Cursor host application itself was not installed in automated tests.

Copy `mcp.json` to the MCP configuration location supported by your Cursor
version. Replace `<ABSOLUTE_PATH_TO_PYTHON>` with the absolute interpreter path
from the Securedact environment. JSON Windows paths must escape backslashes.

Expected tools are `prepare_for_external_ai`, `analyze_text`, `redact_text`,
`restore_text`, `create_safe_copy`, and `securedact_read_file`.

Add persistent project or agent rules that require:

1. Call `prepare_for_external_ai` before potentially sensitive text enters an
   external workflow.
2. Continue only when `status == "ok"` and use only `sanitized_text`.
3. Never copy original text downstream.
4. Stop and request trusted local review for `review_required`; stop for
   `blocked`.
5. Never request debug or legacy mapping responses in ordinary workflows.

Synthetic request: `{"text":"Contact alex.cursor@example.test"}`. The expected
safe response has `status: "ok"`, `sanitized_text: "Contact [EMAIL_1]"`, and no
original address or mapping.

If tools do not appear, verify the absolute path, run `securedact-mcp models
verify`, and restart the host. Do not include private material in diagnostics.
MCP configuration cannot guarantee that every prompt is intercepted; host
behavior is outside the server trust boundary.
