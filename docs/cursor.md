# Cursor Setup

## Install first

Create a Python 3.12 virtual environment and install Securedact MCP. See
[Installation](installation.md).

## Configuration

Cursor supports custom MCP servers through `mcp.json`, including a project file
at `.cursor/mcp.json` and a user-level configuration. Exact locations and UI may
change by client version.

Copy [`examples/cursor-mcp.json`](../examples/cursor-mcp.json), replace
`<USERNAME>`, and verify the absolute path:

```json
{
  "mcpServers": {
    "securedact": {
      "command": "C:\\Users\\<USERNAME>\\Desktop\\securedact-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "securedact_mcp"]
    }
  }
}
```

Windows paths in JSON require escaped backslashes. Run `securedact-mcp install`
and `securedact-mcp models verify` before starting Cursor.

## Verification

1. Restart Cursor after editing MCP configuration.
2. Inspect the server and confirm the four documented tools.
3. Test only with `examples/synthetic-test-prompts.md`.
4. Confirm review/block results are not treated as approved output.
5. Confirm the agent uses only `sanitized_text` after `status == "ok"`.
6. Test the same command with MCP Inspector if connection fails.

MCP availability does not prove that each prompt was passed through a privacy
tool. Add Cursor project rules requiring the secure workflow and validate them
with synthetic canaries.

## Official reference

See [Cursor's MCP documentation](https://docs.cursor.com/context/model-context-protocol).
Verify configuration locations and supported fields for the installed version.
