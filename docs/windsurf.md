# Windsurf Setup

## Install first

Create a Python 3.12 virtual environment and install Securedact MCP. See
[Installation](installation.md).

## Configuration

Windsurf documents local MCP servers in `mcp_config.json` using an
`mcpServers` object. Configuration locations and administrative controls may
differ by version or organization policy.

Copy [`examples/windsurf-mcp.json`](../examples/windsurf-mcp.json), replace
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

Run `securedact-mcp install` and `securedact-mcp models verify` before starting
Windsurf.

## Verification

1. Restart Windsurf after changing the configuration.
2. Verify Cascade lists the Securedact server and four documented tools.
3. Test only with synthetic prompts.
4. Require analyze, policy decision, redaction, exact status check, and use of
   only approved sanitized output.
5. Confirm the server separately with MCP Inspector.

An enabled server does not guarantee automatic routing of every prompt.

## Official reference

See
[Windsurf's MCP documentation](https://docs.windsurf.com/windsurf/cascade/mcp).
Verify the current configuration location and organization allowlist policy for
the installed version.
