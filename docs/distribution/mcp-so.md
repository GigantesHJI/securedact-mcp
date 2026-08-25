# MCP.so — Submission Package

mcp.so is a community-driven MCP directory. Submission is a manual web form /
GitHub issue at <https://mcp.so/submit>. It reads the repository `README.md`
(first paragraph, install snippet, `## Tools` table) and `server.json`.

Status: **NEEDS HUMAN ACTION** (manual submission + review). No repository file
is required beyond what already exists (`README.md`, `server.json`).

## Ready-to-copy submission

**Name:** SecuRedact MCP

**Repository / GitHub URL:**
https://github.com/GigantesHJI/securedact-mcp

**Short description (1–2 sentences):**
Local-first privacy & security for AI agents. SecuRedact detects and protects PII, secrets, credentials, and sensitive files before they reach models, tools, or external destinations.

**Category:** Security (or Privacy / Data Protection)

**Tags:** `mcp`, `ai-security`, `privacy`, `pii`, `secret-detection`, `gdpr`, `ai-agents`, `python`

**Key features:**
- Local PII / GDPR-sensitive data detection and redaction/pseudonymization
- Secret, API key, token, and password detection and blocking
- Filesystem protection (traversal/symlink defense, protected-path blocking)
- AI Agent Privacy Firewall via Claude Code and Gemini CLI enforced hooks
- Network/egress destination classification (internal/external/unknown)
- MCP `stdio` server plus a reusable Python privacy engine

**Connection / install information:**

```powershell
py -3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

MCP client config (stdio):

```json
{
  "mcpServers": {
    "securedact": {
      "command": "securedact-mcp",
      "args": []
    }
  }
}
```

**Supported clients:** Any Model Context Protocol client (Codex, Cursor,
Windsurf) via the official MCP registry; enforced mode for Claude Code and
Gemini CLI.

**License:** Apache-2.0

**Privacy policy:** https://www.securedact.com/privacy

**Security notes:** Local-first. No network listener by default, no telemetry,
no provider calls. Production fails closed when required detection capability is
unavailable. MCP registration does not force a host to invoke the tool; the
host must use only `sanitized_text` when `status == "ok"`.

## Notes for the maintainer

- mcp.so re-fetches the README weekly; keep the first paragraph clear and
  keyword-rich (it already is). Do not start the README with a wall of badges.
- mcp.so pulls the first `![](image)` as a demo screenshot. The repository
  currently has **no image**; consider adding one (see
  `docs/distribution/assets-needed.md`) before or after submission.
- Review time is typically minutes (automated parse) to ~2 days (human check).
- After listing, add the mcp.so link to the README only once the listing is
  live (do not add a fake badge — see `docs/distribution/README.md`).
