# AllMCPs — Submission Package

AllMCPs (<https://allmcps.com>) is an open MCP directory. It accepts submissions
through a web form and via the `allmcps-server` MCP, both of which require a
contact email for verification & status updates.

Status: **NEEDS HUMAN ACTION** (manual submission or via `allmcps-server`).
No special repository file is required.

## Ready-to-copy submission fields

| Field | Value |
| --- | --- |
| **Name** | SecuRedact MCP |
| **URL** | https://github.com/GigantesHJI/securedact-mcp |
| **Website URL** | https://www.securedact.com |
| **Description** | Local-first privacy & security for AI agents. Detects and protects PII, secrets, credentials, and sensitive files before they reach models, tools, or external destinations. Apache-2.0 MCP server + Claude/Gemini enforced hooks. |
| **License** | Apache-2.0 |
| **Category** | `security` (or the closest current AllMCPs enum value — confirm at submission) |
| **Tags** | `mcp`, `ai-security`, `privacy`, `pii`, `secret-detection`, `gdpr`, `ai-agents` |
| **Email** | info@securedact.com |
| **Auth type** | none (local stdio server) |
| **Suggested install command** | `securedact-mcp` |
| **Suggested install args** | (none — stdio entry point) |
| **Support URL** | https://github.com/GigantesHJI/securedact-mcp/issues |
| **Compatible clients** | claude-code, gemini-cli, cursor, codex, windsurf (via MCP registry) |

## Ownership / verification

AllMCPs verifies ownership via a GitHub README badge, a website badge, or a DNS
TXT record. Options for the maintainer:

1. Submit with the email above; the response returns a `claim_url` and a
   ready-to-paste `badge_markdown` snippet. Adding that badge to the README
   verifies the listing instantly instead of waiting on manual review.
2. Or verify later through the AllMCPs web UI.

> The `info@securedact.com` address is the project's public security/privacy
> contact already referenced in `SECURITY.md`. If a different project contact is
> preferred, replace it before submitting.

## Notes

- Do **not** hard-code a personal maintainer email; `info@securedact.com` is the
  only public project contact present in the repository.
- Confirm the `category` enum value against AllMCPs' current list at submission
  time (fields are dropped, not rejected, if unrecognized).
