# GitHub Repository Metadata Recommendations

These values are set manually on GitHub
(`https://github.com/GigantesHJI/securedact-mcp/settings`). They are not part of
the repository contents, so a maintainer must apply them. Derived from
`docs/distribution/marketplace-metadata.md`.

## Repository description (≤ about 350 chars)

> SecuRedact — local-first privacy & security for AI agents. Detects and protects PII, secrets, credentials, and sensitive files before they reach models, tools, or external destinations. Apache-2.0 MCP server + Claude/Gemini enforced hooks.

## Website

https://www.securedact.com

## Suggested GitHub topics (strongest 8–12)

Use only relevant topics. Recommended set:

1. `mcp` — core protocol, highest relevance.
2. `model-context-protocol` — matches the protocol name exactly.
3. `ai-security` — primary positioning.
4. `ai-agents` — primary audience.
5. `agent-security` — complements ai-security.
6. `privacy` — core benefit.
7. `pii` — core detection capability.
8. `data-protection` — core benefit, GDPR-adjacent.
9. `gdpr` — supported policy profile (detection, not certification).
10. `secret-detection` — core capability.
11. `cybersecurity` — discovery category.
12. `python` — implementation language.

Also consider (lower priority): `data-loss-prevention`, `local-first`,
`gemini-cli`, `claude-code`, `mcp-server`.

Do **not** add generic or spammy topics (e.g., `ai`, `tools`, `open-source`,
`security` as a lone vague tag is acceptable but low signal).

## Other recommended GitHub settings

- **Social preview image:** add a clean 1280×640 image (see
  `docs/distribution/assets-needed.md`). High priority for click-through.
- **About → Topics:** apply the list above.
- **About → Website:** `https://www.securedact.com`
- **Releases:** ensure a tagged release exists (current version `0.4.2`) so
  Gemini extension gallery indexing and PyPI references resolve.
- **Issues / Security:** keep `SECURITY.md` linked via the "Security policy"
  link in repository settings.

## Verification needed

- Confirm the GitHub account/org `GigantesHJI` is the one that will claim
  ownership on Glama and the MCP Registry (GitHub OAuth).
- PyPI package `securedact-mcp` must be published and its version must match
  `server.json` (`0.4.2`) for the official registry to verify ownership.
