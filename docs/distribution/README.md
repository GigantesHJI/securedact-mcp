# Distribution & Marketplace Readiness — Checklist

Operating checklist for launching SecuRedact across directories and launch
channels. Repository-side work for this milestone is complete;
**NEEDS HUMAN ACTION** means a maintainer must do something external
(account, submission, asset, or publish). Nothing has been submitted or
published as part of this milestone.

Legend: READY = repo-side complete · PARTIAL = partial repo-side · SUBMITTED /
LISTED = external evidence exists · NEEDS HUMAN ACTION · NEEDS VERIFICATION

| Channel | Repository ready? | Manual action required? | Submission URL / instructions | Assets required | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Official MCP Registry | Yes (`server.json` valid, `2025-12-11` schema) | Yes — `mcp-publisher publish` (GitHub OAuth + PyPI version match) | `mcp-publisher publish` (CLI) | none | NEEDS HUMAN ACTION | Highest leverage: Glama/PulseMCP/Smithery/mcp.so sync downstream. Verify PyPI `securedact-mcp==0.4.2` published. |
| Smithery | Yes (no repo manifest needed) | Yes — connect repo or publish MCPB | smithery.ai/new (repo connect) | none for self-hosted | NEEDS HUMAN ACTION | One-click install needs a hosted HTTP endpoint (not applicable for local-first). Self-hosted/stdio listing possible. No `smithery.yaml` introduced (deprecated for stdio). |
| Glama | Yes (`glama.json` added) | Yes — sign in & claim ownership | glama.ai/mcp/servers → Add MCP Server | logo/icon optional | NEEDS HUMAN ACTION | Auto-crawls GitHub; `glama.json` sets maintainer. Sign in with `GigantesHJI` GitHub account. |
| MCP.so | Yes (`README.md`, `server.json`) | Yes — web form / GitHub issue | mcp.so/submit | demo screenshot (recommended) | NEEDS HUMAN ACTION | Packet: `docs/distribution/mcp-so.md`. |
| AllMCPs | Yes | Yes — web form or `allmcps-server` | allmcps.com (submit) | none | NEEDS HUMAN ACTION | Packet: `docs/distribution/allmcps.md`. Use `info@securedact.com`. |
| Awesome MCP Servers | Yes (`README.md`) | Yes — open PR | github.com/punkpeye/awesome-mcp-servers | none | NEEDS HUMAN ACTION | Packet: `docs/distribution/awesome-mcp-servers.md`. |
| Gemini | Yes (extension + hooks shipped) | Yes — set `gemini-cli-extension` topic + release tag with root manifest | Gallery auto-index | none | NEEDS VERIFICATION | Per `docs/enforced.md`: topic + release whose tag tree contains root manifest. |
| Claude | Yes (plugin + hooks shipped) | No (already integrated) | n/a | none | READY | Enforced hooks validated locally; host load pending. |
| Product Hunt | Packet ready | Yes — assets + launch | producthunt.com/submit | social/hero images | NEEDS HUMAN ACTION | Packet: `docs/distribution/launch/product-hunt.md`. |
| Hacker News | Packet ready | Yes — post Show HN | news.ycombinator.com/submit | none (terminal demo optional) | NEEDS HUMAN ACTION | Packet: `docs/distribution/launch/show-hn.md`. |
| DEV Community | Outline ready | Yes — write & publish article | dev.to/new | diagram optional | NEEDS HUMAN ACTION | Outline: `docs/distribution/launch/dev-community.md`. |
| Reddit | Recommendations ready | Yes — participate & post per subreddit rules | reddit.com | none | NEEDS HUMAN ACTION | Packages: `docs/distribution/launch/reddit.md`. Stagger, disclose authorship. |

## Canonical sources

- `docs/distribution/marketplace-metadata.md` — single source of truth for
  descriptions, tags, install commands.
- `docs/distribution/security-demo.md` + `examples/security-demo/run_demos.py` —
  reproducible synthetic demos.
- `docs/distribution/assets-needed.md` — visual asset gaps.
- `docs/distribution/follow-up.md` — out-of-scope issues discovered.

## Do not

- Do not submit, publish, or push anything yet (per milestone constraints).
- Do not add fake marketplace badges until listings are live.
- Do not describe the commercial desktop app/plans (website) as part of the
  open-source repository.
