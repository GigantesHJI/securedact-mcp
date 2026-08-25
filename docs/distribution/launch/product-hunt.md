# Product Hunt — Launch Package

> Do not invent testimonials, customer counts, adoption figures, or benchmarks.
> The website references a measured "95.89% deterministic F1" on its synthetic
> corpus; if used, attribute it to that synthetic benchmark and caveated as
> "not a guarantee of perfect privacy." Prefer the defensible phrasing below.

## Product name

SecuRedact

## Tagline

Local-first privacy firewall for AI agents

## Short description

Detect and protect PII, secrets, and sensitive files before they reach your AI models, tools, or external destinations — all on your machine.

## Maker comment (first comment)

Hi PH 👋 — I built SecuRedact because every AI agent I ran kept brushing up
against PII, API keys, and local files. SecuRedact is a local-first privacy
layer for AI workflows: it detects and protects sensitive data before it leaves
your machine. It's an Apache-2.0 MCP server (works with Codex, Cursor,
Windsurf, Claude Code, Gemini CLI) plus a reusable Python engine. No telemetry,
no provider calls, fail-closed by default. Keen for feedback from anyone running
agents on sensitive data.

## Key features

- Local PII / GDPR-sensitive data detection and redaction
- Secret, API key, token, and password detection and blocking
- Filesystem protection (traversal/symlink defense, protected-path blocking)
- AI Agent Privacy Firewall via Claude Code and Gemini CLI enforced hooks
- Network/egress destination classification (internal/external/unknown)
- MCP `stdio` server + reusable Python engine; no telemetry, fail-closed

## First comment (additional)

Try it:

```powershell
py -3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

Reproducible synthetic demos: `docs/distribution/security-demo.md`. The
open-source repo is the MCP server + engine; the website also describes a
separate commercial desktop app and plans (not part of this launch).

## Suggested topics / categories

- Developer Tools
- Open Source
- Artificial Intelligence
- Security
- Privacy

## Launch checklist

- [ ] Prepare 1280×640 social image + Product Hunt gallery images
    (see `docs/distribution/assets-needed.md`)
- [ ] Confirm PyPI package is live (`securedact-mcp`)
- [ ] Draft maker comment + first comment (above)
- [ ] Coordinate launch time (PH traffic peaks)
- [ ] Add a "Made by SecuRedact" / first-comment link to repo + docs
- [ ] Prepare to respond to comments within the first few hours

## Suggested screenshots / assets required

1. Architecture / privacy-firewall diagram (before/after data flow)
2. Terminal: `prepare_for_external_ai` turning a fake API key into a blocked
   result or `[API_TOKEN_1]`
3. Claude Code / Gemini CLI enforced-hook screenshot (sanitized prompt)
4. Social preview (1280×640)
5. Product Hunt hero (per PH specs)
