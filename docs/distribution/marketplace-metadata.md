# SecuRedact — Marketplace Metadata (canonical source)

This file is the **single source of truth** for marketplace submissions. Every
other distribution document in `docs/distribution/` should be derived from the
values below. Keep descriptions consistent across directories.

> Scope note: these listings describe the **open-source repository**
> `GigantesHJI/securedact-mcp` (the `securedact-mcp` PyPI package and its MCP
> server / enforced hooks). The project website (`securedact.com`) also markets
> a separate commercial desktop application and paid plans. Those are **not**
> part of this repository's open-source scope and should not be described as
> such in directory listings.

## Product name

SecuRedact

(Display / server name used in the registry and package index: **SecuRedact MCP**;
PyPI package: `securedact-mcp`; MCP server id: `io.github.GigantesHJI/securedact-mcp`.)

## One-line tagline

Local-first privacy & security for AI agents — detect and protect PII, secrets, and sensitive files before they reach models, tools, or external destinations.

## 80-character description

Local-first privacy firewall that detects PII, secrets, and sensitive files for AI agents.

## ~160-character description

SecuRedact is a local-first privacy and security layer for AI agents. It detects and protects PII, credentials, API keys, and sensitive files locally, before data reaches models, tools, or external destinations.

## Short description

SecuRedact is a local-first privacy and security layer for AI agents and AI workflows. It detects and protects sensitive data — PII, GDPR-sensitive information, credentials, API keys, tokens, secrets, and sensitive files — before that data reaches models, tools, files, or external destinations. It ships as an Apache-2.0 MCP server plus enforced hooks for Claude Code and Gemini CLI.

## Long description

SecuRedact is a local-first privacy and security layer for AI agents and AI workflows. It runs entirely on your machine and helps reduce exposure of sensitive data before it reaches models, tools, files, or external destinations.

The open-source `securedact-mcp` package provides:

- **PII / GDPR detection** — names, emails, IBANs, identifiers, and special-category data are detected and pseudonymized or redacted under versioned policies (including a `gdpr` profile).
- **Secret & credential protection** — API keys, tokens, and passwords are detected and, under `strict_external_ai`, blocked from leaving your environment.
- **Filesystem protection** — file reads are defended against traversal/symlink/UNC escapes and blocked from protected paths such as `.env` and SSH keys.
- **AI Agent Privacy Firewall** — enforced hooks for Claude Code and Gemini CLI run the same local decision before a prompt, model call, or tool action proceeds.
- **Network / egress awareness** — outbound tool calls are classified (internal / external / unknown) so policy can require approval or block egress.
- **Local-first architecture** — no network listener by default, no telemetry, no provider calls, and fail-closed behavior when required detection capability is unavailable.

SecuRedact is an MCP server (`stdio`) and a reusable Python engine. It integrates with any Model Context Protocol client (Codex, Cursor, Windsurf) via the official MCP registry, and offers enforced mode for Claude Code and Gemini CLI.

SecuRedact helps organizations implement privacy safeguards; it is **not** a guarantee of GDPR compliance or a claim that every data leak is prevented. Detection can miss novel, ambiguous, or adversarial disclosure.

## Primary category

AI Security / Privacy

## Secondary categories

- Developer Tools
- MCP Servers
- Data Privacy
- Cybersecurity
- AI Agents
- Secret Detection
- Data Loss Prevention

## Keywords / tags

`mcp`, `model-context-protocol`, `ai-security`, `ai-agents`, `agent-security`, `privacy`, `pii`, `data-protection`, `gdpr`, `secret-detection`, `cybersecurity`, `python`, `local-first`, `data-loss-prevention`, `ai-privacy`, `credential-protection`, `ai-agent-firewall`

## Repository URL

https://github.com/GigantesHJI/securedact-mcp

## Website URL

https://www.securedact.com

## Documentation URL

https://github.com/GigantesHJI/securedact-mcp/tree/main/docs

## Privacy policy

https://www.securedact.com/privacy

## License

Apache-2.0

## Supported environments

- Python `>=3.12,<3.13` (Windows, Linux, macOS)
- Local `stdio` MCP server
- MCP clients via the official MCP registry: Codex, Cursor, Windsurf
- Enforced hooks: Claude Code, Gemini CLI
- Optional local contextual NER model (English/Dutch), installed only with explicit consent

## Key capabilities

- Local PII / GDPR-sensitive data detection and pseudonymization/redaction
- Secret, API key, token, and password detection and blocking
- Filesystem protection (traversal/symlink defense, protected-path blocking)
- AI Agent Privacy Firewall via Claude Code and Gemini CLI enforced hooks
- Network/egress destination classification (internal/external/unknown)
- Versioned, fail-closed policy engine with residual validation
- MCP tool `prepare_for_external_ai` plus analysis, redaction, restoration, safe-copy, and safe-read tools
- No telemetry, no provider clients, minimal-by-default responses

## Security / privacy positioning

SecuRedact is local-first: detection, policy evaluation, redaction, and audit run on the user's machine. There is no network listener by default, no telemetry, and no provider API calls from the server. Production defaults fail closed when required detection capability is missing, corrupt, or unavailable. Responses are minimal by default and never include raw findings, mappings, or sensitive substrings. Model setup is consent-based and restricted to allowlisted, integrity-checked sources.

## Important limitations

- MCP registration does not force a host to invoke SecuRedact; the host must call the tool and use only `sanitized_text` when `status == "ok"`.
- Detection can miss novel, ambiguous, or adversarial disclosure; it is not a universal guarantee.
- Enforced hooks cover documented provider lifecycle paths only; they do not protect arbitrary subprocess, browser, or unloaded-provider traffic.
- Contextual detection requires a locally installed model by default; model download is consent-based and offline-verified.
- GDPR-related behavior is detection/policy configuration, **not** legal compliance certification.
- The project website describes a separate commercial desktop app and paid plans that are outside this repository's open-source scope.

## Install command(s)

Windows:

```powershell
py -3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

Linux / macOS:

```bash
python3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

## Demo command / example

```python
import os
os.environ["SECUREDACT_REQUIRE_FLAIR"] = "0"  # deterministic-only for a quick demo

from securedact_core import RedactionRequest, SecuredactEngine

engine = SecuredactEngine.from_environment()
result = engine.prepare(
    RedactionRequest(
        text="Contact alex@example.test, IBAN NL91ABNA0417164300",
        policy="strict_external_ai",
    )
)
print(result.status)          # "ok"
print(result.sanitized_text)  # "Contact [EMAIL_1], IBAN [IBAN_1]"
```

## Maintainer / contact

Project contact: `info@securedact.com` (public security/privacy contact listed in `SECURITY.md`).
