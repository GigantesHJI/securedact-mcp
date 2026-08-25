# Show HN: SecuRedact — a local-first privacy firewall for AI agents

> Technical, transparent, non-marketing tone. Optimized for Hacker News
> (Show HN). No exaggeration; state limitations honestly.

## Recommended title

Show HN: SecuRedact – a local-first privacy firewall for AI agents

## Opening paragraph

AI agents increasingly read files, call tools, and send prompts to external
models — which means PII, credentials, and sensitive documents can leak unless
something checks the data first. SecuRedact is an open-source (Apache-2.0),
local-first privacy layer for AI workflows. It detects and protects sensitive
data before it reaches models, tools, files, or external destinations. It runs
entirely on your machine: no network listener by default, no telemetry, no
provider API calls.

## Technical explanation

SecuRedact is an MCP (`stdio`) server plus a reusable Python privacy engine. The
recommended flow is a single tool, `prepare_for_external_ai`, that:

1. validates and bounds the input;
2. runs deterministic credential/identifier detectors and (optionally) a local,
   consent-installed NER model;
3. applies a versioned policy (e.g. `strict_external_ai`, `gdpr`);
4. redacts/pseudonymizes or blocks content;
5. runs exact residual validation before marking output approved.

Responses are minimal by default — no raw findings, mappings, or sensitive
substrings leave the process. Production fails closed when required detection
capability is missing, corrupt, or unavailable.

## Threat model

- **Prompt/PII leakage:** an agent forwards a prompt or document containing
  emails, IBANs, names, etc. to an external model.
- **Secret/credential leakage:** `.env` files, API keys, tokens, and passwords
  are read or sent outbound.
- **Filesystem exposure:** an agent reads protected paths (SSH keys,
  credentials).
- **Egress:** outbound tool calls send sensitive content to external
  destinations.

## Concise architecture

```
User / Agent
     |
     v
 SecuRedact
 ├─ Prompt / PII inspection
 ├─ Secret / credential detection
 ├─ File policy (traversal + protected paths)
 ├─ Tool policy
 └─ Network / egress policy
     |
     v
AI Model / Tool / File / Network destination
```

(Enforced mode: Claude Code and Gemini CLI hooks invoke the same local decision
before a prompt, model call, or tool action proceeds.)

## What is open source

- The `securedact-mcp` package, MCP server, Python engine, and enforced hooks
  (Claude Code, Gemini CLI) are Apache-2.0 on GitHub.
- Deterministic detectors, policy engine, residual validation, safe-read, and
  restoration are all local.
- Model setup is consent-based, allowlisted, and offline-integrity-verified.

(Note: the project website also describes a separate commercial desktop app and
paid plans. This Show HN is about the open-source repository only.)

## Install / test instructions

```powershell
py -3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

Quick deterministic demo (no model needed):

```python
import os
os.environ["SECUREDACT_REQUIRE_FLAIR"] = "0"
from securedact_core import RedactionRequest, SecuredactEngine
engine = SecuredactEngine.from_environment()
r = engine.prepare(RedactionRequest(
    text="Contact alex@example.test, IBAN NL91ABNA0417164300",
    policy="strict_external_ai"))
print(r.status, r.sanitized_text)
```

See `docs/distribution/security-demo.md` for runnable synthetic demos
(secret-in-env block, PII redaction, egress classification, safe file, prompt
redaction).

## Limitations (be honest)

- MCP registration does **not** force a host to invoke SecuRedact; the host must
  call the tool and use only `sanitized_text` when `status == "ok"`.
- Detection can miss novel, ambiguous, or adversarial disclosure. It is not a
  universal guarantee.
- Enforced hooks cover documented provider lifecycle paths only.
- Contextual detection requires a locally installed model by default
  (consent-based install).
- GDPR behavior is detection/policy configuration, **not** legal compliance
  certification.

## Request for feedback

Looking for feedback from people running agents in sensitive environments:
which detectors/policies matter most, what host integrations you need, and
where the fail-closed defaults are too strict or too lenient. Synthetic test
cases welcome.

- Repo: https://github.com/GigantesHJI/securedact-mcp
- Docs: https://github.com/GigantesHJI/securedact-mcp/tree/main/docs
