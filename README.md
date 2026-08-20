# Securedact MCP

<!-- mcp-name: io.github.GigantesHJI/securedact-mcp -->

Securedact MCP is an Apache-2.0 local MCP server and reusable Python privacy
engine. It detects sensitive text, applies versioned policies, redacts locally,
and validates residual output before marking sanitized content approved.

> MCP mode does not automatically intercept every prompt. The host must invoke
> the tool and send only `sanitized_text` when `status == "ok"`; a misconfigured
> or malicious MCP host can bypass that ordinary MCP workflow. Provider-native
> enforced hooks are separate integration assets: when a supported provider
> invokes such a hook at its prompt lifecycle boundary, it can apply the same
> deterministic decision before normal model processing. See [SecuRedact
> Enforced](docs/enforced.md).

## Safe default workflow

Use `prepare_for_external_ai` for normal external-AI preparation:

```json
{
  "text": "Contact alex@example.test",
  "policy": "strict_external_ai",
  "language": "auto",
  "response_mode": "minimal"
}
```

Approved response:

```json
{
  "schema_version": "1",
  "status": "ok",
  "sanitized_text": "Contact [EMAIL_1]",
  "counts": {"email": 1},
  "policy": "strict_external_ai",
  "policy_version": 1,
  "policy_digest": "...",
  "reason_codes": []
}
```

`review_required` and `blocked` responses never contain approved
`sanitized_text`. Minimal responses contain no original text, raw entity values,
mapping, exception body, stack trace, model path, or restoration handle unless
`restore_capable` was explicitly selected.

## Architecture and trust boundary

```mermaid
flowchart LR
    H["MCP host"] --> M["Securedact MCP"]
    M --> D["deterministic detectors"]
    M --> C["contextual detectors"]
    D --> P["policy engine"]
    C --> P
    P --> R["redactor"]
    R --> V["residual validator"]
    V --> O["approved sanitized output"]
    O --> W["host-controlled downstream workflow"]
    H -. "host may bypass MCP" .-> W
```

The server has no provider clients, OpenAI-compatible proxy, reverse proxy,
website, desktop chatbot, provider credentials, or provider-specific forwarding.
See [ADR 0001](docs/adr/0001-mcp-server-product-boundary.md) and the
[threat model](docs/threat-model.md).

## Tools

| Tool | Intended use | Sensitive-response behavior |
|---|---|---|
| `prepare_for_external_ai` | Recommended complete safe workflow | Minimal by default |
| `analyze_text` | Lower-level local analysis/review | Minimal; offsets in `review`; raw values only in enabled debug mode |
| `redact_text` | Lower-level compatibility operation | Minimal by default; explicit `legacy` mode is sensitive and deprecated |
| `restore_text` | Consume a local opaque session | Single-use by default; direct mappings require explicit trusted legacy mode |
| `create_safe_copy` | Write approved `.txt`/`.md` content under one configured root | Returns no mapping or absolute path |

Response modes are `minimal`, `review`, `debug`, and `restore_capable`. Debug is
disabled unless the process was started with
`SECUREDACT_ENABLE_DEBUG_RESPONSES=1`; an MCP request cannot enable it. In-memory
restoration sessions use cryptographic random handles, bounded capacity,
expiration, concurrency protection, and single-use consumption. Process exit
destroys all sessions.

See [MCP tools](docs/mcp-tools.md), [response privacy](docs/privacy-model.md), and
[restoration sessions](docs/restoration-sessions.md).

## Installation

Python `>=3.12,<3.13` is supported.

For a normal installation from PyPI:

```powershell
py -3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

On Linux or macOS, use `python3.12 -m pip install "securedact-mcp[ml]"`;
`python -m pip install "securedact-mcp[ml]"` is also appropriate when `python`
already selects a supported 3.12 environment.

`setup` checks the package, Python and ML dependencies, inspects local model
state, offers the existing consent-based model installer, runs the existing
offline verifier, and offers the packaged Claude Code and Gemini CLI
integrations when those hosts are detected. It uses the providers' official
plugin/extension commands and is safe to rerun. It does not call a provider
model API, accept provider trust automatically, or download a contextual model
unless the user explicitly selects model setup and accepts the existing
upstream prompt.

Manual model commands remain available for advanced or unattended operation:

```powershell
securedact-mcp install
securedact-mcp models verify
securedact-mcp
```

The last command starts a local `stdio` server. Standard output is reserved for
MCP protocol messages. `securedact-mcp setup --non-interactive` reports state
without implying upstream acceptance or configuring a new provider. Use
`--host claude`, `--host gemini`, or `--host all` for targeted interactive
provider setup.

### Developer/source installation

To work from a reviewed source checkout instead:

```powershell
git clone https://github.com/GigantesHJI/securedact-mcp.git
cd securedact-mcp
python -m pip install ".[ml]"
securedact-mcp setup
```

No model checkpoint is included in the repository or wheel, and startup never
downloads one. Securedact does not redistribute these model weights. Upstream
model weights retain their own licenses and are not relicensed by Apache-2.0.
See [model installation](docs/model-installation.md) and [third-party
licenses](docs/third-party-licenses.md).

Deterministic-only local development must be explicitly selected:

```powershell
$env:SECUREDACT_REQUIRE_FLAIR = "0"
securedact-mcp
```

Production defaults to requiring contextual capability and fails closed while a
configured model is missing, loading, corrupt, or unavailable.

## Host packages

Tested configuration assets and safe-workflow instructions are under
`integrations/` for Codex, Cursor, and Windsurf. The automated MCP client harness
validates server startup, tool listing, calls, minimal response shape, stdout
integrity, and shutdown. It does not prove that a real host invokes the tool for
every prompt. See the [compatibility evidence](docs/compatibility.md).

The repository is also a Gemini CLI extension root: `gemini extensions install
https://github.com/GigantesHJI/securedact-mcp` can install the hooks. The
`gemini-cli-extension` topic and a release whose tag tree contains the root
manifest are required for that path to resolve; without `pip install
"securedact-mcp[ml]"` and the local models the installed hooks do not enforce
anything. See [SecuRedact Enforced](docs/enforced.md).

## Policies and Python API

Built-ins include `default`, `strict_external_ai`, `gdpr`, `identifiers_only`,
and `review_all_contextual`; compatibility policies remain available. Local
organization policy files load only from the controlled policy directory, use a
strict declarative schema, and cannot disable fail-closed invariants. Unknown,
duplicate, oversized, malformed, or symlinked policies fail closed.

```python
from securedact_core import RedactionRequest, SecuredactEngine

engine = SecuredactEngine.from_environment()
result = engine.prepare(
    RedactionRequest(
        text="Contact alex@example.test",
        policy="strict_external_ai",
    )
)
```

`from_environment()` preserves the contextual-model requirement. Standalone
deterministic development requires `SECUREDACT_REQUIRE_FLAIR=0`; applications may
also inject tested detector implementations. See [public API](docs/public-api.md)
and [policies](docs/policies.md).

## Reproducible development

The committed `uv.lock` resolves runtime, ML, development, benchmark, and
security extras for Python 3.12.

```powershell
uv sync --frozen --extra dev --extra benchmark
uv run python scripts\verify.py
```

Never use real personal information, private documents, credentials, customer
logs, or model weights in tests, issues, screenshots, fixtures, or pull requests.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Evaluation and performance

```powershell
uv run python -m securedact_eval quality --mode deterministic --gate `
  --thresholds benchmarks\thresholds.json `
  --baseline benchmarks\baselines\quality-deterministic.json
uv run python -m securedact_eval performance --mode deterministic
```

The versioned synthetic corpus reports exact and relaxed span precision, recall,
F1, false-positive and false-negative rates, per-entity/language/domain/split
results, action/category accuracy, and bootstrap recall intervals. True negatives
are document-level negative examples, not token-level safety. The GDPR-related
suite is detection evaluation, not legal compliance certification. Real Flair
and GPU benchmarks require an explicitly configured local model and are not
ordinary CI. See [benchmarking](docs/benchmarking.md).
The [benchmark framework](benchmarks/README.md) documents local data tiers and large profiles;
the [migration plan](docs/benchmark-migration.md) defines its future extraction boundary. For a
failure before GitHub executes repository steps, use the
[CI troubleshooting decision tree](docs/ci-troubleshooting.md). Local success does not replace a
required GitHub check.

## Security and limitations

- No prompt, finding, mapping, restoration handle, secret, model input, or
  restored output is logged by application code.
- Deterministic and contextual detection can miss novel, ambiguous, or
  adversarial disclosure; coreference and universal obfuscation resistance are
  not claimed.
- Review offsets let a trusted local client with the original input reconstruct
  a value; keep review responses local.
- Host behavior and downstream provider behavior are outside the trust boundary.
- Repository security settings documented in files still require administrator
  verification.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md). Do not put
vulnerability details or real data in a public issue.

## License

Original repository source and documentation are licensed under the
[Apache License 2.0](LICENSE.md). Copyright attribution is recorded in
[NOTICE](NOTICE). Third-party dependencies and model weights retain their own
licenses.
