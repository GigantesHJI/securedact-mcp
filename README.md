# Securedact MCP

Securedact MCP is a local-first privacy layer for MCP-compatible AI workflows.
It detects, reviews, redacts, and audits sensitive information before approved
sanitized content is used downstream.

> **Important:** Securedact MCP does not automatically intercept every prompt.
> The MCP host must be configured to invoke Securedact and use only approved
> sanitized output.

## What it does

- Runs locally as an MCP `stdio` server.
- Detects deterministic identifiers and contextual sensitive information.
- Applies named privacy policies.
- Returns explicit `ok`, `review_required`, or `blocked` outcomes.
- Replaces detected values with stable typed placeholders.
- Performs residual validation over proposed sanitized text.
- Restores caller-supplied placeholder mappings locally.
- Creates sanitized `.txt` or `.md` copies inside one configured local directory.
- Installs an explicitly selected English and/or Dutch Flair model directly from
  its official Hugging Face repository, then loads it locally in offline mode.
- Fails closed when required contextual capability is unavailable or corrupt.

## What it does not do

- It is not an AI model, chatbot, desktop application, or provider gateway.
- It does not include Tauri, a website, provider clients, or telemetry.
- It does not silently proxy all host prompts.
- It does not guarantee detection of every possible sensitive disclosure.
- It does not send prompts to OpenAI, Anthropic, Gemini, or another provider.
- It does not store restoration sessions; the caller supplies the mapping to
  `restore_text` and must protect it.
- It does not support arbitrary files or unrestricted filesystem access.

## Privacy model

The recommended workflow is:

```text
input
  -> analyze_text
  -> policy decision / human review
  -> redact_text
  -> confirm status == "ok"
  -> use sanitized_text only
  -> downstream AI workflow
```

`redact_text` runs local analysis, policy enforcement, replacement, and residual
validation before returning `status: "ok"`. Review-required and blocked results
do not include an approved `sanitized_text`.

The host remains responsible for invoking the workflow and discarding the raw
input before downstream use. See [Privacy model](docs/privacy-model.md) and
[Threat model](docs/threat-model.md).

## Available MCP tools

| Tool | Purpose | Local state or I/O |
|---|---|---|
| `analyze_text` | Detect and classify sensitive spans locally | No provider or file I/O |
| `redact_text` | Apply policy, redact, and residual-check text | Returns a caller-protected mapping |
| `restore_text` | Restore placeholders from a supplied mapping | No server-side mapping storage |
| `create_safe_copy` | Sanitize and write a `.txt` or `.md` file | Restricted to `SECUREDACT_SAFE_COPY_DIR` |

Exact schemas, output shapes, failures, privacy behavior, and synthetic examples
are documented in [MCP tools](docs/mcp-tools.md).

## Quick start

Python 3.12 is required.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install "securedact-mcp[ml]"

securedact-mcp install
securedact-mcp models verify
securedact-mcp
```

`securedact-mcp install` offers English, Dutch, both, or no contextual model and
downloads an approved selection directly from the official Hugging Face
repository. Every large third-party download requires explicit consent and is
verified before atomic activation.

The final command starts a `stdio` server. It may appear idle while waiting for
Codex or another MCP host; it is not a chat UI and never downloads at startup.

For a source checkout, use `python -m pip install -e ".[ml,dev]"`. On Windows,
`.\scripts\install-securedact-mcp.ps1` provides the same package-plus-model
setup as one guided local flow.

## Requirements

- Python `>=3.12,<3.13`
- Runtime: MCP Python SDK, Pydantic v2, and Cryptography
- Production model setup: Flair, PyTorch, and `huggingface_hub` via `ml`
- Approximately 2.4 GiB free per selected model, plus staging reserve
- A local, integrity-validated Flair model for secure contextual operation

No model checkpoint is included in this repository or any Python distribution.
Securedact does not redistribute these model weights. During installation, the
selected model is downloaded directly from its official Hugging Face repository
to the user's local Securedact data directory.

## Installation

Production installation:

```powershell
python -m pip install "securedact-mcp[ml]"
securedact-mcp install
```

Non-interactive examples:

```powershell
securedact-mcp install --language english --accept-upstream-terms
securedact-mcp install --language dutch --accept-upstream-terms
securedact-mcp install --language all --accept-upstream-terms
securedact-mcp install --language none
```

Development environment:

```powershell
python -m pip install -e ".[ml,dev]"
securedact-mcp install
```

See [Installation](docs/installation.md) and
[Model installation](docs/model-installation.md) for consent, pinned revisions,
storage, integrity, offline operation, licensing uncertainty, and recovery.

Model lifecycle commands:

```text
securedact-mcp models list
securedact-mcp models status
securedact-mcp models verify
securedact-mcp models path
securedact-mcp models update english|dutch
securedact-mcp models remove english|dutch
```

Updates install only the immutable revision in the Securedact registry; they do
not follow an upstream `main` branch or arbitrary latest version.

## Running locally

Installed console entry point:

```powershell
securedact-mcp
```

Equivalent module entry point:

```powershell
python -m securedact_mcp
```

The initial transport is local `stdio`. Standard output is reserved for MCP
protocol messages. Do not wrap the process with scripts that print to stdout.

Supported environment variables:

| Variable | Meaning |
|---|---|
| `SECUREDACT_REQUIRE_FLAIR` | `1` by default; `0` explicitly permits deterministic/rule-based mode |
| `SECUREDACT_MODEL_DIR` | Absolute managed-model location override, subject to path restrictions |
| `SECUREDACT_MODEL_PATH` | Development-only path to a local model |
| `SECUREDACT_SAFE_COPY_DIR` | Required root for `create_safe_copy` |
| `SECUREDACT_MAX_TEXT_CHARS` | Input limit, clamped to `1..1,000,000` |

Legacy development overrides remain available for tested local fixtures. Normal
production setup uses the managed registry and configuration. Hugging Face and
Transformers are forced into offline, telemetry-disabled mode at runtime.

## Testing with MCP Inspector

After a guided model installation:

```powershell
npx @modelcontextprotocol/inspector .\.venv\Scripts\securedact-mcp.exe
```

Use only synthetic input. Verify the four registered tools, invalid parameters,
review and block outcomes, and sanitized output. See
[Testing](docs/testing.md#mcp-inspector).

## Codex setup

Copy and adapt [examples/codex-config.toml](examples/codex-config.toml). It uses
an absolute Windows interpreter path, local `stdio`, and `required = true`.

`required = true` makes Codex fail startup or resume if the server cannot
initialize. It does **not** force every prompt through `analyze_text` or
`redact_text`. Add workflow guidance requiring:

```text
analyze -> policy decision -> redact -> check status -> sanitized output only
```

See [Codex setup](docs/codex.md).

## Cursor setup

Copy [examples/cursor-mcp.json](examples/cursor-mcp.json) into the configuration
location supported by your Cursor version and replace `<USERNAME>`. Windows
paths in JSON use escaped backslashes.

See [Cursor setup](docs/cursor.md). MCP availability does not prove workflow
enforcement.

## Windsurf setup

Copy [examples/windsurf-mcp.json](examples/windsurf-mcp.json) into the
`mcp_config.json` location supported by your Windsurf version and replace
`<USERNAME>`.

See [Windsurf setup](docs/windsurf.md). Organization allowlists may also apply.

## Example synthetic test

Request:

```json
{
  "text": "Contact alex.example@example.test twice: alex.example@example.test",
  "policy": "default"
}
```

Representative `redact_text` response:

```json
{
  "status": "ok",
  "sanitized_text": "Contact [EMAIL_1] twice: [EMAIL_1]",
  "mapping": {
    "[EMAIL_1]": "alex.example@example.test"
  },
  "entities": [
    {
      "entity_type": "email",
      "text": "alex.example@example.test",
      "source": "regex",
      "action": "redact"
    }
  ],
  "entity_counts": {
    "email": 2
  }
}
```

The real response contains complete detection metadata for both spans. The
mapping and entity details contain sensitive values and must remain local.
Additional fixtures are in
[synthetic-test-prompts.md](examples/synthetic-test-prompts.md).

## Security model

- Local `stdio`; no listener or provider client.
- Consent-based direct downloads from two allowlisted official repositories.
- Immutable revisions, pinned sizes/hashes, local manifests, offline load tests,
  atomic activation, and rollback-safe failures.
- Offline model loading with telemetry disabled.
- Default fail-closed model requirement.
- Explicit policy outcomes.
- Residual scanning before approved sanitized output.
- Safe-copy basename, extension, configured-root, and no-overwrite controls.
- Size-limited text input.
- No application logging of prompts, findings, mappings, keys, or responses.

See [SECURITY.md](SECURITY.md) and [Threat model](docs/threat-model.md).

## Privacy guarantees and limitations

For the implemented tool boundary:

- analysis, policy evaluation, redaction, audit, and restoration run locally;
- no tool calls an AI provider;
- `redact_text` does not return approved sanitized output when review is required,
  policy blocks content, residual validation fails, or the required model is
  unavailable;
- `create_safe_copy` writes only `.txt` and `.md` basenames inside its configured
  root and does not overwrite existing files;
- repeated values use stable typed placeholders within one redaction result;
- unknown placeholders remain unchanged during restoration.

Limitations:

- The MCP host can bypass or misuse tools.
- Contextual and statistical detection can miss novel or ambiguous disclosures.
- Current contextual rules focus on English and Dutch.
- `analyze_text` and successful `redact_text` metadata include detected raw
  values for local review.
- Redaction mappings are returned to and managed by the caller; there is no
  server-side session vault.
- Safe-copy supports text and Markdown content supplied as strings, not arbitrary
  file parsing.
- Development mode without Flair has reduced statistical coverage.
- Both upstream repositories currently lack a clear separate model-weight
  license identifier; citation does not provide license permission.
- The release corpus measures known synthetic cases, not universal safety.

## Development

```powershell
python -m pip install -e ".[ml,dev]"
python scripts\validate_repo.py
python -m ruff format --check .
python -m ruff check .
python -m mypy src\securedact_core src\securedact_mcp scripts
python -m pytest
python scripts\run_privacy_tests.py
```

Read [CONTRIBUTING.md](CONTRIBUTING.md). Do not add desktop, Tauri, website,
provider-gateway, model checkpoint, telemetry, real-data, or unrestricted
filesystem code.

## Testing

The synthetic suite covers:

- privacy-engine regex, contextual assertions, policies, merge, replacement,
  restoration, model integrity, storage, and corpus evaluation;
- MCP startup and exact tool registration;
- each implemented tool;
- malformed requests and stdout integrity;
- review, block, and fail-closed model behavior;
- repeated placeholders and unknown placeholders;
- safe-copy configuration, traversal, extension, sanitized writes, and
  no-overwrite behavior;
- property-based identifier and fuzz cases;
- an end-to-end MCP client session over `stdio`.

No live provider key or network call is required. Model setup and model-load
integration tests use tiny mocked checkpoints; CI never downloads real weights.

## Release verification

The release workflow:

1. runs repository, format, lint, type, unit, integration, and privacy checks;
2. builds a source distribution and wheel;
3. validates metadata;
4. inspects artifact contents for forbidden data and model files;
5. installs the wheel in a clean environment;
6. smoke-tests the console entry point;
7. attaches artifacts to a GitHub release;
8. never publishes to PyPI.

See [Release process](docs/release.md).

## Roadmap

- Add more languages and calibrated contextual models.
- Add a hardened manual-import command for separately downloaded official
  snapshots.
- Add richer local review/session workflows without exposing mappings.
- Expand supported safe document formats only after hardened parsers and tests.
- Verify additional MCP host versions and publish compatibility evidence.

Roadmap items are not current functionality.

## Website alignment

`securedact.com` should link to this repository using:

> Protect sensitive data in AI coding workflows.

The website should repeat that the host must invoke Securedact and use only
approved sanitized output. No website code belongs in this repository.

Recommended repository description:

> Local-first privacy MCP server that analyzes, reviews, and redacts sensitive
> data before AI workflows process it.

Suggested topics: `mcp`, `model-context-protocol`, `privacy`, `pii`, `gdpr`,
`data-redaction`, `ai-security`, `local-first`, `codex`, `cursor`, `windsurf`.

## License

This standalone repository currently uses an interim proprietary,
all-rights-reserved license while the owner completes commercial and legal
review. It is not presented as open source. See [LICENSE.md](LICENSE.md).

## Security reporting

Do not file public issues for vulnerabilities or accidental data exposure.
Follow [SECURITY.md](SECURITY.md) and report privately to
`security@securedact.com`. Confirm that this role address is actively monitored
before public release.
