# Installation

## Requirements

- Python `>=3.12,<3.13`
- Internet access during the approved model download only
- Approximately 2.4 GiB free per selected model, plus staging reserve. English
  and Dutch share one additional 13.51 MiB transformer runtime component.
- Optional: Node.js/npm for MCP Inspector

The normal setup does not require administrator rights, Git Xet, the Hugging
Face CLI, Git, `curl`, `wget`, or a remote PowerShell script.

## Windows quick start

Install from PyPI and run the unified guided setup:

```powershell
py -3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

`setup` reports the installed package, Python and ML dependencies; offers the
existing contextual-model setup and upstream acceptance flow; runs the existing
offline model verifier; detects Claude Code and Gemini CLI; and offers their
official plugin or extension installation. It does not call either provider's
model API.

For development from this repository:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[ml,dev]"
securedact-mcp setup
```

The optional one-flow Windows bootstrap performs these local steps and then
prints a Codex configuration:

```powershell
.\scripts\install-securedact-mcp.ps1
```

Unattended example:

```powershell
.\scripts\install-securedact-mcp.ps1 `
  -Language English `
  -AcceptUpstreamTerms
```

The script creates a user-owned virtual environment, installs the local package
or supplied wheel, invokes the official setup command, verifies the selection,
and runs an entry-point smoke test. It does not change execution policy, run as
administrator, execute remote scripts, or install Git/Hugging Face tools.

## Linux and macOS

```bash
python3.12 -m pip install "securedact-mcp[ml]"
securedact-mcp setup
```

Use `python -m pip install "securedact-mcp[ml]"` when `python` already resolves
to a supported Python 3.12 interpreter.

## What unified setup changes

Interactive `securedact-mcp setup` detects installed supported hosts and asks
before configuring each one. `--host claude`, `--host gemini`, and `--host all`
target the provider step. Setup calls the provider's official CLI; it never
rewrites Claude or Gemini settings directly, stores credentials, bypasses trust
prompts, or invokes a hosted model. Rerunning setup verifies existing active
installations and does not duplicate them.

`securedact-mcp setup --non-interactive` performs deterministic preflight and
readiness inspection only. It does not imply model terms acceptance or provider
trust. A new non-interactive model install requires the existing explicit
combination, for example:

```powershell
securedact-mcp setup --non-interactive --language english --accept-upstream-terms
```

New provider configuration remains interactive. A targeted non-interactive run
reports that requirement and exits safely; an already configured provider is
verified without changes.

## Model choice and consent

When model setup is selected, `securedact-mcp setup` delegates to the same flow
used by `securedact-mcp install`, which offers:

1. English
2. Dutch
3. English and Dutch
4. Continue without contextual models

Every selected model is described before download, and confirmation defaults to
No. There is no setup-specific agreement or acceptance record. Declining leaves
models uninstalled, continues safe host inspection/configuration, and reports
that contextual readiness is incomplete. Setup can be rerun later.

The manual commands remain available. Non-interactive downloads require
`--accept-upstream-terms`:

```powershell
securedact-mcp install --language english --accept-upstream-terms
securedact-mcp install --language dutch --accept-upstream-terms
securedact-mcp install --language all --accept-upstream-terms
securedact-mcp install --language none
```

Securedact does not redistribute these model weights. During installation, the
selected model is downloaded directly from its official Hugging Face repository
to the user's local Securedact data directory. The installer also obtains the
pinned XLM-RoBERTa tokenizer/configuration files from their official repository;
Securedact packages neither the checkpoints nor these runtime files.

Early standalone development installations that already have valid checkpoints
can be completed without redownloading them:

```powershell
securedact-mcp models repair all --accept-upstream-terms
securedact-mcp models verify
```

See [Model installation](model-installation.md) for pinned revisions, sizes,
storage locations, integrity manifests, offline use, updates, removal, recovery,
citations, upstream licensing uncertainty, and manual alternatives.

## Fail-closed behavior

The secure default requires a verified, enabled contextual model. If it is
missing, corrupt, incompatible, disabled, or fails its local load test, tool
results block approval and include a setup command. No network fallback occurs.

For synthetic development tests only:

```powershell
$env:SECUREDACT_REQUIRE_FLAIR = "0"
securedact-mcp
```

This is reduced regex/curated-rule coverage and is not recommended for real
sensitive data. It is never enabled automatically by minimal setup.

## Safe-copy configuration

`create_safe_copy` remains blocked until a local output root is configured:

```powershell
$env:SECUREDACT_SAFE_COPY_DIR = "C:\absolute\path\to\safe-copies"
```

Only sanitized `.txt` and `.md` basenames can be created. Existing files are not
overwritten.

## Verify installation

```powershell
python -c "import securedact_mcp; print(securedact_mcp.__version__)"
securedact-mcp models verify
securedact-mcp models status
```

Then configure an MCP host or use MCP Inspector. Do not expect the raw `stdio`
server command to display an interactive interface.

On a cold start the server responds to MCP initialize before loading Flair.
After the host sends the standard initialized notification, each configured
model is validated and loaded once in the background. Calls made before all
enabled languages are ready return `contextual_model_initializing`; wait and
manually resubmit. Securedact does not retain or replay the rejected input.
