# Installation

## Requirements

- Python `>=3.12,<3.13`
- Internet access during the approved model download only
- Approximately 2.4 GiB free per selected model, plus staging reserve
- Optional: Node.js/npm for MCP Inspector

The normal setup does not require administrator rights, Git Xet, the Hugging
Face CLI, Git, `curl`, `wget`, or a remote PowerShell script.

## Windows quick start

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install "securedact-mcp[ml]"

securedact-mcp install
securedact-mcp models verify
securedact-mcp
```

The last command starts the local `stdio` MCP server and can appear idle while it
waits for Codex or another MCP host. It never downloads models during startup.

For development from this repository:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[ml,dev]"
securedact-mcp install
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
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install "securedact-mcp[ml]"
securedact-mcp install
securedact-mcp models verify
securedact-mcp
```

## Model choice and consent

`securedact-mcp install` immediately offers:

1. English
2. Dutch
3. English and Dutch
4. Continue without contextual models

Every selected model is described before download, and confirmation defaults to
No. Non-interactive downloads require `--accept-upstream-terms`:

```powershell
securedact-mcp install --language english --accept-upstream-terms
securedact-mcp install --language dutch --accept-upstream-terms
securedact-mcp install --language all --accept-upstream-terms
securedact-mcp install --language none
```

Securedact does not redistribute these model weights. During installation, the
selected model is downloaded directly from its official Hugging Face repository
to the user's local Securedact data directory.

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
securedact-mcp models status
securedact-mcp models verify
```

Then configure an MCP host or use MCP Inspector. Do not expect the raw `stdio`
server command to display an interactive interface.
