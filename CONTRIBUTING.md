# Contributing to Securedact MCP

Thank you for helping improve Securedact MCP. Privacy and accuracy take
precedence over feature velocity.

## Repository boundary

This repository contains the standalone MCP adapter and provider-independent
privacy engine imported from the tested Securedact source. Keep it independent
from desktop, Tauri, FastAPI gateway, provider, and website code.

## Before opening a change

1. Open an issue for substantial architecture or tool-contract changes.
2. Use only synthetic data in code, tests, examples, issues, and pull requests.
3. Never include model checkpoints, logs, mappings, credentials, or local data.
4. Preserve fail-closed behavior and the host-invocation limitation.
5. Update `CHANGELOG.md` under `Unreleased`.

## Development setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Required checks

```powershell
python scripts\validate_repo.py
python -m ruff format --check .
python -m ruff check .
python -m mypy src\securedact_mcp scripts
python -m pytest
python scripts\run_privacy_tests.py
python -m build
python -m twine check dist\*
```

## Privacy-sensitive changes

Changes to detectors, policies, merging, redaction, residual checks, mappings,
model loading, safe-copy behavior, tool schemas, or result status require:

- focused synthetic unit tests;
- end-to-end MCP tests where the tool contract changes;
- privacy-corpus evaluation;
- documentation and threat-model updates;
- an explanation of whether false negatives or raw-value exposure can increase.

Do not create a second independent copy of privacy logic.

## Pull requests

Keep changes focused. Explain privacy impact, threat-model impact, validation
performed, and remaining limitations. All checks must pass before merge. Do not
merge directly to `main`.

## Security reports

Do not disclose suspected vulnerabilities in public issues. Follow
[SECURITY.md](SECURITY.md).

