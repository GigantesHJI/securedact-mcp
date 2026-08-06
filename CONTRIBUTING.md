# Contributing to Securedact MCP

Securedact MCP is an Apache-2.0 open-source project. Privacy, predictable
interfaces, and fail-closed behavior take precedence over feature velocity.

## Repository boundary

This repository contains only the local MCP server and provider-neutral privacy
engine. The separately released enforceable Securedact gateway is not part of
this project. Do not add provider clients, provider request forwarding, a reverse
proxy, chatbot UI, website, desktop client, or claims of universal prompt
interception.

## Data safety

Use synthetic data everywhere: code, tests, fixtures, issues, screenshots, logs,
benchmarks, and pull requests. Never submit private documents, real personal
data, credentials, tokens, mappings, model weights, customer material, or local
paths containing a username. Use reserved examples such as `example.test` and
obviously inactive credential shapes.

## Development setup

Python 3.12 is the supported development version. With `uv` installed:

```powershell
uv sync --frozen --extra dev
uv run python -m pytest
```

For an editable pip environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Real Flair checkpoints are not required for ordinary development or CI. Tests
use tiny local fakes. Installing `[ml]` or downloading a real model is an
explicit local choice; review the upstream terms first.

## Required checks

```powershell
python scripts\validate_repo.py --require-implementation
python -m ruff format --check .
python -m ruff check .
python -m mypy src scripts
python -m pytest
python -m pytest tests\privacy
python -m securedact_eval quality --mode deterministic
python -m build --no-isolation
python -m twine check dist\*
python scripts\validate_release_artifacts.py dist
```

Update `CHANGELOG.md` under `Unreleased` for user-visible changes. Detector,
policy, merge, restoration, response-schema, residual-validation, model-loading,
or safe-copy changes need focused synthetic tests and a threat-model review.

## Contribution sign-off

The project uses the Developer Certificate of Origin 1.1 process. Add a
`Signed-off-by: Name <email>` trailer to each commit (for example with
`git commit -s`). The sign-off certifies that you have the right to submit the
contribution under the project's license. It is not a copyright assignment.

## Review and governance

- Maintainers triage issues, protect the privacy boundary, review compatibility,
  keep release automation reproducible, and coordinate private disclosures.
- At least one maintainer review is expected for all changes. Security-sensitive
  areas should receive a second knowledgeable review before release.
- Reviews check schema compatibility, safe failure modes, synthetic-data use,
  test evidence, documentation, and whether false negatives or exposure can rise.
- Public contracts follow semantic versioning after the first stable release.
  During `0.x`, breaking changes remain possible but require migration notes and
  an explicit changelog entry.
- Stable serialized schemas carry their own `schema_version`. Breaking schema or
  policy changes require a new version; fields are deprecated before removal
  whenever safety permits.
- Supported Python, operating-system, MCP, and model compatibility is changed
  only with evidence-backed CI or documented manual verification.

Suggested issue categories are `bug`, `security` (private report only),
`enhancement`, `detector-quality`, `policy`, `integration`, `documentation`, and
`release`. Maintainers should document GitHub settings they cannot verify rather
than claiming those controls are enabled.

## Pull requests and security reports

Keep changes scoped and explain privacy impact, threat-model impact, validation,
and remaining limitations. Do not merge directly to `main`. Suspected
vulnerabilities or accidental data exposure must be reported privately as
described in [SECURITY.md](SECURITY.md), never in a public issue.

Dependencies and external model weights keep their own licenses. A contribution
under Apache-2.0 does not relicense those third-party materials; see
[Third-party licenses](docs/third-party-licenses.md).
