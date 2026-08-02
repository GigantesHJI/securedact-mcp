# Testing

## Install development dependencies

```powershell
python -m pip install -e ".[ml,dev]"
```

CI may install only `.[dev]` because all network/model calls and Flair loads are
mocked. Installing `ml` is appropriate for a maintainer's real local model smoke
test; ordinary automated tests must not download multi-gigabyte checkpoints.

## Full verification

```powershell
python scripts\validate_repo.py
python -m ruff format --check .
python -m ruff check .
python -m mypy src\securedact_core src\securedact_mcp scripts
python -m pytest
python scripts\run_privacy_tests.py
python -m build
python -m twine check dist\*
python scripts\validate_release_artifacts.py dist
```

## Test coverage

The repository contains synthetic tests for:

- deterministic and contextual detection;
- checksums, spans, merging, policies, replacement, and restoration;
- all nine GDPR special-category groups in the curated corpus;
- immutable checkpoint and transformer-dependency registry metadata and
  repository allowlisting;
- interactive/non-interactive consent, all four language selections, licensing
  warnings, citation display, and safe reinstall behavior;
- mocked `snapshot_download` parameters, retries, cancellation, staging cleanup,
  disk limits, unexpected files, local hashes, isolated offline load tests,
  dependency repair without checkpoint redownload, activation, and rollback;
- multilingual runtime routing, corrupt-model rejection, offline behavior, and
  fail-closed readiness;
- fresh-process proof that an empty cache fails and the same tiny mocked model
  succeeds only when its managed dependency assets are present;
- tool startup, registration, malformed requests, and stdout integrity;
- `analyze_text`, `redact_text`, `restore_text`, and `create_safe_copy`;
- path traversal, extensions, root confinement, sanitized writes, and
  no-overwrite behavior;
- repeated placeholder stability and unknown placeholders;
- review and block outcomes;
- property-based identifiers and seeded fuzz inputs;
- an end-to-end MCP client session over `stdio`.

No test requires a live provider key or network call.

The mocked integration fixture writes a tiny synthetic checkpoint with a pinned
synthetic digest, substitutes a no-network snapshot function, exercises guided
setup through manifest/config activation, and verifies the model. It does not
attempt to deserialize or represent a real Flair model.

## MCP Inspector

The official MCP Inspector can launch the installed local server:

```powershell
securedact-mcp models verify
npx @modelcontextprotocol/inspector .\.venv\Scripts\securedact-mcp.exe
```

Command-line regression for the production Dutch person/email case:

```powershell
npx @modelcontextprotocol/inspector --cli `
  ".\.venv\Scripts\securedact-mcp.exe" `
  --method tools/call `
  --tool-name analyze_text `
  --tool-arg "text=Mijn naam is Emma de Vries en mijn e-mailadres is emma@example.com." `
  --connect-timeout 180000 `
  --format json
```

The subprocess release test uses the installed console entry point and a slow,
tiny mock loader. It requires initialize and `tools/list` to complete within two
seconds before the loader is released, checks the initializing block does not
invoke inference, then verifies a newly submitted call succeeds and the model
loaded exactly once. This is host-neutral and does not alter the MCP protocol.

Inspector `--cli` starts a one-shot child process. Its first cold call may
correctly return `contextual_model_initializing` and then close that process; it
cannot perform the manual resubmission against the now-closed runtime. Use the
Web Inspector or another persistent MCP session for the after-readiness person
and email assertions.

For explicitly reduced synthetic development testing, set
`SECUREDACT_REQUIRE_FLAIR=0`. In Inspector:

1. connect over `stdio`;
2. confirm exactly four tools;
3. inspect schemas;
4. submit synthetic calls;
5. test invalid types and missing fields;
6. verify review/block results contain no approved `sanitized_text`;
7. inspect notifications and stderr for canary leakage.

See the
[official MCP Inspector documentation](https://modelcontextprotocol.io/docs/tools/inspector).

## Privacy corpus

The versioned synthetic corpus covers prose, forms, JSON-like content, logs,
tables, mixed language, identifiers, credentials, financial data, health data,
sensitive assertions, overlap, repetition, encoding, adversarial cases, and
negative controls.

Metrics are measurements on this corpus, not universal guarantees.
The report records critical deterministic exact-span recall, complete
replacement rate, residual leakage count, and production-factory parity using
fixture IDs rather than raw fixture text. Stdio deadline compliance is measured
by the separate real-process test because it cannot be inferred in-process.

## Release gate

`scripts/run_privacy_tests.py` runs the release-critical privacy suite. It emits
test status only and does not write raw fixture content to a report. Repository
and artifact validators also reject moving model revisions, unapproved download
mechanisms, model weights, Hugging Face caches/snapshots, and unexpected large
binaries in source or distribution archives.
