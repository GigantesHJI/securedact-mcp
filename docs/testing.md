# Testing

## Reproduce the frozen environment

```powershell
uv sync --frozen --extra dev --extra benchmark --extra security
```

Add `--extra ml` only on a machine prepared for the large local Flair runtime.
Ordinary tests never download models or contact an AI provider.

## Complete local verification

```powershell
uv run python scripts\verify.py
```

That is the primary parity command. It checks the lock, repository/data/workflow boundaries,
smoke manifest, formatting, lint, types, full test suite, aggregate smoke evaluation, package build,
Twine metadata, and artifact contents. The corresponding commands and additional release gates are:

```powershell
uv lock --check
uv run python scripts\validate_repo.py --require-implementation
uv run python scripts\validate_repository_size.py
uv run python scripts\validate_workflows.py
uv run securedact-eval validate --dataset benchmarks\fixtures\smoke
uv run ruff format --check .
uv run ruff check .
uv run mypy src scripts
uv run pytest
# Included in the full pytest invocation; useful as a focused rerun:
uv run python scripts\run_privacy_tests.py
# Additional versioned release gates:
uv run securedact-eval quality --corpus benchmarks\corpora --gate --baseline benchmarks\baselines\quality-deterministic.json --output-dir build\evaluation
uv run securedact-eval performance --mode deterministic --gate --output build\evaluation\performance-deterministic.json
uv run python -m build --no-isolation
uv run python -m twine check dist\*
uv run python scripts\validate_release_artifacts.py dist
```

The essential package job additionally proves a clean installation. Reproduce that network-using
tail after the build with:

```powershell
uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file dist\runtime-requirements.txt
uv venv .clean-venv --python 3.12
$cleanPython = if ($IsWindows) { ".clean-venv\Scripts\python.exe" } else { ".clean-venv/bin/python" }
uv pip install --python $cleanPython --requirements dist\runtime-requirements.txt
uv pip install --python $cleanPython --no-deps (Get-ChildItem dist\*.whl).FullName
& $cleanPython scripts\smoke_test_entrypoint.py
```

The suite covers all five MCP tools, minimal/review/debug/restore-capable
responses, absence of approved text on non-success, opaque-session expiry and
replay, policy-file validation, credentials, ambiguous formats, deterministic
merge behavior, safe-copy confinement, model lifecycle, stdout canaries, and a
real MCP client session over `stdio`. Ambiguity cases include initialed and
punctuated names, common-noun organization near misses, capitalized identifiers,
Unicode lookalikes, compound Dutch location offsets, months, and non-Latin text.

## Evaluator

`securedact-eval quality` validates the corpus manifest and hashes before
running. Exact and relaxed metrics use one-to-one matching and report TP, FP,
FN, document-level TN, precision, recall, F1, false-positive rate,
false-negative rate, and support. Reports group by entity, language, domain,
split, and policy action and include micro, macro, weighted, and deterministic
bootstrap 95% confidence intervals. JSON is machine-readable; CSV and Markdown
are reviewer-friendly. Raw corpus text is not copied into reports.

`--mode deterministic` is the reproducible release gate. Real Flair evaluation
requires `SECUREDACT_EVAL_FLAIR_MODEL` and runs only in the manual pre-provisioned
workflow. Tests inject a mocked contextual detector to prove the statistical
path changes results without a checkpoint or download.

`securedact-eval performance` measures fresh-process cold start, initialization,
first inference, warm median/p95/min/max latency, throughput, input scaling,
RSS, CPU, and optional GPU memory. Unsupported GPU metrics are marked
unavailable. See [Benchmarking](benchmarking.md).

## MCP protocol verification

The integration harness starts the installed console entry point, initializes
over `stdio`, lists the exact five tools, calls them with synthetic canaries,
checks blocked and malformed requests, performs a clean shutdown, and asserts
that protocol stdout contains no leaked canary. The release smoke script repeats
the critical installed-wheel path in a clean environment.

MCP Inspector remains useful for interactive host-neutral testing:

```powershell
npx @modelcontextprotocol/inspector .\.venv\Scripts\securedact-mcp.exe
```

Inspector and real host validation are documented honestly in
[Compatibility](compatibility.md); registration does not prove automatic host
routing.

All fixtures and corpora are synthetic. Metrics describe those versioned inputs
and are not a universal privacy guarantee.
