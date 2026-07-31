# Architecture

## Repository boundary

```text
src/
├── securedact_mcp/
│   ├── cli.py
│   ├── server.py
│   ├── model_registry.py
│   ├── model_installer.py
│   └── model_store.py
└── securedact_core/
    ├── detectors/
    ├── engine.py
    ├── policies.py
    ├── redaction.py
    ├── model_management.py
    └── supporting privacy modules
```

`securedact_mcp` owns the MCP adapter and guided model lifecycle.
`securedact_core` remains the provider-independent local privacy engine. No
desktop, Tauri, website, FastAPI gateway, provider adapter, or checkpoint is
included.

## Setup and runtime separation

```text
pip install securedact-mcp[ml]
        |
        | deterministic package install; no model network I/O
        v
securedact-mcp install
        |
        | consent + pinned official Hugging Face snapshot
        v
staging -> hashes/manifest -> offline Flair test -> atomic activation

MCP host -> securedact-mcp (stdio) -> verified local model -> privacy engine
```

The default `securedact-mcp` command starts the `stdio` server. It never invokes
the installer or contacts Hugging Face. Human setup output goes to stderr;
protocol stdout remains reserved for MCP JSON-RPC.

## Runtime flow

```text
MCP host or agent workflow
        |
        | stdio / JSON-RPC
        v
Securedact MCP
        ├── schema validation
        ├── deterministic + contextual detection
        ├── policy decision
        ├── redaction / placeholder mapping
        ├── residual validation
        └── restricted safe-copy output
        |
        v
structured local result -> host uses approved sanitized_text only
```

The host controls whether a tool is invoked and whether its output is used. MCP
does not provide universal interception by itself.

## Responsibilities

The MCP adapter registers exactly `analyze_text`, `redact_text`, `restore_text`,
and `create_safe_copy`; converts local engine results; preserves review/block
outcomes; applies text and filesystem limits; and runs over `stdio`.

The privacy engine owns deterministic/checksum detection, curated English/Dutch
rules and assertions, local Flair NER, merge precedence, policy actions, typed
replacement, restoration, and residual checks. It contains no provider-specific
logic.

The model subsystem owns one versioned allowlist, user consent, official pinned
downloads, storage restrictions, local manifests, integrity verification,
offline smoke testing, activation, rollback, active-language configuration, and
runtime selection. With both models enabled, certain language selects one model;
uncertain language runs both conservatively.

The MCP host must invoke the correct tools, keep analysis/mappings local, resolve
review decisions, require `status == "ok"`, and send only `sanitized_text`
downstream.

## Restoration and safe-copy boundaries

`redact_text` returns a mapping to the local caller; `restore_text` accepts a
mapping on each call. The process does not persist restoration sessions. The host
therefore owns mapping isolation, retention, and destruction.

`create_safe_copy` accepts content strings rather than source paths, permits only
`.txt`/`.md` basenames under a configured root, rejects traversal and drive
prefixes, and creates without overwrite.

## Excluded architecture

- desktop or Tauri code;
- provider dispatch;
- web UI or website;
- telemetry;
- shell execution;
- unrestricted filesystem tools;
- package-install hooks or import-time downloads;
- embedded or redistributed model checkpoints.
