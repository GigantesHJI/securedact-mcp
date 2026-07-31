# Troubleshooting

## The server does not appear in my MCP client

1. Verify the absolute Python executable path.
2. Activate that environment and run `python -c "import securedact_mcp"`.
3. Run `python -m securedact_mcp` from a terminal.
4. Inspect the host's MCP server status.
5. Restart the host after configuration changes.
6. Test the same command with MCP Inspector.

## The process starts but the client reports invalid JSON

For `stdio`, protocol messages are the only allowed stdout content. Remove shell
profile banners or wrappers that print to stdout. Application diagnostics must
use stderr.

## The client starts without Securedact

Where supported, mark the server required. This makes startup fail if the server
cannot initialize; it does **not** guarantee that every prompt is routed through
a Securedact tool.

## `redact_text` reports contextual detector unavailable

The secure default requires a verified enabled Flair model. Run the language
command shown in the tool result, for example:

```powershell
securedact-mcp install --language english --accept-upstream-terms
securedact-mcp models verify
```

The server never downloads during protocol startup. For synthetic development
testing only, `SECUREDACT_REQUIRE_FLAIR=0` permits reduced coverage; it is not
recommended for real sensitive data.

If both `models status` and `models verify` succeed but startup still blocks,
run `securedact-mcp models diagnose`. It reports the managed configuration,
active model IDs, verified states, runtime detector states, and final safe
failure code without revealing model paths or exception bodies.

`contextual_model_load_failed` means at least one enabled child model failed
during the server's in-process startup. Securedact keeps all contextual
processing blocked and does not fall back to regex-only operation. A valid
managed configuration takes precedence over inherited legacy development model
variables. A fresh MCP host process therefore uses the same managed store as
the `models status` and `models verify` commands.

## A model download is declined or interrupted

Confirmation defaults to No. A declined or interrupted transfer is marked
cancelled, its staging directory is removed, the active configuration is not
changed, and any prior working model stays in place. Rerun
`securedact-mcp install` when ready. Downloads are resumable where the upstream
transport can reuse local staging data, but an incomplete snapshot is never
activated.

## A model is corrupt or fails verification

Do not bypass verification or point runtime at the checkpoint directly. Run:

```powershell
securedact-mcp models status
securedact-mcp models verify
securedact-mcp models update english
```

Use `dutch` as appropriate. Update uses the immutable revision already approved
by the Securedact registry, not an arbitrary latest revision. If a configuration
file is corrupt, Securedact reconstructs it only from verified installed models;
otherwise rerun `securedact-mcp install`.

## Setup reports insufficient disk space or an unsafe destination

Allow approximately 2.4 GiB per selected model plus staging reserve. The
`SECUREDACT_MODEL_DIR` override must be absolute and outside the repository,
current directory, Downloads, temporary locations, virtual environments,
site-packages, and system directories. Display the resolved location with:

```powershell
securedact-mcp models path
```

## Offline use

Internet access is needed only during an approved install or update. Once
`securedact-mcp models verify` succeeds, runtime loads the managed checkpoint
locally with offline mode enabled. If an offline machine needs a manual transfer,
read [Model installation](model-installation.md); manually named folders are not
trusted or activated automatically.

## A result requires review or is blocked

Do not pass the original or intermediate text downstream. Resolve the review
through the host workflow or stop. Only `status == "ok"` includes approved
sanitized output.

## Safe-copy creation fails

Confirm:

- `SECUREDACT_SAFE_COPY_DIR` is configured;
- the filename is a `.txt` or `.md` basename;
- the destination does not already exist;
- the content is within the size limit;
- the selected policy permits an approved result.

Do not broaden filesystem permissions merely to suppress an error.

## A placeholder does not restore

`restore_text` uses only the supplied mapping. Unknown placeholders remain
unchanged. Confirm the mapping came from the same local redaction result and has
not been modified. Never post mappings in public support requests.

## Reporting a problem

Use the bug template with synthetic reproduction data. For security or privacy
vulnerabilities, follow [SECURITY.md](../SECURITY.md) and do not open a public
issue.
