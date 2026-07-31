# Model Installation

Securedact does not redistribute these model weights. During installation, the
selected model is downloaded directly from its official Hugging Face repository
to the user's local Securedact data directory.

The Python package installation remains deterministic and non-interactive.
`securedact-mcp install` is the separate, consent-based product setup step; the
MCP server itself never downloads a model.

## Supported models

| Selection | Registry ID | Official repository | Pinned revision | Required inference file | Approximate size |
|---|---|---|---|---|---:|
| English | `english-large` | `flair/ner-english-large` | `e2b1caabf7f9bac1e7829db73eac734df7e6ad7b` | `pytorch_model.bin` | 2.09 GiB |
| Dutch | `dutch-large` | `flair/ner-dutch-large` | `44c285912a9d6eec4d0858580f3cb13b7b8c9959` | `pytorch_model.bin` | 2.09 GiB |

The registry pins immutable commits, exact byte sizes, and SHA-256 hashes.
`main`, `master`, `latest`, and other moving revisions are rejected by release
validation. Repository inspection confirmed that the single checkpoint above is
the file Flair needs for local `SequenceTagger.load`; training logs and model-card
files are not downloaded.

The upstream model cards cite:

> Schweter, Stefan and Alan Akbik. FLERT: Document-Level Features for Named
> Entity Recognition. arXiv:2011.06993, 2020.

A citation is not a license grant. Neither upstream repository currently exposes
a clear, separate model-weight license identifier in its model-card metadata.
Securedact therefore warns before download and obtains the files directly from
the official repository without mirroring or redistributing them. Maintainers
must recheck upstream terms before every release.

## Guided setup

Install ML dependencies and start the guided setup:

```powershell
python -m pip install "securedact-mcp[ml]"
securedact-mcp install
```

The menu offers English, Dutch, both, or no contextual model. For each selected
model it displays the official source, immutable revision, estimated size,
destination, licensing note, and citation. The confirmation prompt defaults to
No.

For unattended setup, the selected upstream download must be accepted explicitly:

```powershell
securedact-mcp install --language english --accept-upstream-terms
securedact-mcp install --language dutch --accept-upstream-terms
securedact-mcp install --language all --accept-upstream-terms
securedact-mcp install --language none
```

`--accept-upstream-terms` records no legal assertion; it is an explicit operator
confirmation that Securedact may fetch the displayed third-party artifacts.

## Managed storage

Models are stored outside the repository, virtual environment, site-packages,
wheel, and source distribution:

| Platform | Default model directory |
|---|---|
| Windows | `%LOCALAPPDATA%\Securedact\MCP\models` |
| Linux | `$XDG_DATA_HOME/securedact-mcp/models`, otherwise `~/.local/share/securedact-mcp/models` |
| macOS | `~/Library/Application Support/Securedact MCP/models` |

`SECUREDACT_MODEL_DIR` may supply an absolute custom directory. Securedact rejects
relative paths and locations under the working tree, temporary directories,
Downloads, virtual environments, site-packages, and protected system roots.

The non-secret active-language configuration is written atomically beside the
managed model root. If it is corrupt, Securedact reconstructs it only from fully
verified installed models; otherwise runtime fails closed and asks the operator
to rerun setup.

## Download and activation safety

The installer uses `huggingface_hub.snapshot_download` directly with:

- only the two registry-allowlisted repository IDs;
- the immutable registry revision and official HTTPS endpoint;
- an exact required-file allowlist;
- no authentication token for these public repositories;
- resumable transfers, bounded outer retries, timeouts, disk-space limits, file
  count limits, and expected total-size limits;
- a random staging directory under the managed model root.

After download, Securedact rejects unexpected layouts, links/reparse points,
partial files, and executable extras. It computes the checkpoint SHA-256 locally,
compares its size and digest with pinned upstream metadata, creates a local
manifest, and performs an offline Flair load test. Only then is the directory
renamed atomically into place. A failed staging tree is removed, the prior active
model and configuration remain unchanged, and setup reports an actionable error.

The local manifest includes registry identity, language, upstream repository and
revision, Securedact version, UTC installation time, file sizes, and local hashes.
Runtime re-verifies it before every model load. HTTPS, a directory name, Git LFS
metadata, or a downloaded manifest alone is never treated as proof of integrity.

## Offline runtime and language selection

After successful setup, model loading uses local paths with Hugging Face and
Transformers offline mode enabled. Server startup never performs a download.

With both models enabled, a local deterministic language detector selects the
matching contextual model. Ambiguous input is analyzed conservatively by both
models. With one model enabled, that model is not silently skipped merely because
language detection is uncertain.

## Model maintenance

```powershell
securedact-mcp models list
securedact-mcp models status
securedact-mcp models verify
securedact-mcp models diagnose
securedact-mcp models path
securedact-mcp models update english
securedact-mcp models update dutch
securedact-mcp models remove english
securedact-mcp models remove dutch
```

Updates use only the revision already approved in the installed Securedact
registry. They never follow an arbitrary latest revision. Verification is local
and performs size/SHA-256 checks plus an offline Flair load test without
contacting Hugging Face.

## Minimal installation

```powershell
securedact-mcp install --language none
```

This records that no contextual model is enabled. Securedact will fail closed
when the selected policy requires contextual detection. Regex-only development
mode requires the explicit `SECUREDACT_REQUIRE_FLAIR=0` override and is not
recommended for real sensitive data.

## Manual download alternatives

The normal installer requires neither Git Xet nor the Hugging Face CLI. Advanced
operators may separately use the official upstream mechanisms:

```powershell
winget install git-xet
git clone https://huggingface.co/flair/ner-english-large
git clone https://huggingface.co/flair/ner-dutch-large

hf download flair/ner-english-large
hf download flair/ner-dutch-large
```

Git Xet is needed only for the Git clone method. The Hugging Face CLI is needed
only for `hf download`. A manually downloaded folder is not trusted because its
name resembles a supported model: it still needs registry provenance, local
hashing, layout validation, a Securedact manifest, and a Flair load test.

The current CLI does not expose manual import, so use the normal guided installer
for an activated model. Securedact intentionally does not recommend bypassing
PowerShell execution policy or piping an internet response into PowerShell.
