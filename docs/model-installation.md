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
validation. Training logs and model-card files are not downloaded.

## Required transformer runtime component

Both serialized Flair checkpoints reference the legacy transformer identifier
`xlm-roberta-large`. A checkpoint alone is therefore not a self-contained
offline installation. Both languages use this one shared registry component:

| Component | Official repository | Pinned revision | Approximate size | License metadata |
|---|---|---|---:|---|
| `xlm-roberta-large-runtime` | `FacebookAI/xlm-roberta-large` | `c23d21b0620b635a76227c604d44e43a9f0ee389` | 13.51 MiB | MIT |

Required files are pinned individually:

| File | Bytes | SHA-256 |
|---|---:|---|
| `config.json` | 616 | `ec7c3a99c58a38ebb702a2297f1c4586944e841b5eb29d201ff87e0f9c9abe0e` |
| `sentencepiece.bpe.model` | 5,069,051 | `cfc8146abe2a0488e9e2a0c56de7952f7c11ab059eca145a0a727afce0db2865` |
| `tokenizer.json` | 9,096,718 | `a898ea75433890f6610f4e470b8ebeb0c21dce5c8dd61f892eb09eb5919d2e2c` |
| `tokenizer_config.json` | 25 | `994f46754c5bf4014f1aa92d34b1374319c3a6b3f702105cd5b742beaecd18ce` |

The official repository identifies this component as MIT licensed. That status
was confirmed from upstream metadata for the 0.1.0 review. It applies to the
transformer repository; it does not establish a license for the separate Flair
checkpoint weights. Citation and license permission remain distinct questions.

The upstream model cards cite:

> Schweter, Stefan and Alan Akbik. FLERT: Document-Level Features for Named
> Entity Recognition. arXiv:2011.06993, 2020.

A citation is not a license grant. The 0.1.0 maintainer review found that the
current `flair/ner-english-large` and `flair/ner-dutch-large` model-card and
repository metadata does not state a clear, separate explicit checkpoint-weight
license identifier. Securedact does not infer one from the MIT-licensed Flair
software framework. The maintainer accepted this recorded status for the 0.1.0
software release because the checkpoints remain explicit, separate downloads
from their official upstream repositories and are never mirrored or
redistributed by Securedact. Users remain responsible for upstream terms, and
maintainers must recheck them before every release. The machine-readable review
record is in [`MODEL_ASSET_LICENSES.json`](../MODEL_ASSET_LICENSES.json).

## Guided setup

Install ML dependencies and start the guided setup:

```powershell
python -m pip install "securedact-mcp[ml]"
securedact-mcp install
```

The menu offers English, Dutch, both, or no contextual model. For each selected
model it displays the official source, immutable revision, estimated size,
destination, licensing note, citation, and required transformer component. The
confirmation prompt defaults to No.

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

The shared dependency cache is stored at
`<model-directory>/.runtime-cache`. It uses the legacy cache key
`models--xlm-roberta-large` because that is the identifier serialized inside the
checkpoints. Setup, `models status`, `models verify`, diagnostics, and MCP startup
all resolve this same directory. They do not consult an ambient user Hugging Face
cache.

## Download and activation safety

The installer uses `huggingface_hub.snapshot_download` directly with:

- only the three registry-allowlisted repository IDs (two checkpoints and the
  shared transformer component);
- the immutable registry revision and official HTTPS endpoint;
- an exact required-file allowlist;
- no authentication token for these public repositories;
- resumable transfers, bounded outer retries, timeouts, disk-space limits, file
  count limits, and expected total-size limits;
- a random staging directory under the managed model root.

After download, Securedact rejects unexpected layouts, links/reparse points,
partial files, and executable extras. It computes every required file SHA-256
locally, compares size and digest with pinned metadata, and creates a local
manifest. Flair is then loaded in a fresh subprocess with user-site imports
disabled, network access disabled by Hugging Face/Transformers offline flags,
and every cache variable pointed at only the staged Securedact cache. Only after
that succeeds are the model and dependency activated. A failed staging tree is
removed, the prior active model, dependency cache, manifest, and configuration
remain unchanged, and setup reports an actionable error.

The version 2 local manifest includes registry identity, language, Securedact
version, UTC installation time, and one provenance record for every checkpoint
and runtime file. Each record distinguishes its component, upstream repository,
immutable revision, storage boundary, relative path, byte size, and locally
computed SHA-256. Runtime re-verifies it before every model load. HTTPS, a
directory name, Git LFS metadata, or a downloaded manifest alone is never treated
as proof of integrity.

## Offline runtime and language selection

After successful setup, model loading uses local paths with `HF_HOME`,
`HF_HUB_CACHE`, and `TRANSFORMERS_CACHE` set to Securedact-managed storage before
Flair imports. Hugging Face and Transformers offline mode is enabled. Server
startup never performs a download.

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
securedact-mcp models repair english --accept-upstream-terms
securedact-mcp models repair dutch --accept-upstream-terms
securedact-mcp models repair all --accept-upstream-terms
securedact-mcp models remove english
securedact-mcp models remove dutch
```

Updates use only the revision already approved in the installed Securedact
registry. They never follow an arbitrary latest revision. Verification is local
and performs size/SHA-256 checks plus an offline Flair load test without
contacting Hugging Face.

`repair` is for early standalone installations whose pinned checkpoint is valid
but whose transformer runtime component is absent. It validates the existing
checkpoint first and downloads only the missing 13.51 MiB shared component. It
does not redownload or replace a valid 2.09 GiB checkpoint. Removing one language
keeps a dependency still used by the other; removing the final dependent model
removes the now-unused managed component.

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
