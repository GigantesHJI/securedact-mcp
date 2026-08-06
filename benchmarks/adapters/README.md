# External adapters

Adapter code lives in `securedact_eval.benchmark.adapters` so it can later move into a
standalone `securedact-benchmark` package without depending on the MCP transport. An adapter may
read only a source enabled in `../registry/sources.yml`, after its exact file has passed size and
digest validation. Raw source data and record-level adapted output stay in the external workspace.

MultiCoNER 1 supports English and Dutch CoNLL files. The generic Dutch open-government contract is
disabled until a specific dataset, license, publisher, URL, size, and SHA-256 are reviewed.
