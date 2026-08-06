# Benchmark migration readiness

The benchmark remains beside `securedact_core` and `securedact_eval` while its schemas, data tiers,
generator contracts, source-review process, and stable CLI mature. This keeps privacy-engine changes
and their evaluation evidence reviewable in one pull request without creating an immature second
release process. Large, external, and restricted data already lives outside the repository, so this
temporary arrangement does not make Git the corpus store.

The migration boundary is `securedact_eval.benchmark`. Profiles, schemas, generators, adapters,
registry models, workspace handling, manifests, and integrity checks are self-contained there and
must not import MCP transport code. A future `securedact-benchmark` project will receive that
package plus `benchmarks/registry`, `schemas`, `generators`, `adapters`, `fixtures`, `manifests`, and
aggregate reports. The span mathematics, quality/performance runners, regression gates, and
compatibility facade remain in `securedact_eval` until consumers can depend on the benchmark
package directly.

Compatibility will be preserved by keeping `securedact-eval` command names and manifest v2 stable,
then delegating them to the extracted package. `securedact_eval.benchmark` will remain a re-export
for at least one documented compatibility cycle. Benchmark versions (for example v0.2) will advance
independently from MCP server versions; manifests record both benchmark/generator identity and the
engine/tool version used for scoring.

When migration happens, use `git filter-repo` or a subtree split on the benchmark paths so file
history and authorship survive. Land an extraction commit in the new repository, then a dependency
and compatibility-facade commit here. Do not copy restricted workspaces or rewrite public history
merely to make the split visually tidy.

Migration should be proposed when any of these becomes true:

- benchmark assets approach 250 MiB;
- more than roughly 10,000 records must be stored rather than generated;
- external datasets become central to ordinary evaluation;
- private or restricted evaluation grows materially;
- independent benchmark releases are required;
- benchmark and MCP contributor groups diverge;
- DOI, publication, or leaderboard support is introduced.

A migration review must first freeze the CLI/schema compatibility contract, document source licence
ownership, establish independent security and release processes, and prove that the MCP release gate
still works without network access to the new repository.
