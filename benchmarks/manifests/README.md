# Manifests

Only small, aggregate, non-sensitive manifests may be committed here. Manifests for external or
restricted corpora belong under `$SECUREDACT_BENCHMARK_DATA_DIR/manifests`; do not commit local paths,
record identifiers, source excerpts, or private-holdout membership.

`private-release-gate.example.json` defines the only public shape for private release evidence. An
authorized maintainer runs `quality --aggregate-only` against an explicit restricted workspace,
checks organization disclosure rules, and stores the real aggregate outside Git. The example has
zero support and undefined metrics intentionally; it is not a benchmark result. Never add record
IDs, membership, group sizes small enough to identify a subject, or raw text.
