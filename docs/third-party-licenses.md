# Third-party licenses and model terms

Apache License 2.0 covers the original Securedact MCP source and documentation in
this repository. It does not relicense dependencies, build tools, MCP hosts, or
model weights obtained from another source.

Python dependencies retain the license published by each upstream project. The
release process generates a dependency license report and SBOM so maintainers can
review the resolved distribution before release.

`sigstore-models` 0.0.6 currently omits a machine-readable license expression;
its installed `LICENSE` is MIT. The license gate pins and hashes that exact file
as a narrow reviewed exception. Any version or file change fails closed and
requires renewed review. Missing, proprietary, or unreviewed license metadata is
a release blocker.

No model checkpoint is committed to or distributed in the Python artifacts.
The optional installer downloads an explicitly selected, immutable revision from
an allowlisted upstream repository after user consent. Users and distributors
must independently review and comply with the model repository's license and
terms. Citation metadata is not a substitute for license permission.

See [Model installation](model-installation.md) for the pinned sources and the
known upstream model-license uncertainty.
