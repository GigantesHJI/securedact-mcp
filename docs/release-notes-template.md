# Release notes template

## Securedact X.Y.Z

Release date: YYYY-MM-DD

### Summary

State the user-visible outcome and whether privacy behavior changed.

### Security and privacy

- Safe response, detection, policy, residual, restoration, logging, or model
  changes.
- Vulnerability identifier/advisory and coordinated-disclosure status, if any.

### Compatibility and migration

- MCP schema/tool changes and `schema_version` impact.
- Python public API changes and deprecations.
- Required host configuration or model action.
- Link to exact upgrade/rollback guidance.

### Evaluation

- Corpus manifest hash, policy digest, lock hash, deterministic quality gate,
  performance comparison, and execution environment.
- Real Flair model IDs/revisions/hashes and hardware only if actually run.
- State unavailable or mocked measurements explicitly; do not infer them.

### Supply chain

- Checksums, SBOM, keyless signature, and build-provenance links.
- Dependency/action/model provenance changes and license review outcome.

### Known limitations

List unresolved detection, host-enforcement, platform, model, and operational
limitations. Metrics are not a compliance or universal-detection claim.
