## Summary

Describe the scoped change.

## Privacy and security impact

- What data crosses each boundary?
- Can this affect false negatives, review/block behavior, mappings, logs, files,
  model loading, or approved output?
- Does the MCP host-invocation limitation remain accurate?

## Validation

- [ ] Repository validator
- [ ] Ruff formatting
- [ ] Ruff lint
- [ ] mypy
- [ ] Full pytest suite
- [ ] Privacy release tests
- [ ] Package build and artifact inspection, if packaging changed
- [ ] Only synthetic test data used

## Repository boundary

- [ ] No desktop, Tauri, website, API gateway, or provider code
- [ ] No secrets, model checkpoints, logs, mappings, local databases, or user data
- [ ] Documentation and changelog updated

