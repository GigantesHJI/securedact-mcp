# Versioned policies

Policies are declarative Pydantic models with strict unknown-field rejection and
`schema_version: 1`. Approved results include the policy version and a SHA-256
digest of canonical policy JSON.

Built-ins:

- `default`: automatic protection with review for uncertain contextual findings;
- `strict_external_ai`: blocks credential and special-category data, redacts
  deterministic identifiers, and reviews ambiguous organization findings;
- `gdpr`: broad evaluation policy for categories relevant to GDPR; it is not a
  compliance certification;
- `identifiers_only`: focuses on direct identifiers while leaving other
  sensitive findings reviewable;
- `review_all_contextual`: requires local review for all contextual/statistical
  findings.

Compatibility profiles such as `gdpr_strict` remain available during migration.

## Local organization policies

Set `SECUREDACT_POLICY_DIR` to one controlled local directory, or use the default
`policies` directory under the Securedact application-data root. Files may be
JSON or YAML, are limited to 64 KiB each and 64 files, and cannot be symlinks,
junctions, templates, or Python. No command or expression evaluation occurs.

```yaml
schema_version: 1
name: organization_external
description: Synthetic example organization policy
category_actions:
  email: redact
  phone: redact
  organization: review
  api_token: block
thresholds:
  person: 0.85
  organization: 0.92
residual_validation_enabled: true
residual_on_failure: block
default_response_mode: minimal
expose_raw_values: false
expose_mapping: false
```

Duplicate names, unsupported actions or versions, malformed files, oversized
files, unknown fields, unsafe filesystem objects, and invalid thresholds fail
closed with stable configuration codes.

The loader will not accept a local policy that allows critical or GDPR
special-category types, disables residual validation, changes residual failure
away from block, exposes raw values, exposes mappings, or makes debug a default.
Those invariants are not customizable through policy files.
