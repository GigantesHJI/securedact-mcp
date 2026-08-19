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
automatic_pseudonymization: true
category_actions:
  email: redact
  phone: redact
  organization: review
  api_token: block
thresholds:
  person: 0.85
  organization: 0.92
automatic_pseudonymization_rules:
  email:
    source_thresholds:
      regex: 0.99
      label: 0.99
low_confidence_review_types:
  - health_data
  - biometric_data
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

Automatic thresholds are intentionally nested under entity type and source.
They are conservative policy configuration, not a claim that detector scores are
globally calibrated. A finding below `minimum_confidence` is ignored only when
its category is also outside `low_confidence_review_types` and it has no merge
conflict; strict policies retain weak high-risk signals for review or block.

`automatic_pseudonymization` defaults to `true` and is included in the policy
digest. Setting it to `false` converts otherwise automatic pseudonymization or
redaction into local review; it never approves the original value. The optional
process-start environment override
`SECUREDACT_AUTOMATIC_PSEUDONYMIZATION=1|0` takes precedence over this field for
all policies. Restart the server or start a fresh enforced-provider session
after changing either source.
