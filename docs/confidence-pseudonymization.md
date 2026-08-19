# Confidence-aware pseudonymization

SecuRedact selects a provider-neutral disposition for every accepted finding:
`allow`, `pseudonymize`, `redact`, `review`, or `block`. The policy action remains separate
for compatibility (`redact`, `review`, `allow`, or `block`); a typed-token
transformation is reported as pseudonymization, while `replacement_mode: remove`
is reported as redaction.

## Confidence is detector-specific

Confidence values are not treated as calibrated probabilities. Regex and label
rules use fixed rule confidence, validated formats such as IBAN add deterministic
checks, and Flair exposes a raw model label score. The public corpus measures
span and action quality but does not currently establish probability calibration.

Policies therefore configure `automatic_pseudonymization_rules` per entity type
and detector source. Built-ins use conservative defaults:

- validated or complete structured identifiers from regex/label detection can be
  pseudonymized automatically;
- PERSON requires high source-specific confidence plus personal context (an
  explicit label, contact/address evidence, or a relationship between people);
- LOCATION requires a person relationship and precise address evidence for
  automatic transformation;
- ORGANIZATION and other ambiguous contextual categories remain review-only;
- `review_all_contextual` and `always_review_types` override automatic rules;
- overlapping contextual type conflicts require review, while a validated
  structured match can safely win over a weak overlapping NER span;
- exact type/span support from multiple detector sources is recorded as
  `multiple_detector_agreement`.

The provider-neutral policy field `automatic_pseudonymization` defaults to
`true`. When it is `false`, a finding that satisfies one of these automatic
rules becomes `review` with reason
`automatic_pseudonymization_disabled`; it is not allowed through unchanged.
Decisions that were already review, block, or special-category controls are not
downgraded. The setting controls automatic transformation only: an explicit
local `ReviewDecision` may still apply an approved typed replacement.

Below the ordinary detection threshold does not universally mean `allow`.
Low-risk noise may be ignored by policy, while `low_confidence_review_types`
retains critical and special-category findings for review or block. This prevents
a weak high-risk signal from disappearing merely because its score is low.

## Sensitive assertions

Special-category assertions remain review/block decisions unless a policy already
defines assertion-level transformation. Replacing only a person's name or email
does not make a health, religion, political-opinion, union, sexuality,
biometric, or genetic statement safe. Residual assertion checks still fail
closed.

## Scope and restoration

Typed pseudonyms are allocated by the existing redaction implementation. Equal
entity type/value pairs and conservatively resolved PERSON aliases receive one
token; unrelated or unresolved identities receive distinct tokens within one
`prepare()` transformation. There is no process-global or cross-user identity
mapping. `restore_capable` may place the same mapping in the existing bounded,
opaque, expiring, in-memory restoration vault for one local restoration session.

Before PERSON tokens are allocated, SecuRedact performs conservative alias
grouping within that transformation only. Repeated normalized full names share
a group. A one-token mention may join a full name when it exactly equals the
first or last name token and exactly one distinct compatible full name exists in
the request. This supports forms such as `Sophie de Vries` plus `Sophie`, or
`Mark Jansen` plus `Jansen`, without fuzzy identity inference. Case differences
and surrounding punctuation are normalized; nicknames, spelling variants,
transliterations, titles, and initials are not inferred.

When more than one full name is compatible, the short mention receives its own
unresolved group. SecuRedact never chooses by recency. Group identifiers such as
`person-group-1` and aggregate counts exist only in memory and contain no source
name. Raw aliases, identity graphs, and token-to-name mappings are never written
to diagnostics or receipts. The pre-existing restoration vault remains the only
optional bounded holder of a transformation mapping.

## Safe decision metadata

`PrepareResult.outcome` distinguishes `allow`, `pseudonymized`, `redacted`,
`review_required`, and `blocked`, while the compatibility `status` remains `ok`,
`review_required`, or `blocked`. `action_counts` and review-mode findings expose
category, source, confidence, decision, reason, offsets, and a typed replacement
suggestion without copying the source value. Debug decision diagnostics contain
the same safe fields and never include original values.

Review results expose the local options `send_pseudonymized`,
`edit_replacements`, `keep_selected_values`, and `cancel`. A local caller can
resubmit `ReviewDecision` values to `prepare()`: `accept` uses the suggested
typed token, `replace` accepts a category-preserving token such as `[PERSON_7]`,
and `allow_once` keeps the selected local value. Unresolved review findings never
produce provider-bound text.

Decision reasons include `high_confidence_structured_pii`,
`high_confidence_contextual_pii`, `multiple_detector_agreement`,
`ambiguous_detection`, `sensitive_category_requires_review`,
`generic_geographic_reference`, `personal_location_context`, and
`automatic_pseudonymization`, plus
`automatic_pseudonymization_disabled` when automatic transformation is off.
