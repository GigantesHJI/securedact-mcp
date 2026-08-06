# Detection conflict resolution

Merge output is deterministic, ordered, and non-overlapping. Adjacent spans do
not conflict. Candidate rank is evaluated in this order:

1. explicit policy-selected full assertion or sentence scope;
2. deterministic source before contextual/statistical source;
3. entity-specific precedence (complete address, sensitive URL, credential, and
   structured identifiers before broader fragments);
4. longer span;
5. higher confidence;
6. start offset, normalized entity name, source name, and rule name as stable
   tie-breakers.

| Conflict | Winner | Reason |
|---|---|---|
| Email inside broader Flair person span | Email | Specific deterministic identifier |
| Credential inside generic URL/text span | Credential or complete credential-bearing URL | Critical specific precedence |
| Complete address over postcode/house fragments | Address | Whole semantic unit |
| Identical span and category from two detectors | Higher-ranked deterministic source | Avoid duplicate placeholder |
| Identical span, different categories | Explicit type/source precedence then lexical tie-break | Stable across input ordering |
| Partial overlap in one source | Higher type precedence, then longer span | No partial replacement |
| Adjacent spans | Both | No character overlap |
| Policy assertion over nested identifiers | Policy assertion | Explicit review/redaction scope |

Offsets are Python Unicode character offsets into the original string. No
normalization is applied before replacement, so offsets always validate against
the exact source. Detection tests cover repeated values, punctuation, Markdown,
JSON/YAML, URLs, logs, accented and non-Latin labelled text, Dutch prefixes,
hyphenated names, and common-word/month near misses. The project does not claim
complete coreference or adversarial Unicode-obfuscation handling.
