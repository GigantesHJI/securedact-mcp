# Restoration sessions

`restore_capable` keeps the placeholder mapping in a bounded in-memory vault and
returns a cryptographically random opaque handle. Handles use 32 random bytes
(256 bits), are not derived from content, and are never logged.

Default controls:

- 15-minute expiration;
- at most 256 live sessions;
- at most 4 MiB total mapped data and 1 MiB per mapping;
- single-use consumption;
- synchronized store, cleanup, and consume operations;
- explicit malformed, unknown, expired, consumed, and capacity error codes;
- mapping erasure on consumption, expiration, cleanup, close, or process exit.

Short-lived hashed tombstones distinguish replay from unknown handles without
retaining mappings. They expire and are bounded by the live-session creation
rate. The vault has no database or persistent storage; process termination makes
all outstanding handles unusable.

`restore_text` consumes a session handle. Direct caller-supplied mapping remains
only as explicit `trusted_local_review: true` legacy behavior and returns a
deprecation code. Mappings and restored text are sensitive and must never enter
an external-AI workflow or log.
