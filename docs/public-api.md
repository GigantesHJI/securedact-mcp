# Public Python API

The stable provider-neutral entry points are exported from `securedact_core`:

- `SecuredactEngine`, `RedactionRequest`, `PrepareResult`, and `SafeFinding`;
- `RestorationRequest` and `RestorationResult`;
- `ResponseMode`, `PrepareStatus`, and `ErrorCode`;
- `SecuredactError` and `SecuredactConfigurationError`;
- `RestorationVault` and its safe error enums for advanced local embedding.

Existing low-level exports remain for compatibility during the `0.x` series but
are not all promised as stable. Detector implementations, merge helpers, model
management, storage, MCP transport, and server lifecycle modules are internal
implementation surfaces unless named above.

```python
from securedact_core import RedactionRequest, SecuredactEngine

engine = SecuredactEngine.from_environment()
result = engine.prepare(
    RedactionRequest(
        text="Contact alex@example.test",
        policy="strict_external_ai",
        response_mode="minimal",
    )
)
if result.status == "ok":
    approved = result.sanitized_text
```

`prepare()` and `restore()` are synchronous. One engine serializes detector
inference because injected statistical models are not assumed thread-safe; the
vault separately protects concurrent access. Reuse an engine so models load
once. Call `close()` to erase in-memory restoration sessions before dropping a
long-lived engine.

`from_environment()` honors `SECUREDACT_REQUIRE_FLAIR` and therefore fails closed
by default when no contextual model has been injected into the standalone core.
The MCP runtime owns its managed model lifecycle. For deterministic local tests,
explicitly set `SECUREDACT_REQUIRE_FLAIR=0`, or inject detectors:

```python
from securedact_core import SecuredactEngine
from securedact_core.detectors import RegexDetector

engine = SecuredactEngine.with_detectors([RegexDetector()])
```

Injected deterministic detectors must report `contextual = False`; contextual
detectors must report `contextual = True`. Empty or incorrectly classified stacks
raise `SecuredactConfigurationError` rather than silently reducing coverage.

## Schema and deprecation policy

Public result JSON carries `schema_version: "1"`. Additive optional fields may be
introduced within a compatible release. Removing or changing a field's meaning
requires a new schema version and migration documentation. Public Python API
compatibility follows semantic versioning after 1.0. During 0.x, breaking changes
require changelog and upgrade notes. Unsafe legacy mapping behavior may be
removed faster when retaining it would create material exposure.
