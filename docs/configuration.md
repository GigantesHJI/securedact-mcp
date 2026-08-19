# Configuration Guide

This guide documents all configuration options for Securedact MCP.

## Environment Variables

### Runtime Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECUREDACT_REQUIRE_FLAIR` | `1` | Require contextual model for operation |
| `SECUREDACT_AUTOMATIC_PSEUDONYMIZATION` | policy value (`1` by default) | Override automatic transformation for all policies |
| `SECUREDACT_ENABLE_DEBUG_RESPONSES` | `0` | Enable debug response mode |
| `SECUREDACT_SAFE_COPY_DIR` | (unset) | Directory for safe copy creation |

### SECUREDACT_REQUIRE_FLAIR

**Controls**: Whether the server requires a contextual model to operate.

**Values**:
- `1` (default): Server requires a verified contextual model. If missing or unavailable, the server fails closed and blocks requests.
- `0`: Server operates in deterministic-only mode (regex and curated rules only).

**Use Case**: Set to `0` for development or testing without ML dependencies.

```powershell
$env:SECUREDACT_REQUIRE_FLAIR = "0"
securedact-mcp
```

**Warning**: This reduces detection coverage and is not recommended for production use with sensitive data.

### SECUREDACT_AUTOMATIC_PSEUDONYMIZATION

**Controls**: Whether findings that satisfy the active policy's conservative
automatic-transformation rules may be sent in core-sanitized form.

**Values**:

- `1`: permit existing policy-driven automatic pseudonymization or redaction;
- `0`: require local review for findings that would otherwise be transformed
  automatically. Original protected text is not approved for transmission.

The policy field `automatic_pseudonymization` defaults to `true`. If the
environment variable is set, it overrides that field for every built-in and
locally loaded policy. Any value other than `0` or `1` is invalid and causes
policy configuration to fail closed.

```powershell
$env:SECUREDACT_AUTOMATIC_PSEUDONYMIZATION = "0"
securedact-mcp
```

Changing this setting requires restarting the MCP server or starting a fresh
enforced-provider session. Configuration is loaded once at process start;
runtime caches are session-local and are not carried into the replacement
process.

Setting the value to `0` does **not** disable privacy protection. It disables
automatic sending of transformed content and routes that content to trusted
local review. Existing `review_required`, `blocked`, sensitive-category, and
runtime-failure decisions remain authoritative. A replacement explicitly
approved through the local review contract can still be applied.

### SECUREDACT_ENABLE_DEBUG_RESPONSES

**Controls**: Whether debug response mode is available.

**Values**:
- `0` (default): Debug mode is disabled. MCP requests cannot enable it.
- `1`: Debug mode is enabled. Responses may include raw entity values and detailed detection information.

**Use Case**: Development and troubleshooting. Never enable in production.

```powershell
$env:SECUREDACT_ENABLE_DEBUG_RESPONSES = "1"
securedact-mcp
```

**Security Note**: Debug responses may contain sensitive information. Use only in trusted environments.

### SECUREDACT_SAFE_COPY_DIR

**Controls**: Directory for `create_safe_copy` operation.

**Values**: Absolute path to a writable directory.

**Use Case**: Enable safe copy creation for approved sanitized content.

```powershell
$env:SECUREDACT_SAFE_COPY_DIR = "C:\absolute\path\to\safe-copies"
```

**Behavior**:
- Only `.txt` and `.md` basenames are created
- Existing files are not overwritten
- Returns filename only, not absolute path

## Runtime Configuration

### Policy Selection

Policies are selected by name in tool calls. Built-in policies include:

- `default`: Standard privacy protection
- `strict_external_ai`: Strict mode for external AI processing
- `gdpr`: GDPR-focused policy
- `identifiers_only`: Identifier detection only
- `review_all_contextual`: Review all contextual detections

Custom policies can be loaded from the controlled policy directory.

### Redaction Modes

Redaction modes control response detail level:

| Mode | Description | Contains Sensitive Data |
|------|-------------|------------------------|
| `minimal` | Basic redaction, no details | No |
| `review` | Includes offsets and classifications | No raw values |
| `debug` | Full detection details | Yes (if enabled) |
| `restore_capable` | Includes restoration handle | No raw values |

Default mode is `minimal`.

## Model Configuration

### Model Selection

Models are selected during installation via `--language` flag:

- `english`: English language model
- `dutch`: Dutch language model
- `all`: Both English and Dutch
- `none`: No contextual model (regex-only)

### Model Storage Location

Models are stored in the user's local Securedact data directory. The exact path is determined by `SecuredactPaths.resolve()` and is outside the installation directory.

### Model Verification

Models are verified on startup and before use:

```powershell
securedact-mcp models verify
```

Verification checks:
- File integrity (hash verification)
- Model compatibility
- Load capability

## Policy Configuration

### Custom Policies

Custom policies can be loaded from the controlled policy directory. Policy files must:

- Use the strict declarative schema
- Not disable fail-closed invariants
- Be valid YAML
- Not be symlinks

They may set `automatic_pseudonymization: true` or `false`. The field is part of
the serialized policy and its digest, so the two configurations cannot share a
policy identity.

Invalid policies fail closed.

### Policy Registry

The policy registry manages available policies:

```python
from securedact_core.policies import PolicyRegistry

registry = PolicyRegistry()
policy = registry.get("strict_external_ai")
```

## Debug Configuration

### Enabling Debug Mode

Debug mode must be enabled at process start via environment variable:

```powershell
$env:SECUREDACT_ENABLE_DEBUG_RESPONSES = "1"
```

An MCP request cannot enable debug mode at runtime.

### Debug Response Contents

When enabled, debug responses may include:
- Raw entity values
- Detailed detection information
- Model paths
- Exception details

**Security Warning**: Do not use debug mode in production or with sensitive data.

## Path Configuration

### Application Paths

Application paths are resolved automatically:

```python
from securedact_core.app_paths import SecuredactPaths

paths = SecuredactPaths.resolve()
```

Paths include:
- Data directory (user-owned, outside installation)
- Model storage directory
- Policy directory
- Restoration vault location

### Override Paths

Paths can be overridden for testing or custom deployments:

```python
from securedact_core.app_paths import SecuredactPaths

paths = SecuredactPaths.resolve(override="/custom/path")
```

## Failure Behavior

### Fail-Closed Default

The system defaults to fail-closed behavior:

- Missing model: Blocks requests
- Corrupt model: Blocks requests
- Model load failure: Blocks requests
- Invalid policy: Blocks requests
- Symlinked policy: Blocks requests

### Synthetic Development Mode

For development testing only:

```powershell
$env:SECUREDACT_REQUIRE_FLAIR = "0"
```

This mode has reduced detection coverage and is not recommended for production.

## Next Steps

- [Models](models.md) - Detailed model configuration
- [Architecture](architecture.md) - How configuration affects the system
- [Use Cases](use-cases.md) - Configuration examples for different scenarios
