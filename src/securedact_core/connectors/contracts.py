# SPDX-License-Identifier: Apache-2.0
"""Platform-independent connector contracts for SecuRedact Enterprise Connectors.

These models are the canonical boundary between external platforms (Microsoft
365, GitHub, Google Workspace, ...) and the SecuRedact privacy engine. They are
deliberately:

* **lightweight** -- pure Pydantic, no platform SDK, no network code;
* **platform-neutral** -- they never assume a resource is a "file";
* **privacy-safe by construction** -- they carry references/metadata, never raw
  extracted content beyond the normalized text handed to the engine, and they are
  serialized with the same allowlisting discipline as the rest of the core.

Microsoft/Graph/OAuth code lives outside this package (see ``CONN-002`` / the web
control plane). Importing this module must never pull in a Microsoft dependency.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Allowlist of characters permitted inside a *path-style* platform resource
# identifier (Google Drive file id, ``ConnectorResource.resource_id`` /
# ``parent_id`` / ``content_ref``, ``org_id`` / ``tenant_id``). The set
# excludes whitespace, path separators, quotes, angle brackets and other
# characters that could be abused for traversal or URL injection when these
# identifiers are reflected into control-plane payloads or local filesystem
# paths. Microsoft Graph identifiers are NOT path-style and are validated by
# :func:`validate_opaque_identifier` instead.
_IDENTIFIER_CHARS = r"A-Za-z0-9._\-~:/+=@"
_IDENTIFIER_PATTERN = re.compile(rf"^[{_IDENTIFIER_CHARS}]{{1,512}}$")

# Allowlist of characters permitted inside an *opaque* platform identifier
# such as a Microsoft Graph ``driveId`` / ``siteId`` / ``driveItem id``. These
# values are produced by Microsoft Graph itself and are base64url/base64/GUID
# shaped in practice, but real production drives do contain ``!`` (e.g.
# ``b!eO_jJqnieUqfFFH_...``). The validator rejects only what is genuinely
# unsafe at the boundary: empty/oversize, control characters, CR/LF and NUL.
# Where the value is placed into a URL, the caller MUST URL-encode it; this
# validator is intentionally permissive because URL construction is the
# real safety boundary for opaque Graph IDs.
_OPAQUE_MAX_LEN = 1024
_OPAQUE_FORBIDDEN_CONTROL = frozenset(chr(c) for c in range(32)) | {"\x7f"}


class InvalidResourceIdentifierError(ValueError):
    """Raised when a connector identifier fails validation."""


def validate_resource_identifier(value: str, *, field: str = "identifier") -> str:
    """Return ``value`` if it is a safe path-style platform identifier, else raise.

    Rejects empty strings, overly long strings, path-traversal sequences
    (``..``) and any character outside the safe allowlist. Used for local
    filesystem-path-shaped identifiers (Google Drive file ids, the
    ``ConnectorResource`` identity fields, ``org_id`` / ``tenant_id``).
    """

    if not isinstance(value, str) or not value:
        raise InvalidResourceIdentifierError(f"{field} must be a non-empty string")
    if ".." in value:
        raise InvalidResourceIdentifierError(f"{field} must not contain '..'")
    if not _IDENTIFIER_PATTERN.match(value):
        raise InvalidResourceIdentifierError(f"{field} contains an unsafe character: {value!r}")
    return value


def validate_opaque_identifier(value: str, *, field: str = "opaque_identifier") -> str:
    """Return ``value`` if it is a safe *opaque* platform identifier, else raise.

    Microsoft Graph ``driveId`` / ``siteId`` / ``driveItem id`` values are
    opaque identifiers returned by Graph itself. They are NOT local filesystem
    paths, NOT user-supplied URLs, and NOT shell fragments. Real production
    Graph drive ids contain characters such as ``!`` (the documented base64url
    + base64 encoded ``b!`` prefix for OneDrive for Business drives).

    Validation contract:

    * Reject empty / non-string values.
    * Reject values above :data:`_OPAQUE_MAX_LEN` characters.
    * Reject control characters (U+0000..U+001F, U+007F), CR, LF and NUL.
    * Permit the printable characters Microsoft Graph can emit (including
      ``!``, ``_``, ``-``, ``.``, alphanumerics, base64 ``+/=``).
    * Path-traversal protection and URL-injection protection for opaque
      Graph IDs is provided by the Graph request builder
      (:func:`securedact_core.connectors.microsoft.browser._quote_path_segment`),
      which URL-encodes the value into a single path segment, NOT by a
      restrictive character allowlist.
    """

    if not isinstance(value, str) or not value:
        raise InvalidResourceIdentifierError(f"{field} must be a non-empty string")
    if len(value) > _OPAQUE_MAX_LEN:
        raise InvalidResourceIdentifierError(f"{field} exceeds maximum length")
    if any(ch in _OPAQUE_FORBIDDEN_CONTROL for ch in value):
        raise InvalidResourceIdentifierError(f"{field} contains a control character")
    return value


class ResourceKind(StrEnum):
    """The kind of resource a connector is normalizing.

    The model is intentionally not file-only: future connectors (GitHub,
    Slack, Jira, Salesforce, ...) map cleanly onto these without forcing a file
    abstraction.
    """

    FILE = "file"
    DOCUMENT = "document"
    MESSAGE = "message"
    RECORD = "record"
    ISSUE = "issue"
    PAGE = "page"
    COMMENT = "comment"
    ATTACHMENT = "attachment"
    REPO_CONTENT = "repo_content"


class ConnectorCapability(StrEnum):
    """Capability-oriented connector declaration.

    A connector advertises only the subset it implements. Unimplemented
    capabilities are simply absent from the declared set; a connector must never
    implement meaningless operations purely to satisfy a monolithic interface.
    """

    READ = "read"
    SCAN = "scan"
    WRITE = "write"
    LIST = "list"
    WATCH = "watch"
    METADATA = "metadata"
    PERMISSIONS = "permissions"
    QUARANTINE = "quarantine"
    UI_ACTIONS = "ui_actions"
    ANNOTATIONS = "annotations"
    CHECKS = "checks"


class ConnectorResource(BaseModel):
    """A normalized description of an external resource.

    This is the contract object that flows from a connector into the SecuRedact
    service boundary. It carries identity and metadata only; raw bytes are not
    embedded. ``org_id`` and ``tenant_id`` are the isolation keys that the
    control plane enforces server-side.
    """

    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(min_length=1, max_length=512)
    platform: str = Field(min_length=1, max_length=64)
    resource_kind: ResourceKind
    org_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    parent_id: str | None = Field(default=None, max_length=512)
    name: str = Field(default="", max_length=512)
    mime_type: str | None = Field(default=None, max_length=256)
    size_bytes: int | None = Field(default=None, ge=0, le=2_147_483_647)
    external_url: str | None = Field(default=None, max_length=2048)
    sensitivity_context: dict[str, Any] = Field(default_factory=dict)
    content_ref: str | None = Field(default=None, max_length=512)
    extracted_text: str | None = Field(default=None)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_identifiers(self) -> ConnectorResource:
        validate_resource_identifier(self.resource_id, field="resource_id")
        validate_resource_identifier(self.org_id, field="org_id")
        validate_resource_identifier(self.tenant_id, field="tenant_id")
        if self.parent_id is not None:
            validate_resource_identifier(self.parent_id, field="parent_id")
        if self.content_ref is not None:
            validate_resource_identifier(self.content_ref, field="content_ref")
        return self


class ConnectorIdentity(BaseModel):
    """Server-resolved identity context for a connector operation.

    This is built entirely server-side from the authenticated user and the
    organization/integration the request was authorized against. It must never
    be populated from trusted client input alone.
    """

    model_config = ConfigDict(extra="forbid")

    org_id: str = Field(min_length=1, max_length=128)
    integration_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    platform: str = Field(min_length=1, max_length=64)
    user_id: str | None = Field(default=None, max_length=128)


class ScanContext(BaseModel):
    """Request context for a connector scan.

    Mirrors the policy/response controls of the core ``RedactionRequest`` so the
    connector layer can reuse the engine without re-implementing policy logic.
    """

    model_config = ConfigDict(extra="forbid")

    policy: str = Field(default="strict_external_ai", pattern=r"^[a-z][a-z0-9_]{0,63}$")
    language: Literal["auto", "en", "nl"] = "auto"
    correlation_id: str | None = Field(default=None, max_length=128)
    response_mode: Literal["minimal", "review"] = "minimal"


class NormalizedContent(BaseModel):
    """Connector-owned normalized text + structural metadata for the engine."""

    model_config = ConfigDict(extra="forbid")

    text: str
    source_format: str | None = Field(default=None, max_length=64)
    char_count: int = Field(default=0, ge=0)
