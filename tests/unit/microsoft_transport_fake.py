# SPDX-License-Identifier: Apache-2.0
"""Microsoft Graph transport double for tests (M365-102).

Minimal in-memory Microsoft Graph v1.0 double (no SDK, no network).
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from securedact_core.connectors.microsoft import (
    CANONICAL_GRAPH_BASE,
    MicrosoftApiError,
)


class FakeMicrosoftTransport:
    """Minimal in-memory Microsoft Graph v1.0 double (no SDK, no network)."""

    def __init__(self, user_id: str = "user-123", tenant_id: str = "tenant-456") -> None:
        self.base_url = CANONICAL_GRAPH_BASE
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.drives: dict[str, dict] = {}
        self.sites: dict[str, dict] = {}
        self.items: dict[str, dict] = {}  # key: "drive_id:item_id"
        self.content: dict[str, bytes] = {}  # key: "drive_id:item_id"
        self._site_drive_map: dict[str, str] = {}  # site_id -> drive_id

    def add_drive(self, **kwargs: object) -> dict:
        item = dict(kwargs)
        self.drives[item["id"]] = item
        return item

    def add_site(self, **kwargs: object) -> dict:
        item = dict(kwargs)
        self.sites[item["id"]] = item
        return item

    def set_site_drive(self, site_id: str, drive_id: str) -> None:
        """Map a site to its default document library drive."""
        self._site_drive_map[site_id] = drive_id

    def add_item(self, drive_id: str, **kwargs: object) -> dict:
        item = dict(kwargs)
        # Ensure parentReference has path for root items
        if "parentReference" in item and item["parentReference"].get("id") == "root":
            item["parentReference"]["path"] = "/drive/root:/"
        key = f"{drive_id}:{item['id']}"
        self.items[key] = item
        return item

    def set_content(self, drive_id: str, item_id: str, data: bytes) -> None:
        self.content[f"{drive_id}:{item_id}"] = data

    def get_json(self, path: str) -> dict[str, Any]:
        path = urllib.parse.unquote(path)

        # me endpoint
        if path == "me" or path.startswith("me?"):
            return {
                "id": self.user_id,
                "userPrincipalName": "test@example.com",
            }

        # organization endpoint
        if path == "organization" or path.startswith("organization?"):
            return {"value": [{"id": self.tenant_id}]}

        # drives
        if path == "drives" or path.startswith("drives?"):
            return {"value": list(self.drives.values())}

        m = re.match(r"drives/([^?/]+)(?:\?(.*))?$", path)
        if m:
            drive_id = m.group(1)
            if drive_id not in self.drives:
                raise MicrosoftApiError("not found", status_code=404)
            return self.drives[drive_id]

        # sites
        if path == "sites" or path.startswith("sites?"):
            return {"value": list(self.sites.values())}

        m = re.match(r"sites/([^?/]+)(?:\?(.*))?$", path)
        if m:
            site_id = m.group(1)
            if site_id not in self.sites:
                raise MicrosoftApiError("not found", status_code=404)
            return self.sites[site_id]

        # site drive - return mapped drive or first documentLibrary
        m = re.match(r"sites/([^/]+)/drive(?:\?(.*))?$", path)
        if m:
            site_id = m.group(1)
            # Check explicit mapping first
            if site_id in self._site_drive_map:
                drive_id = self._site_drive_map[site_id]
                if drive_id in self.drives:
                    return self.drives[drive_id]
            # Fall back to first documentLibrary
            for drive in self.drives.values():
                if drive.get("driveType") == "documentLibrary":
                    return drive
            raise MicrosoftApiError("not found", status_code=404)

        # drive children - root
        m = re.match(r"drives/([^/]+)/root/children(?:\?(.*))?$", path)
        if m:
            drive_id = m.group(1)
            items = [
                it
                for k, it in self.items.items()
                if k.startswith(f"{drive_id}:")
                and it.get("parentReference", {}).get("id") == "root"
            ]
            return {"value": items}

        # drive children - folder
        m = re.match(r"drives/([^/]+)/items/([^/]+)/children(?:\?(.*))?$", path)
        if m:
            drive_id = m.group(1)
            folder_id = m.group(2)
            items = [
                it
                for k, it in self.items.items()
                if k.startswith(f"{drive_id}:")
                and it.get("parentReference", {}).get("id") == folder_id
            ]
            return {"value": items}

        # drive item by id
        m = re.match(r"drives/([^/]+)/items/([^?/]+)(?:\?(.*))?$", path)
        if m:
            drive_id = m.group(1)
            item_id = m.group(2)
            key = f"{drive_id}:{item_id}"
            item = self.items.get(key)
            if item is None:
                raise MicrosoftApiError("not found", status_code=404)
            return item

        raise MicrosoftApiError("unexpected path", status_code=400)

    def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
        # Handle download URLs
        if path.startswith("http"):
            # Extract item info from download URL if possible
            pass

        m = re.match(r"drives/([^/]+)/items/([^?/]+)/content", path)
        if m:
            drive_id = m.group(1)
            item_id = m.group(2)
            key = f"{drive_id}:{item_id}"
            data = self.content.get(key)
            if data is None:
                raise MicrosoftApiError("not found", status_code=404)
            if max_bytes is not None and len(data) > max_bytes:
                raise MicrosoftApiError(
                    "exceeds maximum inspectable size",
                    status_code=413,
                )
            return data

        raise MicrosoftApiError("unexpected content path", status_code=400)
