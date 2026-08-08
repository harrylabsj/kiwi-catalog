# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shared helpers for hosted A2A publication builders (PRIVATE).

Not part of the public ``kiwi_catalog.a2a`` API surface.  These helpers
enforce the publication invariants shared by the Agent Card and UCP Profile
builders:

* §5.1 / §14: only ``source_type=hosted`` + ``lifecycle_status=active``
  catalog agents are publishable — anything else is indistinguishable from an
  unknown id (same NotFoundError, no existence oracle);
* base_url rule: http/https with no userinfo (the shared-host authority);
* §14.1 shared-host agent path: ``https://<host>/a2a/agents/{catalog_agent_id}``;
* §3.4 public-field boundary via the shared serializers.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §14, §5.1, §3.4
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from kiwi_catalog.core.errors import NotFoundError, ValidationError


def validate_base_url(base_url: str) -> str:
    """Validate and normalize the shared-host base URL.

    Rules: http/https scheme, a hostname present, and no userinfo.  The
    trailing slash is stripped so callers can join path segments safely.
    """
    raw = str(base_url or "").strip()
    if not raw:
        raise ValidationError("base_url is required to build hosted A2A documents")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            f"base_url must be an http(s) URL, got {parsed.scheme!r}"
        )
    if not parsed.hostname:
        raise ValidationError("base_url must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("base_url must not contain userinfo")
    return raw.rstrip("/")


def load_hosted_agent(conn: Any, catalog_agent_id: str) -> dict[str, Any]:
    """Load a publishable catalog agent or raise NotFoundError.

    Only ``source_type=hosted`` and ``lifecycle_status=active`` agents are
    publishable.  Non-hosted / non-active / unknown ids all raise the same
    NotFoundError so the route never reveals which case applied.
    """
    from kiwi_catalog.agent_catalog.sqlite_repository import (
        get_catalog_agent_with_merchant,
    )

    cagt_id = str(catalog_agent_id or "").strip()
    row = get_catalog_agent_with_merchant(conn, cagt_id)
    if row is None:
        raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")
    if str(row.get("source_type") or "") != "hosted":
        raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")
    if str(row.get("lifecycle_status") or "") != "active":
        raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")
    return row


def agent_card_url(base_url: str, catalog_agent_id: str) -> str:
    """§14.1 shared-host agent path for a catalog agent."""
    # 审查 P3：id 拼 URL 前 percent-encode（路由层禁 "/" 只是兜底，id 里
    # 的 ?#% 等字符此前会破坏 URL 语义）。
    return f"{validate_base_url(base_url)}/a2a/agents/{urllib.parse.quote(str(catalog_agent_id), safe='')}"


def merchant_public_ref(row: dict[str, Any]) -> dict[str, Any]:
    """Project the joined merchant block through the §3.4 public serializer."""
    from kiwi_catalog.agent_catalog.serializers import public_merchant_ref

    merchant = {
        "id": row.get("merchant_id", ""),
        "name": row.get("merchant_name", ""),
        "city": row.get("merchant_city", ""),
        "service_area": row.get("merchant_service_area", ""),
        "tags_json": row.get("merchant_tags_json", "[]"),
    }
    return public_merchant_ref(merchant) or {}


def display_name(
    row: dict[str, Any],
    merchant_ref: dict[str, Any],
    catalog_agent_id: str,
) -> str:
    """Pick the agent's public display name (display_name → merchant → id)."""
    return (
        str(row.get("display_name") or "")
        or str(merchant_ref.get("name") or "")
        or str(row.get("merchant_name") or "")
        or catalog_agent_id
    )


def publication_description(row: dict[str, Any], merchant_ref: dict[str, Any]) -> str:
    """Synthesize a factual, public-only description from merchant metadata.

    The catalog schema has no free-text description column, so the published
    documents carry a deterministic projection of public merchant fields
    (name, city, service_area).  Natural-language description fields are DATA
    (§17.2) — nothing here is interpreted as an instruction downstream.
    """
    name = str(
        merchant_ref.get("name")
        or row.get("merchant_name")
        or row.get("display_name")
        or ""
    ).strip()
    location = " · ".join(
        x
        for x in (
            str(merchant_ref.get("city") or ""),
            str(merchant_ref.get("service_area") or ""),
        )
        if x
    )
    parts = ["Hosted commerce agent"]
    if name:
        parts.append(f"for {name}")
    if location:
        parts.append(f"serving {location}")
    return " — ".join(parts) + "."
