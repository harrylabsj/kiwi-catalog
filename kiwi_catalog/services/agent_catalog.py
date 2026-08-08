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

"""Agent Catalog service layer — search, lookup, and hosted projection.

This module is the single entry point for all agent-catalog use cases.
It delegates persistence to the agent_catalog package and enforces
business invariants (§5.1) and the one-way publication projection (§25).
"""

from __future__ import annotations

from typing import Any

from kiwi_catalog.agent_catalog.search import search_catalog_agents as _search
from kiwi_catalog.agent_catalog.serializers import (
    catalog_agent_detail,
    catalog_agent_write_result,
    catalog_search_result,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    append_catalog_audit,
    get_catalog_agent_with_merchant,
    list_capabilities,
    list_endpoints,
    replace_capabilities,
    upsert_catalog_agent,
)
from kiwi_catalog.core.errors import NotFoundError, ValidationError

# ── Publication policy (§25 Phase 1) ────────────────────────────────────────
# Runtime capabilities (agents.capabilities_json short names) are mapped to
# fully-qualified catalog capability identifiers.  Capabilities NOT in this
# mapping are NOT published — the policy is an explicit allowlist, not a
# pass-through.
#
# §28 DoD#25: the namespace is the reverse-domain of the capability semantic
# owner (harrylabsj.com, owned by the shopping-cli operator) — a production
# namespace, never a documentation placeholder.

_PUBLICATION_CAPABILITY_MAP: dict[str, tuple[str, str]] = {
    "catalog": ("com.harrylabsj.shopping.capability", "catalog"),
    "inventory": ("com.harrylabsj.shopping.capability", "inventory"),
    "delivery": ("com.harrylabsj.shopping.capability", "delivery"),
    "consultation": ("com.harrylabsj.shopping.capability", "consultation"),
}


def _project_capabilities(runtime_capabilities: list[str]) -> list[dict[str, Any]]:
    """Apply publication policy: agents.capabilities_json → agent_capabilities.

    Only capabilities in the explicit allowlist are projected.  Unknown
    runtime capabilities are silently dropped (fail-closed).
    """
    projected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in runtime_capabilities:
        name = str(name).strip()
        if not name or name in seen:
            continue
        mapping = _PUBLICATION_CAPABILITY_MAP.get(name)
        if mapping is None:
            continue  # not in publication allowlist → drop
        seen.add(name)
        projected.append({
            "namespace": mapping[0],
            "capability_id": mapping[1],
            "version": "",
            "required": 1,
            "source": "hosted_runtime_projection",
            "schema_url": "",
            "spec_url": "",
        })
    return projected


# ── Invariant enforcement (§5.1) ────────────────────────────────────────────


def _validate_hosting_invariant(
    source_type: str,
    verification_status: str,
    hosted_runtime_agent_id: str,
) -> None:
    """Enforce §5.1 invariants for published catalog records.

    - hosted + COMMERCE_VERIFIED → hosted_runtime_agent_id MUST be non-empty
    - non-hosted + COMMERCE_VERIFIED → hosted_runtime_agent_id MUST be empty
    """
    if verification_status != "commerce_verified":
        return  # invariants only apply at publish time

    is_hosted = source_type == "hosted"
    has_runtime = bool(str(hosted_runtime_agent_id or "").strip())

    if is_hosted and not has_runtime:
        raise ValidationError(
            "§5.1: hosted catalog agent with verification_status=commerce_verified "
            "MUST have a non-empty hosted_runtime_agent_id"
        )
    if not is_hosted and has_runtime:
        raise ValidationError(
            "§5.1: non-hosted catalog agent with verification_status=commerce_verified "
            "MUST have an empty hosted_runtime_agent_id"
        )


# ── Public API ──────────────────────────────────────────────────────────────


def search_catalog_agents(
    conn: Any,
    q: str = "",
    category: str = "",
    skill: str = "",
    capability: str = "",
    protocol: str = "",
    hosting_mode: str = "",
    verification_status: str = "",
    verified_after: str = "",
    verification_level: str = "",
    freshness_state: str = "",
    administrative_state: str = "",
    handoff_destination_types: str = "",
    limit: int = 20,
    cursor: str = "",
) -> dict[str, Any]:
    """Search the Commerce Agent Catalog.

    Every non-empty filter narrows the result set (AND semantics).
    Results follow the §8.2 Search Result Contract — each entry is a
    Candidate, not a verified live identity.  三正交状态域过滤（v0.3 §8）：
    verification_level / freshness_state / administrative_state /
    handoff_destination_types（KTH destination_type 词表，逗号分隔）。

    Returns {"results": [...], "next_cursor": str|None}.
    """
    limit = max(1, min(int(limit), 100))

    rows, next_cursor = _search(
        conn,
        q=str(q or "").strip(),
        category=str(category or "").strip(),
        skill=str(skill or "").strip(),
        capability=str(capability or "").strip(),
        protocol=str(protocol or "").strip(),
        hosting_mode=str(hosting_mode or "").strip(),
        verification_status=str(verification_status or "").strip(),
        verified_after=str(verified_after or "").strip(),
        verification_level=str(verification_level or "").strip(),
        freshness_state=str(freshness_state or "").strip(),
        administrative_state=str(administrative_state or "").strip(),
        handoff_destination_types=str(handoff_destination_types or "").strip(),
        limit=limit,
        cursor=str(cursor or "").strip(),
    )

    results: list[dict[str, Any]] = []
    for row in rows:
        cagt_id = str(row.get("catalog_agent_id", ""))
        caps = list_capabilities(conn, cagt_id)
        eps = list_endpoints(conn, cagt_id)
        # Build a merchant-like dict from the joined row
        merchant: dict[str, Any] = {
            "id": row.get("merchant_id", ""),
            "name": row.get("merchant_name", ""),
            "city": row.get("merchant_city", ""),
            "service_area": row.get("merchant_service_area", ""),
            "tags_json": row.get("merchant_tags_json", "[]"),
        }
        results.append(catalog_search_result(
            catalog_agent=row,
            merchant=merchant,
            capabilities=caps,
            endpoints=eps,
        ))

    return {"results": results, "next_cursor": next_cursor}


def get_catalog_agent(conn: Any, catalog_agent_id: str) -> dict[str, Any]:
    """Return the public detail for a single catalog agent (§8.2 contract)."""
    row = get_catalog_agent_with_merchant(conn, str(catalog_agent_id).strip())
    if row is None:
        raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")

    cagt_id = str(row.get("catalog_agent_id", ""))
    caps = list_capabilities(conn, cagt_id)
    eps = list_endpoints(conn, cagt_id)
    merchant: dict[str, Any] = {
        "id": row.get("merchant_id", ""),
        "name": row.get("merchant_name", ""),
        "city": row.get("merchant_city", ""),
        "service_area": row.get("merchant_service_area", ""),
        "tags_json": row.get("merchant_tags_json", "[]"),
    }

    return catalog_agent_detail(
        catalog_agent=row,
        merchant=merchant,
        capabilities=caps,
        endpoints=eps,
    )


def get_catalog_agent_write_detail(conn: Any, catalog_agent_id: str) -> dict[str, Any]:
    """Public detail for write responses (register §10.2 / claim §10.4).

    Same composition as :func:`get_catalog_agent` plus the canonical identity
    fields (``canonical_domain`` / ``source_type``) so a caller that just
    registered or claimed an agent sees the exact identity it acted on.
    """
    row = get_catalog_agent_with_merchant(conn, str(catalog_agent_id).strip())
    if row is None:
        raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")

    cagt_id = str(row.get("catalog_agent_id", ""))
    caps = list_capabilities(conn, cagt_id)
    eps = list_endpoints(conn, cagt_id)
    merchant: dict[str, Any] = {
        "id": row.get("merchant_id", ""),
        "name": row.get("merchant_name", ""),
        "city": row.get("merchant_city", ""),
        "service_area": row.get("merchant_service_area", ""),
        "tags_json": row.get("merchant_tags_json", "[]"),
    }

    return catalog_agent_write_result(
        catalog_agent=row,
        merchant=merchant,
        capabilities=caps,
        endpoints=eps,
    )


def ensure_hosted_catalog_agent(
    conn: Any,
    agent_id: str,
    merchant_id: str,
    merchant_name: str = "",
    runtime_capabilities: list[str] | None = None,
) -> dict[str, Any]:
    """Ensure a catalog_agents row exists for a hosted runtime agent.

    This is the one-way projection entry point (§25 Phase 1):
      agents.capabilities_json → publication policy → agent_capabilities

    It is idempotent — calling it multiple times for the same agent_id
    updates the catalog entry (last_seen_at, capabilities) rather than
    creating duplicates.

    §5.1 invariant: hosted + COMMERCE_VERIFIED requires non-empty
    hosted_runtime_agent_id.  This function always satisfies it.
    """
    agent_id = str(agent_id or "").strip()
    merchant_id = str(merchant_id or "").strip()
    if not agent_id:
        raise ValidationError("agent_id is required for hosted catalog projection")
    if not merchant_id:
        raise ValidationError("merchant_id is required for hosted catalog projection")

    catalog_agent_id = f"cagt_{agent_id}"
    caps = list(runtime_capabilities or [])

    # 审查 P1-4a：治理优先——被 admin 处置（suspended / rejected）的 agent
    # 不得被 hosted 投影同步复活（「REJECTED 终态 / 仅 admin reinstate 恢复」
    # 契约）。投影对治理行是无操作：不 upsert、不重置三域、不写审计。
    try:
        governed = get_catalog_agent(conn, catalog_agent_id)
    except NotFoundError:
        governed = None
    if governed is not None and str(governed.get("administrative_state") or "") != "active":
        return get_catalog_agent(conn, catalog_agent_id)

    # ── upsert catalog_agents row ───────────────────────────────────────
    upsert_catalog_agent(
        conn,
        catalog_agent_id=catalog_agent_id,
        merchant_id=merchant_id,
        hosted_runtime_agent_id=agent_id,
        display_name=merchant_name or merchant_id,
        source_type="hosted",
        hosting_mode="hosted",
        verification_status="commerce_verified",
        lifecycle_status="active",
    )

    # ── enforce §5.1 ────────────────────────────────────────────────────
    _validate_hosting_invariant("hosted", "commerce_verified", agent_id)

    # ── one-way projection: runtime capabilities → catalog capabilities ─
    projected = _project_capabilities(caps)
    replace_capabilities(conn, catalog_agent_id, projected)

    # ── audit ───────────────────────────────────────────────────────────
    append_catalog_audit(
        conn,
        catalog_agent_id,
        "system",
        "catalog_agent_registered",
        {
            "agent_id": agent_id,
            "merchant_id": merchant_id,
            "source_type": "hosted",
            "hosting_mode": "hosted",
            "capability_count": len(projected),
        },
    )

    return get_catalog_agent(conn, catalog_agent_id)
