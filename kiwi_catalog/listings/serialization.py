"""Listing 公开序列化器（产品文档 v0.4 §9；wire 契约权威在 kiwi 仓）。

**必须逐字节对齐** contracts/kiwi-catalog/1.0/listing-record.schema.json 与
listing-search-result.schema.json（M1）：字段名、枚举大小写、authority 常量。
教训（agent_catalog/serializers.py：绝不 _strip_private 后当公开输出——
显式白名单构造；字段缺省输出空串而非 null 与 kiwi 侧 decode 语义一致）。

Listing 是 public-only discovery projection：这里只透传已经过 contracts 校验
的 canonical 字段；任何新字段先进 schema + contracts 白名单，再进本文件。
"""

from __future__ import annotations

import secrets
from typing import Any

from kiwi_catalog.agent_catalog.state_domains import DISCOVERED
from kiwi_catalog.listings.domain import FRESH, STALE

_LISTING_ID_PREFIX = "lst_"


def new_listing_id() -> str:
    """生成 listing_id（lst_ + 20 hex，参照 new_catalog_agent_id 先例）。"""
    return f"{_LISTING_ID_PREFIX}{secrets.token_hex(10)}"


def listing_record(row: dict[str, Any]) -> dict[str, Any]:
    """Row（已解码 json 列）→ listing-record.schema.json 形状（逐字段白名单）。"""
    attributes = row.get("attributes_json") or {}
    commercial_hints = row.get("commercial_hints_json") or {}
    handoff = row.get("handoff_destination_types_json") or []
    result: dict[str, Any] = {
        "listing_id": str(row.get("listing_id") or ""),
        "listing_type": str(row.get("listing_type") or ""),
        "owner_agent_id": str(row.get("owner_agent_id") or ""),
        "merchant_id": str(row.get("merchant_id") or ""),
        "title": str(row.get("title") or ""),
        "category": str(row.get("category") or ""),
        "listing_digest": str(row.get("listing_digest") or ""),
        "publication_state": str(row.get("publication_state") or ""),
        "listing_freshness_state": str(row.get("listing_freshness_state") or ""),
        "published_at": str(row.get("published_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
        "fresh_until": str(row.get("fresh_until") or ""),
    }
    source_ref = row.get("source_product_ref")
    if source_ref:
        result["source_product_ref"] = str(source_ref)
    source_revision = row.get("source_revision")
    if source_revision:
        result["source_revision"] = str(source_revision)
    summary = row.get("summary")
    if summary:
        result["summary"] = str(summary)
    brand = row.get("brand")
    if brand:
        result["brand"] = str(brand)
    if attributes:
        result["attributes"] = attributes
    regions = row.get("regions_json")
    if regions:
        result["regions"] = list(regions)
    tags = row.get("tags_json")
    if tags:
        result["tags"] = list(tags)
    if commercial_hints:
        result["commercial_hints"] = commercial_hints
    if handoff:
        result["handoff_destination_types"] = list(handoff)
    return result


def listing_search_result(
    row: dict[str, Any],
    merchant: dict[str, Any] | None,
    agent: dict[str, Any] | None,
) -> dict[str, Any]:
    """单个搜索结果（v0.4 §9；CD #24 恒值 authority / requires_direct_confirmation）。

    *merchant*: merchants 影子表 public 投影；*agent*: catalog_agents join
    投影（verification/freshness/admin 三态）。
    """
    record = listing_record(row)
    result: dict[str, Any] = {
        "listing": record,
        "merchant": {
            "merchant_id": str((merchant or {}).get("merchant_id") or ""),
            "display_name": str((merchant or {}).get("display_name") or ""),
        },
        "agent": {
            "catalog_agent_id": str((agent or {}).get("catalog_agent_id") or ""),
            "verification_level": str((agent or {}).get("verification_level") or ""),
            "freshness_state": str((agent or {}).get("freshness_state") or ""),
            "administrative_state": str((agent or {}).get("administrative_state") or ""),
        },
        "listing_freshness_state": str(row.get("listing_freshness_state") or ""),
        "authority": "discovery_projection",
        "requires_direct_confirmation": True,
    }
    return result


def merchant_projection(merchant_row: dict[str, Any] | None) -> dict[str, Any] | None:
    """merchants 影子表行 → 搜索结果的 merchant 投影（弱引用：无行则 None）。"""
    if merchant_row is None:
        return None
    return {
        "merchant_id": str(merchant_row.get("id") or ""),
        "display_name": str(merchant_row.get("name") or ""),
    }


def agent_projection(agent_row: dict[str, Any] | None) -> dict[str, Any] | None:
    """catalog_agents 行 → 搜索结果的 agent 投影（三态域；不复制 endpoint）。"""
    if agent_row is None:
        return None
    return {
        "catalog_agent_id": str(agent_row.get("catalog_agent_id") or ""),
        "verification_level": str(agent_row.get("verification_level") or DISCOVERED),
        "freshness_state": str(agent_row.get("freshness_state") or "fresh"),
        "administrative_state": str(agent_row.get("administrative_state") or "active"),
    }
