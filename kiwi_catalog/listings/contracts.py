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

"""Listing publish 契约校验（产品文档 v0.4 §4/§5/§6.1；升级计划 §5）。

publish payload 是 untrusted remote content（v0.4 §19）：白名单字段 +
per-type required（product→source_product_ref 必填；capability 不得带
handoff_destination_types）+ JSON bounds + secret scan + 私有字段拒绝。
通过校验的 canonical 形状由 service.py 落库；未识别字段一律拒绝（不落库）。
"""

from __future__ import annotations

import re
from typing import Any

from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.discovery._validation import scan_secrets
from kiwi_catalog.listings.domain import (
    COMMERCIAL_HINTS_KEYS,
    FORBIDDEN_FIELDS,
    LISTING_TYPES,
    PRODUCT,
)

# 请求层认证/幂等字段（不属于 listing 内容；校验前剥离，不进 canonical/request_hash）
_AUTH_FIELDS: frozenset[str] = frozenset({
    "owner_token",
    "_auth_token",
    "_binding_jws",
    "admin_token",
    "idempotency_key",
    "_idempotency_key",
})

# v0.4 §4/§5 wire 字段白名单（对齐 listing-record.schema.json；不含私有字段）。
_PUBLISH_KEYS: frozenset[str] = frozenset({
    "listing_type",
    "owner_agent_id",
    "merchant_id",
    "source_product_ref",
    "publisher_listing_key",
    "source_revision",
    "title",
    "summary",
    "category",
    "brand",
    "attributes",
    "regions",
    "tags",
    "commercial_hints",
    "handoff_destination_types",
    "handoff_destination_ref",  # 每商品成交入口（KTH destination_ref）
    "fresh_until",  # Deprecated wire field retained for legacy signatures.
})

_MAX_STRING_LENGTH = 4096
_MAX_ARRAY_LENGTH = 256
_MAX_HINTS_LENGTH = 256
_SCALAR_TYPES: tuple[type, ...] = (str, int, float, bool)


def _require_str(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    value = value.strip()
    if not allow_empty and not value:
        raise ValidationError(f"{field} must not be empty")
    if len(value) > _MAX_STRING_LENGTH:
        raise ValidationError(f"{field} exceeds {_MAX_STRING_LENGTH} characters")
    return value


def _require_str_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_ARRAY_LENGTH:
        raise ValidationError(f"{field} must be an array of strings (<= {_MAX_ARRAY_LENGTH})")
    return [_require_str(item, f"{field}[{i}]") for i, item in enumerate(value)]


def _validate_commercial_hints(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("commercial_hints must be an object")
    unknown = set(value) - COMMERCIAL_HINTS_KEYS
    if unknown:
        raise ValidationError(f"commercial_hints has unknown keys: {sorted(unknown)}")
    hints: dict[str, Any] = {}
    for key, item in value.items():
        if key == "moq":
            if not isinstance(item, int) or isinstance(item, bool) or item < 1:
                raise ValidationError("commercial_hints.moq must be a positive integer")
            hints[key] = item
        elif key in ("price_range_hint", "availability_hint", "lead_time_hint"):
            hints[key] = _require_str(item, f"commercial_hints.{key}")
        elif key in ("supports_bulk_quote", "supports_customization"):
            if not isinstance(item, bool):
                raise ValidationError(f"commercial_hints.{key} must be a boolean")
            hints[key] = item
        elif key == "fulfillment_regions":
            hints[key] = _require_str_list(item, "commercial_hints.fulfillment_regions")
    return hints


def _validate_attributes(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 64:
        raise ValidationError("attributes must be an object with <= 64 keys")
    attributes: dict[str, Any] = {}
    for key, item in value.items():
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", key):
            raise ValidationError(f"attribute key {key!r} has invalid characters")
        # type() 精确匹配：bool 是 int 子类，isinstance 会放行/误判
        if type(item) not in _SCALAR_TYPES:
            raise ValidationError(f"attribute {key!r} must be a string, number, or boolean")
        if isinstance(item, str) and len(item) > _MAX_STRING_LENGTH:
            raise ValidationError(f"attribute {key!r} exceeds {_MAX_STRING_LENGTH} characters")
        attributes[key] = item
    return attributes


def _validate_handoff_destination_types(value: Any) -> list[str]:
    from kiwi_catalog.agent_catalog.state_domains import HANDOFF_DESTINATION_TYPES

    items = _require_str_list(value, "handoff_destination_types")
    for item in items:
        if item not in HANDOFF_DESTINATION_TYPES:
            raise ValidationError(
                f"handoff_destination_types has unknown value {item!r} (KTH vocabulary single source)"
            )
    return items


def legacy_fresh_until(value: Any) -> str | None:
    """Reproduce the old signed timestamp without using it as a listing deadline."""
    from datetime import UTC, datetime

    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is not None:
            return parsed.astimezone(UTC).replace(microsecond=0).isoformat()
    except (ValueError, OverflowError):
        pass
    return None


def validate_publish_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """校验 + 归一化 publish payload（untrusted remote content，v0.4 §19）。

    Returns the canonicalized fields dict (all JSON-serializable scalars).
    """
    if not isinstance(payload, dict):
        raise ValidationError("publish payload must be an object")
    payload = {key: value for key, value in payload.items() if key not in _AUTH_FIELDS}
    unknown = set(payload) - _PUBLISH_KEYS
    if unknown:
        raise ValidationError(f"publish payload has unknown fields: {sorted(unknown)}")

    forbidden = set(payload) & FORBIDDEN_FIELDS
    if forbidden:
        raise ValidationError(f"publish payload contains forbidden private fields: {sorted(forbidden)}")

    listing_type = _require_str(payload.get("listing_type"), "listing_type")
    if listing_type not in LISTING_TYPES:
        raise ValidationError(f"listing_type must be one of {LISTING_TYPES}")
    owner_agent_id = _require_str(payload.get("owner_agent_id"), "owner_agent_id")
    merchant_id = _require_str(payload.get("merchant_id"), "merchant_id")

    source_product_ref: str | None = None
    publisher_listing_key: str | None = None
    if listing_type == PRODUCT:
        source_product_ref = _require_str(payload.get("source_product_ref"), "source_product_ref")
    else:
        raw_ref = payload.get("source_product_ref")
        if raw_ref is not None:
            raise ValidationError("capability listing must not carry source_product_ref")
        raw_key = payload.get("publisher_listing_key")
        if raw_key is not None:
            publisher_listing_key = _require_str(raw_key, "publisher_listing_key")

    if "handoff_destination_types" in payload and listing_type != PRODUCT:
        raise ValidationError("capability listing must not carry handoff_destination_types")

    canonical: dict[str, Any] = {
        "listing_type": listing_type,
        "owner_agent_id": owner_agent_id,
        "merchant_id": merchant_id,
        "title": _require_str(payload.get("title"), "title"),
        "category": _require_str(payload.get("category"), "category"),
    }
    if source_product_ref is not None:
        canonical["source_product_ref"] = source_product_ref
    if publisher_listing_key is not None:
        canonical["publisher_listing_key"] = publisher_listing_key
    for key, _default in (
        ("summary", ""),
        ("brand", ""),
        ("source_revision", ""),
    ):
        raw = payload.get(key)
        if raw is not None:
            canonical[key] = _require_str(raw, key, allow_empty=True)
    if "attributes" in payload:
        canonical["attributes"] = _validate_attributes(payload["attributes"])
    if "regions" in payload:
        canonical["regions"] = _require_str_list(payload["regions"], "regions")
    if "tags" in payload:
        canonical["tags"] = _require_str_list(payload["tags"], "tags")
    if "commercial_hints" in payload:
        canonical["commercial_hints"] = _validate_commercial_hints(payload["commercial_hints"])
    if "handoff_destination_types" in payload:
        canonical["handoff_destination_types"] = _validate_handoff_destination_types(
            payload["handoff_destination_types"]
        )
    if "handoff_destination_ref" in payload:
        # 每商品成交入口（KTH destination_ref）：URL 类为 https URL，联系/会话
        # 类为 opaque ref。URL 安全性（SSRF）由 handoff 执行侧（url-safety）负责，
        # 这里只做有界字符串校验。
        canonical["handoff_destination_ref"] = _require_str(
            payload["handoff_destination_ref"], "handoff_destination_ref"
        )
    # fresh_until：Listing 上架即永久，字段仍被接受但忽略（服务端统一写永久
    # 哨兵）；不再校验 TTL，也不再影响可见性。

    # secret scan（v0.4 §19：标题/summary/attributes 是 untrusted remote content）
    secrets = scan_secrets(canonical)
    if secrets:
        raise ValidationError(f"publish payload contains secret-like content at: {secrets[:3]}")

    # 分享码链接（WorkBuddy 门禁参数/路径段）不是商品内容：新写入 fail-closed。
    # 普通商品/服务链接（含 WorkBuddy 服务地址本身）保持不变。
    from kiwi_catalog.services.merchant_publications import sanitize_share_code_urls

    if sanitize_share_code_urls(canonical) != canonical:
        raise ValidationError("publish payload contains a share-code link")

    return canonical
