"""Listing 域词表单一来源（产品文档 kiwi-catalog v0.4 §4/§5/§7）。

- ``ListingType`` —— product（固定 SKU 搜索投影）/ capability（供给能力，
  无固定 SKU，不虚构 SKU）；
- ``PublicationState`` —— ACTIVE / WITHDRAWN（publisher 主动下架）/
  SUSPENDED（catalog governance 处置）；大写，与 Agent 域小写
  administrative_state 拼写区分（评审 P2-7）；
- ``ListingFreshnessState`` —— FRESH / STALE 两态（v0.4 §7.2），独立于
  Agent 域 freshness_state 三态（fresh/stale/unreachable）；fresh_until
  到期后 on-read 惰性翻转（v0.4 §15.1，无后台进程）。

wire 契约权威在 kiwi 仓 contracts/kiwi-catalog/1.0/listing-record.schema.json
（M1）；本模块与 serialization.py 必须逐字节对齐该 schema。
"""

from __future__ import annotations

# ── ListingType（v0.4 §4/§5）───────────────────────────────────────────────

PRODUCT = "product"
CAPABILITY = "capability"

LISTING_TYPES: tuple[str, ...] = (PRODUCT, CAPABILITY)

# ── PublicationState（v0.4 §7.1）───────────────────────────────────────────

ACTIVE = "ACTIVE"
WITHDRAWN = "WITHDRAWN"
SUSPENDED = "SUSPENDED"

PUBLICATION_STATES: tuple[str, ...] = (ACTIVE, WITHDRAWN, SUSPENDED)

# ── ListingFreshnessState（v0.4 §7.2）──────────────────────────────────────

FRESH = "FRESH"
STALE = "STALE"

LISTING_FRESHNESS_STATES: tuple[str, ...] = (FRESH, STALE)

# ── Freshness TTL（v0.4 §15.1；评审 P1-2 拍板默认值）───────────────────────
# publisher 可在 publish 时声明 fresh_until；无声明时用服务端默认。
DEFAULT_TTL_HOURS: dict[str, int] = {
    PRODUCT: 24,
    CAPABILITY: 7 * 24,
}

# ── commercial_hints 白名单（v0.4 §4.1 七键；additionalProperties:false）──
COMMERCIAL_HINTS_KEYS: frozenset[str] = frozenset({
    "moq",
    "price_range_hint",
    "availability_hint",
    "lead_time_hint",
    "supports_bulk_quote",
    "supports_customization",
    "fulfillment_regions",
})

# ── 私有字段（v0.4 §4.2 Forbidden Fields；schema 层 additionalProperties:false
#    之外，服务层再拒一轮——双保险，绝不落库）───────────────────────────────
FORBIDDEN_FIELDS: frozenset[str] = frozenset({
    "merchant_cost",
    "cost",
    "floor_price",
    "private_inventory",
    "pricing_rule",
    "discount_policy",
    "customer_discount",
    "credential",
    "token",
    "api_key",
    "private_customer_data",
    "principal_memory",
    "credentials",
})

# ── attribute 过滤路径约束（升级计划 §6；JSON1 只对白名单路径 json_extract）──
# attributes 是 publisher 自定义 JSON（无预定义键），MVP 白名单 = 路径格式
# 约束（仅 [A-Za-z0-9_] 段、深度 ≤3），防 json_extract path 注入；语义路径
# 由 search query 的 attribute.<path>=<value> 传入（search.py 校验）。
ATTRIBUTE_PATH_SEGMENT_RE = r"^[A-Za-z0-9_]{1,64}$"
MAX_ATTRIBUTE_PATH_DEPTH = 3

# ── Listing 状态机 ──────────────────────────────────────────────────────────


def require_listing_type(value: str) -> str:
    if value not in LISTING_TYPES:
        raise ValueError(f"unknown listing_type {value!r}: not one of {LISTING_TYPES}")
    return value


def require_publication_state(value: str) -> str:
    if value not in PUBLICATION_STATES:
        raise ValueError(f"unknown publication_state {value!r}: not one of {PUBLICATION_STATES}")
    return value


def require_listing_freshness_state(value: str) -> str:
    if value not in LISTING_FRESHNESS_STATES:
        raise ValueError(
            f"unknown listing_freshness_state {value!r}: not one of {LISTING_FRESHNESS_STATES}"
        )
    return value
