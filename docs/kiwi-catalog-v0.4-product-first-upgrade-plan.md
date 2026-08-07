---
title: kiwi-catalog v0.4 Product-first Commerce Discovery Upgrade Plan
version: "0.1"
date: 2026-08-07
status: Implementation Plan
baseline: FEATURES.md — main branch, 66 passed / 5 skipped
---

# kiwi-catalog v0.4 升级实施方案

## 1. Current Baseline to Preserve

本升级以当前已实现能力为硬约束，不重写已有 Agent Catalog：

```text
FastAPI + fallback ASGI shared handlers
/v1/agents/* + legacy /v1/agent-catalog/*
verification ladder
VerificationLevel / AgentFreshnessState / AdministrativeState
persistent verification queue
SSRF-safe profile fetcher
owner/admin/worker authentication
write idempotency
actor/domain rate limiting
audit events
SQLite migrations
hosted Agent Card / UCP publishing
CLI + Docker/systemd
```

目标是“加一层 Listing”，不是“重新做 Catalog”。

## 2. Minimal Code Surface

推荐新包：

```text
kiwi_catalog/
  listings/
    domain.py
    contracts.py
    repository.py
    service.py
    search.py
    policy.py
    serialization.py
```

并复用现有：

```text
auth
idempotency
rate_limit
audit
db/migrations
route/handler abstraction
```

## 3. Migration

新增：

```text
commerce_listings
```

MVP 字段：

```text
id
listing_type
owner_agent_id
merchant_id
source_product_ref nullable
publisher_listing_key nullable
source_revision nullable
title
summary nullable
category
brand nullable
attributes_json
regions_json
tags_json
commercial_hints_json
listing_digest
publication_state
freshness_state
published_at
updated_at
fresh_until
created_at
```

Indexes：

```text
(owner_agent_id)
(listing_type, category)
(publication_state, freshness_state)
(updated_at, id)
partial unique(owner_agent_id, listing_type, source_product_ref)
partial unique(owner_agent_id, listing_type, publisher_listing_key)  # WHERE publisher_listing_key IS NOT NULL
```

不要新增到 Merchant 外部数据库的 FK。

幂等 upsert key：ProductListing 用 `source_product_ref`（必填）；CapabilityListing 用 `publisher_listing_key`（publisher-supplied stable external key，对应产品架构 v0.4 §14；提供时幂等成立，缺省时只能按 id 幂等处理）。

Freshness 判定（MVP，闭环保底）：

```text
publish/upsert 时 fresh_until = now + publisher TTL（无声明用服务端默认：ProductListing 24h / CapabilityListing 7d）
fresh_until < now → STALE（on-read 惰性判定，无后台进程）
STALE Listing 默认搜索降权，可由 query 显式过滤
publisher 自查 GET /v1/agents/{agent_id}/listings?freshness_state=STALE 并重发布
```

## 4. API Increment

```text
GET  /v1/listings/search
GET  /v1/listings/{id}
GET  /v1/agents/{id}/listings
POST /v1/listings/publish
POST /v1/listings/{id}/withdraw
POST /v1/listings/{id}/reinstate    # publisher/governance policy
```

所有 write endpoint 复用现有 owner actor + idempotency + rate limit + audit。

## 5. Publish Contract

允许字段严格白名单。

ProductListing：

```text
listing_type=product
source_product_ref required
```

CapabilityListing：

```text
listing_type=capability
source_product_ref optional/absent
publisher_listing_key optional; stable external key, provides upsert idempotency when present
```

Server 负责：

```text
canonicalize
secret scan
size/depth bounds
digest
ownership validation
upsert
freshness
```

## 6. Search Implementation

第一版不要引入 PG/vector infra 前置依赖。

复用 SQLite 单实例目标，先做：

```text
normalized q
category
brand
region
listing_type
public attributes
commercial hints
agent verification/freshness join
cursor pagination
```

Ranking 必须 deterministic。

Attribute / commercial-hint 过滤的 MVP 实现路径：SQLite JSON1 表达式（json_extract / json_each）作用于 attributes_json / commercial_hints_json 中的白名单字段路径；白名单外的属性不上过滤。若过滤字段集合小而稳定，可后续迁移为显式列，不改变 public contract。

后续可以单独增加 FTS/vector adapter，不改变 public contract。

## 7. Agent Join

Listing Search 查询必须 join/resolve Agent current projection：

```text
listing.owner_agent_id
→ catalog_agents
→ verification/freshness/admin
```

默认搜索 MUST 排除：

```text
owner Agent suspended/rejected
Listing withdrawn/suspended
```

stale 是否返回由 query/policy 控制，并必须显式标注。

Agent suspended/rejected 时：搜索 join 排除 owned Listings，同时 governance 动作将其 publication_state 置为 SUSPENDED（两件事都做）。

## 8. Merchant-side Publication

shopping-cli 新增：

```text
PublicListingProjection
```

它只读取 public/authorized 字段，将：

```text
Product / SKU / Inventory / Price / Delivery
```

压缩为可公开的 discovery projection。

不要把 Catalog 连接到 Merchant ERP 进行主动抓取。

## 9. Buyer-side Integration

Buyer Kiwi 新 happy path：

```text
Need
→ ProductIntent
→ /v1/listings/search
→ shortlist
→ owner_agent_id
→ current Agent Card
→ fresh verify
→ Direct A2A
→ KNP Inquiry/RFQ
```

## 10. Compatibility

必须保持：

```text
/v1/agents/search unchanged
legacy /v1/agent-catalog/* unchanged
verification_status folded projection unchanged
current 13-table behavior unchanged except additive migration
```

## 11. Tests

至少新增：

```text
listing contract allowlist
secret rejection
product/capability listing validation
idempotent publish
publish conflict
withdraw/reinstate policy
agent suspension suppresses listings
listing freshness
q/category/region filters
cursor determinism
agent state join
private fields never serialized
source_product_ref uniqueness
Product-first E2E
```

## 12. Release Gate

不宣布 v0.4 完成，直到：

```text
all existing tests green
new listing tests green
migration fresh/upgrade paths equivalent
FEATURES.md updated only after implementation lands
```
