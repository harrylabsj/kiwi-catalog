# CLAUDE.md — kiwi-catalog

kiwi-catalog：独立的 Commerce Agent Catalog 服务（Python FastAPI，v1.1
产品文档 `kiwi-catalog-product-architecture-v0.3` 的实现）。承载 Agent
注册/发现/搜索/验证/治理，**不依赖 shopping-cli 数据库**（弱引用 +
shadow tables），是 kiwi 仓（`<WORKSPACE>/kiwi`）AgentDiscovery 的消费端。

## 与 kiwi 仓的契约（改这里前必读）

- **wire 契约权威在 kiwi 仓**：`contracts/kiwi-catalog/1.0/agent-record.schema.json`
  （additionalProperties: false）。本服务的 `/v1/agents` 响应必须逐字节通过它；
  任何字段变更先改 kiwi 仓 schema + 词表契约测试（`tests/kiwi-catalog-source.test.ts`
  断言 schema enum === kiwi 的 `DESTINATION_TYPES`）。
- **KTH destination_type 词表单一来源**：`kiwi_catalog/agent_catalog/state_domains.py`
  的 `HANDOFF_DESTINATION_TYPES` 与 kiwi 仓 schema 枚举逐值一致（`tests/
  test_state_domains.py` 有断言）；禁止 `supports_*` 平行词表。
- **legacy 兼容红线**：`/v1/agent-catalog/*`（CandidateAgent DTO 1.0 +
  折叠 `verification.status`）必须保留——kiwi 仓 `ShoppingCliCatalogSource`/
  `registerCatalogAgent` 依赖它。折叠优先级：
  rejected > suspended > unreachable > stale > verification_level。
- **license**：Apache-2.0（LICENSE 随包，与 kiwi/shopping-cli 一致）；新代码
  文件必须带 Apache-2.0 license header（与 kiwi 仓文件头约定一致）。

## 架构

- **三正交状态域**（v0.3 §7，MUST NOT 坍缩为一个状态机）：
  - `VerificationLevel`：discovered → profile_valid → domain_verified →
    agent_verified → commerce_verified（promote 一次一级；证据失效按最新未过期
    证据重算降级）；
  - `FreshnessState`：fresh / stale / unreachable（可达性是事实非声誉）；
  - `AdministrativeState`：active / suspended / rejected（REJECTED 终态，
    可重新注册恢复）。
  - 核心在 `kiwi_catalog/agent_catalog/state_domains.py`；服务编排在
    `services/agent_verification.py`。
- **折叠投影**：`catalog_agents.verification_status` 列是 legacy 折叠视图，
  任何三域写入经 `set_state_domains` 同步（永不漂移）；legacy 路由/metrics
  继续读它。
- **API**：`/v1/agents*`（新，record 三态域）+ `/v1/agent-catalog/*`（legacy
  兼容）；双栈（FastAPI / fallback ASGI）共用同一批 handler——
  `tests/test_fastapi_dualstack.py` 要求 fallback 路由 ⊆ FastAPI 路由。

## 常用命令

```sh
python3 -m unittest discover -s tests   # 全量测试（5 skip 为 FastAPI 条件）
docker build -t kiwi-catalog:test .     # 部署冒烟
docker run --rm -p 8601:8600 -e KIWI_CATALOG_OWNER_TOKEN_SECRET=... kiwi-catalog:test
```

## 代码布局（kiwi_catalog/）

- `agent_catalog/` — repository Protocol + sqlite_repository（公开函数必须进
  `tests/test_repository_abstraction.py` 的 `_CATALOG_MAPPING`）、serializers
  （`catalog_agent_record` 是 /v1/agents 序列化器，**不要复用 legacy 的
  `_strip_private`**——它剥 created_at/updated_at，历史教训）、search.py、
  state_domains.py
- `discovery/` — verifier.py（域控制/信任评估）、fetcher.py（SSRF-safe）
- `services/` — agent_catalog.py（search/ensure_hosted）、agent_verification.py
  （verify/mark_stale/suspend/reinstate 三域编排）、agent_catalog_writes.py
  （register/claim，public-only 字段白名单）
- `api/` — app.py（路由表 + FastAPI 双栈）、handlers/agent_catalog.py（v1 +
  legacy handler）、auth.py（admin token / owner token HMAC）、idempotency.py
- `db/` — models.py（SCHEMA）、migrations.py（**新增列先加迁移 vN，幂等
  ALTER + 回填**；user_version 门保证每库只跑一次）

## 约定

- 数据目录/文件 0700/0600；owner token = HMAC-SHA256(secret,
  `kiwi-catalog-owner:{merchant_id}`)。
- fail-closed：任何校验/状态迁移失败抛类型化错误（core/errors.py），不静默
  容错；三域迁移合法性由 state_domains 状态机约束。
- register 只读取白名单公开字段（display_name/hosting_mode/
  handoff_destination_types/capabilities/skills），未识别字段不落库（#8）。
- canonical hosting_mode（direct_only/hosted_only）在写边界归一化为 legacy
  存储值（direct/hosted）——DB CHECK 只收 legacy 4 值。
