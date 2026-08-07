# kiwi-catalog 功能文档

> 状态：对应 `main` 分支当前实现（2026-08-07，118 passed / 6 skipped；
> v0.4 Product-first Commerce Discovery 已落地）。
> 本文描述**已实现**的功能面，不含设计文档中规划但未落地的部分
> （如 PG/Redis 多实例限流、验证阶梯的第三方互操作证据、FTS/vector 搜索）。

kiwi-catalog 是 Kiwi A2A 商业协商网络的 **Agent Catalog 服务**——从
shopping-cli 抽离的独立部署目录（切割分水岭：**不含托管协商与 marketplace
域**）。它回答两个问题：*「网络里有哪些可协商的 commerce agent，它们的
状态如何，是否可信」*（Agent 域），以及 *「谁可能有我要的商品/能力」
*（v0.4 Listing 域，Product-first Commerce Discovery）*。

---

## 1. 核心能力总览

| 能力域 | 入口 | 说明 |
| --- | --- | --- |
| 注册/发布 | `POST /v1/agents/register` + hosted 发布面 | self_registered / hosted 两类来源；一商家一 agent；public-only 白名单字段落库 |
| 验证 | `POST /v1/agents/{id}/verify` / `refresh` | §6 五阶验证阶梯 + 三正交状态域 + 持久验证队列 |
| 发现/搜索 | `GET /v1/agents/search` | 多维度硬过滤 + 确定性排序 + cursor 分页 |
| 治理 | `suspend` / `reinstate` / `claim` | admin 处置、owner 认领、审计事件、双维度限流 |
| Listing（v0.4） | `POST /v1/listings/publish` + `/v1/listings/search` | ProductListing/CapabilityListing 发布、搜索、下架、恢复（public-only discovery projection） |
| Listing 治理联动 | agent `suspend` | owned Listings 同事务置 SUSPENDED + 搜索 join 排除（DoD #12） |
| 观测 | `GET /health` + CLI `stats` / `doctor` | §24 runtime metrics |

## 2. API 面

### 2.1 双栈实现

`create_catalog_app()` 优先返回 **FastAPI** 应用（全部 catalog 路由与
fallback 共享同一 handler 层）；FastAPI 不可用时回退 **fallback ASGI**。
两条栈的响应/异常映射行为一致（有测试锁定）。

### 2.2 路由清单

| 方法 | 路径 | 功能 |
| --- | --- | --- |
| GET | `/health` | 健康检查 |
| GET | `/v1/agent-catalog/agents` | 列出 catalog agents（legacy 面） |
| GET | `/v1/agent-catalog/agents/search` | 搜索（legacy 面，支持 q/category/skill/capability/protocol/hosting-mode/verification-status/verified-after/cursor） |
| GET | `/v1/agent-catalog/agents/{id}` | 单个 agent 详情 |
| GET | `/v1/agent-catalog/merchants/{merchant_id}/agents` | 按商家列出 agents |
| POST | `/v1/agent-catalog/agents/register` | 注册 self_registered agent（legacy 面） |
| POST | `/v1/agent-catalog/agents/{id}/refresh` | 显式刷新（重抓 profile + 重跑阶梯） |
| POST | `/v1/agent-catalog/agents/{id}/verify` | 同步跑验证阶梯 |
| POST | `/v1/agent-catalog/agents/{id}/claim` | owner 认领（domain-control / hosted 身份证明） |
| POST | `/v1/agent-catalog/agents/{id}/suspend` | admin 处置：挂起 |
| POST | `/v1/agent-catalog/agents/{id}/reinstate` | admin 处置：恢复（重置为 discovered + 重验证） |
| GET | `/v1/agents` | 列出（v1 面，三态域过滤） |
| GET | `/v1/agents/search` | 搜索（v1 面：三态域 + KTH destination_type 词表过滤） |
| GET | `/v1/agents/{id}` | 单个 agent（v1 面） |
| POST | `/v1/agents/register` | 注册（v1 面，public-only 白名单 + 词表校验） |
| POST | `/v1/agents/{id}/refresh` / `verify` / `claim` | v1 面对应动作 |
| GET | `/v1/hosted/agents/{id}/agent-card.json` | hosted 发布面：Agent Card |
| GET | `/v1/hosted/agents/{id}/ucp` | hosted 发布面：UCP profile |
| GET | `/v1/listings/search` | Listing 搜索（v0.4：JSON1 结构化过滤 + agent join 排除 + 确定性排序 + cursor） |
| GET | `/v1/listings/{id}` | 单个 Listing（public-only 投影） |
| GET | `/v1/agents/{id}/listings` | publisher 自查（支持 `?freshness_state=STALE` 过期项） |
| POST | `/v1/listings/publish` | 发布/upsert Listing（owner token + 五步幂等 + digest 去重锚点） |
| POST | `/v1/listings/{id}/withdraw` | publisher 主动下架 |
| POST | `/v1/listings/{id}/reinstate` | SUSPENDED → ACTIVE（publisher/governance） |

### 2.3 v1 面（`/v1/agents/*`）与 legacy 面（`/v1/agent-catalog/*`）

两套面共享同一存储与服务层：

- **legacy 面**：`verification_status` 单列过滤（折叠投影）；
- **v1 面**：三正交状态域（`verification_level` / `freshness_state` /
  `administrative_state`）+ `handoff_destination_types` 精确词表过滤，
  `hosting_mode` 接受 canonical + legacy 别名，响应经 contract schema
  （`additionalProperties: false`）校验。

## 3. 验证阶梯（§6）

### 3.1 五阶证据链

```
discovered → profile_valid → domain_verified → agent_verified → commerce_verified
```

每阶由对应 stage 推进（`_stage_domain` / `_stage_identity` / `_stage_commerce`），
不可跳级；profile 抓取失败只动 freshness（保留最后已验证级别与快照）。

### 3.2 三正交状态域（v0.3 §7）

| 域 | 取值 | 语义 |
| --- | --- | --- |
| `verification_level` | discovered → commerce_verified（5 阶） | 证据链级别，只进不退（除非重验证重入） |
| `freshness_state` | fresh / stale / unreachable | profile 新鲜度 |
| `administrative_state` | active / suspended / rejected | 治理处置（终态，可经 reinstate / 重新注册恢复） |

legacy `verification_status` 保留为**折叠投影**（优先级 rejected > suspended >
unreachable > stale > level），legacy 消费方与指标继续读它。任何写入口
（insert / update / set_verification_status）都经 `_domains_for_legacy_status`
同步三域，折叠与三域永不漂移（有回归测试锁定）。

### 3.3 持久验证队列（v3.0-P4）

- 有界内存队列 + **ledger 写穿**（`verification_queue_tasks` 表）；
- 每任务独立 SQLite 连接（不跨线程共享）、每任务 wall-clock 超时；
- 超时后 supervisor 通知 runaway 线程放弃（**不再改写 ledger 结果**，
  与调用方拿到的 timeout 一致）；
- crash recovery：重启后 pending/running 行重新入队（所有任务幂等）；
- 队列满 → fail-closed（注册仍成功但显式标注未入队，可稍后 verify）；
- 单任务异常不杀 worker（并发预算不丢失）。

### 3.4 profile 抓取（SSRF-safe fetcher）

- socket 级防护：先解析全部 IP 逐一校验（含 IPv4-mapped IPv6、CGNAT、
  metadata 端点），连接直打已校验 IP（**DNS rebinding 免疫**）；
- 重定向完整复验且 fail-closed、端口/scheme 白名单、流式 1MiB 截断、
  JSON 深度/节点双限；
- **条件请求**：带 etag/last-modified 抓取，304 → 复用最新快照的 raw JSON
  （内容未变不重新解析、不失败）；
- secret 扫描：profile 含 secret-like 字段即拒绝，绝不落库。

## 4. 治理与安全

### 4.1 认证

| token | 来源 | 用途 |
| --- | --- | --- |
| admin token | `KIWI_CATALOG_ADMIN_TOKEN` | suspend/reinstate/verify（moderation） |
| catalog-owner token | `KIWI_CATALOG_OWNER_TOKEN_SECRET` 派生 HMAC | claim/refresh（owner 语义，请求体 `owner_token` 字段） |
| verification worker token | `SHOPPING_VERIFICATION_WORKER_TOKEN` | 验证 worker 动作 |

### 4.2 幂等与限流（SQLite 原子实现）

- 写端点幂等：`agent_catalog_write_idempotency` 表（endpoint+actor+key →
  request_hash 冲突检测，replay 返回首次响应）；
- 双维度限流：per-actor 写限流（env 可配）+ 公共注册 per-domain 限流
  （`agent_catalog_register_limits`）；`limit<=0` 的 env 误配回退默认值
  （不静默关闭限流）；
- 请求体大小上限（`KIWI_CATALOG_MAX_REQUEST_BODY_BYTES`，1KB–16MB）。

### 4.3 审计

所有写动作（注册/验证/挂起/认领/刷新）落 `audit_events` 影子表，
带 actor 与结构化 details。

## 5. 数据模型

14 张表（`db/models.py` 单一 SCHEMA 源 + `db/migrations.py` 迁移链 v1–v10，
两路径产出同一表集合，有测试锁定）：

- **catalog 域**：catalog_agents（含三域列 + handoff_destination_types）、
  agent_endpoints、agent_capabilities、agent_skills、agent_profile_snapshots、
  agent_verifications；
- **治理域**：agent_catalog_register_limits、agent_catalog_write_idempotency、
  agent_catalog_write_rate_limits、a2a_inbound_idempotency、
  verification_queue_tasks、agent_trust_observations；
- **listing 域（v10）**：commerce_listings（listing 类型/owner 绑定/upsert
  key 双轨/JSON 投影列/发布与新鲜度状态；partial unique 兜底行级幂等）；
- **影子域**：merchants（public 字段）、audit_events、meta。

要点：

- **弱引用**：对 merchants/agents 外部表无 FK（独立 schema，跨库不依赖）；
  一商家一 agent 由部分唯一索引兜底（服务层给明确 ConflictError）；
- **public-only**：register 只读白名单字段（display_name/hosting_mode/
  handoff/capabilities/skills），未识别字段不落库（完成定义 #8）；
- **幂等 upsert**：`ON CONFLICT` 语义，re-register 即"重新打开"（行政终态
  可恢复，三域一致归位）。

## 6. CLI 面

```
kiwi-catalog catalog search|get|register|verify|refresh|claim|suspend|reinstate|stats|doctor
```

- `search`：与 API 同维度的过滤 + `--format text|json` + cursor 分页；
- `verify` / `refresh`：同步跑阶梯（CLI 侧无队列，直接执行）；
- `suspend` / `reinstate`：admin 处置（`--admin-token`）；
- `stats` / `doctor`：本地 §24 指标与健康检查（doctor 有问题退出码 1）。

## 7. 部署

- **容器**：`Dockerfile`（SQLite 落持久卷）；
- **VM**：`deploy/systemd/kiwi-catalog.service`（systemd 守护 + 环境文件）；
- **多实例**：PG + Redis 限流是 P3/P5 接缝（未实现，单实例 SQLite 为当前形态）；
- 目标形态是 VM/容器（fetcher 需要真实网络栈），**不要在无网络栈的
  serverless（如 Cloudflare Workers）上部署**。

## 8. 测试与已知边界

- 118 passed / 6 skipped（FastAPI 条件 skip）；覆盖：三态域迁移与折叠、
  幂等/限流、SSRF fetcher、影子表、仓库抽象防接口漂移、验证队列执行模型、
  迁移路径与 fresh SCHEMA 一致、Listing 域（publish 契约/幂等 upsert/
  搜索/新鲜度惰性翻转/agent 治理联动/dualstack 路由）。
- **未实现/接缝**：PG+Redis 多实例限流（P3/P5）；验证阶梯的第三方互操作
  证据（wire 级）；`agent_trust_observations` 的写入方（表已建，消费在
  后续版本）；`reported_external_conversion` 类外部成交指标不在本服务范围；
  FTS/vector/语义搜索（v0.4 §8 MAY）；`/v1/listings/bulk-publish` 与
  listing_public_snapshots 历史快照表（v0.4 §14 optional）；refresh webhook
  （catalog → publisher 主动通知，v0.4 §15.1 MAY）。
