# Phase 3 口径统一：旧聚合表从 access_log 派生或退役——盘点与迁移方案

- 状态：Draft（2026-08-22）
- 范围：kiwi-catalog 仓内部运营统计口径（外部/跨仓无消费方，见 §4）
- 前置：Phase 1（access_log v28）与 Phase 2（access-insights）已落地

---

## 1. 结论速览

| 旧表 | 消费方 | 可从 access_log 重建 | 建议 |
|---|---|---|---|
| `usage_metrics` | dashboard 趋势 + buyer-stats 总量 | ⚠️ 是，但有 2 处口径差异 + 90 天保留上限 | **保留**，access_log 作为旁路新口径，逐步并行不退役 |
| `buyer_keyword_daily` | buyer-stats 关键词排行 | ✅ 是（需精确复刻归一化） | **可从 access_log 派生**（中优先级） |
| `buyer_search_daily` | buyer-stats 去重买家 | ❌ 否（HMAC+salt 日作用域 ≠ SHA-256 无 salt） | **保留**，口径不可替代 |
| `buyer_search_events` | /portal/admin/searches 回看页 | ❌ 否（result_summary 无来源） | **保留**，唯一「买家看到什么」来源 |

**核心结论：Phase 3 不能「整体退役」，只能「单表逐判」。** 其中 2 张表（buyer_search_daily、buyer_search_events）因隐私口径和 result_summary 缺口**不可退役**；`buyer_keyword_daily` 是唯一干净可派生的；`usage_metrics` 可派生但有口径偏差。

---

## 2. 四表逐项盘点

### 2.1 `usage_metrics`（metric × day × count）

**写入**（5 处，均在 handler 内）：`agent_catalog.py:201,933`、`listings.py:148,308`、`merchants.py:156`。
4 metric：`buyer_agent_search` / `buyer_listing_search` / `merchant_self_check` / `listing_publish`。

**读取**：`usage_series()`（dashboard 趋势）→ `/v1/admin/dashboard`；`buyer_stats_summary()`（总量）→ `/v1/admin/buyer-stats`。页面 JS `renderUsage` / `renderBuyerStats`。

**access_log 重建映射**（path 过滤 + UTC 日分组）：
- `buyer_agent_search` ← `surface=buyer_search AND path IN ('/v1/agents/search','/v1/agent-catalog/agents/search')`
- `buyer_listing_search` ← `path='/v1/listings/search'`
- `listing_publish` ← `path='/v1/listings/publish'`
- `merchant_self_check` ← `path='/v1/merchants/self'`

**口径差异**：
1. `merchant_self_check`：access_log 记所有 `/v1/merchants/self`（含 admin-token 查询路径），usage_metrics 只计 token 路径 → access_log 会**多算**。
2. 事件 vs 请求：access_log 记到达中间件的每个请求（含被限流/404/405 拦截），usage_metrics 仅 handler 成功时 +1 → access_log 计数**偏高**。
3. 保留期：usage_metrics 无上限；access_log 默认 90 天 → 超 90 天历史不可重建。

### 2.2 `buyer_keyword_daily`（day × search_type × keyword）

**写入**：`_record_agent_search_event`（agent）/ `_record_listing_search_event`（listing），归一化 `_normalize_keyword()`（NFKC + 去零宽 + 折叠空白 + 小写 + 截 80）。
**读取**：`top_keywords()` → `/v1/admin/buyer-stats` top_keywords / zero_hit_keywords。

**access_log 重建映射**：
- `keyword` ← `query_summary.q`（buyer_search 面记）→ 重放 `_normalize_keyword()`
- `search_type` ← path 派生（agent / listing）
- `searches` ← 非空 q 计数；`zero_results` ← `result_count==0` 计数
- 边界：q 超 500 字符才可能被 query_summary 截断（keyword 截 80，罕见影响）

**结论：可派生**。前提是归一化逻辑与写入端保持一致（同函数复用）。

### 2.3 `buyer_search_daily`（day × metric × buyer_hash）

**写入**：`record_buyer_search()`。`buyer_hash = HMAC-SHA256(KIWI_CATALOG_STATS_SALT, "{day}:{identity}")[0:16]`——**带盐、日作用域、跨天不可关联**（隐私设计，测试锁定）。
**读取**：`buyer_daily_series()` → `/v1/admin/buyer-stats` distinct_buyers / identified_events。

**access_log 重建映射**：
- `identified_events` ← `surface=buyer_search AND actor_kind='buyer'` 计数 ✅
- `unidentified_events` ← 总量 − 已识别 ✅
- `distinct_buyers` ← actor_key 去重 **❌ 语义不同**：actor_key 是 `SHA-256(identity)[0:12]`（**无盐、跨天同 key**），重算 distinct 会 (a) 得到不同 hash 值、(b) **破坏跨天不可关联的隐私设计**（90 天内可画像买家）。

**结论：不可按原口径重建**。「去重买家数」是运营硬指标，保留本表。

### 2.4 `buyer_search_events`（有界原始流，5000 条）

**写入**：`record_search_event()`（含 `result_summary_json`——前 10 条结果投影）。
**读取**：`/v1/admin/searches` → `/portal/admin/searches` 回看页（含命中/未命中徽标）。

**access_log 重建映射**：
- `search_type` / `query` / `result_count` / `created_at` ✅ 可派生
- `result_summary_json`（买家实际看到的前 N 条：listing_id/title、catalog_agent_id/display_name）**❌ access_log 无此字段**

**结论：不可完整重建**。若「买家回看命中内容」能力需要保留，本表不能退役。

---

## 3. 迁移方案（分步）

### Step A（低风险，✅ 2026-08-22 已实现）：`buyer_keyword_daily` 改为从 access_log 派生
- 写路径：保留现有 `record_buyer_keyword`（写入即时、原子累加，保持 dashboard 响应快），**新增** access_log 派生的只读查询函数 `top_keywords_from_access_log()`（`top_keywords` 的 access_log 版），两者并存。
- `/v1/admin/buyer-stats` 的 `top_keywords`/`zero_hit_keywords` 经 `admin_reports._keyword_ranking` 分派数据源，默认 access_log 版，env `KIWI_CATALOG_KEYWORD_SOURCE=buyer_keyword_daily` 回退旧表。
- 验证：双源对账一致（写路径归一化与派生归一化同一 `_normalize_keyword` 函数），测试 `test_keyword_derived_matches_table_double_write` 锁定。

### Step B（可选，谨慎）：`usage_metrics` 增加 access_log 派生视图
- `usage_series_from_access_log()`，按 §2.1 映射。
- 不作为默认数据源（口径偏差存在），只作对账/告警用。

### Step C（不做）：`buyer_search_daily` / `buyer_search_events` 退役
- **明确不建议退役**。前者是隐私设计的硬指标（口径不可替代），后者是唯一「买家看到什么」来源。
- 若要消除双写，可考虑 access_log **增补** `result_summary` 字段（中间件从响应 body 提取前 N 条投影），但那是「access_log 追赶旧表」而非「旧表派生」，成本高、收益低，本期不做。

---

## 4. 契约影响

- **外部无影响**：kiwi / kiwi-buyer / kiwi-merchant / kiwi-dual-test 均不消费这 4 张表或 `/v1/admin/*` 端点（agent 盘点确认）。跨仓契约只涉及买家侧端点。
- **页面契约**：`/portal/dashboard`（dashboard/buyer-stats/access-insights）、`/portal/admin/searches` 是 admin-token 页面，改数据源不破坏页面（响应形状保持）。
- **测试契约**：`test_admin_api`、`test_buyer_stats`、`test_buyer_search_events`、`test_access_log`、`test_route_table`、`test_shadow_tables` 锁端点/DDL。改数据源需同步测试。

---

## 5. 建议

Phase 3 的「单一事实源」目标，对 4 张表只有 1 张（buyer_keyword_daily）能干净达成。建议：
1. **做 Step A**（keyword 派生，中收益、低风险）；
2. **不做 Step C**（两张表口径不可替代，保留双写是合理的——access_log 是新增原始层，旧聚合层继续服务运营指标）；
3. 长期演进方向：如果运营确实只需要「计数」而不要「买家画像/回看」，未来可降级 buyer_search_daily/events；但那是产品决策，不是技术可裁决的。
