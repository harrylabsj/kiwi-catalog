# kiwi-catalog Merchant Token 分发与门户设计 v0.1

- Status: Draft（2026-08-08）
- Doc revision: rev0.1
- Product: kiwi-catalog standalone service + kiwi 官网
- 关联：`docs/kiwi-catalog-product-architecture-v0.4.md`、`docs/kiwi-catalog-v0.4-product-first-upgrade-plan.md`、
  审查 `docs/kiwi-catalog整体代码审查-2026-08-08.md`（P1-11 数据权限在本设计一并落地）

## 1. 问题

merchant 要向 kiwi-catalog 注册 Agent 并发布产品 listing，需要 owner token。
现状（`api/auth.py`）：

- owner token = **HMAC-SHA256(secret, `kiwi-catalog-owner:{merchant_id}`)** 确定性派生，
  secret 在服务端 env（`KIWI_CATALOG_OWNER_TOKEN_SECRET`）；
- merchant_id 由调用方自报（`services/agent_catalog_writes.py::_ensure_merchant_shadow`
  INSERT OR IGNORE 影子行），平台没有签发 merchant 身份的环节；
- 无面向 merchant 的 token 分发机制：merchant 算不出自己的 token，只能由平台带外交付。

**硬伤**：HMAC 模型下同一 merchant_id 永远同一 token，**无法单点轮换/吊销**。
泄露只能换 secret（= 全量轮换）或 suspend + 换 merchant_id 重注册。

## 2. 决策（2026-08-08 项目决策）

| 决策点 | 选择 |
| --- | --- |
| Token 模型 | **随机 token 落库**（支持签发/轮换/吊销），HMAC 派生路径保留兼容 |
| 门户承载 | **内嵌 kiwi-catalog 进程**（`/portal/*` 路由），secret 不出进程 |
| 域名 | 官网静态层 + 子域名 `catalog.kiwi.harrylabsj.com`（动态门户 + API，2026-08-08 生产实测已指向阿里云香港节点，Caddy 反代） |

## 3. 数据模型（schema v12）

`merchant_tokens`（每 merchant 至多一条 active）：

```sql
create table if not exists merchant_tokens (
    merchant_id text primary key,
    token_hash text not null,
    status text not null default 'active' check (status in ('active','revoked')),
    issued_at text not null,
    rotated_at text not null default '',
    revoked_at text not null default ''
) without rowid;
```

- `token_hash` = SHA-256(明文 token)（复用 `core/tokens.py::token_digest`）；明文永不落库。
- 明文格式：`mkt_` + 32 字节 urlsafe base64（≈43 字符）。

`merchant_applications`（申请工单）：

```sql
create table if not exists merchant_applications (
    application_id integer primary key autoincrement,
    status text not null default 'pending' check (status in ('pending','approved','rejected')),
    domain text not null,
    agent_name text not null,
    contact_email text not null,
    purpose text not null default '',
    merchant_id text not null default '',
    review_note text not null default '',
    created_at text not null,
    reviewed_at text not null default ''
);
```

DDL 同时进 `db/models.py::SCHEMA`（fresh 路径）与 `db/migrations.py` v12（`test_shadow_tables`
锁定两路径逐字一致）。`CURRENT_SCHEMA_VERSION` 11 → 12。

## 4. Token 生命周期

```
申请(apply, 会话鉴权) → 审核(list/approve/reject, admin) → 签发(approve 原子完成)
→ 交付(明文仅一次) → 使用(注册 agent / 发布 listing) → 轮换(rotate, admin) / 吊销(revoke, admin)
```

### 4.1 申请 `POST /v1/merchants/applications`（会话鉴权）

> 2026-08-12 变更：原为匿名公开通道，生产上被滥用（`y@y.com` 等假邮箱直接
> 提交工单并被误批准），已关闭。该端点改为会话鉴权，与
> `POST /v1/accounts/token-request` 同一处理函数（`handlers/accounts.py`
> `token_request`）：`_require_session` 鉴权 + 按账号限流 +
> `accounts_service.request_token` 建工单，contact_email 取账号邮箱；
> payload 多余字段（contact_email 等）自然忽略。

- body：**只需 `domain`**（店铺规范域名，bare hostname 校验复用
  normalize_canonical_domain）；`agent_name`/`phone` 从账号（注册时填写）
  自动带出，`purpose` 已从申请面移除（保留列与参数仅历史兼容）。contact_email
  取会话账号邮箱。`agent_id` 已从申请面移除——仅归档/展示用，无系统逻辑消费，
  不再要求用户填写（历史 API 调用方仍可携带，服务端接受为可选）。
- 限流：按账号固定窗口（复用登录限流 env，`services/rate_limit.py`）。
- 响应：`{"application_id": N, "status": "pending"}`，不含任何凭证。
- 审计：不落 audit_events；DB 行即工单。

### 4.2 列表 `GET /v1/merchants/applications?status=pending`（admin）

- admin token 必填（fail-closed）。供门户后台渲染待审列表。

### 4.3 签发 `POST /v1/merchants/applications/{id}/approve`（admin）

- 校验：工单存在且 pending；重复 approve → ConflictError。
- 原子完成：生成平台 merchant_id `mkt_<slug>_<rand>`（slug 取 agent_name 拼音化前缀
  的宽松降级：`mkt_` + 8 位 urlsafe 随机串，防撞名、防枚举）；写影子 merchants 行
  （`_ensure_merchant_shadow` 语义，INSERT OR IGNORE 不覆盖外部字段）；写
  `merchant_tokens` active 行；工单置 approved（记 merchant_id/reviewed_at）。
- 响应（**明文 token 仅此一次**）：`{"merchant_id": "...", "token": "mkt_..."}`；
  明文不进审计（审计只记 merchant_id + 事件 + token 指纹 `token_prefix`）。
- 拒绝 `POST /v1/merchants/applications/{id}/reject`（admin）：工单置 rejected + review_note。

### 4.4 轮换 `POST /v1/merchants/{merchant_id}/rotate`（admin）

- 新随机 token 覆盖 active 行（旧 hash 作废），`rotated_at = now`。
- 响应同上：明文 token 仅此一次。
- **轮换故意走 admin，不用"旧 token 自助换新"**：泄露场景下旧 token 可能已在攻击者
  手里，自助轮换 = 攻击者也能轮换。商家联系运营触发。

### 4.5 吊销 `POST /v1/merchants/{merchant_id}/revoke`（admin）

- active 行置 revoked（`revoked_at = now`）；后续所有带该 token 的写请求 fail-closed。
- 级联：可另行 suspend merchant 的 catalog agent（行政处置走既有 `/suspend` 端点）。

### 4.6 自查 `GET /v1/merchants/self?owner_token=…`（merchant 用 token 即身份）

- 服务端按 token hash 解析 merchant_id（GET 无 body，token 经 query string——
  审查 P2 已记录 CLAUDE.md 不修）。
- 响应：`{merchant_id, agents: [...], listings_count, token_status, issued_at}`。

## 5. auth 双路径（`api/auth.py`）

新增 `require_merchant_token(payload, merchant_id, conn)`：

1. 查 `merchant_tokens`：merchant_id 存在且 status=active → SHA-256(呈现值)
   恒时比较 token_hash（`hmac.compare_digest`）；命中返回。
2. 未命中 → fallback 现有 HMAC `owner_token` 校验（存量调用方/CLI/测试兼容）。

既有 `require_owner_token` 保留不动。**所有 merchant 写路径换用双路径**：
- `handlers/agent_catalog.py`：`_require_catalog_write_auth` / `_register_actor` / `_claim_identity`
  （三者已有 conn）
- `handlers/listings.py`：`_require_owner_token_for_merchant`（补 conn 参数）

## 6. 门户页面（`/portal/*`，fallback ASGI 渲染 HTML）

| 路径 | 页面 | 行为 |
| --- | --- | --- |
| `GET /portal/apply` | 申请表单 | 静态 HTML + 内联 JS fetch 提交到 §4.1 API；成功显示 application_id |
| `GET /portal/admin` | 审核后台 | 输入 admin token → fetch 待审列表 → 批准/拒绝 → **一次性展示明文 token**（页面不缓存、不写日志；响应头 `Cache-Control: no-store`） |
| `GET /portal/status` | 商家自查 | 输入 token → fetch §4.6 → 显示 merchant/agent/listing 状态 + 轮换指引 |
| `GET /portal/` | 门户首页 | 三入口导航 |

实现：`handlers/portal.py` 内 HTML 字符串常量（内联 CSS/JS，零新依赖）；响应体
`{"__html__": "..."}` 标记，`fallback_asgi._send_json` 检测该键改发 `text/html`
（ETag/304 语义不变，门户页响应带 `Cache-Control: no-store`）。FastAPI 双栈
同样注册门户页（HTMLResponse），保持 route 覆盖 parity 测试通过；生产 Dockerfile
跑 fallback 栈（`kiwi_catalog_api.py`）。

## 7. 官网（kiwi 仓库 `docs/website/merchants.html`）

- 新增「申请接入」区块：三步说明（提交申请 → 审核签发 → 用 token 发布产品）+
  FAQ（token 是什么/怎么用/遗失怎么办）+ CTA 按钮 → `https://catalog.kiwi.harrylabsj.com/portal/apply`。
- 官网保持纯静态（Cloudflare Pages 放不下动态逻辑）；门户子域名 CNAME 指向
  catalog 部署主机。域名迁移照 `docs/DEPLOY-website.md` 路径执行。

## 8. 安全要求

- 明文 token 只出现在 approve/rotate 响应体，响应日志脱敏；门户页 `no-store`。
- DB 文件权限 0700/0600（审查 P1-11；`db/session.py` 已落地，本设计不新增读写路径）。
- 申请面限流防刷；admin 端点 fail-closed（无默认 token、未配置即拒绝）。
- 审计：approve/rotate/revoke 进 `audit_events`（actor=admin，details 只含
  merchant_id/token_prefix/application_id，**不含明文**）。

## 9. MVP 范围与后续

MVP（本次落地）：schema v12 + auth 双路径 + §4 七端点 + §6 四页面 + 官网 CTA +
CLI（`catalog merchant applications list/approve/reject`、`token rotate/revoke`、
`status`——与 HTTP 共用 `services/merchant_tokens.py`，本地直连 SQLite 信任边界）
+ 测试（双栈全量 191）。

Dashboard（2026-08-08）：运营后台 /portal/dashboard（admin token，env KIWI_CATALOG_PORTAL_ADMIN_ENABLED 默认关）——待审申请审批 + KPI 统计 + 14 天使用趋势（usage_metrics 埋点：buyer 搜索/listing 搜索/商家自查/商品发布）+ 商家列表与报告。生产已开启并验证。

每日去重买家（2026-08-21）：schema v26 buyer_search_daily——搜索 handler 从
Authorization Bearer / X-Buyer-Id 头取买家身份，落库仅日作用域 HMAC 截断 hash
（services/buyer_stats.py，跨天不可关联、不存原始身份；匿名搜索只计入 usage_metrics
总量）。`GET /v1/admin/buyer-stats?days=14`（admin）返回 distinct_buyers /
identified_events / total_events / unidentified_events 日序列 + today；门户页
/portal/admin/buyer-stats（同一 env 开关，默认 404）展示 KPI + 14 天双系列柱状图
+ 明细表。

搜索关键词统计（2026-08-21）：schema v27 buyer_keyword_daily——三个搜索 handler
（/v1/agents/search、legacy /v1/agent-catalog/agents/search、/v1/listings/search）
把归一化 query（trim/折叠空白/小写/80 字符截断；空 query 的 filter-only 搜索不记）
按 day × search_type × keyword 日聚合：searches + 1，零结果时 zero_results + 1
（无保留上限，区别于 buyer_search_events 的 5000 条有界事件流）。
/v1/admin/buyer-stats 响应新增 top_keywords（热门，按搜索次数）与
zero_hit_keywords（未命中 = 供需缺口信号，按未命中次数），窗口同 days、各取前 20；
门户页 /portal/admin/buyer-stats 新增「热门搜索关键词」「未命中关键词（供需缺口）」
两张排行表——后者是运营招商补供给的可行动清单。

门户合并（2026-08-22）：独立页 /portal/admin/buyer-stats 并入运营 Dashboard
（/portal/dashboard）——买家搜索统计（去重买家 KPI + 14 天双系列柱状图 +
明细 + 热门/未命中关键词排行）作为 dashboard 的「买家搜索统计」区块，同一
admin token 输入解锁全页；旧 URL 开启时 302 跳转到 /portal/dashboard
（fallback 栈与 FastAPI 栈均支持响应 ``__redirect__`` 元键），关闭时仍真实
404。/v1/admin/buyer-stats API 端点保留不变。

关键词去重修复（2026-08-22）：运营报告两张关键词排行同一关键词出现多行——
两处根因均已修复：(1) top_keywords 由按 (keyword, search_type) 分组改为按
keyword 跨类型合并（agent_searches / listing_searches 分列两类计数，
/v1/admin/buyer-stats 的 top_keywords / zero_hit_keywords 条目形状随之变为
{keyword, searches, zero_results, agent_searches, listing_searches}；查询期
合并同时并掉归一化升级前的存量行）；(2) 关键词归一化增加 Unicode NFKC +
零宽字符（U+200B/200C/200D/FEFF）删除，全角/半角与兼容字符不再落多行。
门户表格改为「关键词 | 类型分布（找商家 N · 找商品 M）| …」一行一关键词。

访问日志（2026-08-22）：schema v28 access_log——运营原则从「只记次数不记
个体日志」修订为「记录个体访问日志用于运营质量与安全审计；最小必要仍适用
——绝不记录凭据本体，身份一律派生，日志有保留期」。ASGI 中间件在双栈
（fallback / FastAPI）各挂一处共用 `services/access_log.py`：记录每个请求
的 method/path/surface（buyer_search / buyer_detail / merchant_write /
account_portal / admin）/actor（buyer/merchant/admin/anonymous，身份原文
SHA-256 截断 12 hex，绝不存 token 明文）/IP 前缀（IPv4 /24、IPv6 前 4 段，
不存完整 IP）/user-agent/搜索 query 摘要（q + 筛选键值 JSON，凭据参数
owner_token/token/key/password/code 一律剔除）/target_id（路径里的
listing_id/catalog_agent_id/merchant_id）/status/result_count/latency_ms。
`/health` 不记录；保留期 env `KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS`
默认 90 天，写路径每 N 条概率触发清理。`GET /v1/admin/access-log?surface=
&days=&limit=`（admin，days 上限 90、limit 上限 500）按时间倒序返回。

部署（2026-08-08 现状）：`catalog.kiwi.harrylabsj.com` 已指向阿里云香港节点的
catalog（Caddy 反代 TLS → 127.0.0.1:8600）。生产部署与升级步骤（代码同步 /
env / 重启 / 验证 / 回滚）见 `deploy/production.md`。

后续（不在本次）：邮件交付（项目无邮件设施，MVP 靠一次性展示 + 轮换兜底）；
catalog 监听收紧为 127.0.0.1（见 production.md 安全边界）。

## 10. 测试要点

- apply：会话鉴权（2026-08-12 关闭匿名公开通道）、校验失败、按账号限流；
- approve/rotate/revoke：admin 必填（fail-closed）、明文仅一次、旧 token 轮换后失效、
  吊销后失效、重复 approve 409；
- 双路径：HMAC 旧 token 仍可 publish（兼容）；新随机 token 可 register(带 merchant)/publish；
- 门户页 GET 返回 200 + `text/html`；
- fresh 路径（models.SCHEMA）与迁移路径（v12）DDL 逐字一致（test_shadow_tables 守护）。
