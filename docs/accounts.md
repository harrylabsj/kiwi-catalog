# kiwi-catalog 商家账号、Runtime 连接与商品名额（docs §account）

> 本文记录账号与门户现行行为；Listings 的额度和迁移细节见
> [商品名额](./listing-entitlements.md)。旧 token 分发 API 仍为其他 owner
> 语义和存量数据保留，不属于新商家的商品发布步骤。

## 1. 目标

商家在 kiwi-catalog 上的自助接入面：注册商家账号（**商家名称、电话必填**，
邮箱 + 密码，微信选填）→ 邮箱验证 → 登录。**注册即成为商家**——分配平台
merchant_id 并创建影子 `merchants` 行，同时自动获得 **free 方案，默认 20 个
同时占用的 Listings 名额**，admin dashboard **无需审批即可见**。邮箱验证后，
商家可完成一次 Runtime 连接确认；名片上线后，Runtime 用活动绑定签名发布、
自查和撤回商品。无需另行申请 Listings 资格，也无需复制 owner token。
Catalog 每次发布都检查账号、绑定、方案额度、内容与治理状态；额度可由本地
管理员调整。未来收费通过更新方案与额度接入，不把额度编码到 token 中。

`/v1/accounts/token-request` 与 `/v1/merchants/*` 的 token 分发能力仍可处理
旧 owner 语义；其审批和 token 状态**不授予新账号 Listings 发布权**。
Listings 旧 owner-token 路径默认关闭，仅无账号存量商家可在迁移期显式开启。

owner token 双路径（`api/auth.py`）：

- **随机 token 落库路径**（v13+，本体系）：`merchant_tokens` 表 active 行 +
  SHA-256 恒时比较；
- **HMAC fallback**（legacy）：`owner_token(merchant_id) = HMAC-SHA256(
  KIWI_CATALOG_OWNER_TOKEN_SECRET, "kiwi-catalog-owner:"+merchant_id)`。

## 2. 数据模型（当前 schema 41）

| 表 | 用途 |
| --- | --- |
| `merchant_accounts` | 商家账号（email、PBKDF2 口令哈希、email_verified、merchant_name、phone、wechat） |
| `account_sessions` | 登录会话（随机 session token，SHA-256 存储） |
| `merchants` | 商家影子表（admin dashboard 只读；**注册即创建**——`register_account` 经 `ensure_merchant_id` 同步 `insert or ignore`，审批/Agent 注册兜底；存量账号会话解析懒回填） |
| `merchant_applications` | 接入申请（merchant_id、状态 pending/approved/rejected、工单字段） |
| `merchant_application_limits` | 注册/登录/申请/公开资料发布/买家关注限流（per-email / per-actor / per-merchant / per-buyer 15min 窗口） |
| `merchant_tokens` | 签发 token（`token_encrypted` Fernet 加密存储，active/revoked；注册种入空 hash 的 revoked 占位行） |
| `listing_plans` | 方案额度；free 初始为 20，可由管理员修改 |
| `merchant_listing_entitlements` | 商家方案、资格状态和可选的单商家额度覆盖 |
| `listing_entitlement_audit` | 方案／商家额度调整与迁移回填审计 |
| `usage_metrics` | 令牌使用量（rotated/revoked 等） |
| `merchant_publications` | 商家公开资料（M0，§3.5：账号会话发布的 public-only 声明快照，draft/published/withdrawn；v30 起含 view_count 浏览计数） |
| `merchant_public_events` | 商家公开事件流（M4，§3.6：发布/更新/撤回时服务端生成的 public-only 发布动态，version 按商家单调递增） |
| `buyer_follows` | 买家关注（M4，§3.6：buyer_subject 不透明字符串 + last_seen_at 拉取水位，active/cancelled） |

- 迁移：v13（usage_metrics）、v14（accounts）、v15（邮箱验证）、
  v16（基本信息字段）、v24（忘记密码重置：merchant_accounts 加
  `reset_code_hash` / `reset_expires_at`，与邮箱验证码同机制——SHA-256
  落库 + 15 分钟过期）、v25（联系方式微信：merchant_accounts 加 `wechat`）、
  v29（商家公开资料 merchant_publications，M0）、v30（买家订阅：
  merchant_public_events + buyer_follows + merchant_publications.view_count，
  M4）；v40（商品名额与治理暂停保护）、v41（未自定义的免费默认额度从 10 调整到 20）；
  `CURRENT_SCHEMA_VERSION = 41`。
- Fernet 密钥派生：`sha256("kiwi-token-fernet:" + KIWI_CATALOG_OWNER_TOKEN_SECRET)`
  ——token 明文永不落盘。

## 3. API

### 3.1 `/v1/accounts/*`（公开注册/登录）

| 路由 | 语义 |
| --- | --- |
| `POST /v1/accounts/register` | 注册商家账号（**商家名称、电话必填** + 邮箱 + 密码；微信选填）→ 分配 merchant_id、影子 `merchants` 行和 free 商品方案（默认 20 个名额）→ 签发邮箱验证码；验证后才能公开发布 Listings |
| `POST /v1/accounts/login` | 校验 + 签发会话（`__cookies__` 透传）；邮箱未验证 → 403 |
| `POST /v1/accounts/verify-email` | 验证码核验（通过后才可登录） |
| `POST /v1/accounts/resend-code` | 重发验证码 |
| `POST /v1/accounts/forgot-password` | 签发密码重置验证码；**防枚举**：邮箱不存在也返回同样的 ok 文案（不发码）；console 模式响应含 `reset_code`，smtp 模式发邮件 |
| `POST /v1/accounts/reset-password` | 重置码 + 新密码改密；账号不存在与码错误统一 403（不区分）；成功后该账号全部会话失效、邮箱标记已验证 |
| `POST /v1/accounts/logout` | 吊销会话 |
| `GET /v1/accounts/me` | 当前会话账号视图，含 `listing_capacity`（方案、状态、已用、总额、可用） |
| `POST /v1/accounts/token-request` | 旧 owner-token 申请 API；不用于新 Listings 流程，门户不提供申请按钮 |
| `GET /v1/accounts/profile` | 会话账号 + 名下 merchants 状态 |

限流：register/login 均 15min 窗口 per-email（`merchant_application_limits`）。

### 3.2 `/v1/merchants/*`（token 分发，owner/admin）

| 路由 | 语义 |
| --- | --- |
| `POST /v1/merchants/applications` | 提交接入申请（**会话鉴权**：2026-08-12 起关闭匿名公开通道——假邮箱直接提交工单被滥用；与 `/v1/accounts/token-request` 同一处理函数，contact_email 取账号邮箱） |
| `GET /v1/merchants/applications` | 列出申请（admin） |
| `POST /v1/merchants/applications/{id}/approve` | 审批通过 → 签发随机 token（Fernet 加密落库），响应含 `token_prefix` |
| `POST /v1/merchants/applications/{id}/reject` | 拒绝 |
| `POST /v1/merchants/{merchant_id}/token/rotate` | 轮换 token（旧 token 失效） |
| `POST /v1/merchants/{merchant_id}/token/revoke` | 吊销 token |
| `POST /v1/merchants/{merchant_id}/token/recover` | 恢复 token（幂等重放路径，POST /merchants 幂等错误提示指引该端点） |
| `GET /v1/merchants/{merchant_id}/agents` | 按商家列出 agents（owner/admin） |

### 3.3 `/v1/admin/*`（运营 dashboard，admin token 保护）

应用列表/审批动作的管理视图。

| 路由 | 说明 |
| --- | --- |
| `GET /v1/admin/*` | 只读聚合（dashboard / merchants / report / searches / buyer-stats / buyer-day / access-log / access-insights） |
| `POST /v1/admin/token/rotate` | **轮换 admin token**（2026-09-26，迁移 v37）。必须带当前 token；body `new_token` 可选（≥24 字符、不含空白），缺省由服务端生成 43 字符；响应里的明文**只返回一次**；旧值立即失效 |

**轮换语义与恢复**（`services/admin_credentials.py` + `db/session.py` 的迁移链）：

- 表 `admin_credentials` 是**单例行**，只存 SHA-256 摘要；`env` 的
  `KIWI_CATALOG_ADMIN_TOKEN` 只作**首次引导**——一旦有行，旧配置值不再被接受
  （否则轮换对已拿到旧值的人毫无作用）。
- 判定口径统一在 `api.auth.effective_admin_digest(db)`：有行读行、无行读 env；
  **所有**调用点必须带 db 上下文（`db_path` 或 `conn`），漏传 = 那条路径上旧值复活
  ——由 `tests/test_admin_token_rotate.py::test_every_require_admin_token_call_passes_db_context` 静态守住。
- **恢复路径**（丢失新 token / 需要交回配置管理时）：
  `sqlite3 <db> "delete from admin_credentials where credential_id = 1"` + 重启服务，
  env 引导值重新生效。
- **回滚注意**：迁移 v37 会把 `meta.schema_version` 提到 37，而旧版本代码拒绝打开
  "比自己新"的库（`RuntimeError: database schema version ... is newer`）。因此回滚旧包时
  需一并把 `meta.schema_version` 改回 36（多出的空表对旧代码无害）或恢复部署前的库备份。
- 轮换后发一封通知邮件（`KIWI_CATALOG_ADMIN_NOTIFY_EMAIL`，未配置则不发）：轮换会让旧值
  立即失效，若是攻击者所为，这封信是运营唯一的即时信号。发信失败不回滚轮换。
- 门户 `/portal/*` 的 admin 页都有 token 面板：「记住」把 token 存进**本浏览器**
  （localStorage，已记住时校验一次并给出"通过/被拒/无法判定"）、「更换」只改本浏览器、
  「轮换服务器 token」才真正改服务器（需当前 token 有效 + 二次确认）。

### 3.4 `/portal/*`（HTML 门户，登录态）

| 路由 | 页面 |
| --- | --- |
| `/portal` | 商家后台／商品名额入口 |
| `/portal/apply` | 旧链接，显示商家后台／商品名额 |
| `/portal/admin` | admin 审批列表 |
| `/portal/dashboard` | 商家仪表盘 |
| `/portal/register` / `/portal/login` | 商家注册（**必填商家名称**，注册即商家）/ 登录 |
| `/portal/reset-password` | 忘记密码（邮箱 → 重置码 → 新密码，成功后回登录页） |
| `/portal/account` | 账号 + 商品名额（已用／总额），不展示 Listings owner-token 配置步骤 |
| `/portal/publications` | 公开资料编辑/预览/发布（M0）：发布成功回执显示 publication_id、版本、发布时间；页内显示关注/浏览匿名汇总；未登录引导去 `/portal/login` |
| `/portal/follows` | 我的关注（M4，买家视角）：关注列表 + 按 merchant_id 关注 + 取消 + 主动拉取更新 |

### 3.5 `/v1/merchant-publications/*`（M0 商家公开资料，账号会话）

没有部署 Merchant Agent 的注册商家，用**账号会话**（cookie `kiwi_session`，
**不是 owner token**）发布 public-only 的商家/商品声明快照；买家按商品词
公开检索（kiwi 仓 merchant-buddy 第 0 版设计 §4 / M0 工作包 A）。

| 路由 | 语义 |
| --- | --- |
| `POST /v1/merchant-publications` | 保存草稿（`action=draft`，缺省）/ 确认发布（`action=publish`）；必填 `merchant_display_name` + `title`（商品名）；响应回执含 `publication_id`、`version`、`published_at` |
| `GET /v1/merchant-publications/search` | 公开检索（`q`/`category`/`merchant_id`/`limit`/`cursor`）；仅 `published` 且未过期（`expires_at` 为空或在未来）；排序分页沿用 listings 搜索约定；结果恒带 `inquiry_available=false` |
| `GET /v1/merchant-publications/{id}` | 公开详情；匿名仅 published 未过期可见，商家本人（会话归属一致）可见自己的 draft/withdrawn，其余 404 |
| `POST /v1/merchant-publications/{id}/withdraw` | 撤回（终态）；会话归属校验——只能撤回自己 merchant_id 名下的资料 |

- **状态域**：`draft`（私有草稿，不进搜索）→ `published`（公开可搜）→
  `withdrawn`（撤回终态，退出搜索与匿名详情）；`source_kind` 恒为
  `merchant_declared`（商家声明内容，不是 Kiwi 背书）。
- **会话归属**：`merchant_id` 一律取自服务端会话，客户端传值无效；
  按商家限流（env `KIWI_CATALOG_PUBLICATION_RATE_LIMIT_PER_15MIN`，默认
  30/15min，复用 `merchant_application_limits` 表）。
- **public-only 白名单**：公开投影只有白名单字段——注册账户的电话/邮箱/
  凭据绝不出现；写入侧对公开字段做私密字段扫描（明显的邮箱/手机号模式
  fail-closed 拒绝 + 审计 `merchant_publication_private_field_rejected`）。
- **幂等**：同一商家同名商品（`merchant_id` + `lower(title)`，非撤回行）
  重复提交 = 更新既有行（响应 `idempotent=true` + 说明文案，发布动作版本
  递增）；`(merchant_id, lower(title))` 非撤回行部分唯一索引数据层兜底。
- **不生成虚假能力**：公开资料不产出 Agent Card、A2A 端点或实时报价标记
  （`inquiry_available=false`）；第 1 版商家的实时询价走既有 Agent/Listing
  链路与绑定签名、方案额度权限模型。
- **审计**：发布/更新（`merchant_publication_published` / `_republished` /
  `_saved` / `_updated`）、撤回（`merchant_publication_withdrawn`）、私密
  字段拒绝均落 `audit_events` 影子表。

### 3.6 `/v1/me/follows/*`（M4 买家主动订阅，账号会话）

买家**显式关注**商家后，在主动查询时按 `last_seen_at` 水位拉取商家已批准
公开的动态（kiwi 仓 merchant-buddy 第 0 版设计 §4/§2 买家路径 3-5）。
**拉取式订阅**：无邮件/短信/WorkBuddy 消息/A2A 主动消息等任何推送通道；
搜索、浏览、调用专家或发询价都不产生关注行。

| 路由 | 语义 |
| --- | --- |
| `PUT /v1/me/follows/{merchant_id}` | 显式关注（幂等：重复关注不产生重复记录，可更新可选 body 的 `category`/`consent_version`）；首次关注水位从关注时刻起，取消后重新关注水位重置 |
| `DELETE /v1/me/follows/{merchant_id}` | 取消关注（状态置 cancelled，幂等）；取消后不再出现在更新与关注列表里，商家汇总数字随之减一 |
| `GET /v1/me/follows` | 我的活跃关注列表（买家管理面） |
| `GET /v1/me/follows/updates` | 仅响应买家主动查询：按各关注的 `last_seen_at` 增量返回公开事件并推进水位（返回什么再推进，不丢不重）；`category` 非空的关注只投递该类目事件 |
| `GET /v1/merchant-publications/stats` | 商家本人匿名汇总（仅本人 merchant_id，取自会话）：活跃关注者**总数** + 各公开资料浏览计数；**不返回任何买家身份**，无关注者列表 |

- **买家身份**：任何已登录账号都可以作为买家；`buyer_subject` 一律取自
  服务端会话（`account:{account_id}` 不透明字符串，不用邮箱等可变/私密
  字段），客户端传值无效；未来可切换 WorkBuddy open_id。
- **事件流**：发布（`product_added`）/更新（仅 FAQ 变化为 `faq_updated`，
  其余为 `product_updated`）/撤回（`publication_withdrawn`）公开资料时由
  服务端生成；version 按 merchant_id 单调递增、created_at 按商家严格递增
  （水位不丢不重的前提）；payload 复用 M0 公开投影白名单——RFQ、内部任务
  状态、未发布草稿一律不进入事件流；`service_notice` 为词表保留（可不绑
  定单个资料，当前无生成点）。
- **匿名汇总原则**：商家只能看到关注者总数与浏览计数，永远拿不到
  buyer_subject / 关注者列表，也没有任何向关注者写消息的 API；浏览计数
  只计非商家本人的公开详情浏览。
- **限流与审计**：关注/取消按买家限流（env
  `KIWI_CATALOG_FOLLOW_RATE_LIMIT_PER_15MIN`，默认 60/15min，复用
  `merchant_application_limits` 表）；关注/取消操作落 `audit_events`
  （`buyer_followed` / `buyer_unfollowed`，系统审计可见，不出现在任何商家
  侧接口）。

## 4. 安全属性

- 口令：PBKDF2-SHA256（每账号随机盐）；邮箱验证码 console/smtp 双模式；
- session token 随机 + SHA-256 存储；密码/密钥不落明文；
- merchant token Fernet 加密（`token_encrypted`）；旧 `/v1/accounts/me` 响应
  仍可能包含 active token，应按敏感会话保护；新门户不展示或配置该 token。
  admin 列表/审计仅回显 `token_prefix`；
- 注册/登录/申请均限流；`require_merchant_token` 恒时比较（sha256 digest）；
- 忘记密码：重置码与邮箱验证码同机制（6 位、SHA-256 落库、15 分钟过期）；
  forgot-password 对未知邮箱返回相同 ok 文案防账号枚举；reset-password
  不区分「账号不存在」与「码错误」；改密成功即删除该账号全部
  account_sessions（所有会话失效），并顺带置 email_verified=1
  （能收到码即证明邮箱归属，避免未验证账号重置后仍无法登录的死角）；
- 生产部署需配置 `KIWI_CATALOG_ADMIN_TOKEN` 与
  `KIWI_CATALOG_OWNER_TOKEN_SECRET`（未配置时鉴权一律 fail-closed）；
- admin token：轮换行只存摘要（同商家令牌模型）；轮换后旧值在**所有** admin 端点
  立即失效（含 env 引导值），恢复 = 删行 + 重启（见 §3.3）；
- 买家订阅（§3.6）：`buyer_subject` 为账号稳定标识的不透明字符串（不存
  邮箱）；商家侧接口只输出匿名汇总数字，无任何买家身份/列表/写消息通道。

## 5. 与其它模块的关系

- 新商家 Runtime 由 enrollment、活动绑定和请求签名证明身份；Catalog 的
  `listing_plans`／`merchant_listing_entitlements` 独立决定商品发布额度。
- `kiwi merchant publish` 没有已发布绑定时拒绝发布，不回退 owner token；
  账号商家即使拥有旧 token，也不能用它发布 Listings。
- 无账号存量商家的 Listings owner-token 路径默认关闭，仅迁移期间可显式
  设置 `KIWI_CATALOG_ENABLE_LEGACY_LISTINGS=on`；该开关不对账号商家生效。
