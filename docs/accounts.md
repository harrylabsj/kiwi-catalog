# kiwi-catalog 商家账号与 Token 分发（docs §account）

> 本文是 `/v1/accounts`、`/v1/merchants`（token 分发）、`/v1/admin` 与
> `/portal` 门户的唯一权威文档（代码注释中的 "docs §account" 指向本文）。
> 范围：已实现功能；不覆盖 token portal 设计稿中规划未落地部分。

## 1. 目标

商家在 kiwi-catalog 上的自助接入面：注册账号 → 邮箱验证 → 登录 → 提交
merchant 接入申请 → admin 审批 → 获得**随机 owner token**（加密存储），
用于 `/v1/listings/publish`、`/v1/agents/{id}/listings` 自查、
`/v1/merchants/{id}/token/*` 等 owner 语义动作。

owner token 双路径（`api/auth.py`）：

- **随机 token 落库路径**（v13+，本体系）：`merchant_tokens` 表 active 行 +
  SHA-256 恒时比较；
- **HMAC fallback**（legacy）：`owner_token(merchant_id) = HMAC-SHA256(
  KIWI_CATALOG_OWNER_TOKEN_SECRET, "kiwi-catalog-owner:"+merchant_id)`。

## 2. 数据模型（20 张表的一部分，迁移 v13–v16）

| 表 | 用途 |
| --- | --- |
| `merchant_accounts` | 商家账号（email、PBKDF2 口令哈希、email_verified） |
| `account_sessions` | 登录会话（随机 session token，SHA-256 存储） |
| `merchant_applications` | 接入申请（merchant_id、状态 pending/approved/rejected、工单字段） |
| `merchant_application_limits` | 注册/登录/申请限流（per-email / per-actor 15min 窗口） |
| `merchant_tokens` | 签发 token（`token_encrypted` Fernet 加密存储，active/revoked） |
| `usage_metrics` | 令牌使用量（rotated/revoked 等） |

- 迁移：v13（usage_metrics）、v14（accounts）、v15（邮箱验证）、
  v16（基本信息字段）；`CURRENT_SCHEMA_VERSION = 16`。
- Fernet 密钥派生：`sha256("kiwi-token-fernet:" + KIWI_CATALOG_OWNER_TOKEN_SECRET)`
  ——token 明文永不落盘。

## 3. API

### 3.1 `/v1/accounts/*`（公开注册/登录）

| 路由 | 语义 |
| --- | --- |
| `POST /v1/accounts/register` | 极简注册（邮箱+密码）→ 签发邮箱验证码；console 模式响应含明文 `verification_code`，smtp 模式发邮件 |
| `POST /v1/accounts/login` | 校验 + 签发会话（`__cookies__` 透传）；邮箱未验证 → 403 |
| `POST /v1/accounts/verify-email` | 验证码核验（通过后才可登录） |
| `POST /v1/accounts/resend-code` | 重发验证码 |
| `POST /v1/accounts/logout` | 吊销会话 |
| `GET /v1/accounts/me` | 当前会话账号视图 |
| `POST /v1/accounts/token-request` | 登录态提交 token 申请（`/v1/merchants/applications` 的 POST 与本端点同一处理函数） |
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

### 3.4 `/portal/*`（HTML 门户，登录态）

| 路由 | 页面 |
| --- | --- |
| `/portal` | 首页（登录态 → Token 申请入口） |
| `/portal/apply` | 接入申请 |
| `/portal/admin` | admin 审批列表 |
| `/portal/dashboard` | 商家仪表盘 |
| `/portal/register` / `/portal/login` | 账号注册/登录 |
| `/portal/account` | 账号 + Token 管理 |

## 4. 安全属性

- 口令：PBKDF2-SHA256（每账号随机盐）；邮箱验证码 console/smtp 双模式；
- session token 随机 + SHA-256 存储；密码/密钥不落明文；
- merchant token Fernet 加密（`token_encrypted`）；登录态“我的”页会解密显示 active token，
  因此会话应按凭据保护，疑似泄露时立即轮换；每次登录态展示记录
  `merchant_token_viewed` 审计事件（不含明文）；admin 列表/审计仅回显 `token_prefix`；
- 注册/登录/申请均限流；`require_merchant_token` 恒时比较（sha256 digest）；
- 生产部署需配置 `KIWI_CATALOG_ADMIN_TOKEN` 与
  `KIWI_CATALOG_OWNER_TOKEN_SECRET`（未配置时鉴权一律 fail-closed）。

## 5. 与其它模块的关系

- owner token 由 `/v1/listings/publish|withdraw` 消费（`listings.py`
  `require_owner_token` 双路径校验）；
- `kiwi merchant publish`（kiwi 仓）优先使用随机 token
  （`KIWI_MERCHANT_TOKEN` 直传），缺省回退 HMAC 派生（register.ts
  与 `auth.py:owner_token` 逐字节一致）；
- 设计稿 `docs/kiwi-catalog-token-portal-design-v0.1.md` 为 Draft——
  与本文不一致处以本文（当前实现）为准。
