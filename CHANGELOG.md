# Changelog

## 0.5.11 — 2026-10-30

- **日配额 429 不再回滚每买家 15 分钟计数**：日限额在独立事务消费；新增回归测试。
- 明确“每天”为 **UTC 自然日**，补跨零点与 +08:00 归一测试。
- 新增 `merchant_access_near_cap` 指标：日配额达到 80% 后仍放行的请求计数，供运营告警。
- 修正 CHANGELOG/测试名：不存在的 agent 无法解析商家，不计入任何商家配额。

## 0.5.10 — 2026-10-29

- **商家级每日发放上限**：平台口径（2026-10-28 工单回复）明确 sharecode 是访问凭据、官方定位为人工分享、"不适合大规模机器自动分发"。除既有的「每买家 60 次/15 分钟」外，新增 `KIWI_CATALOG_MERCHANT_ACCESS_DAILY_LIMIT_PER_MERCHANT`（默认 500/天/商家，0 = 关闭，按 **UTC 自然日**计）：按**商家**计数，超过后返回 429，并留有审计可见的计数行；达到 80% 后仍放行的请求另记 `merchant_access_near_cap` 运营指标，供告警。同一商家的重复请求（含已处置 agent 的查询，以及后续被 429 拒绝的那次）同样计入，避免靠试探绕过；不存在的 agent 无法解析商家，不计入任何商家配额。
## 0.5.9 — 2026-10-28

- **门户「连接此服务并发布」页无法显示配对码、确认按钮永远禁用**：`public_enrollment()` 自 2026-10-11 加固起不返回 `user_code`（无会话预览不得泄漏认领用的秘密），而门户页面按 `d.user_code` 渲染并据此启用按钮，两边自那时起就对不上。
- **收敛方式**：接口继续保持不返回配对码（不变量不变，`test_a422` 仍然钉住）；`authorize` 的配对码改为**可选**——请求里带了就必须匹配（错码照旧拒绝），不带则仅凭登录会话 + 显式确认。门户页面随之去掉「配对码」一行。
- **补偿防护**：已有 `active` 运行时绑定的商家，不能再用**另一把密钥**的 enrollment 授权覆盖；只有同一 `key_id`（同一 Runtime 重跑 `connect`）才允许。避免"转发授权页 + 点一下"就把攻击者的 Runtime 绑到商家身份上。
## 0.5.8 — 2026-10-28

- **注册/重置发码遇到"收件人被拒收"改为 400**：`smtplib.SMTPRecipientsRefused`（服务端拒绝该地址，典型如格式合法但不存在的邮箱）此前会冒泡成 **500**，让用户可修复的输入错误看起来像服务端故障。现在验证码与密码重置两条 fail-closed 路径统一映射为 400 `email address is not deliverable`；连接失败、认证失败、未配置 SMTP 仍然抛异常（服务端问题不伪装成 4xx），注册事务照旧回滚、不留半条记录。

## 0.5.7 — 2026-10-27

### WorkBuddy 分享码访问配置（schema v46）

- **商家登记一次访问配置，Catalog 代 Buyer 完成平台门禁**。新增 `runtime_access_configs` 表：分享码只存 Fernet 密文，密钥与 owner secret、业务签名密钥相互独立（`KIWI_CATALOG_ACCESS_CONFIG_KEYS_JSON` 存 `{key_id: fernet_key}`，`KIWI_CATALOG_ACCESS_CONFIG_ACTIVE_KEY_ID` 指定当前加密 key；未配置、未知 key 或解密失败一律 fail-closed）。每个 Agent 最多一个 `active` 版本由部分唯一索引兜底。
- **写入面**：首绑 `POST /v1/agents/{id}/runtime-bindings` 可附带 `access_config`（D1 请求随后确认激活、enrollment 随绑定激活、admin 兜底直接激活）；更新/撤销 `PUT /v1/agents/{id}/runtime-access` 由当前 active binding 私钥签名，中间经带码 `/control/challenge` 持钥证明。失败保留旧 `active` 版本并把新版本标 `invalid`，不残留 `pending`。
- **读取面**：`GET /v1/me/merchant-access/{catalog_agent_id}` 只对已登录且活跃关注该商家的 Buyer 返回当前 active 配置（`Cache-Control: no-store`，按 Buyer 限流：`KIWI_CATALOG_MERCHANT_ACCESS_RATE_LIMIT_PER_15MIN`，默认 60，`0` 关闭；成功发放写 `runtime_access_issued` 审计），被行政处置（`suspended`/`rejected`）的商家与不存在同口径 404。`/v1/agents` 新增只含 active 元数据的 `runtime_access` 公开投影，任何公开面都不含分享码。
- 双栈一致：fallback ASGI 栈的 `__no_store__` 响应不再下发 ETag、不再参与条件请求（此前会按 `If-None-Match` 返回 304）。
- **代管授权（政策风险控制，schema v44）**：商家必须显式授权（这是启用代管的唯一门槛）"目录代管分享码并只在其已接受的采购方关注时出示"（条款版本 `workbuddy-share-v1-2026-10-27`）才能提交配置；授权落 `runtime_access_consents`，激活时同事务记录。撤回（`access_mode: none`）会**同时清空密文**并记录 `revoked_at`——不再出现"状态已撤销但凭据还在库里"。Buyer 发放要求"总开关开启 + 授权有效 + 配置 active"三者同时成立。运营开关 `KIWI_CATALOG_ACCESS_CUSTODY_ENABLED` **默认启用**（产品决定 2026-10-27：代管的门槛是商家逐户授权，而非默认关停）；把它设为 `0/false/off/no` 即**紧急停用**——不得新建/激活、Buyer 停止发放，撤销与读取仍可用。
- **废弃原因可区分（v45）**：`runtime_access_configs.revoked_reason` 区分 `superseded`（被新版本替换）与 `merchant_revoked`（商家撤销），工作台据此显示"已被新版本替换"而不是笼统的"已撤销"。
- **门禁失败上报（v46，C-06）**：买家在受控获取后遇到平台门禁拒绝，可 `POST /v1/me/merchant-access/{id}/fault`（会话 + 活跃关注 + 限流）上报 `gate_rejected`/`config_missing`；目录只记账 7 天，**不改配置状态**。商家签名读返回近 24h 计数与最后一次时间，工作台据此提示"请核对分享码是否已更换或失效"。买家身份只以哈希入账，不存原值。
- **契约对齐**：`GET /v1/me/merchant-access` 的无会话/未关注统一为 **403**（此前契约写 401），与平台全局 AuthError 映射一致。
- **部署约束（breaking）**：schema v46 在旧包里无法打开（`user_version > CURRENT_SCHEMA_VERSION` 直接拒绝），因此必须先上新代码、且**不能回滚到旧包**。契约锁重钉到 kiwi `82c1cfcb`（bundle `5be0f0e8`）。
- 本版本不改变现有商家/ Buyer 的普通流程：未配置访问能力的商家，公开记录与绑定行为逐字节不变。

## 0.5.6 — 2026-10-13

### 注册改为邮箱先行（breaking API change）

- **先证明邮箱归属，再创建账号**。`POST /v1/accounts/register` 不再"建号 + 发验证码"，改为凭一次性 `verification_ticket` 建号。新端点是 `POST /v1/accounts/register/code`（发码）与 `POST /v1/accounts/register/verify`（验码换 ticket）。原先的顺序（填四个字段 → 建号 → 发码 → 商家再验证）会让**任何中途放弃或填错邮箱的注册都留下一条永远无法登录、也无法回收的账号行**——线上 20 个账号里有 2 条正是这种半成品。
- 建号即 `email_verified=1`，注册成功即自动登录（`__cookies__`）。"已注册、邮箱待验证"这个中间态对新账号不再出现。
- 新建表 `registration_verifications`（schema v42）：账号尚不存在时验证码无处依附，故单独建表，一邮箱一行；验码通过后码作废、改发 15 分钟的一次性 ticket；建号成功即删行，过期行由 `register/code` 顺手惰性清理。**ticket 是必需的**——只记"该邮箱 15 分钟内已验证"的时间戳等于一个没有凭据的能力，任何知道该邮箱的人都能在窗口内抢先建号并设自己的密码（账号接管）；ticket 只有读到过验证码的人持有。
- 服务端强制校验 ticket：门户页把未验证字段置灰只是 UX，绕过页面直接调接口同样被拒。
- 发码端点带 per-email + per-IP 前缀 + 全局发信预算三道闸（发信风险随发码步骤前移）；验码端点额外带 per-IP 桶。验证码邮件仍是 fail-closed：发不出去就整个事务回滚。
- `/v1/accounts/verify-email` 与 `/v1/accounts/resend-code` **保留但转为 legacy**：它们如今只服务 2026-10-13 之前注册的存量未验证账号，且是这些账号唯一的取码途径——不能删。

### 邮件

- `notify_admin_new_registration` 在账号提交后通知运营邮箱（`KIWI_CATALOG_ADMIN_NOTIFY_EMAIL`）；`send_welcome_email` 在首次成功验证邮箱后给商家发欢迎信（仅 smtp 模式；console/未配置返回 False）。两封都是**旁路**：自身不抛异常，SMTP 故障绝不影响注册/验证——刻意与验证码的 fail-closed 语义相反——且都在 `db_session` 事务提交**之后**发出。
- **Repo/main alignment**：这段行为自 2026-10-09 起以运行时 `patch` 的形式直接打在 `/opt/kiwi-catalog-0.5.5/.venv/.../site-packages` 上（见 `runtime-email.patch`），所以线上会发通知而 main 不会。移植过来的函数除 docstring/注释外与线上逐字节一致。
- 邮箱先行之后建号时邮箱已验证，运营通知不再写「（邮箱待验证）」——那句话在这种情况下已经不成立。

### 门户

- `/portal/register` 重做为三段式：只有邮箱可填 → 发码/验码 → 其余字段解锁。未验证前商家名称/密码/电话/微信与「注册」按钮均为 `disabled`，并新增 `input:disabled` 的显式灰化样式（浏览器默认表现跨平台不一致，Safari 几乎看不出来）。

## 0.5.5 — 2026-10-01

- Launch preflight: new `kiwi_catalog.a2a.launch_preflight.issuance_preflight` reuses the existing fail-closed validators (`load_issuer_key_set`, `catalog_public_origin`) to check the issuance-required configuration — issuer key set (exactly one ACTIVE key via `KIWI_CATALOG_ISSUER_KEYS_FILE` or the single-key env fallback) and `KIWI_CATALOG_PUBLIC_ORIGIN` — and reports fixed codes (`ISSUER_KEY_OK`/`ISSUER_KEY_REJECTED`, `PUBLIC_ORIGIN_OK`/`PUBLIC_ORIGIN_REJECTED`). Read-only: no network access, no key generation, no private-key material or key-file paths in the report.
- `kiwi-catalog-api --check-config` exits 0 only when both checks pass, 1 otherwise (usable as a systemd `ExecStartPre` or deployment-checklist step). The serving path prints a stderr warning at startup when the configuration is incomplete but keeps serving — issuance stays fail-closed at request time, semantics unchanged. The packaged systemd unit gains an `ExecStartPre` line so a misconfigured host refuses to start instead of silently returning 403 on `runtime-bindings` (A37: 91×403 with no startup-period signal).

## 0.5.4 — 2026-09-30

- Runtime-binding denial diagnostics: every 403 branch on the enrollment bind path now logs a fixed own error code (`BIND_GRANT_UNAVAILABLE`, `BIND_MATERIAL_MISMATCH`, `BIND_CHALLENGE_DELIVERY_FAILED`, …) with a safe stage label before responding; response bodies and status codes are unchanged. Log lines contain no grant, request JWS, key material, or remote error text.
- Converge `urllib.error.URLError` (TLS-handshake-timeout shape) in `ProfileFetcher._make_request` to `FetchError`, matching the existing `_fetch` convention: challenge-egress network failures return the existing diagnosable 409 instead of leaking an unhandled 500. HTTPError status passthrough, SSRF/HTTPS/port/timeout policies unchanged.

## 0.5.3 — 2026-09-30

- Move the merchant portal HTML pages (`/portal/*`, `handlers/portal.py`, `handlers/portal_kit.py`) out of the package: they are provided by the private `kiwi-catalog-admin` extension. Core keeps only the `/v1` business APIs. This is the same move that was released as 0.5.1 but was never merged into `main`, so 0.5.2 re-shipped the in-package portal — whose base routes shadow the extension's routes and silently reverted merchant pages on hosts that installed it.
- Guard the public-package boundary in tests: no `/portal*` route, no portal handler module, and no `admin_reports` reference may return to the package.
- Keep the 0.5.2 `GET /v1/accounts/me/service-status` API in the route table.

## 0.5.2 — 2026-09-29

- Include the read-only `GET /v1/accounts/me/service-status` API for merchant onboarding, publication, heartbeat presence, and product-quota status.
- Prepare the package version for the protected portfolio PyPI release. Production hosts must install this release from PyPI only.
