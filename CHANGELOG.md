# Changelog

## 0.5.22 — 2026-11-12

- **断开连接后的公开面收口**：无活动绑定时，门户列表、公开搜索/详情投影与
  公开主页统一不再给出主页入口；`GET /m/{merchant_id}` 直接 404，旧应用
  留下的 ACTIVE 商品不再能通过直链继续展示。内部发布事件 payload 保留
  历史快照语义。
- **交易平台运营写入**：新增 admin-only `GET /v1/marketplace-platforms/admin`、
  `POST /v1/marketplace-platforms`、`PUT/DELETE /v1/marketplace-platforms/{id}`；
  公开读取补 per-IP 限流。链接仍由 kiwi 客户端按公开规则生成。
- **文案与冗余清理**：链接模板错误示例改为通用域名；绑定 revoke 路径不再
  重复同步端点（撤卡路径已由 `set_publication_state` 完成）；修正 0.5.21
  CHANGELOG 中关于管理端的夸大表述。
- **错误响应不再下发 ETag**：fallback 栈此前对 404/410 等错误体也计算并
  下发 ETag，与「错误不可缓存」及 FastAPI 栈的 200 门禁不一致；现已对齐，
  仅成功表示携带 ETag。
- 包含 0.5.21 之后的修复：撤卡传播、门户 disconnect 信封、FastAPI query
  传参、mypy narrowing、测试 flake 修复，以及交易平台错误示例文案。

## 0.5.21 — 2026-11-11

- **门户取消连接响应信封**：`POST /v1/accounts/agents/{cagt}/disconnect`
  的 200 响应补齐 `ok: true`；此前页面按 `r.ok` 判断会把已成功的撤销
  显示成「操作失败」。首次解除与重复幂等两条路径均覆盖断言。
- **Agent 详情丢失查询参数**：`GET /v1/agents/{id}` 的 FastAPI 路由把
  query 误传到 payload 位置参数，`include` 等参数被静默丢弃，详情响应
  缺少 buyer_access / no-store；已改为显式 `query=` 传参并补回归测试。
- **断开后继续展示旧应用名片**：门户取消连接 / 运行时 revoke 现在把该应用
  已发布的公开名片置为 `WITHDRAWN`（稳定读 410，写
  `card_publication_withdrawn` 审计）；门户详情在撤回或无活动绑定时不再
  投影 `card` / `runtime_access`，避免「已取消连接」后仍展示旧应用的名称、
  介绍和服务地址。
- **断开后的残留入口**：无活动绑定时门户详情不再返回 `public_home_url`；
  旧应用留下的 ACTIVE 商品不再被当作当前「公开主页」入口。管理端依赖同一
  无活动绑定的 fail-closed 判断，不再展示旧应用的保活授权入口（管理端代码
  未改）。

## 0.5.20 — 2026-11-11

- **交易平台规则（schema v54）**：新增 `trade_platform_rules`（平台 ID/名称 ↔
  域名 ↔ 链接模板），默认种子 jd/taobao/tmall；新增公开
  `GET /v1/marketplace-platforms`。商家导入只提交平台 + 平台商品 ID，链接由
  模板生成；不接受商家上传完整链接。

## 0.5.19 — 2026-11-11

- **买家来源归因（schema v53）**：`access_log` 与 `buyer_search_events` 新增
  `buyer_source`。来源按 `X-Buyer-Source` → `X-Buyer-Id` 渠道前缀 →
  `Origin`/`Referer` host → `User-Agent` 的优先级派生并归一化（最长 64
  字符）；只落渠道标签，不落完整 Referer/原始身份/地理位置。存量行为空串，
  读侧显示 `unknown`。
- **买家搜索事件保留可配**：默认保留从 5000 条提高到 20000 条，可用
  `KIWI_CATALOG_BUYER_SEARCH_EVENT_RETENTION` 调整（上限 20 万）；裁剪改为
  每 200 条插入检查一次、且超过上限 + 500 条才执行，避免每条 insert 扫全表。
- **部署约束（breaking）**：schema v53 在旧包中无法打开；升级后不能回滚到
  旧包。

## 0.5.18 — 2026-11-10

- **门户取消连接**：新增 `POST /v1/accounts/agents/{cagt}/disconnect`（商家会话；body 带 `binding_id`）。与运行时签名面的 revoke 同一结果：绑定置 revoked、无其他活动绑定时下线 a2a/agent_card 端点行、写 `runtime_binding_revoked` 审计（actor `merchant:<id>`、channel `portal`）；重复解除幂等，非本商家或未知绑定一律 404。依赖该绑定的代管/开放询价/保活/访问配置随即 fail-closed，不删历史行。
- **domain-control 挑战绑定（审查 P1-12）**：schema v51 新增
  `catalog_domain_bindings`。`self_registered`/`discovered` agent 的 domain
  阶段必须在 `https://{domain}/.well-known/kiwi-catalog-agent.json` 发布
  回指本行的 `catalog_agent_id` + `challenge`；仅返回 200 的 well-known
  不再构成身份证明，关闭「一域多商家」下克隆已验证身份的路径。
- 新增 `GET /v1/agent-catalog/agents/{id}/domain-challenge`（商家/管理员鉴权）
  与 admin-only `POST .../domain-challenge/rotate`；CLI 新增
  `catalog challenge <id> [--rotate]`。换域名重注册自动轮换 challenge。
- 迁移兼容：升级前已通过 domain 阶段的非 hosted 行标记为 `legacy`，继续按
  旧证据通过，不突然掉级；新注册行一律 `challenge_pending`。
- 验证证据 details 新增 `shared_domain_agents` 计数（同域多 active agent 时）。
- **首绑滥用面收敛（审查 P1-13）**：未认证首绑在落请求前按来源 IP
  （`KIWI_CATALOG_FIRST_BIND_IP_PER_HOUR`，默认 10）与绑定密钥指纹
  （`KIWI_CATALOG_FIRST_BIND_KEY_PER_HOUR`，默认 5）双桶限流；运营邮件通知
  改为进程内旁路队列（有界、失败丢弃、同 agent+密钥 10 分钟去重），SMTP
  故障不再阻塞请求线程。
- **登录/账号安全（审查 P2/P3）**：登录、邮箱验证、找回/重置密码补 per-IP
  预算（邮箱预算的 5 倍、至少 20/15min）；未知邮箱执行同成本 dummy PBKDF2，
  消除登录时序枚举；`resolve_client_ip` 改为从右往左跳过可信代理（伪造左侧
  XFF 不再能轮换限流桶）；FastAPI 栈登录家族统一注入传输层来源 IP。
- **设备授权配对码默认收紧（breaking）**：`KIWI_CATALOG_ENROLLMENT_PAIRING_MODE`
  缺省改为 `required`；未知取值按 required 处理。确有旧授权页的部署必须
  显式设置 `optional` 过渡。
- **发布/绑定治理**：有商家账号的 legacy owner-token Listing 发布同样受
  free-plan 名额约束；域名未变的重注册保留原 verification_level/freshness；
  名片版本/绑定版本并发的 `max+1` 唯一索引冲突映射为 409 而非 500；
  `verify_binding_possession` 对畸形 JWS/JWK 统一 403；设备授权页/Keepalive
  同意路由补齐 Authorization 头合并。
- **其余 P3**：公开 listing 搜索先做只读探测，没有过期行时不产生写事务；
  console 邮件模式与 SMTP 配置同时存在时拒绝运行（防验证码进响应体）；
  围观列表等既有行为不变。
- **匿名域名占位回收**：未验证（discovered）的匿名域名行超过
  `KIWI_CATALOG_ANONYMOUS_CLAIM_TTL_DAYS`（默认 7 天）后可被新的匿名注册
  复用；已进入验证阶梯或绑定商家的行不受影响。
- **domain 阶段前不再公开 profile 能力**：capabilities/skills/端点索引改为
  domain-control 通过后才写入——避免把受害者 profile 的能力发布到攻击者行上。
- **schema v52**：匿名域名 active 行的 partial unique index（并发兜底）；旧库已有
  重复行时跳过建索引，升级不失败。
- **部署约束**：schema v52 在旧包中无法打开；升级后不能回滚到旧包。

## 0.5.17 — 2026-11-09

> 0.5.16 已由旧源发布（不含本条目）；0.5.17 是包含注册来源的首个正式版本。

- **账号注册来源（运营归因）**：schema v50 增加
  `merchant_accounts.registration_source`（白名单 `unknown/website/workbuddy/admin/partner/import`，
  默认 `unknown`）；`POST /v1/accounts/register` 接受可选 `source` 并在响应回显。
  官网注册页默认 `website`，WorkBuddy 入口使用 `/portal/register?src=workbuddy`；
  白名单外取值 400，缺省不猜 Referer/UA。运营后台商家列表与详情新增「注册来源」列，
  账号来源缺失时用 hosted 投影兜底标 `workbuddy`，其余保持 `unknown`。
- **部署约束（breaking）**：schema v50 在旧包中无法打开；升级后不能回滚到旧包。

## 0.5.15 — 2026-11-04

- **目录侧 WorkBuddy 保活（默认关闭）**：新增商家独立授权 `directory_keepalive`、商家工作台授权/撤销、受控调度器、真实 `/merchant/` 只读适配器；探测在 TTL 前 300 秒开始，interval/cooldown 由 TTL 派生，避免先离线后探测。
- **公平分页与持久限流**：schema v49 增加 `runtime_keepalive_state.last_tick_at` 与 `runtime_keepalive_consents.last_attempt_at`；多进程共享 claim、重启恢复；fresh 行不写 claim，避免推迟恢复；分页扫描避免 fresh/无时间戳商家饿死 stale/临期商家。
- **安全边界**：固定可信 host、固定 `/merchant/`、无重定向、DNS 固定、错误脱敏、探测不改在线状态；scheduler 默认关闭，必须显式配置 `KIWI_CATALOG_KEEPALIVE_ENABLED=1` 与 `KIWI_CATALOG_KEEPALIVE_TRUSTED_HOSTS`。
- **商家账号认证限流持久化**：登录、注册、验证码、重发和找回密码的失败尝试改为独立连接先提交计数，避免失败请求回滚把限流计数一并抹掉；计数写在业务写入之前，存储失败 fail-closed，不签发会话。双栈回归覆盖并发、限流窗口、FastAPI/fallback。
- **部署约束（breaking）**：schema v49 在旧包中无法打开；升级后只能通过备份恢复回滚，不能回滚到旧包。

## 0.5.14 — 2026-11-03

- **分享码污染的已签名/摘要记录改为安全隔离，不再原地清洗**：历史云端名片命中分享码 URL 时公开稳定读返回 410（不产生伪造 ETag），商家详情标记 `quarantined`/`republish_required`；历史 Listing 命中时**纯读隐藏**（不改 `publication_state`/`governance_hold`/digest/内容），公开搜索/详情/主页不再返回，商家自查面提示 `quarantined`/`republish_required`，可用同 key 重新发布（新 digest）。正常记录的内容/ETag/digest 契约不变。
- **分享码判定加固**：path/query/fragment 统一做有界重复百分号解码（最多 5 层），覆盖 `ShareCode`/`SHARE_CODE`/`share-code`、片段、编码后的嵌套 URL；测试只使用合成值。
- **公开商家主页接入公开读限流**，并支持 `?page=N` 翻页：单页仍 50 件，第 51 件起可通过下一页访问（列表超过 50 件不再是硬截断）；分页按原始行边界扫描，隔离记录不会让下一页条目重复或跳过，整页被隐藏时返回空页并继续前进。
- **公开主页链接进入商家卡片**：`GET /v1/accounts/agents/{id}/card` 与商家自查列表新增 `public_home_url`（无可公开内容时为空串），商家后台可直接打开目录托管的公开主页。
- **Listing 搜索接受 `owner_agent_id` 精确过滤**：与 `kiwi-source.ts` 的查询键对齐，避免客户端全局限量搜索后本地过滤造成合法 owner 被截断。
- **统一暂停/撤回语义与商家文案**：PAUSED 仍公开展示、只停止新询价；WITHDRAWN 才停止公开展示（稳定读 410）。
- **连接授权页恢复人工配对码，且由服务端强制校验**：商家从自己的商家应用工作台读出 8 位短码，在 `/portal/connect/{enrollment_id}` 手动输入。会话预览仍只返回策略位 `pairing_required`，**永不回显** `user_code`；配对码只从 JSON 请求体读取（查询串出现同名字段直接 400、不落日志），页面不预填、不写地址栏，成功即清空。
- **分阶段下线的旧客户端兼容**：新增 `KIWI_CATALOG_ENROLLMENT_PAIRING_MODE`（`optional` 默认 / `required`）。`optional` 下旧授权页不带码仍可确认；`required` 下缺码一律 409，绕过前端按钮也拿不到授权。门户扩展可先上线收集配对码，再收紧后端。
- **配对尝试真实计入限流**：账号级 10 次/15 分钟之外，新增按 enrollment 的 10 次/15 分钟预算；限流计数在独立事务提交——此前错码等拒绝会随授权事务回滚，导致猜测完全不受预算约束。恒定时间比较与既有过期/同源/会话/反接管/幂等语义保留。
- **商家服务地址不再伪装成主页**：`GET /v1/accounts/agents/{id}/card` 新增已生效访问门禁的**公开投影** `runtime_access`（provider/access_mode/版本，无分享码/密文）与 `public_shop_url`（published 且未过期公开资料里的 `shop_url`）。读侧拒绝 WorkBuddy（`*.workbuddy.host`/`*.workbuddy.cn`）、Kiwi 官网/目录域、目录/托管基址、`/a2a`/well-known Agent 端点、分享码参数/路径段，以及与卡片/绑定服务地址完全相同的 URL；门户只在这些检查通过时提供「打开店铺页」外链。门禁提示明确区分「目录代管」（商家授权后向已关注采购方发放分享码）与「开放询价」（独立 opt-in，买家无需关注或逐个批准，中继在服务端完成门禁）。

## 0.5.13 — 2026-11-01

- **首绑访问配置改为"挑战通过后同事务落库"**：随 enrollment 首绑提交的 WorkBuddy 分享码不再在挑战前暂存；持钥挑战、授权校验与 nonce 消费全部通过后，才在提交绑定的同一事务里暂存/激活。挑战阶段失败即随事务回滚，不再占用版本号，也不再需要任何失败补偿（不产生、不删除任何版本行）。
- **版本冲突降级为跳过，不覆盖既有配置**：目录已有生效/待验证配置时，随绑凭据按 CAS 冲突跳过、绑定本身照常完成，回执以 `access_config_outcome`（`applied` / `reason` / `head_version` / `head_status`）说明；更换或启用仍只能走商家签名 + 权威版本的 `PUT /runtime-access`。
- **新增只读版本状态投影**：`runtime_access.current_version_state()` 只返回最新配置版本与状态，不含任何凭据材料。
- **开放询价授权**：新增商家侧独立授权（`PUT/GET /v1/agents/{id}/public-inquiry-consent`，当前绑定私钥签名并校验现行条款版本）、公开可用性探测（`GET /v1/agents/{id}/public-inquiry`，仅 `{available, catalog_agent_id}` 两键）、`POST /v1/agents/{id}/public-inquiry` 代理与 fallback 栈实现、migration 47 的 `public_inquiry_consents` 表，以及经 pinned DNS/TLS 的 `post_signed_a2a` 签名转发（无重定向、无 cookie）。
- 回归测试覆盖首绑事务重排、代理不泄露门禁凭据、fallback 不信任请求正文自报的客户端地址、两套栈都要求签名与现行条款。
- **部署约束（breaking）**：schema v47 在旧包中无法打开（`user_version > CURRENT_SCHEMA_VERSION` 直接拒绝），升级后**不能回滚到旧包**；发版说明必须写明。

## 0.5.12 — 2026-11-01

- **连接器身份确认页显示当前登录商家**：待确认请求在批准前没有商家，`request_view` 现返回当前会话账号自己的 `session_merchant_name` / `session_email` 与请求来源 `return_origin`，让确认页显示“你将授权给谁”；请求侧 `merchant_name` 仍只在已绑定到当前账号时返回，跨账号不泄露他人信息。
- 回归测试覆盖待确认视图与跨账号视图。

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
