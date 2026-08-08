---
title: kiwi-catalog 整体代码审查（2026-08-08）
created: 2026-08-08
updated: 2026-08-08
type: code-review
topic: kiwi-catalog 服务代码质量与安全审查
status: 已全量修复
tags: [code-review, kiwi-catalog, fastapi, security, python]
---

# kiwi-catalog 整体代码审查报告

审查对象：`<WORKSPACE>/kiwi-catalog`（Python FastAPI + SQLite 的 Agent Catalog 服务，17.5k LOC，130 个测试）
审查方式：5 个分域并行深度审查（API 层 / agent_catalog 域 / discovery / services / listings+db+core+a2a+cli）+ 本人逐条核验 + 测试套件实跑。
核验标注：✅=本人读码/实验实锤；🔬=agent 在本机实测复现；📄=agent 读码确认（高置信）。

## 一句话结论

**架构与安全骨架扎实（SSRF 核心链路过关、认证无提权路径、状态机纯逻辑正确），但存在 8 条 P1：其中 1 条凭据泄漏（默认配置可触发）、1 条测试套件假绿掩盖了其余所有问题、2 条治理绕过、2 条分页丢行/降级失效的语义 bug、2 条恶意输入可打挂验证管线。当前 HEAD 的测试套件在 FastAPI 环境下是红的（40F+8E）。**

---

## 修复状态（2026-08-08 当日全部落地）

**8×P1 + 14×P2 + 21×P3 全部修复，测试 130 → 160 全绿（FastAPI 环境下首次真绿）。**

| Commit | 范围 | 测试 |
|--------|------|------|
| `4ea42bd` | 8×P1（secret 泄漏/测试假绿/治理绕过/写锁跨 I/O/分页/降级/fetcher 异常面/队列 NameError） | 130→144 |
| `8aa0590` | P2 权限 0700/0600 + 双栈对齐（body 上限/错误形状/ETag） | →149 |
| `fed6fdd` | P2 小项×5（ucp 缓存/LIKE 转义/域限流 0/admin 豁免/幂等 hash） | →152 |
| `57f5835` | P2 中项×6（fresh_until 索引/唯一约束/TTL 清理/迁移守卫/孤儿任务/竞态 409） | →157 |
| `9370e2f` | P2 大项×5（队列去重/超时语义/慢滴漏上限/http 支持/信任文档） | →159 |
| `75137e2` | P3 全清（卫生/时间戳/N+1/域写入边缘/fetcher-auth/服务小项） | →160 |

**修复过程中额外发现并解决的问题**：
- 测试时间炸弹：`fresh_until` 硬编码 2026-08-08 零点，当天过期变红（改相对未来时间）；
- 双栈 query 透传漂移：FastAPI 路由声明参数丢弃 `attribute.*` 动态键与未知键（改 Request 全量透传，`from __future__ import annotations` 下必须模块级导入 Request 类型）；
- REJECTED→freshness=STALE 是行为变更（P3-9 修复），4 个测试暴露异步队列竞态——enqueue 替身确定性化 + 新契约测试。

**设计取舍（已记录 CLAUDE.md，不修）**：GET 自查 token 经 query string（无 body 的必然）；CLI `--admin-token` 只标 actor 不校验（本地信任边界）；verifier 过渡表允许跳级是表语义（服务层逐 stage 不真跳）。

---

## P1 发现（8 条）

### P1-1 凭据泄漏：secret 扫描 64 条上限提前终止，超出部分直接进 public 投影并落库（安全）
- **位置**：`discovery/_validation.py:256-271`（cap 早退）→ `discovery/agent_card.py:150,274-278`、`discovery/ucp.py:142-146,284-296`（`_skip()` 用 paths 判定）→ `services/agent_verification.py:_write_snapshot`（`raw_json = encode_json(parsed.public)` 持久化）✅
- **机制**：`_scan` 在 `len(paths) >= max_secrets`（64）时整棵子树停止扫描；第 65 个起的 secret 字段不在 paths 里 → `_skip()` 判「未隔离」→ 进入 public 投影 → 写入 `agent_profile_snapshots.raw_json` 对目录消费者展示。
- **失败场景**：恶意 agent 的 card/ucp 里 70 个 service description 各含 `Bearer xxx`（50KB，远低于 1MiB 上限）→ 6 条凭据泄漏进目录数据库。
- **修复**：命中 cap 时 fail-closed（抛 `ProfileValidationError`），或去掉 early-return 全量扫描。

### P1-2 恶意源站可把验证管线打成 500：深嵌套 JSON 的 RecursionError 与非法端口 ValueError 未捕获（安全/可用性）
- **位置**：`discovery/fetcher.py:687-691`（`json.loads` 在深度防护**之前**，except 只捕 JSONDecodeError）；`fetcher.py:526,283,600`（三处 `parsed.port` 抛 ValueError）🔬
- **机制**：深度/字节/节点限制全在 parse 之后施加；Python 3.14 约 25 万层嵌套（500KB）即触发 RecursionError，`"https://host:abc/"` 的 `.port` 直接抛 ValueError——两者都不属于 `FetchError`，从 `_fetch`/`_load_profiles` 全部漏出 → 500。
- **失败场景**：恶意源站在 card/ucp/well-known 路径返回 `"["*25万+"]"*25万`，或注册 `https://example.com:abc/`、302 到非法端口——每次重验证都 500，验证管线持续失败。
- **修复**：RecursionError → `FetchLimitError`；`parsed.port` 提取包 try/except → `SSRFBlockError`。

### P1-3 测试套件假绿：FastAPI 栈下 40 failures + 8 errors，FastAPI 栈的 POST 路径从未被覆盖（流程/质量）
- **位置**：`tests/test_kiwi_catalog_v1_api.py`、`test_listings_api.py`、`test_listings_search.py` 的 `_call_http`（`"headers": []` 无 content-type）✅（本人对照实验实锤：补头后 422→正常进入认证校验）
- **机制**：FastAPI/Starlette 只在有 `content-type: application/json` 时解析 JSON body；裸 ASGI 调用全部 422 `dict_type`。fallback ASGI 栈无视 content-type 直接 `json.loads`，所以无 fastapi 环境全绿。
- **影响链**：`67a8cd2`（双栈）起就该红，后续 5 个 commit 声称「pytest 124 passed / 6 skipped」全是 fallback 环境的数字；Dockerfile `pip install .[api]` 装 fastapi——**生产跑的就是 FastAPI 栈，其 POST 路径从未被集成测试覆盖过**。`test_fastapi_dualstack.py` 用 TestClient（自带 content-type）所以这 5 个过。
- **修复**：`_call_http` 助手补 `(b"content-type", b"application/json")` 头；并建议补 CI，防止假绿再发生。

### P1-4 治理绕过（两个路径同主题）：hosted 同步复活 SUSPENDED/REJECTED agent；公开 register 可对 SUSPENDED 匿名解禁
- **4a**：`services/agent_catalog.py:277` → `agent_catalog/sqlite_repository.py:168-172` ✅——`ensure_hosted_catalog_agent` 无条件以 `verification_status="commerce_verified"` 走 upsert 更新分支，`_domains_for_legacy_status` 派生 `administrative_state=ACTIVE`，无「非 ACTIVE 守卫」。下一次 hosted 投影同步 → 治理处置被静默撤销，REJECTED 终态契约被绕过。
- **4b**：`services/agent_catalog_writes.py:59`（`_RE_REGISTERABLE_ADMIN = {"rejected","suspended"}`）+ `:168-186`（upsert 重置 admin=ACTIVE）✅——register 无 merchant_id 时完全公开（`api/handlers/agent_catalog.py:255-270`），任何人知道 domain 即可 60 秒内解禁任意被 suspend 的 agent。与 suspend 端点 docstring「the only way back is an explicit admin reinstate」、state_domains「SUSPENDED 唯一出向 reinstate」自相矛盾。
- **修复**：4a 在更新分支前检查 administrative_state，非 ACTIVE 跳过域重置；4b 若 §7.3 设计确实允许 SUSPENDED 重注册则改文档统一语义，否则只允许 REJECTED 走公开重注册。

### P1-5 写事务跨网络 I/O：verify/claim/队列任务持有 SQLite 写锁期间执行 10s 级 HTTP 抓取，全服务写面 500（可用性）
- **位置**：`api/handlers/agent_catalog.py:498`（`service.verify` 在 `db_session` 事务内）、`:543`（claim 域控制抓取）；`services/agent_verification.py:561`（快照 INSERT 开事务）→ `:630-657`（well-known 抓取在事务内）→ `:912-921`（任务末尾 commit）；`db/session.py`（busy_timeout 5s）✅
- **机制**：WAL 下同时只有一个写者；同步 `/verify` 与队列 worker（concurrency=2）都在写事务内做多次 10s 级抓取。期间任何并发写请求等 5s 后抛 `OperationalError: database is locked` → 未类型化 → 500。
- **失败场景**：匿名注册一个 `agent_card_url` 指向自己控制的慢端点 → 触发 verify → 期间所有 register/publish/withdraw 全部 500；两个队列 worker 还互锁（并发=2 时任务互相制造失败）。**攻击者可无凭证放大。**
- **修复**：抓取移出写事务（先抓后写/分阶段提交）；SQLite 写冲突映射为 503/429 而非 500。

### P1-6 分页游标与 ORDER BY 键不匹配，跨页丢行（4 处同型 bug）（正确性）
- **位置**：`agent_catalog/sqlite_repository.py:462,527,588`（游标仅 `catalog_agent_id > ?`，ORDER BY 是 rank→last_verified_at→display_name→id）；`listings/search.py:223-244`（游标 `(updated_at,id)`，ORDER BY 是 freshness rank→updated_at→id）✅
- **机制**：键集分页的谓词必须与排序键前缀一致；这里只编码了 id 或 (updated_at,id)，首键是验证等级/新鲜度 rank。
- **失败场景**：agent_catalog 侧——rank0 行 id=100/101 + rank1 行 id=50，limit=2：第 2 页 `id>101` 把 50 过滤掉 → rank1 行永久不可见。listings 侧——STALE 翻转把过期行 updated_at 刷成 now（晚于全部 FRESH）：第 2 页谓词把 STALE 行全部排除，且现有分页测试只覆盖全 FRESH 场景。
- **修复**：游标编码完整排序键元组（rank/lva/name/id 或 freshness/updated_at/id），谓词与 ORDER BY 完全同键；补混合状态分页回归测试。

### P1-7 verify() 阶梯重入先清级别，证据重算降级在主链路上永远退化为 DISCOVERED（核心语义）
- **位置**：`services/agent_verification.py:317-319`（抓取成功后 `if level != DISCOVERED: self._apply_level(agent, DISCOVERED)`）→ `:792-818`（`_degrade_level_to_supported` 读的是已清零的 current）🔬（agent 脚本实测复现）
- **机制**：§7.1「按最新未过期证据重算降级」在完整 verify() 链路上失效：级别先被清成 discovered，domain/identity 阶段瞬时失败时 `can_degrade(discovered, target)` 全拦截 → 返回 discovered。且失败证据落库后，下次重算看到的是失败行 → **后续所有失败路径持续退化到 DISCOVERED，agent 从验证结果中永久消失**。granular 入口（verify_domain_control 等）行为正确——两条路径语义分裂。
- **修复**：重置前保存原级别，降级以原级别为基准；重算按「最近一条 passed 证据」而非「最近一条证据」判级。补 refresh 中瞬时失败保留级别的回归测试。

### P1-8 队列满的优雅降级是死代码：`except VerificationQueueFullError` 引用未定义名字 → NameError 500
- **位置**：`api/handlers/agent_catalog.py:426`；名字只在 `:168` 函数内导入，模块级不存在 ✅
- **失败场景**：队列满（max_pending=50）→ 注册事务已提交 → enqueue 抛 VerificationQueueFullError → except 求值 NameError → 500；调用方重试 → 幂等重放返回「verification_enqueued=True, task_id=""」→ **验证永不执行而调用方以为已入队**——正是注释声称要避免的「静默不验证」。
- **修复**：模块级导入；加队列满测试断言 `verification_enqueued=False`。

---

## P2 发现（精选 14 条）

| # | 发现 | 位置 |
|---|------|------|
| 1 | 队列无同 agent 去重/串行化：并发 verify（worker×2 或 worker+同步请求）读-改-写竞态可把已晋升级别回退（P1-7 的放大器；超时重入队放大） | `agent_verification.py:1311-1369,987`；`sqlite_repository.py:664-709` |
| 2 | 超时语义是假的：runner 线程 commit 在 cancelled 检查之前（:1577→:1610），timeout 已返回后 runaway 线程仍提交 catalog 状态；`_persist_finish` 存在 TOCTOU 可把已落 timeout 改写成 completed | `agent_verification.py:1494-1631` |
| 3 | FastAPI 栈跳过整个 payload 校验层（JSON 深度/节点/大小上限 + 1MB body 上限只在 fallback 的 `handle_request`），任意大/深 body 直入内存——双栈 fail-open 差异 | `app.py:449-791` vs `limits.py:46-79` |
| 4 | 双栈错误响应系统性不一致：400 `{ok:false}` vs 422 `{detail}`、404/500 形状不同、ETag/304 只在 fallback 实现；双栈测试只断言路由集合不断言错误形状 | `fallback_asgi.py:98-133,176-189`；`app.py:461-491` |
| 5 | GET /v1/agents/{id}/listings 的 admin 豁免未生效（已绑定 merchant 时 admin 必 403，与 withdraw/reinstate 行为不一致）——两个审查 agent 独立发现 | `api/handlers/listings.py:147-159` |
| 6 | 状态机合法性仅是约定：`set_state_domains` 只校验枚举成员不校验迁移（可 discovered 直跳 commerce_verified、rejected 改回 active）；granular verify 入口不检查 administrative_state（SUSPENDED 可被提升） | `sqlite_repository.py:664-709`；`agent_verification.py:447-502` |
| 7 | canonical_domain 无唯一约束：并发同域注册产生永久重复行（一域一 agent 契约失效）；兜底 IntegrityError 未映射 → 500 | `agent_catalog_writes.py:168-172`；`models.py` |
| 8 | 慢滴漏无总时长上限：timeout 只约束单次 socket 读，1B/s 滴漏可把单个 fetch 线程钉住约 12 天，worker 池耗尽（redirect_limit=5 只限跳数） | `fetcher.py:88,639,715-737` |
| 9 | domain_control 只验 well-known 返回 200/304，响应体从不解析、不与声明 URL 内容比对；commerce_verified 仅需一条自报能力字符串（纯自证，无端点探测）——verified 语义与证据强度差距应写进文档 | `verifier.py:222-245,352-366` |
| 10 | 迁移两处升级风险：v7 唯一索引遇历史重复 merchant 绑定直接卡死启动（无诊断）；v8 回填无条件 UPDATE，对「列已存在+user_version<8」的中间版本库可覆盖真实三域值（数据丢失） | `db/migrations.py:272-275,321-340` |
| 11 | 数据目录/文件权限未落地：CLAUDE.md 约定 0700/0600，实际 mkdir 默认 0755、sqlite 文件 0644——同机其他用户可读 catalog.sqlite（含 token digest/审计/影子表） | `db/session.py:71` |
| 12 | 每次公开读都全表 STALE 翻转（无 fresh_until 索引，注释声称的索引路径不存在）——匿名读洪泛 = 写锁竞争放大器（放大 P1-5） | `listings/search.py:136`；`models.py:271-274` |
| 13 | suspend→listings 联动只走 legacy admin API 入口（`after_work` 挂钩）；CLI suspend 与队列 worker 自动 suspend 直接调 `service.suspend` 绕过——「两件事都做」契约 3 入口只落实 1 个（注：listings agent 误报为死代码，本人核验修正） | `handlers/agent_catalog.py:672-693` vs `cli_agent_catalog_commands.py:260`、`agent_verification.py:1570` |
| 14 | 杂项：ucp 快照 kind 串位（查 "ucp_profile" 存 "ucp"）→ ucp 的 304/ETag 缓存永不生效；LIKE 通配符未转义（2 处）；enqueue ledger 写失败遗留孤儿 `_tasks` → wait() 永久挂死；register 域限流 env 设 0 静默关闭 SSRF 放大防护；限流表/队列表永不清；publish/claim 先查后插竞态 IntegrityError→500；http 支持是假的（`_build_opener` 故意不注册 HTTPHandler，permissive_local 下 http:// 恒失败）；`_iso_from_epoch` 带微秒 vs `now_iso` 无微秒字符串比较 ≤1s 漂移；publish 幂等 hash 未含 display_name 等公开字段 | 见各文件 |

---

## P3（速览）

- `build/lib/` 52 个构建产物被 git 跟踪（.gitignore 漏 `build/`，上次只清 egg-info）✅
- 品牌串残留 shopping-cli（ucp_profile 版本串、CLI 提示、错误文案）；CLI/API/config 三条默认 DB 路径不一致
- 队列表时间戳用 epoch REAL，全库其余 ISO 文本——无格式契约
- N+1 查询（搜索结果每行 2 次额外查询，limit=100 → 200+ 次往返）
- legacy DTO 缺 merchant 影子行时回退块缺 id（schema 必填）
- owner/admin token 经 query string 传递，泄入访问日志/代理
- 已完成幂等行/限流行永不清理；auth 错误可区分「未配置」与「无效」辅助枚举
- `_parse_fresh_until` 微秒截断可产生「立即到期」的 fresh_until；a2a 构建器不校验/编码 id；CLI audit actor 自证不校验；`record_observation` 日期不校验；doctor 报告 `ok` 恒 True；`record_latency` 对负值抛异常；REJECTED 降级后 freshness 保持 FRESH 使 `/verify` 变 no-op

---

## 亮点（值得保持的部分）

1. **SSRF 核心链路过关**：DNS→全 IP 校验（loopback/私网/链路本地/ULA/元数据/IPv4-mapped，混合公网+私网整体拒绝）→ 直连已验证 IP + SNI 保留主机名校验证书（默认 `check_hostname=True`，无 `verify=False`）；重定向逐跳复检；跨协议跳转在 require_https 下拦截。核心链路无 P0 级绕过。
2. **认证设计扎实**：owner token = HMAC-SHA256 派生 + `hmac.compare_digest` 恒时比较；admin/worker/owner 三角色 fail-closed；merchant 隔离在 handler 层严格约束；无默认 token、缺配置 fail-closed。
3. **三域状态机纯逻辑正确**（一次一级、REJECTED 终态、降级重算），折叠投影当前所有写路径一致；SQL 全参数化无注入面；迁移结构（user_version 门 + 幂等 ALTER + SCHEMA 逐字对齐）是仓库最扎实部分。
4. **测试量大**（130 个，含契约词表断言、shadow JOIN、双栈路由覆盖）；license header 全合规；systemd 单元硬化到位。

---

## 修复优先级建议

1. **P1-3 测试 harness 补 content-type 头**（10 分钟）→ 恢复真绿，建立后续一切修复的基线；顺手补 CI。
2. **P1-1 secret 扫描 fail-closed**（安全，30 分钟）。
3. **P1-5 写事务移出网络 I/O**（可用性，半天~一天：分阶段提交）。
4. **P1-4 治理绕过两条路径**（加守卫 + 语义统一）。
5. **P1-6 分页游标对齐排序键**（4 处 + 回归测试）。
6. **P1-7 降级语义**（保留原级别基准 + passed-证据优先）。
7. **P1-2 fetcher 异常面**（RecursionError/ValueError 映射）。
8. **P1-8 NameError 一行修复**（+队列满测试）。
9. P2 按上表：双栈对齐（payload 校验/错误形状/ETag）、队列去重与超时语义、0700/0600 权限、迁移回填守卫、index 清理。
