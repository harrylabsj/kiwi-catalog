# kiwi-catalog P0 安全复核记录（2026-08-09）

## 结论

代码侧 P0 已完成：门户存储型 XSS 防护、CSP/响应头硬化，以及 admin token 不进入 query string 的路径收口均已落地。生产 admin token 已完成轮换并验证旧 token 失效；历史日志中的 query 记录仍需按组织凭据事件流程脱敏/封存或限制访问后，P0 才可完全关单。

## 代码证据

- 门户动态数据统一经 `escHtml` 或 `textContent` 写入；内嵌脚本使用 per-response nonce；响应提供 `Content-Security-Policy: frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`。相关安全提交：`ed51fe2`、`cd943f9`。
- 门户管理界面的 GET 请求与 `GET /v1/agents/{id}/listings` 的 admin 凭据来自
  `Authorization: Bearer`；后者对 `?admin_token=...` fail-closed，legacy
  `owner_token` query 自查语义保留。现有 POST 调用的 JSON `admin_token` 兼容路径
  未改变，且不进入 URL/query。修复提交：`6a32c9e`。
- FastAPI 与 fallback ASGI 双栈都透传 Authorization；不再从 listings query 派生 `admin_token`。

## 独立验收

- P0 相关 portal/admin/listings/FastAPI 双栈测试：62 passed。
- kiwi-catalog 全量测试：274 passed。
- production code 扫描不再发现 `query.get("admin_token")` 或等价 query 派生 admin 凭据路径；仅保留安全边界说明注释。
- 当前 ruff 检查仍有 3 条既有基线告警（`app.py` 的 TRY401、两个测试文件的未使用 import），不由本 P0 提交引入。

## 生产侧待办

1. 在生产 `/etc/kiwi-catalog/env` 生成新的高熵 `KIWI_CATALOG_ADMIN_TOKEN`，重启 `kiwi-catalog`，并用 Authorization header 验证 admin 端点；不要修改仍在使用中的 `KIWI_CATALOG_OWNER_TOKEN_SECRET`。
2. 在 Caddy/access log、APM、WAF 和集中日志中搜索 `admin_token=`，按凭据事件处理并清理/限制历史暴露；确认新代码上线后不再出现该 query 参数。
3. 记录轮换时间、旧 token 失效验证、日志检索范围和操作者，作为发布前 P0 复核证据。

### 部署管理员交接步骤（不在本地执行）

- 通过受控终端生成新 token，仅替换 `/etc/kiwi-catalog/env` 中的
  `KIWI_CATALOG_ADMIN_TOKEN`；保留仍在使用的
  `KIWI_CATALOG_OWNER_TOKEN_SECRET`，并维持文件权限 `0600`。
- `systemctl restart kiwi-catalog` 后确认服务健康；使用新 token 的
  `Authorization: Bearer <new-token>` 请求 `/v1/admin/dashboard?days=1`，再用无
  Authorization header 的 `?admin_token=probe-invalid` 请求确认 query 凭据返回
  `401/403`。探针值必须是一次性假值，不得把真实凭据放入 URL。
- 在 Caddy、systemd、APM、WAF 和集中日志的保留范围内检索
  `admin_token=`；按组织凭据事件流程脱敏、封存或限制访问，禁止未经批准直接删除
  审计记录。新版本上线后再次检索并记录“无新增 query 凭据”的时间窗口。
- 回填：轮换时间、旧 token 失效结果、服务版本/提交、验证 URL（不含凭据）、日志
  系统与时间范围、处置方式、操作者和审批号。回填内容不得包含 token 明文。

## 生产执行证据（2026-08-09）

- 已部署经本地验收的源码包（提交 `6a32c9e`，包 SHA-256
  `ec990076b1fd0fa1f973b5bbfae85c54b973fe836efbc2d06de9056ca46c3050`）；部署前源码备份位于生产 `/opt/kiwi-catalog-backups/`，服务重启后健康检查为 `200`。
- `KIWI_CATALOG_ADMIN_TOKEN` 已轮换，`KIWI_CATALOG_OWNER_TOKEN_SECRET` 未改动；环境文件保持 `0600 root:root`。
- 认证回归：新 token `200`；旧 token `403`；无 Authorization 的
  `admin_token=probe-invalid` `403`；Authorization + 假 query `200`。探针值不是真实凭据。
- 轮换前 24 小时 journald 计到 16 条 `admin_token=`（未读取正文）；轮换后仅新增 2 条上述假探针记录；当前 token 命中数为 `0`。Caddy 日志文件命中数为 `0`；journald 文件权限为 `640 root:systemd-journal`。
- 尚未删除或重写历史审计日志：缺少明确的组织保留/脱敏批准。历史记录已因旧 token 失效而不可用于认证，但仍需凭据事件流程完成处置并记录操作者与范围。

本地工作区不保存生产凭据；上述生产执行证据仅记录状态码、哈希和计数，不包含 token 明文或日志正文。历史日志处置仍以生产组织的保留/脱敏批准为准。
