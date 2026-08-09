# kiwi-catalog P0 安全复核记录（2026-08-09）

## 结论

代码侧 P0 已完成：门户存储型 XSS 防护、CSP/响应头硬化，以及 admin token 不进入 query string 的路径收口均已落地。生产侧仍有两项必须由部署管理员执行的动作：轮换 `KIWI_CATALOG_ADMIN_TOKEN`，并检索/清理反向代理、APM 与访问日志中的历史 `admin_token` query 记录。

## 代码证据

- 门户动态数据统一经 `escHtml` 或 `textContent` 写入；内嵌脚本使用 per-response nonce；响应提供 `Content-Security-Policy: frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`。相关安全提交：`ed51fe2`、`cd943f9`。
- `/v1/merchants/*`、`/v1/admin/*` 及 `GET /v1/agents/{id}/listings` 的 admin 凭据统一来自 `Authorization: Bearer`。`GET /v1/agents/{id}/listings?admin_token=...` 即使 token 正确也会 fail-closed；legacy `owner_token` query 自查语义保留。修复提交：`6a32c9e`。
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

本地工作区没有生产主机、日志或有效远程运维授权，因此本记录不宣称上述生产动作已经完成。
