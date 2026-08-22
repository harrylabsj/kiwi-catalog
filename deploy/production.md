# kiwi-catalog 生产部署与升级（阿里云香港 + Caddy）

- 状态：2026-08-08 核实。线上已运行旧版（`/v1/merchants/*`、`/portal/*` 404），
  需按本文升级到 token 分发版。
- 生产拓扑（已核实，curl -v 实测）：

```
https://catalog.kiwi.harrylabsj.com ──> Caddy（TLS 终结，via: 1.1 Caddy）
    └──> 127.0.0.1:8600 ──> kiwi-catalog（systemd，uvicorn）
            db: /var/lib/kiwi-catalog/catalog.sqlite
```

- 说明：TLS 由 Caddy 反代终结（非 Cloudflare Tunnel——2026-08-08 曾规划
  tunnel 方案，实际部署用 Caddy，本文件为准）。

## 环境事实（已核实）

| 项 | 值 |
| --- | --- |
| 服务 | `kiwi-catalog.service`（`deploy/systemd/`，`--host 127.0.0.1 --port 8600`） |
| 数据库 | `/var/lib/kiwi-catalog/catalog.sqlite`（`/health` 实测） |
| 反代 | Caddy（`via: 1.1 Caddy`），`catalog.kiwi.harrylabsj.com` |
| 配置 | `/etc/kiwi-catalog/env`（EnvironmentFile） |
| 域名 | `catalog.kiwi.harrylabsj.com`（**生产唯一入口**；门户 `/portal/*` 与 API `/v1/*` 同域） |

## 升级到 token 分发版（本次）

### 1. 代码同步

主机 `/opt/kiwi-catalog`（systemd unit 的 WorkingDirectory）：
git pull 或 rsync 本仓库；装依赖 `pip install -e '.[api]'`（或 `uv pip install`）。

### 2. 环境变量（/etc/kiwi-catalog/env）

新代码需要两个 env（**缺失即 fail-closed**，门户 admin 页与签发端点拒绝）：

```sh
KIWI_CATALOG_ADMIN_TOKEN=<强随机值>        # 审核后台/签发/轮换/吊销
KIWI_CATALOG_OWNER_TOKEN_SECRET=<强随机值>  # 存量 HMAC 派生 fallback（兼容旧调用方）
KIWI_CATALOG_EMAIL_VERIFICATION_MODE=smtp  # 生产必须 smtp；未配置会 fail-closed
# KIWI_CATALOG_SMTP_HOST / _PORT / _USER / _PASSWORD / _FROM
# 已移除：KIWI_CATALOG_APPLY_RATE_LIMIT_PER_HOUR（2026-08-12 匿名申请通道关闭，限流并入登录限流 env）
# 可选：KIWI_CATALOG_DISCOVERY_SEARCH_RATE_LIMIT_PER_MINUTE=60（默认 60 次/分，公开发现目录检索）
# 可选：KIWI_CATALOG_STATS_SALT=<强随机值>（每日去重买家统计的 HMAC salt；默认 dev 值，
# 轮换会使存量 buyer_hash 失效——只影响历史去重口径，不丢事件数）
# 可选：KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS=90（个体访问日志保留天数；默认 90，
# 写路径每 N 条概率触发清理超期行）
# 可选：KIWI_CATALOG_KEYWORD_SOURCE=access_log（关键词排行数据源；默认 access_log
# 派生，Phase 3 单一事实源；回退旧聚合表设 buyer_keyword_daily）
```

> 若线上已有 `KIWI_CATALOG_OWNER_TOKEN_SECRET` 且 merchant 在用 HMAC token，
> **不要换 secret**（换了全量失效）。新增 admin token 即可。

### 3. 重启

```sh
sudo systemctl restart kiwi-catalog
# 首次启动自动跑迁移 v16（accounts / email verification / token tables，
# 幂等 create-if-not-exists + user_version 门，
# 存量数据不破坏）
journalctl -u kiwi-catalog -n 20 --no-pager   # 确认无迁移错误
```

### 4. 验证清单（升级后）

```text
[ ] curl -s https://catalog.kiwi.harrylabsj.com/health                → ok
[ ] curl -s -o /dev/null -w '%{http_code}' \
      https://catalog.kiwi.harrylabsj.com/portal/apply                → 200 + text/html + no-store
[ ] curl -s https://catalog.kiwi.harrylabsj.com/v1/merchants/self     → 403（无 token，fail-closed 正常）
[ ] 门户申请 → 提交成功返回 application_id
[ ] admin 登录审核 → 批准签发 → 明文 token 一次性展示
[ ] 用 token 调 /v1/agents/register + /v1/listings/publish → 200
[ ] 官网 CTA（catalog.kiwi.harrylabsj.com/portal/apply）可点通
```

## 安全边界（升级后成立）

- catalog 通过 systemd 监听 127.0.0.1:8600，仅允许同机 Caddy 反代访问；
  容器部署才使用 0.0.0.0（由 Docker 网络边界控制）。
- admin token fail-closed：未配置即拒绝（不区分未配置与无效，防枚举探测）；
- approve/rotate 响应只返回新明文一次；已登录商家账号页可再次查看 active token，
  因此应将会话视为敏感凭据，疑似泄露时立即联系运营轮换；门户响应仍为 no-store。
- 申请面按邮箱限流。

## 回滚

```sh
git checkout <旧 tag> && sudo systemctl restart kiwi-catalog
# schema v16 表对旧代码透明（旧代码不读新表）；已签发的 merchant_tokens
# 在旧版 HMAC 路径下不生效（随机 token 需新代码校验）——回滚后商家需等
# 再次升级，勿在回滚期间宣称门户可用。
```
