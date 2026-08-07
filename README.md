# kiwi-catalog

独立部署的 Agent Catalog 服务——从 shopping-cli 抽离（
`shopping-cli/docs/shopping-cli-agent-catalog-extraction-plan-v1.0.md`，
切割分水岭：**不含托管协商与 marketplace 域**）。

## 能力

- 注册/发布（`POST /v1/agent-catalog/agents/register` + hosted 发布面
  `GET /v1/hosted/agents/{id}/agent-card.json` / `ucp`）
- 验证（HTTPS domain-control / agent identity / commerce，持久验证队列）
- 发现/搜索（`GET /v1/agent-catalog/agents/search`，CandidateAgent DTO）
- 治理（suspend/reinstate、双维度限流、审计、§24 runtime metrics）

## 快速开始

```bash
pip install -e '.[api]'
export KIWI_CATALOG_ADMIN_TOKEN=change-me
export KIWI_CATALOG_OWNER_TOKEN_SECRET=change-me
kiwi-catalog-api --db catalog.sqlite --host 127.0.0.1 --port 8600
```

## 认证

- **admin token**（`KIWI_CATALOG_ADMIN_TOKEN`）：moderation 动作
  （suspend/reinstate）与 verify；
- **catalog-owner token**（`KIWI_CATALOG_OWNER_TOKEN_SECRET` 派生 HMAC）：
  owner 语义（claim/refresh）——`kiwi_catalog.api.auth.owner_token(merchant_id)`
  生成，请求体 `owner_token` 字段携带。

## 架构要点

- 独立 SQLite schema：10 张 catalog 表（去 merchants/agents 外键，
  弱引用）+ 影子表（merchants public 字段 / audit_events）+ migration
  子链 v1–v6（与 shopping-cli 的 v15 各自演化）；
- 持久验证队列（ledger 写穿 + crash recovery）随包；
- SSRF fetcher 的 socket 级防护（DNS→IP 校验 + 直连已验证 IP）原样保留
  ——**不要在无真实网络栈的 serverless 上部署**（如 Cloudflare Workers），
  VM/容器（腾讯云/阿里云轻量等）是目标形态。

## 部署

- 容器：`docker build -t kiwi-catalog . && docker run -v catalog-data:/data ...`
  （Dockerfile，SQLite 落持久卷）；
- VM：`deploy/systemd/kiwi-catalog.service`（systemd 守护 + 环境文件）；
- 多实例：接 PG + Redis 限流（P3/P5 接缝，见 shopping-cli 接缝文档）。

## 测试

```bash
python3 -m unittest discover -s tests
```

## License

[Apache License 2.0](LICENSE) — wire 契约（权威在 kiwi 仓）与实现同许可
（与 Kiwi、shopping-cli 一致）。
