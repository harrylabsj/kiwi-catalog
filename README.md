# kiwi-catalog

当前开发发布线：`0.2.2`（PyPI 正式发布仍由 Kiwi portfolio workflow 统一触发）。

独立部署的 Agent Catalog 服务——从 shopping-cli 抽离（
`shopping-cli/docs/shopping-cli-agent-catalog-extraction-plan-v1.0.md`，
切割分水岭：**不含托管协商与 marketplace 域**）。

## 能力

- 注册/发布（`POST /v1/agent-catalog/agents/register` + v1 面
  `POST /v1/agents/register` + hosted 发布面
  `GET /v1/hosted/agents/{id}/agent-card.json` / `ucp`）
- 验证（HTTPS domain-control / agent identity / commerce，持久验证队列）
- 发现/搜索（`GET /v1/agent-catalog/agents/search`，CandidateAgent DTO；
  v1 面 `/v1/agents/search`：三态域——VerificationLevel / FreshnessState /
  AdministrativeState——与 KTH destination_type 词表过滤）
- **Listing 域（v0.4）**：`/v1/listings/publish|withdraw|reinstate|search|get`
  + publisher 自查 `/v1/agents/{id}/listings`（行级幂等 upsert、服务端
  digest、fresh_until TTL、owner token 双路径认证）
- **商家接入（v0.5+）**：`/v1/merchants/*` token 申请/审批/恢复
  （Fernet 加密存储）+ `/v1/accounts/*` 与 `/portal` 商家门户（账号注册/
  登录/Token 管理；**注册即商家**——商家名称 + 邮箱 + 密码注册即分配
  merchant_id、admin dashboard 无需审批即可见，令牌仍单独申请/审批）
- 治理（suspend/reinstate——owned Listings 联动置 SUSPENDED、双维度限流、
  审计、§24 runtime metrics）

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

- 独立 SQLite schema：**20 张表**（`db/models.py` 单一 SCHEMA 源：
  catalog 域 6 + 治理域 4 + listing 域 + 商家接入/账号域 7 + 影子域 3），
  `CURRENT_SCHEMA_VERSION = 16`（`db/migrations.py`，与 shopping-cli 各自
  演化）；弱引用——对 merchants/agents 外部表无 FK；
- 账号与 Token：`merchant_accounts` / `account_sessions` / `merchant_tokens`
  （Fernet 加密 `token_encrypted`）/ `merchant_applications`（申请+审批），
  详见 `docs/accounts.md`；
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
