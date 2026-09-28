# kiwi-catalog

当前源码发布线：`0.5.0`；最近的 PyPI 发布记录为 `0.2.2`。PyPI 发布由 Kiwi portfolio workflow 统一触发，见 [Portfolio 发布管理](https://github.com/harrylabsj/kiwi/blob/main/docs/portfolio-release-management.md)。

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
- **Listing 域**：`/v1/listings/publish|withdraw|reinstate|search|get`
  + publisher 自查 `/v1/agents/{id}/listings`；已连接 Runtime 使用绑定签名，
  注册商家自动获得可配置的免费商品名额（见 [商品名额说明](docs/listing-entitlements.md)）。
- **商家接入（v0.5+）**：`/v1/merchants/*` token 申请/审批/恢复
  （Fernet 加密存储）+ `/v1/accounts/*` 商家账号 API；商家后台 HTML 由私有
  `kiwi-catalog-admin` 扩展提供；**注册即商家**——注册即分配 merchant_id 与免费方案，
  邮箱验证和 Runtime 连接后可在额度内发布。
- 商家门户和运营/审核后台（`/portal/*` HTML）均由私有扩展提供；核心仅保留
  `/v1/accounts/*`、`/v1/merchant-publications/*` 等业务 API。
- 治理（suspend/reinstate——owned Listings 联动置 SUSPENDED、双维度限流、
  审计、§24 runtime metrics）

## 快速开始

```bash
pip install -e '.[api]'
export KIWI_CATALOG_ADMIN_TOKEN=change-me   # moderation 用（运营后台在私有扩展里）
export KIWI_CATALOG_OWNER_TOKEN_SECRET=change-me
kiwi-catalog-api --db catalog.sqlite --host 127.0.0.1 --port 8600
```

商家后台页面由私有仓 `kiwi-catalog-admin` 提供；需要在同一 Python 环境安装该扩展，
并设置 `KIWI_CATALOG_EXTENSIONS=kiwi_catalog_admin`（部署步骤见
[`kiwi-catalog-admin` 安装说明](https://github.com/harrylabsj/kiwi-catalog-admin)）。

## 认证

- **admin token**（`KIWI_CATALOG_ADMIN_TOKEN`）：moderation 动作
  （suspend/reinstate）与 verify。运营/审核 API（`/v1/admin/*`、
  商家审核 HTTP API）**不在本包**——以私有扩展
  `kiwi-catalog-admin` 经 `KIWI_CATALOG_EXTENSIONS` 挂载（docs/extensions.md）；
- **catalog-owner token**（`KIWI_CATALOG_OWNER_TOKEN_SECRET` 派生 HMAC）：
  owner 语义（claim/refresh）——`kiwi_catalog.api.auth.owner_token(merchant_id)`
  生成，请求体 `owner_token` 字段携带。

## 架构要点

- 独立 SQLite schema；当前迁移版本为 `41`（`db/migrations.py`）。
  Listings 方案、商家权益和额度审计由 schema 40 增加；schema 41 将免费默认额度调整为 20，与 shopping-cli 分别演化。
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
