# 0.5.15 保活发布方案（本地评审稿）

本文件是上线操作清单，不是已在生产执行的记录。生产执行前必须重新核对实际
`PRAGMA user_version`、备份校验和、制品哈希与环境配置。

## 版本与制品

| 组件 | 新版本 | 制品 |
| --- | --- | --- |
| kiwi-catalog | `0.5.15`（PyPI 已占用到 0.5.14，0.5.15 未占用） | `dist/kiwi_catalog-0.5.15-py3-none-any.whl` / `.tar.gz` |
| kiwi-catalog-admin | `0.2.13`（私有仓，不发布 PyPI） | `dist/kiwi_catalog_admin-0.2.13-py3-none-any.whl` |

admin 0.2.13 的依赖下限已收紧为：

```text
kiwi-catalog[api]>=0.5.15,<0.6
```

0.5.1–0.5.14 没有保活 consent 端点，不能与本 UI 搭配；`test_dependency_floor.py`
和 wheel metadata 都必须显示该下限。

依赖锁：

- `kiwi-catalog/uv.lock` 已更新到本项目 `0.5.15`；
- `kiwi-catalog-admin/uv.lock` 仍解析到已发布的 core `0.5.14`，因为 `0.5.15`
  尚未发布；该文件在 admin 仓被 `.gitignore` 忽略，不是发布制品。**发布 core 后**
  必须在 admin 仓重新执行 `uv lock`，确认解析结果为 `0.5.15`，再跑全量测试、
  重建 admin wheel 并检查 wheel `METADATA` 中的
  `Requires-Dist: kiwi-catalog[api]<0.6,>=0.5.15`。

## 当前 schema 与升级

源码当前 `CURRENT_SCHEMA_VERSION = 49`。v49 只增加：

- `runtime_keepalive_consents.last_attempt_at`；
- `runtime_keepalive_state(singleton,last_tick_at)`。

升级前：

```bash
systemctl stop kiwi-catalog
sqlite3 /var/lib/kiwi-catalog/catalog.sqlite \
  ".backup '/var/backups/kiwi-catalog/catalog-before-0.5.15.sqlite'"
sqlite3 /var/lib/kiwi-catalog/catalog.sqlite "PRAGMA wal_checkpoint(TRUNCATE);"
sha256sum /var/backups/kiwi-catalog/catalog-before-0.5.15.sqlite
sqlite3 /var/backups/kiwi-catalog/catalog-before-0.5.15.sqlite \
  "PRAGMA integrity_check; PRAGMA user_version;"
```

必须记录实际备份前 `user_version`；如果线上不是 48，先核对 migration 链，
不能假定。升级后验证：

```bash
sqlite3 /var/lib/kiwi-catalog/catalog.sqlite \
  "PRAGMA integrity_check; PRAGMA user_version;"
# user_version 必须为 49
sqlite3 /var/lib/kiwi-catalog/catalog.sqlite \
  "SELECT name FROM sqlite_master WHERE type='table' AND name='runtime_keepalive_state';"
sqlite3 /var/lib/kiwi-catalog/catalog.sqlite \
  "PRAGMA table_info(runtime_keepalive_consents);" | grep last_attempt_at
```

## 回滚

v49 没有 down migration，旧包会拒绝打开 `user_version > 48` 的库。回滚只能：

```bash
systemctl stop kiwi-catalog
install -m 600 /var/backups/kiwi-catalog/catalog-before-0.5.15.sqlite \
  /var/lib/kiwi-catalog/catalog.sqlite
# 回装 0.5.14 + admin 0.2.12
systemctl start kiwi-catalog
```

不要只回装旧包而不恢复数据库；否则服务会因 schema 版本过新拒绝启动。

## 配置

已有核心配置保持不变（owner secret、access config keys、扩展装载等）。
新增配置默认不启用：

```bash
# 先保持关闭；验收通过后才改成 1
KIWI_CATALOG_KEEPALIVE_ENABLED=0

# 只有验收通过后才设置；必须是精确 host，不允许通配符
KIWI_CATALOG_KEEPALIVE_TRUSTED_HOSTS=linkluck-reception.app.workbuddy.host

# 默认值由 TTL 派生；可显式覆盖，但必须满足 interval/cooldown <= lead
KIWI_CATALOG_KEEPALIVE_INTERVAL_SECONDS=300
KIWI_CATALOG_KEEPALIVE_COOLDOWN_SECONDS=150
KIWI_CATALOG_KEEPALIVE_CONCURRENCY=1
KIWI_CATALOG_KEEPALIVE_MAX_AGENTS=10
KIWI_CATALOG_KEEPALIVE_POLL_SECONDS=30
KIWI_CATALOG_AGENT_FRESH_TTL_SECONDS=900
```

关系（默认 TTL 900s）：

```text
lead     = 300s
due      = last_seen + 600s
interval = 300s
cooldown = 150s
```

interval/cooldown 超过 lead 会被拒绝创建 scheduler。只有商家显式
`directory_keepalive` 授权、active custody/config/binding 且 `/merchant/`
host 在 allowlist 内时才会发送；探测不改在线状态。

## 安装与启动

```bash
# 先 core，后 admin
/opt/kiwi-catalog/.venv/bin/pip install \
  /path/to/kiwi_catalog-0.5.15-py3-none-any.whl
/opt/kiwi-catalog/.venv/bin/pip install \
  /path/to/kiwi_catalog_admin-0.2.13-py3-none-any.whl

/opt/kiwi-catalog/.venv/bin/kiwi-catalog-api --check-config

# 先保持 KEEPALIVE_ENABLED=0 启动
systemctl daemon-reload
systemctl start kiwi-catalog
systemctl status kiwi-catalog --no-pager
```

确认启动后 `/portal/account/card` 仍由 admin 扩展提供，且核心 API 正常。
验收通过后设置 `KIWI_CATALOG_KEEPALIVE_ENABLED=1`，再：

```bash
systemctl restart kiwi-catalog
```

## 验收

1. **UI 实际连接**：登录商家工作台，打开 `/portal/account/card`，确认
   「目录保活授权」可见、条款可读、默认关闭；点击授权后重新加载仍为已授权，
   撤销后为未授权。不得在页面/网络日志看到分享码。
2. **接口**：`GET/PUT /v1/agents/{id}/runtime-keepalive-consent` 使用同一
   `kiwi_session`，授权/撤销都返回 200；未登录/他人 merchant 返回 403。
3. **FastAPI 生命周期**：
   - 未配置时启动无线程；
   - 配置 enabled + hosts 后启动单线程；
   - `systemctl stop` 后线程退出，进程正常结束。
4. **重启恢复**：重启后 scheduler 读取 DB 的 `last_tick_at`/`last_attempt_at`，
   不在 cooldown 内重复请求。
5. **多进程**：若启动多个 worker，共享同一 SQLite；请求次数不超过单次
   tick claim，不出现同一 agent 并发重复。
6. **保活时机**：在线商家在 last_seen+600s 进入探测窗口；探测不改变
   `freshness_state`；只有商家真实签名心跳恢复 fresh。
7. **撤销**：撤销后下一次 tick 不再发送；已发出的单次请求不可取消，需确认
   该竞态窗口可接受。
8. **回滚演练**：在预生产用备份恢复并回装旧包验证。

## 本地离线安装与 HTTP 联调（已做）

使用已构建的 core 0.5.15 wheel 和 admin 0.2.13 wheel，在独立临时 venv 中：

```bash
pip install --no-index --no-deps \
  kiwi_catalog-0.5.15-py3-none-any.whl \
  kiwi_catalog_admin-0.2.13-py3-none-any.whl
```

实测：

```text
kiwi-catalog 0.5.15（从 wheel 安装）
kiwi-catalog-admin 0.2.13（从 wheel 安装）
FastAPI 0.141.1 / uvicorn 0.35.0
```

启动真实 uvicorn 后，用登录 session cookie 请求：

```text
GET  /portal/account/card                         200，包含 keepalive_card
GET  /v1/agents/{id}/runtime-keepalive-consent    200，granted=false
PUT  /v1/agents/{id}/runtime-keepalive-consent    200，granted=true
PUT  /v1/agents/{id}/runtime-keepalive-consent    200，granted=false
```

服务收到 SIGTERM 后日志显示 application shutdown complete；日志未出现
`sharecode=`、session token 或分享码。FastAPI 生命周期测试同时覆盖默认不启动
线程、显式配置启动单线程、退出后线程停止。

## 备份恢复测试

本地已实测 v48→v49：

```text
test_v48_to_v49_preserves_rows_and_adds_state      passed
test_backup_restores_v48_after_v49_upgrade         passed
```

备份必须是完整 SQLite 文件（停机 `.backup` + WAL checkpoint），恢复后再次
`PRAGMA integrity_check`；不要只回滚 Python 包。

## 制品哈希


记录 `dist/*` 的 SHA-256 后再发布；本地方案生成值见发布记录，不以本文件的
静态文本替代重新计算。
