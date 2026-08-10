# kiwi-catalog 部署手册（云主机 + systemd + Caddy）

> 这是可公开的部署模板。真实服务器 IP、实例 ID、内网地址、SSH 用户名和密钥路径不写入仓库；请通过私有运维系统或部署平台注入占位符。

## 0. 部署拓扑

```
用户/Agent（kiwi runtime / shopping-cli / 浏览器）
        │ https://catalog.kiwi.harrylabsj.com
        ▼
DNS（A/AAAA 记录，按组织网络策略选择是否代理）
        ▼
云主机 ${SERVER_HOST}
        ├── Caddy :443/:80（TLS 终结）
        │       └── reverse_proxy 127.0.0.1:8600
        └── kiwi-catalog（systemd，监听 127.0.0.1:8600）
                └── SQLite /var/lib/kiwi-catalog/catalog.sqlite
```

## 1. 需要由私有运维系统提供的变量

| 变量 | 说明 |
| --- | --- |
| `SERVER_HOST` | 云主机公网 DNS 名称或地址；不要提交真实值 |
| `SERVER_USER` | 受限部署用户；禁止把长期 root 登录信息写入文档 |
| `SSH_KEY_PATH` | 本机私有 SSH 密钥路径；不要提交密钥文件 |
| `SERVER_REGION` | 云厂商与地域 |
| `CATALOG_BASE_URL` | 对外 HTTPS 入口，默认 `https://catalog.kiwi.harrylabsj.com` |

建议通过 CI/CD secret、云端密钥管理或密码管理器注入这些变量。仓库只保存下面的命令模板。

## 2. 前置条件

1. 云主机运行受支持的 Linux LTS，启用自动安全更新。
2. DNS 已将 `catalog.kiwi.harrylabsj.com` 指向云主机或负载均衡器。
3. 公网只放行 TCP 22（受限来源）、80、443；应用端口 8600 只监听回环地址。
4. 部署用户具备发布目录和 systemd 服务所需的最小权限。

## 3. 部署步骤

### 3.1 SSH 与目录

```bash
ssh-add "${SSH_KEY_PATH}"
ssh -i "${SSH_KEY_PATH}" "${SERVER_USER}@${SERVER_HOST}" \
  'hostname && cat /etc/os-release | sed -n "1,3p"'

ssh -i "${SSH_KEY_PATH}" "${SERVER_USER}@${SERVER_HOST}" \
  'id kiwi-catalog 2>/dev/null || sudo useradd --system --home /opt/kiwi-catalog --shell /usr/sbin/nologin kiwi-catalog'
ssh -i "${SSH_KEY_PATH}" "${SERVER_USER}@${SERVER_HOST}" \
  'sudo install -d -o kiwi-catalog -g kiwi-catalog /opt/kiwi-catalog /var/lib/kiwi-catalog /etc/kiwi-catalog'
```

### 3.2 构建与传输

在本地工作区执行，先完成 `uv sync --locked --extra api --extra dev` 和测试，再创建不含 `.git`、`.venv`、缓存及密钥的归档：

```bash
tar --exclude='.git' --exclude='__pycache__' --exclude='*.egg-info' \
    --exclude='.venv' --exclude='*.sqlite*' -czf /tmp/kiwi-catalog.tar.gz .
scp -i "${SSH_KEY_PATH}" /tmp/kiwi-catalog.tar.gz \
  "${SERVER_USER}@${SERVER_HOST}:/tmp/kiwi-catalog.tar.gz"
ssh -i "${SSH_KEY_PATH}" "${SERVER_USER}@${SERVER_HOST}" \
  'sudo rm -rf /opt/kiwi-catalog/* && sudo tar -xzf /tmp/kiwi-catalog.tar.gz -C /opt/kiwi-catalog && sudo chown -R kiwi-catalog:kiwi-catalog /opt/kiwi-catalog'
```

### 3.3 Python 环境与运行时密钥

```bash
ssh -i "${SSH_KEY_PATH}" "${SERVER_USER}@${SERVER_HOST}" <<'REMOTE'
set -euo pipefail
cd /opt/kiwi-catalog
sudo apt-get update -qq
sudo apt-get install -y -qq python3-venv
sudo -u kiwi-catalog python3 -m venv .venv
sudo -u kiwi-catalog .venv/bin/pip install --upgrade pip
sudo -u kiwi-catalog .venv/bin/pip install '.[api]'
REMOTE
```

管理员令牌与 owner secret 必须由私有密钥管理系统生成，写入 `/etc/kiwi-catalog/env`，权限设为 `0600`，不能写入 shell 历史、镜像层、日志或 Git：

```text
KIWI_CATALOG_ADMIN_TOKEN=<injected-secret>
KIWI_CATALOG_OWNER_TOKEN_SECRET=<injected-secret>
```

### 3.4 systemd

安装 `deploy/systemd/kiwi-catalog.service`，确认服务使用 `User=kiwi-catalog`、`NoNewPrivileges=true`、只读系统目录保护，并将监听地址固定为 `127.0.0.1:8600`。修改服务后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kiwi-catalog
sudo systemctl status kiwi-catalog --no-pager
```

### 3.5 Caddy 与 HTTPS

```caddyfile
catalog.kiwi.harrylabsj.com {
    reverse_proxy 127.0.0.1:8600
}
```

验证配置后重载 Caddy。DNS 未生效时不要把证书错误写入公开 issue；在私有运维记录中处理 DNS 传播问题。

## 4. 上线验证清单

```bash
curl -fsS "${CATALOG_BASE_URL}/health"
curl -fsS "${CATALOG_BASE_URL}/v1/agents"
```

- `/health` 返回服务健康状态，不包含文件系统绝对路径、环境变量或密钥。
- 未携带 token 的受保护 API 返回 401/403，不能返回调试 traceback。
- 8600 从公网不可达，Caddy 只允许 HTTPS 入口。
- 生产环境关闭 debug/OpenAPI 暴露或按组织策略加访问控制。
- 备份、恢复、令牌轮换和日志保留策略记录在私有运维系统。

## 5. 更新与回滚

每次更新使用已验证的 release artifact 或固定 commit，先在临时目录解包并执行锁定依赖安装、契约校验和测试，再原子替换 `/opt/kiwi-catalog`。回滚到上一个已验证 artifact，不在服务器上直接 `git pull`，也不删除当前数据库备份。

## 6. 网络故障排查（私有环境）

如果本机代理/TUN 接管了到服务器的路由，只在本机私有配置中将 `${SERVER_HOST}` 对应的目标加入直连规则。代理配置文件路径、网关地址和控制器端口不要写入仓库或公开日志。

## 7. 安全底线

- 不提交真实 IP、实例 ID、内网地址、SSH 用户名、密钥文件名或代理配置路径。
- 不在命令行参数、Docker build args、systemd unit、公开 CI 日志中传递 token。
- 只允许 HTTPS 访问外部 catalog，SSRF 保护与 DNS/IP 解析策略保持默认 fail-closed。
- 发布前运行 `uv lock --check`、`uv run --locked python scripts/verify_contract_lock.py` 与完整测试。
