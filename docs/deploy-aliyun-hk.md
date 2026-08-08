# kiwi-catalog 部署手册（阿里云 ECS 香港 · systemd + Caddy）

> 状态：本文档对应 **2026-08-08 官方生产部署**（catalog.kiwi.harrylabsj.com，
> 服务器 `${SERVER_NAME}`）。步骤均已实测，可作为复现手册。
> 部署形态：**VM + systemd + Caddy 反代**（README 明确要求真实网络栈，
> 不要在 serverless 上部署——SSRF fetcher 的 socket 级防护依赖真实网络）。

## 0. 部署拓扑

```
用户/Agent（kiwi runtime / shopping-cli / 浏览器）
        │  https://catalog.kiwi.harrylabsj.com
        ▼
Cloudflare DNS（A 记录，DNS only，不代理）
        │
        ▼
阿里云 ECS 香港 ${SERVER_NAME}（${SERVER_HOST}）
        ├── Caddy :443/:80  （Let's Encrypt 自动证书）
        │        └── reverse_proxy 127.0.0.1:8600
        └── kiwi-catalog（systemd 守护，监听 8600）
                └── SQLite /var/lib/kiwi-catalog/catalog.sqlite
```

## 1. 服务器信息（本次部署实例）

| 项 | 值 |
| --- | --- |
| 云厂商 / 地域 | 阿里云 ECS · 香港 |
| 实例名 | ${SERVER_NAME} |
| 实例 ID | ${INSTANCE_ID} |
| 公网 IP | ${SERVER_HOST} |
| 内网 IP | ${SERVER_PRIVATE_HOST} |
| 规格 | 2 vCPU · 4 GiB |
| 系统盘 | ESSD 60 GiB |
| 系统 | Ubuntu 24.04.4 LTS（内核 6.8.0-136） |
| SSH | root + 密钥 `${SSH_KEY_PATH}`（RSA 2048） |

## 2. 前置条件

1. **服务器**：阿里云 ECS（香港），Ubuntu 24.04，SSH 密钥可登录。
2. **域名**：`kiwi.harrylabsj.com` 的 zone 在 Cloudflare 托管
   （能添加 `catalog.kiwi.harrylabsj.com` 的 A 记录）。
3. **本地网络注意**：本机若运行 ClashX/代理（TUN 模式），必须给服务器
   公网 IP 加 **DIRECT 规则**，否则 SSH/HTTP 表现诡异（TCP 握手成功但
   无数据）。见 §8 排障。

## 3. 部署步骤（已实测）

### 3.1 SSH 打通

```bash
# 密钥文件（今日生成）加入 agent
ssh-add ${SSH_KEY_PATH}

# 验证（服务器系统确认）
ssh -i ${SSH_KEY_PATH} ${SERVER_USER}@${SERVER_HOST} \
  'hostname && cat /etc/os-release | head -3'
# → ${INSTANCE_HOST} / Ubuntu 24.04.4 LTS
```

> 教训：此前把截图里的 IP 误读为 43.154.71.46，导致长时间排查
> （所有端口"connected, no data"）。**以控制台公网 IP 为准**，必要时
> OCR 截图核实（macOS Vision：`swift -e 'import Vision; ...'`）。

### 3.2 系统用户与目录（对齐官方 systemd unit）

```bash
id kiwi-catalog 2>/dev/null || useradd --system --home /opt/kiwi-catalog \
  --shell /usr/sbin/nologin kiwi-catalog
mkdir -p /opt/kiwi-catalog /var/lib/kiwi-catalog /etc/kiwi-catalog
```

### 3.3 代码上机（tar + scp；服务器无 GitHub 凭据）

```bash
# 本机：打包（排除 .git/__pycache__/egg-info）
cd <WORKSPACE>/kiwi-catalog
tar --exclude='.git' --exclude='__pycache__' --exclude='*.egg-info' \
    --exclude='.venv' -czf /tmp/kiwi-catalog.tar.gz .
scp -i ${SSH_KEY_PATH} /tmp/kiwi-catalog.tar.gz ${SERVER_USER}@${SERVER_HOST}:/tmp/

# 服务器：解包 + 属主
rm -rf /opt/kiwi-catalog/*
cd /opt/kiwi-catalog && tar -xzf /tmp/kiwi-catalog.tar.gz
chown -R kiwi-catalog:kiwi-catalog /opt/kiwi-catalog
```

> tar 解包时的 `LIBARCHIVE.xattr.*` 警告无害（macOS 扩展属性）。

### 3.4 Python 环境（Ubuntu 需先装 python3-venv）

```bash
apt-get update -qq
apt-get install -y -qq python3.12-venv

cd /opt/kiwi-catalog
rm -rf .venv
python3 -m venv .venv
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -q '.[api]'
.venv/bin/kiwi-catalog-api --help   # 确认入口存在
```

> 注意：Ubuntu 24.04 默认 **没有** python3-venv 包，直接 `python3 -m venv`
> 会报 "Failing command"——必须先装。

### 3.5 环境变量（/etc/kiwi-catalog/env，0600）

```bash
ADMIN_TOKEN=$(openssl rand -hex 24)
OWNER_SECRET=$(openssl rand -hex 32)
cat > /etc/kiwi-catalog/env << ENV
KIWI_CATALOG_ADMIN_TOKEN=${ADMIN_TOKEN}
KIWI_CATALOG_OWNER_TOKEN_SECRET=${OWNER_SECRET}
ENV
chmod 600 /etc/kiwi-catalog/env
chown root:root /etc/kiwi-catalog/env
```

> - admin token：moderation 动作（suspend/reinstate）与 verify；
> - owner token secret：HMAC 派生 catalog-owner token（claim/refresh）。
> 两个值**务必妥善保管**，泄露即需轮换（改 env 文件后 `systemctl restart`）。

### 3.6 systemd 服务（官方 unit）

```bash
cp /opt/kiwi-catalog/deploy/systemd/kiwi-catalog.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now kiwi-catalog
systemctl status kiwi-catalog --no-pager   # active (running)
ss -tlnp | grep 8600                        # LISTEN 0.0.0.0:8600
```

**权限陷阱（实测踩坑）**：unit 以 `User=kiwi-catalog` 运行，但
`/var/lib/kiwi-catalog` 默认属主是 root——服务起来后 `/v1/agents` 报
500 `unable to open database file`。修复：

```bash
chown kiwi-catalog:kiwi-catalog /var/lib/kiwi-catalog
systemctl restart kiwi-catalog
```

### 3.7 本机验证（服务器内）

```bash
curl -s http://127.0.0.1:8600/health        # {"ok":true,...}
curl -s http://127.0.0.1:8600/v1/agents      # {"ok":true,"results":[]}
```

### 3.8 Caddy 反代 + HTTPS（Let's Encrypt 自动证书）

```bash
# 安装 Caddy（官方源）
apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
apt-get update -qq && apt-get install -y -qq caddy

# 配置
cat > /etc/caddy/Caddyfile << 'CADDY'
catalog.kiwi.harrylabsj.com {
	reverse_proxy 127.0.0.1:8600
}
CADDY
caddy validate --config /etc/caddy/Caddyfile
systemctl restart caddy
```

**证书时序**：Caddy 在 DNS 记录生效前会一直报
`NXDOMAIN looking up A for catalog.kiwi.harrylabsj.com` 并每 10 分钟重试。
**DNS 记录生效后重启 Caddy 即可立即签发**：

```bash
systemctl restart caddy
journalctl -u caddy --no-pager -n 20 | grep "certificate obtained successfully"
# → tls.obtain msg:"certificate obtained successfully"
```

### 3.9 DNS 记录（Cloudflare 控制台）

- Zone：**harrylabsj.com**（不是 kiwi.harrylabsj.com——它是子域，非独立 zone）
- Type：`A`，Name：`catalog`（控制台自动补全为 `catalog.kiwi.harrylabsj.com`；
  填 `catalog.kiwi` 也会被规范化成同样的 FQDN）
- IPv4：`${SERVER_HOST}`
- Proxy status：**DNS only（灰色云朵）**——Caddy 证书挑战需直连服务器
- TTL：Auto

> 验证：`curl -H "accept: application/dns-json" \
> "https://dns.google/resolve?name=catalog.kiwi.harrylabsj.com&type=A"` → `${SERVER_HOST}`

### 3.10 阿里云安全组

放行入方向 TCP：**22 / 80 / 443**（8600 不需公网放行——Caddy 只在
127.0.0.1 反代，公网一律走 443 TLS）。

> 本实例实测安全组已放行 80/443；若公网访问不通，先在阿里云控制台
> 实例 → 安全组确认入方向规则。

## 4. 上线验证清单

```bash
# 1) 服务健康
curl -s https://catalog.kiwi.harrylabsj.com/health
# {"ok":true,"service":"kiwi-catalog","db":"/var/lib/kiwi-catalog/catalog.sqlite"}

# 2) 发现面
curl -s https://catalog.kiwi.harrylabsj.com/v1/agents
# {"ok":true,"results":[],"next_cursor":null}

# 3) 全链路（本机 kiwi runtime）
cd <WORKSPACE>/kiwi && npm run build
node dist/cli.js doctor
# kiwi_catalog: { ok: true, reachable: true,
#                base_url: "https://catalog.kiwi.harrylabsj.com" }

# 4) 真实 merchant 自动注册（E2E）
#    启动 kiwi A2A 节点（merchant 角色，catalog 指向官方地址）→
#    注册返回 catalog_agent_id → 官方 catalog 搜索可见
```

## 5. 运维速查

```bash
# 状态 / 日志
systemctl status kiwi-catalog
journalctl -u kiwi-catalog -f
journalctl -u caddy -f

# 更新（新版本发布后）
cd <WORKSPACE>/kiwi-catalog
tar -czf /tmp/kiwi-catalog.tar.gz --exclude='.git' --exclude='__pycache__' \
    --exclude='*.egg-info' --exclude='.venv' .
scp -i ${SSH_KEY_PATH} /tmp/kiwi-catalog.tar.gz ${SERVER_USER}@${SERVER_HOST}:/tmp/
ssh -i ${SSH_KEY_PATH} ${SERVER_USER}@${SERVER_HOST} \
  'cd /opt/kiwi-catalog && tar -xzf /tmp/kiwi-catalog.tar.gz && \
   chown -R kiwi-catalog:kiwi-catalog /opt/kiwi-catalog && \
   .venv/bin/pip install -q ".[api]" && systemctl restart kiwi-catalog'

# 轮换令牌（泄露时）：改 /etc/kiwi-catalog/env → systemctl restart kiwi-catalog
```

## 6. 数据与备份

- 数据库：`/var/lib/kiwi-catalog/catalog.sqlite`（SQLite，WAL 模式）
- 备份：直接复制该文件即可（建议先 `systemctl stop kiwi-catalog` 或
  用 sqlite3 `.backup` 在线备份）
- 证书：Caddy 自动续期（Let's Encrypt，90 天），无需人工干预

## 7. 安全要点

| 项 | 说明 |
| --- | --- |
| 服务账户 | systemd `User=kiwi-catalog`（无登录 shell）+ NoNewPrivileges/ProtectSystem |
| 环境文件 | `/etc/kiwi-catalog/env` 0600 root-only，unit 经 EnvironmentFile 注入 |
| 端口暴露 | 公网仅 22/80/443；8600 仅回环 |
| TLS | 全链路 https（Caddy 终止，Let's Encrypt） |
| 令牌 | admin / owner-secret 均为 openssl 随机生成；泄露即轮换 |
| 代理规则 | 本机 ClashX 必须对 ${SERVER_HOST} 走 DIRECT（§8） |

## 8. 常见排障

### 8.1 本机 ClashX/TUN 代理拦截（本次最大坑）

症状：`nc` 报端口 open 但 SSH `kex_exchange_identification: Connection
closed`；curl 超时；**所有端口**（含未开放的 80/443）都 "connected, no
data"。原因：ClashX TUN（gVisor 栈）接管路由，规则把香港 IP 送进代理节点，
节点连不上 → 握手后无数据。

修复（本机 `${CLASH_CONFIG_PATH}`）：

```yaml
rules:
- IP-CIDR,${SERVER_HOST}/32,DIRECT   # 放规则链最前
```

然后经 external-controller 重载：

```bash
curl -X PUT http://127.0.0.1:9090/configs \
  -H "Content-Type: application/json" \
  -d '{"path":"${CLASH_CONFIG_PATH}"}'
```

> 判断依据：`route -n get ${SERVER_HOST}` 显示 gateway `${PROXY_GATEWAY}`
> （ClashX fake-ip 网关）即被接管。

### 8.2 SSH banner 阶段被关闭

`Connection closed by ... port 22`（TCP 通、无 banner）≠ 密钥错误。
可能：fail2ban 封来源 IP、来源限制、TUN 拦截（先查 §8.1）。

### 8.3 /v1/agents 500 "unable to open database file"

`/var/lib/kiwi-catalog` 属主不是 kiwi-catalog。见 §3.6 权限修复。

### 8.4 Caddy 一直 NXDOMAIN

DNS 记录未生效（Cloudflare 控制台确认 A 记录存在且 DNS only），
生效后 `systemctl restart caddy` 立即签发（§3.8）。

### 8.5 本地端口被遗留测试实例占用

本机曾有遗留 kiwi-catalog 测试实例占 18600/18601 端口，导致 SSH 隧道
bind 失败。排查：`lsof -iTCP:<port> -sTCP:LISTEN`。

## 9. 版本记录

| 日期 | 版本 | 说明 |
| --- | --- | --- |
| 2026-08-08 | 3.0.0 | 官方首次生产部署（kiwi-catalog 3.0.0 + kiwi 0.6.0 默认 catalog 指向） |
