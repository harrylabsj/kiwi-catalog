# kiwi-catalog 门户部署：Cloudflare Tunnel 接线（方案 A）

- 状态：2026-08-08 编写，待执行（需项目维护者在 Cloudflare 控制台操作 + catalog 主机 root）
- 目标：`https://merchant.kiwi.harrylabsj.com` → 本机 `127.0.0.1:8600`（kiwi-catalog）
- 设计依据：`docs/kiwi-catalog-token-portal-design-v0.1.md` §6/§9

## 为什么是 Tunnel（方案 A）

- catalog 主机**不需要公网 IP、不开任何公网端口**——cloudflared 主动外连
  Cloudflare 边缘，SSH/HTTP 都不暴露；
- TLS 由 Cloudflare 边缘终结（自动证书），本机只需 HTTP；
- 与官网 `kiwi.harrylabsj.com`（Cloudflare Pages 静态）同一账户，互不冲突。

## 前置条件（已核实）

- catalog 已按 `deploy/systemd/kiwi-catalog.service` 部署，`8600` 在监听；
- 敏感配置在 `/etc/kiwi-catalog/env`（`KIWI_CATALOG_ADMIN_TOKEN`、
  `KIWI_CATALOG_OWNER_TOKEN_SECRET`）——**先改回只监听本机**（见步骤 0）；
- Cloudflare 账户持有 `harrylabsj.com`（官网域名迁移路径照 kiwi 仓
  `docs/DEPLOY-website.md`，merchant 子域名不受 kiwi-spec 占用影响）。

## 步骤

### 0. catalog 收紧为仅本机监听（安全，必做）

tunnel 下外部流量只经 cloudflared 进来，catalog 无需暴露 0.0.0.0：

```ini
# /etc/systemd/system/kiwi-catalog.service 的 ExecStart 改为：
--host 127.0.0.1 --port 8600
```

```sh
sudo systemctl daemon-reload && sudo systemctl restart kiwi-catalog
```

### 1. 安装 cloudflared

```sh
# Debian/Ubuntu
curl -L https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared bookworm main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared
```

### 2. 登录并创建隧道（在 catalog 主机上，浏览器授权一次）

```sh
cloudflared tunnel login            # 打开浏览器选 harrylabsj.com 域名授权
cloudflared tunnel create kiwi-merchant
```

输出隧道 ID（形如 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`）与凭证 JSON
（`~/.cloudflared/xxxxxxxx-...json`），记下 ID。

### 3. 写 ingress 配置

```yaml
# ~/.cloudflared/config.yml
tunnel: <TUNNEL_ID>
credentials-file: /home/<user>/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: merchant.kiwi.harrylabsj.com
    service: http://127.0.0.1:8600
  - service: http_status:404
```

### 4. 建 DNS 路由（CNAME 自动由 Cloudflare 管理）

```sh
cloudflared tunnel route dns kiwi-merchant merchant.kiwi.harrylabsj.com
```

### 5. 以 systemd 常驻运行

```sh
sudo cloudflared service install
sudo systemctl status cloudflared     # active (running)
```

### 6. 验证清单

```text
[ ] curl -I https://merchant.kiwi.harrylabsj.com/portal/apply
    → 200, content-type: text/html; charset=utf-8, cache-control: no-store
[ ] curl -I https://merchant.kiwi.harrylabsj.com/v1/merchants/self → 200 JSON
[ ] 门户申请 → 提交成功（返回 application_id）
[ ] admin 登录审核 → 批准签发 → 明文 token 一次性展示
[ ] 移动端宽度（≤640px）无横向滚动
```

## 安全边界（接线后成立）

- 公网面只有两个入口：`/portal/*`（HTML，no-store）与 `/v1/merchants/*` JSON
  API；admin 端点 fail-closed（无默认 token，未配置即拒绝）；
- 明文 token 只在 approve/rotate 响应出现一次，门户页 no-store 防缓存；
- 申请面按邮箱限流（`KIWI_CATALOG_APPLY_RATE_LIMIT_PER_HOUR`，默认 5/时）；
- catalog 只监听 127.0.0.1——即使主机被攻破，8600 也不对局域网开放。

## 回滚

```sh
sudo cloudflared service uninstall
cloudflared tunnel route dns kiwi-merchant merchant.kiwi.harrylabsj.com --overwrite-dns  # 或控制台删除
```

官网 CTA 已指向该域名（kiwi 仓 `docs/website/merchants.html`）——接线完成前
点击会 523/解析失败，属预期；可先接线后发版官网。
