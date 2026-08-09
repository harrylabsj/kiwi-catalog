# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Merchant 门户页面（docs/kiwi-catalog-token-portal-design-v0.1 §6）。

fallback 栈渲染的轻量 HTML（零新依赖）：申请表单 / 审核后台 / 商家自查 /
门户首页。样式与官网（kiwi 仓 docs/website/）完全一致——内联官网 style.css
+ 门户特有表单补充（主题变量同源，官网改样式时同步拷贝）。

安全边界：
- **审核后台不对外公布**：/portal/admin 由 env ``KIWI_CATALOG_PORTAL_ADMIN_ENABLED``
  控制，默认关闭（404）；审核工作主走 CLI（catalog merchant applications
  approve/reject），网页后台按需在主机开启、用完关闭；
- 页面只做表单与 fetch 调用，动态数据全部走 JSON API（/v1/merchants/*，
  admin 端点另有 admin token fail-closed）；
- 响应体 ``{"__html__": "..."}`` 标记经 fallback _send_json 发 text/html +
  no-store（明文 token 只在审核后台批准/轮换响应出现一次）。
"""

from __future__ import annotations

import os
import secrets
from typing import Any

_PORTAL_ADMIN_ENABLED_ENV = "KIWI_CATALOG_PORTAL_ADMIN_ENABLED"

# 官网 style.css（kiwi 仓 docs/website/style.css，2026-08-08 同步）——两处
# 共用同一套主题（--kiwi-* 变量、nav/section/card/btn/notice/footer）。
_OFFICIAL_CSS = """
:root {
  --kiwi-900: #143d18;
  --kiwi-800: #1b5e20;
  --kiwi-700: #2e7d32;
  --kiwi-600: #43a047;
  --kiwi-100: #e8f5e9;
  --ink: #1a1f1a;
  --ink-soft: #4b554b;
  --paper: #ffffff;
  --paper-soft: #f6f8f6;
  --line: #dde5dd;
  --radius: 14px;
  --maxw: 1080px;
  font-size: 17px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: system-ui, -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
  color: var(--ink);
  background: var(--paper);
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}
.nav {
  position: sticky; top: 0; z-index: 10;
  background: rgba(255, 255, 255, 0.94);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--line);
}
.nav-inner { max-width: var(--maxw); margin: 0 auto; padding: 14px 24px; display: flex; align-items: center; gap: 28px; }
.nav-logo { font-weight: 700; font-size: 1.15rem; letter-spacing: -0.01em; color: var(--kiwi-800); text-decoration: none; }
.nav-links { display: flex; gap: 20px; margin-left: auto; }
.nav-links a { color: var(--ink-soft); text-decoration: none; font-size: 0.95rem; padding: 4px 2px; border-bottom: 2px solid transparent; }
.nav-links a:hover, .nav-links a.active { color: var(--kiwi-700); border-bottom-color: var(--kiwi-600); }
.hero {
  background:
    radial-gradient(1100px 500px at 85% -10%, rgba(67, 160, 71, 0.35), transparent 60%),
    linear-gradient(160deg, var(--kiwi-900), var(--kiwi-800) 55%, var(--kiwi-700));
  color: #fff; padding: 72px 24px 64px;
}
.hero-inner { max-width: var(--maxw); margin: 0 auto; }
.hero h1 { font-size: clamp(2rem, 4.5vw, 3rem); line-height: 1.1; letter-spacing: -0.02em; font-weight: 800; }
.hero .tagline { margin-top: 12px; font-size: clamp(1rem, 2vw, 1.2rem); color: rgba(255, 255, 255, 0.88); max-width: 42em; }
.hero-actions { margin-top: 28px; display: flex; gap: 14px; flex-wrap: wrap; }
.btn { display: inline-block; padding: 12px 24px; border-radius: 999px; font-weight: 600; text-decoration: none; font-size: 0.98rem; transition: transform 0.12s ease, box-shadow 0.12s ease; }
.btn:hover { transform: translateY(-1px); }
.btn-solid { background: #fff; color: var(--kiwi-800); box-shadow: 0 6px 20px rgba(0, 0, 0, 0.18); }
.btn-ghost { border: 1.5px solid rgba(255, 255, 255, 0.75); color: #fff; }
.section { padding: 56px 24px; }
.section-inner { max-width: var(--maxw); margin: 0 auto; }
.section-alt { background: var(--paper-soft); }
.kicker { color: var(--kiwi-700); font-weight: 700; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.08em; }
h2 { font-size: clamp(1.5rem, 3vw, 2rem); letter-spacing: -0.02em; margin-top: 10px; }
.lead { margin-top: 10px; font-size: 1.05rem; color: var(--ink-soft); max-width: 44em; }
.grid { display: grid; gap: 20px; margin-top: 30px; }
.grid-3 { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
.card { background: var(--paper); border: 1px solid var(--line); border-radius: var(--radius); padding: 24px; box-shadow: 0 2px 8px rgba(20, 40, 24, 0.04); }
.card h3 { font-size: 1.05rem; margin-bottom: 8px; }
.card p { color: var(--ink-soft); font-size: 0.94rem; margin-bottom: 8px; }
.card-num { display: inline-flex; align-items: center; justify-content: center; width: 30px; height: 30px; border-radius: 50%; background: var(--kiwi-100); color: var(--kiwi-800); font-weight: 700; font-size: 0.85rem; margin-bottom: 12px; }
.notice { margin-top: 32px; border-left: 4px solid var(--kiwi-600); background: var(--kiwi-100); border-radius: 0 var(--radius) var(--radius) 0; padding: 18px 22px; font-size: 0.94rem; max-width: 46em; }
.notice strong { color: var(--kiwi-800); }
pre { background: #12251a; color: #d7f0da; border-radius: var(--radius); padding: 18px 20px; overflow-x: auto; font-size: 0.85rem; line-height: 1.6; margin-top: 20px; }
code { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
.footer { border-top: 1px solid var(--line); padding: 32px 24px 44px; background: var(--paper-soft); color: var(--ink-soft); font-size: 0.9rem; }
.footer-inner { max-width: var(--maxw); margin: 0 auto; }
.footer a { color: var(--kiwi-700); text-decoration: none; }
@media (max-width: 640px) {
  .nav-inner { flex-wrap: wrap; gap: 10px; }
  .nav-links { margin-left: 0; width: 100%; }
  .hero { padding: 52px 20px 44px; }
  .section { padding: 40px 20px; }
}
"""

# 门户特有（表单/令牌展示/审核列表），主题变量与官网同源
_PORTAL_EXTRA_CSS = """
.form-card { max-width: 560px; }
label { display: block; font-size: 0.9rem; font-weight: 600; margin: 16px 0 6px; color: var(--ink); }
input, textarea {
  width: 100%; padding: 11px 14px;
  border: 1px solid var(--line); border-radius: 10px;
  font-size: 0.95rem; font-family: inherit; color: var(--ink);
  background: var(--paper);
}
input:focus, textarea:focus { outline: 2px solid var(--kiwi-600); outline-offset: 1px; border-color: var(--kiwi-600); }
.btn-form {
  margin-top: 22px; display: inline-block; border: none; cursor: pointer;
  padding: 12px 26px; border-radius: 999px; font-weight: 600;
  font-size: 0.98rem; font-family: inherit;
  background: var(--kiwi-800); color: #fff;
  transition: transform 0.12s ease, box-shadow 0.12s ease;
}
.btn-form:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(27, 94, 32, 0.25); }
.btn-form:disabled { opacity: 0.55; cursor: not-allowed; }
.btn-mini {
  border: 1px solid var(--line); background: var(--paper-soft); color: var(--ink);
  padding: 7px 14px; border-radius: 999px; font-size: 0.85rem; font-weight: 600;
  cursor: pointer; font-family: inherit; margin-left: 6px;
}
.token-box { background: var(--kiwi-100); color: var(--kiwi-900); border-left: 4px solid var(--kiwi-600); border-radius: 0 var(--radius) var(--radius) 0; font-family: ui-monospace, Menlo, monospace; font-size: 0.92rem; padding: 12px 14px; word-break: break-all; margin: 10px 0; }
.mono { font-family: ui-monospace, Menlo, monospace; font-size: 0.85rem; }
.small { font-size: 0.83rem; color: var(--ink-soft); }
.err { color: #b3261e; font-size: 0.9rem; margin-top: 10px; }
.ok { color: var(--kiwi-700); font-size: 0.9rem; margin-top: 10px; }
.app-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 14px 0; border-bottom: 1px solid var(--line); }
.app-row:last-child { border-bottom: none; }
.app-actions { flex-shrink: 0; }
/* 账号页居中（register/login/account） */
.center-page { text-align: center; }
.center-page .kicker, .center-page h2, .center-page .lead { text-align: center; margin-left: auto; margin-right: auto; }
.center-page .form-card { text-align: left; margin: 28px auto 0; float: none; }
.center-page .card { text-align: left; }
/* dashboard */
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-top: 26px; }
.kpi { background: var(--paper); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px 20px; }
.kpi .num { font-size: 2rem; font-weight: 800; color: var(--kiwi-800); letter-spacing: -0.02em; }
.kpi .lbl { font-size: 0.83rem; color: var(--ink-soft); margin-top: 2px; }
.bars { display: flex; align-items: flex-end; gap: 6px; height: 120px; margin-top: 18px; }
.bar { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 4px; }
.bar .fill { width: 100%; background: var(--kiwi-600); border-radius: 6px 6px 2px 2px; min-height: 2px; }
.bar .d { font-size: 0.68rem; color: var(--ink-soft); white-space: nowrap; }
.section-title { font-size: 1.05rem; font-weight: 700; margin: 26px 0 6px; }
.legend { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 10px; font-size: 0.83rem; color: var(--ink-soft); }
.legend .sw { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 5px; }
table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 0.88rem; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--kiwi-800); font-weight: 700; white-space: nowrap; font-size: 0.82rem; }
.muted { color: var(--ink-soft); }
.mono { font-family: ui-monospace, Menlo, monospace; font-size: 0.82rem; }
"""


def _page(title: str, body: str, extra_js: str = "") -> dict[str, Any]:
    # CSP（KC-SEC-01 硬化）：script 走 per-response nonce——页面内嵌脚本
    # 是唯一合法执行源，匿名数据即使绕过转义也无法执行（meta CSP 对
    # 同源注入有效）。style 允许 inline（页面样式内嵌且无用户数据）。
    # frame-ancestors 经 meta 会被浏览器忽略——由响应头提供（见
    # fallback _send_json 与 FastAPI _parity_middleware）。
    nonce = secrets.token_urlsafe(16)
    csp = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        "style-src 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "object-src 'none'"
    )
    # 页面 body 自带的内嵌 <script>（每页独立 JS 块）同样必须带 nonce——
    # 否则被 CSP 拦截导致页面 JS 失效（生产浏览器验证发现）。
    body = body.replace("<script>", f'<script nonce="{nonce}">')
    return {
        "__html__": (
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">"
            f"<title>{title} — Kiwi Merchant Portal</title>"
            f"<style>{_OFFICIAL_CSS}{_PORTAL_EXTRA_CSS}</style></head>"
            f"<body>{body}<script nonce=\"{nonce}\">{_PORTAL_JS}{extra_js}</script></body></html>"
        )
    }


_PORTAL_JS = """
function escHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>\"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', "'": '&#39;'
  }[c]));
}
function postJson(url, body, token) {
  const headers = {'Content-Type': 'application/json'};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(url, {method: 'POST', headers, body: JSON.stringify(body)})
    .then(r => r.json());
}
function getJson(url, token) {
  const headers = {};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(url, {method: 'GET', headers}).then(r => r.json());
}
"""


_OFFICIAL_HOME = "https://kiwi.harrylabsj.com/"


def _nav(active: str = "") -> str:
    """商家侧一级导航：Home（官网首页）+ API Token + 我的（My Account）。

    Kiwi logo 与 Home 都指向官网首页（kiwi.harrylabsj.com）。
    """
    portal_cls = ' class="active"' if active == "portal" else ""
    account_cls = ' class="active"' if active == "account" else ""
    return f"""
<nav class="nav"><div class="nav-inner">
  <a class="nav-logo" href="{_OFFICIAL_HOME}">Kiwi</a>
  <div class="nav-links">
    <a href="{_OFFICIAL_HOME}">Home</a>
    <a href="/portal"{portal_cls}>API Token</a>
    <a href="/portal/account"{account_cls}>My Account</a>
  </div>
</div></nav>
"""

# 运营后台专用导航：不出现商家门户入口（审核后台/dashboard 不对外公布，
# 官方找不到、无链接可到）。
_ADMIN_NAV = """
<nav class="nav"><div class="nav-inner">
  <span class="nav-logo">Kiwi 运营后台</span>
</div></nav>
"""

_FOOTER = """
<footer class="footer"><div class="footer-inner">
  <p>Kiwi Merchant Portal · 登录后可查看当前令牌，遗失或疑似泄露请联系运营轮换 · 明文令牌永不出现在日志中</p>
</div></footer>
"""


def portal_home() -> dict[str, Any]:
    """门户首页 = Token 申请（登录态表单；未登录引导登录）。

    邮箱/电话不需要填写——注册与账户基本信息已提供，提交时自动带上。
    """
    body = (
        _nav("portal")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Token 申请</div>
  <h2>Token 申请</h2>
  <p class="lead">申请商家令牌，平台审核通过后签发。令牌会显示在「我的」里。</p>
  <div class="card form-card">
    <label for="t_domain">店铺域名（如 acme.example）</label>
    <input id="t_domain" placeholder="acme.example" autocomplete="off">
    <label for="t_name">商家名称</label>
    <input id="t_name" placeholder="Acme Merchant">
    <label for="t_purpose">用途说明（选填）</label>
    <textarea id="t_purpose" rows="3" placeholder="想销售的商品类目 / 目标买家"></textarea>
    <button class="btn-form" id="t_submit">提交申请</button>
    <div id="t_out"></div>
  </div>
</div></section>
<script>
// 登录态检查：未登录进入登录流程（邮箱/电话自动从账户带出）
fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
  if (!r.ok) { window.location.href = '/portal/login'; return; }
  if (r.merchant_name) { document.getElementById('t_name').value = r.merchant_name; }
});
document.getElementById('t_submit').addEventListener('click', () => {
  const btn = document.getElementById('t_submit');
  const out = document.getElementById('t_out');
  btn.disabled = true;
  postJson('/v1/accounts/token-request', {
    domain: document.getElementById('t_domain').value.trim(),
    agent_name: document.getElementById('t_name').value.trim(),
    purpose: document.getElementById('t_purpose').value.trim(),
  }).then(r => {
    if (r.ok) {
      out.className = 'ok';
      out.textContent = r.status === 'active' ? '你已有有效令牌，可在「我的」查看。' : '申请已提交，等待平台审核。';
      setTimeout(() => go('/portal/account'), 1000);
    } else {
      out.className = 'err';
      out.textContent = r.error || '提交失败';
      btn.disabled = false;
    }
  });
});
</script>
"""
        + _FOOTER
    )
    return _account_page("Token 申请", body)


def portal_apply() -> dict[str, Any]:
    """/portal/apply 兼容旧路径——与首页（Token 申请）同内容。"""
    return portal_home()



def portal_admin() -> dict[str, Any]:
    """审核后台——默认不对外公布（env 开关，见模块 docstring）。

    关闭时返回 404 HTML（__status__ 标记让 fallback/FastAPI 双栈发真实
    404 状态码，而非 200 包 404 页面）。
    """
    if str(os.environ.get(_PORTAL_ADMIN_ENABLED_ENV) or "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return {"__html__": _not_found_html(), "__status__": 404}
    body = (
        _ADMIN_NAV
        + """
<section class="section"><div class="section-inner">
  <div class="kicker">Admin</div>
  <h2>审核后台</h2>
  <p class="lead">输入平台 admin token，查看待审申请并签发商家令牌。</p>
  <div class="card form-card">
    <label for="admin_token">Admin Token</label>
    <input id="admin_token" type="password" placeholder="admin token" autocomplete="off">
    <button class="btn-form" id="load">加载待审申请</button>
    <div id="out"></div>
    <div id="list"></div>
  </div>
  <div class="card form-card" id="result_card" style="display:none">
    <h3>签发结果（令牌仅显示一次）</h3>
    <div id="result"></div>
  </div>
</div></section>
<script>
function showToken(r) {
  const card = document.getElementById('result_card');
  const out = document.getElementById('result');
  card.style.display = 'block';
  out.innerHTML = '<p class="small">商家 ID</p><div class="token-box">' + escHtml(r.merchant_id)
    + '</div><p class="small">访问令牌 — 复制保存，关闭页面后不可再见</p>'
    + '<div class="token-box">' + escHtml(r.token) + '</div>'
    + '<p class="small">在 kiwi CLI 中用 --merchant-id ' + escHtml(r.merchant_id)
    + ' --merchant-token ' + escHtml(r.token_prefix) + '… 注册 Agent，或用 owner_token 字段调用 /v1/listings/publish。</p>';
}
function loadList() {
  const token = document.getElementById('admin_token').value.trim();
  const out = document.getElementById('out');
  const list = document.getElementById('list');
  out.className = ''; out.textContent = '';
  getJson('/v1/merchants/applications?status=pending', token).then(r => {
    if (!r.ok) { out.className = 'err'; out.textContent = r.error || '加载失败'; return; }
    list.innerHTML = '';
    if (!r.results.length) { list.innerHTML = '<p class="small">没有待审申请</p>'; return; }
    r.results.forEach(a => {
      const row = document.createElement('div');
      row.className = 'app-row';
      row.innerHTML = '<div><strong>' + escHtml(a.agent_name) + '</strong><br>'
        + '<span class="small mono">' + escHtml(a.domain) + ' · ' + escHtml(a.contact_email) + '</span>'
        + (a.purpose ? '<br><span class="small">' + escHtml(a.purpose) + '</span>' : '')
        + '</div>'
        + '<div class="app-actions"><button data-app="' + escHtml(a.application_id) + '" class="btn-mini">批准签发</button>'
        + '<button data-rej="' + escHtml(a.application_id) + '" class="btn-mini">拒绝</button></div>';
      list.appendChild(row);
    });
  });
}
document.getElementById('load').addEventListener('click', loadList);
document.getElementById('list').addEventListener('click', e => {
  const token = document.getElementById('admin_token').value.trim();
  const app = e.target.dataset.app;
  const rej = e.target.dataset.rej;
  if (app) {
    postJson('/v1/merchants/applications/' + app + '/approve', {}, token)
      .then(r => { if (r.ok) { showToken(r); loadList(); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  } else if (rej) {
    postJson('/v1/merchants/applications/' + rej + '/reject', {}, token)
      .then(r => { if (r.ok) { loadList(); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  }
});
</script>
"""
        + _FOOTER
    )
    return _page("审核后台", body)



def portal_dashboard() -> dict[str, Any]:
    """运营 Dashboard——默认不对外公布（env 开关，与审核后台一致）。"""
    if str(os.environ.get(_PORTAL_ADMIN_ENABLED_ENV) or "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return {"__html__": _not_found_html(), "__status__": 404}
    body = (
        _ADMIN_NAV
        + """
<section class="section"><div class="section-inner">
  <div class="kicker">Operations</div>
  <h2>运营 Dashboard</h2>
  <p class="lead">商家申请审批、网络规模与使用趋势。</p>
  <div class="card form-card">
    <label for="admin_token">Admin Token</label>
    <input id="admin_token" type="password" placeholder="admin token" autocomplete="off">
    <button class="btn-form" id="load">加载 Dashboard</button>
    <div id="out"></div>
  </div>
  <div id="content" style="display:none">
    <div class="kpis" id="kpis"></div>
    <div class="section-title">使用趋势（最近 14 天）</div>
    <div id="usage"></div>
    <div class="legend" id="legend"></div>
    <div class="section-title">待审申请</div>
    <div id="apps"></div>
    <div class="section-title">商家列表</div>
    <div id="merchants"></div>
  </div>
  <div class="card form-card" id="report_card" style="display:none">
    <h3 id="report_title">商家报告</h3>
    <div id="report"></div>
    <button class="btn-mini" id="report_back" style="margin-top:12px">← 返回列表</button>
  </div>
</div></section>
"""
        + _FOOTER
    )
    return _page("运营 Dashboard", body, extra_js=_PORTAL_JS_EXTRA)


_PORTAL_JS_EXTRA = """
const METRIC_LABELS = {
  buyer_agent_search: 'Agent 搜索',
  buyer_listing_search: '商品搜索',
  merchant_self_check: '商家自查',
  listing_publish: '商品发布',
};
const METRIC_COLORS = {
  buyer_agent_search: '#2e7d32',
  buyer_listing_search: '#43a047',
  merchant_self_check: '#81c784',
  listing_publish: '#143d18',
};

function adminApi(path, token) {
  return getJson(path, token);
}

function renderKpis(d) {
  const c = d.counts;
  const kpis = [
    ['商家数', c.merchants], ['Agent 数', c.agents], ['商品数', c.listings],
    ['待审申请', c.pending_applications], ['有效令牌', c.active_tokens],
  ];
  document.getElementById('kpis').innerHTML = kpis.map(([lbl, n]) =>
    '<div class="kpi"><div class="num">' + escHtml(n) + '</div><div class="lbl">' + escHtml(lbl) + '</div></div>'
  ).join('');
}

function renderUsage(usage) {
  const max = Math.max(1, ...usage.map(u => u.total));
  document.getElementById('usage').innerHTML =
    '<div class="bars">' + usage.map(u =>
      '<div class="bar" title="' + escHtml(u.day) + ' 总 ' + escHtml(u.total) + '"><div class="fill" style="height:' + Math.max(2, Math.round(u.total / max * 100)) + '%"></div><div class="d">' + escHtml(u.day.slice(5)) + '</div></div>'
    ).join('') + '</div>';
  document.getElementById('legend').innerHTML = Object.entries(METRIC_LABELS).map(([k, v]) =>
    '<span><span class="sw" style="background:' + METRIC_COLORS[k] + '"></span>' + v + '</span>'
  ).join('');
}

function renderApps(token, apps) {
  const el = document.getElementById('apps');
  if (!apps.length) { el.innerHTML = '<p class="small muted">没有待审申请</p>'; return; }
  el.innerHTML = '<table><tr><th>#</th><th>名称</th><th>域名</th><th>邮箱</th><th>用途</th><th></th></tr>' +
    apps.map(a => '<tr><td>' + escHtml(a.application_id) + '</td><td>' + escHtml(a.agent_name) + '</td><td class="mono">' + escHtml(a.domain) +
      '</td><td>' + escHtml(a.contact_email) + '</td><td class="small muted">' + escHtml(a.purpose || '-') + '</td><td>' +
      '<button class="btn-mini" data-app="' + escHtml(a.application_id) + '">批准</button>' +
      '<button class="btn-mini" data-rej="' + escHtml(a.application_id) + '">拒绝</button></td></tr>').join('') + '</table>';
}

function renderMerchants(list) {
  const el = document.getElementById('merchants');
  if (!list.length) { el.innerHTML = '<p class="small muted">还没有商家</p>'; return; }
  el.innerHTML = '<table><tr><th>商家 ID</th><th>名称</th><th>Agent</th><th>商品</th><th>令牌</th><th>签发</th><th></th></tr>' +
    list.map(m => '<tr><td class="mono">' + escHtml(m.merchant_id) + '</td><td>' + escHtml(m.name) + '</td><td>' + escHtml(m.agents_count) +
      '</td><td>' + escHtml(m.listings_count) + '</td><td>' + escHtml(m.token_status) + '</td><td class="small muted">' +
      escHtml((m.token_issued_at || '-').slice(0, 10)) + '</td><td><button class="btn-mini" data-report="' +
      escHtml(m.merchant_id) + '">报告</button></td></tr>').join('') + '</table>';
}

function renderReport(r, token) {
  const m = r.merchant;
  let html = '<p class="small muted">' + escHtml(m.merchant_id) + ' · 创建 ' + escHtml((m.created_at || '').slice(0, 10)) + ' · 更新 ' + escHtml((m.updated_at || '').slice(0, 10)) + '</p>';
  html += '<div class="section-title">Token 生命周期</div>';
  html += r.tokens.length ? '<table><tr><th>状态</th><th>签发</th><th>轮换</th><th>吊销</th></tr>' + r.tokens.map(t =>
    '<tr><td>' + escHtml(t.status) + '</td><td>' + escHtml((t.issued_at || '-').slice(0, 10)) + '</td><td>' + escHtml((t.rotated_at || '-').slice(0, 10)) + '</td><td>' + escHtml((t.revoked_at || '-').slice(0, 10)) + '</td></tr>').join('') + '</table>' : '<p class="small muted">无令牌</p>';
  html += '<div class="section-title">Agents（' + escHtml(r.agents.length) + '）</div>';
  html += r.agents.length ? '<table><tr><th>ID</th><th>名称</th><th>域名</th><th>验证</th><th>状态</th></tr>' + r.agents.map(a =>
    '<tr><td class="mono">' + escHtml(a.catalog_agent_id) + '</td><td>' + escHtml(a.display_name) + '</td><td class="mono">' + escHtml(a.canonical_domain) +
    '</td><td>' + escHtml(a.verification_level) + '</td><td>' + escHtml(a.administrative_state) + '</td></tr>').join('') + '</table>' : '<p class="small muted">无 Agent</p>';
  html += '<div class="section-title">商品（' + escHtml(r.listings.length) + '）</div>';
  html += r.listings.length ? '<table><tr><th>ID</th><th>标题</th><th>类目</th><th>状态</th><th>发布</th></tr>' + r.listings.map(l =>
    '<tr><td class="mono">' + escHtml(l.listing_id) + '</td><td>' + escHtml(l.title) + '</td><td>' + escHtml(l.category) + '</td><td>' +
    escHtml(l.publication_state) + '</td><td>' + escHtml((l.published_at || '').slice(0, 10)) + '</td></tr>').join('') + '</table>' : '<p class="small muted">无商品</p>';
  html += '<div class="section-title">审计事件（' + escHtml(r.audit_events.length) + '）</div>';
  html += r.audit_events.length ? '<table><tr><th>时间</th><th>事件</th><th>操作者</th><th>详情</th></tr>' + r.audit_events.map(e =>
    '<tr><td class="small muted">' + escHtml((e.created_at || '').slice(0, 16)) + '</td><td>' + escHtml(e.event) + '</td><td>' + escHtml(e.actor) +
    '</td><td class="small muted">' + escHtml(e.details) + '</td></tr>').join('') + '</table>' : '<p class="small muted">无审计事件</p>';
  document.getElementById('report_title').textContent = '商家报告：' + String(m.name == null ? '' : m.name);
  document.getElementById('report').innerHTML = html;
  document.getElementById('report_card').style.display = 'block';
  document.getElementById('content').style.display = 'none';
}

function loadDashboard(token) {
  const out = document.getElementById('out');
  out.className = ''; out.textContent = '';
  adminApi('/v1/admin/dashboard', token).then(r => {
    if (!r.ok) { out.className = 'err'; out.textContent = r.error || '加载失败'; return; }
    renderKpis(r); renderUsage(r.usage);
    document.getElementById('content').style.display = 'block';
    adminApi('/v1/admin/merchants', token).then(mr => {
      if (mr.ok) { renderMerchants(mr.results); }
    });
    adminApi('/v1/merchants/applications?status=pending', token).then(ar => {
      if (ar.ok) { renderApps(token, ar.results); }
    });
  });
}

document.getElementById('load').addEventListener('click', () => {
  const token = document.getElementById('admin_token').value.trim();
  if (token) loadDashboard(token);
});
document.getElementById('apps').addEventListener('click', e => {
  const token = document.getElementById('admin_token').value.trim();
  const app = e.target.dataset.app;
  const rej = e.target.dataset.rej;
  if (app) {
    postJson('/v1/merchants/applications/' + app + '/approve', {}, token)
      .then(r => { if (r.ok) { loadDashboard(token); alert('已签发：' + r.merchant_id + '\\n令牌（仅显示一次）：\\n' + r.token); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  } else if (rej) {
    postJson('/v1/merchants/applications/' + rej + '/reject', {}, token)
      .then(r => { if (r.ok) { loadDashboard(token); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  }
});
document.getElementById('merchants').addEventListener('click', e => {
  const token = document.getElementById('admin_token').value.trim();
  const mid = e.target.dataset.report;
  if (mid) {
    adminApi('/v1/admin/merchants/' + mid + '/report', token).then(r => {
      if (r.ok) { renderReport(r, token); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; }
    });
  }
});
document.getElementById('report_back').addEventListener('click', () => {
  document.getElementById('report_card').style.display = 'none';
  document.getElementById('content').style.display = 'block';
});
"""


_ACCOUNT_JS = """
function postJson(url, body) {
  return fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json());
}
function go(path) { window.location.href = path; }
"""


def _account_page(title: str, body: str) -> dict[str, Any]:
    return _page(title, body, extra_js=_ACCOUNT_JS)


def portal_register() -> dict[str, Any]:
    """注册页（极简：仅邮箱 + 密码）→ 邮箱验证码 → 验证后进入「我的」。"""
    body = (
        _nav("portal")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Register</div>
  <h2>注册商家账号</h2>
  <p class="lead">只需邮箱和密码。验证邮箱后，在「我的」里申请商家令牌。</p>
  <div class="card form-card">
    <div id="step1">
      <label for="email">邮箱</label>
      <input id="email" type="email" placeholder="ops@acme.example" autocomplete="email">
      <label for="password">密码（至少 8 位）</label>
      <input id="password" type="password" autocomplete="new-password">
      <button class="btn-form" id="submit">注册</button>
      <div id="out1"></div>
      <p class="small" style="margin-top:16px">已有账号？<a href="/portal/login">登录</a></p>
    </div>
    <div id="step2" style="display:none">
      <p class="ok" id="sent_note">验证码已发送到你的邮箱。</p>
      <label for="code">邮箱验证码</label>
      <input id="code" placeholder="6 位验证码" autocomplete="one-time-code">
      <button class="btn-form" id="verify">验证并进入</button>
      <div id="out2"></div>
      <button class="btn-mini" id="resend" style="margin-top:12px">重新发送验证码</button>
    </div>
  </div>
</div></section>
<script>
let regEmail = '';
document.getElementById('submit').addEventListener('click', () => {
  const btn = document.getElementById('submit');
  const out = document.getElementById('out1');
  btn.disabled = true;
  postJson('/v1/accounts/register', {
    email: document.getElementById('email').value.trim(),
    password: document.getElementById('password').value,
  }).then(r => {
    if (r.ok) {
      regEmail = r.email;
      if (r.verification_code) {
        document.getElementById('sent_note').textContent = '演示模式：验证码 ' + r.verification_code;
      }
      document.getElementById('step1').style.display = 'none';
      document.getElementById('step2').style.display = 'block';
    } else {
      out.className = 'err';
      out.textContent = r.error || '注册失败';
      btn.disabled = false;
    }
  });
});
document.getElementById('verify').addEventListener('click', () => {
  const btn = document.getElementById('verify');
  const out = document.getElementById('out2');
  btn.disabled = true;
  postJson('/v1/accounts/verify-email', {
    email: regEmail,
    code: document.getElementById('code').value.trim(),
  }).then(r => {
    if (r.ok) {
      out.className = 'ok';
      out.textContent = '邮箱已验证，正在进入「我的」…';
      setTimeout(() => go('/portal/account'), 800);
    } else {
      out.className = 'err';
      out.textContent = r.error || '验证失败';
      btn.disabled = false;
    }
  });
});
document.getElementById('resend').addEventListener('click', () => {
  const btn = document.getElementById('resend');
  btn.disabled = true;
  postJson('/v1/accounts/resend-code', {email: regEmail}).then(r => {
    document.getElementById('sent_note').textContent = r.verification_code
      ? '演示模式：验证码 ' + r.verification_code
      : '验证码已重新发送。';
    btn.disabled = false;
  });
});
</script>
"""
        + _FOOTER
    )
    return _account_page("商家注册", body)


def portal_login() -> dict[str, Any]:
    """登录页：邮箱 + 密码 → 会话 cookie → 「我的」。

    邮箱未验证时提示并显示验证码输入（验证通过自动登录）。
    """
    body = (
        _nav("portal")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Login</div>
  <h2>商家登录</h2>
  <div class="card form-card">
    <label for="email">邮箱</label>
    <input id="email" type="email" autocomplete="email">
    <label for="password">密码</label>
    <input id="password" type="password" autocomplete="current-password">
    <button class="btn-form" id="submit">登录</button>
    <div id="out"></div>
    <div id="verify_block" style="display:none">
      <label for="code">邮箱验证码（登录前需先验证邮箱）</label>
      <input id="code" placeholder="6 位验证码" autocomplete="one-time-code">
      <button class="btn-form" id="verify">验证并登录</button>
      <button class="btn-mini" id="resend" style="margin-top:12px">重新发送验证码</button>
    </div>
    <p class="small" style="margin-top:16px">还没有账号？<a href="/portal/register">注册商家账号</a></p>
  </div>
</div></section>
<script>
let logEmail = '';
document.getElementById('submit').addEventListener('click', () => {
  const btn = document.getElementById('submit');
  const out = document.getElementById('out');
  logEmail = document.getElementById('email').value.trim();
  btn.disabled = true;
  postJson('/v1/accounts/login', {
    email: logEmail,
    password: document.getElementById('password').value,
  }).then(r => {
    if (r.ok) {
      out.className = 'ok';
      out.textContent = '登录成功，正在进入「我的」…';
      setTimeout(() => go('/portal/account'), 500);
    } else {
      out.className = 'err';
      out.textContent = r.error || '登录失败';
      btn.disabled = false;
      if (r.error && r.error.indexOf('not verified') !== -1) {
        document.getElementById('verify_block').style.display = 'block';
        postJson('/v1/accounts/resend-code', {email: logEmail}).then(r2 => {
          if (r2.verification_code) { document.getElementById('out').textContent += '（演示模式：' + r2.verification_code + '）'; }
        });
      }
    }
  });
});
document.getElementById('verify').addEventListener('click', () => {
  postJson('/v1/accounts/verify-email', {
    email: logEmail,
    code: document.getElementById('code').value.trim(),
  }).then(r => {
    if (r.ok) { window.location.href = '/portal/account'; }
    else {
      const out = document.getElementById('out');
      out.className = 'err';
      out.textContent = r.error || '验证失败';
    }
  });
});
document.getElementById('resend').addEventListener('click', () => {
  postJson('/v1/accounts/resend-code', {email: logEmail}).then(r => {
    const out = document.getElementById('out');
    out.textContent = r.verification_code ? '演示模式：验证码 ' + r.verification_code : '验证码已重新发送。';
  });
});
</script>
"""
        + _FOOTER
    )
    return _account_page("商家登录", body)


def portal_account() -> dict[str, Any]:
    """「我的」：工单状态 / 申请 token / 查看 token（明文，登录态）/ 状态查询。"""
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">My Account</div>
  <h2>我的</h2>
  <div id="out"></div>
  <div id="content" style="display:none">
    <div class="card form-card">
      <div id="profile"></div>
      <div id="token_box"></div>
      <div id="apply_form" style="display:none">
        <label for="a_domain">店铺域名（如 acme.example）</label>
        <input id="a_domain" placeholder="acme.example" autocomplete="off">
        <label for="a_name">商家名称</label>
        <input id="a_name" placeholder="Acme Merchant">
        <label for="a_phone">电话联系方式（选填）</label>
        <input id="a_phone" placeholder="+86 138 0000 0000">
        <label for="a_purpose">用途说明（选填）</label>
        <textarea id="a_purpose" rows="2" placeholder="想销售的商品类目"></textarea>
        <button class="btn-form" id="request_token">申请令牌</button>
      </div>
      <div class="section-title" style="text-align:left;margin-top:26px">账户基本信息</div>
      <div id="profile_edit" style="text-align:left">
        <label for="p_email">邮箱（登录账号，不可修改）</label>
        <input id="p_email" disabled>
        <label for="p_name">商家名称</label>
        <input id="p_name">
        <label for="p_phone">电话（选填）</label>
        <input id="p_phone">
        <button class="btn-form" id="save_profile">保存基本信息</button>
        <div id="out_profile"></div>
      </div>
      <button class="btn-form" id="logout">退出登录</button>
    </div>
  </div>
</div></section>
<script>
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function loadMe() {
  fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
    if (!r.ok) {
      // 未登录：直接进入登录流程（登录页含注册入口）
      window.location.href = '/portal/login';
      return;
    }
    document.getElementById('content').style.display = 'block';
    const p = document.getElementById('profile');
    let html = '<h3>' + esc(r.email) + '</h3>';
    html += '<p class="small">账号 ID ' + esc(r.account_id) + (r.merchant_id ? ' · 商家 ' + esc(r.merchant_id) : '') + '</p>';
    if (r.application) {
      html += '<p>申请状态：<strong>' + esc(r.application.status) + '</strong>'
        + (r.application.status === 'rejected' && r.application.review_note ? '（' + esc(r.application.review_note) + '）' : '')
        + ' · ' + esc(r.application.agent_name) + ' · ' + esc(r.application.domain) + '</p>';
    }
    p.innerHTML = html;
    document.getElementById('p_email').value = r.email;
    document.getElementById('p_name').value = r.merchant_name || '';
    document.getElementById('p_phone').value = r.phone || '';
    const tb = document.getElementById('token_box');
    const rt = document.getElementById('request_token');
    if (r.token && r.token.status === 'active') {
      tb.innerHTML = '<p class="small">商家令牌（mkt_…，当前登录会话可查看；遗失或疑似泄露请联系运营轮换）</p>'
        + '<div class="token-box">' + esc(r.token.token) + '</div>'
        + '<p class="small">签发 ' + esc((r.token.issued_at || '').slice(0, 10))
        + (r.token.rotated_at ? ' · 最近轮换 ' + esc(r.token.rotated_at.slice(0, 10)) : '')
        + (r.token.revoked_at ? ' · 已吊销 ' + esc(r.token.revoked_at.slice(0, 10)) : '')
        + '</p><p class="small">Agent ' + r.agents_count + ' · 商品 ' + r.listings_count + '</p>'
        + '<button class="btn-mini" id="copy_token">复制令牌</button>';
      document.getElementById('copy_token').addEventListener('click', () => {
        navigator.clipboard.writeText(document.querySelector('.token-box').textContent.trim());
      });
      rt.style.display = 'none';
    } else if (r.application && r.application.status === 'pending') {
      tb.innerHTML = '<p class="ok">申请审核中，请稍候。通过后令牌会显示在这里。</p>';
      rt.style.display = 'none';
      document.getElementById('apply_form').style.display = 'none';
    } else {
      tb.innerHTML = '<p class="small muted">还没有令牌。填写商家信息提交申请，平台审核通过后签发。</p>';
      rt.style.display = 'none';
      document.getElementById('apply_form').style.display = 'block';
    }
  });
}
document.getElementById('request_token').addEventListener('click', () => {
  const btn = document.getElementById('request_token');
  btn.disabled = true;
  postJson('/v1/accounts/token-request', {
    domain: document.getElementById('a_domain').value.trim(),
    agent_name: document.getElementById('a_name').value.trim(),
    phone: document.getElementById('a_phone').value.trim(),
    purpose: document.getElementById('a_purpose').value.trim(),
  }).then(r => {
    if (r.ok) { loadMe(); } else {
      const out = document.getElementById('out');
      out.className = 'err';
      out.textContent = r.error || '申请失败';
      btn.disabled = false;
    }
  });
});
document.getElementById('save_profile').addEventListener('click', () => {
  const btn = document.getElementById('save_profile');
  btn.disabled = true;
  postJson('/v1/accounts/profile', {
    merchant_name: document.getElementById('p_name').value.trim(),
    phone: document.getElementById('p_phone').value.trim(),
  }).then(r => {
    const out = document.getElementById('out_profile');
    if (r.ok) {
      out.className = 'ok';
      out.textContent = '已保存。';
      loadMe();
    } else {
      out.className = 'err';
      out.textContent = r.error || '保存失败';
      btn.disabled = false;
    }
  });
});
document.getElementById('logout').addEventListener('click', () => {
  postJson('/v1/accounts/logout', {}).then(() => { window.location.href = '/portal'; });
});
loadMe();
</script>
"""
        + _FOOTER
    )
    return _account_page("我的", body)


def _not_found_html() -> str:
    """404 页面 HTML 字符串（不含 JS，供 __status__: 404 包裹）。"""
    body = (
        _nav("")
        + """
<section class="section"><div class="section-inner">
  <div class="kicker">404</div>
  <h2>页面不存在</h2>
  <p class="lead">审核后台不对外公开，运营请使用本地 CLI：<code>kiwi-catalog catalog merchant applications approve &lt;id&gt;</code>。</p>
</div></section>
"""
        + _FOOTER
    )
    return _page("Not Found", body)["__html__"]
