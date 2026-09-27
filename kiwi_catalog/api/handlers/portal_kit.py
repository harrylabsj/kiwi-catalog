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

"""门户页面共享渲染基建（portal 页面套件的公开、可复用层）。

从 ``handlers/portal.py`` 抽出的 move-only 模块：官网同源 CSS、CSP nonce
页面骨架 ``page()``、通用 JS helper（``PORTAL_JS``）、导航/页脚与 404。
依赖单向——``portal.py → portal_kit``；包外扩展（如私有运营后台）也只
允许依赖本模块，不 import portal 的私有名字。

安全边界（沿用原实现，逐字节不变）：
- ``page()`` 生成 per-response CSP nonce，页面所有 ``<script>``（含 body
  内嵌块与共享/扩展 JS）统一重写带上 nonce——绕过转义的匿名数据无法执行
  （KC-SEC-01）。**任何页面都必须经 ``page()`` 渲染**：手拼 HTML 的脚本
  没有 nonce，会被 CSP 静默拦截（表现为"按钮点了没反应"）。
- ``head_js`` 在 body 之前发射（页面 load 期脚本要用 helper，见
  tests/test_portal_script_order.py 的生产事故说明），只能放纯函数声明。
"""

from __future__ import annotations

import secrets
from typing import Any

# 官网 style.css（kiwi 仓 docs/website/style.css，2026-08-08 同步）——两处
# 共用同一套主题（--kiwi-* 变量、nav/section/card/btn/notice/footer）。
OFFICIAL_CSS = """
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
.subnav { display: flex; gap: 14px; margin: 14px 0 20px; border-bottom: 1px solid var(--line); padding-bottom: 10px; }
.subnav a { color: var(--ink-soft); text-decoration: none; font-size: 0.95rem; padding: 4px 2px; border-bottom: 2px solid transparent; }
.subnav a:hover, .subnav a.active { color: var(--kiwi-700); border-bottom-color: var(--kiwi-600); }
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
PORTAL_EXTRA_CSS = """
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
.token-panel { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
.token-panel .btn-mini { margin-left: 0; }
.token-panel .small { flex: 1 1 auto; }
.btn-mini {
  border: 1px solid var(--line); background: var(--paper-soft); color: var(--ink);
  padding: 7px 14px; border-radius: 999px; font-size: 0.85rem; font-weight: 600;
  cursor: pointer; font-family: inherit; margin-left: 6px;
}
.btn-mini:disabled { opacity: 0.45; cursor: not-allowed; }
.token-actions { display: flex; gap: 10px; margin: 12px 0 4px; }
.token-box { background: var(--kiwi-100); color: var(--kiwi-900); border-left: 4px solid var(--kiwi-600); border-radius: 0 var(--radius) var(--radius) 0; font-family: ui-monospace, Menlo, monospace; font-size: 0.92rem; padding: 12px 14px; word-break: break-all; margin: 10px 0; }
.mono { font-family: ui-monospace, Menlo, monospace; font-size: 0.85rem; }
.small { font-size: 0.83rem; color: var(--ink-soft); }
.req { color: #b3261e; font-weight: 700; }
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

# 通用 JS helper：所有门户页面共享（原 _PORTAL_JS 通用段）。admin 专用
# 面板 JS 不在本模块——它属于具体页面/扩展，经 shared_js / extra_js 传入。
PORTAL_JS = """
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
(function () {
  const el = document.getElementById('nav_logout');
  if (el) el.addEventListener('click', (e) => {
    e.preventDefault();
    postJson('/v1/accounts/logout', {}).then(() => { window.location.href = '/portal'; });
  });
})();
"""

OFFICIAL_HOME = "https://kiwi.harrylabsj.com/"


def nav(active: str = "") -> str:
    """商家侧一级导航：首页 / 买家接入 / 商家接入 / 开发者 / 商家后台。

    与官网（kiwi.harrylabsj.com）首页导航一致，指向官网各页（Demo 已在官网
    首页，不再单列）；商家后台为门户本地页（/portal/account）。令牌申请/复制
    入口收敛在商家后台页内（有令牌显示复制按钮，无令牌显示申请按钮）。
    """
    account_cls = ' class="active"' if active == "account" else ""
    return f"""
<nav class="nav"><div class="nav-inner">
  <a class="nav-logo" href="{OFFICIAL_HOME}">Kiwi</a>
  <div class="nav-links">
    <a href="{OFFICIAL_HOME}">首页</a>
    <a href="{OFFICIAL_HOME}buyers">买家</a>
    <a href="{OFFICIAL_HOME}merchants">商家</a>
    <a href="{OFFICIAL_HOME}developers">开发者</a>
    <a href="/portal/account"{account_cls}>商家后台</a>
  </div>
</div></nav>
"""


FOOTER = """
<footer class="footer"><div class="footer-inner">
  <p>Kiwi Merchant Portal · 注册后自动获得免费商品名额 · 商品发布由当前 Runtime 绑定签名</p>
</div></footer>
"""


def page(
    title: str,
    body: str,
    extra_js: str = "",
    head_js: str = "",
    shared_js: str = PORTAL_JS,
) -> dict[str, Any]:
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
            f"<style>{OFFICIAL_CSS}{PORTAL_EXTRA_CSS}</style></head>"
            # `head_js` 在 **body 之前**发射：页面自己的 <script> 在 load 期就会调用
            # 共享 helper（如 `nextTarget`），放在 body 之后会 ReferenceError →
            # 整段页面脚本中断 → 按钮点了没反应（生产事故：商家登录页）。
            # 因此它只能放**纯函数声明**，不得有 load 期的 DOM 访问。
            f"<body><script nonce=\"{nonce}\">{head_js}</script>{body}"
            f"<script nonce=\"{nonce}\">{shared_js}{extra_js}</script></body></html>"
        )
    }


def not_found_html(lead_html: str = "") -> str:
    """404 页面 HTML 字符串（不含 JS，供 __status__: 404 包裹）。

    ``lead_html`` 由调用方给正文说明（运营后台等扩展传入自己的文案），
    默认中性。
    """
    body = (
        nav("")
        + f"""
<section class="section"><div class="section-inner">
  <div class="kicker">404</div>
  <h2>页面不存在</h2>
  <p class="lead">{lead_html}</p>
</div></section>
"""
        + FOOTER
    )
    return page("Not Found", body)["__html__"]
