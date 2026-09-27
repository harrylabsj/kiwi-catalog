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
import json
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


def _page(title: str, body: str, extra_js: str = "", head_js: str = "") -> dict[str, Any]:
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
            # `head_js` 在 **body 之前**发射：页面自己的 <script> 在 load 期就会调用
            # 共享 helper（如 `nextTarget`），放在 body 之后会 ReferenceError →
            # 整段页面脚本中断 → 按钮点了没反应（生产事故：商家登录页）。
            # 因此它只能放**纯函数声明**，不得有 load 期的 DOM 访问。
            f"<body><script nonce=\"{nonce}\">{head_js}</script>{body}"
            f"<script nonce=\"{nonce}\">{_PORTAL_JS}{extra_js}</script></body></html>"
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
(function () {
  const el = document.getElementById('nav_logout');
  if (el) el.addEventListener('click', (e) => {
    e.preventDefault();
    postJson('/v1/accounts/logout', {}).then(() => { window.location.href = '/portal'; });
  });
})();

/* ── admin token 面板：记住（本浏览器）/ 更换 / 清除 ──────────────────────
   三个 admin 页各自有一个 token 输入框（元素 id 为 admin_token），这里统一
   接管：token 存 localStorage（键 kiwi_admin_token，同源共享），页面代码
   一律走 adminToken()。

   三条行为约定（2026-09-26 修）：
   1. **空白一律剥离**：token 是 hex/base64 串，空白只可能来自粘贴；此前只
      `.trim()` 首尾，粘贴带入的内部换行会让服务端比对必然失败。
   2. **记住即校验**：保存后立刻用一个轻量 admin 端点探一次，把"记住了但
      服务端不认"当场说清楚——此前要等下一次业务请求才以「invalid admin
      token」暴露，看起来像"记住失败"。
   3. **面板只管本浏览器**：它**不修改服务器上的 admin token**（服务器值在
      部署配置 /etc/kiwi-catalog/env 里，改动需要运维操作）。已记住时不回填
      输入框（避免截屏/共享屏泄露），输入框与其 label 在已记住时隐藏，点
      「更换」才显示——避免页面上留一个空框让人以为要在这里改服务器 token。

   localStorage 存全权凭据是有意识取舍：portal 无第三方脚本、CSP 用
   per-response nonce，XSS 面可控；localStorage 不可用（隐私模式）时静默
   降级为「每次手输」，行为与改造前一致。 */
const ADMIN_TOKEN_KEY = 'kiwi_admin_token';
function normalizeTokenValue(v) {
  // 去所有空白（含 NBSP / 全角空格等），token 里不可能有空白
  return String(v == null ? '' : v).replace(/\\s+/g, '');
}
function storedAdminToken() {
  try { return normalizeTokenValue(window.localStorage.getItem(ADMIN_TOKEN_KEY) || ''); } catch (e) { return ''; }
}
function adminToken() {
  const el = document.getElementById('admin_token');
  const typed = el ? normalizeTokenValue(el.value) : '';
  return typed || storedAdminToken();
}
function setTokenStatus(text, cls) {
  const s = document.getElementById('admin_token_status');
  if (s) { s.textContent = text || ''; s.className = 'small ' + (cls || 'muted'); }
}
function adminTokenFields(show) {
  const input = document.getElementById('admin_token');
  const label = document.querySelector('label[for="admin_token"]');
  if (input) { input.style.display = show ? '' : 'none'; }
  if (label) { label.style.display = show ? '' : 'none'; }
}
function probeAdminToken(token) {
  // true=服务端通过 / false=被拒 / null=无法判定（网络或服务问题——
  // 不把"探不通"说成"token 无效"）。用最小窗口的 dashboard 端点，只读。
  return getJson('/v1/admin/dashboard?days=1', token).then(
    r => (r && r.ok === true) ? true : (r && r.error ? false : null),
    () => null
  );
}
function mountAdminTokenPanel() {
  const input = document.getElementById('admin_token');
  if (!input || document.getElementById('admin_token_panel')) { return; }
  const panel = document.createElement('div');
  panel.id = 'admin_token_panel';
  panel.className = 'token-panel';
  panel.innerHTML = '<span id="admin_token_status" class="small muted"></span>'
    + '<button type="button" class="btn-mini" id="admin_token_remember">记住</button>'
    + '<button type="button" class="btn-mini" id="admin_token_edit">更换</button>'
    + '<button type="button" class="btn-mini" id="admin_token_clear">清除</button>'
    + '<button type="button" class="btn-mini" id="admin_token_rotate_toggle">轮换服务器 token</button>';
  input.insertAdjacentElement('afterend', panel);
  // 查询写错会得到 null，抛出的 TypeError 会把同一段脚本里**后续所有**监听
  // 一起带走——"按钮点了没反应"的经典成因（2026-09-26 实测抓到过一次）。
  // 全部按钮统一走这个守卫：今后再错也只是该按钮失效，不会整页瘫。
  const on = (root, sel, handler) => {
    const el = root.querySelector(sel);
    if (el) { el.addEventListener('click', handler); }
  };
  const rememberBtn = panel.querySelector('#admin_token_remember');
  const editBtn = panel.querySelector('#admin_token_edit');
  // 轮换区：改的是**服务器上**的 admin token（需要当前 token 有效）。
  // 与「更换」的区别在文案里写死，避免又一次把两者混起来。
  const rotateBox = document.createElement('div');
  rotateBox.id = 'admin_token_rotate_box';
  rotateBox.style.cssText = 'display:none;margin-top:8px';
  rotateBox.innerHTML = '<label for="admin_new_token">新 token（留空 = 自动生成 43 字符；至少 24 字符、不含空白）</label>'
    + '<input id="admin_new_token" placeholder="新 admin token" autocomplete="off">'
    + '<div class="token-panel">'
    + '<button type="button" class="btn-mini" id="admin_token_rotate_go">确认轮换（旧值立即失效）</button>'
    + '<button type="button" class="btn-mini" id="admin_token_rotate_cancel">取消</button>'
    + '</div><div id="admin_token_rotate_out" class="small"></div>';
  panel.insertAdjacentElement('afterend', rotateBox);
  function setRotateOut(text, cls) {
    const out = document.getElementById('admin_token_rotate_out');
    if (out) { out.className = 'small ' + (cls || 'muted'); out.textContent = text || ''; }
  }
  function showStoredState() {
    const has = !!storedAdminToken();
    adminTokenFields(!has);
    rememberBtn.style.display = has ? 'none' : '';
    editBtn.style.display = has ? '' : 'none';
  }
  /** 校验**已记住**的那个 token 并把结果说出来。
   *
   * 为什么必须做：`showStoredState()` 只说"本浏览器存了一个值"，此前页面就停在
   * 那句中性文案上——用户会读成"token 有效"，直到点「加载」才吃一个 invalid
   * （2026-09-26 生产反馈）。记住的那一刻校验过还不够：值可能是**上次**存下的
   * （当时就报错、但按设计仍保留），或服务器端 token 期间被轮换。
   */
  function validateStored() {
    const current = storedAdminToken();
    if (!current) { return; }
    setTokenStatus('已记住 token（仅本浏览器），正在校验…', 'muted');
    probeAdminToken(current).then(ok => {
      // 校验期间用户可能已改过/清掉 → 只在值未变时更新，避免新值被旧结果盖住
      if (storedAdminToken() !== current) { return; }
      if (ok === true) { setTokenStatus('已记住 token（仅本浏览器），校验通过', 'muted'); }
      else if (ok === false) { setTokenStatus('已记住的 token 被服务端拒绝（invalid）——点「更换」填入正确的 token，或点「清除」', 'err'); }
      else { setTokenStatus('已记住 token（仅本浏览器），但校验请求没成功（网络或服务问题），有效性未确认', 'err'); }
    });
  }
  if (rememberBtn) rememberBtn.addEventListener('click', () => {
    const v = normalizeTokenValue(input.value);
    if (!v) { setTokenStatus('输入框为空，未记住', 'err'); return; }
    try { window.localStorage.setItem(ADMIN_TOKEN_KEY, v); }
    catch (e) { setTokenStatus('本浏览器不允许记住（localStorage 不可用）', 'err'); return; }
    input.value = '';
    showStoredState();
    validateStored();
  });
  if (editBtn) editBtn.addEventListener('click', () => {
    adminTokenFields(true);
    input.value = '';
    input.focus();
    rememberBtn.style.display = '';
    editBtn.style.display = 'none';
    setTokenStatus('输入 token 后点「记住」（只改本浏览器；服务器上的 token 不受影响）', 'muted');
  });
  on(panel, '#admin_token_clear', () => {
    try { window.localStorage.removeItem(ADMIN_TOKEN_KEY); } catch (e) { /* 忽略 */ }
    input.value = '';
    adminTokenFields(true);
    rememberBtn.style.display = '';
    editBtn.style.display = 'none';
    setTokenStatus('已清除（服务器上的 token 未受影响）', 'muted');
  });
  // ── 轮换服务器 token ────────────────────────────────────────────────────
  on(panel, '#admin_token_rotate_toggle', () => {
    const show = rotateBox.style.display === 'none';
    rotateBox.style.display = show ? '' : 'none';
    if (show) {
      setRotateOut('轮换会改动**服务器上**的 token：旧值在所有地方立即失效。'
        + '需要当前 token 有效（本浏览器已记住或已输入）。', 'muted');
      const el = document.getElementById('admin_new_token');
      if (el) { el.value = ''; el.focus(); }
    }
  });
  on(rotateBox, '#admin_token_rotate_cancel', () => {
    rotateBox.style.display = 'none';
    setRotateOut('', '');
  });
  on(rotateBox, '#admin_token_rotate_go', () => {
    const current = adminToken();
    if (!current) {
      setRotateOut('需要先在输入框里填当前 token（或先「记住」）才能轮换', 'err');
      return;
    }
    if (!window.confirm('轮换后旧 admin token 在所有地方立即失效（其它浏览器/脚本都要重新输入新值）。继续？')) {
      return;
    }
    const body = {};
    const chosen = normalizeTokenValue((document.getElementById('admin_new_token') || {}).value || '');
    if (chosen) { body.new_token = chosen; }
    setRotateOut('正在轮换…', 'muted');
    postJson('/v1/admin/token/rotate', body, current).then(r => {
      if (!r || !r.ok) {
        setRotateOut('轮换失败：' + ((r && r.error) || '未知错误'), 'err');
        return;
      }
      try { window.localStorage.setItem(ADMIN_TOKEN_KEY, r.token); } catch (e) { /* 忽略 */ }
      input.value = '';          // 关键：别让输入框里的旧值继续赢过已存的新值
      showStoredState();
      const out = document.getElementById('admin_token_rotate_out');
      out.className = 'small ok';
      out.innerHTML = '已轮换（第 ' + escHtml(r.rotation_count) + ' 次 · ' + escHtml(r.rotated_at) + '）。'
        + '<div class="token-box" id="admin_token_new_value">' + escHtml(r.token) + '</div>'
        + '<button type="button" class="btn-mini" id="admin_token_copy_new">复制新 token</button>'
        + '<p class="small err">旧 token 已立即失效。请把新值保存好——服务器配置里仍是旧值，'
        + '恢复路径见部署文档（删库里的轮换行 + 重启）。</p>';
      on(document, '#admin_token_copy_new', () => {
        const box = document.getElementById('admin_token_new_value');
        if (box && navigator.clipboard) { navigator.clipboard.writeText(box.textContent || ''); }
      });
    });
  });
  showStoredState();
  validateStored();  // 页面一打开就校验已记住的值，别让"已记住"被读成"有效"
}
mountAdminTokenPanel();
"""


_OFFICIAL_HOME = "https://kiwi.harrylabsj.com/"


def _nav(active: str = "") -> str:
    """商家侧一级导航：首页 / 买家接入 / 商家接入 / 开发者 / 商家后台。

    与官网（kiwi.harrylabsj.com）首页导航一致，指向官网各页（Demo 已在官网
    首页，不再单列）；商家后台为门户本地页（/portal/account）。令牌申请/复制
    入口收敛在商家后台页内（有令牌显示复制按钮，无令牌显示申请按钮）。
    """
    account_cls = ' class="active"' if active == "account" else ""
    return f"""
<nav class="nav"><div class="nav-inner">
  <a class="nav-logo" href="{_OFFICIAL_HOME}">Kiwi</a>
  <div class="nav-links">
    <a href="{_OFFICIAL_HOME}">首页</a>
    <a href="{_OFFICIAL_HOME}buyers">买家</a>
    <a href="{_OFFICIAL_HOME}merchants">商家</a>
    <a href="{_OFFICIAL_HOME}developers">开发者</a>
    <a href="/portal/account"{account_cls}>商家后台</a>
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
  <p>Kiwi Merchant Portal · 登录后仅商家本人可查看或复制目录令牌 · 明文令牌不写入日志</p>
</div></footer>
"""


def portal_home() -> dict[str, Any]:
    """门户首页 = Token 申请（登录态一个按钮；未登录引导登录）。

    D7：申请收成一个按钮「申请目录令牌」，不再收集域名（API 的 domain 参数
    仍保留给 CLI 与老调用方）。邮箱/电话不需要填写——注册与账户基本信息已
    提供，提交时自动带上。商家 ID（平台分配）与商家名称为只读展示（取自
    /v1/accounts/me；名称在「基本信息」页修改）；未分配商家 ID 或未填写名称
    时按钮灰化并引导先补全。四态：active 显示令牌 + 复制、pending 按钮禁用、
    被拒显示理由 + 「重新申请」、无令牌无工单按钮可点。
    """
    body = (
        _nav("portal")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Token 申请</div>
  <h2>Token 申请</h2>
  <p class="lead">申请商家目录令牌，平台审核通过后签发。令牌会显示在「商家后台」里。</p>
  <div class="card form-card">
    <label for="t_merchant_id">商家 ID（平台分配，只读）</label>
    <input id="t_merchant_id" readonly placeholder="加载中…">
    <label for="t_name">商家名称（只读，可在<a href="/portal/account/profile">基本信息</a>页修改）</label>
    <input id="t_name" readonly placeholder="加载中…">
    <div id="t_state"></div>
    <button class="btn-form" id="t_submit">申请目录令牌</button>
    <div id="t_out"></div>
  </div>
</div></section>
<script>
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
// 登录态检查：未登录进入登录流程（邮箱/电话自动从账户带出）
fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
  if (!r.ok) { window.location.href = '/portal/login'; return; }
  document.getElementById('t_name').value = r.merchant_name || '';
  document.getElementById('t_merchant_id').value = r.merchant_id || '';
  const out = document.getElementById('t_out');
  const state = document.getElementById('t_state');
  const btn = document.getElementById('t_submit');
  if (!r.merchant_id) {
    // 未分配商家 ID：禁止提交，引导先完成注册（服务端 request_token 同样 fail-closed）
    btn.disabled = true;
    out.className = 'err';
    out.innerHTML = '尚未分配商家 ID，请先<a href="/portal/register">完成注册</a>';
    return;
  }
  if (!r.merchant_name) {
    // 商家名称只读：为空时引导先去基本信息页补全（服务端要求 agent_name 非空）
    btn.disabled = true;
    out.className = 'err';
    out.innerHTML = '尚未填写商家名称，请先在<a href="/portal/account/profile">基本信息</a>页补全';
    return;
  }
  // 只陈述 Catalog 能观察到的审批/签发事实；不推断 Runtime 本地配置。
  if (r.token && r.token.status === 'active') {
    state.innerHTML = '<p class="ok"><strong>可发布（目录侧）</strong></p>'
      + '<p class="small">Catalog 已确认审批通过且令牌有效。是否已配置到 Runtime 由 Catalog 无法观测。</p>'
      + '<p class="small">商家令牌仅登录后向本人显示，请妥善保管。</p>'
      + '<div class="token-box">' + esc(r.token.token) + '</div>'
      + '<button type="button" class="btn-mini" id="t_copy_token">复制令牌</button>';
    btn.disabled = true;
    const copyBtn = document.getElementById('t_copy_token');
    if (copyBtn) copyBtn.addEventListener('click', () => {
      const box = state.querySelector('.token-box');
      if (box && navigator.clipboard) navigator.clipboard.writeText((box.textContent || '').trim());
    });
  } else if (r.application && r.application.status === 'pending') {
    state.innerHTML = '<p class="ok"><strong>审核中</strong>：目录令牌申请正在审核。</p>';
    btn.disabled = true;
  } else if (r.application && r.application.status === 'rejected') {
    state.innerHTML = '<p class="err"><strong>未申请</strong>。上次申请未通过'
      + (r.application.review_note ? '：' + esc(r.application.review_note) : '')
      + '。可点击「重新申请」再次提交。</p>';
    btn.textContent = '重新申请';
  } else if (r.application && r.application.status === 'approved') {
    state.innerHTML = '<p class="ok"><strong>待配置</strong>：申请已通过，请在 Runtime 的安全配置中设置目录令牌；Catalog 无法确认本地配置状态。</p>';
    btn.disabled = true;
  } else {
    state.innerHTML = '<p class="small muted"><strong>未申请</strong>：目录商品 listings 需要审批通过的目录令牌。名片接入不受此审批影响。</p>';
  }
});
document.getElementById('t_submit').addEventListener('click', () => {
  const btn = document.getElementById('t_submit');
  const out = document.getElementById('t_out');
  btn.disabled = true;
  // 申请已零输入（D7）——点击只建 pending 工单，不带任何字段
  postJson('/v1/accounts/token-request', {}).then(r => {
    if (r.ok) {
      out.className = 'ok';
      out.textContent = r.status === 'active' ? '你已有有效令牌，可在「商家后台」查看。' : '申请已提交，等待平台审核。';
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
    """/portal/apply 兼容旧路径——与首页（Token 申请，D7 一个按钮）同内容。"""
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
  out.innerHTML = '<p class="small">已批准商家</p><div class="token-box">' + escHtml(r.merchant_id)
    + '</div><p class="small">令牌已签发并加密存储，商家可在自己的「商家后台」查看。
      运营无需记录令牌。</p>';
}
function loadList() {
  const token = adminToken();
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
        + '<span class="small mono">' + escHtml(a.domain) + ' · Agent ' + escHtml(a.agent_id || '-') + ' · ' + escHtml(a.contact_email) + '</span>'
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
  const token = adminToken();
  const app = e.target.dataset.app;
  const rej = e.target.dataset.rej;
  if (app) {
    postJson('/v1/merchants/applications/' + app + '/approve', {}, token)
      .then(r => { if (r.ok) { showToken(r); loadList(); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  } else if (rej) {
    const note = prompt('拒绝理由（必填，将展示给商家）：');
    if (note === null) { return; }
    if (!note.trim()) {
      document.getElementById('out').textContent = '拒绝理由不能为空';
      document.getElementById('out').className = 'err';
      return;
    }
    postJson('/v1/merchants/applications/' + rej + '/reject', {review_note: note.trim()}, token)
      .then(r => { if (r.ok) { loadList(); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  }
});
</script>
"""
        + _FOOTER
    )
    return _page("审核后台", body)



def portal_admin_searches() -> dict[str, Any]:
    """买家搜索事件页——默认不对外公布（env 开关，与审核后台一致）。

    表格展示最近买家搜索：时间/类型/搜索词/过滤/结果数（命中 vs 未命中
    徽标）/返回摘要。未命中（result_count==0）= 需求缺口信号。
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
  <h2>买家搜索事件</h2>
  <p class="lead">买家通过 catalog 搜索 agent / listing 的记录。未命中（结果数 0）= 需求缺口信号。</p>
  <div class="card form-card">
    <label for="admin_token">Admin Token</label>
    <input id="admin_token" type="password" placeholder="admin token" autocomplete="off">
    <label for="search_limit" style="margin-top:10px">条数</label>
    <input id="search_limit" type="number" value="100" min="1" max="500">
    <button class="btn-form" id="load">加载搜索记录</button>
    <div id="out"></div>
    <div id="list"></div>
  </div>
</div></section>
<style>
.search-table{width:100%;border-collapse:collapse;margin-top:16px;font-size:0.86rem}
.search-table th,.search-table td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.search-table th{background:var(--kiwi-100);color:var(--kiwi-800)}
.badge-hit{color:#0a7d3c;font-weight:700}
.badge-miss{color:#b02a37;font-weight:700}
</style>
<script>
function renderEvents(events) {
  const list = document.getElementById('list');
  list.innerHTML = '';
  if (!events.length) { list.innerHTML = '<p class="small">暂无搜索记录</p>'; return; }
  const table = document.createElement('table');
  table.className = 'search-table';
  table.innerHTML = '<thead><tr><th>时间(UTC)</th><th>类型</th><th>搜索词</th><th>过滤</th><th>结果</th><th>返回摘要</th></tr></thead>';
  events.forEach(e => {
    const hit = (e.result_count || 0) > 0;
    const filters = Object.entries(e.filters || {})
      .map(([k, v]) => k + '=' + v).join(', ');
    const summary = (e.result_summary || []).slice(0, 5)
      .map(s => (s.title || s.display_name || s.catalog_agent_id || s.listing_id || ''))
      .filter(Boolean).join(' · ');
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="small mono">' + escHtml(e.created_at || '') + '</td>'
      + '<td>' + escHtml(e.search_type || '') + '</td>'
      + '<td><strong>' + escHtml(e.query || '') + '</strong></td>'
      + '<td class="small">' + escHtml(filters) + '</td>'
      + '<td>' + (hit
          ? '<span class="badge-hit">命中 ' + escHtml(e.result_count) + '</span>'
          : '<span class="badge-miss">未命中</span>') + '</td>'
      + '<td class="small">' + escHtml(summary) + '</td>';
    table.appendChild(tr);
  });
  list.appendChild(table);
}
function loadSearches() {
  const token = adminToken();
  const limit = document.getElementById('search_limit').value || 100;
  const out = document.getElementById('out');
  out.className = ''; out.textContent = '';
  getJson('/v1/admin/searches?limit=' + encodeURIComponent(limit), token).then(r => {
    if (!r.ok) { out.className = 'err'; out.textContent = r.error || '加载失败'; return; }
    renderEvents(r.results || []);
  });
}
document.getElementById('load').addEventListener('click', loadSearches);
</script>
"""
        + _FOOTER
    )
    return _page("买家搜索事件", body)


def portal_merchant(merchant_id: str) -> dict[str, Any]:
    """单商家详情页（/portal/merchant/{merchant_id}）。

    商家列表行末的「详情」链到这里：可刷新、可分享、可后退。页面不含数据，
    由页面 JS 用 admin token 调 /v1/admin/merchants/{id}/report 渲染（与
    Dashboard 同一条 API，读侧逻辑只有一份）。merchant_id 由 JS 从
    location.pathname 取——**不注入 HTML**，零注入面；服务端参数仅用于
    路由匹配与（非法时）404 之外的占位。
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
  <h2>商家详情</h2>
  <p class="lead"><a href="/portal/dashboard">← 返回 Dashboard</a></p>
  <div class="card form-card">
    <label for="admin_token">Admin Token</label>
    <input id="admin_token" type="password" placeholder="admin token" autocomplete="off">
    <button class="btn-form" id="load">加载详情</button>
    <div id="out"></div>
  </div>
  <div id="report"></div>
</div></section>
<script>
function merchantIdFromPath() {
  // 路径形如 /portal/merchant/<id>（id 由服务端生成，这里只做最后一段解码）。
  const parts = window.location.pathname.split('/').filter(Boolean);
  return decodeURIComponent(parts[parts.length - 1] || '');
}
function loadMerchant() {
  const out = document.getElementById('out');
  out.className = ''; out.textContent = '';
  const mid = merchantIdFromPath();
  if (!mid) { out.className = 'err'; out.textContent = '缺少商家 ID'; return; }
  adminApi('/v1/admin/merchants/' + encodeURIComponent(mid) + '/report', adminToken()).then(r => {
    if (!r.ok) { out.className = 'err'; out.textContent = r.error || '加载失败'; return; }
    document.getElementById('report').innerHTML = reportHtml(r);
  });
}
document.getElementById('load').addEventListener('click', loadMerchant);
// 已记住 token 时自动加载。必须等 load 事件：本段脚本先于共享 helper
// （_PORTAL_JS / _PORTAL_JS_EXTRA，发射在 body 之后）执行，parse 期直接调用会
// ReferenceError（生产上出过同类事故）。
window.addEventListener('load', () => { if (storedAdminToken()) { loadMerchant(); } });
</script>
"""
        + _FOOTER
    )
    return _page("商家详情", body, extra_js=_PORTAL_JS_EXTRA)


def portal_day(day: str) -> dict[str, Any]:
    """某一天的买家搜索详情页（/portal/day/{YYYY-MM-DD}）。

    两块内容：① 当天关键词（来自 ``buyer_keyword_daily`` 日聚合，任意历史日期
    都有，分「搜商家 / 搜商品」）② 当天明细事件（来自有界事件流，超出保留窗口
    时页面按 ``events_note`` 如实说明，不伪装成「当天没有搜索」）。
    日期由 JS 从 location.pathname 取，服务端只做路由匹配；日期选择器切换时
    整页跳转（保持可分享/可后退）。
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
  <h2>某日买家搜索</h2>
  <p class="lead"><a href="/portal/dashboard">← 返回 Dashboard</a></p>
  <div class="card form-card">
    <label for="day_pick">日期（UTC）</label>
    <input id="day_pick" type="date">
    <label for="admin_token">Admin Token</label>
    <input id="admin_token" type="password" placeholder="admin token" autocomplete="off">
    <button class="btn-form" id="load">加载这一天</button>
    <div id="out"></div>
  </div>
  <div id="day_content"></div>
</div></section>
<style>
.search-table{width:100%;border-collapse:collapse;margin-top:16px;font-size:0.86rem}
.search-table th,.search-table td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.search-table th{background:var(--kiwi-100);color:var(--kiwi-800)}
.badge-hit{color:#0a7d3c;font-weight:700}
.badge-miss{color:#b02a37;font-weight:700}
</style>
<script>
function dayFromPath() {
  const parts = window.location.pathname.split('/').filter(Boolean);
  return decodeURIComponent(parts[parts.length - 1] || '');
}
function keywordTable(rows, title) {
  if (!rows.length) { return '<div class="section-title">' + title + '（0）</div><p class="small muted">该日没有这类搜索</p>'; }
  return '<div class="section-title">' + title + '（' + escHtml(rows.length) + '）</div>'
    + '<table class="search-table"><thead><tr><th>关键词</th><th>搜索次数</th><th>零命中</th></tr></thead>'
    + rows.map(k => '<tr><td><strong>' + escHtml(k.keyword) + '</strong></td><td>' + escHtml(k.searches) + '</td><td>'
        + ((k.zero_results || 0) > 0 ? '<span class="badge-miss">' + escHtml(k.zero_results) + '</span>' : '0') + '</td></tr>').join('')
    + '</table>';
}
function renderDay(r) {
  const kw = r.keywords || [];
  const agentKw = kw.filter(k => k.search_type === 'agent');
  const listingKw = kw.filter(k => k.search_type === 'listing');
  let html = '<div class="kpis">'
    + '<div class="kpi"><div class="num">' + escHtml(agentKw.length) + '</div><div class="lbl">搜商家关键词</div></div>'
    + '<div class="kpi"><div class="num">' + escHtml(listingKw.length) + '</div><div class="lbl">搜商品关键词</div></div>'
    + '<div class="kpi"><div class="num">' + escHtml((r.events || []).length) + '</div><div class="lbl">明细条数</div></div>'
    + '</div>';
  html += keywordTable(agentKw, '搜商家（agent）');
  html += keywordTable(listingKw, '搜商品（listing）');
  if (r.events_note) { html += '<p class="small muted">' + escHtml(r.events_note) + '</p>'; }
  const events = r.events || [];
  html += '<div class="section-title">当天明细（' + escHtml(events.length) + '）</div>';
  if (!events.length) {
    html += '<p class="small muted">' + (r.events_note ? '明细不可得（见上）' : '该日没有搜索明细') + '</p>';
  } else {
    html += '<table class="search-table"><thead><tr><th>时间(UTC)</th><th>类型</th><th>关键词</th><th>筛选</th><th>结果</th><th>返回摘要</th></tr></thead>'
      + events.map(e => {
          const hit = (e.result_count || 0) > 0;
          const filters = Object.entries(e.filters || {}).map(([k, v]) => k + '=' + v).join(', ');
          const summary = (e.result_summary || []).slice(0, 5)
            .map(s => (s.title || s.display_name || s.catalog_agent_id || s.listing_id || ''))
            .filter(Boolean).join(' · ');
          return '<tr><td class="small mono">' + escHtml(e.created_at || '') + '</td>'
            + '<td>' + escHtml(e.search_type || '') + '</td>'
            + '<td><strong>' + escHtml(e.query || '') + '</strong></td>'
            + '<td class="small">' + escHtml(filters) + '</td>'
            + '<td>' + (hit ? '<span class="badge-hit">命中 ' + escHtml(e.result_count) + '</span>'
                            : '<span class="badge-miss">未命中</span>') + '</td>'
            + '<td class="small">' + escHtml(summary) + '</td></tr>';
        }).join('')
      + '</table>';
  }
  document.getElementById('day_content').innerHTML = html;
}
function loadDay() {
  const out = document.getElementById('out');
  out.className = ''; out.textContent = '';
  const day = dayFromPath();
  if (!day) { out.className = 'err'; out.textContent = '缺少日期'; return; }
  adminApi('/v1/admin/buyer-day?day=' + encodeURIComponent(day), adminToken()).then(r => {
    if (!r.ok) { out.className = 'err'; out.textContent = r.error || '加载失败'; return; }
    renderDay(r);
  });
}
document.getElementById('day_pick').value = dayFromPath();
document.getElementById('day_pick').addEventListener('change', e => {
  if (e.target.value) { window.location.href = '/portal/day/' + encodeURIComponent(e.target.value); }
});
document.getElementById('load').addEventListener('click', loadDay);
window.addEventListener('load', () => { if (storedAdminToken()) { loadDay(); } });
</script>
"""
        + _FOOTER
    )
    return _page("某日买家搜索", body, extra_js=_PORTAL_JS_EXTRA)


def portal_admin_buyer_stats() -> dict[str, Any]:
    """旧买家统计页——已并入运营 Dashboard（/portal/dashboard，2026-08-22 合并）。

    env 开关关闭时仍真实 404（与其他 admin 页一致）；开启时 302 跳转到
    /portal/dashboard——``__redirect__`` 元键由 fallback _send_json 与
    FastAPI _portal_html 双栈处理。API 端点 /v1/admin/buyer-stats 保留。
    """
    if str(os.environ.get(_PORTAL_ADMIN_ENABLED_ENV) or "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return {"__html__": _not_found_html(), "__status__": 404}
    return {"__redirect__": "/portal/dashboard"}



def portal_dashboard() -> dict[str, Any]:
    """运营 Dashboard——默认不对外公布（env 开关，与审核后台一致）。

    2026-08-22 起并入买家搜索统计（原 /portal/admin/buyer-stats 独立页，
    现 302 跳到本页）：去重买家 KPI + 14 天双系列柱状图 + 明细 +
    热门/未命中关键词排行。同一 admin token 输入解锁全页
    （/v1/admin/dashboard + /v1/admin/buyer-stats 等）。
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
    <div class="section-title">买家搜索统计</div>
    <div class="kpis" id="buyer_kpis"></div>
    <div class="section-title">每日去重买家数（最近 14 天）</div>
    <div id="buyer_usage"></div>
    <div class="legend" id="buyer_legend"></div>
    <div class="section-title">买家搜索明细</div>
    <div id="buyer_detail"></div>
    <div class="section-title">热门搜索关键词（最近 14 天）</div>
    <div id="top_keywords"></div>
    <div class="section-title">未命中关键词（供需缺口）</div>
    <p class="small muted">买家搜了但没有任何结果的关键词——运营招商据此补供给。</p>
    <div id="zero_hit_keywords"></div>
    <div class="section-title">访问洞察（搜索→查看漏斗）</div>
    <p class="small muted">个体访问日志（access_log）运营视图——搜→看转化、详情热度与登录失败信号。</p>
    <div class="kpis" id="funnel_kpis"></div>
    <div class="section-title">每日搜索 / 详情查看（最近 14 天）</div>
    <div id="funnel_usage"></div>
    <div class="legend" id="funnel_legend"></div>
    <div class="section-title">被查看最多的商家 / 商品</div>
    <div id="top_viewed"></div>
    <div class="section-title">登录失败信号</div>
    <p class="small muted">登录失败数（今日）与失败来源 IP 前缀 Top——防爆破监测（仅存 /24 前缀）。</p>
    <div id="login_failures"></div>
  </div>
  </div></section>
<style>
.bars2{display:flex;align-items:flex-end;gap:6px;height:120px;margin-top:18px}
.bars2 .bar{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.bars2 .pair{display:flex;align-items:flex-end;gap:2px;width:100%;height:100px}
.bars2 .fill{flex:1;border-radius:4px 4px 2px 2px;min-height:2px}
.bars2 .d{font-size:0.68rem;color:var(--ink-soft);white-space:nowrap}
</style>
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
      '<div class="bar" title="' + escHtml(u.day) + ' 总 ' + escHtml(u.total) + '"><div class="fill" style="height:' + Math.max(2, Math.round(u.total / max * 100)) + '%"></div><div class="d"><a href="/portal/day/' + encodeURIComponent(u.day) + '">' + escHtml(u.day.slice(5)) + '</a></div></div>'
    ).join('') + '</div>';
  document.getElementById('legend').innerHTML = Object.entries(METRIC_LABELS).map(([k, v]) =>
    '<span><span class="sw" style="background:' + METRIC_COLORS[k] + '"></span>' + v + '</span>'
  ).join('');
}

// ── 买家搜索统计（原 /portal/admin/buyer-stats 独立页，2026-08-22 并入）──────
const BSERIES = [
  ['buyer_agent_search', '找商家', '#2e7d32'],
  ['buyer_listing_search', '找商品', '#43a047'],
];

function renderBuyerKpis(today) {
  const total = BSERIES.reduce((s, [k]) => s + (today.total_events[k] || 0), 0);
  const unidentified = BSERIES.reduce((s, [k]) => s + (today.unidentified_events[k] || 0), 0);
  const kpis = [
    ['今日去重买家（找商家）', today.distinct_buyers.buyer_agent_search],
    ['今日去重买家（找商品）', today.distinct_buyers.buyer_listing_search],
    ['今日搜索事件总数', total],
    ['今日未识别身份事件数', unidentified],
  ];
  document.getElementById('buyer_kpis').innerHTML = kpis.map(([lbl, n]) =>
    '<div class="kpi"><div class="num">' + escHtml(n) + '</div><div class="lbl">' + escHtml(lbl) + '</div></div>'
  ).join('');
}

function renderBuyerChart(series) {
  const max = Math.max(1, ...series.flatMap(u => BSERIES.map(([k]) => u.distinct_buyers[k] || 0)));
  document.getElementById('buyer_usage').innerHTML =
    '<div class="bars2">' + series.map(u =>
      '<div class="bar" title="' + escHtml(u.day) + ' 找商家 ' + escHtml(u.distinct_buyers.buyer_agent_search)
        + ' / 找商品 ' + escHtml(u.distinct_buyers.buyer_listing_search) + '"><div class="pair">'
        + BSERIES.map(([k, , color]) =>
          '<div class="fill" style="background:' + color + ';height:'
          + Math.max(2, Math.round((u.distinct_buyers[k] || 0) / max * 100)) + '%"></div>'
        ).join('')
        + '</div><div class="d"><a href="/portal/day/' + encodeURIComponent(u.day) + '">' + escHtml(u.day.slice(5)) + '</a></div></div>'
    ).join('') + '</div>';
  document.getElementById('buyer_legend').innerHTML = BSERIES.map(([, lbl, color]) =>
    '<span><span class="sw" style="background:' + color + '"></span>' + lbl + '</span>'
  ).join('');
}

function renderBuyerDetail(series) {
  const rows = series.slice().reverse();
  document.getElementById('buyer_detail').innerHTML =
    '<table><thead><tr><th>日期</th><th>去重买家(找商家)</th><th>去重买家(找商品)</th>'
    + '<th>事件(找商家)</th><th>事件(找商品)</th><th>未识别事件</th></tr></thead>'
    + rows.map(u => {
      const unid = BSERIES.reduce((s, [k]) => s + (u.unidentified_events[k] || 0), 0);
      return '<tr><td class="mono"><a href="/portal/day/' + encodeURIComponent(u.day) + '">' + escHtml(u.day) + '</a></td>'
        + '<td>' + escHtml(u.distinct_buyers.buyer_agent_search) + '</td>'
        + '<td>' + escHtml(u.distinct_buyers.buyer_listing_search) + '</td>'
        + '<td>' + escHtml(u.total_events.buyer_agent_search) + '</td>'
        + '<td>' + escHtml(u.total_events.buyer_listing_search) + '</td>'
        + '<td>' + escHtml(unid) + '</td></tr>';
    }).join('') + '</table>';
}

function renderKeywordTable(elId, rows, cols, emptyText) {
  // cols = [label1, field1, label2, field2]（两张表共享：关键词 + 类型分布 + 两列数值）
  const el = document.getElementById(elId);
  if (!rows.length) { el.innerHTML = '<p class="small muted">' + emptyText + '</p>'; return; }
  el.innerHTML = '<table><thead><tr><th>关键词</th><th>类型分布</th><th>' + cols[0] + '</th><th>' + cols[2] + '</th></tr></thead>'
    + rows.map(kw =>
      '<tr><td><strong>' + escHtml(kw.keyword) + '</strong></td>'
      + '<td class="small muted">找商家 ' + escHtml(kw.agent_searches || 0)
      + ' · 找商品 ' + escHtml(kw.listing_searches || 0) + '</td>'
      + '<td>' + escHtml(kw[cols[1]] || 0) + '</td>'
      + '<td>' + escHtml(kw[cols[3]] || 0) + '</td></tr>'
    ).join('') + '</table>';
}

function renderBuyerStats(r) {
  renderBuyerKpis(r.today);
  renderBuyerChart(r.series || []);
  renderBuyerDetail(r.series || []);
  renderKeywordTable('top_keywords', r.top_keywords || [],
    ['搜索次数', 'searches', '未命中次数', 'zero_results'],
    '暂无搜索关键词');
  renderKeywordTable('zero_hit_keywords', (r.zero_hit_keywords || []).filter(k => (k.zero_results || 0) > 0),
    ['未命中次数', 'zero_results', '搜索总次数', 'searches'],
    '暂无未命中关键词');
}

// ── 访问洞察（access_log v28 个体访问日志；/v1/admin/access-insights）──────
function renderFunnelKpis(f) {
  const conv = f.conversion == null ? '—' : (f.conversion * 100).toFixed(1) + '%';
  const kpis = [
    ['搜索总数', f.total_searches],
    ['详情查看总数', f.total_detail_views],
    ['搜→看转化率', conv],
  ];
  document.getElementById('funnel_kpis').innerHTML = kpis.map(([lbl, n]) =>
    '<div class="kpi"><div class="num">' + escHtml(n) + '</div><div class="lbl">' + escHtml(lbl) + '</div></div>'
  ).join('');
}

function renderFunnelChart(daily) {
  const max = Math.max(1, ...daily.map(d => Math.max(d.searches, d.detail_views)));
  document.getElementById('funnel_usage').innerHTML =
    '<div class="bars2">' + daily.map(d =>
      '<div class="bar" title="' + escHtml(d.day) + ' 搜索 ' + escHtml(d.searches)
        + ' / 详情 ' + escHtml(d.detail_views) + '"><div class="pair">'
        + '<div class="fill" style="background:#2e7d32;height:' + Math.max(2, Math.round(d.searches / max * 100)) + '%"></div>'
        + '<div class="fill" style="background:#ef6c00;height:' + Math.max(2, Math.round(d.detail_views / max * 100)) + '%"></div>'
        + '</div><div class="d"><a href="/portal/day/' + encodeURIComponent(d.day) + '">' + escHtml(d.day.slice(5)) + '</a></div></div>'
    ).join('') + '</div>';
  document.getElementById('funnel_legend').innerHTML =
    '<span><span class="sw" style="background:#2e7d32"></span>搜索</span>'
    + '<span><span class="sw" style="background:#ef6c00"></span>详情查看</span>';
}

function renderTopViewed(agents, listings) {
  function table(rows, title) {
    if (!rows.length) return '<p class="small muted">暂无' + title + '</p>';
    return '<table><tr><th>' + title + '</th><th>查看次数</th><th>带身份查看者</th></tr>'
      + rows.map(r =>
        '<tr><td>' + escHtml(r.name || r.target_id) + '</td><td>' + escHtml(r.views)
        + '</td><td>' + escHtml(r.viewers) + '</td></tr>'
      ).join('') + '</table>';
  }
  document.getElementById('top_viewed').innerHTML =
    table(agents, '被查看最多的商家')
    + '<p style="height:8px"></p>'
    + table(listings, '被查看最多的商品');
}

function renderLoginFailures(lf) {
  const el = document.getElementById('login_failures');
  let html = '<div class="kpis"><div class="kpi"><div class="num">' + escHtml(lf.today)
    + '</div><div class="lbl">今日登录失败</div></div></div>';
  if (!lf.by_ip_prefix || !lf.by_ip_prefix.length) {
    html += '<p class="small muted">窗口内无登录失败记录</p>';
  } else {
    html += '<table><tr><th>IP 前缀</th><th>失败次数</th></tr>'
      + lf.by_ip_prefix.map(r =>
        '<tr><td class="mono">' + escHtml(r.ip_prefix) + '</td><td>' + escHtml(r.failures) + '</td></tr>'
      ).join('') + '</table>';
  }
  el.innerHTML = html;
}

function renderAccessInsights(r) {
  renderFunnelKpis(r.funnel);
  renderFunnelChart(r.funnel.daily || []);
  renderTopViewed(r.top_viewed_agents || [], r.top_viewed_listings || []);
  renderLoginFailures(r.login_failures || { today: 0, by_ip_prefix: [] });
}

function renderApps(token, apps) {
  const el = document.getElementById('apps');
  if (!apps.length) { el.innerHTML = '<p class="small muted">没有待审申请</p>'; return; }
  el.innerHTML = '<table><tr><th>#</th><th>名称</th><th>域名</th><th>Agent</th><th>邮箱</th><th>用途</th><th></th></tr>' +
    apps.map(a => '<tr><td>' + escHtml(a.application_id) + '</td><td>' + escHtml(a.agent_name) + '</td><td class="mono">' + escHtml(a.domain || '(未填)') +
      '</td><td>' + escHtml(a.agent_id || '-') + '</td><td>' + escHtml(a.contact_email) + '</td><td class="small muted">' + escHtml(a.purpose || '-') + '</td><td>' +
      '<button class="btn-mini" data-app="' + escHtml(a.application_id) + '">批准</button>' +
      '<button class="btn-mini" data-rej="' + escHtml(a.application_id) + '">拒绝</button></td></tr>').join('') + '</table>';
}

function renderMerchants(list) {
  const el = document.getElementById('merchants');
  if (!list.length) { el.innerHTML = '<p class="small muted">还没有商家</p>'; return; }
  el.innerHTML = '<table><tr><th>商家 ID</th><th>名称</th><th>注册邮箱</th><th>Agent</th><th>商品</th><th>令牌</th><th>签发</th><th></th></tr>' +
    list.map(m => '<tr><td class="mono">' + escHtml(m.merchant_id) + '</td><td>' + escHtml(m.name) +
      '</td><td class="mono small">' + escHtml(m.account_email || '—') +
      '</td><td>' + escHtml(m.agents_count) +
      '</td><td>' + escHtml(m.listings_count) + '</td><td>' + escHtml(m.token_status) + '</td><td class="small muted">' +
      escHtml((m.token_issued_at || '-').slice(0, 10)) + '</td><td><a class="btn-mini" href="/portal/merchant/' +
      encodeURIComponent(m.merchant_id) + '">详情</a></td></tr>').join('') + '</table>';
}

/* 商家报告正文（纯函数，详情页 /portal/merchant/<id> 复用）。 */
function reportHtml(r) {
  const m = r.merchant;
  let html = '<div class="merchant-info">'
    + '<p><strong>' + escHtml(m.name || '') + '</strong> <span class="mono">' + escHtml(m.merchant_id) + '</span></p>'
    + '<p class="small muted">创建 ' + escHtml((m.created_at || '').slice(0, 10)) + ' · 更新 ' + escHtml((m.updated_at || '').slice(0, 10)) + '</p>'
    + '<table class="kv"><tr><td>商家 ID</td><td class="mono">' + escHtml(m.merchant_id || '-') + '</td></tr>'
    + '<tr><td>商家名称</td><td>' + escHtml(m.name || '-') + '</td></tr>'
    + '<tr><td>注册邮箱（账号）</td><td class="mono">' + escHtml(m.account_email || '-') + '</td></tr>'
    + '<tr><td>申请邮箱</td><td class="mono">' + escHtml(m.contact_email || '-') + '</td></tr>'
    + '<tr><td>城市</td><td>' + escHtml(m.city || '-') + '</td></tr>'
    + '<tr><td>服务区域</td><td>' + escHtml(m.service_area || '-') + '</td></tr>'
    + '<tr><td>联系</td><td class="mono">' + escHtml(m.contact || '-') + '</td></tr>'
    + '<tr><td>创建时间</td><td class="small muted">' + escHtml(m.created_at || '-') + '</td></tr>'
    + '<tr><td>更新时间</td><td class="small muted">' + escHtml(m.updated_at || '-') + '</td></tr></table></div>';
  html += '<div class="section-title">令牌（' + escHtml((r.tokens || []).length) + '）</div>';
  html += (r.tokens || []).length ? '<table><tr><th>状态</th><th>签发</th><th>轮换</th><th>吊销</th></tr>' + r.tokens.map(t =>
    '<tr><td>' + escHtml(t.status) + '</td><td class="small muted">' + escHtml(t.issued_at || '-') + '</td><td class="small muted">' +
    escHtml(t.rotated_at || '-') + '</td><td class="small muted">' + escHtml(t.revoked_at || '-') + '</td></tr>').join('') + '</table>'
    : '<p class="small muted">无令牌记录</p>';
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
  return html;
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
    // 买家搜索统计（去重买家 + 关键词排行）；失败不阻断 dashboard 主内容
    adminApi('/v1/admin/buyer-stats?days=14', token).then(br => {
      if (br.ok) { renderBuyerStats(br); }
    });
    // 访问洞察（access_log 漏斗/热度榜/登录失败）；失败不阻断 dashboard 主内容
    adminApi('/v1/admin/access-insights?days=14', token).then(ir => {
      if (ir.ok) { renderAccessInsights(ir); }
    });
  });
}

document.getElementById('load').addEventListener('click', () => {
  const token = adminToken();
  if (!token) {
    // 无 token 时此前是"点了没反应"——运维最容易读成"页面坏了"
    const out = document.getElementById('out');
    out.className = 'err';
    out.textContent = '请先输入 admin token 并点「记住」，再点「加载」（没有 token 无法读取数据）';
    return;
  }
  loadDashboard(token);
});
document.getElementById('apps').addEventListener('click', e => {
  const token = adminToken();
  const app = e.target.dataset.app;
  const rej = e.target.dataset.rej;
  if (app) {
    postJson('/v1/merchants/applications/' + app + '/approve', {}, token)
      .then(r => { if (r.ok) { document.getElementById('out').className = ''; document.getElementById('out').textContent = '已批准 ' + r.merchant_id + '——令牌已加密存储，商家在「商家后台」查看。'; loadDashboard(token); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  } else if (rej) {
    const note = prompt('拒绝理由（必填，将展示给商家）：');
    if (note === null) { return; }
    if (!note.trim()) {
      document.getElementById('out').textContent = '拒绝理由不能为空';
      document.getElementById('out').className = 'err';
      return;
    }
    postJson('/v1/merchants/applications/' + rej + '/reject', {review_note: note.trim()}, token)
      .then(r => { if (r.ok) { loadDashboard(token); } else { document.getElementById('out').textContent = r.error; document.getElementById('out').className = 'err'; } });
  }
});
/* 商家详情已拆为独立页 /portal/merchant/<id>（列表行末的「详情」是链接），
   本页不再有同页报告卡片与其点击分支。 */
"""


_ACCOUNT_JS = """
function postJson(url, body) {
  return fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json());
}
function go(path) { window.location.href = path; }
function nextTarget(fallback) {
  // 登录/注册后的站内回跳（如 /portal/connect 的连接流程）。只接受站内相对
  // 路径：'//evil.example' 这类协议相对 URL 会被拒绝，避免开放重定向。
  const next = new URLSearchParams(window.location.search).get('next') || '';
  if (next.startsWith('/') && !next.startsWith('//')) { return next; }
  return fallback || '/portal/account';
}
"""


def _account_page(title: str, body: str) -> dict[str, Any]:
    """商家账号页（登录/注册/连接/后台…）。

    `_ACCOUNT_JS` 走 **head_js**（body 之前）：这些页面的 <script> 在 load 期就会用
    `nextTarget`，必须在它之前定义。`_ACCOUNT_JS` 只有函数声明、无 load 期 DOM 访问，
    所以前置是安全的。
    """
    return _page(title, body, head_js=_ACCOUNT_JS)


def portal_register() -> dict[str, Any]:
    """注册页（商家名称 + 邮箱 + 密码）→ 邮箱验证码 → 验证后进入「我的」。

    注册即成为商家（admin dashboard 无需审批即可见）；商家令牌仍在「我的」
    申请工单、经审核后签发。
    """
    body = (
        _nav("portal")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Register</div>
  <h2>注册商家账号</h2>
  <p class="lead">填写商家名称、邮箱、密码和联系电话即可注册成为商家（无需审核）。
    微信选填。验证邮箱后，在「我的」里申请商家令牌。</p>
  <div class="card form-card">
    <div id="step1">
      <label for="merchant_name">商家名称 <span class="req">*</span></label>
      <input id="merchant_name" placeholder="Acme 商贸" autocomplete="organization" required>
      <label for="email">邮箱</label>
      <input id="email" type="email" placeholder="ops@acme.example" autocomplete="email">
      <label for="password">密码（至少 8 位）</label>
      <input id="password" type="password" autocomplete="new-password">
      <label for="phone">电话 <span class="req">*</span></label>
      <input id="phone" type="tel" placeholder="+86 138 0000 0000" autocomplete="tel" required>
      <label for="wechat">微信（选填）</label>
      <input id="wechat" placeholder="微信号">
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
  const nameEl = document.getElementById('merchant_name');
  const merchantName = nameEl.value.trim();
  const phoneEl = document.getElementById('phone');
  if (!merchantName) {
    out.className = 'err';
    out.textContent = '请填写商家名称';
    nameEl.focus();
    return;
  }
  if (!phoneEl.value.trim()) {
    out.className = 'err';
    out.textContent = '请填写联系电话';
    phoneEl.focus();
    return;
  }
  btn.disabled = true;
  postJson('/v1/accounts/register', {
    merchant_name: merchantName,
    email: document.getElementById('email').value.trim(),
    password: document.getElementById('password').value,
    phone: document.getElementById('phone').value.trim(),
    wechat: document.getElementById('wechat').value.trim(),
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
      out.textContent = '邮箱已验证，正在继续…';
      setTimeout(() => go(nextTarget('/portal/account')), 800);
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
    <p class="small" style="margin-top:16px">还没有账号？<a id="to_register" href="/portal/register">注册商家账号</a>
      　忘记密码？<a href="/portal/reset-password">重置</a></p>
  </div>
</div></section>
<script>
let logEmail = '';
// 注册入口带上 next：连接流程中「没有账号」的商家注册+验证邮箱后回到原流程。
document.getElementById('to_register').href =
  '/portal/register?next=' + encodeURIComponent(nextTarget('/portal/account'));
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
      out.textContent = '登录成功，正在继续…';
      setTimeout(() => go(nextTarget('/portal/account')), 500);
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
    if (r.ok) { window.location.href = nextTarget('/portal/account'); }
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


def portal_connect() -> dict[str, Any]:
    """商家连接器（「Kiwi 商家运营」）连接确认页（第 1 版设计 §3.2）。

    商家从 Buddy 经商家连接器被引导到本页：登录/注册态确认「允许以我的商家
    身份访问目录资料」。同意 → 服务端签发一次性 code 并回跳入口；拒绝 → 回跳
    ``error=access_denied``。页面只展示入口自报的 client_label 与请求有效期，
    不展示也不收集任何密码（密码只在本门户的登录/注册表单里输入）。
    """
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Connect</div>
  <h2>连接「Kiwi 商家运营」</h2>
  <p class="lead">「Kiwi 商家运营」连接器请求以你的商家身份访问 Kiwi 目录资料。
    确认前请核对下方来源；你随时可以拒绝。</p>
  <div class="card form-card">
    <div id="out"></div>
    <div id="body" style="display:none">
      <p>请求方：<strong id="c_label">—</strong></p>
      <p>当前商家：<strong id="c_merchant">—</strong></p>
      <p class="small">请求编号 <span class="mono" id="c_req">—</span> · 有效期至 <span id="c_exp">—</span></p>
      <p class="small">同意后，该连接器只能在你于本门户再次确认的前提下，读写<b>你自己</b>的公开资料
        （草稿、发布状态、撤回）。它拿不到你的目录密码，也不能代替你操作其他商家；
        发布公开资料仍需你在本门户的「公开资料」页明确确认。</p>
      <div class="token-actions">
        <button class="btn-mini" id="approve">同意授权</button>
        <button class="btn-mini" id="deny">拒绝</button>
      </div>
    </div>
  </div>
</div></section>
<script>
const connectParams = new URLSearchParams(window.location.search);
const connectRequestId = connectParams.get('request_id') || '';
const connectNext = '/portal/connect?request_id=' + encodeURIComponent(connectRequestId);
function showConnectErr(msg) {
  const out = document.getElementById('out');
  out.className = 'err';
  out.textContent = msg;
}
function decideConnect(decision) {
  const approve = document.getElementById('approve');
  const deny = document.getElementById('deny');
  approve.disabled = true;
  deny.disabled = true;
  postJson('/v1/connector-identity/requests/' + encodeURIComponent(connectRequestId) + '/decision', {
    decision: decision,
  }).then(r => {
    if (!r.ok) {
      approve.disabled = false;
      deny.disabled = false;
      showConnectErr(r.error || '操作失败，请重试');
      return;
    }
    // 回跳由服务端给出（入口回跳地址 + 一次性 code / access_denied）；
    // 只接受绝对 http(s) 地址，避免脚本把自己送去别处。
    const target = String(r.redirect_url || '');
    if (!/^https?:\\/\\//.test(target)) { showConnectErr('回跳地址无效，请返回应用后重试连接'); return; }
    window.location.href = target;
  });
}
if (!connectRequestId) {
  showConnectErr('缺少 request_id：请从 Buddy 重新发起连接');
} else {
  fetch('/v1/connector-identity/requests/' + encodeURIComponent(connectRequestId), {method: 'GET', credentials: 'same-origin'})
    .then(r => r.json()).then(r => {
      if (!r.ok) {
        // 未登录/会话过期：先登录，登录后回到本页（登录页提供注册入口）
        window.location.href = '/portal/login?next=' + encodeURIComponent(connectNext);
        return;
      }
      const req = r.request || {};
      document.getElementById('c_label').textContent = req.client_label || '（未标注来源）';
      document.getElementById('c_merchant').textContent = req.merchant_name || '当前登录商家';
      document.getElementById('c_req').textContent = req.request_id || '';
      document.getElementById('c_exp').textContent = req.expires_at || '';
      document.getElementById('body').style.display = 'block';
      if (req.status !== 'pending') {
        showConnectErr(req.status === 'approved' ? '该请求已授权，请返回应用继续。' : '该请求已结束（' + req.status + '），请从应用重新发起。');
        document.getElementById('approve').disabled = true;
        document.getElementById('deny').disabled = true;
        return;
      }
      document.getElementById('approve').addEventListener('click', () => decideConnect('approve'));
      document.getElementById('deny').addEventListener('click', () => decideConnect('deny'));
    });
}
</script>
"""
        + _FOOTER
    )
    return _account_page("连接 Kiwi 商家运营", body)


def portal_reset_password() -> dict[str, Any]:
    """忘记密码页：邮箱 → 重置验证码 → 新密码 → 回登录页。

    防枚举：step1 无论邮箱是否注册都进入 step2（服务端同样返回通用 ok
    文案）；console（演示）模式直接显示重置码。
    """
    body = (
        _nav("portal")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Reset Password</div>
  <h2>重置密码</h2>
  <p class="lead">输入注册邮箱，收到验证码后设置新密码。重置成功后需要重新登录。</p>
  <div class="card form-card">
    <div id="step1">
      <label for="email">邮箱</label>
      <input id="email" type="email" placeholder="ops@acme.example" autocomplete="email">
      <button class="btn-form" id="send">发送重置验证码</button>
      <div id="out1"></div>
    </div>
    <div id="step2" style="display:none">
      <p class="ok" id="sent_note">如果该邮箱已注册，重置验证码已发送到你的邮箱。</p>
      <label for="code">重置验证码</label>
      <input id="code" placeholder="6 位验证码" autocomplete="one-time-code">
      <label for="password">新密码（至少 8 位）</label>
      <input id="password" type="password" autocomplete="new-password">
      <button class="btn-form" id="reset">重置密码</button>
      <div id="out2"></div>
    </div>
    <p class="small" style="margin-top:16px">想起来了？<a href="/portal/login">去登录</a></p>
  </div>
</div></section>
<script>
let resetEmail = '';
document.getElementById('send').addEventListener('click', () => {
  const btn = document.getElementById('send');
  const out = document.getElementById('out1');
  btn.disabled = true;
  resetEmail = document.getElementById('email').value.trim();
  postJson('/v1/accounts/forgot-password', {email: resetEmail}).then(r => {
    if (r.ok) {
      if (r.reset_code) {
        document.getElementById('sent_note').textContent = '演示模式：重置码 ' + r.reset_code;
      }
      document.getElementById('step1').style.display = 'none';
      document.getElementById('step2').style.display = 'block';
    } else {
      out.className = 'err';
      out.textContent = r.error || '发送失败';
      btn.disabled = false;
    }
  });
});
document.getElementById('reset').addEventListener('click', () => {
  const btn = document.getElementById('reset');
  const out = document.getElementById('out2');
  btn.disabled = true;
  postJson('/v1/accounts/reset-password', {
    email: resetEmail,
    code: document.getElementById('code').value.trim(),
    new_password: document.getElementById('password').value,
  }).then(r => {
    if (r.ok) {
      out.className = 'ok';
      out.textContent = '密码已重置，正在跳转到登录页…';
      setTimeout(() => go('/portal/login'), 800);
    } else {
      out.className = 'err';
      out.textContent = r.error || '重置失败';
      btn.disabled = false;
    }
  });
});
</script>
"""
        + _FOOTER
    )
    return _account_page("重置密码", body)


def portal_account() -> dict[str, Any]:
    """「我的」：工单状态 / 申请 token / 查看 token（明文，登录态）/ 状态查询。"""
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">商家后台</div>
  <h2>商家后台</h2>
  <div class="subnav">
    <a href="/portal/account/profile"{sub_profile}>基本信息</a>
    <a href="/portal/account"{sub_apply}>令牌信息</a>
    <a href="/portal/account/card"{sub_card}>我的名片</a>
    <a href="/portal/publications">公开资料</a>
    <a href="/portal/follows">我的关注</a>
    <a href="#" id="nav_logout" style="margin-left:auto">退出登录</a>
  </div>
  <div id="out"></div>
  <div id="content" style="display:none">
    <div class="card form-card">
  <p class="small">目录商品 listings 需要审批通过的目录令牌。名片绑定与发布不依赖该令牌。</p>
      <div id="profile"></div>
      <div id="token_box"></div>
      <div class="token-actions">
        <button class="btn-mini" id="copy_token">复制令牌</button>
        <button class="btn-mini" id="apply_token">申请目录令牌</button>
      </div>
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
        + ' · ' + esc(r.application.agent_name)
        + (r.application.domain ? ' · ' + esc(r.application.domain) : '') + '</p>';
    }
    p.innerHTML = html;
    const tb = document.getElementById('token_box');
    const copyBtn = document.getElementById('copy_token');
    const applyBtn = document.getElementById('apply_token');
    // 仅在已认证的商家本人会话页回显令牌；公开预览及接入页绝不包含凭据。
    if (r.token && r.token.status === 'active') {
      tb.innerHTML = '<p class="ok"><strong>可发布（目录侧）</strong></p>'
        + '<p class="small">Catalog 已确认审批通过且令牌有效。是否已配置到 Runtime 由 Catalog 无法观测。</p>'
        + '<p class="small">商家令牌仅登录后向本人显示，请妥善保管。</p>'
        + '<div class="token-box">' + esc(r.token.token) + '</div>'
        + '<div style="margin-top:12px;border-left:3px solid var(--kiwi-600);padding-left:10px">'
        + '<p class="small"><strong>下一步：把令牌填进你的 Kiwi Merchant</strong></p>'
        + '<p class="small">① 自建实例：终端运行 <code>kiwi merchant init</code>，在第 4 个提示「商家令牌」处粘贴；'
        + '或把下面这行写进 <code>~/.kiwi/credentials.env</code>（权限 0600）'
        + ' <button type="button" class="btn-mini" id="copy_env_line">复制这一行</button><br>'
        + '<code>KIWI_MERCHANT_TOKEN=&lt;你的令牌&gt;</code></p>'
        + '<p class="small">② 填好后 <code>kiwi merchant publish</code>、<code>kiwi agent serve</code> '
        + '等命令会自动读取（shopping-cli 不需要配这个令牌）。</p>'
        + '<p class="small">③ WorkBuddy 云端应用：填入口在接入向导里。只是发布公开资料，现在不需要令牌。</p>'
        + '</div>';
      copyBtn.disabled = false;
      const copyEnv = document.getElementById('copy_env_line');
      if (copyEnv) copyEnv.addEventListener('click', () => {
        const box = document.querySelector('#token_box .token-box');
        if (box && navigator.clipboard) navigator.clipboard.writeText('KIWI_MERCHANT_TOKEN=' + (box.textContent || '').trim());
      });
      applyBtn.disabled = true;  // 有令牌：申请按钮变灰
    } else if (r.application && r.application.status === 'pending') {
      tb.innerHTML = '<p class="ok"><strong>审核中</strong>：目录令牌申请正在审核。</p>';
      copyBtn.disabled = true;
      applyBtn.disabled = true;
    } else if (r.application && r.application.status === 'rejected') {
      tb.innerHTML = '<p class="err"><strong>未申请</strong>。上次申请未通过'
        + (r.application.review_note ? '：' + esc(r.application.review_note) : '')
        + '。可点击「重新申请」再次提交（原工单保留为记录）。</p>';
      copyBtn.disabled = true;
      applyBtn.disabled = false;
      applyBtn.textContent = '重新申请';
    } else {
      tb.innerHTML = r.application && r.application.status === 'approved'
        ? '<p class="ok"><strong>待配置</strong>：申请已通过，请在 Runtime 的安全配置中设置目录令牌。Catalog 无法确认本地配置状态。</p>'
        : '<p class="small muted"><strong>未申请</strong>：目录商品 listings 需要审批通过的目录令牌。名片绑定与发布不受此审批影响。</p>';
      copyBtn.disabled = true;
      applyBtn.disabled = false;
    }
  });
}
document.getElementById('copy_token').addEventListener('click', () => {
  const box = document.querySelector('#token_box .token-box');
  if (box && navigator.clipboard) navigator.clipboard.writeText((box.textContent || '').trim());
});
// 申请已零输入（D7）——点击只建 pending 工单；被拒后同一按钮即「重新申请」
document.getElementById('apply_token').addEventListener('click', () => {
  const btn = document.getElementById('apply_token');
  btn.disabled = true;
  postJson('/v1/accounts/token-request', {}).then(r => {
    if (r.ok) { loadMe(); } else {
      const out = document.getElementById('out');
      out.className = 'err';
      out.textContent = r.error || '申请失败';
      btn.disabled = false;
    }
  });
});
// 退出登录已移至二级导航（nav_logout，见 _PORTAL_JS 共享 handler）
loadMe();
</script>
"""
        + _FOOTER
    )
    # 二级导航高亮（申请令牌 = 本页）
    body = (
        body.replace("{sub_apply}", ' class="active"')
        .replace("{sub_profile}", "")
        .replace("{sub_card}", "")
    )
    return _account_page("商家后台", body)


def portal_account_profile() -> dict[str, Any]:
    """「基本信息」二级页：商家名称 / 电话，可编辑。"""
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">商家后台</div>
  <h2>商家后台</h2>
  <div class="subnav">
    <a href="/portal/account/profile"{sub_profile}>基本信息</a>
    <a href="/portal/account"{sub_apply}>令牌信息</a>
    <a href="/portal/account/card"{sub_card}>我的名片</a>
    <a href="/portal/publications">公开资料</a>
    <a href="/portal/follows">我的关注</a>
    <a href="#" id="nav_logout" style="margin-left:auto">退出登录</a>
  </div>
  <div id="out"></div>
  <div class="card form-card">
    <h3>账户基本信息</h3>
    <label for="p_email">邮箱（登录账号，不可修改）</label>
    <input id="p_email" disabled>
    <label for="p_name">商家名称</label>
    <input id="p_name">
    <label for="p_phone">电话（选填）</label>
    <input id="p_phone">
    <label for="p_wechat">微信（选填）</label>
    <input id="p_wechat">
    <button class="btn-form" id="save_profile">保存基本信息</button>
    <div id="out_profile"></div>
  </div>
</div></section>
<script>
fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
  if (!r.ok) { window.location.href = '/portal/login'; return; }
  document.getElementById('p_email').value = r.email;
  document.getElementById('p_name').value = r.merchant_name || '';
  document.getElementById('p_phone').value = r.phone || '';
  document.getElementById('p_wechat').value = r.wechat || '';
});
document.getElementById('save_profile').addEventListener('click', () => {
  const btn = document.getElementById('save_profile');
  btn.disabled = true;
  postJson('/v1/accounts/profile', {
    merchant_name: document.getElementById('p_name').value.trim(),
    phone: document.getElementById('p_phone').value.trim(),
    wechat: document.getElementById('p_wechat').value.trim(),
  }).then(r => {
    const out = document.getElementById('out_profile');
    if (r.ok) { out.className = 'ok'; out.textContent = '已保存。'; }
    else { out.className = 'err'; out.textContent = r.error || '保存失败'; }
    btn.disabled = false;
  });
});
</script>
"""
        + _FOOTER
    )
    body = (
        body.replace("{sub_apply}", "")
        .replace("{sub_profile}", ' class="active"')
        .replace("{sub_card}", "")
    )
    return _account_page("基本信息", body)


def portal_account_card() -> dict[str, Any]:
    """「我的名片」只读页（设计 §9）。

    页面保留治理动作；首次接入授权统一走 portal_connect 的预览确认页，
    不在名片页重复确认技术绑定。
    门户不产出内容：页面没有任何「编辑/生成名片」按钮；「未创建接入记录」
    空态提供「创建接入记录」按钮（POST /v1/accounts/agents，一商家一条、
    幂等）。
    """
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">商家后台</div>
  <h2>我的名片</h2>
  <div class="subnav">
    <a href="/portal/account/profile">基本信息</a>
    <a href="/portal/account">令牌信息</a>
    <a href="/portal/account/card" class="active">我的名片</a>
    <a href="/portal/publications">公开资料</a>
    <a href="/portal/follows">我的关注</a>
    <a href="#" id="nav_logout" style="margin-left:auto">退出登录</a>
  </div>
  <p class="lead">名片是你的 Agent 在目录里的公开身份页：由你的运行时签名发布、
    Catalog 托管在稳定读地址上。本页只读展示——名片内容只能由运行时发布。</p>
  <div id="out"></div>
  <div id="content" style="display:none">
    <div class="card form-card" id="create_card" style="display:none">
      <h3>还没有接入记录</h3>
      <p class="small">接入记录是你的 Agent 在目录里的身份条目（一个商家一条）。
        创建后可在一键上云向导里完成运行时绑定与名片发布。</p>
      <button class="btn-form" id="create_agent">创建接入记录</button>
      <p class="small muted">没有运行时？也可以先到<a href="/portal/publications">公开资料</a>
        发布商品资料，买家同样能在目录里搜到你。</p>
    </div>
    <div class="card form-card" id="pending_card">
      <h3>接入方式</h3>
      <p class="small">WorkBuddy 与独立 Kiwi Merchant Runtime 共用同一公开预览和一次业务确认流程。</p>
      <p class="small">买家 Agent 会直接连接你的商家服务。请确保服务有可从互联网访问的 HTTPS 地址，并保持在线。我们会在绑定时自动检查。</p>
      <p class="small muted">从 Runtime 发起接入后，打开其 Catalog 授权页并核对配对码，再确认公开资料并发布。</p>
    </div>
    <div class="card form-card" id="status_card">
      <h3>名片状态</h3>
      <div id="status_body"></div>
    </div>
    <div class="card form-card" id="binding_card">
      <h3>运行时绑定</h3>
      <div id="binding_body"></div>
    </div>
    <div class="card form-card" id="content_card">
      <h3>名片内容（公开字段）</h3>
      <div id="card_body"></div>
    </div>
  </div>
</div></section>
<script>
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
// 命名避开 _PORTAL_JS 的 getJson(url, token)（它在 body 末尾会重新定义全局 getJson）
function getSessionJson(url) { return fetch(url, {method: 'GET', credentials: 'same-origin'}).then(r => r.json()); }
// 当前商家的接入记录 id（一商家一条；治理动作的目标）
let currentAgentId = '';
function renderStatus(d) {
  const body = document.getElementById('status_body');
  const pub = d.publication || {state: 'none'};
  if (pub.state === 'none') {
    body.innerHTML = (d.binding
      ? '<p class="small muted">已绑定运行时，还没有发布的名片——名片由你的运行时签名发布后显示在这里。</p>'
      : '<p class="small muted">还没有发布的名片。</p>')
      + '<p class="small">预留稳定读地址（名片发布后才有内容，现在读取会 404）：</p>'
      + '<div class="token-box">' + esc(d.card_url) + '</div>';
    return;
  }
  const label = {ACTIVE: '已发布 ACTIVE', PAUSED: '已暂停 PAUSED', WITHDRAWN: '已撤回 WITHDRAWN'}[pub.state] || pub.state;
  body.innerHTML = '<p><strong>' + esc(label) + '</strong> 版本 r' + esc(pub.active_revision)
    + (pub.digest ? ' · digest ' + esc(pub.digest.slice(0, 16)) + '…' : '')
    + (pub.updated_at ? ' · 更新 ' + esc(pub.updated_at.slice(0, 10)) : '') + '</p>'
    + '<p class="small">稳定读地址' + (pub.state === 'WITHDRAWN' ? '（已撤回，读取返回 410）' : '') + '</p>'
    + '<div class="token-box" id="card_url_box">' + esc(d.card_url) + '</div>'
    + '<div class="token-actions"><button type="button" class="btn-mini" id="copy_card_url">复制地址</button>'
    + '<a class="btn-mini" href="' + esc(d.card_url) + '" target="_blank" rel="noopener">查看原始 JSON</a></div>'
    + '<div class="token-actions" id="card_governance"></div>';
  // 守卫式绑定：该按钮只存在于上面这段 innerHTML 里
  const copyBtn = document.getElementById('copy_card_url');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const box = document.getElementById('card_url_box');
      if (box && navigator.clipboard) { navigator.clipboard.writeText((box.textContent || '').trim()); }
    });
  }
  renderGovernance(pub);
}
// ── 治理动作（P1；设计 §5.1/§5.3）：只切状态，不产出内容 ─────────────────
// ACTIVE → [暂停] [撤回]；PAUSED → [恢复] [撤回]；WITHDRAWN → 只有说明
function renderGovernance(pub) {
  const box = document.getElementById('card_governance');
  if (!box) { return; }
  const rev = pub.active_revision;
  const btn = (id, label) => '<button type="button" class="btn-mini" id="' + id + '">' + label + '</button>';
  if (pub.state === 'ACTIVE') {
    box.innerHTML = btn('gov_pause', '暂停') + btn('gov_withdraw', '撤回')
      + '<p class="small muted">暂停：公开信息保留、停止接待；撤回：稳定地址变 410。</p>';
    bindGov('gov_pause', 'pause', rev, '');
    bindGov('gov_withdraw', 'withdraw', rev,
      '撤回后稳定读地址立即返回 410，买家将无法再读到名片（重新上线需要运行时重新发布并激活）。确认撤回？');
  } else if (pub.state === 'PAUSED') {
    box.innerHTML = btn('gov_resume', '恢复') + btn('gov_withdraw', '撤回')
      + '<p class="small muted">恢复：回到已发布 ACTIVE；撤回：稳定地址变 410。</p>';
    bindGov('gov_resume', 'resume', rev, '');
    bindGov('gov_withdraw', 'withdraw', rev,
      '撤回后稳定读地址立即返回 410，买家将无法再读到名片（重新上线需要运行时重新发布并激活）。确认撤回？');
  } else if (pub.state === 'WITHDRAWN') {
    box.innerHTML = '<p class="small muted">名片已撤回——稳定读地址返回 410。'
      + '重新上线需要你的运行时重新发布并激活名片。</p>';
  }
}
function bindGov(id, action, rev, confirmText) {
  const el = document.getElementById(id);
  if (!el) { return; }
  el.addEventListener('click', () => {
    if (confirmText && !window.confirm(confirmText)) { return; }
    el.disabled = true;
    postJson('/v1/accounts/agents/' + encodeURIComponent(currentAgentId) + '/card/' + action,
      {expected_revision: rev}).then(r => {
      const out = document.getElementById('out');
      if (r.ok) {
        out.className = 'ok';
        out.textContent = '已' + ({pause: '暂停', resume: '恢复', withdraw: '撤回'})[action] + '。';
        loadCardPage();
      } else {
        out.className = 'err';
        out.textContent = r.error || '操作失败';
        el.disabled = false;
      }
    });
  });
}
function renderBinding(d) {
  const body = document.getElementById('binding_body');
  const b = d.binding;
  if (!b) {
    body.innerHTML = '<p class="small muted">未绑定运行时——在一键上云向导里完成绑定与确认后，'
      + '运行时地址与绑定版本会显示在这里。</p>'
      + '<p class="small muted">没有运行时？也可以先到<a href="/portal/publications">公开资料</a>'
      + '发布商品资料，买家同样能在目录里搜到你。</p>';
    return;
  }
  body.innerHTML = '<table class="kv">'
    + '<tr><td>运行时地址</td><td class="mono">' + esc(b.runtime_origin) + '</td></tr>'
    + '<tr><td>A2A 端点</td><td class="mono">' + esc(b.a2a_endpoint) + '</td></tr>'
    + '<tr><td>绑定版本</td><td>' + esc(b.binding_version) + '</td></tr>'
    + '<tr><td>状态</td><td>' + esc(b.status) + '</td></tr></table>';
}
function renderCardContent(d) {
  const body = document.getElementById('card_body');
  const card = d.card;
  if (!card) {
    body.innerHTML = '<p class="small muted">还没有名片内容——发布后这里显示与公开读地址一致的公开字段。</p>';
    return;
  }
  body.innerHTML = '<table class="kv">'
    + '<tr><td>name</td><td>' + esc(card.name) + '</td></tr>'
    + '<tr><td>description</td><td>' + esc(card.description) + '</td></tr>'
    + '<tr><td>url</td><td class="mono">' + esc(card.url) + '</td></tr>'
    + '<tr><td>supportedInterfaces</td><td><code>' + esc(JSON.stringify(card.supportedInterfaces)) + '</code></td></tr>'
    + '<tr><td>skills</td><td><code>' + esc(JSON.stringify(card.skills)) + '</code></td></tr></table>'
    + '<p class="small muted">这些字段与公开读地址一致，任何人都能看到。</p>';
}
function renderEmptyStates() {
  // 未创建接入记录：创建卡片 + 其余三块诚实空态
  document.getElementById('create_card').style.display = 'block';
  document.getElementById('status_body').innerHTML =
    '<p class="small muted">未创建接入记录——创建后这里会显示名片发布状态与稳定读地址。</p>';
  document.getElementById('binding_body').innerHTML =
    '<p class="small muted">未绑定运行时。</p>';
  document.getElementById('card_body').innerHTML =
    '<p class="small muted">还没有名片内容。</p>';
}
function loadCardPage() {
  fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(me => {
    if (!me.ok) {
      // 未登录：直接进入登录流程（登录页含注册入口）
      window.location.href = '/portal/login';
      return;
    }
    document.getElementById('content').style.display = 'block';
    getSessionJson('/v1/accounts/agents').then(r => {
      const out = document.getElementById('out');
      if (!r.ok) { out.className = 'err'; out.textContent = r.error || '加载失败'; return; }
      if (!r.results || !r.results.length) { renderEmptyStates(); return; }
      document.getElementById('create_card').style.display = 'none';
      const agent = r.results[0];
      currentAgentId = agent.catalog_agent_id;
      getSessionJson('/v1/accounts/agents/' + encodeURIComponent(agent.catalog_agent_id) + '/card').then(d => {
        if (!d.ok) { out.className = 'err'; out.textContent = d.error || '加载失败'; return; }
        renderStatus(d);
        renderBinding(d);
        renderCardContent(d);
      });
    });
  });
}
// 「未创建接入记录」空态的唯一动作：创建（幂等，重复点击返回同一条）
document.getElementById('create_agent').addEventListener('click', () => {
  const btn = document.getElementById('create_agent');
  btn.disabled = true;
  postJson('/v1/accounts/agents', {}).then(r => {
    if (r.ok) { loadCardPage(); } else {
      const out = document.getElementById('out');
      out.className = 'err';
      out.textContent = r.error || '创建失败';
      btn.disabled = false;
    }
  });
});
loadCardPage();
</script>
"""
        + _FOOTER
    )
    return _account_page("我的名片", body)


def portal_enrollment_connect(enrollment_id: str) -> dict[str, Any]:
    """统一 WorkBuddy / 独立 Runtime 的公开预览和一次业务确认页。

    GET 页面本身不批准任何请求。冻结预览由登录态 API 读取；用户需登录、
    核对来自 Runtime 的短配对码和公开内容，再显式点击一次授权发布。
    """
    enrollment_json = json.dumps(str(enrollment_id)).replace("<", "\\u003c")
    body = (
        _nav("account")
        + """
<section class="section"><div class="section-inner">
  <div class="kicker">Kiwi 商家接入</div>
  <h2>连接此服务并发布</h2>
  <p class="lead">请确认这是你刚才从商家 Runtime 发起的连接，并核对公开名片。确认后系统会自动完成绑定与发布，不会再要求你确认技术细节。</p>
  <div class="card form-card" style="max-width:720px">
    <div id="connect_state"><p class="small muted">正在读取本次接入请求…</p></div>
    <div id="connect_preview" style="display:none">
      <p><strong>商家</strong> <span id="connect_merchant"></span></p>
      <p><strong>配对码</strong> <span class="token-box" id="connect_code"></span></p>
      <p class="small">请将此配对码与刚才运行 Runtime 的终端显示内容核对。配对码只用于识别请求，不能取回授权或令牌。</p>
      <p><strong>服务地址</strong> <span class="mono" id="connect_origin"></span></p>
      <p><strong>请求时间</strong> <span id="connect_requested"></span></p>
      <h3 style="margin-top:18px">将公开的资料</h3>
      <div id="connect_card"></div>
      <p class="small" style="margin-top:14px">采购方可发现并向本店发送询价；仅按已设置规则报价。</p>
      <button class="btn-form" id="connect_authorize" disabled>连接此服务并发布</button>
      <p class="small muted">此确认同时授权当前 Runtime 绑定及上方公开资料，不包含商品 listings 发布审批。</p>
    </div>
  </div>
  <div class="notice"><strong>公网 HTTPS 要求</strong><br>买家 Agent 会直接连接你的商家服务。请确保服务有可从互联网访问的 HTTPS 地址，并保持在线。我们会在绑定时自动检查。</div>
</div></section>
<script>
const enrollmentId = __ENROLLMENT_ID__;
const state = document.getElementById('connect_state');
function connectMessage(text, kind) { state.className = kind || ''; state.textContent = text; }
function showConnectError() { connectMessage('无法读取这次接入请求。请从 Runtime 重新打开授权页，或稍后重试。', 'err'); }
function renderPreview(d) {
  if (!d || !d.ok) { showConnectError(); return; }
  if (['authorized', 'AUTHORIZED', 'verifying', 'VERIFYING', 'bound', 'BOUND'].includes(d.status)) {
    connectMessage('已确认，Runtime 正在自动检查服务并完成绑定。请返回 Runtime 查看实际进度。', 'ok'); return;
  }
  if (['published', 'PUBLISHED'].includes(d.status)) {
    connectMessage('服务已上线。买家可按已公开能力向本店发送询价。', 'ok'); return;
  }
  if (!['ready_for_authorization', 'READY_FOR_AUTHORIZATION', 'pending'].includes(d.status)) {
    connectMessage('此接入请求已结束或已过期，请从 Runtime 重新发起。', 'err'); return;
  }
  const origin = String(d.runtime_origin || '');
  let url;
  try { url = new URL(origin); } catch (_) { url = null; }
  const host = url ? url.hostname.toLowerCase() : '';
  const ipv4 = host.split('.').map(Number);
  const privateIPv4 = ipv4.length === 4 && (ipv4[0] === 10 || ipv4[0] === 127
    || (ipv4[0] === 192 && ipv4[1] === 168)
    || (ipv4[0] === 172 && ipv4[1] >= 16 && ipv4[1] <= 31));
  if (!url || url.protocol !== 'https:' || host === 'localhost' || host === '::1'
      || host.endsWith('.localhost') || privateIPv4) {
    connectMessage('你的商家服务还没有可用的公网 HTTPS 地址，买家 Agent 暂时无法连接并询价。请先配置公网 HTTPS 入口，或使用 WorkBuddy 云端应用。配置完成后重新检查，已有资料会保留。', 'err');
    const retry = document.createElement('button'); retry.className = 'btn-mini'; retry.textContent = '重新检查';
    retry.addEventListener('click', loadEnrollment); state.appendChild(retry);
    const later = document.createElement('a'); later.className = 'btn-mini'; later.href = '/portal/account/card'; later.textContent = '稍后继续'; state.appendChild(later);
    return;
  }
  document.getElementById('connect_state').textContent = '';
  document.getElementById('connect_preview').style.display = 'block';
  document.getElementById('connect_merchant').textContent = d.merchant_name || '当前商家';
  document.getElementById('connect_code').textContent = d.user_code || '';
  document.getElementById('connect_origin').textContent = origin;
  document.getElementById('connect_requested').textContent = d.requested_at || '刚刚';
  const card = d.public_preview || {};
  const rows = [['商家名称', card.name || d.merchant_name], ['简介', card.description], ['公开服务能力', Array.isArray(card.skills) ? card.skills.map(x => x.name || x.id || '').filter(Boolean).join('、') : '']];
  document.getElementById('connect_card').innerHTML = '<table>' + rows.map(row => '<tr><th>' + escHtml(row[0]) + '</th><td>' + escHtml(row[1] || '未提供') + '</td></tr>').join('') + '</table>'
    + '<details style="margin-top:12px"><summary>查看完整公开资料</summary><pre>' + escHtml(JSON.stringify(card, null, 2)) + '</pre></details>';
  document.getElementById('connect_authorize').disabled = !d.user_code;
}
function loadEnrollment() {
  state.className = 'small muted'; state.textContent = '正在读取本次接入请求…';
  fetch('/v1/accounts/enrollments/' + encodeURIComponent(enrollmentId), {credentials: 'same-origin'}).then(async response => ({
    status: response.status, data: await response.json()
  })).then(({status, data}) => {
    if (status === 401 || status === 403) {
      window.location.href = '/portal/login?next=' + encodeURIComponent('/portal/connect/' + enrollmentId); return;
    }
    renderPreview(data);
  }).catch(showConnectError);
}
document.getElementById('connect_authorize').addEventListener('click', e => {
  const btn = e.currentTarget; btn.disabled = true;
  const code = document.getElementById('connect_code').textContent;
  fetch('/v1/accounts/enrollments/' + encodeURIComponent(enrollmentId) + '/authorize', {
    method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_code: code})
  }).then(r => r.json()).then(d => {
    if (d.ok) { document.getElementById('connect_preview').style.display = 'none'; connectMessage('已确认。正在由 Runtime 自动完成绑定和发布，请返回 Runtime 查看进度。', 'ok'); }
    else { connectMessage('确认未完成。请重新打开授权页检查请求状态。', 'err'); btn.disabled = false; }
  }).catch(() => { connectMessage('确认未完成。请重新打开授权页检查请求状态。', 'err'); btn.disabled = false; });
});
loadEnrollment();
</script>
""".replace("__ENROLLMENT_ID__", enrollment_json)
        + _FOOTER
    )
    return _page("连接此服务并发布", body)


def portal_publications() -> dict[str, Any]:
    """「公开资料」页（M0）：编辑 → 预览 → 保存草稿 / 确认发布 → 发布回执。

    未登录引导去 /portal/login（页面 JS 检查 /v1/accounts/me，与「我的」同
    模式）。发布回执显示 publication_id、版本、发布时间；已发布资料可撤回。
    公开资料是商家声明快照（source_kind=merchant_declared），不产生 Agent
    Card / A2A 端点 / 实时报价标记；注册账户的电话/邮箱不进入公开字段
    （服务端私密字段扫描 fail-closed）。
    """
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">商家后台</div>
  <h2>公开资料</h2>
  <div class="subnav">
    <a href="/portal/account/profile">基本信息</a>
    <a href="/portal/account">令牌信息</a>
    <a href="/portal/account/card">我的名片</a>
    <a href="/portal/publications" class="active">公开资料</a>
    <a href="/portal/follows">我的关注</a>
    <a href="#" id="nav_logout" style="margin-left:auto">退出登录</a>
  </div>
  <p class="lead">发布商家及商品基本资料后，买家可按商品词在 Kiwi 目录搜索到你。
    公开资料是你的声明快照（仅展示，不含实时报价/库存）；请勿填写电话、邮箱等联系方式——
    含联系方式的内容会被拒绝。</p>
  <div id="out"></div>
  <div class="card form-card" id="stats_card" style="display:none">
    <h3>关注与浏览（匿名汇总）</h3>
    <div id="stats_body"></div>
  </div>
  <div id="editor" style="display:none">
    <div class="card form-card">
      <label for="m_name">公开商家名称 <span class="req">*</span></label>
      <input id="m_name" placeholder="Acme 商贸">
      <label for="m_title">商品名 <span class="req">*</span></label>
      <input id="m_title" placeholder="如：明前龙井 2026 新茶">
      <label for="m_category">类目（选填）</label>
      <input id="m_category" placeholder="如：茶叶">
      <label for="m_platform">店铺平台（选填，如 淘宝 / 京东）</label>
      <input id="m_platform" placeholder="淘宝">
      <label for="m_url">公开店铺链接（选填，http/https）</label>
      <input id="m_url" placeholder="https://shop.example.com">
      <label for="m_summary">简介（选填，公开可见）</label>
      <textarea id="m_summary" rows="4" placeholder="商品基本说明，公开可见"></textarea>
      <label for="m_faq">FAQ（选填，每行一条：问题|答案）</label>
      <textarea id="m_faq" rows="4" placeholder="保修多久？|整机保修一年"></textarea>
      <label for="m_expires">资料有效期（选填，到期后不再出现在搜索中）</label>
      <input id="m_expires" type="datetime-local">
      <div class="token-actions">
        <button class="btn-mini" id="preview">预览</button>
        <button class="btn-mini" id="save_draft">保存草稿</button>
        <button class="btn-mini" id="publish">确认发布</button>
      </div>
    </div>
    <div class="card form-card" id="preview_card" style="display:none">
      <h3>公开预览（买家可见内容）</h3>
      <div id="preview_body"></div>
    </div>
    <div class="card form-card" id="receipt_card" style="display:none">
      <h3 id="receipt_title">发布成功</h3>
      <div id="receipt_body"></div>
      <div class="token-actions">
        <button class="btn-mini" id="withdraw" style="display:none">撤回该资料</button>
      </div>
    </div>
  </div>
</div></section>
<script>
let currentPublicationId = '';
function formPayload(action) {
  const faq = [];
  document.getElementById('m_faq').value.split('\\n').forEach(line => {
    const idx = line.indexOf('|');
    if (idx > 0) faq.push({question: line.slice(0, idx).trim(), answer: line.slice(idx + 1).trim()});
  });
  const expires = document.getElementById('m_expires').value;
  return {
    action: action,
    merchant_display_name: document.getElementById('m_name').value.trim(),
    title: document.getElementById('m_title').value.trim(),
    category: document.getElementById('m_category').value.trim(),
    shop_platform: document.getElementById('m_platform').value.trim(),
    shop_url: document.getElementById('m_url').value.trim(),
    summary: document.getElementById('m_summary').value.trim(),
    faq: faq,
    expires_at: expires ? new Date(expires).toISOString() : '',
  };
}
function showErr(msg) {
  const out = document.getElementById('out');
  out.className = 'err';
  out.textContent = msg;
}
document.getElementById('preview').addEventListener('click', () => {
  const p = formPayload('draft');
  let html = '<p><strong>' + escHtml(p.merchant_display_name) + '</strong> · ' + escHtml(p.title) + '</p>';
  if (p.category) html += '<p class="small">类目：' + escHtml(p.category) + '</p>';
  if (p.shop_platform || p.shop_url) html += '<p class="small">店铺：' + escHtml(p.shop_platform) + ' ' + escHtml(p.shop_url) + '</p>';
  if (p.summary) html += '<p>' + escHtml(p.summary) + '</p>';
  p.faq.forEach(item => { html += '<p class="small">Q：' + escHtml(item.question) + '<br>A：' + escHtml(item.answer) + '</p>'; });
  html += '<p class="small muted">来源：商家声明（merchant_declared）· 不可实时询价</p>';
  document.getElementById('preview_body').innerHTML = html;
  document.getElementById('preview_card').style.display = 'block';
});
function submitPublication(action) {
  const btn = document.getElementById(action === 'publish' ? 'publish' : 'save_draft');
  btn.disabled = true;
  postJson('/v1/merchant-publications', formPayload(action)).then(r => {
    btn.disabled = false;
    if (!r.ok) { showErr(r.error || '提交失败'); return; }
    const pub = r.publication || {};
    currentPublicationId = pub.publication_id || '';
    const published = pub.status === 'published';
    document.getElementById('receipt_title').textContent = published ? '发布成功' : '草稿已保存';
    let html = '<p class="small">资料编号（publication_id）</p>'
      + '<div class="token-box">' + escHtml(pub.publication_id) + '</div>'
      + '<p class="small">状态 ' + escHtml(pub.status) + ' · 版本 v' + escHtml(pub.version)
      + (pub.published_at ? ' · 发布时间 ' + escHtml(pub.published_at) : '') + '</p>';
    if (r.message) html += '<p class="small muted">' + escHtml(r.message) + '</p>';
    if (published) html += '<p class="ok">买家现在可以按商品词在 Kiwi 目录搜索到该资料（仅展示，不可实时询价）。</p>';
    document.getElementById('receipt_body').innerHTML = html;
    document.getElementById('withdraw').style.display = published ? 'inline-block' : 'none';
    document.getElementById('receipt_card').style.display = 'block';
  });
}
document.getElementById('save_draft').addEventListener('click', () => submitPublication('draft'));
document.getElementById('publish').addEventListener('click', () => submitPublication('publish'));
document.getElementById('withdraw').addEventListener('click', () => {
  const btn = document.getElementById('withdraw');
  btn.disabled = true;
  postJson('/v1/merchant-publications/' + encodeURIComponent(currentPublicationId) + '/withdraw', {}).then(r => {
    btn.disabled = false;
    if (!r.ok) { showErr(r.error || '撤回失败'); return; }
    document.getElementById('receipt_title').textContent = '已撤回';
    document.getElementById('receipt_body').innerHTML = '<p class="small">资料已撤回，不再出现在买家搜索中。</p>';
    btn.style.display = 'none';
  });
});
fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
  if (!r.ok) { window.location.href = '/portal/login'; return; }
  document.getElementById('m_name').value = r.merchant_name || '';
  document.getElementById('editor').style.display = 'block';
  // 匿名汇总（M4）：只有关注者总数与浏览计数——商家拿不到任何买家身份
  fetch('/v1/merchant-publications/stats', {method: 'GET', credentials: 'same-origin'}).then(s => s.json()).then(s => {
    if (!s.ok) return;
    const st = s.stats || {};
    let html = '<p>关注本商家的买家：<strong>' + escHtml(st.followers_total) + '</strong>'
      + ' · 公开资料累计浏览：<strong>' + escHtml(st.views_total) + '</strong></p>'
      + '<p class="small muted">汇总为匿名数字——你无法看到具体是哪些买家，也不能向他们发消息。</p>';
    (st.publications || []).forEach(p => {
      html += '<p class="small">' + escHtml(p.title) + '（' + escHtml(p.status) + '）：浏览 ' + escHtml(p.view_count) + ' 次</p>';
    });
    document.getElementById('stats_body').innerHTML = html;
    document.getElementById('stats_card').style.display = 'block';
  });
});
</script>
"""
        + _FOOTER
    )
    return _account_page("公开资料", body)


def portal_follows() -> dict[str, Any]:
    """「我的关注」页（M4 拉取式订阅，买家视角）。

    任何已登录账号都可以作为买家关注商家：列表 + 按商家 ID 关注 + 取消 +
    主动拉取更新（无推送通道——只有买家主动点「查看更新」才拉取）。未登录
    引导去 /portal/login（页面 JS 检查 /v1/accounts/me，与「我的」同模式）。
    """
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">商家后台</div>
  <h2>我的关注</h2>
  <div class="subnav">
    <a href="/portal/account/profile">基本信息</a>
    <a href="/portal/account">令牌信息</a>
    <a href="/portal/account/card">我的名片</a>
    <a href="/portal/publications">公开资料</a>
    <a href="/portal/follows" class="active">我的关注</a>
    <a href="#" id="nav_logout" style="margin-left:auto">退出登录</a>
  </div>
  <p class="lead">关注是显式订阅：只有你主动关注商家后，才能在这里拉取它的公开更新
    （新品、资料更新、撤回等）；搜索、浏览、询价都不会产生订阅。商家只能看到匿名关注数，
    看不到你是谁，也不能给你发消息。</p>
  <div id="out"></div>
  <div id="content" style="display:none">
    <div class="card form-card">
      <h3>关注商家</h3>
      <label for="f_merchant">商家 ID（merchant_id，从搜索结果或商家资料中获得）</label>
      <input id="f_merchant" placeholder="mkt_...">
      <label for="f_category">关注范围（选填，只接收该类目的更新）</label>
      <input id="f_category" placeholder="留空 = 全部公开更新">
      <button class="btn-form" id="follow">关注</button>
    </div>
    <div class="card form-card">
      <h3>已关注的商家</h3>
      <div id="follows_body"></div>
      <button class="btn-mini" id="check_updates">查看更新</button>
      <div id="updates_body"></div>
    </div>
  </div>
</div></section>
<script>
function showErr(msg) {
  const out = document.getElementById('out');
  out.className = 'err';
  out.textContent = msg;
}
function loadFollows() {
  fetch('/v1/me/follows', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
    if (!r.ok) { showErr(r.error || '加载失败'); return; }
    const box = document.getElementById('follows_body');
    const follows = r.follows || [];
    if (!follows.length) { box.innerHTML = '<p class="small muted">还没有关注任何商家。</p>'; return; }
    let html = '';
    follows.forEach(f => {
      html += '<p><strong>' + escHtml(f.merchant_name || f.merchant_id) + '</strong>'
        + ' <span class="small mono">' + escHtml(f.merchant_id) + '</span>'
        + (f.category ? ' <span class="small">范围：' + escHtml(f.category) + '</span>' : ' <span class="small">范围：全部公开更新</span>')
        + ' <button class="btn-mini" data-unfollow="' + escHtml(f.merchant_id) + '">取消关注</button></p>';
    });
    box.innerHTML = html;
    box.querySelectorAll('button[data-unfollow]').forEach(btn => {
      btn.addEventListener('click', () => {
        btn.disabled = true;
        fetch('/v1/me/follows/' + encodeURIComponent(btn.getAttribute('data-unfollow')), {
          method: 'DELETE', credentials: 'same-origin',
        }).then(r => r.json()).then(r => {
          if (!r.ok) { showErr(r.error || '取消失败'); btn.disabled = false; return; }
          loadFollows();
        });
      });
    });
  });
}
document.getElementById('follow').addEventListener('click', () => {
  const btn = document.getElementById('follow');
  btn.disabled = true;
  const merchantId = document.getElementById('f_merchant').value.trim();
  fetch('/v1/me/follows/' + encodeURIComponent(merchantId), {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    credentials: 'same-origin',
    body: JSON.stringify({category: document.getElementById('f_category').value.trim()}),
  }).then(r => r.json()).then(r => {
    btn.disabled = false;
    if (!r.ok) { showErr(r.error || '关注失败'); return; }
    document.getElementById('f_merchant').value = '';
    loadFollows();
  });
});
document.getElementById('check_updates').addEventListener('click', () => {
  const btn = document.getElementById('check_updates');
  btn.disabled = true;
  fetch('/v1/me/follows/updates', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
    btn.disabled = false;
    if (!r.ok) { showErr(r.error || '拉取失败'); return; }
    const box = document.getElementById('updates_body');
    const updates = r.updates || [];
    if (!updates.length) { box.innerHTML = '<p class="small muted">暂无新更新。</p>'; return; }
    let html = '';
    updates.forEach(u => {
      html += '<p><strong>' + escHtml(u.merchant_name || u.merchant_id) + '</strong></p>';
      (u.events || []).forEach(e => {
        const p = e.payload || {};
        html += '<p class="small">· ' + escHtml(e.event_type) + '：' + escHtml(p.title || '')
          + ' <span class="muted">' + escHtml((e.created_at || '').slice(0, 19)) + '</span></p>';
      });
    });
    box.innerHTML = html;
  });
});
fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
  if (!r.ok) { window.location.href = '/portal/login'; return; }
  document.getElementById('content').style.display = 'block';
  loadFollows();
});
</script>
"""
        + _FOOTER
    )
    return _account_page("我的关注", body)


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
