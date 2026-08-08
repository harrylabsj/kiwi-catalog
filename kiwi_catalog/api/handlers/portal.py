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

fallback 栈渲染的轻量 HTML（内联 CSS/JS，零新依赖）：申请表单 / 审核后台 /
商家自查 / 门户首页。页面只做表单与 fetch 调用——动态数据全部走 JSON API
（/v1/merchants/*），页面本身无逻辑可被注入。

响应体约定：``{"__html__": "..."}`` 标记，fallback_asgi._send_json 检测该
键改发 text/html（ETag/304 语义不变）。明文 token 只在审核后台批准/轮换的
响应里出现一次，页面 JS 展示后不缓存（响应头 no-store 由 _send_json 加）。
"""

from __future__ import annotations

from typing import Any

_PAGE_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f6f7f9;color:#1a2332;line-height:1.6}
.wrap{max-width:760px;margin:0 auto;padding:32px 20px}
h1{font-size:26px;margin-bottom:8px}
h2{font-size:18px;margin:28px 0 12px}
p{color:#3d4a5c;margin-bottom:12px}
.card{background:#fff;border:1px solid #e3e7ee;border-radius:10px;padding:24px;margin-bottom:20px}
label{display:block;font-size:14px;font-weight:600;margin:14px 0 6px}
input,textarea,select{width:100%;padding:10px 12px;border:1px solid #c9d1dc;border-radius:8px;font-size:14px;font-family:inherit}
button{margin-top:18px;padding:11px 20px;background:#1a6cff;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
button.ghost{background:#eef1f6;color:#1a2332;margin-left:8px}
button:disabled{opacity:.5;cursor:not-allowed}
.note{background:#f0f5ff;border-left:4px solid #1a6cff;padding:12px 16px;border-radius:0 8px 8px 0;margin:16px 0;font-size:14px}
.token-box{background:#0f172a;color:#7dd3fc;font-family:ui-monospace,Menlo,monospace;font-size:14px;padding:14px 16px;border-radius:8px;word-break:break-all;margin:12px 0}
.err{color:#d93025;font-size:14px;margin-top:10px}
.ok{color:#188038;font-size:14px;margin-top:10px}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:13px}
.row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #eef1f6}
.row:last-child{border-bottom:none}
.small{font-size:13px;color:#5b6779}
.nav{display:flex;gap:16px;margin-bottom:24px;font-size:14px}
.nav a{color:#1a6cff;text-decoration:none}
"""

_NAV = """
<div class="nav">
  <a href="/portal">门户首页</a>
  <a href="/portal/apply">商家申请</a>
  <a href="/portal/admin">审核后台</a>
  <a href="/portal/status">状态自查</a>
</div>
"""


def _page(title: str, body: str) -> dict[str, Any]:
    return {
        "__html__": (
            f"<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{title} — Kiwi Merchant Portal</title>"
            f"<style>{_PAGE_CSS}</style></head>"
            f"<body><div class=\"wrap\">{_NAV}{body}</div>"
            f"<script>{_PORTAL_JS}</script></body></html>"
        )
    }


_PORTAL_JS = """
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


def portal_home() -> dict[str, Any]:
    body = """
<h1>Kiwi Merchant 门户</h1>
<p>注册 Kiwi 商家身份，获取访问令牌（token），把产品目录接入 Kiwi 网络。</p>
<div class="card">
  <h2>三步接入</h2>
  <p>1. <strong>提交申请</strong> — 填写店铺域名、Agent 名称与联系邮箱。</p>
  <p>2. <strong>等待审核</strong> — 平台批准后签发商家 ID（mkt_…）与访问令牌。</p>
  <p>3. <strong>发布产品</strong> — 用令牌注册 Agent、发布 Listing，Buyer Agent 就能找到你。</p>
</div>
<div class="card">
  <h2>入口</h2>
  <p><a href="/portal/apply">商家申请</a> — 提交接入申请</p>
  <p><a href="/portal/admin">审核后台</a> — 平台运营审批申请、签发/轮换/吊销令牌（需 admin token）</p>
  <p><a href="/portal/status">状态自查</a> — 用你的 token 查看名下 Agent 与产品状态</p>
</div>
<div class="note">令牌只在签发时显示一次，遗失请联系运营轮换。明文令牌永不出现在日志中。</div>
"""
    return _page("Merchant Portal", body)


def portal_apply() -> dict[str, Any]:
    body = """
<h1>商家申请</h1>
<p>提交以下信息，平台审核通过后签发商家 ID 与访问令牌。</p>
<div class="card">
  <label for="domain">店铺域名（bare hostname，如 acme.example）</label>
  <input id="domain" placeholder="acme.example" autocomplete="off">
  <label for="agent_name">Agent 名称</label>
  <input id="agent_name" placeholder="Acme Merchant Agent">
  <label for="contact_email">联系邮箱</label>
  <input id="contact_email" type="email" placeholder="ops@acme.example">
  <label for="purpose">用途说明（可选）</label>
  <textarea id="purpose" rows="3" placeholder="想销售的商品类目 / 目标买家"></textarea>
  <button id="submit">提交申请</button>
  <div id="out"></div>
</div>
<script>
document.getElementById('submit').addEventListener('click', () => {
  const btn = document.getElementById('submit');
  const out = document.getElementById('out');
  btn.disabled = true;
  postJson('/v1/merchants/applications', {
    domain: document.getElementById('domain').value.trim(),
    agent_name: document.getElementById('agent_name').value.trim(),
    contact_email: document.getElementById('contact_email').value.trim(),
    purpose: document.getElementById('purpose').value.trim(),
  }).then(r => {
    if (r.ok) {
      out.className = 'ok';
      out.textContent = '申请已提交，编号 #' + r.application.application_id + '。平台审核后将签发令牌。';
    } else {
      out.className = 'err';
      out.textContent = r.error || '提交失败';
    }
  }).finally(() => { btn.disabled = false; });
});
</script>
"""
    return _page("商家申请", body)


def portal_admin() -> dict[str, Any]:
    body = """
<h1>审核后台</h1>
<p>输入平台 admin token，查看待审申请并签发商家令牌。</p>
<div class="card">
  <label for="admin_token">Admin Token</label>
  <input id="admin_token" type="password" placeholder="admin token" autocomplete="off">
  <button id="load">加载待审申请</button>
  <div id="out"></div>
  <div id="list"></div>
</div>
<div class="card" id="result_card" style="display:none">
  <h2>签发结果（令牌仅显示一次）</h2>
  <div id="result"></div>
</div>
<script>
function showToken(r) {
  const card = document.getElementById('result_card');
  const out = document.getElementById('result');
  card.style.display = 'block';
  out.innerHTML = '<p class="small">商家 ID</p><div class="token-box">' + r.merchant_id
    + '</div><p class="small">访问令牌 — 复制保存，关闭页面后不可再见</p>'
    + '<div class="token-box">' + r.token + '</div>'
    + '<p class="small">在 kiwi CLI 中用 --merchant-id ' + r.merchant_id
    + ' --merchant-token ' + r.token_prefix + '… 注册 Agent，或用 owner_token 字段调用 /v1/listings/publish。</p>';
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
      row.className = 'row';
      row.innerHTML = '<div><strong>' + a.agent_name + '</strong><br>'
        + '<span class="small mono">' + a.domain + ' · ' + a.contact_email + '</span>'
        + (a.purpose ? '<br><span class="small">' + a.purpose + '</span>' : '')
        + '</div>'
        + '<div><button data-app="' + a.application_id + '" class="ghost">批准签发</button>'
        + '<button data-rej="' + a.application_id + '" class="ghost">拒绝</button></div>';
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
    return _page("审核后台", body)


def portal_status() -> dict[str, Any]:
    body = """
<h1>状态自查</h1>
<p>输入你的商家令牌，查看名下 Agent 与产品状态。</p>
<div class="card">
  <label for="owner_token">你的令牌</label>
  <input id="owner_token" type="password" placeholder="mkt_…" autocomplete="off">
  <button id="check">查询</button>
  <div id="out"></div>
</div>
<script>
document.getElementById('check').addEventListener('click', () => {
  const token = document.getElementById('owner_token').value.trim();
  const out = document.getElementById('out');
  getJson('/v1/merchants/self?owner_token=' + encodeURIComponent(token)).then(r => {
    if (!r.ok) { out.className = 'err'; out.textContent = r.error || '查询失败'; return; }
    out.className = 'ok';
    out.innerHTML = '<strong>商家 ID：</strong><span class="mono">' + r.merchant_id + '</span><br>'
      + '<strong>令牌状态：</strong>' + r.token_status + '（签发 ' + r.issued_at
      + (r.rotated_at ? '，最近轮换 ' + r.rotated_at : '')
      + (r.revoked_at ? '，已吊销 ' + r.revoked_at : '') + '）<br>'
      + '<strong>Agent 数：</strong>' + r.agents_count
      + '　<strong>产品数：</strong>' + r.listings_count;
  });
});
</script>
"""
    return _page("状态自查", body)
