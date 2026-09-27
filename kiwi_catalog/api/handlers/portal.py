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

"""Merchant 门户页面（注册 / 登录 / 商家后台 / 连接 Runtime / 关注）。

fallback 栈渲染的轻量 HTML（零新依赖）。共享渲染基建（官网同源 CSS、
CSP nonce 页面骨架、通用 JS helper、导航/页脚）在 handlers/portal_kit.py。

安全边界：
- 页面只做表单与 fetch 调用，动态数据全部走 JSON API（/v1/merchants/*、
  /v1/accounts/*），本包不含任何 admin 页面或端点；
- 运营/审核后台已移至私有扩展 kiwi-catalog-admin（docs/extensions.md），
  经 KIWI_CATALOG_EXTENSIONS 挂载；
- 响应体 ``{"__html__": "..."}`` 标记经 fallback _send_json 发 text/html +
  no-store。
"""

from __future__ import annotations

import html

from typing import Any

from kiwi_catalog.api.handlers import portal_kit as kit

# ── 共享渲染基建在 portal_kit（handlers/portal_kit.py）─────────────────────
# CSS / page()（CSP nonce）/ 通用 JS helper / 导航 / 页脚 / 404 均由 kit
# 提供，本模块只保留旧名薄别名供各页面函数使用。
_nav = kit.nav
_FOOTER = kit.FOOTER
_page = kit.page


def _not_found_html() -> str:
    """404 页面 HTML 字符串（不含 JS，供 __status__: 404 包裹）。"""
    return kit.not_found_html("你访问的页面不存在。")

def portal_home() -> dict[str, Any]:
    """商家入口直接展示自动开通的商品名额。"""
    return portal_account()


def portal_apply() -> dict[str, Any]:
    """旧令牌申请链接转到商品名额页。"""
    return portal_home()


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

    注册即成为商家并获得免费商品名额；邮箱验证后可连接 Runtime。
    """
    body = (
        _nav("portal")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">Register</div>
  <h2>注册商家账号</h2>
  <p class="lead">填写商家名称、邮箱、密码和联系电话即可注册成为商家（无需审核）。
    微信选填。验证邮箱后即可查看免费商品名额并连接 Runtime。</p>
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
    """「我的」：展示自动开通的 Listings 方案和当前占用。"""
    body = (
        _nav("account")
        + """
<section class="section center-page"><div class="section-inner">
  <div class="kicker">商家后台</div>
  <h2>商家后台</h2>
  <div class="subnav">
    <a href="/portal/account/profile"{sub_profile}>基本信息</a>
    <a href="/portal/account"{sub_apply}>商品名额</a>
    <a href="/portal/account/card"{sub_card}>我的名片</a>
    <a href="/portal/publications">公开资料</a>
    <a href="/portal/follows">我的关注</a>
    <a href="#" id="nav_logout" style="margin-left:auto">退出登录</a>
  </div>
  <div id="out"></div>
  <div id="content" style="display:none">
    <div class="card form-card">
      <div id="profile"></div>
      <div id="listing_capacity"></div>
    </div>
  </div>
</div></section>
<script>
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
fetch('/v1/accounts/me', {method: 'GET', credentials: 'same-origin'}).then(r => r.json()).then(r => {
    if (!r.ok) {
      window.location.href = '/portal/login';
      return;
    }
    document.getElementById('content').style.display = 'block';
    const p = document.getElementById('profile');
    p.innerHTML = '<h3>' + esc(r.email) + '</h3><p class="small">商家 ' + esc(r.merchant_id) + '</p>';
    const c = r.listing_capacity;
    document.getElementById('listing_capacity').innerHTML = c
      ? '<h3>商品名额：' + esc(c.active_used) + ' / ' + esc(c.active_limit) + '</h3>'
        + '<p class="small">方案：' + esc(c.plan_code) + ' · 可用：' + esc(c.active_remaining) + '</p>'
        + (c.status === 'active'
          ? '<p class="small">验证邮箱并连接 Runtime、发布名片后，商品可自动同步。更新现有商品不占新名额。</p>'
          : '<p class="err">商品发布已暂停，请联系平台处理；现有商品仍可下架。</p>')
      : '<p class="err">商品方案尚未开通，请联系平台处理。</p>';
  }).catch(() => {
    document.getElementById('out').textContent = '无法加载商品名额，请稍后重试。';
  });
</script>
"""
        + _FOOTER
    )
    # 二级导航高亮（商品名额 = 本页）
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
    enrollment_id_attribute = html.escape(str(enrollment_id), quote=True)
    body = (
        _nav("account")
        + """
<section class="section"><div class="section-inner">
  <div class="kicker">Kiwi 商家接入</div>
  <h2>连接此服务并发布</h2>
  <p class="lead">请确认这是你刚才从商家 Runtime 发起的连接，并核对公开名片。确认后系统会自动完成绑定与发布，不会再要求你确认技术细节。</p>
  <div class="card form-card" style="max-width:720px">
    <div id="connect_state" data-enrollment-id="__ENROLLMENT_ID__"><p class="small muted">正在读取本次接入请求…</p></div>
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
const enrollmentId = document.getElementById('connect_state').dataset.enrollmentId;
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
""".replace("__ENROLLMENT_ID__", enrollment_id_attribute)
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
