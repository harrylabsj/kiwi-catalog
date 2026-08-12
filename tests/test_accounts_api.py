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

"""商家账号体系集成测试（docs §account）。

覆盖：
- 注册：建账号 + 待审工单 + 自动登录（Set-Cookie）；重复邮箱 409；
  弱密码/非法邮箱校验；
- 登录：正确/错误密码；限流；会话有效期；
- me：未登录 403；登录后返回工单状态；审批后返回 token 明文（找回）；
- token-request：pending 去重、active 去重、rejected 后可重新申请（新工单）；
- 登出后 me 403；
- /portal/register、/portal/login、/portal/account 页面 200。
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app

ADMIN_TOKEN = "admin-tok-123"
OWNER_SECRET = "test-owner-secret"

REGISTER_BODY = {
    "email": "ops@acme.example",
    "password": "strong-pw-123",
}


def _call_http(app, method: str, path: str, body: bytes = b"", cookie: str = "") -> tuple[int, dict, dict]:
    headers = [(b"content-type", b"application/json")]
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
        "http_version": "1.1",
        "scheme": "http",
    }
    sent = {"body": body}
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": sent["body"], "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    async def run():
        await app(scope, receive, send)

    asyncio.run(run())
    start = next(m for m in received if m["type"] == "http.response.start")
    headers_out = {
        k.decode("latin1"): v.decode("latin1") for k, v in start.get("headers", [])
    }
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        try:
            payload = json.loads(chunks.decode())
        except json.JSONDecodeError:
            payload = {"_raw": chunks.decode()}
    return start.get("status", 500), payload, headers_out


class AccountsApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _register(self) -> tuple[str, str]:
        """注册（console 模式）并验证邮箱，返回会话 cookie + 验证码。"""
        status, payload, headers = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps(REGISTER_BODY).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["email_verified"])
        code = payload["verification_code"]
        self.assertTrue(code, "console 模式应返回验证码")
        # 验证邮箱 → 自动登录（Set-Cookie）
        status, payload, headers = _call_http(
            self.app,
            "POST",
            "/v1/accounts/verify-email",
            json.dumps({"email": REGISTER_BODY["email"], "code": code}).encode(),
        )
        self.assertEqual(status, 200, payload)
        set_cookie = headers.get("set-cookie", "")
        self.assertIn("kiwi_session=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("Secure", set_cookie)
        return set_cookie.split(";")[0].split("=", 1)[1], code

    def _approve_application_by_id(self, app_id: int) -> dict:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/approve",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )
        self.assertEqual(status, 200, payload)
        return payload

    def _request_token(self, session: str) -> None:
        """用商家信息申请令牌（建工单）。"""
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant", "agent_id": "merchant-001"}).encode(),
            cookie=f"kiwi_session={session}",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")

    def _approve_first_application(self) -> dict:
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select application_id from merchant_applications"
                " order by application_id limit 1"
            ).fetchone()
        app_id = row["application_id"]
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/approve",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )
        self.assertEqual(status, 200, payload)
        return payload

    # ── 注册 ───────────────────────────────────────────────────────────────

    def test_register_creates_account_no_application_yet(self) -> None:
        """极简注册：建账号即分配 merchant_id，商家工单在申请令牌时才创建。"""
        session, _ = self._register()
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["email"], "ops@acme.example")
        self.assertIsNone(payload["application"])  # 未申请令牌，无工单
        self.assertIsNone(payload["token"])
        # 注册完成即分配平台 merchant_id（与审批签发同一格式 mkt_<slug>_<rand>）
        self.assertRegex(payload["merchant_id"], r"^mkt_[a-z0-9-]+_.+")

    def test_register_duplicate_email_conflicts(self) -> None:
        self._register()
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps(REGISTER_BODY).encode(),
        )
        self.assertEqual(status, 409, payload)

    def test_register_validation(self) -> None:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({**REGISTER_BODY, "password": "short"}).encode(),
        )
        self.assertEqual(status, 400, payload)
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({**REGISTER_BODY, "email": "not-an-email"}).encode(),
        )
        self.assertEqual(status, 400, payload)

    # ── 登录 ───────────────────────────────────────────────────────────────

    def test_login_success_and_failure(self) -> None:
        self._register()
        status, payload, headers = _call_http(
            self.app,
            "POST",
            "/v1/accounts/login",
            json.dumps({"email": "ops@acme.example", "password": "strong-pw-123"}).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertIn("set-cookie", headers)
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/login",
            json.dumps({"email": "ops@acme.example", "password": "wrong-password"}).encode(),
        )
        self.assertEqual(status, 403, payload)

    def test_me_requires_login(self) -> None:
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/me")
        self.assertEqual(status, 403, payload)

    # ── 邮箱验证 ───────────────────────────────────────────────────────────

    def test_login_blocked_before_email_verification(self) -> None:
        """未验证邮箱不能登录。"""
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps(REGISTER_BODY).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["email_verified"])
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/login",
            json.dumps({"email": "ops@acme.example", "password": "strong-pw-123"}).encode(),
        )
        self.assertEqual(status, 403, payload)
        self.assertIn("not verified", payload.get("error", ""))

    def test_verify_email_wrong_code(self) -> None:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps(REGISTER_BODY).encode(),
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/verify-email",
            json.dumps({"email": "ops@acme.example", "code": "000000"}).encode(),
        )
        self.assertEqual(status, 403, payload)

    def test_resend_code_works(self) -> None:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps(REGISTER_BODY).encode(),
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/resend-code",
            json.dumps({"email": "ops@acme.example"}).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["verification_code"])
        # 新码可验证并登录
        status, payload, headers = _call_http(
            self.app,
            "POST",
            "/v1/accounts/verify-email",
            json.dumps({"email": "ops@acme.example", "code": payload["verification_code"]}).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertIn("set-cookie", headers)

    # ── token 找回（核心：审批后"我的"可见明文）──────────────────────────

    def test_token_visible_after_approval(self) -> None:
        session, _ = self._register()
        self._request_token(session)
        issued = self._approve_first_application()
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["merchant_id"], issued["merchant_id"])
        self.assertIsNotNone(payload["token"])
        self.assertEqual(payload["token"]["status"], "active")
        # 明文与签发时一致（加密存储可解密找回）
        self.assertEqual(payload["token"]["token"], issued["token"])
        self.assertNotEqual(payload["token"]["token"], "")
        # sqlite3.Connection 的 with 只管事务不关连接（审查 P3-09）——显式 close
        conn = sqlite3.connect(self.db_path)
        try:
            event = conn.execute(
                "select event, details_json from audit_events "
                "where event = 'merchant_token_viewed' order by id desc limit 1"
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(event)
        self.assertEqual(event[0], "merchant_token_viewed")
        self.assertNotIn(issued["token"], event[1])

    def test_login_then_me_after_approval(self) -> None:
        session, _ = self._register()
        self._request_token(session)
        self._approve_first_application()
        status, payload, headers = _call_http(
            self.app,
            "POST",
            "/v1/accounts/login",
            json.dumps({"email": "ops@acme.example", "password": "strong-pw-123"}).encode(),
        )
        self.assertEqual(status, 200, payload)
        session = headers["set-cookie"].split(";")[0].split("=", 1)[1]
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["token"]["token"].startswith("mkt_"))

    # ── token-request ──────────────────────────────────────────────────────

    def test_token_request_with_merchant_info(self) -> None:
        session, _ = self._register()
        cookie = f"kiwi_session={session}"
        # 缺商家信息 → 400
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/token-request", b"{}", cookie=cookie
        )
        self.assertEqual(status, 400, payload)
        # 带商家信息 → 建工单 pending
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant", "agent_id": "merchant-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        # 重复申请去重
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant", "agent_id": "merchant-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        # 审批后 request 返回 active 现状
        self._approve_first_application()
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant", "agent_id": "merchant-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "active")

    def test_token_request_after_rejection_allowed(self) -> None:
        """被拒绝后可重新申请：新建 pending 工单，原被拒工单保留为审计记录。"""
        session, _ = self._register()
        cookie = f"kiwi_session={session}"
        # 首次申请 → pending
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme", "agent_id": "merchant-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        # 运营拒绝（带理由）
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            app_id = conn.execute(
                "select application_id from merchant_applications order by application_id limit 1"
            ).fetchone()["application_id"]
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/reject",
            json.dumps({"admin_token": ADMIN_TOKEN, "review_note": "domain unverifiable"}).encode(),
        )
        self.assertEqual(status, 200, payload)
        # 重新申请 → 新 pending 工单（非 409）
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme", "agent_id": "merchant-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        # 审计：原被拒工单保留，共 2 条
        with db_session(self.db_path) as conn:
            rows = conn.execute(
                "select status from merchant_applications order by application_id"
            ).fetchall()
        self.assertEqual([r["status"] for r in rows], ["rejected", "pending"])

    def test_reapproval_reuses_merchant_id(self) -> None:
        """审查 BUG-09：revoked→reapply→approve 必须复用原 merchant_id。

        此前无条件 new_platform_merchant_id 并覆盖账户绑定——旧 ID 下的
        catalog_agents / commerce_listings / 影子 merchants / 审计身份全部
        脱离商家控制（商户无法用新 token 管理旧资源）。merchant_id 是稳定
        身份，token 是可轮换/撤销凭据。
        """
        from kiwi_catalog.db.session import db_session

        session, _ = self._register()
        cookie = f"kiwi_session={session}"
        # 首次申请 → 批准
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme", "agent_id": "merchant-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        first = self._approve_first_application()
        merchant_id = first["merchant_id"]
        self.assertTrue(merchant_id.startswith("mkt_"))

        # 吊销（token 失效，merchant_id 保留）
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/{merchant_id}/revoke",
            json.dumps({"admin_token": ADMIN_TOKEN}).encode(),
        )
        self.assertEqual(status, 200, payload)

        # 重新申请 → 批准 → 同一 merchant_id（复用而非新建）
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme", "agent_id": "merchant-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        with db_session(self.db_path) as conn:
            app_id = conn.execute(
                "select application_id from merchant_applications"
                " order by application_id desc limit 1"
            ).fetchone()["application_id"]
        second = self._approve_application_by_id(app_id)
        self.assertEqual(second["merchant_id"], merchant_id, "重批准必须复用原 merchant_id")
        self.assertNotEqual(second["token"], first["token"], "token 是重新签发的凭据")

        # 新 token active；旧资源（同 merchant_id）仍在控制面下
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select status from merchant_tokens where merchant_id = ?", (merchant_id,)
            ).fetchone()
        self.assertEqual(row["status"], "active")

    # ── 账户基本信息 ───────────────────────────────────────────────────────

    def test_profile_update_and_view(self) -> None:
        session, _ = self._register()
        cookie = f"kiwi_session={session}"
        # 更新基本信息
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/profile",
            json.dumps({"merchant_name": "Acme 商贸", "phone": "+86 138 0000 0000"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["merchant_name"], "Acme 商贸")
        self.assertEqual(payload["phone"], "+86 138 0000 0000")
        # me 反映基本信息
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=cookie
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["merchant_name"], "Acme 商贸")
        self.assertEqual(payload["phone"], "+86 138 0000 0000")
        self.assertTrue(payload["created_at"])

    def test_token_request_carries_phone(self) -> None:
        session, _ = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme", "agent_id": "merchant-001", "phone": "+86 139"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        # 工单带电话
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select phone from merchant_applications where account_id = ("
                "select account_id from merchant_accounts where email = 'ops@acme.example')"
            ).fetchone()
        self.assertEqual(row["phone"], "+86 139")

    # ── 无账号工单（存量匿名通道数据）→ 审批 → 账号关联 ─────────────────────

    def test_accountless_application_links_account_on_approve(self) -> None:
        """无账号工单（account_id=0，匿名通道关闭前的存量数据）审批后按邮箱兜底关联账号。"""
        session, _ = self._register()
        # 直插 account_id=0 的工单（2026-08-12 起匿名提交端点已关闭，仅存量数据存在此形态）
        from kiwi_catalog.db.session import db_session, now_iso

        with db_session(self.db_path) as conn:
            cursor = conn.execute(
                "insert into merchant_applications"
                " (status, domain, agent_name, agent_id, contact_email, purpose, phone, created_at)"
                " values ('pending', 'public.example', 'Public Shop', 'merchant-001',"
                " 'ops@acme.example', '', '', ?)",
                (now_iso(),),
            )
            app_id = int(cursor.lastrowid or 0)
        self._approve_application_by_id(app_id)
        # 账号 merchant_id 回填
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["merchant_id"].startswith("mkt_"))
        self.assertIsNotNone(payload["token"])
        self.assertEqual(payload["token"]["status"], "active")

    # ── request_token fail-closed ──────────────────────────────────────────

    def test_request_token_requires_merchant_id(self) -> None:
        """纵深防御：账号无 merchant_id 时 request_token 抛 ValidationError。

        正常路径 resolve_session 已懒回填；此处直接构造无 merchant_id 的账号
        dict 绕过懒回填，验证服务层 fail-closed。
        """
        from kiwi_catalog.core.errors import ValidationError
        from kiwi_catalog.db.session import db_session
        from kiwi_catalog.services import accounts as accounts_service

        account = {"account_id": 0, "email": "ghost@acme.example", "merchant_id": ""}
        with db_session(self.db_path) as conn:
            with self.assertRaises(ValidationError):
                accounts_service.request_token(
                    conn,
                    account,
                    domain="acme.example",
                    agent_name="Acme",
                    agent_id="merchant-001",
                )

    # ── 登出 ───────────────────────────────────────────────────────────────

    def test_logout_invalidates_session(self) -> None:
        session, _ = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/logout", b"{}", cookie=cookie
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=cookie
        )
        self.assertEqual(status, 403, payload)

    # ── 导航 ───────────────────────────────────────────────────────────────

    def test_portal_nav_has_my_account(self) -> None:
        """「我的」页一级导航：Home / For Buyers / For Merchants / For Developers / My Account。

        官网四项链接到 kiwi.harrylabsj.com 各页（Demo 在官网首页，不单列）；
        My Account 为本地页；令牌申请收敛到页内（无独立导航链接）。
        """
        _, payload, _ = _call_http(self.app, "GET", "/portal/account")
        raw = payload.get("_raw", "")
        for label in (">Home</a>", ">For Buyers</a>", ">For Merchants</a>",
                      ">For Developers</a>", ">My Account</a>"):
            self.assertIn(label, raw)
        self.assertNotIn(">Demo</a>", raw)
        self.assertIn("buyers.html", raw)
        self.assertIn("merchants.html", raw)
        self.assertIn("developers.html", raw)
        self.assertNotIn("demo.html", raw)
        self.assertIn("复制令牌", raw)  # 令牌态双按钮：复制令牌 + 申请令牌（静态模板）
        self.assertIn("申请令牌", raw)
        self.assertNotIn(">API Token</a>", raw)
        self.assertNotIn(">令牌申请</a>", raw)
        self.assertNotIn("/portal/status", raw)
        self.assertNotIn(">Merchant Portal<", raw)  # 导航无 Merchant Portal（title 后缀除外）

    def test_home_nav_points_to_my_account(self) -> None:
        """`/portal` 一级导航指向 My Account；不再有独立令牌申请导航链接。"""
        _, payload, _ = _call_http(self.app, "GET", "/portal")
        raw = payload.get("_raw", "")
        self.assertIn(">My Account</a>", raw)
        self.assertIn("/portal/account", raw)
        self.assertIn(">For Merchants</a>", raw)
        self.assertNotIn(">API Token</a>", raw)
        self.assertNotIn(">令牌申请</a>", raw)

    def test_status_page_removed(self) -> None:
        status, _, _ = _call_http(self.app, "GET", "/portal/status")
        self.assertEqual(status, 404, "令牌页已移除")

    # ── 页面 ───────────────────────────────────────────────────────────────

    def test_account_pages_serve_html(self) -> None:
        markers = {
            "/portal/register": "注册商家账号",
            "/portal/login": "商家登录",
            "/portal/account": "我的",
        }
        for path, marker in markers.items():
            status, payload, _ = _call_http(self.app, "GET", path)
            self.assertEqual(status, 200, (path, payload))
            self.assertTrue(payload.get("_raw", "").startswith("<!doctype html"), path)
            self.assertIn(marker, payload.get("_raw", ""), path)


class PasswordResetApiTest(unittest.TestCase):
    """忘记密码重置流程（迁移 v24，docs/accounts.md）。

    覆盖：防枚举（未知邮箱也 ok）、console 模式返回重置码、错误码/未知
    邮箱统一 403、成功后旧密码失效 + 新密码可登录 + email_verified 置 1
    （未验证账号死角）、旧会话全部失效、过期码拒绝、新密码长度校验。
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _register(self, email: str = "ops@acme.example", password: str = "strong-pw-123") -> None:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({"email": email, "password": password}).encode(),
        )
        self.assertEqual(status, 200, payload)

    def _forgot(self, email: str = "ops@acme.example") -> dict:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/forgot-password",
            json.dumps({"email": email}).encode(),
        )
        self.assertEqual(status, 200, payload)
        return payload

    def _reset(self, email: str, code: str, new_password: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/reset-password",
            json.dumps({"email": email, "code": code, "new_password": new_password}).encode(),
        )
        return status, payload

    def _login(self, email: str, password: str) -> tuple[int, dict, dict]:
        return _call_http(
            self.app,
            "POST",
            "/v1/accounts/login",
            json.dumps({"email": email, "password": password}).encode(),
        )

    def test_forgot_password_unknown_email_returns_ok(self) -> None:
        """防枚举：未知邮箱同样返回 ok 通用文案，且不带 reset_code。"""
        payload = self._forgot("ghost@acme.example")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload.get("reset_code") or "", "")

    def test_forgot_password_known_email_returns_code(self) -> None:
        self._register()
        payload = self._forgot()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["reset_code"], "console 模式应返回重置码")

    def test_reset_password_wrong_code_and_unknown_email(self) -> None:
        self._register()
        self._forgot()
        # 错误码 → 403（与账号不存在同一错误，不区分）
        status, payload = self._reset("ops@acme.example", "000000", "new-strong-pw-456")
        self.assertEqual(status, 403, payload)
        # 未知邮箱 → 同样 403
        status, payload = self._reset("ghost@acme.example", "000000", "new-strong-pw-456")
        self.assertEqual(status, 403, payload)

    def test_reset_password_success_flow(self) -> None:
        """成功重置：旧密码登录失败、新密码登录成功、未验证账号顺带完成邮箱验证。"""
        self._register()  # 未验证邮箱（此前无法登录）
        code = self._forgot()["reset_code"]
        status, payload = self._reset("ops@acme.example", code, "new-strong-pw-456")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["message"], "password reset")
        # email_verified 置 1（能收到码即证明邮箱归属）
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select email_verified, reset_code_hash from merchant_accounts"
                " where email = 'ops@acme.example'"
            ).fetchone()
        self.assertEqual(int(row["email_verified"]), 1)
        self.assertEqual(row["reset_code_hash"], "", "重置码用后清除")
        # 旧密码登录失败，新密码登录成功（未验证死角也随 email_verified=1 消除）
        status, _, _ = self._login("ops@acme.example", "strong-pw-123")
        self.assertEqual(status, 403)
        status, payload, headers = self._login("ops@acme.example", "new-strong-pw-456")
        self.assertEqual(status, 200, payload)
        self.assertIn("set-cookie", headers)

    def test_reset_password_invalidates_sessions(self) -> None:
        """改密后所有旧会话失效（重置前登录拿的 session 之后 /me 403）。"""
        self._register()
        code = self._forgot()["reset_code"]
        status, payload = self._reset("ops@acme.example", code, "new-strong-pw-456")
        self.assertEqual(status, 200, payload)
        # 重置顺带完成邮箱验证 → 可登录拿会话
        status, _, headers = self._login("ops@acme.example", "new-strong-pw-456")
        self.assertEqual(status, 200)
        session = headers["set-cookie"].split(";")[0].split("=", 1)[1]
        # 再次重置 → 刚拿的会话也应失效
        code = self._forgot()["reset_code"]
        status, payload = self._reset("ops@acme.example", code, "another-pw-789")
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 403, payload)

    def test_reset_password_expired_code(self) -> None:
        self._register()
        code = self._forgot()["reset_code"]
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            conn.execute(
                "update merchant_accounts set reset_expires_at = '2000-01-01T00:00:00+00:00'"
                " where email = 'ops@acme.example'"
            )
        status, payload = self._reset("ops@acme.example", code, "new-strong-pw-456")
        self.assertEqual(status, 403, payload)

    def test_reset_password_short_password(self) -> None:
        self._register()
        code = self._forgot()["reset_code"]
        status, payload = self._reset("ops@acme.example", code, "short")
        self.assertEqual(status, 400, payload)

    def test_portal_reset_password_page(self) -> None:
        status, payload, _ = _call_http(self.app, "GET", "/portal/reset-password")
        self.assertEqual(status, 200, payload)
        raw = payload.get("_raw", "")
        self.assertTrue(raw.startswith("<!doctype html"))
        self.assertIn("重置密码", raw)
        # 登录页有「忘记密码」入口
        _, payload, _ = _call_http(self.app, "GET", "/portal/login")
        self.assertIn("/portal/reset-password", payload.get("_raw", ""))


if __name__ == "__main__":
    unittest.main()
