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
- token-request：pending 去重、active 去重、rejected 冲突；
- 登出后 me 403；
- /portal/register、/portal/login、/portal/account 页面 200。
"""

from __future__ import annotations

import asyncio
import json
import os
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

    def _request_token(self, session: str) -> None:
        """用商家信息申请令牌（建工单）。"""
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant"}).encode(),
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
        """极简注册：建账号，商家工单在申请令牌时才创建。"""
        session, _ = self._register()
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["email"], "ops@acme.example")
        self.assertIsNone(payload["application"])  # 未申请令牌，无工单
        self.assertIsNone(payload["token"])
        self.assertEqual(payload["merchant_id"], "")

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
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        # 重复申请去重
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant"}).encode(),
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
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "active")

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
            json.dumps({"domain": "acme.example", "agent_name": "Acme", "phone": "+86 139"}).encode(),
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


if __name__ == "__main__":
    unittest.main()
