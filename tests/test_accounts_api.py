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
- 商家后台 HTML 页面由私有 kiwi-catalog-admin 扩展负责测试。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import shutil
import tempfile
import unittest
from unittest import mock

from cryptography.fernet import Fernet

from kiwi_catalog.api import auth
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.core.errors import AuthError, ShoppingCliError
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import accounts

ADMIN_TOKEN = "admin-tok-123"
OWNER_SECRET = "test-owner-secret"

REGISTER_BODY = {
    "merchant_name": "Acme 商贸",
    "email": "ops@acme.example",
    "password": "strong-pw-123",
    "phone": "+86 138 0000 0000",
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


def register_via_api(
    app,
    *,
    email: str = "ops@acme.example",
    password: str = "strong-pw-123",
    merchant_name: str = "Acme 商贸",
    phone: str = "+86 138 0000 0000",
    wechat: str = "",
    db_path: str = "",
    legacy_unverified: bool = False,
) -> tuple[int, dict, dict]:
    """走完邮箱先行的三步注册：register/code → register/verify → register。

    返回**建号那一步**的 ``(status, payload, headers)``；成功时 ``headers``
    带 ``set-cookie``（建号即自动登录），``payload["email_verified"] is True``。

    ``legacy_unverified=True`` 时建号后把 ``email_verified`` 拨回 0，等价于
    2026-10-13 之前注册、从未验证邮箱的存量账号。新流程已经不产生这种状态，
    但线上仍有存量，且 ``/v1/accounts/verify-email``、``/v1/accounts/resend-code``
    与登录页的 ``verify_block`` 分支仍要服务它们——相关测试用这个开关构造前置。
    需要同时传 ``db_path``。
    """
    status, payload, _ = _call_http(
        app, "POST", "/v1/accounts/register/code", json.dumps({"email": email}).encode()
    )
    if status != 200:
        return status, payload, {}
    ticket_status, ticket_payload, _ = _call_http(
        app,
        "POST",
        "/v1/accounts/register/verify",
        json.dumps({"email": email, "code": payload.get("verification_code") or ""}).encode(),
    )
    if ticket_status != 200:
        return ticket_status, ticket_payload, {}
    status, payload, headers = _call_http(
        app,
        "POST",
        "/v1/accounts/register",
        json.dumps(
            {
                "merchant_name": merchant_name,
                "email": email,
                "password": password,
                "phone": phone,
                "wechat": wechat,
                "verification_ticket": ticket_payload["verification_ticket"],
            }
        ).encode(),
    )
    if legacy_unverified and status == 200:
        from kiwi_catalog.db.session import db_session

        with db_session(db_path) as conn:
            conn.execute(
                "update merchant_accounts set email_verified = 0 where email = ?",
                (email.strip().lower(),),
            )
    return status, payload, headers


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

    def _register(self) -> str:
        """走完邮箱先行注册三步 → 建号即自动登录，返回会话 cookie 值。"""
        status, payload, headers = register_via_api(self.app, **REGISTER_BODY)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["email_verified"], "邮箱先行：建号时即已验证")
        set_cookie = headers.get("set-cookie", "")
        self.assertIn("kiwi_session=", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("Secure", set_cookie)
        return set_cookie.split(";")[0].split("=", 1)[1]

    def _approve_application_by_id(self, app_id: int) -> dict:
        # HTTP 审核端点已移私有仓；service 层与本地 CLI 同一实现
        from kiwi_catalog.db.session import db_session as _db_session
        from kiwi_catalog.services import merchant_tokens as tokens_service

        with _db_session(self.db_path) as conn:
            issued = tokens_service.approve_application(conn, app_id)
        return {"ok": True, **issued}

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
        from kiwi_catalog.services import merchant_tokens as tokens_service

        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select application_id from merchant_applications"
                " order by application_id limit 1"
            ).fetchone()
        app_id = row["application_id"]
        with db_session(self.db_path) as conn:
            issued = tokens_service.approve_application(conn, app_id)
        return {"ok": True, **issued}

    # ── 注册 ───────────────────────────────────────────────────────────────

    def test_register_creates_account_no_application_yet(self) -> None:
        """注册即商家：分配 merchant_id、影子行和 20 个免费商品名额。"""
        session = self._register()
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["email"], "ops@acme.example")
        self.assertIsNone(payload["application"])  # 未申请令牌，无工单
        self.assertIsNone(payload["token"])
        self.assertEqual(payload["listing_capacity"]["active_limit"], 20)
        self.assertEqual(payload["listing_capacity"]["active_used"], 0)
        # 注册完成即分配平台 merchant_id（与审批签发同一格式 mkt_<slug>_<rand>）
        self.assertRegex(payload["merchant_id"], r"^mkt_[a-z0-9-]+_.+")
        # 注册即商家：影子 merchants 行已创建（admin dashboard 无需审批即可见）
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "select id, name from merchants where id = ?",
                (payload["merchant_id"],),
            ).fetchone()
            self.assertIsNotNone(row, "注册即应创建影子 merchants 行")
            self.assertEqual(row["name"], "Acme 商贸")
        finally:
            conn.close()

    def test_register_requires_merchant_name(self) -> None:
        """注册必须提供商家名称（页面体现 + API 校验，注册即商家的数据基础）。"""
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({**REGISTER_BODY, "merchant_name": ""}).encode(),
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("merchant_name", payload.get("error", ""))
        # 缺失字段同样拒绝（require_field）
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({"email": "x@example.com", "password": "strong-pw-123"}).encode(),
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("merchant_name", payload.get("error", ""))

    def test_register_requires_phone_wechat_optional(self) -> None:
        """注册联系电话必填（微信选填）。"""
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register",
            json.dumps({**REGISTER_BODY, "phone": ""}).encode(),
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("phone", payload.get("error", ""))
        # 微信缺省不影响注册
        status, payload, _ = register_via_api(
            self.app, email="wx-ok@example.com", wechat=""
        )
        self.assertEqual(status, 200, payload)

    def test_register_seeds_revoked_row_and_closes_hmac_fallback(self) -> None:
        """审查 C-H2：注册即种 revoked 占位行，HMAC fallback 对新商户立即关闭。"""
        self._register()
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "select merchant_id, status from merchant_tokens where token_hash = ''"
            ).fetchone()
            self.assertIsNotNone(row, "register 应种入 revoked 占位行")
            self.assertEqual(row["status"], "revoked")
            merchant_id = str(row["merchant_id"])
            # HMAC 派生的 owner_token 不再通过（占位行关闭 fallback）。
            owner = hmac.new(
                OWNER_SECRET.encode("utf-8"),
                f"kiwi-catalog-owner:{merchant_id}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            with self.assertRaises(AuthError):
                auth.require_merchant_token({"owner_token": owner}, merchant_id, conn)
        finally:
            conn.close()

    def test_legacy_hmac_fallback_closed_by_env_flag(self) -> None:
        """审查 C-H2 第 3 步：KIWI_CATALOG_LEGACY_HMAC_AUTH=off 时无行商户 HMAC 被拒。"""
        conn = open_connection(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            merchant_id = "mkt_legacy_x"
            owner = hmac.new(
                OWNER_SECRET.encode("utf-8"),
                f"kiwi-catalog-owner:{merchant_id}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            # 默认（未设 flag）：无行商户经 HMAC 派生凭证放行
            auth.require_merchant_token({"owner_token": owner}, merchant_id, conn)
            # off：拒绝（须迁移到随机 token）
            with mock.patch.dict(os.environ, {"KIWI_CATALOG_LEGACY_HMAC_AUTH": "off"}):
                with self.assertRaises(AuthError):
                    auth.require_merchant_token({"owner_token": owner}, merchant_id, conn)
        finally:
            conn.close()

    def test_backfill_legacy_merchant_tokens(self) -> None:
        """审查 C-H2 第 2 步：backfill 为无行商户签发随机 token，跳过已有行，幂等。"""
        conn = open_connection(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            from kiwi_catalog.services import merchant_tokens as mt

            ts = "2026-08-13T00:00:00+00:00"
            for mid in ("mkt_legacy_1", "mkt_legacy_2", "mkt_has_token"):
                conn.execute(
                    "insert into merchants (id, name, created_at, updated_at) values (?, ?, ?, ?)",
                    (mid, "m", ts, ts),
                )
            conn.execute(
                "insert into merchant_tokens (merchant_id, token_hash, token_encrypted, status, issued_at)"
                " values ('mkt_has_token', 'h', '', 'active', ?)",
                (ts,),
            )
            conn.commit()

            issued = mt.backfill_legacy_merchant_tokens(conn)
            self.assertEqual(
                sorted(e["merchant_id"] for e in issued),
                ["mkt_legacy_1", "mkt_legacy_2"],
            )
            self.assertTrue(all(e["token"].startswith("mkt_") for e in issued))
            # 幂等：第二次运行无新增
            self.assertEqual(mt.backfill_legacy_merchant_tokens(conn), [])
        finally:
            conn.close()

    def test_register_duplicate_email_conflicts(self) -> None:
        """同一邮箱重复注册：第一步发码就 409（明确提示，接受枚举换 UX 清晰）。"""
        self._register()
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register/code",
            json.dumps({"email": REGISTER_BODY["email"]}).encode(),
        )
        self.assertEqual(status, 409, payload)
        self.assertIn("already registered", payload.get("error", ""))

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
        """legacy：建号时邮箱未验证（2026-10-13 之前的存量账号）不能登录。"""
        status, payload, _ = register_via_api(
            self.app, **REGISTER_BODY, db_path=self.db_path, legacy_unverified=True
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/login",
            json.dumps({"email": "ops@acme.example", "password": "strong-pw-123"}).encode(),
        )
        self.assertEqual(status, 403, payload)
        self.assertIn("not verified", payload.get("error", ""))

    def test_verify_email_wrong_code(self) -> None:
        """legacy：存量未验证账号用错码走 verify-email → 403。"""
        status, payload, _ = register_via_api(
            self.app, **REGISTER_BODY, db_path=self.db_path, legacy_unverified=True
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
        """legacy：存量未验证账号靠 resend-code 取新码才能完成验证。

        新流程不再产生未验证账号（邮箱先行，建号即已验证），这条路径如今
        只服务存量账号——而且它们**没有别的取码途径**，所以必须一直保留。
        """
        status, payload, _ = register_via_api(
            self.app, **REGISTER_BODY, db_path=self.db_path, legacy_unverified=True
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
        session = self._register()
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
        session = self._register()
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

    def test_me_returns_error_not_empty_token_when_decrypt_fails(self) -> None:
        """审查 C-M3：/me 解密失败必须返回可诊断错误，绝不静默给空 token。"""
        session = self._register()
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
        # 篡改 token_encrypted → 解密必然失败（C-H1 fail-closed 路径）。
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("update merchant_tokens set token_encrypted = 'v2:corrupted'")
            conn.commit()
        finally:
            conn.close()
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={session}"
        )
        # fail-closed：非 200 错误信封，绝不 200 + 空 token（C-M3 读路径）。
        self.assertNotEqual(status, 200)
        self.assertNotIn("token", payload)

    # ── token-request ──────────────────────────────────────────────────────

    def test_token_request_with_merchant_info(self) -> None:
        session = self._register()
        cookie = f"kiwi_session={session}"
        # 非法 domain → 400（非空仍走 canonical 校验）
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "https://x/y"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 400, payload)
        # 空 body（D7：门户零输入）→ 建工单 pending
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/token-request", b"{}", cookie=cookie
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        # 重复申请去重
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/token-request", b"{}", cookie=cookie
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

    def test_token_request_without_domain_allowed(self) -> None:
        """D7：domain 选填——空值申请建 pending 工单且 domain 存空。"""
        session = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/token-request", b"{}", cookie=cookie
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "select domain from merchant_applications order by application_id desc limit 1"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row["domain"], "")
        # /me 回显工单，domain 为空
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/me", cookie=cookie)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["application"]["domain"], "")

    def test_token_request_invalid_domain_rejected(self) -> None:
        """非空 domain 仍走 canonical 校验：URL 形态 → 400，不落工单。"""
        session = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "https://x/y"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 400, payload)
        conn = sqlite3.connect(self.db_path)
        try:
            n = conn.execute("select count(*) from merchant_applications").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 0)

    def test_token_request_with_domain_still_accepted(self) -> None:
        """老调用方带合法 domain 仍通过，且归一化落库（CLI/历史 API 兼容）。"""
        session = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "Acme.Example."}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["status"], "pending")
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/me", cookie=cookie)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["application"]["domain"], "acme.example")

    def test_me_roundtrips_agent_id_from_application(self) -> None:
        """「基本信息」页的 Agent ID 来自申请工单，/me 需回显（投影含 agent_id）。"""
        session = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme Merchant", "agent_id": "my-shop-agent-001"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=cookie
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["application"]["agent_id"], "my-shop-agent-001")

    def test_token_request_after_rejection_allowed(self) -> None:
        """被拒绝后可重新申请：新建 pending 工单，原被拒工单保留为审计记录。"""
        session = self._register()
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
        from kiwi_catalog.db.session import db_session as _db_session
        from kiwi_catalog.services import merchant_tokens as tokens_service

        with _db_session(self.db_path) as conn:
            tokens_service.reject_application(conn, app_id, "domain unverifiable")
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

        session = self._register()
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

        # 吊销（token 失效，merchant_id 保留）——service 层（与 CLI 同一实现）
        from kiwi_catalog.db.session import db_session as _db_session
        from kiwi_catalog.services import merchant_tokens as tokens_service

        with _db_session(self.db_path) as conn:
            tokens_service.revoke_token(conn, merchant_id)

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
        session = self._register()
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
        session = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme", "agent_id": "merchant-001", "phone": "+86 139"}).encode(),
            cookie=cookie,
        )
        self.assertEqual(status, 200, payload)
        # 工单带电话：注册时填写的账号电话优先（申请无需再填）
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select phone from merchant_applications where account_id = ("
                "select account_id from merchant_accounts where email = 'ops@acme.example')"
            ).fetchone()
        self.assertEqual(row["phone"], "+86 138 0000 0000")

    # ── 无账号工单（存量匿名通道数据）→ 审批 → 账号关联 ─────────────────────

    def test_accountless_application_links_account_on_approve(self) -> None:
        """无账号工单（account_id=0，匿名通道关闭前的存量数据）审批后按邮箱兜底关联账号。"""
        session = self._register()
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
        session = self._register()
        cookie = f"kiwi_session={session}"
        status, payload, _ = _call_http(
            self.app, "POST", "/v1/accounts/logout", b"{}", cookie=cookie
        )
        self.assertEqual(status, 200, payload)
        status, payload, _ = _call_http(
            self.app, "GET", "/v1/accounts/me", cookie=cookie
        )
        self.assertEqual(status, 403, payload)

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
        """造一个 legacy 的「已注册、邮箱未验证」账号，供重置流程断言使用。

        新流程建号时邮箱即已验证，所以这里走完注册后把 ``email_verified``
        拨回 0——等价于 2026-10-13 之前注册、从未验证邮箱的存量账号。
        重置流程"能收码即证明邮箱归属、顺带把 email_verified 置 1"这条
        兜底只对这类账号还有意义。
        """
        status, payload, _ = register_via_api(
            self.app,
            email=email,
            password=password,
            db_path=self.db_path,
            legacy_unverified=True,
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

class TokenEncryptionTest(unittest.TestCase):
    """审查 C-H1：Fernet 密钥派生升级为 scrypt + v2 前缀 + 解密 fail-closed。"""

    def setUp(self) -> None:
        self.env = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
        )
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()

    def test_v2_roundtrip_and_v1_backward_compat(self) -> None:
        token = "mkt_" + "a" * 32
        enc = accounts.encrypt_merchant_token(token)
        self.assertTrue(enc.startswith("v2:"), enc[:8])
        self.assertEqual(accounts.decrypt_merchant_token(enc), token)
        # 旧单次 SHA-256 派生的存量密文仍可解密（向后兼容）。
        legacy_key = base64.urlsafe_b64encode(
            hashlib.sha256(("kiwi-token-fernet:" + OWNER_SECRET).encode("utf-8")).digest()
        )
        legacy = Fernet(legacy_key).encrypt(token.encode("utf-8")).decode("ascii")
        self.assertEqual(accounts.decrypt_merchant_token(legacy), token)

    def test_decrypt_fails_closed_on_corruption(self) -> None:
        # 密文损坏 / 密钥轮换不再静默返回空串，而是抛类型化错误（fail-closed）。
        with self.assertRaises(ShoppingCliError):
            accounts.decrypt_merchant_token("v2:not-a-valid-ciphertext")


class AdminApplicationNotificationTest(unittest.TestCase):
    """商家提交接入申请 → 通知运营邮箱（2026-09-26 新增）。

    语义要点：通知是**旁路**——SMTP 故障不得影响商家的申请（与注册验证邮件的
    fail-closed 刻意不同）；未配置通知邮箱时静默跳过。
    """

    NOTIFY_TO = "1711496337@qq.com"

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_ADMIN_NOTIFY_EMAIL": self.NOTIFY_TO,
                "KIWI_CATALOG_SMTP_HOST": "smtp.example",
                "KIWI_CATALOG_SMTP_USER": "ops@example",
                "KIWI_CATALOG_SMTP_PASSWORD": "pw",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        # 本类只断言「接入申请」通知；注册本身也会通知运营（见
        # RegistrationEmailTest），mock 掉以免污染 assert_called_once 计数。
        registration_patch = mock.patch.object(accounts, "notify_admin_new_registration")
        registration_patch.start()
        self.addCleanup(registration_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _register_and_apply(self) -> tuple[int, dict]:
        """注册（邮箱先行三步，自动登录）→ 提交接入申请，返回 (状态码, 响应)。"""
        status, registered, headers = register_via_api(self.app, **REGISTER_BODY)
        self.assertEqual(status, 200, registered)
        cookie = headers.get("set-cookie", "").split(";")[0]
        status, applied, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme 商贸"}).encode(),
            cookie=cookie,
        )
        return status, applied

    def test_new_application_notifies_admin_inbox(self) -> None:
        with mock.patch("smtplib.SMTP") as smtp_cls:
            status, applied = self._register_and_apply()
        self.assertEqual(status, 200, applied)
        self.assertEqual(applied["status"], "pending")
        smtp_cls.assert_called_once()
        message = smtp_cls.return_value.__enter__.return_value.send_message.call_args[0][0]
        self.assertEqual(message["To"], self.NOTIFY_TO)
        self.assertIn("Acme 商贸", message["Subject"])
        body = message.get_content()
        self.assertIn("acme.example", body)
        self.assertIn(str(applied["application_id"]), body)

    def test_notification_failure_does_not_break_application(self) -> None:
        """SMTP 抛错 → 申请仍然成功且工单已落库（旁路语义）。"""
        with mock.patch("smtplib.SMTP") as smtp_cls:
            smtp_cls.return_value.__enter__.return_value.send_message.side_effect = (
                RuntimeError("smtp down")
            )
            status, applied = self._register_and_apply()
        self.assertEqual(status, 200, applied)
        self.assertEqual(applied["status"], "pending")
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select status, contact_email from merchant_applications where application_id = ?",
                (applied["application_id"],),
            ).fetchone()
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["contact_email"], REGISTER_BODY["email"])

    def test_no_notify_email_configured_is_silent(self) -> None:
        """未配置 KIWI_CATALOG_ADMIN_NOTIFY_EMAIL → 不发信，也不报错。"""
        os.environ.pop("KIWI_CATALOG_ADMIN_NOTIFY_EMAIL", None)
        self.addCleanup(
            os.environ.__setitem__, "KIWI_CATALOG_ADMIN_NOTIFY_EMAIL", self.NOTIFY_TO
        )
        with mock.patch("smtplib.SMTP") as smtp_cls:
            status, applied = self._register_and_apply()
        self.assertEqual(status, 200, applied)
        smtp_cls.assert_not_called()

    def test_repeat_application_does_not_renotify(self) -> None:
        """已有 pending 工单时再次申请 → 不重复通知（避免噪音）。"""
        with mock.patch("smtplib.SMTP") as first:
            status, _ = self._register_and_apply()
            self.assertEqual(status, 200)
        self.assertEqual(first.call_count, 1)
        with mock.patch("smtplib.SMTP") as second:
            status, again = self._register_and_apply_second_attempt()
        self.assertEqual(status, 200, again)
        second.assert_not_called()

    def _register_and_apply_second_attempt(self) -> tuple[int, dict]:
        """同一账号再申请一次（走登录而非注册，复用邮箱验证码通道）。"""
        status, logged_in, headers = _call_http(
            self.app,
            "POST",
            "/v1/accounts/login",
            json.dumps(
                {"email": REGISTER_BODY["email"], "password": REGISTER_BODY["password"]}
            ).encode(),
        )
        self.assertEqual(status, 200, logged_in)
        cookie = headers.get("set-cookie", "").split(";")[0]
        status, applied, _ = _call_http(
            self.app,
            "POST",
            "/v1/accounts/token-request",
            json.dumps({"domain": "acme.example", "agent_name": "Acme 商贸"}).encode(),
            cookie=cookie,
        )
        return status, applied


class UndeliverableRecipientTest(unittest.TestCase):
    """收件人被邮件服务端拒收 → 400（不是 500），且不留半条记录。

    此前 `SMTPRecipientsRefused` 会冒泡成 500：用户打错邮箱看到的是服务端错误。
    发码仍是 fail-closed（事务回滚、不发信、不建号），只是对外口径改为调用方
    可修复的 4xx。
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "smtp",
                "KIWI_CATALOG_SMTP_HOST": "smtp.example",
                "KIWI_CATALOG_SMTP_USER": "ops@example",
                "KIWI_CATALOG_SMTP_PASSWORD": "pw",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def test_register_code_with_rejected_recipient_is_400_not_500(self) -> None:
        import smtplib

        with mock.patch("smtplib.SMTP") as smtp_cls:
            smtp_cls.return_value.__enter__.return_value.send_message.side_effect = (
                smtplib.SMTPRecipientsRefused({"not-an-email": (553, b"invalid address")})
            )
            status, payload, _ = _call_http(
                self.app,
                "POST",
                "/v1/accounts/register/code",
                json.dumps({"email": "not-an-email"}).encode(),
            )
        self.assertEqual(status, 400, payload)
        self.assertIn("not deliverable", str(payload.get("error", "")))
        # fail-closed 不变：没有留下待验证的行。
        from kiwi_catalog.db.session import db_session

        with db_session(self.db_path) as conn:
            rows = conn.execute(
                "select count(*) from registration_verifications"
            ).fetchone()[0]
        self.assertEqual(rows, 0)

    def test_both_fail_closed_senders_map_recipient_refusal(self) -> None:
        """验证码与重置密码两条 fail-closed 发信路径口径一致。"""
        import smtplib
        from kiwi_catalog.core.errors import ValidationError
        from kiwi_catalog.services import accounts as accounts_service

        for send, args in (
            (accounts_service.send_verification_email, ("x", "123456")),
            (accounts_service.send_password_reset_email, ("x", "123456")),
        ):
            with self.subTest(sender=send.__name__):
                with mock.patch("smtplib.SMTP") as smtp_cls:
                    smtp_cls.return_value.__enter__.return_value.send_message.side_effect = (
                        smtplib.SMTPRecipientsRefused({"x": (553, b"invalid address")})
                    )
                    with self.assertRaises(ValidationError):
                        send(*args)

    def test_other_smtp_failures_are_not_masked(self) -> None:
        """连接/认证类失败仍是服务端问题：不得伪装成 400。"""
        from kiwi_catalog.core.errors import ValidationError
        from kiwi_catalog.services import accounts as accounts_service

        with mock.patch("smtplib.SMTP") as smtp_cls:
            smtp_cls.return_value.__enter__.return_value.send_message.side_effect = (
                RuntimeError("smtp down")
            )
            with self.assertRaises(RuntimeError):
                accounts_service.send_verification_email("buyer@example.com", "123456")
        # 未配置 SMTP 同样保持 fail-closed。
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_SMTP_HOST": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                accounts_service.send_verification_email("buyer@example.com", "123456")
        self.assertFalse(issubclass(RuntimeError, ValidationError))


class RegistrationEmailTest(unittest.TestCase):
    """注册 → 通知运营邮箱；首次验证邮箱 → 发欢迎信。

    语义要点与接入申请通知一致：两封都是**旁路**——SMTP 故障不得影响注册/验证
    结果；且都必须在**事务提交之后**发出（发送时另开支路连接能读到已提交的行）。
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_path = os.path.join(tmp.name, "catalog.sqlite")
        env = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_ADMIN_NOTIFY_EMAIL": "1711496337@qq.com",
            },
            clear=True,
        )
        env.start()
        self.addCleanup(env.stop)
        sender = mock.patch.object(accounts, "_send_email")
        self.send = sender.start()
        self.addCleanup(sender.stop)
        self.app = create_catalog_app(self.db_path)

    def code(self, email: str = REGISTER_BODY["email"]):
        return _call_http(
            self.app,
            "POST",
            "/v1/accounts/register/code",
            json.dumps({"email": email}).encode(),
        )

    def verify(self, email: str, code: str):
        return _call_http(
            self.app,
            "POST",
            "/v1/accounts/register/verify",
            json.dumps({"email": email, "code": code}).encode(),
        )

    def register(self, ticket: str, **overrides):
        body = {
            **REGISTER_BODY,
            "wechat": "acme-wechat",
            "verification_ticket": ticket,
            **overrides,
        }
        return _call_http(
            self.app, "POST", "/v1/accounts/register", json.dumps(body).encode()
        )

    def _ticket(self, email: str = REGISTER_BODY["email"]) -> str:
        """走完 register/code → register/verify，返回一次性 ticket。"""
        status, payload, _ = self.code(email)
        self.assertEqual(status, 200, payload)
        status, payload, _ = self.verify(email, payload["verification_code"])
        self.assertEqual(status, 200, payload)
        return payload["verification_ticket"]

    def test_register_auto_logs_in_and_notifies_admin_after_commit(self):
        ticket = self._ticket()
        self.send.reset_mock()
        committed = []

        def check_committed(to, subject, body):
            with sqlite3.connect(self.db_path) as conn:
                committed.append(
                    conn.execute("select email_verified from merchant_accounts").fetchone()[0]
                )

        self.send.side_effect = check_committed
        status, payload, headers = self.register(ticket)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["email_verified"])
        # 建号即自动登录（与 verify-email 通过后的行为一致）。
        self.assertIn("kiwi_session=", headers.get("set-cookie", ""))
        # console 模式不发欢迎信（send_welcome_email 只在 smtp 模式发），
        # 所以这里只有运营通知一封。
        self.send.assert_called_once()
        # 发信时账号已提交（旁路连接可见）——「事务提交之后」的证明。
        self.assertEqual(committed, [1])
        to, subject, body = self.send.call_args.args
        self.assertEqual(to, "1711496337@qq.com")
        self.assertIn("Acme 商贸", subject)
        for value in (
            REGISTER_BODY["email"],
            REGISTER_BODY["phone"],
            "acme-wechat",
            "merchant_id",
        ):
            self.assertIn(value, body)
        # 邮箱先行：建号时邮箱已验证，通知不再写「邮箱待验证」。
        self.assertNotIn("待验证", body)

    def test_welcome_sent_after_register_commit_in_smtp_mode(self):
        ticket = self._ticket()
        os.environ["KIWI_CATALOG_EMAIL_VERIFICATION_MODE"] = "smtp"
        self.send.reset_mock()
        committed = []

        def check_committed(to, subject, body):
            with sqlite3.connect(self.db_path) as conn:
                committed.append(
                    conn.execute("select email_verified from merchant_accounts").fetchone()[0]
                )

        self.send.side_effect = check_committed
        status, payload, _ = self.register(ticket)
        self.assertEqual(status, 200, payload)
        # 欢迎信 + 运营通知，两封都在提交之后发（两次都读到已提交的行）。
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual(committed, [1, 1])
        welcome = next(
            call.args
            for call in self.send.call_args_list
            if call.args[1] == "欢迎成为 Kiwi 商家"
        )
        self.assertEqual(welcome[0], REGISTER_BODY["email"])
        self.assertEqual(
            welcome[2],
            "Acme 商贸，\n\n"
            "您好，感谢您注册成为kiwi 商家，欣赏您尝试新事物的勇气。"
            "让我们一起开启Agentic Commerce 之旅。\n\n"
            "我们的官网是: kiwi.harrylabsj.com , 有问题也可以随时添加我的微信（hhdshwe）联系。\n\n"
            "感谢，\nKiwi 客服\n",
        )

    def test_ticket_is_single_use(self):
        """ticket 单次消费：重放必须被拒，不能重复建号。"""
        ticket = self._ticket()
        self.assertEqual(self.register(ticket)[0], 200)
        self.send.reset_mock()
        status, payload, _ = self.register(ticket)
        self.assertEqual(status, 403, payload)
        self.send.assert_not_called()

    def test_register_without_ticket_is_rejected(self):
        """服务端强制校验：页面把字段禁用只是 UX，绕过页面直接调接口同样被拒。"""
        status, payload, _ = self.register("")
        self.assertEqual(status, 403, payload)
        self.assertIn("verification required", payload.get("error", ""))
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute("select count(*) from merchant_accounts").fetchone()[0], 0
            )

    def test_bogus_ticket_is_rejected(self):
        status, payload, _ = self.register("not-a-real-ticket")
        self.assertEqual(status, 403, payload)

    def test_wrong_code_does_not_issue_ticket(self):
        self.assertEqual(self.code()[0], 200)
        status, payload, _ = self.verify(REGISTER_BODY["email"], "000000")
        self.assertEqual(status, 403, payload)
        self.assertNotIn("verification_ticket", payload)

    def test_duplicate_email_stops_at_the_code_step(self):
        """已注册邮箱在第一步就被拦住：明确提示，且不重复发码。"""
        self.assertEqual(self.register(self._ticket())[0], 200)
        self.send.reset_mock()
        status, payload, _ = self.code()
        self.assertEqual(status, 409, payload)
        self.assertIn("already registered", payload.get("error", ""))
        self.send.assert_not_called()

    def test_code_email_failure_leaves_no_pending_record(self):
        """验证码邮件 fail-closed：发不出去就整事务回滚，不留半条记录。"""
        os.environ["KIWI_CATALOG_EMAIL_VERIFICATION_MODE"] = "smtp"
        self.send.side_effect = RuntimeError("smtp down")
        from kiwi_catalog.api.handlers import accounts as handlers

        with self.assertRaisesRegex(RuntimeError, "smtp down"):
            handlers.request_register_code(
                self.db_path, {"email": REGISTER_BODY["email"]}
            )
        self.send.assert_called_once()
        self.assertEqual(self.send.call_args.args[1], "Kiwi 商家账号邮箱验证码")
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(
                conn.execute(
                    "select count(*) from registration_verifications"
                ).fetchone()[0],
                0,
            )

    def test_missing_admin_recipient_does_not_suppress_welcome(self):
        """未配置运营邮箱只静默跳过注册通知，不影响欢迎信。"""
        ticket = self._ticket()
        os.environ.pop("KIWI_CATALOG_ADMIN_NOTIFY_EMAIL")
        os.environ["KIWI_CATALOG_EMAIL_VERIFICATION_MODE"] = "smtp"
        self.send.reset_mock()
        status, payload, _ = self.register(ticket)
        self.assertEqual(status, 200, payload)
        self.send.assert_called_once()
        self.assertEqual(self.send.call_args.args[1], "欢迎成为 Kiwi 商家")


if __name__ == "__main__":
    unittest.main()
