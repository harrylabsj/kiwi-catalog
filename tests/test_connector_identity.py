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

"""商家连接器一次性身份授权（第 1 版设计 §3.2 / 商家连接器发布计划 §3.1）测试。

覆盖（对应设计硬边界）：
- 创建/兑换需 connector token（未配置 fail-closed，错误 token 拒绝）；
- return_url 必须落在运维白名单 origin（拒绝开放重定向：非白名单、协议相对、
  带 userinfo、未配置白名单）；
- 商家会话才能查看/决定；未验证邮箱账号不能授权（服务层第二道门）；
- 同意 → 回跳带一次性 code → 兑换返回已验证 merchant_id；单次消费；
- 拒绝 → 回跳带 error=access_denied，且不可兑换；
- 过期请求不可兑换；跨请求混用 code 拒绝；
- v31 迁移：fresh SCHEMA 与迁移链产出同一表集合。
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.core.errors import PermissionDenied
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import connector_identity as identity_service

OWNER_SECRET = "test-owner-secret"
CONNECTOR_TOKEN = "test-connector-token"
RETURN_URL = "https://connector.kiwi.example/connect/callback"


def _call_http(
    app,
    method: str,
    path: str,
    body: bytes = b"",
    cookie: str = "",
    query_string: bytes = b"",
    authorization: str = "",
) -> tuple[int, dict, dict]:
    headers = [(b"content-type", b"application/json")]
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": query_string,
        "http_version": "1.1",
        "scheme": "http",
    }
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    asyncio.run(app(scope, receive, send))
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


def _register_and_login(app, email: str, merchant_name: str) -> str:
    status, payload, _ = _call_http(
        app,
        "POST",
        "/v1/accounts/register",
        json.dumps(
            {
                "merchant_name": merchant_name,
                "email": email,
                "password": "strong-pw-123",
                "phone": "+86 138 0000 0000",
            }
        ).encode(),
    )
    assert status == 200, payload
    status, payload, headers = _call_http(
        app,
        "POST",
        "/v1/accounts/verify-email",
        json.dumps({"email": email, "code": payload["verification_code"]}).encode(),
    )
    assert status == 200, payload
    return headers["set-cookie"].split(";")[0]


class ConnectorIdentityApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_CONNECTOR_TOKEN": CONNECTOR_TOKEN,
                "KIWI_CATALOG_CONNECTOR_RETURN_URLS": "https://connector.kiwi.example",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)
        self.cookie_a = _register_and_login(self.app, "a@acme.example", "Acme 商贸")
        self.cookie_b = _register_and_login(self.app, "b@rival.example", "Rival 商行")

    # ── helpers ────────────────────────────────────────────────────────────

    def _create(
        self, *, authorization: str = f"Bearer {CONNECTOR_TOKEN}", return_url: str = RETURN_URL
    ) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/connector-identity/requests",
            json.dumps({"return_url": return_url, "client_label": "Kiwi 商家运营"}).encode(),
            authorization=authorization,
        )
        return status, payload

    def _exchange(self, request_id: str, code: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/connector-identity/exchange",
            json.dumps({"request_id": request_id, "code": code}).encode(),
            authorization=f"Bearer {CONNECTOR_TOKEN}",
        )
        return status, payload

    def _view(self, request_id: str, cookie: str = "") -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app,
            "GET",
            f"/v1/connector-identity/requests/{request_id}",
            cookie=cookie,
        )
        return status, payload

    def _decide(self, request_id: str, cookie: str, decision: str) -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            f"/v1/connector-identity/requests/{request_id}/decision",
            json.dumps({"decision": decision}).encode(),
            cookie=cookie,
        )
        return status, payload

    def _merchant_id(self, cookie: str) -> str:
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/me", cookie=cookie)
        assert status == 200, payload
        return str(payload["merchant_id"])

    # ── 创建：connector token + return_url 白名单 ──────────────────────────

    def test_create_requires_connector_token(self) -> None:
        status, _ = self._create(authorization="")
        self.assertEqual(status, 403)
        status, _ = self._create(authorization="Bearer wrong-token")
        self.assertEqual(status, 403)
        status, payload = self._create()
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["request"]["request_id"].startswith("creq_"))
        self.assertIn("/portal/connect?request_id=", payload["login_url"])
        self.assertIn(payload["request"]["request_id"], payload["login_url"])

    def test_create_fails_closed_without_connector_token_config(self) -> None:
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_CONNECTOR_TOKEN": ""}, clear=False):
            status, _ = self._create()
        self.assertEqual(status, 403)

    def test_create_rejects_return_urls_outside_allowlist(self) -> None:
        for bad in (
            "https://evil.example/callback",
            "https://connector.kiwi.example.evil.example/callback",
            "http://connector.kiwi.example/callback",  # scheme 变化 = origin 变化
            "/connect/callback",
            "https://user:pass@connector.kiwi.example/callback",
            "https://connector.kiwi.example/callback#frag",
            "",
        ):
            with self.subTest(url=bad):
                status, _ = self._create(return_url=bad)
                self.assertEqual(status, 400)

    def test_create_fails_closed_without_allowlist_config(self) -> None:
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_CONNECTOR_RETURN_URLS": ""}, clear=False
        ):
            status, _ = self._create()
        self.assertEqual(status, 400)

    # ── 门户确认页 ─────────────────────────────────────────────────────────

    def test_connect_page_is_served(self) -> None:
        status, payload, _ = _call_http(self.app, "GET", "/portal/connect")
        self.assertEqual(status, 200)
        self.assertIn("连接「Kiwi 商家运营」", payload["_raw"])

    def test_view_requires_session(self) -> None:
        status, payload = self._create()
        request_id = payload["request"]["request_id"]
        status, _ = self._view(request_id)
        self.assertEqual(status, 403)
        status, view = self._view(request_id, cookie=self.cookie_a)
        self.assertEqual(status, 200, view)
        self.assertEqual(view["request"]["status"], "pending")
        self.assertEqual(view["request"]["client_label"], "Kiwi 商家运营")

    # ── 同意 → 兑换 ────────────────────────────────────────────────────────

    def test_approve_then_exchange_returns_verified_merchant(self) -> None:
        status, payload = self._create()
        request_id = payload["request"]["request_id"]
        status, decided = self._decide(request_id, self.cookie_a, "approve")
        self.assertEqual(status, 200, decided)
        self.assertEqual(decided["decision"], "approve")
        self.assertIn("code=", decided["redirect_url"])
        code = decided["redirect_url"].split("code=")[1].split("&")[0]
        status, exchanged = self._exchange(request_id, code)
        self.assertEqual(status, 200, exchanged)
        self.assertEqual(exchanged["identity"]["merchant_id"], self._merchant_id(self.cookie_a))
        self.assertEqual(exchanged["identity"]["merchant_name"], "Acme 商贸")
        self.assertNotIn("account_id", exchanged["identity"])

    def test_exchange_is_single_use(self) -> None:
        status, payload = self._create()
        request_id = payload["request"]["request_id"]
        _, decided = self._decide(request_id, self.cookie_a, "approve")
        code = decided["redirect_url"].split("code=")[1].split("&")[0]
        self.assertEqual(self._exchange(request_id, code)[0], 200)
        status, _ = self._exchange(request_id, code)
        self.assertEqual(status, 409)

    def test_exchange_rejects_wrong_code(self) -> None:
        status, payload = self._create()
        request_id = payload["request"]["request_id"]
        self._decide(request_id, self.cookie_a, "approve")
        status, _ = self._exchange(request_id, "not-the-code")
        self.assertEqual(status, 403)

    def test_code_from_other_request_is_rejected(self) -> None:
        _, first = self._create()
        _, second = self._create()
        request_a = first["request"]["request_id"]
        request_b = second["request"]["request_id"]
        _, decided = self._decide(request_a, self.cookie_a, "approve")
        code_a = decided["redirect_url"].split("code=")[1].split("&")[0]
        status, _ = self._exchange(request_b, code_a)
        self.assertEqual(status, 409)  # B 未批准：不因持有 A 的 code 而通过

    def test_pending_request_cannot_be_exchanged(self) -> None:
        _, payload = self._create()
        request_id = payload["request"]["request_id"]
        status, _ = self._exchange(request_id, "anything")
        self.assertEqual(status, 409)

    # ── 拒绝 / 过期 ────────────────────────────────────────────────────────

    def test_deny_returns_access_denied_and_blocks_exchange(self) -> None:
        _, payload = self._create()
        request_id = payload["request"]["request_id"]
        status, decided = self._decide(request_id, self.cookie_b, "deny")
        self.assertEqual(status, 200, decided)
        self.assertIn("error=access_denied", decided["redirect_url"])
        status, _ = self._exchange(request_id, "anything")
        self.assertEqual(status, 409)

    def test_expired_request_cannot_be_exchanged(self) -> None:
        _, payload = self._create()
        request_id = payload["request"]["request_id"]
        _, decided = self._decide(request_id, self.cookie_a, "approve")
        code = decided["redirect_url"].split("code=")[1].split("&")[0]
        conn = open_connection(self.db_path)
        try:
            conn.execute(
                "update connector_identity_requests set expires_at = ? where request_id = ?",
                ("2000-01-01T00:00:00+00:00", request_id),
            )
            conn.commit()
        finally:
            conn.close()
        status, _ = self._exchange(request_id, code)
        self.assertEqual(status, 404)

    def test_view_does_not_expose_other_account_approval(self) -> None:
        _, payload = self._create()
        request_id = payload["request"]["request_id"]
        self._decide(request_id, self.cookie_a, "approve")
        status, view = self._view(request_id, cookie=self.cookie_b)
        self.assertEqual(status, 200, view)
        self.assertFalse(view["request"]["approved_for_current_account"])
        self.assertEqual(view["request"]["merchant_name"], "")

    def test_invalid_decision_value_rejected(self) -> None:
        _, payload = self._create()
        request_id = payload["request"]["request_id"]
        status, _ = self._decide(request_id, self.cookie_a, "maybe")
        self.assertEqual(status, 400)


class ConnectorMerchantCredentialTest(unittest.TestCase):
    """v32 商家连接器凭据：兑换签发、代表本商家读写目录、撤销与越权拒绝。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_CONNECTOR_TOKEN": CONNECTOR_TOKEN,
                "KIWI_CATALOG_CONNECTOR_RETURN_URLS": "https://connector.kiwi.example",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)
        self.cookie_a = _register_and_login(self.app, "a@acme.example", "Acme 商贸")
        self.cookie_b = _register_and_login(self.app, "b@rival.example", "Rival 商行")
        self.token_a = self._issue(self.cookie_a)

    def _post(self, path: str, body: dict, *, cookie: str = "", token: str = "") -> tuple[int, dict]:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            path,
            json.dumps(body).encode(),
            cookie=cookie,
            authorization=f"Bearer {token}" if token else "",
        )
        return status, payload

    def _merchant_id(self, cookie: str) -> str:
        status, payload, _ = _call_http(self.app, "GET", "/v1/accounts/me", cookie=cookie)
        assert status == 200, payload
        return str(payload["merchant_id"])

    def _issue(self, cookie: str) -> str:
        status, payload, _ = _call_http(
            self.app,
            "POST",
            "/v1/connector-identity/requests",
            json.dumps({"return_url": RETURN_URL, "client_label": "Kiwi 商家运营"}).encode(),
            authorization=f"Bearer {CONNECTOR_TOKEN}",
        )
        assert status == 200, payload
        request_id = payload["request"]["request_id"]
        status, decided, _ = _call_http(
            self.app,
            "POST",
            f"/v1/connector-identity/requests/{request_id}/decision",
            json.dumps({"decision": "approve"}).encode(),
            cookie=cookie,
        )
        assert status == 200, decided
        code = decided["redirect_url"].split("code=")[1].split("&")[0]
        status, exchanged, _ = _call_http(
            self.app,
            "POST",
            "/v1/connector-identity/exchange",
            json.dumps({"request_id": request_id, "code": code}).encode(),
            authorization=f"Bearer {CONNECTOR_TOKEN}",
        )
        assert status == 200, exchanged
        credential = exchanged["credential"]
        assert credential["expires_at"] != ""
        return str(credential["access_token"])

    def _draft_body(self, title: str) -> dict:
        return {"action": "draft", "merchant_display_name": "Acme 商贸", "title": title}

    def test_credential_is_merchant_scoped_and_prefixed(self) -> None:
        self.assertTrue(self.token_a.startswith("cmt_"))
        status, payload = self._post(
            "/v1/merchant-publications", self._draft_body("凭据草稿"), token=self.token_a
        )
        self.assertEqual(status, 200, payload)
        # merchant_id 只来自凭据绑定（请求体没有也不接受自述值）。
        self.assertEqual(payload["publication"]["merchant_id"], self._merchant_id(self.cookie_a))

    def test_credential_cannot_touch_other_merchant_publication(self) -> None:
        """A 的凭据不能撤回 B 的资料（归属只按凭据绑定的 merchant_id 判定）。"""
        status, published = self._post(
            "/v1/merchant-publications",
            {"action": "publish", "merchant_display_name": "Rival 商行", "title": "B 的商品"},
            cookie=self.cookie_b,
        )
        self.assertEqual(status, 200, published)
        other = published["publication"]["publication_id"]
        status, _ = self._post(f"/v1/merchant-publications/{other}/withdraw", {}, token=self.token_a)
        self.assertEqual(status, 403)

    def test_revoked_credential_rejected(self) -> None:
        status, revoked = self._post("/v1/connector-identity/revoke", {}, token=self.token_a)
        self.assertEqual(status, 200, revoked)
        self.assertTrue(revoked["revoked"])
        status, _ = self._post(
            "/v1/merchant-publications", self._draft_body("撤销后"), token=self.token_a
        )
        self.assertEqual(status, 403)

    def test_unknown_credential_rejected(self) -> None:
        status, _ = self._post(
            "/v1/merchant-publications", self._draft_body("伪造"), token="cmt_not-a-real-token"
        )
        self.assertEqual(status, 403)

    def test_expired_credential_rejected(self) -> None:
        conn = open_connection(self.db_path)
        try:
            conn.execute(
                "update connector_merchant_tokens set expires_at = ? where merchant_id = ?",
                ("2000-01-01T00:00:00+00:00", self._merchant_id(self.cookie_a)),
            )
            conn.commit()
        finally:
            conn.close()
        status, _ = self._post(
            "/v1/merchant-publications", self._draft_body("过期"), token=self.token_a
        )
        self.assertEqual(status, 403)

    def test_session_still_works_alongside_credential(self) -> None:
        status, payload = self._post(
            "/v1/merchant-publications", self._draft_body("会话草稿"), cookie=self.cookie_a
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["publication"]["merchant_id"], self._merchant_id(self.cookie_a))


class ConnectorIdentityServiceTest(unittest.TestCase):
    """服务层防线：HTTP 路径之外也必须成立（如未验证邮箱账号）。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        self.conn = open_connection(self.db_path)
        self.addCleanup(self.conn.close)
        env_patch = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_CONNECTOR_RETURN_URLS": "https://connector.kiwi.example"},
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def _request(self) -> str:
        record = identity_service.create_request(
            self.conn, return_url=RETURN_URL, client_label="test"
        )
        self.conn.commit()
        return record["request_id"]

    def test_unverified_account_cannot_approve(self) -> None:
        request_id = self._request()
        with self.assertRaises(PermissionDenied):
            identity_service.approve_request(
                self.conn,
                request_id=request_id,
                account={
                    "account_id": 1,
                    "email_verified": 0,
                    "merchant_id": "mkt_x_1",
                    "merchant_name": "Acme",
                },
            )

    def test_account_without_merchant_id_cannot_approve(self) -> None:
        request_id = self._request()
        with self.assertRaises(PermissionDenied):
            identity_service.approve_request(
                self.conn,
                request_id=request_id,
                account={
                    "account_id": 1,
                    "email_verified": 1,
                    "merchant_id": "",
                    "merchant_name": "Acme",
                },
            )


class ConnectorIdentityMigrationTest(unittest.TestCase):
    """v31 表在迁移路径上可用（fresh/迁移两路径的全表等价由 test_shadow_tables 守护）。"""

    def test_migration_creates_connector_identity_table(self) -> None:
        from kiwi_catalog.db.migrations import MIGRATIONS, _set_schema_user_version

        tmp = tempfile.mkdtemp()
        legacy = Path(tmp) / "legacy.sqlite"
        conn = sqlite3.connect(legacy)
        try:
            for migration in MIGRATIONS:
                migration.apply(conn)
            _set_schema_user_version(conn, len(MIGRATIONS))
            conn.commit()
            tables = {
                row[0]
                for row in conn.execute("select name from sqlite_master where type='table'")
            }
        finally:
            conn.close()
        self.assertIn("connector_identity_requests", tables)
