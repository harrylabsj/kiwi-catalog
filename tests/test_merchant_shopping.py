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

"""商家"我的商品"测试（v20 shopping-cli 绑定 + 写回代理）。

- 服务层：bind/get shopping token 往返（Fernet 加解密）；
- handler：绑定需 owner/admin token；portal 页可渲染。
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.handlers import merchant_shopping as handlers
from kiwi_catalog.api.handlers.portal import portal_products
from kiwi_catalog.core.errors import AuthError, PermissionDenied, ValidationError
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services import merchant_shopping


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    # 一个 merchant_tokens 行（bind 前置）
    conn.execute(
        "insert into merchant_tokens (merchant_id, token_hash, status, issued_at)"
        " values ('mkt_test', 'x', 'active', ?)",
        (now_iso(),),
    )
    conn.commit()
    conn.close()
    return db


class MerchantShoppingServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["KIWI_CATALOG_OWNER_TOKEN_SECRET"] = "test-secret"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_OWNER_TOKEN_SECRET", None)

    def test_bind_and_get_roundtrip(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        merchant_shopping.bind_shopping_token(conn, "mkt_test", "shop-token-123")
        self.assertEqual(merchant_shopping.get_shopping_token(conn, "mkt_test"), "shop-token-123")
        # 未绑定商家 → 空
        conn.execute(
            "insert into merchant_tokens (merchant_id, token_hash, status, issued_at)"
            " values ('mkt_none', 'x', 'active', ?)",
            (now_iso(),),
        )
        self.assertEqual(merchant_shopping.get_shopping_token(conn, "mkt_none"), "")
        conn.close()

    def test_bind_unknown_merchant_rejected(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        from kiwi_catalog.core.errors import NotFoundError

        with self.assertRaises(NotFoundError):
            merchant_shopping.bind_shopping_token(conn, "mkt_missing", "token")
        conn.close()


class MerchantShoppingHandlersTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = "test-admin"
        os.environ["KIWI_CATALOG_OWNER_TOKEN_SECRET"] = "test-secret"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_OWNER_TOKEN_SECRET", None)

    def test_bind_requires_owner_token(self) -> None:
        db = _make_db()
        with self.assertRaises(AuthError):
            handlers.bind_shopping_token(db, "mkt_test", {})
        # admin token 可绑定
        res = handlers.bind_shopping_token(
            db, "mkt_test", {"_auth_token": "test-admin", "shopping_cli_token": "shop-abc"}
        )
        self.assertTrue(res["ok"])
        self.assertTrue(res["bound"])

    def test_status_no_token_echo(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        merchant_shopping.bind_shopping_token(conn, "mkt_test", "secret-token")
        conn.commit()
        conn.close()
        res = handlers.shopping_token_status(db, "mkt_test", {"_auth_token": "test-admin"})
        self.assertTrue(res["bound"])
        self.assertNotIn("token", res)  # 不回显明文

    def test_portal_products_page(self) -> None:
        page = portal_products()
        self.assertIn("__html__", page)
        self.assertIn("我的商品", page["__html__"])
        self.assertIn("上传商品", page["__html__"])
        # 免费通道文案：免费 10 件 + 超限申请令牌
        self.assertIn("免费", page["__html__"])
        # 临时商家 id 方案已移除：商品一律挂在注册即分配的真实 merchant_id 下
        self.assertNotIn("mkt_free_", page["__html__"])


class FreeTierShoppingTest(unittest.TestCase):
    """免费通道：无 owner token 的账号会话 + 注册即分配的 merchant_id。"""

    def setUp(self) -> None:
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": "test-admin",
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": "test-secret",
                "KIWI_CATALOG_PROXY_TOKEN": "proxy-secret",
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.db = _make_db()
        self.account_id, self.merchant_id, self.session = self._make_account(
            "free@acme.example"
        )

    def _make_account(self, email: str) -> tuple[int, str, str]:
        """注册账号并签发会话，返回 (account_id, merchant_id, session_token)。"""
        conn = open_connection(self.db)
        try:
            account = accounts_service.register_account(
                conn, email=email, password="password-123"
            )
            session = accounts_service.create_session(conn, int(account["account_id"]))
            conn.commit()
            return int(account["account_id"]), str(account["merchant_id"]), session
        finally:
            conn.close()

    def test_registration_assigns_merchant_id(self) -> None:
        """注册完成即分配 merchant_id，格式与审批签发一致（mkt_<slug>_<rand>），且幂等。"""
        self.assertRegex(self.merchant_id, r"^mkt_[a-z0-9-]+_.+")
        conn = open_connection(self.db)
        try:
            # 幂等：重复调用不重新分配
            self.assertEqual(
                accounts_service.ensure_merchant_id(conn, self.account_id),
                self.merchant_id,
            )
        finally:
            conn.close()

    def test_existing_account_backfilled_on_session_resolve(self) -> None:
        """存量无 merchant_id 的账号：会话解析时懒回填，回填后保持稳定。"""
        conn = open_connection(self.db)
        try:
            conn.execute(
                "update merchant_accounts set merchant_id = '' where account_id = ?",
                (self.account_id,),
            )
            conn.commit()
            account = accounts_service.resolve_session(conn, self.session)
            self.assertIsNotNone(account)
            backfilled = str(account["merchant_id"])
            self.assertRegex(backfilled, r"^mkt_[a-z0-9-]+_.+")
            # 落库 + 再次解析保持同一 id（不重复分配）
            row = conn.execute(
                "select merchant_id from merchant_accounts where account_id = ?",
                (self.account_id,),
            ).fetchone()
            self.assertEqual(str(row["merchant_id"]), backfilled)
            again = accounts_service.resolve_session(conn, self.session)
            self.assertEqual(str(again["merchant_id"]), backfilled)
        finally:
            conn.close()

    def test_session_auth_free_tier_crud(self) -> None:
        """账号会话 + 自己的 merchant_id：list/create/update 走代理凭据调 shopping-cli。"""
        payload = {"kiwi_session": self.session}
        calls: list[tuple[str, str, str]] = []
        bodies: list[dict] = []

        def fake_request(method: str, path: str, token: str, body: dict | None = None) -> dict:
            calls.append((method, path, token))
            if body is not None:
                bodies.append(body)
            if method == "GET":
                return {"results": [{"sku": "VQ-001"}]}
            return {"ok": True}

        with mock.patch.object(merchant_shopping, "_shopping_request", fake_request):
            res = handlers.list_products(self.db, self.merchant_id, payload)
            self.assertTrue(res["ok"])
            self.assertEqual(res["results"], [{"sku": "VQ-001"}])
            res = handlers.create_product(
                self.db,
                self.merchant_id,
                {**payload, "sku": "VQ-001", "title": "t", "price": 1, "stock": 1},
            )
            self.assertTrue(res["ok"])
            res = handlers.update_product(
                self.db, self.merchant_id, "VQ-001", {**payload, "title": "t2"}
            )
            self.assertTrue(res["ok"])
        # 三次调用都以共享代理凭据为 Bearer token
        self.assertEqual([c[2] for c in calls], ["proxy-secret"] * 3)
        # 商品挂在账号真实 merchant_id 下（GET 经 query string，POST/PATCH 经 body）
        self.assertIn(f"merchant_id={self.merchant_id}", calls[0][1])
        self.assertEqual([b["merchant_id"] for b in bodies], [self.merchant_id] * 2)
        # 会话凭据不转发给 shopping-cli
        for body in bodies:
            self.assertNotIn("kiwi_session", body)

    def test_quota_403_guidance_propagates(self) -> None:
        """shopping-cli 配额 403 的引导文案原样透传到 handler 响应错误。"""
        guidance = "免费额度（10 件商品）已用完——请到 Kiwi Catalog 门户「我的账户」申请商家令牌"
        body = ('{"ok": false, "error": "' + guidance + '"}').encode("utf-8")

        def fake_urlopen(req: object, timeout: int = 0) -> object:
            raise urllib.error.HTTPError(
                "http://test/products", 403, "Forbidden", None, io.BytesIO(body)
            )

        with mock.patch.object(merchant_shopping.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(ValidationError) as ctx:
                handlers.create_product(
                    self.db,
                    self.merchant_id,
                    {"kiwi_session": self.session, "sku": "VQ-011", "title": "t", "price": 1, "stock": 1},
                )
        self.assertIn(guidance, str(ctx.exception))

    def test_session_cannot_use_other_accounts_merchant_id(self) -> None:
        """账号会话不能操作他人 merchant_id（403 PermissionDenied）。"""
        _other_id, other_merchant_id, _other_session = self._make_account(
            "other@acme.example"
        )
        with mock.patch.object(merchant_shopping, "_shopping_request", return_value={"results": []}):
            with self.assertRaises(PermissionDenied):
                handlers.list_products(
                    self.db, other_merchant_id, {"kiwi_session": self.session}
                )

    def test_owner_token_still_wins_over_proxy(self) -> None:
        """回归：已签发 owner token 的商家仍用 owner token（代理凭据不抢占）。"""
        conn = open_connection(self.db)
        conn.execute(
            "update merchant_tokens set token_encrypted = ? where merchant_id = 'mkt_test'",
            (accounts_service.encrypt_merchant_token("owner-token-123"),),
        )
        conn.commit()
        conn.close()
        calls: list[str] = []

        def fake_request(method: str, path: str, token: str, body: dict | None = None) -> dict:
            calls.append(token)
            return {"results": []}

        with mock.patch.object(merchant_shopping, "_shopping_request", fake_request):
            res = handlers.list_products(self.db, "mkt_test", {"_auth_token": "test-admin"})
            self.assertTrue(res["ok"])
        self.assertEqual(calls, ["owner-token-123"])

    def test_no_proxy_no_owner_token_original_error(self) -> None:
        """代理凭据未配置 + 无 owner token → 原有 ValidationError 文案不变。"""
        os.environ.pop("KIWI_CATALOG_PROXY_TOKEN", None)
        with self.assertRaises(ValidationError) as ctx:
            handlers.list_products(self.db, "mkt_test", {"_auth_token": "test-admin"})
        self.assertEqual(
            str(ctx.exception), "商家尚未签发 owner token——请先在 My Account 申请令牌"
        )


if __name__ == "__main__":
    unittest.main()
