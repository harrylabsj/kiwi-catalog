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

import os
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.api.handlers import merchant_shopping as handlers
from kiwi_catalog.api.handlers.portal import portal_products
from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.db.session import now_iso, open_connection
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
        self.assertIn("shopping-token", page["__html__"])


if __name__ == "__main__":
    unittest.main()
