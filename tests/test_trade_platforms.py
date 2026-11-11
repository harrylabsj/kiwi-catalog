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

"""交易平台规则（schema v54）：默认种子、CRUD 校验与公开读取。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.api.handlers.trade_platforms import list_marketplace_platforms
from kiwi_catalog.core.errors import ConflictError, NotFoundError, ValidationError
from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import trade_platforms


class TradePlatformRulesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = Path(tempfile.mkdtemp()) / "catalog.sqlite"
        self.conn = open_connection(self.db)

    def tearDown(self) -> None:
        self.conn.close()

    def test_schema_v54_and_defaults(self) -> None:
        self.assertEqual(CURRENT_SCHEMA_VERSION, 54)
        rows = trade_platforms.list_platforms(self.conn)
        self.assertEqual([row["id"] for row in rows], ["jd", "taobao", "tmall"])
        self.assertTrue(all(row["enabled"] for row in rows))
        self.assertEqual(rows[0]["domain"], "jd.com")

    def test_create_update_delete_roundtrip(self) -> None:
        created = trade_platforms.create_platform(
            self.conn,
            {
                "id": "pinduoduo",
                "label": "拼多多",
                "domain": "yangkeduo.com",
                "url_template": "https://mobile.yangkeduo.com/goods.html?goods_id={id}",
                "sort_order": 40,
            },
        )
        self.assertEqual(created["id"], "pinduoduo")
        self.assertTrue(created["enabled"])

        updated = trade_platforms.update_platform(
            self.conn, "pinduoduo", {"label": "拼多多商城", "enabled": False}
        )
        self.assertEqual(updated["label"], "拼多多商城")
        self.assertFalse(updated["enabled"])
        self.assertEqual(
            [row["id"] for row in trade_platforms.list_platforms(self.conn, enabled_only=True)],
            ["jd", "taobao", "tmall"],
        )

        trade_platforms.delete_platform(self.conn, "pinduoduo")
        self.assertIsNone(trade_platforms.get_platform(self.conn, "pinduoduo"))

    def test_duplicate_and_missing_ids(self) -> None:
        with self.assertRaises(ConflictError):
            trade_platforms.create_platform(
                self.conn,
                {
                    "id": "jd",
                    "label": "京东",
                    "domain": "jd.com",
                    "url_template": "https://item.jd.com/{id}.html",
                },
            )
        with self.assertRaises(NotFoundError):
            trade_platforms.update_platform(self.conn, "missing", {"label": "x"})
        with self.assertRaises(NotFoundError):
            trade_platforms.delete_platform(self.conn, "missing")

    def test_template_and_domain_validation(self) -> None:
        base = {"id": "demo", "label": "演示", "domain": "example.com"}
        invalid = [
            {**base, "url_template": "http://example.com/item/{id}"},
            {**base, "url_template": "https://other.example.org/item/{id}"},
            {**base, "url_template": "https://example.com/item"},
            {**base, "url_template": "https://example.com/item/{sku}"},
            {**base, "url_template": "https://user:pass@example.com/item/{id}"},
        ]
        for payload in invalid:
            with self.assertRaises(ValidationError, msg=payload["url_template"]):
                trade_platforms.create_platform(self.conn, payload)

        for bad_domain in ("https://example.com", "example.com/path", "bad domain"):
            with self.assertRaises(ValidationError, msg=bad_domain):
                trade_platforms.create_platform(
                    self.conn,
                    {**base, "domain": bad_domain, "url_template": "https://example.com/{id}"},
                )

    def test_build_product_url(self) -> None:
        url = trade_platforms.build_product_url(
            "jd", "12345678901234567890", "https://item.jd.com/{id}.html", "jd.com"
        )
        self.assertEqual(url, "https://item.jd.com/12345678901234567890.html")
        for bad_id in ("0", "001", "-1", "1e20", "https://item.jd.com/1.html"):
            with self.assertRaises(ValidationError, msg=bad_id):
                trade_platforms.build_product_url(
                    "jd", bad_id, "https://item.jd.com/{id}.html", "jd.com"
                )

    def test_public_handler_hides_operator_fields(self) -> None:
        result = list_marketplace_platforms(self.db, {}, {})
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["platforms"]), 3)
        self.assertEqual(
            set(result["platforms"][0]),
            {"id", "label", "domain", "url_template", "sort_order"},
        )


if __name__ == "__main__":
    unittest.main()
