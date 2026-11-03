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

"""公开主页 / 名片隔离与暂停/撤回展示语义（合成数据）。"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from kiwi_catalog.a2a.card_store import (
    CardQuarantineError,
    compute_etag,
    read_active_card,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    new_catalog_agent_id,
    upsert_catalog_agent,
)
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services.account_agents import _publication_summary
from kiwi_catalog.services.merchant_publications import (
    has_public_content,
    public_merchant_home_url_for,
)

MERCHANT_ID = "mkt_public_quarantine_1"
SECRET = "SYNTH-CARD-QUARANTINE-ONLY"


def _call_http(app, method: str, path: str, query_string: bytes = b""):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"content-type", b"application/json")],
        "query_string": query_string,
        "http_version": "1.1",
        "scheme": "http",
    }
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in received if m["type"] == "http.response.start")
    chunks = b"".join(
        m.get("body", b"") for m in received if m["type"] == "http.response.body"
    )
    return start["status"], chunks.decode("utf-8", "replace")


class PublicCardQuarantineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        self.agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn,
                self.agent_id,
                merchant_id=MERCHANT_ID,
                display_name="隔离测试商家",
                canonical_domain="quarantine.example",
            )

    def _card(self, description: str) -> dict:
        return {
            "name": "隔离测试商家",
            "description": description,
            "version": "1.0.0",
            "url": "https://runtime.quarantine.example",
            "supportedInterfaces": [
                {
                    "url": "https://runtime.quarantine.example/a2a",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0",
                }
            ],
        }

    def _seed_card(self, card: dict, *, state: str = "ACTIVE") -> str:
        etag = compute_etag(card)
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert or replace into agent_card_versions"
                " (catalog_agent_id, card_revision, wire_profile, canonical_bytes,"
                " digest, created_by, created_at) values (?, 1, 'a2a-1.0', ?, ?, 'test', ?)",
                (
                    self.agent_id,
                    json.dumps(
                        card, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ),
                    "sha256:" + "c" * 64,
                    "2026-10-01T00:00:00+00:00",
                ),
            )
            conn.execute(
                "insert or replace into card_publications (catalog_agent_id,"
                " active_revision, publication_state, etag, updated_at)"
                " values (?, 1, ?, ?, ?)",
                (self.agent_id, state, etag, "2026-10-01T00:00:00+00:00"),
            )
        return etag

    def _state(self, state: str) -> None:
        with db_session(self.db_path) as conn:
            conn.execute(
                "update card_publications set publication_state = ?"
                " where catalog_agent_id = ?",
                (state, self.agent_id),
            )

    def test_contaminated_signed_card_is_quarantined(self) -> None:
        card = self._card(f"门禁链接 https://shop.example.com/a?sharecode={SECRET}")
        etag = self._seed_card(card)
        with db_session(self.db_path) as conn:
            with self.assertRaises(CardQuarantineError):
                read_active_card(conn, self.agent_id)
            summary = _publication_summary(conn, self.agent_id)
            self.assertTrue(summary["quarantined"])
            self.assertTrue(summary["republish_required"])
            # 摘要/ETag 不被改写（不伪造发布方摘要）。
            self.assertEqual(summary["etag"], etag)
            self.assertEqual(summary["digest"], "sha256:" + "c" * 64)
            self.assertFalse(has_public_content(conn, MERCHANT_ID))
            self.assertEqual(public_merchant_home_url_for(conn, MERCHANT_ID), "")

        status, raw = _call_http(self.app, "GET", f"/m/{MERCHANT_ID}")
        self.assertEqual(status, 404, raw)
        self.assertNotIn(SECRET, raw)

    def test_paused_card_still_visible_and_withdrawn_not_visible(self) -> None:
        self._seed_card(self._card("暂停仍公开的介绍"), state="PAUSED")
        status, raw = _call_http(self.app, "GET", f"/m/{MERCHANT_ID}")
        self.assertEqual(status, 200, raw)
        self.assertIn("暂停仍公开的介绍", raw)

        self._state("WITHDRAWN")
        status, raw = _call_http(self.app, "GET", f"/m/{MERCHANT_ID}")
        self.assertEqual(status, 404, raw)

    def test_clean_card_keeps_etag_contract(self) -> None:
        etag = self._seed_card(self._card("正常公开介绍"))
        with db_session(self.db_path) as conn:
            card, stored_etag, state = read_active_card(conn, self.agent_id)
        self.assertEqual(state, "ACTIVE")
        self.assertEqual(stored_etag, etag)
        self.assertEqual(compute_etag(card), etag)
        self.assertEqual(card["description"], "正常公开介绍")


    def test_public_home_paginates_past_dangerous_listings_without_writes(self) -> None:
        """连续危险 listing 不阻断后续正常商品的分页；GET 不回写状态。"""
        secret = "SYNTH-PUBLIC-HOME-SHARE-CODE-7"
        dangerous_ts = "2026-11-02T00:00:00+00:00"
        normal_ts = "2026-01-01T00:00:00+00:00"
        with db_session(self.db_path) as conn:
            for i in range(520):
                conn.execute(
                    "insert into commerce_listings (listing_id, listing_type, owner_agent_id,"
                    " merchant_id, source_product_ref, title, summary, category,"
                    " listing_digest, publication_state, governance_hold,"
                    " listing_freshness_state, published_at, updated_at, fresh_until, created_at)"
                    " values (?, 'product', ?, ?, ?, ?, ?, 'home', ?, 'ACTIVE', 0,"
                    " 'FRESH', ?, ?, '2099-01-01T00:00:00+00:00', ?)",
                    (
                        f"lst_home_d_{i:04d}",
                        self.agent_id,
                        MERCHANT_ID,
                        f"SKU-HD-{i:04d}",
                        f"主页危险商品 {i}",
                        f"主页危险 https://shop.example.com/a?sharecode={secret}-{i}",
                        f"sha256:{i:064d}",
                        dangerous_ts,
                        dangerous_ts,
                        dangerous_ts,
                    ),
                )
            conn.execute(
                "insert into commerce_listings (listing_id, listing_type, owner_agent_id,"
                " merchant_id, source_product_ref, title, summary, category,"
                " listing_digest, publication_state, governance_hold,"
                " listing_freshness_state, published_at, updated_at, fresh_until, created_at)"
                " values ('lst_home_normal', 'product', ?, ?, 'SKU-HOME-NORMAL',"
                " '主页正常商品', '正常公开商品', 'home', ?, 'ACTIVE', 0, 'FRESH', ?, ?,"
                " '2099-01-01T00:00:00+00:00', ?)",
                (
                    self.agent_id,
                    MERCHANT_ID,
                    "sha256:" + "a" * 64,
                    normal_ts,
                    normal_ts,
                    normal_ts,
                ),
            )

        status, first = _call_http(self.app, "GET", f"/m/{MERCHANT_ID}")
        self.assertEqual(status, 200, first)
        self.assertNotIn(secret, first)
        self.assertIn("下一页", first)

        status, second = _call_http(
            self.app, "GET", f"/m/{MERCHANT_ID}", query_string=b"page=11"
        )
        self.assertEqual(status, 200, second)
        self.assertIn("主页正常商品", second)
        self.assertNotIn(secret, second)

        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select publication_state, governance_hold from commerce_listings"
                " where listing_id = 'lst_home_d_0000'"
            ).fetchone()
        self.assertEqual(row["publication_state"], "ACTIVE")
        self.assertEqual(int(row["governance_hold"]), 0)


    def _seed_home_listings(self, count: int, safe_titles: dict[int, str]) -> None:
        secret = "SYNTH-HOME-BOUNDARY-SHARE-CODE"
        base = datetime(2026, 11, 2, tzinfo=UTC)
        with db_session(self.db_path) as conn:
            for index in range(1, count + 1):
                title = safe_titles.get(index, f"边界危险商品 {index}")
                summary = (
                    "正常公开商品"
                    if index in safe_titles
                    else f"危险 https://shop.example.com/a?sharecode={secret}-{index}"
                )
                updated = (base + timedelta(seconds=count - index)).isoformat()
                conn.execute(
                    "insert into commerce_listings (listing_id, listing_type, owner_agent_id,"
                    " merchant_id, source_product_ref, title, summary, category,"
                    " listing_digest, publication_state, governance_hold,"
                    " listing_freshness_state, published_at, updated_at, fresh_until, created_at)"
                    " values (?, 'product', ?, ?, ?, ?, ?, 'home', ?, 'ACTIVE', 0,"
                    " 'FRESH', ?, ?, '2099-01-01T00:00:00+00:00', ?)",
                    (
                        f"lst_boundary_{index:03d}",
                        self.agent_id,
                        MERCHANT_ID,
                        f"SKU-B-{index:03d}",
                        title,
                        summary,
                        f"sha256:{index:064d}",
                        updated,
                        updated,
                        updated,
                    ),
                )

    def test_public_home_page_boundary_does_not_duplicate_or_skip(self) -> None:
        """第 51 条只属于第 2 页；第 50 条安全项不得被补进第 1 页重复。"""
        self._seed_home_listings(
            52,
            {50: "边界第50条安全商品", 51: "边界第51条安全商品"},
        )
        status, first = _call_http(self.app, "GET", f"/m/{MERCHANT_ID}")
        self.assertEqual(status, 200, first)
        self.assertIn("边界第50条安全商品", first)
        self.assertNotIn("边界第51条安全商品", first)
        self.assertNotIn("SYNTH-HOME-BOUNDARY-SHARE-CODE", first)

        status, second = _call_http(
            self.app, "GET", f"/m/{MERCHANT_ID}", query_string=b"page=2"
        )
        self.assertEqual(status, 200, second)
        self.assertIn("边界第51条安全商品", second)
        self.assertNotIn("边界第50条安全商品", second)

    def test_public_home_all_hidden_page_is_empty_but_advances(self) -> None:
        """第 1–50 条全被隔离时返回空页 + 下一页；第 51 条只在第 2 页出现。"""
        self._seed_home_listings(51, {51: "边界第51条安全商品"})
        status, first = _call_http(self.app, "GET", f"/m/{MERCHANT_ID}")
        self.assertEqual(status, 200, first)
        self.assertNotIn("边界第51条安全商品", first)
        self.assertIn("下一页", first)

        status, second = _call_http(
            self.app, "GET", f"/m/{MERCHANT_ID}", query_string=b"page=2"
        )
        self.assertEqual(status, 200, second)
        self.assertIn("边界第51条安全商品", second)


if __name__ == "__main__":
    unittest.main()
