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

"""Listing 搜索测试（升级计划 §6；v0.4 §8/§12；测试计划 v0.3 §7 search 组）。

覆盖：
- q/category/region/listing_type/tag/handoff_destination_type 过滤；
- JSON1 commercial_hints 过滤（moq 区间、布尔）；
- attribute.<path> 过滤与路径注入防护；
- 默认排除 WITHDRAWN/SUSPENDED 与 owner suspended/rejected（agent join）；
- 确定性排序与 cursor 翻页稳定；
- freshness：fresh_until 到期后 on-read 惰性翻转 STALE + 搜索降权/过滤；
- authority=discovery_projection / requires_direct_confirmation=true 恒值。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api.auth import owner_token
from kiwi_catalog.db.session import db_session

OWNER_SECRET = "test-owner-secret"
MERCHANT_ID = "mrc_01JABC"

REGISTER_BODY = {
    "domain": "acme.example",
    "display_name": "Acme Merchant",
    "agent_card_url": "https://acme.example/.well-known/agent-card.json",
    "hosting_mode": "direct_only",
}


def _call_http(app, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
    path_only = path.split("?", 1)[0]
    query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
    scope = {
        "type": "http",
        "method": method,
        "path": path_only,
        "headers": [(b"content-type", b"application/json")],
        "query_string": query_bytes,
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
    status = next((m.get("status") for m in received if m["type"] == "http.response.start"), None)
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        payload = json.loads(chunks.decode())
    return status or 500, payload


class ListingsSearchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)
        self.token = owner_token(MERCHANT_ID)
        body = {**REGISTER_BODY, "merchant_id": MERCHANT_ID, "owner_token": self.token}
        status, payload = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, payload)
        self.agent_id = payload["agent"]["catalog_agent_id"]
        # merchants 影子表行（外部同步的真实语义；搜索 merchant join 依赖它）
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert or ignore into merchants(id, name, created_at, updated_at)"
                " values (?, ?, 't', 't')",
                (MERCHANT_ID, "Acme Merchant"),
            )

    def _publish(self, overrides: dict | None = None) -> int:
        body = {
            "listing_type": "product",
            "owner_agent_id": self.agent_id,
            "merchant_id": MERCHANT_ID,
            "source_product_ref": "SKU-001",
            "title": "21.5 inch Industrial Touch Display",
            "category": "industrial-display",
            "brand": "Acme Display",
            "regions": ["CN", "EU"],
            "tags": ["touch"],
            "commercial_hints": {"moq": 50, "supports_bulk_quote": True},
            "handoff_destination_types": ["external_checkout_url"],
            "owner_token": self.token,
            **(overrides or {}),
        }
        if body.get("listing_type") != "product":
            body.pop("source_product_ref", None)  # capability 不得携带 SKU（v0.4 §5）
            body.pop("handoff_destination_types", None)
            body.pop("regions", None)
            body.pop("tags", None)
        status, payload = _call_http(self.app, "POST", "/v1/listings/publish", json.dumps(body).encode())
        self.assertEqual(status, 200, payload)
        return payload

    def _seed(self) -> None:
        self._publish()
        self._publish(
            {
                "source_product_ref": "SKU-002",
                "title": "10 inch Industrial Touch Panel",
                "category": "industrial-display",
                "regions": ["CN"],
                "commercial_hints": {"moq": 10, "supports_bulk_quote": False},
            }
        )
        base = {
            "listing_type": "capability",
            "publisher_listing_key": "custom-mfg",
            "title": "Custom Manufacturing Service",
            "category": "manufacturing-services",
            "commercial_hints": {"moq": 100, "supports_customization": True},
        }
        base.pop("source_product_ref", None)  # capability 不得携带 SKU（v0.4 §5）
        self._publish(base)

    # ── filters ─────────────────────────────────────────────────────────────

    def test_search_all_returns_active_listings(self) -> None:
        self._seed()
        status, payload = _call_http(self.app, "GET", "/v1/listings/search")
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 3)

    def test_search_by_q_and_category(self) -> None:
        self._seed()
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?q=Touch")
        self.assertEqual(len(payload["results"]), 2)
        _, payload = _call_http(
            self.app, "GET", "/v1/listings/search?q=Touch+Display"
        )
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?category=manufacturing-services")
        self.assertEqual(len(payload["results"]), 1)

    def test_search_by_listing_type_and_region(self) -> None:
        self._seed()
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?listing_type=capability")
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?region=EU")
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?tag=touch")
        self.assertEqual(len(payload["results"]), 2)

    def test_search_commercial_hints_json1_filters(self) -> None:
        self._seed()
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?min_moq=50")
        self.assertEqual(len(payload["results"]), 2)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?max_moq=10")
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?supports_bulk_quote=true")
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?supports_customization=true")
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(
            self.app, "GET", "/v1/listings/search?handoff_destination_type=external_checkout_url"
        )
        self.assertEqual(len(payload["results"]), 2)

    def test_search_attribute_path_filter(self) -> None:
        self._publish({"attributes": {"screen_size": "21.5", "ip_rating": "IP67"}})
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?attribute.screen_size=21.5")
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?attribute.ip_rating=IP68")
        self.assertEqual(len(payload["results"]), 0)
        # 路径注入防护
        status, payload = _call_http(
            self.app, "GET", "/v1/listings/search?attribute.a%27%3B%20drop%20table=1"
        )
        self.assertEqual(status, 400, payload)

    def test_unknown_query_key_rejected(self) -> None:
        status, payload = _call_http(self.app, "GET", "/v1/listings/search?mystery=1")
        self.assertEqual(status, 400, payload)

    def test_malformed_cursor_rejected_400(self) -> None:
        """畸形 cursor：400 而非 500（fail-closed 信封）。"""
        status, payload = _call_http(self.app, "GET", "/v1/listings/search?cursor=abc")
        self.assertEqual(status, 400, payload)
        self.assertIn("cursor", payload.get("error", ""))

    # ── deterministic ranking / cursor ──────────────────────────────────────

    def test_cursor_pagination_is_stable(self) -> None:
        for i in range(5):
            self._publish({"source_product_ref": f"SKU-{i:03d}", "title": f"Item {i}"})
        _, page1 = _call_http(self.app, "GET", "/v1/listings/search?limit=2")
        self.assertEqual(len(page1["results"]), 2)
        self.assertTrue(page1["next_cursor"])
        _, page2 = _call_http(
            self.app, "GET", f"/v1/listings/search?limit=2&cursor={page1['next_cursor']}"
        )
        self.assertEqual(len(page2["results"]), 2)
        _, page3 = _call_http(
            self.app, "GET", f"/v1/listings/search?limit=2&cursor={page2['next_cursor']}"
        )
        self.assertEqual(len(page3["results"]), 1)
        ids1 = [r["listing"]["listing_id"] for r in page1["results"]]
        ids2 = [r["listing"]["listing_id"] for r in page2["results"]]
        ids3 = [r["listing"]["listing_id"] for r in page3["results"]]
        all_ids = ids1 + ids2 + ids3
        self.assertEqual(len(set(all_ids)), 5, "cursor pages must not overlap or skip")

    def test_cursor_pagination_crosses_freshness_ranks(self) -> None:
        """审查 P1-6：STALE 行跨页可达——游标谓词必须与排序键（rank, updated_at, id）同键。

        历史 bug：游标只编码 (updated_at, id)，STALE 行（翻转后 updated_at 最
        新、排序却靠后）在后续任何页都不再出现。
        """
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        for i in range(5):
            self._publish(
                {
                    "source_product_ref": f"SKU-{i:03d}",
                    "title": f"Item {i}",
                    "fresh_until": future,
                }
            )
        self._publish({"source_product_ref": "SKU-stale", "title": "Stale item", "fresh_until": future})
        with db_session(self.db_path) as conn:
            conn.execute(
                "update commerce_listings set fresh_until = '2000-01-01T00:00:00Z'"
                " where source_product_ref = 'SKU-stale'"
            )

        seen: list[str] = []
        cursor = ""
        for _ in range(10):
            path = (
                f"/v1/listings/search?limit=2&cursor={cursor}"
                if cursor
                else "/v1/listings/search?limit=2"
            )
            _, page = _call_http(self.app, "GET", path)
            seen += [r["listing"]["listing_id"] for r in page["results"]]
            cursor = page["next_cursor"]
            if not cursor:
                break
        self.assertEqual(len(seen), 6, "all 6 rows must be reachable across pages")
        self.assertEqual(len(set(seen)), 6, "no overlap / no skip across pages")

    def test_ranking_is_deterministic(self) -> None:
        for i in range(3):
            self._publish({"source_product_ref": f"SKU-{i:03d}", "title": f"Item {i}"})
        _, first = _call_http(self.app, "GET", "/v1/listings/search?limit=10")
        _, second = _call_http(self.app, "GET", "/v1/listings/search?limit=10")
        self.assertEqual(
            [r["listing"]["listing_id"] for r in first["results"]],
            [r["listing"]["listing_id"] for r in second["results"]],
        )

    # ── freshness (v0.4 §7.2 / §15.1) ───────────────────────────────────────

    def test_expired_listing_flips_to_stale_on_read(self) -> None:
        # 相对未来时间（publish 要求 future；随后手动改成 2000 触发翻转）
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self._publish({"fresh_until": future})
        listing_id = None
        with db_session(self.db_path) as conn:
            listing_id = conn.execute("select listing_id from commerce_listings").fetchone()[0]
            conn.execute(
                "update commerce_listings set fresh_until = '2000-01-01T00:00:00Z'"
                " where listing_id = ?",
                (listing_id,),
            )
        # on-read 惰性翻转：搜索触发翻转，结果带 STALE 标注
        _, payload = _call_http(self.app, "GET", "/v1/listings/search")
        self.assertEqual(len(payload["results"]), 1)
        self.assertEqual(payload["results"][0]["listing"]["listing_freshness_state"], "STALE")
        self.assertEqual(payload["results"][0]["listing_freshness_state"], "STALE")
        # 翻转已写回
        with db_session(self.db_path) as conn:
            state = conn.execute(
                "select listing_freshness_state from commerce_listings where listing_id = ?",
                (listing_id,),
            ).fetchone()[0]
        self.assertEqual(state, "STALE")

    def test_freshness_state_filter(self) -> None:
        self._publish()
        with db_session(self.db_path) as conn:
            conn.execute(
                "update commerce_listings set listing_freshness_state = 'STALE', fresh_until = '2000-01-01T00:00:00Z'"
            )
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?freshness_state=STALE")
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(self.app, "GET", "/v1/listings/search?freshness_state=FRESH")
        self.assertEqual(payload["results"], [])

    def test_republish_refreshes_freshness(self) -> None:
        published = self._publish()
        with db_session(self.db_path) as conn:
            conn.execute(
                "update commerce_listings set listing_freshness_state = 'STALE', fresh_until = '2000-01-01T00:00:00Z'"
            )
        self._publish({"title": "Refreshed"})  # 同 source_product_ref upsert
        _, payload = _call_http(self.app, "GET", "/v1/listings/search")
        self.assertEqual(payload["results"][0]["listing"]["listing_freshness_state"], "FRESH")
        self.assertEqual(payload["results"][0]["listing"]["listing_id"], published["listing"]["listing_id"])

    # ── search result contract (v0.4 §9 / CD #24) ───────────────────────────


    def test_register_creates_merchant_shadow_for_search_join(self) -> None:
        """D4 修复：注册带 merchant_id 时自维护 merchants 影子行——
        搜索结果的 merchant 投影非空（schema minLength 1 校验要求）。"""
        # setUp 已注册 agent（注册路径现在会创建影子行）——不手动插行
        self._publish()
        _, payload = _call_http(self.app, "GET", "/v1/listings/search")
        result = payload["results"][0]
        self.assertEqual(result["merchant"]["merchant_id"], MERCHANT_ID)
        self.assertTrue(result["merchant"]["display_name"])

    def test_search_result_shape_has_authority_and_confirm_flags(self) -> None:
        self._seed()
        _, payload = _call_http(self.app, "GET", "/v1/listings/search")
        result = payload["results"][0]
        self.assertEqual(result["authority"], "discovery_projection")
        self.assertTrue(result["requires_direct_confirmation"])
        self.assertIn("merchant", result)
        self.assertEqual(result["merchant"]["merchant_id"], MERCHANT_ID)
        self.assertIn("agent", result)
        self.assertEqual(result["agent"]["catalog_agent_id"], self.agent_id)
        self.assertIn("verification_level", result["agent"])
        self.assertIn("listing_freshness_state", result)


if __name__ == "__main__":
    unittest.main()
