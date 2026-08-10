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

"""买家搜索事件保留测试（v18 运营数据源）。

- 服务层：record_search_event / list_recent_search_events（往返 + 有界保留）；
- 搜索 handler：search_agent_catalog / v1_search_agents / v1_search_listings 埋点；
- admin API：search_events 需 admin token，返回最近事件；
- portal 页：portal_admin_searches 在开关开启时返回 HTML。
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.api.handlers import admin as admin_handlers
from kiwi_catalog.api.handlers import agent_catalog as agent_handlers
from kiwi_catalog.api.handlers import listings as listings_handlers
from kiwi_catalog.api.handlers.portal import portal_admin_searches
from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import buyer_search_events


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    conn.close()
    return db


class BuyerSearchEventsServiceTest(unittest.TestCase):
    def test_record_and_list_roundtrip(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        buyer_search_events.record_search_event(
            conn,
            search_type="listing",
            query="保温杯",
            filters={"category": "kitchenware"},
            result_count=1,
            result_summary=[{"listing_id": "lst_1", "title": "保温杯"}],
        )
        buyer_search_events.record_search_event(
            conn, search_type="agent", query="xyz", result_count=0, result_summary=[]
        )
        conn.commit()
        events = buyer_search_events.list_recent_search_events(conn)
        self.assertEqual(len(events), 2)
        # 倒序：最近的在最前
        self.assertEqual(events[0]["search_type"], "agent")
        self.assertEqual(events[0]["query"], "xyz")
        self.assertEqual(events[0]["result_count"], 0)
        self.assertEqual(events[1]["result_count"], 1)
        self.assertEqual(events[1]["filters"]["category"], "kitchenware")
        self.assertEqual(events[1]["result_summary"][0]["listing_id"], "lst_1")
        conn.close()

    def test_bounded_retention(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        for i in range(buyer_search_events.MAX_RETAINED_EVENTS + 50):
            buyer_search_events.record_search_event(conn, search_type="agent", query=f"q{i}")
        conn.commit()
        n = conn.execute("select count(*) from buyer_search_events").fetchone()[0]
        self.assertLessEqual(n, buyer_search_events.MAX_RETAINED_EVENTS)
        conn.close()

    def test_filters_and_summary_stored_as_json_dumps(self) -> None:
        """审查 P2-06：filters/result_summary 必须以 json.dumps 写入（原始列为
        合法 JSON，可被 json.loads 反序列化）——不能用 str()/手工拼接。"""
        import json

        db = _make_db()
        conn = open_connection(db)
        filters = {"category": "kitchenware", "region": "sh", "multi": ["a", "b"]}
        summary = [{"listing_id": "lst_1", "title": "保温杯"}]
        buyer_search_events.record_search_event(
            conn,
            search_type="listing",
            query="保温杯",
            filters=filters,
            result_count=1,
            result_summary=summary,
        )
        conn.commit()
        row = conn.execute(
            "select filters_json, result_summary_json,"
            " json_valid(filters_json) as filters_valid,"
            " json_valid(result_summary_json) as summary_valid"
            " from buyer_search_events order by event_id desc limit 1"
        ).fetchone()
        # 原始列是 json.dumps 产物且通过 SQLite json_valid：可反序列化、与输入一致。
        self.assertEqual(row["filters_valid"], 1)
        self.assertEqual(row["summary_valid"], 1)
        self.assertEqual(json.loads(row["filters_json"]), filters)
        self.assertEqual(json.loads(row["result_summary_json"]), summary)
        # 反序列化后 round-trip 一致。
        events = buyer_search_events.list_recent_search_events(conn)
        self.assertEqual(events[0]["filters"], filters)
        self.assertEqual(events[0]["result_summary"], summary)
        conn.close()

    def test_long_values_produce_valid_bounded_json(self) -> None:
        """审查 P2-06：超长 filters/result_summary 值 → 落库仍是**合法 JSON**
        （修复前 ``json.dumps(...)[:cap]`` 在字符串/结构中间切断产生非法 JSON），
        长度受限且读取可反序列化。"""
        import json

        db = _make_db()
        conn = open_connection(db)
        long_val = "x" * 5000
        long_title = "长标题" + "啊" * 9000
        buyer_search_events.record_search_event(
            conn,
            search_type="listing",
            query="q",
            filters={"category": long_val, "region": "sh", "tag": "t"},
            result_count=1,
            result_summary=[
                {"listing_id": "lst_1", "title": long_title},
                {"listing_id": "lst_2", "title": "短"},
            ],
        )
        conn.commit()
        row = conn.execute(
            "select filters_json, result_summary_json,"
            " json_valid(filters_json) as filters_valid,"
            " json_valid(result_summary_json) as summary_valid"
            " from buyer_search_events order by event_id desc limit 1"
        ).fetchone()
        # SQLite json_valid() = 1：列必须是合法 JSON——修复前 [:cap] 切断 →
        # json_valid 返回 0 且 json.loads 抛异常。
        self.assertEqual(row["filters_valid"], 1)
        self.assertEqual(row["summary_valid"], 1)
        filters = json.loads(row["filters_json"])
        summary = json.loads(row["result_summary_json"])
        self.assertLessEqual(len(row["filters_json"]), buyer_search_events._FILTERS_CAP)
        self.assertLessEqual(len(row["result_summary_json"]), buyer_search_events._SUMMARY_CAP)
        # 结构保真：非超长字段保留原值，超长值被截断但仍为字符串。
        self.assertEqual(filters["region"], "sh")
        self.assertEqual(filters["tag"], "t")
        self.assertLess(len(filters["category"]), 5000)
        self.assertEqual(len(summary), 2)
        self.assertEqual(summary[1]["title"], "短")
        self.assertLess(len(summary[0]["title"]), 9000)
        # 读取端反序列化一致。
        events = buyer_search_events.list_recent_search_events(conn)
        self.assertEqual(events[0]["filters"]["region"], "sh")
        self.assertEqual(len(events[0]["result_summary"]), 2)
        conn.close()

    def test_invalid_json_in_db_falls_back_to_defaults(self) -> None:
        """审查 P2-06：DB 中非法 JSON 的 filters/result_summary（脏行）不得让
        list_recent_search_events 崩——回退默认值（filters={}, result_summary=[]）。"""
        db = _make_db()
        conn = open_connection(db)
        # 手工插入一行 corrupt JSON（模拟历史脏数据 / 手工篡改）。
        conn.execute(
            "insert into buyer_search_events"
            " (search_type, query, filters_json, result_count, result_summary_json, created_at)"
            " values ('listing', '脏行', '{not-json', 3, '[unclosed', '2026-08-10T00:00:00+00:00')"
        )
        buyer_search_events.record_search_event(conn, search_type="agent", query="正常行")
        conn.commit()
        events = buyer_search_events.list_recent_search_events(conn)
        self.assertEqual(len(events), 2)
        dirty = next(e for e in events if e["query"] == "脏行")
        self.assertEqual(dirty["filters"], {})
        self.assertEqual(dirty["result_summary"], [])
        self.assertEqual(dirty["result_count"], 3)
        clean = next(e for e in events if e["query"] == "正常行")
        self.assertEqual(clean["filters"], {})
        self.assertEqual(clean["result_summary"], [])
        conn.close()


class BuyerSearchEventsHandlersTest(unittest.TestCase):
    def test_legacy_agents_search_records_event(self) -> None:
        db = _make_db()
        agent_handlers.search_agent_catalog(db, {"q": "保温杯"})
        conn = open_connection(db)
        events = buyer_search_events.list_recent_search_events(conn)
        conn.close()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["search_type"], "agent")
        self.assertEqual(events[0]["query"], "保温杯")

    def test_v1_agents_search_records_event(self) -> None:
        db = _make_db()
        agent_handlers.v1_search_agents(db, {"q": "xyz"})
        conn = open_connection(db)
        events = buyer_search_events.list_recent_search_events(conn)
        conn.close()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["search_type"], "agent")
        self.assertEqual(events[0]["result_count"], 0)  # 未命中也记录

    def test_listings_search_records_event(self) -> None:
        db = _make_db()
        listings_handlers.v1_search_listings(db, {"q": "保温杯"})
        conn = open_connection(db)
        events = buyer_search_events.list_recent_search_events(conn)
        conn.close()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["search_type"], "listing")


class BuyerSearchEventsAdminTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = "test-admin"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)

    def test_admin_searches_requires_token_and_returns_events(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        buyer_search_events.record_search_event(conn, search_type="listing", query="咖啡")
        conn.commit()
        conn.close()
        with self.assertRaises(AuthError):
            admin_handlers.search_events(db, {}, {})
        res = admin_handlers.search_events(db, {"_auth_token": "test-admin"}, {})
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["results"]), 1)
        self.assertEqual(res["results"][0]["query"], "咖啡")

    def test_portal_searches_page(self) -> None:
        os.environ["KIWI_CATALOG_PORTAL_ADMIN_ENABLED"] = "1"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_PORTAL_ADMIN_ENABLED", None)
        page = portal_admin_searches()
        self.assertIn("__html__", page)
        self.assertIn("买家搜索事件", page["__html__"])


if __name__ == "__main__":
    unittest.main()
