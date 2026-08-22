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

"""每日去重买家统计测试（v26，buyer_search_daily + /v1/admin/buyer-stats）。

- 服务层：record_buyer_search 去重（同买家同日 +1）、日作用域 hash
  （同身份跨天不同 hash）、匿名/未知 metric 静默跳过；
- buyer_daily_series：零填充连续日期；
- 搜索 handler：带/不带身份头的埋点（usage 总量 vs 去重买家）；
- admin API：buyer_stats 需 admin token、响应形状（distinct/identified/
  total/unidentified + today）；
- 关键词统计（v27，buyer_keyword_daily）：归一化、upsert 累加、
  zero_results 计数、空 query 跳过、top_keywords 排序/窗口/limit、
  端点 top_keywords/zero_hit_keywords 字段、搜索 handler 关键词埋点；
- portal 页（2026-08-22 合并）：旧 /portal/admin/buyer-stats 独立页 302
  跳转到 /portal/dashboard（双栈）；dashboard 渲染并入的买家搜索统计区块。
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.handlers import admin as admin_handlers
from kiwi_catalog.api.handlers import agent_catalog as agent_handlers
from kiwi_catalog.api.handlers import listings as listings_handlers
from kiwi_catalog.api.handlers.portal import portal_admin_buyer_stats, portal_dashboard
from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.services import buyer_stats, usage_metrics

ADMIN_TOKEN = "test-admin"
AGENT = usage_metrics.METRIC_BUYER_AGENT_SEARCH
LISTING = usage_metrics.METRIC_BUYER_LISTING_SEARCH


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    conn.close()
    return db


def _today() -> str:
    return now_iso()[:10]


class BuyerStatsServiceTest(unittest.TestCase):
    def test_dedup_per_buyer_per_day(self) -> None:
        """同一买家同日多次搜索：一行 count 累加；不同买家各自一行。"""
        db = _make_db()
        conn = open_connection(db)
        for _ in range(3):
            buyer_stats.record_buyer_search(conn, AGENT, "buyer-1")
        buyer_stats.record_buyer_search(conn, AGENT, "buyer-2")
        buyer_stats.record_buyer_search(conn, LISTING, "buyer-1")
        conn.commit()
        rows = conn.execute(
            "select metric, buyer_hash, count from buyer_search_daily order by metric, buyer_hash"
        ).fetchall()
        self.assertEqual(len(rows), 3)
        agent_rows = [r for r in rows if r["metric"] == AGENT]
        self.assertEqual(len(agent_rows), 2)
        self.assertEqual(sorted(int(r["count"]) for r in agent_rows), [1, 3])
        listing_rows = [r for r in rows if r["metric"] == LISTING]
        self.assertEqual(len(listing_rows), 1)
        self.assertEqual(int(listing_rows[0]["count"]), 1)
        conn.close()

    def test_hash_is_day_scoped_and_pseudonymous(self) -> None:
        """同一身份跨天 → 不同 hash（不可关联）；库中不出现原始身份。"""
        hash_d1 = buyer_stats._buyer_hash("2026-08-20", "buyer-1")
        hash_d2 = buyer_stats._buyer_hash("2026-08-21", "buyer-1")
        self.assertNotEqual(hash_d1, hash_d2)
        # 同日同身份稳定（去重前提），16 hex 截断
        self.assertEqual(hash_d1, buyer_stats._buyer_hash("2026-08-20", "buyer-1"))
        self.assertEqual(len(hash_d1), 16)

        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_search(conn, AGENT, "buyer-secret-token")
        conn.commit()
        row = conn.execute("select day, buyer_hash from buyer_search_daily").fetchone()
        self.assertEqual(row["day"], _today())
        self.assertEqual(row["buyer_hash"], buyer_stats._buyer_hash(_today(), "buyer-secret-token"))
        self.assertNotIn("buyer-secret-token", row["buyer_hash"])
        conn.close()

    def test_day_scoped_rows_across_days(self) -> None:
        """跨天记录（mock 日期）：同一身份落两行不同 hash。"""
        db = _make_db()
        conn = open_connection(db)
        with mock.patch.object(
            buyer_stats, "now_iso", return_value="2026-08-20T00:00:00+00:00"
        ):
            buyer_stats.record_buyer_search(conn, AGENT, "buyer-1")
        buyer_stats.record_buyer_search(conn, AGENT, "buyer-1")
        conn.commit()
        rows = conn.execute(
            "select day, buyer_hash from buyer_search_daily order by day"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["day"], "2026-08-20")
        self.assertEqual(rows[1]["day"], _today())
        self.assertNotEqual(rows[0]["buyer_hash"], rows[1]["buyer_hash"])
        conn.close()

    def test_anonymous_and_unknown_metric_skipped(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_search(conn, AGENT, None)
        buyer_stats.record_buyer_search(conn, AGENT, "")
        buyer_stats.record_buyer_search(conn, AGENT, "   ")
        buyer_stats.record_buyer_search(conn, "merchant_self_check", "buyer-1")
        buyer_stats.record_buyer_search(conn, "bogus_metric", "buyer-1")
        conn.commit()
        n = conn.execute("select count(*) from buyer_search_daily").fetchone()[0]
        self.assertEqual(n, 0)
        conn.close()

    def test_identity_from_payload_prefers_bearer(self) -> None:
        self.assertEqual(
            buyer_stats.buyer_identity_from_payload(
                {"_auth_token": "tok", "_buyer_id": "b1"}
            ),
            "tok",
        )
        self.assertEqual(buyer_stats.buyer_identity_from_payload({"_buyer_id": "b1"}), "b1")
        self.assertEqual(buyer_stats.buyer_identity_from_payload({}), "")
        self.assertEqual(buyer_stats.buyer_identity_from_payload(None), "")

    def test_daily_series_zero_fill(self) -> None:
        """无数据日期补 0；有数据日期给出 distinct（行数）与 identified（count 和）。"""
        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_search(conn, AGENT, "buyer-1")
        buyer_stats.record_buyer_search(conn, AGENT, "buyer-1")
        buyer_stats.record_buyer_search(conn, AGENT, "buyer-2")
        buyer_stats.record_buyer_search(conn, LISTING, "buyer-1")
        conn.commit()
        series = buyer_stats.buyer_daily_series(conn, days=14)
        self.assertEqual(len(series), 14)
        first_day = (dt.datetime.now(dt.UTC).date() - dt.timedelta(days=13)).isoformat()
        self.assertEqual(series[0]["day"], first_day)
        self.assertEqual(series[-1]["day"], _today())
        # 历史日全 0
        self.assertEqual(series[0]["distinct_buyers"], {AGENT: 0, LISTING: 0})
        self.assertEqual(series[0]["identified_events"], {AGENT: 0, LISTING: 0})
        today = series[-1]
        self.assertEqual(today["distinct_buyers"][AGENT], 2)
        self.assertEqual(today["identified_events"][AGENT], 3)
        self.assertEqual(today["distinct_buyers"][LISTING], 1)
        self.assertEqual(today["identified_events"][LISTING], 1)
        conn.close()

    def test_keyword_derived_matches_table_double_write(self) -> None:
        """Phase 3 Step A：access_log 派生关键词排行与旧表逐字段一致（双写对账）。"""
        from kiwi_catalog.services import access_log as access_log_service

        db = _make_db()
        for path, q, rc in [
            ("/v1/agents/search", "match tea", 3),   # 命中
            ("/v1/agents/search", "match tea", 0),   # 未命中
            ("/v1/agents/search", "MATCH TEA", 5),   # 大小写折叠 → 合并
            ("/v1/listings/search", "green tea", 5),  # listing 命中
            ("/v1/listings/search", "", 0),           # filter-only → 跳过
        ]:
            access_log_service.record_http_access(
                db,
                method="GET",
                path=path,
                query={"q": q},
                headers={"user-agent": "test"},
                client_ip="203.0.113.7",
                status=200,
                latency_ms=1,
                result_count=rc,
            )
        conn = open_connection(db)
        # 旧表同步写（模拟真实双写：各自连接）
        with open_connection(db) as c:
            buyer_stats.record_buyer_keyword(c, "agent", "match tea", 3)
            buyer_stats.record_buyer_keyword(c, "agent", "match tea", 0)
            buyer_stats.record_buyer_keyword(c, "agent", "MATCH TEA", 5)
            buyer_stats.record_buyer_keyword(c, "listing", "green tea", 5)
            buyer_stats.record_buyer_keyword(c, "listing", "", 0)  # 空 → 跳过
        derived = buyer_stats.top_keywords_from_access_log(conn, days=14)
        table = buyer_stats.top_keywords(conn, days=14)
        self.assertEqual(derived, table)
        # match tea 合并 3 次（2 命中 + 1 未命中），green tea 1 次命中
        by_kw = {r["keyword"]: r for r in derived}
        self.assertEqual(by_kw["match tea"]["searches"], 3)
        self.assertEqual(by_kw["match tea"]["zero_results"], 1)
        self.assertEqual(by_kw["match tea"]["agent_searches"], 3)
        self.assertEqual(by_kw["green tea"]["searches"], 1)
        self.assertEqual(by_kw["green tea"]["zero_results"], 0)
        self.assertEqual(by_kw["green tea"]["listing_searches"], 1)
        conn.close()

    def test_keyword_derived_skips_non_search_and_health(self) -> None:
        """派生只取 buyer_search 面：非搜索请求（merchant_write）与 /health 不进排行。"""
        from kiwi_catalog.services import access_log as access_log_service

        db = _make_db()
        for path, q, rc in [
            ("/v1/agents/search", "only real", 2),
            ("/v1/merchants/self", "not a search", 1),
            ("/health", "no", 1),
        ]:
            access_log_service.record_http_access(
                db,
                method="GET",
                path=path,
                query={"q": q},
                headers={},
                client_ip="203.0.113.7",
                status=200,
                latency_ms=1,
                result_count=rc,
            )
        conn = open_connection(db)
        derived = buyer_stats.top_keywords_from_access_log(conn, days=14)
        self.assertEqual([r["keyword"] for r in derived], ["only real"])
        conn.close()

    def test_keyword_source_env_switch(self) -> None:
        """env KIWI_CATALOG_KEYWORD_SOURCE 控制数据源：默认 access_log，可回退旧表。"""
        self.assertEqual(buyer_stats.keyword_source(), buyer_stats._KEYWORD_SOURCE_ACCESS_LOG)
        with mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_KEYWORD_SOURCE": "buyer_keyword_daily"},
            clear=False,
        ):
            self.assertEqual(buyer_stats.keyword_source(), buyer_stats._KEYWORD_SOURCE_TABLE)
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_KEYWORD_SOURCE": ""}, clear=False):
            self.assertEqual(buyer_stats.keyword_source(), buyer_stats._KEYWORD_SOURCE_ACCESS_LOG)


class BuyerStatsHandlersTest(unittest.TestCase):
    def test_v1_agents_search_records_distinct_buyer(self) -> None:
        db = _make_db()
        agent_handlers.v1_search_agents(db, {"q": "x"}, auth_payload={"_buyer_id": "b1"})
        agent_handlers.v1_search_agents(db, {"q": "y"}, auth_payload={"_buyer_id": "b1"})
        agent_handlers.v1_search_agents(db, {"q": "z"})  # 匿名
        conn = open_connection(db)
        series = buyer_stats.buyer_daily_series(conn, days=1)
        usage = usage_metrics.usage_series(conn, days=1)
        conn.close()
        # 同买家 2 次去重为 1；匿名不计买家但仍计 usage 总量
        self.assertEqual(series[-1]["distinct_buyers"][AGENT], 1)
        self.assertEqual(series[-1]["identified_events"][AGENT], 2)
        self.assertEqual(usage[-1]["counts"][AGENT], 3)

    def test_legacy_agents_search_records_distinct_buyer(self) -> None:
        db = _make_db()
        agent_handlers.search_agent_catalog(db, {"q": "x"}, auth_payload={"_buyer_id": "b1"})
        conn = open_connection(db)
        series = buyer_stats.buyer_daily_series(conn, days=1)
        conn.close()
        self.assertEqual(series[-1]["distinct_buyers"][AGENT], 1)

    def test_listings_search_records_distinct_buyer(self) -> None:
        db = _make_db()
        listings_handlers.v1_search_listings(db, {"q": "x"}, auth_payload={"_auth_token": "tok-1"})
        conn = open_connection(db)
        series = buyer_stats.buyer_daily_series(conn, days=1)
        conn.close()
        self.assertEqual(series[-1]["distinct_buyers"][LISTING], 1)
        self.assertEqual(series[-1]["distinct_buyers"][AGENT], 0)


class BuyerStatsAdminTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = ADMIN_TOKEN
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)

    def test_requires_admin_token(self) -> None:
        db = _make_db()
        with self.assertRaises(AuthError):
            admin_handlers.buyer_stats(db, {}, {})

    def test_response_shape_and_unidentified_derivation(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        # 买家 b1 搜 agent ×2、匿名搜 agent ×1、买家 b2 搜 listing ×1
        buyer_stats.record_buyer_search(conn, AGENT, "b1")
        buyer_stats.record_buyer_search(conn, AGENT, "b1")
        buyer_stats.record_buyer_search(conn, LISTING, "b2")
        usage_metrics.record_usage(conn, AGENT)
        usage_metrics.record_usage(conn, AGENT)
        usage_metrics.record_usage(conn, AGENT)
        usage_metrics.record_usage(conn, LISTING)
        conn.commit()
        conn.close()

        res = admin_handlers.buyer_stats(db, {"_auth_token": ADMIN_TOKEN}, {})
        self.assertTrue(res["ok"])
        self.assertEqual(res["days"], 14)
        self.assertEqual(len(res["series"]), 14)
        today = res["today"]
        self.assertEqual(today["day"], _today())
        self.assertEqual(today["distinct_buyers"], {AGENT: 1, LISTING: 1})
        self.assertEqual(today["identified_events"], {AGENT: 2, LISTING: 1})
        self.assertEqual(today["total_events"], {AGENT: 3, LISTING: 1})
        self.assertEqual(today["unidentified_events"], {AGENT: 1, LISTING: 0})
        self.assertEqual(res["series"][-1], today)

    def test_days_query_validation(self) -> None:
        from kiwi_catalog.core.errors import ValidationError

        db = _make_db()
        with self.assertRaises(ValidationError):
            admin_handlers.buyer_stats(db, {"_auth_token": ADMIN_TOKEN}, {"days": "abc"})
        res = admin_handlers.buyer_stats(db, {"_auth_token": ADMIN_TOKEN}, {"days": "7"})
        self.assertEqual(res["days"], 7)
        self.assertEqual(len(res["series"]), 7)


class BuyerStatsHttpTest(unittest.TestCase):
    """端到端（ASGI 双栈共用路由表）：X-Buyer-Id / Authorization 头经 transport
    合并进 payload，搜索埋点见到买家身份。"""

    def setUp(self) -> None:
        from kiwi_catalog.api.app import create_catalog_app

        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN}, clear=False
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _get(
        self, path: str, headers: dict[str, str] | None = None
    ) -> tuple[int, dict, dict[str, str]]:
        path_only = path.split("?", 1)[0]
        query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
        scope_headers: list[tuple[bytes, bytes]] = []
        for key, value in (headers or {}).items():
            scope_headers.append((key.lower().encode("latin1"), value.encode("latin1")))
        scope = {
            "type": "http",
            "method": "GET",
            "path": path_only,
            "headers": scope_headers,
            "query_string": query_bytes,
            "http_version": "1.1",
            "scheme": "http",
        }
        received: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg: dict) -> None:
            received.append(msg)

        asyncio.run(self.app(scope, receive, send))
        start = next(m for m in received if m["type"] == "http.response.start")
        chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
        try:
            payload = json.loads(chunks.decode())
        except json.JSONDecodeError:
            payload = {"_raw": chunks.decode()}
        headers = {
            k.decode("latin1").lower(): v.decode("latin1")
            for k, v in start.get("headers", [])
        }
        return start.get("status", 500), payload, headers

    def test_search_with_buyer_id_header_then_admin_stats(self) -> None:
        # 买家 b1（X-Buyer-Id）搜 agent ×2、搜 listing ×1；匿名搜 listing ×1
        for _ in range(2):
            status, _, _ = self._get("/v1/agents/search?q=x", headers={"X-Buyer-Id": "b1"})
            self.assertEqual(status, 200)
        self._get("/v1/listings/search?q=x", headers={"X-Buyer-Id": "b1"})
        self._get("/v1/listings/search?q=y")
        # legacy 搜索面同样埋点
        self._get("/v1/agent-catalog/agents/search?q=z", headers={"X-Buyer-Id": "b2"})

        status, res, _ = self._get(
            "/v1/admin/buyer-stats?days=1",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, res)
        today = res["today"]
        # b1 × agent + b2 × legacy agent → 2 个去重买家 / 3 个已识别事件
        self.assertEqual(today["distinct_buyers"][AGENT], 2)
        self.assertEqual(today["identified_events"][AGENT], 3)
        self.assertEqual(today["total_events"][AGENT], 3)
        self.assertEqual(today["unidentified_events"][AGENT], 0)
        # listing：b1 已识别 1 + 匿名 1 → distinct 1 / 未识别 1
        self.assertEqual(today["distinct_buyers"][LISTING], 1)
        self.assertEqual(today["identified_events"][LISTING], 1)
        self.assertEqual(today["total_events"][LISTING], 2)
        self.assertEqual(today["unidentified_events"][LISTING], 1)

    def test_admin_buyer_stats_requires_token_over_http(self) -> None:
        status, payload, _ = self._get("/v1/admin/buyer-stats")
        self.assertEqual(status, 403, payload)

    def test_bearer_token_counts_as_identity(self) -> None:
        self._get("/v1/agents/search?q=x", headers={"Authorization": "Bearer buyer-tok-9"})
        status, res, _ = self._get(
            "/v1/admin/buyer-stats?days=1",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, res)
        self.assertEqual(res["today"]["distinct_buyers"][AGENT], 1)

    def test_fallback_stack_merges_buyer_id_header(self) -> None:
        """fallback ASGI 栈（无 FastAPI 部署形态）同样合并 X-Buyer-Id。"""
        from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp

        self.app = MarketplaceASGIApp(self.db_path)
        self._get("/v1/listings/search?q=x", headers={"X-Buyer-Id": "fb-buyer"})
        status, res, _ = self._get(
            "/v1/admin/buyer-stats?days=1",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, res)
        self.assertEqual(res["today"]["distinct_buyers"][LISTING], 1)

    def test_old_buyer_stats_page_redirects_to_dashboard(self) -> None:
        """/portal/admin/buyer-stats 已并入 dashboard：开启时双栈 302 + Location。"""
        from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp

        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}, clear=False
        ):
            # FastAPI 栈（create_catalog_app 默认）
            status, _, headers = self._get("/portal/admin/buyer-stats")
            self.assertEqual(status, 302)
            self.assertEqual(headers.get("location"), "/portal/dashboard")
            # fallback 栈
            self.app = MarketplaceASGIApp(self.db_path)
            status, _, headers = self._get("/portal/admin/buyer-stats")
            self.assertEqual(status, 302)
            self.assertEqual(headers.get("location"), "/portal/dashboard")

    def test_old_buyer_stats_page_hidden_by_default_over_http(self) -> None:
        status, _, _ = self._get("/portal/admin/buyer-stats")
        self.assertEqual(status, 404)


class BuyerStatsPortalTest(unittest.TestCase):
    def test_page_hidden_by_default(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "KIWI_CATALOG_PORTAL_ADMIN_ENABLED"}
        with mock.patch.dict(os.environ, env, clear=True):
            page = portal_admin_buyer_stats()
            self.assertEqual(page.get("__status__"), 404)

    def test_page_enabled_redirects_to_dashboard(self) -> None:
        """独立买家统计页已并入 /portal/dashboard（2026-08-22）：开启时 302 跳转。"""
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}, clear=False
        ):
            page = portal_admin_buyer_stats()
            self.assertEqual(page, {"__redirect__": "/portal/dashboard"})

    def test_dashboard_renders_merged_buyer_sections(self) -> None:
        """合并后的运营 Dashboard 含买家搜索统计区块（KPI/柱状图/明细/关键词表）。"""
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_PORTAL_ADMIN_ENABLED": "1"}, clear=False
        ):
            page = portal_dashboard()
            html = page["__html__"]
            self.assertIn("运营 Dashboard", html)
            self.assertIn("买家搜索统计", html)
            self.assertIn("热门搜索关键词", html)
            self.assertIn("未命中关键词", html)
            self.assertIn("供需缺口", html)
            self.assertIn("/v1/admin/buyer-stats", html)
            self.assertIn("buyer_kpis", html)
            # 关键词表：每关键词一行 + 类型分布窄列（找商家 N · 找商品 M）
            self.assertIn("类型分布", html)
            self.assertIn("找商家", html)
            self.assertIn("找商品", html)
            # 访问洞察区块（access_log v28：漏斗/热度榜/登录失败）并入 dashboard
            self.assertIn("访问洞察", html)
            self.assertIn("搜索→查看漏斗", html)
            self.assertIn("funnel_kpis", html)
            self.assertIn("funnel_usage", html)
            self.assertIn("top_viewed", html)
            self.assertIn("login_failures", html)
            self.assertIn("renderAccessInsights", html)
            self.assertIn("/v1/admin/access-insights?days=14", html)
            self.assertIn("被查看最多的商家", html)
            # 同一 token 输入解锁全页（buyer-stats 不再有独立 token 表单）
            self.assertEqual(html.count('id="admin_token"'), 1)


class BuyerKeywordServiceTest(unittest.TestCase):
    def test_keyword_normalization(self) -> None:
        """NFKC + 去零宽字符 + trim + 折叠内部空白 + 小写 + 80 字符截断。"""
        self.assertEqual(buyer_stats._normalize_keyword("  保温  Cup\t\nSTANLEY "), "保温 cup stanley")
        self.assertEqual(buyer_stats._normalize_keyword(""), "")
        self.assertEqual(buyer_stats._normalize_keyword("   \t "), "")
        self.assertEqual(buyer_stats._normalize_keyword(None), "")
        self.assertEqual(buyer_stats._normalize_keyword(123), "")
        self.assertEqual(len(buyer_stats._normalize_keyword("x" * 200)), 80)

    def test_normalization_nfkc_and_zero_width(self) -> None:
        """全角/半角与兼容字符折到同一形式；零宽字符删除（2026-08-22 重复行修复）。"""
        self.assertEqual(buyer_stats._normalize_keyword("ＡＢＣ"), "abc")
        self.assertEqual(buyer_stats._normalize_keyword("ＡＢＣ"), buyer_stats._normalize_keyword("ABC"))
        # 全角空格 → 普通空格（参与折叠）
        self.assertEqual(buyer_stats._normalize_keyword("血压仪　家用"), "血压仪 家用")
        # 零宽字符（ZWSP/ZWNJ/ZWJ/BOM）删除
        self.assertEqual(buyer_stats._normalize_keyword("\u8840\u538b\u200b\u4eea\u200c\u5bb6\u200d\u7528\ufeff"), "血压仪家用")
        # 兼容字符（如全角数字/带圈数字）折到标准形式
        self.assertEqual(buyer_stats._normalize_keyword("２０２６"), "2026")
        # 归一化后为空（纯零宽）→ 跳过
        self.assertEqual(buyer_stats._normalize_keyword("\u200b\u200c\u200d\ufeff"), "")

    def test_nfkc_variants_record_as_one_keyword(self) -> None:
        """全角与零宽变体落库为同一行（record 期归一化）。"""
        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_keyword(conn, "agent", "血压仪", 1)
        buyer_stats.record_buyer_keyword(conn, "agent", "\u8840\u538b\u200b\u4eea", 1)
        buyer_stats.record_buyer_keyword(conn, "agent", "ＡＢＣ", 0)
        buyer_stats.record_buyer_keyword(conn, "agent", "abc", 0)
        conn.commit()
        rows = conn.execute(
            "select keyword, searches, zero_results from buyer_keyword_daily order by keyword"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["keyword"], "abc")
        self.assertEqual(int(rows[0]["searches"]), 2)
        self.assertEqual(int(rows[0]["zero_results"]), 2)
        self.assertEqual(rows[1]["keyword"], "血压仪")
        self.assertEqual(int(rows[1]["searches"]), 2)
        conn.close()

    def test_record_upsert_and_zero_results(self) -> None:
        """同关键词（归一化后相同）累加 searches；result_count==0 累加 zero_results。"""
        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_keyword(conn, "agent", "保温杯", 3)
        buyer_stats.record_buyer_keyword(conn, "agent", "  保温杯 ", 0)
        buyer_stats.record_buyer_keyword(conn, "agent", "Touch  Display", 0)
        buyer_stats.record_buyer_keyword(conn, "listing", "保温杯", 1)
        conn.commit()
        rows = conn.execute(
            "select search_type, keyword, searches, zero_results"
            " from buyer_keyword_daily order by search_type, keyword"
        ).fetchall()
        self.assertEqual(len(rows), 3)
        agent_cup = next(r for r in rows if r["search_type"] == "agent" and r["keyword"] == "保温杯")
        self.assertEqual(int(agent_cup["searches"]), 2)
        self.assertEqual(int(agent_cup["zero_results"]), 1)
        touch = next(r for r in rows if r["keyword"] == "touch display")
        self.assertEqual(int(touch["searches"]), 1)
        self.assertEqual(int(touch["zero_results"]), 1)
        listing_cup = next(r for r in rows if r["search_type"] == "listing")
        self.assertEqual(int(listing_cup["zero_results"]), 0)
        conn.close()

    def test_record_skips_bad_input(self) -> None:
        """空关键词 / 未知 search_type 静默跳过；坏 result_count 不抛错（按命中计）。"""
        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_keyword(conn, "agent", "", 0)
        buyer_stats.record_buyer_keyword(conn, "agent", "   ", 0)
        buyer_stats.record_buyer_keyword(conn, "agent", None, 0)
        buyer_stats.record_buyer_keyword(conn, "merchant", "保温杯", 0)
        buyer_stats.record_buyer_keyword(conn, "bogus", "保温杯", 0)
        buyer_stats.record_buyer_keyword(conn, "agent", "ok", "not-a-number")
        conn.commit()
        rows = conn.execute(
            "select keyword, searches, zero_results from buyer_keyword_daily"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["keyword"], "ok")
        self.assertEqual(int(rows[0]["searches"]), 1)
        self.assertEqual(int(rows[0]["zero_results"]), 0)
        conn.close()

    def test_top_keywords_ordering_window_limit(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        # 今日：a×3（1 未命中）、b×2（2 未命中）、c×1
        for _ in range(3):
            buyer_stats.record_buyer_keyword(conn, "agent", "a", 1)
        buyer_stats.record_buyer_keyword(conn, "agent", "a", 0)
        for _ in range(2):
            buyer_stats.record_buyer_keyword(conn, "agent", "b", 0)
        buyer_stats.record_buyer_keyword(conn, "listing", "c", 1)
        # 30 天前的旧数据：days=14 窗口外
        old_day = (dt.datetime.now(dt.UTC).date() - dt.timedelta(days=30)).isoformat()
        with mock.patch.object(
            buyer_stats, "now_iso", return_value=old_day + "T00:00:00+00:00"
        ):
            for _ in range(10):
                buyer_stats.record_buyer_keyword(conn, "agent", "old-hot", 0)
        conn.commit()

        top = buyer_stats.top_keywords(conn, days=14)
        self.assertEqual([k["keyword"] for k in top], ["a", "b", "c"])
        self.assertEqual(top[0]["searches"], 4)
        self.assertEqual(top[0]["zero_results"], 1)
        # 窗口外的不计入
        self.assertNotIn("old-hot", [k["keyword"] for k in top])
        wide = buyer_stats.top_keywords(conn, days=40)
        self.assertEqual(wide[0]["keyword"], "old-hot")

        zero_hits = buyer_stats.top_keywords(conn, days=14, sort="zero_results")
        self.assertEqual([k["keyword"] for k in zero_hits], ["b", "a", "c"])
        self.assertEqual(zero_hits[0]["zero_results"], 2)

        limited = buyer_stats.top_keywords(conn, days=14, limit=2)
        self.assertEqual(len(limited), 2)
        conn.close()

    def test_top_keywords_merges_across_search_types(self) -> None:
        """同一关键词跨 agent/listing 搜索合并为一行，分列两类计数
        （2026-08-22 修复：此前按 (keyword, search_type) 分组 → 重复行）。"""
        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_keyword(conn, "agent", "血压仪", 0)
        buyer_stats.record_buyer_keyword(conn, "agent", "血压仪", 1)
        buyer_stats.record_buyer_keyword(conn, "listing", "血压仪", 0)
        buyer_stats.record_buyer_keyword(conn, "listing", "咖啡机", 1)
        conn.commit()
        top = buyer_stats.top_keywords(conn, days=14)
        keywords = [k["keyword"] for k in top]
        self.assertEqual(keywords, ["血压仪", "咖啡机"])  # 每关键词一行
        merged = top[0]
        self.assertEqual(
            merged,
            {
                "keyword": "血压仪",
                "searches": 3,
                "zero_results": 2,
                "agent_searches": 2,
                "listing_searches": 1,
            },
        )
        zero_hits = buyer_stats.top_keywords(conn, days=14, sort="zero_results")
        self.assertEqual([k["keyword"] for k in zero_hits], ["血压仪", "咖啡机"])
        conn.close()


class BuyerKeywordHandlersTest(unittest.TestCase):
    def test_search_with_zero_results_records_keyword(self) -> None:
        """空库搜索（0 结果）→ 关键词行 zero_results=1；三个搜索面都埋点。"""
        db = _make_db()
        agent_handlers.v1_search_agents(db, {"q": "保温杯"})
        agent_handlers.search_agent_catalog(db, {"q": "保温杯"})
        listings_handlers.v1_search_listings(db, {"q": "咖啡机"})
        conn = open_connection(db)
        rows = conn.execute(
            "select search_type, keyword, searches, zero_results from buyer_keyword_daily"
        ).fetchall()
        conn.close()
        self.assertEqual(len(rows), 2)
        agent_row = next(r for r in rows if r["search_type"] == "agent")
        # legacy + v1 两个搜索面同一关键词 → 同一行累加
        self.assertEqual(agent_row["keyword"], "保温杯")
        self.assertEqual(int(agent_row["searches"]), 2)
        self.assertEqual(int(agent_row["zero_results"]), 2)
        listing_row = next(r for r in rows if r["search_type"] == "listing")
        self.assertEqual(listing_row["keyword"], "咖啡机")
        self.assertEqual(int(listing_row["zero_results"]), 1)

    def test_empty_query_is_not_a_keyword(self) -> None:
        """filter-only 搜索（无 q）不记关键词。"""
        db = _make_db()
        agent_handlers.v1_search_agents(db, {"category": "tea"})
        listings_handlers.v1_search_listings(db, {"category": "tea"})
        conn = open_connection(db)
        n = conn.execute("select count(*) from buyer_keyword_daily").fetchone()[0]
        conn.close()
        self.assertEqual(n, 0)

    def test_same_keyword_across_agent_and_listing_search_merges(self) -> None:
        """找商家 + 找商品搜同一关键词 → 排行里一行，带两类计数。"""
        db = _make_db()
        agent_handlers.v1_search_agents(db, {"q": "血压仪"})
        listings_handlers.v1_search_listings(db, {"q": "血压仪"})
        conn = open_connection(db)
        top = buyer_stats.top_keywords(conn, days=14)
        conn.close()
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0]["keyword"], "血压仪")
        self.assertEqual(top[0]["searches"], 2)
        self.assertEqual(top[0]["zero_results"], 2)
        self.assertEqual(top[0]["agent_searches"], 1)
        self.assertEqual(top[0]["listing_searches"], 1)


class BuyerKeywordAdminTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = ADMIN_TOKEN
        # Phase 3 Step A：本类测旧聚合表数据源（回退开关）；access_log 派生的
        # 端点形状由 test_keyword_derived_matches_table_double_write 覆盖。
        os.environ["KIWI_CATALOG_KEYWORD_SOURCE"] = buyer_stats._KEYWORD_SOURCE_TABLE
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_KEYWORD_SOURCE", None)

    def test_response_includes_keyword_rankings(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        buyer_stats.record_buyer_keyword(conn, "agent", "保温杯", 0)
        buyer_stats.record_buyer_keyword(conn, "agent", "保温杯", 1)
        buyer_stats.record_buyer_keyword(conn, "listing", "咖啡机", 0)
        conn.commit()
        conn.close()
        res = admin_handlers.buyer_stats(db, {"_auth_token": ADMIN_TOKEN}, {"days": "7"})
        self.assertTrue(res["ok"])
        top = res["top_keywords"]
        self.assertEqual(
            top,
            [
                {
                    "keyword": "保温杯",
                    "searches": 2,
                    "zero_results": 1,
                    "agent_searches": 2,
                    "listing_searches": 0,
                },
                {
                    "keyword": "咖啡机",
                    "searches": 1,
                    "zero_results": 1,
                    "agent_searches": 0,
                    "listing_searches": 1,
                },
            ],
        )
        zero_hits = res["zero_hit_keywords"]
        self.assertEqual([k["keyword"] for k in zero_hits], ["保温杯", "咖啡机"])
        # 原有字段保持（向后兼容，纯新增）
        self.assertIn("series", res)
        self.assertIn("today", res)
        self.assertEqual(res["days"], 7)


if __name__ == "__main__":
    unittest.main()
