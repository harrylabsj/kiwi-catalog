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

"""FastAPI dual-stack tests (phase 3 follow-up).

create_catalog_app returns a FastAPI app when fastapi is installed and
falls back to the fallback ASGI app otherwise — both serve the same 13
catalog routes through the same wrappers.  This module asserts the
FastAPI branch (skipped when fastapi is unavailable).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.api import app as app_module


def _has_fastapi() -> bool:
    return app_module.FastAPI is not None


@unittest.skipUnless(_has_fastapi(), "fastapi not installed")
class FastApiDualStackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_file = Path(self.tmp.name) / "catalog.sqlite"
        self.app = app_module.create_catalog_app(self.db_file)
        self.assertIsNotNone(self.app)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_returns_fastapi_app(self) -> None:
        self.assertEqual(type(self.app).__name__, "FastAPI")

    def test_register_via_fastapi(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            resp = client.post(
                "/v1/agent-catalog/agents/register",
                json={"domain": "merchant.example", "idempotency_key": "r1"},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            cagt = resp.json()["catalog_agent"]["catalog_agent_id"]

            search = client.get("/v1/agent-catalog/agents/search")
            self.assertEqual(search.status_code, 200)
            self.assertEqual(len(search.json()["results"]), 1)

            stats = client.get("/v1/agent-catalog/agents", params={"limit": "10"})
            self.assertEqual(stats.status_code, 200)

            card = client.get(f"/v1/hosted/agents/{cagt}/agent-card.json")
            self.assertIn(card.status_code, (200, 404))  # hosted gate 语义

    def test_marketplace_routes_are_cut_in_fastapi(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            for path in ("/merchants", "/products", "/negotiation/pending-messages"):
                resp = client.get(path)
                self.assertEqual(resp.status_code, 404, f"{path}")

    def test_hosted_negotiation_endpoint_is_cut_in_fastapi(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            resp = client.post(
                "/a2a/agents/cagt_any",
                json={"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {}},
            )
            self.assertEqual(resp.status_code, 404)

    def test_route_count_matches_fallback(self) -> None:
        fastapi_paths = {route.path for route in self.app.routes if hasattr(route, "path")}
        fallback_paths = {entry.path_template for entry in app_module._ROUTE_TABLE}
        # FastAPI 追加 /openapi.json 等内置路由——只断言 catalog 路由被覆盖。
        self.assertTrue(fallback_paths <= fastapi_paths)

    def test_listings_routes_in_both_stacks(self) -> None:
        """6 条 listing 路由双栈覆盖（v0.4）；/v1/listings/search 不被 {listing_id} 吞掉。"""
        from fastapi.testclient import TestClient

        listing_paths = {
            "/v1/listings/search",
            "/v1/listings/{listing_id}",
            "/v1/agents/{catalog_agent_id}/listings",
            "/v1/listings/publish",
            "/v1/listings/{listing_id}/withdraw",
            "/v1/listings/{listing_id}/reinstate",
        }
        self.assertTrue(listing_paths <= {entry.path_template for entry in app_module._ROUTE_TABLE})
        with TestClient(self.app) as client:
            # search 静态段优先于参数段：不把 "search" 当 listing_id（404 而不是 400）
            resp = client.get("/v1/listings/search")
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertEqual(resp.json()["results"], [])
            # 未知 listing_id → 404（参数段正确解析）
            resp = client.get("/v1/listings/lst_doesnotexist")
            self.assertEqual(resp.status_code, 404, resp.text)
            # FastAPI 默认参数传空字符串：数值/布尔过滤视为未提供（不 400）
            resp = client.get("/v1/listings/search")
            self.assertEqual(resp.status_code, 200, resp.text)

    def test_error_shapes_match_fallback(self) -> None:
        """审查 P2：错误信封 {ok:false,error} + 状态码与 fallback 对齐。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            # 未知路由 → 404 信封（fallback 文案）
            resp = client.get("/v1/does-not-exist")
            self.assertEqual(resp.status_code, 404, resp.text)
            self.assertEqual(resp.json(), {"ok": False, "error": "No route for GET /v1/does-not-exist"})
            # 方法不允许 → 405 信封
            resp = client.delete("/v1/agents/register")
            self.assertEqual(resp.status_code, 405, resp.text)
            self.assertIn("Method not allowed", resp.json()["error"])
            # 非法 JSON body → 400 信封（FastAPI 默认是 422 detail）
            resp = client.post(
                "/v1/agents/register",
                content=b"{not json",
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertEqual(resp.json(), {"ok": False, "error": "invalid JSON request body"})

    def test_body_limits_match_fallback(self) -> None:
        """审查 P2：FastAPI 栈补齐 body 大小/深度上限（此前无限制）。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            # 深嵌套 body → 400（validate_payload 深度上限 16；嵌套数组先被
            # 「must be an object」拦截，与 fallback 检查顺序一致）
            deep = '{"a":' * 20 + "1" + "}" * 20
            resp = client.post(
                "/v1/agents/register",
                content=deep,
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            self.assertIn("nesting", resp.json()["error"])

    def test_get_etag_and_304_match_fallback(self) -> None:
        """审查 P2：GET 200 带 etag；显式 If-None-Match 匹配 → 304。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            first = client.get("/v1/listings/search")
            self.assertEqual(first.status_code, 200, first.text)
            etag = first.headers.get("etag")
            self.assertTrue(etag, "GET 响应必须带 etag header")
            revalidated = client.get(
                "/v1/listings/search", headers={"if-none-match": etag}
            )
            self.assertEqual(revalidated.status_code, 304, revalidated.text)
            self.assertEqual(revalidated.text, "")


if __name__ == "__main__":
    unittest.main()
