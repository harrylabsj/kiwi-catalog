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


if __name__ == "__main__":
    unittest.main()
