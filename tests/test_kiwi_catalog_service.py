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

"""kiwi-catalog standalone service smoke tests (阶段 1 裁剪原型).

Verifies the route-level cut of the Agent Catalog domain into an
independently deployable service:

- a fresh DB file initializes itself (full-schema superset in phase 1)
  and the catalog write/read path works end to end (register → search →
  stats);
- marketplace routes (/merchants, /products, /negotiation/*) are 404;
- the hosted publication surface (/v1/hosted/* Agent Card / UCP) is
  present;
- the hosted negotiation endpoint (/a2a/agents/{id}) is excluded (切割
  分水岭).

See docs/shopping-cli-agent-catalog-extraction-plan-v1.0.md.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api.route_registry import catalog_route_info


def _request(app: object, method: str, path: str, body: dict | None = None, token: str = "") -> tuple[int, dict]:
    sent: list[dict] = []
    body_bytes = json.dumps(body or {}).encode("utf-8")
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body_bytes, "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    headers = [(b"content-type", b"application/json")]
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode("latin1")))

    async def run() -> None:
        await app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "query_string": b"",
                "headers": headers,
            },
            receive,
            send,
        )

    asyncio.run(run())
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(out.decode("utf-8") or "{}")


class KiwiCatalogServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_file = Path(self.tmp.name) / "catalog.sqlite"
        self.app = create_catalog_app(self.db_file)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_catalog_routes_are_served(self) -> None:
        paths = {route.path for route in catalog_route_info()}
        self.assertIn("/v1/agent-catalog/agents/register", paths)
        self.assertIn("/v1/agent-catalog/agents/search", paths)
        self.assertIn("/v1/agent-catalog/agents/{catalog_agent_id}/verify", paths)
        self.assertIn("/v1/agent-catalog/agents/{catalog_agent_id}/suspend", paths)
        self.assertIn("/v1/hosted/agents/{catalog_agent_id}/agent-card.json", paths)
        self.assertIn("/health", paths)
        # 切割分水岭：托管协商端点被排除。
        self.assertNotIn("/a2a/agents/{catalog_agent_id}", paths)

    def test_register_search_stats_end_to_end_on_fresh_db(self) -> None:
        status, body = _request(
            self.app, "POST", "/v1/agent-catalog/agents/register",
            {"domain": "merchant.example", "idempotency_key": "reg-1"},
        )
        self.assertEqual(status, 200, body)
        catalog_agent_id = body["catalog_agent"]["catalog_agent_id"]

        status, body = _request(self.app, "GET", "/v1/agent-catalog/agents/search")
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body["results"]), 1)
        self.assertEqual(body["results"][0]["catalog_agent_id"], catalog_agent_id)

        status, body = _request(self.app, "GET", "/v1/agent-catalog/agents")
        self.assertEqual(status, 200, body)
        self.assertEqual(len(body["results"]), 1)

    def test_register_rejects_unknown_fields_schema_hard_rejection(self) -> None:
        # CD #8：register-input.schema.json additionalProperties:false ——
        # 私有经营数据（floor_price / cost / 私密库存）与未知字段在 schema
        # 层拒绝（422），即使带了合法 domain。
        status, body = _request(
            self.app, "POST", "/v1/agent-catalog/agents/register",
            {
                "domain": "merchant.example",
                "idempotency_key": "reg-private-1",
                "floor_price": {"currency": "CNY", "amount_minor": 100},
            },
        )
        # 项目约定 ValidationError → 400（双栈一致；422 是 FastAPI 默认形状）
        self.assertEqual(status, 400, body)
        self.assertIn("register payload invalid", body.get("error", ""))

        status, body = _request(
            self.app, "POST", "/v1/agent-catalog/agents/register",
            {"domain": "merchant.example", "idempotency_key": "reg-unknown-1", "bogus_field": "x"},
        )
        self.assertEqual(status, 400, body)

        # 认证/幂等字段剥离后合法注册不受影响
        status, body = _request(
            self.app, "POST", "/v1/agent-catalog/agents/register",
            {
                "domain": "merchant.example",
                "idempotency_key": "reg-legit-1",
                "owner_token": "whatever-token",
                "display_name": "Acme",
                "hosting_mode": "direct",
                "capabilities": ["com.example.shopping.negotiation"],
            },
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(body["catalog_agent"]["catalog_agent_id"])

    def test_marketplace_routes_are_cut(self) -> None:
        for path in ("/merchants", "/products", "/negotiation/pending-messages", "/conversations"):
            status, body = _request(self.app, "GET", path)
            self.assertEqual(status, 404, f"{path}: {body}")

    def test_hosted_negotiation_endpoint_is_cut(self) -> None:
        status, body = _request(
            self.app, "POST", "/a2a/agents/cagt_any",
            {"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {}},
        )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
