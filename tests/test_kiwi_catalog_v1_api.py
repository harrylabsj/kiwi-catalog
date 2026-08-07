"""kiwi-catalog /v1/agents 新 API + 三正交状态域集成测试（v0.3 §7/§8/§9）。

覆盖：
- register 带 handoff_destination_types / capabilities / display_name 落库
  （public-only；非法 handoff 词表拒绝）；
- /v1/agents/search 三态域 + handoff 词表过滤（AND 语义）；
- /v1/agents/{id} record 形状（三域原样、legacy 折叠列同步）；
- 三域迁移：级别晋升/降级、freshness、行政处置、reinstate 保留级别；
- 折叠投影一致性：set_state_domains 后 verification_status 与 fold 一致。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.agent_catalog.state_domains import InvalidStateTransitionError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.agent_catalog.sqlite_repository import require_catalog_agent

REGISTER_BODY = {
    "domain": "acme.example",
    "display_name": "Acme Merchant",
    "agent_card_url": "https://acme.example/.well-known/agent-card.json",
    "hosting_mode": "direct_only",
    "handoff_destination_types": ["external_checkout_url", "quote_document"],
    "capabilities": ["com.harrylabsj.shopping.capability:catalog"],
}


def _call_http(app, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
    """裸 ASGI 调用（fallback 栈），返回 (status, parsed json)。

    query 参数经 scope["query_string"] 传递（fallback ASGI 从 scope 解析，
    不解析 path 中的 ?…）。
    """
    path_only = path.split("?", 1)[0]
    query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
    scope = {
        "type": "http",
        "method": method,
        "path": path_only,
        "headers": [],
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


class KiwiCatalogV1ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)

    def _register(self, overrides: dict | None = None) -> dict:
        body = {**REGISTER_BODY, **(overrides or {})}
        status, payload = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, payload)
        return payload

    def test_register_stores_public_fields_and_three_domains(self) -> None:
        payload = self._register()
        agent = payload["agent"]
        self.assertEqual(agent["display_name"], "Acme Merchant")
        # canonical 输入（direct_only）在写边界归一化为 legacy 存储值（direct）——
        # wire schema 两种都收，消费方 normalize 无感知。
        self.assertEqual(agent["hosting_mode"], "direct")
        self.assertEqual(agent["handoff_destination_types"], ["external_checkout_url", "quote_document"])
        self.assertEqual(agent["capabilities"], ["com.harrylabsj.shopping.capability:catalog"])
        # 三正交域初始值
        self.assertEqual(agent["verification_level"], "discovered")
        self.assertEqual(agent["freshness_state"], "fresh")
        self.assertEqual(agent["administrative_state"], "active")
        self.assertTrue(payload["verification_enqueued"])

    def test_register_rejects_parallel_supports_vocabulary(self) -> None:
        status, payload = _call_http(
            self.app,
            "POST",
            "/v1/agents/register",
            json.dumps(
                {**REGISTER_BODY, "handoff_destination_types": ["supports_external_checkout"]}
            ).encode(),
        )
        self.assertEqual(status, 400)
        self.assertIn("handoff_destination_types", str(payload.get("error", "")))

    def test_search_filters_by_three_domains_and_handoff(self) -> None:
        self._register()
        # 全量命中
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?handoff_destination_types=external_checkout_url",
        )
        self.assertEqual(len(payload["results"]), 1)
        # handoff 不匹配 → 空
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?handoff_destination_types=platform_deep_link",
        )
        self.assertEqual(payload["results"], [])
        # 三态域过滤
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?verification_level=discovered&freshness_state=fresh&administrative_state=active",
        )
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?administrative_state=suspended",
        )
        self.assertEqual(payload["results"], [])

    def test_get_agent_record_shape(self) -> None:
        registered = self._register()
        cagt_id = registered["agent"]["catalog_agent_id"]
        status, payload = _call_http(self.app, "GET", f"/v1/agents/{cagt_id}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["agent"]["catalog_agent_id"], cagt_id)
        self.assertNotIn("floor_price_minor", payload["agent"])  # #8 private-only

    def test_unknown_agent_404(self) -> None:
        status, _ = _call_http(self.app, "GET", "/v1/agents/does_not_exist")
        self.assertEqual(status, 404)


class ThreeDomainPersistenceTest(unittest.TestCase):
    """三域写入 → 折叠投影一致性 + 迁移约束（repository 层）。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        body = json.dumps(REGISTER_BODY).encode()
        _, payload = _call_http(self.app, "POST", "/v1/agents/register", body)
        self.cagt_id = payload["agent"]["catalog_agent_id"]

    def _row(self) -> dict:
        with db_session(self.db_path) as conn:
            return require_catalog_agent(conn, self.cagt_id)

    def test_set_state_domains_syncs_fold_projection(self) -> None:
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(
                conn,
                self.cagt_id,
                verification_level="domain_verified",
                freshness_state="stale",
                administrative_state="active",
            )
        row = self._row()
        self.assertEqual(row["verification_level"], "domain_verified")
        self.assertEqual(row["freshness_state"], "stale")
        self.assertEqual(row["verification_status"], "stale")  # 折叠：stale > level

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="suspended")
        row = self._row()
        self.assertEqual(row["verification_status"], "suspended")  # 折叠：suspended 最重

    def test_reinstate_preserves_verification_level(self) -> None:
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, verification_level="commerce_verified")
            service = VerificationService(conn)
            service.suspend(self.cagt_id, actor="admin", reason="test")
            row = require_catalog_agent(conn, self.cagt_id)
            self.assertEqual(row["administrative_state"], "suspended")
            self.assertEqual(row["verification_level"], "commerce_verified")
            service.reinstate(self.cagt_id, actor="admin", reason="test")
            row = require_catalog_agent(conn, self.cagt_id)
        # v0.3 语义：恢复后级别保留（legacy 重置为 discovered 的行为已被取代）
        self.assertEqual(row["administrative_state"], "active")
        self.assertEqual(row["verification_level"], "commerce_verified")
        self.assertEqual(row["verification_status"], "commerce_verified")

    def test_mark_stale_keeps_level(self) -> None:
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, verification_level="agent_verified")
            service = VerificationService(conn)
            service.mark_stale(self.cagt_id)
            row = require_catalog_agent(conn, self.cagt_id)
        self.assertEqual(row["freshness_state"], "stale")
        self.assertEqual(row["verification_level"], "agent_verified")
        self.assertEqual(row["verification_status"], "stale")

    def test_rejected_admin_is_terminal_for_verify(self) -> None:
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="rejected")
            service = VerificationService(conn)
            with self.assertRaises(InvalidStateTransitionError):
                service.verify(self.cagt_id)

    def test_rejected_fold_and_registration_reopen(self) -> None:
        """行政 REJECTED 折叠为 rejected；同域可重新注册（v0.3 §7.3 可恢复终态）。"""
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="rejected")
            row = require_catalog_agent(conn, self.cagt_id)
        self.assertEqual(row["verification_status"], "rejected")

        status, payload = _call_http(
            self.app,
            "POST",
            "/v1/agents/register",
            json.dumps({**REGISTER_BODY, "domain": "acme.example"}).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["agent"]["catalog_agent_id"], self.cagt_id)


if __name__ == "__main__":
    unittest.main()
