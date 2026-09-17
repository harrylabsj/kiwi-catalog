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

"""Agent 新鲜度与心跳（WP6 / 发布计划 §3.6）测试。

覆盖：
- 读时只降不升：存储 fresh 且 last_seen_at 超 TTL → stale；存储 stale/unreachable 原样；
  无 last_seen_at 的旧数据保持 fresh（向后兼容）；
- 心跳：刷新 last_seen_at 并把 active 商家复活为 fresh；治理状态（suspended）不复活；
- 鉴权：心跳需 owner 凭据（未授权 401/403）。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from kiwi_catalog.agent_catalog.freshness import (
    agent_fresh_ttl_seconds,
    effective_freshness_state,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    new_catalog_agent_id,
    set_state_domains,
    touch_catalog_agent,
    upsert_catalog_agent,
)
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api.auth import owner_token as owner_token_for
from kiwi_catalog.db.session import db_session, open_connection

OWNER_SECRET = "test-owner-secret"


def _now(offset_seconds: int = 0) -> str:
    return (
        datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=offset_seconds)
    ).isoformat()


def _call_http(app, method: str, path: str, body: bytes = b"", authorization: str = ""):
    headers = [(b"content-type", b"application/json")]
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
        "http_version": "1.1",
        "scheme": "http",
    }
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in received if m["type"] == "http.response.start")
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload = json.loads(chunks.decode()) if chunks else {}
    return start.get("status", 500), payload


class FreshnessDerivationTest(unittest.TestCase):
    """读时有效新鲜度：只降不升 + 向后兼容。"""

    def test_fresh_within_ttl(self) -> None:
        record = {"freshness_state": "fresh", "last_seen_at": _now(-10)}
        self.assertEqual(effective_freshness_state(record, ttl_seconds=900), "fresh")

    def test_fresh_beyond_ttl_becomes_stale(self) -> None:
        record = {"freshness_state": "fresh", "last_seen_at": _now(-901)}
        self.assertEqual(effective_freshness_state(record, ttl_seconds=900), "stale")

    def test_stored_states_are_never_upgraded(self) -> None:
        for stored in ("stale", "unreachable"):
            record = {"freshness_state": stored, "last_seen_at": _now(0)}
            self.assertEqual(effective_freshness_state(record, ttl_seconds=900), stored)

    def test_missing_last_seen_is_backward_compatible(self) -> None:
        # 旧数据/未上报：不因缺字段被判 stale（否则升级即"全线离线"）。
        self.assertEqual(
            effective_freshness_state({"freshness_state": "fresh"}, ttl_seconds=900), "fresh"
        )
        self.assertEqual(effective_freshness_state({}, ttl_seconds=900), "fresh")

    def test_ttl_env_is_clamped(self) -> None:
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_AGENT_FRESH_TTL_SECONDS": "1"}):
            self.assertEqual(agent_fresh_ttl_seconds(), 60)
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_AGENT_FRESH_TTL_SECONDS": "99999999"}):
            self.assertEqual(agent_fresh_ttl_seconds(), 24 * 60 * 60)
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_AGENT_FRESH_TTL_SECONDS": "abc"}):
            self.assertEqual(agent_fresh_ttl_seconds(), 900)


class HeartbeatTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ, {"KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET}, clear=False
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        conn = open_connection(self.db_path)
        conn.close()

    def _seed_agent(self, *, merchant_id: str = "mkt_fresh_1") -> str:
        catalog_agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn,
                catalog_agent_id,
                merchant_id=merchant_id,
                display_name="Acme",
                canonical_domain="merchant.example",
            )
        return catalog_agent_id

    def test_touch_refreshes_last_seen_and_revives_freshness(self) -> None:
        agent_id = self._seed_agent()
        with db_session(self.db_path) as conn:
            # 先人为打回 stale（模拟验证管线结论）
            set_state_domains(conn, agent_id, freshness_state="stale")
            self.assertEqual(
                conn.execute(
                    "select freshness_state from catalog_agents where catalog_agent_id = ?",
                    (agent_id,),
                ).fetchone()["freshness_state"],
                "stale",
            )
            updated = touch_catalog_agent(conn, agent_id)
        self.assertEqual(updated["freshness_state"], "fresh")
        self.assertNotEqual(updated["last_seen_at"], "")

    def test_touch_does_not_revive_suspended_agent(self) -> None:
        agent_id = self._seed_agent(merchant_id="mkt_fresh_2")
        with db_session(self.db_path) as conn:
            set_state_domains(conn, agent_id, administrative_state="suspended")
            updated = touch_catalog_agent(conn, agent_id)
        self.assertEqual(updated["administrative_state"], "suspended")
        # 治理状态优先：心跳不改变治理域
        self.assertEqual(updated["freshness_state"], "fresh")

    def test_heartbeat_api_requires_owner_credential(self) -> None:
        app = create_catalog_app(self.db_path)
        agent_id = self._seed_agent(merchant_id="mkt_fresh_3")
        path = f"/v1/agent-catalog/agents/{agent_id}/heartbeat"
        status, _ = _call_http(app, "POST", path, b"{}")
        self.assertEqual(status, 403)

        # owner 凭据：由 KIWI_CATALOG_OWNER_TOKEN_SECRET 派生的 owner_token（body 字段）
        owner_token = owner_token_for("mkt_fresh_3")
        status, payload = _call_http(
            app, "POST", path, json.dumps({"owner_token": owner_token}).encode()
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["catalog_agent_id"], agent_id)
        self.assertEqual(payload["freshness_state"], "fresh")
        self.assertGreaterEqual(payload["fresh_ttl_seconds"], 60)


if __name__ == "__main__":
    unittest.main()
