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

"""T041「hosted 语义回归」：两条名片通道并存，互不串味。

设计 v0.1.2 §11.1 明确：旧托管通道的卡片生成器是**已有状态的只读投影**，其
`supportedInterfaces` 是旧形状、`url` 指向 Catalog 自己——**不能因为名字叫 hosted
就用于本次云端发布**。因此 M3 的云端名片走独立稳定读地址，旧通道保持原语义。

本文件把这条边界钉成回归矩阵（四条）：

| 商家类型 | 旧通道 `/v1/hosted/.../agent-card.json` | 稳定读地址 `/v1/agents/{id}/agent-card.json` |
|---|---|---|
| 旧 hosted（`source_type=hosted`，无发布记录） | 200（旧形状 Card） | 404（没有发布版本） |
| 云端（有绑定 + 已发布） | **404**（不用旧生成器服务云端名片） | 200（原始 Card JSON） |

换句话说：**新增通道不破坏旧通道**，同时旧生成器也不会被误用于云端名片。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
import unittest.mock

from kiwi_catalog.agent_catalog.sqlite_repository import (
    new_catalog_agent_id,
    upsert_catalog_agent,
)
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session

HOSTED_BASE_URL = "https://catalog.example"


def _call(app, method: str, path: str):
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    asyncio.run(
        app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "headers": [(b"content-type", b"application/json")],
                "query_string": b"",
                "http_version": "1.1",
                "scheme": "http",
            },
            receive,
            send,
        )
    )
    start = next(m for m in received if m["type"] == "http.response.start")
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    try:
        payload = json.loads(chunks.decode("utf-8")) if chunks else {}
    except json.JSONDecodeError:
        payload = {}
    return start["status"], payload


class HostedChannelRegressionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        env = unittest.mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_HOSTED_A2A_BASE_URL": HOSTED_BASE_URL},
            clear=False,
        )
        env.start()
        self.addCleanup(env.stop)

    def _seed(self, *, source_type: str, hosted_runtime_agent_id: str = "") -> str:
        agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn,
                agent_id,
                merchant_id="mkt_hosted_1",
                hosted_runtime_agent_id=hosted_runtime_agent_id,
                display_name="Legacy Hosted Merchant",
                canonical_domain="merchant.example",
                source_type=source_type,
            )
        return agent_id

    def _seed_cloud_publication(self, agent_id: str) -> None:
        """让一个 agent 具备"云端"特征：活动绑定 + 活动发布版本。"""
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
                " values ('bind_legacy_1', ?, 'mkt_hosted_1', 'https://pilot.example.host',"
                " 'https://pilot.example.host/a2a', 'https://pilot.example.host',"
                " 'sha256:abc', '{}', 1, 1, 'active', '', '', '')",
                (agent_id,),
            )
            conn.execute(
                "insert into agent_card_versions (catalog_agent_id, card_revision, wire_profile,"
                " canonical_bytes, digest, created_by, created_at)"
                " values (?, 1, 'a2a-1.0', ?, 'sha256:x', 'test', '')",
                (agent_id, json.dumps({"name": "Cloud Merchant"})),
            )
            conn.execute(
                "insert into card_publications (catalog_agent_id, active_revision,"
                " publication_state, etag, updated_at) values (?, 1, 'ACTIVE', '\"e1\"', '')",
                (agent_id,),
            )

    # ── 旧通道：旧 hosted 商家照旧可读 ─────────────────────────────
    def test_legacy_hosted_agent_still_served_by_legacy_channel(self) -> None:
        agent_id = self._seed(source_type="hosted", hosted_runtime_agent_id="rt_legacy_1")
        status, card = _call(self.app, "GET", f"/v1/hosted/agents/{agent_id}/agent-card.json")
        self.assertEqual(status, 200, card)
        # 旧通道的既有形状：url 指向 Catalog 共享主机，不套 ok 信封
        self.assertNotIn("ok", card)
        self.assertTrue(str(card["url"]).startswith(HOSTED_BASE_URL))
        self.assertTrue(card["supportedInterfaces"])

    def test_legacy_hosted_agent_ucp_profile_still_served(self) -> None:
        agent_id = self._seed(source_type="hosted", hosted_runtime_agent_id="rt_legacy_2")
        status, profile = _call(self.app, "GET", f"/v1/hosted/agents/{agent_id}/ucp")
        self.assertEqual(status, 200, profile)

    # ── 旧通道：自注册商家照旧 404（原语义不变） ────────────────────
    def test_self_registered_agent_is_not_hosted(self) -> None:
        agent_id = self._seed(source_type="self_registered")
        status, _payload = _call(self.app, "GET", f"/v1/hosted/agents/{agent_id}/agent-card.json")
        self.assertEqual(status, 404)

    # ── 交叉：两条通道不互相冒充 ───────────────────────────────────
    def test_legacy_hosted_agent_has_no_stable_read_address(self) -> None:
        """旧 hosted 商家没有被发布的云端名片 → 稳定读地址 404（不是"回退到旧生成器"）。"""
        agent_id = self._seed(source_type="hosted", hosted_runtime_agent_id="rt_legacy_3")
        status, _payload = _call(self.app, "GET", f"/v1/agents/{agent_id}/agent-card.json")
        self.assertEqual(status, 404)

    def test_cloud_agent_is_not_served_by_the_legacy_generator(self) -> None:
        """云端商家在旧通道上 **404**。

        §11.1：旧生成器产出的 `supportedInterfaces` 是旧形状、`url` 指向 Catalog
        自己——把它当成云端名片发出去，Buyer 会连到 Catalog 而不是 Runtime。
        两条通道必须互不冒充：云端名片只从稳定读地址出。
        """
        agent_id = self._seed(source_type="self_registered")
        self._seed_cloud_publication(agent_id)
        status, _payload = _call(self.app, "GET", f"/v1/hosted/agents/{agent_id}/agent-card.json")
        self.assertEqual(status, 404)
        # 同一商家从稳定读地址可读（这就是它的正规出口）
        status, card = _call(self.app, "GET", f"/v1/agents/{agent_id}/agent-card.json")
        self.assertEqual(status, 200, card)
        self.assertEqual(card["name"], "Cloud Merchant")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
