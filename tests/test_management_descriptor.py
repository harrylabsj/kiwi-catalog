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

"""BD §6.3：`GET /v1/cloud-enrollments/{id}/management-descriptor`（Catalog 侧交付）。

这个对象是"商家登录后，门户从可信控制面取得本商家的管理地址"的唯一来源（BD §6.2 第 1 步）。
四条纪律，逐条有测试：

1. **归属鉴权**：不是本商家的 agent 一律 **404**（与"不存在"不可区分，避免枚举）；
2. **绝不含凭据**：只有绑定元数据；任何 Token/Cookie/私钥/底价都不在这里；
3. **未声明即拒**：运行时没声明管理面元数据 → **409**，绝不用 Catalog 默认值伪造；
4. **对得上契约**：响应用 `kiwi/contracts/merchant-management/1.0/runtime-management-descriptor
   .schema.json` 校验（跨仓契约，检出不存在时跳过）。
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import jsonschema

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.agent_catalog.sqlite_repository import (
    new_catalog_agent_id,
    upsert_catalog_agent,
)
from kiwi_catalog.db.session import db_session

SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "kiwi"
    / "contracts"
    / "merchant-management"
    / "1.0"
    / "runtime-management-descriptor.schema.json"
)

DESCRIPTOR_BASE = "/v1/cloud-enrollments"
OWNER_TOKEN = "cmt_descriptor_owner_token"
OTHER_TOKEN = "cmt_descriptor_other_token"


def _call(app, method: str, path: str, query: str = ""):
    """直调 ASGI（与其它 catalog 测试同口径）；返回 (status, payload)。"""
    import asyncio

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
                "query_string": query.encode(),
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


class ManagementDescriptorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        self.merchant_id = "mkt_descriptor_1"
        self.other_merchant_id = "mkt_descriptor_2"
        self.agent_id = self._seed_agent(self.merchant_id, "Descriptor Merchant")
        self.other_agent_id = self._seed_agent(self.other_merchant_id, "Other Merchant")
        self._seed_tokens()

    def _seed_agent(self, merchant_id: str, display_name: str) -> str:
        agent_id = new_catalog_agent_id()
        with db_session(self.db_path) as conn:
            upsert_catalog_agent(
                conn,
                agent_id,
                merchant_id=merchant_id,
                display_name=display_name,
                canonical_domain="merchant.example",
            )
        return agent_id

    def _seed_tokens(self) -> None:
        """两张 owner token（token 即身份：表里存 SHA-256 摘要，不存明文）。"""
        from kiwi_catalog.services.merchant_tokens import token_digest

        with db_session(self.db_path) as conn:
            for merchant_id, token in (
                (self.merchant_id, OWNER_TOKEN),
                (self.other_merchant_id, OTHER_TOKEN),
            ):
                conn.execute(
                    "insert into merchant_tokens (merchant_id, token_hash, token_encrypted,"
                    " status, issued_at, rotated_at, revoked_at)"
                    " values (?, ?, '', 'active', '', '', '')",
                    (merchant_id, token_digest(token)),
                )

    def _seed_binding(
        self,
        *,
        agent_id: str,
        merchant_id: str,
        base_path: str = "/merchant/",
        api_major: int = 1,
        mcp_path: str = "",
        status: str = "active",
        expires_at: str = "",
    ) -> None:
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                " binding_version, service_epoch, status, expires_at, created_at, updated_at,"
                " management_base_path, management_api_major, mcp_path)"
                " values (?, ?, ?, 'https://pilot.example.host', 'https://pilot.example.host/a2a',"
                " 'https://pilot.example.host', 'sha256:abc', '{}', 3, 7, ?, ?, '', '', ?, ?, ?)",
                (f"bind_{agent_id[-6:]}", agent_id, merchant_id, status, expires_at, base_path, api_major, mcp_path),
            )

    def _get(self, agent_id: str, token: str = OWNER_TOKEN, *, raw: bool = False):
        query = f"owner_token={token}"
        return _call(self.app, "GET", f"{DESCRIPTOR_BASE}/{agent_id}/management-descriptor", query)

    # ── 归属鉴权 ─────────────────────────────────────────────────
    def test_requires_owner_token(self) -> None:
        """无 token / 坏 token 一律 403——**这是 Catalog 的既有约定**。

        注意别照 BD §11.3 的 401 改这里：那张表管的是 **Runtime 侧** `/merchant/api/*`
        （那边确实是 401，见 `merchant-management` 契约）。Catalog 控制面一律用
        `AuthError → 403`，全仓现有端点与测试都依赖这一点；本端点从众。
        """
        self._seed_binding(agent_id=self.agent_id, merchant_id=self.merchant_id)
        path = f"{DESCRIPTOR_BASE}/{self.agent_id}/management-descriptor"
        self.assertEqual(_call(self.app, "GET", path)[0], 403)
        # 坏 token 与无 token 同形（不区分"没带"与"带错"）
        self.assertEqual(_call(self.app, "GET", path, "owner_token=cmt_nope")[0], 403)

    def test_other_merchants_agent_is_a_uniform_404(self) -> None:
        """用别的商家 token 读本商家的 agent → 404，与"不存在"不可区分。"""
        self._seed_binding(agent_id=self.agent_id, merchant_id=self.merchant_id)
        status, payload = self._get(self.agent_id, token=OTHER_TOKEN)
        self.assertEqual(status, 404)
        # 与"agent 根本不存在"的响应完全一致（不泄漏存在性）
        missing = new_catalog_agent_id()
        status_missing, payload_missing = self._get(missing, token=OWNER_TOKEN)
        self.assertEqual(status_missing, 404)
        self.assertEqual(payload.get("error"), payload_missing.get("error"))

    def test_no_active_binding_is_404(self) -> None:
        self._seed_binding(agent_id=self.agent_id, merchant_id=self.merchant_id, status="revoked")
        self.assertEqual(self._get(self.agent_id)[0], 404)

    # ── 未声明即拒（fail-closed）─────────────────────────────────
    def test_undeclared_management_metadata_is_409(self) -> None:
        """运行时没声明 → 409，不用默认值伪造地址。"""
        self._seed_binding(agent_id=self.agent_id, merchant_id=self.merchant_id, base_path="", api_major=0)
        status, payload = self._get(self.agent_id)
        self.assertEqual(status, 409, payload)
        self.assertIn("not declared", str(payload.get("error", "")))

    # ── 正常路径 ─────────────────────────────────────────────────
    def test_happy_path_returns_binding_metadata_only(self) -> None:
        self._seed_binding(
            agent_id=self.agent_id,
            merchant_id=self.merchant_id,
            expires_at="2026-10-01T00:00:00+00:00",
        )
        status, payload = self._get(self.agent_id)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["merchant_id"], self.merchant_id)
        self.assertEqual(payload["agent_id"], self.agent_id)
        self.assertEqual(payload["runtime_origin"], "https://pilot.example.host")
        self.assertEqual(payload["management_base_path"], "/merchant/")
        self.assertEqual(payload["management_api_major"], 1)
        self.assertEqual(payload["binding_version"], 3)
        self.assertEqual(payload["status"], "active")
        self.assertEqual(payload["expires_at"], "2026-10-01T00:00:00+00:00")
        # 未声明 MCP 路径 → 不出现在响应里（B07 前不返回）
        self.assertNotIn("mcp_path", payload)

    def test_declared_mcp_path_is_returned(self) -> None:
        self._seed_binding(
            agent_id=self.agent_id, merchant_id=self.merchant_id, mcp_path="/merchant/mcp"
        )
        status, payload = self._get(self.agent_id)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["mcp_path"], "/merchant/mcp")

    def test_no_credentials_in_response(self) -> None:
        """描述符**绝不含凭据**——它不是认证凭据。"""
        self._seed_binding(agent_id=self.agent_id, merchant_id=self.merchant_id)
        _status, payload = self._get(self.agent_id)
        serialized = json.dumps(payload)
        for forbidden in ("token", "Token", "cookie", "Cookie", "secret", "private_key", "floor", "cmt_"):
            self.assertNotIn(forbidden, serialized)

    def test_open_ended_binding_gets_a_valid_far_future_expiry(self) -> None:
        """绑定未设到期时间时也必须给出合法 date-time（空串过不了 schema，也会被误判过期）。"""
        self._seed_binding(agent_id=self.agent_id, merchant_id=self.merchant_id, expires_at="")
        status, payload = self._get(self.agent_id)
        self.assertEqual(status, 200, payload)
        self.assertRegex(payload["expires_at"], r"^\d{4}-\d{2}-\d{2}T")

    # ── 契约 ─────────────────────────────────────────────────────
    @unittest.skipUnless(SCHEMA_PATH.is_file(), "kiwi checkout not available")
    def test_response_matches_the_frozen_contract(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self._seed_binding(
            agent_id=self.agent_id, merchant_id=self.merchant_id, mcp_path="/merchant/mcp"
        )
        _status, payload = self._get(self.agent_id)
        jsonschema.validate(payload, schema)

    @unittest.skipUnless(SCHEMA_PATH.is_file(), "kiwi checkout not available")
    def test_undeclared_cannot_be_forced_with_schema_required_fields(self) -> None:
        """反向确认：schema 要求 management_base_path / management_api_major 必填——
        所以"没声明"时**只能**拒，不能返回一个缺字段的对象。"""
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertIn("management_base_path", schema["required"])
        self.assertIn("management_api_major", schema["required"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
