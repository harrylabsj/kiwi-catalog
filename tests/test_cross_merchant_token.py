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

"""审查 P2-05：body ``merchant_id`` 不能代替 authenticated token 的 merchant
ownership（claim/register 路径）回归。

现状实现（已核实）：register 的 ``_register_actor`` 与 claim 的
``_claim_identity`` 在携带 body ``merchant_id`` 时都调用
``api_auth.require_merchant_token(payload, merchant_id, conn)``——该调用把
呈现的 token 严格绑定到该 merchant（随机 token 落库路径按 merchant_id 查
SHA-256；HMAC fallback 派生 ``owner_token(merchant_id)``），跨商户 token 无法
通过。本文件把这些行为固化为回归：跨商户 token + 目标 merchant_id 的
register / claim 必须被拒，自己的 token + 自己的 merchant_id 才放行；已绑定
agent 无法被他人 token 抢走。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api.auth import owner_token
from kiwi_catalog.core.errors import AuthError, ConflictError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services.agent_catalog_writes import (
    claim_catalog_agent,
    register_catalog_agent,
)

OWNER_SECRET = "test-p2-05-secret"


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


class _PassVerifier:
    """Fake IdentityVerifier（无网络）：domain-control 恒通过。"""

    def verify_domain_control(self, domain: str, declared: dict | None = None) -> object:
        return type("E", (), {"passed": True, "reason": "mock"})()


class CrossMerchantTokenTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmp) / "catalog.sqlite")
        self.env = mock.patch.dict(
            os.environ, {"KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET}, clear=False
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.app = create_catalog_app(self.db_path)
        self.t1 = owner_token("mrc-1")
        self.t2 = owner_token("mrc-2")
        self.t3 = owner_token("mrc-3")  # 无 agent 的新商户，用于正向 claim
        with db_session(self.db_path) as conn:
            # mrc-1 已绑定 agent + 一个未绑定（匿名）agent。
            self.bound_id = register_catalog_agent(
                conn, domain="bound.example", merchant_id="mrc-1", actor="test"
            )["catalog_agent_id"]
            self.free_id = register_catalog_agent(
                conn, domain="free.example", actor="test"
            )["catalog_agent_id"]

    def _register(self, body: dict) -> tuple[int, dict]:
        return _call_http(self.app, "POST", "/v1/agents/register", json.dumps(body).encode())

    def _claim(self, catalog_agent_id: str, body: dict) -> tuple[int, dict]:
        return _call_http(
            self.app,
            "POST",
            f"/v1/agents/{catalog_agent_id}/claim",
            json.dumps(body).encode(),
        )

    # ── register：body merchant_id 必须匹配 token ──────────────────────────

    def test_register_cross_merchant_token_rejected(self) -> None:
        """mrc-1 的 token + body merchant_id='mrc-2' → 403（body 不能代替 token）。"""
        status, payload = self._register(
            {"domain": "attack.example", "merchant_id": "mrc-2", "owner_token": self.t1}
        )
        self.assertEqual(status, 403, payload)
        self.assertIn("owner token", str(payload.get("error", "")))

    def test_register_own_token_binds_own_merchant(self) -> None:
        """mrc-1 的 token + body merchant_id='mrc-1' → 200，绑定 mrc-1。"""
        status, payload = self._register(
            {"domain": "own.example", "merchant_id": "mrc-1", "owner_token": self.t1}
        )
        self.assertEqual(status, 200, payload)
        cid = payload["agent"]["catalog_agent_id"]
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cid,)
            ).fetchone()
        self.assertEqual(row["merchant_id"], "mrc-1")

    def test_register_without_merchant_id_is_anonymous(self) -> None:
        """不带 merchant_id → 匿名（不绑定任何商家），token 不替代 merchant_id。"""
        status, payload = self._register({"domain": "anon.example", "owner_token": self.t1})
        self.assertEqual(status, 200, payload)
        cid = payload["agent"]["catalog_agent_id"]
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (cid,)
            ).fetchone()
        self.assertEqual(row["merchant_id"] or "", "")

    # ── claim：body merchant_id 必须匹配 token ─────────────────────────────

    def test_claim_cross_merchant_token_rejected(self) -> None:
        """未绑定 agent：mrc-1 token + body merchant_id='mrc-2' → 403。"""
        status, payload = self._claim(self.free_id, {"merchant_id": "mrc-2", "owner_token": self.t1})
        self.assertEqual(status, 403, payload)

    def test_claim_own_token_binds_own_merchant(self) -> None:
        """未绑定 agent：mrc-3 token + body merchant_id='mrc-3' → 200，绑定 mrc-3
        （mrc-3 名下无 agent，不触发一商家一 agent 约束）。"""
        with mock.patch(
            "kiwi_catalog.api.handlers.agent_catalog._identity_verifier", return_value=_PassVerifier()
        ):
            status, payload = self._claim(self.free_id, {"merchant_id": "mrc-3", "owner_token": self.t3})
        self.assertEqual(status, 200, payload)
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select merchant_id from catalog_agents where catalog_agent_id = ?", (self.free_id,)
            ).fetchone()
        self.assertEqual(row["merchant_id"], "mrc-3")

    def test_claim_cannot_steal_agent_bound_to_other_merchant(self) -> None:
        """已绑定 mrc-1 的 agent：mrc-2 token + body merchant_id='mrc-2' → 409
        （auth 只证明 token 属于 mrc-2；service 层拒绝改绑已绑定 agent）。"""
        with mock.patch(
            "kiwi_catalog.api.handlers.agent_catalog._identity_verifier", return_value=_PassVerifier()
        ):
            status, payload = self._claim(self.bound_id, {"merchant_id": "mrc-2", "owner_token": self.t2})
        self.assertEqual(status, 409, payload)

    def test_claim_empty_merchant_id_uses_agent_binding(self) -> None:
        """已绑定 mrc-1 的 agent：不带 body merchant_id → 默认目标 = agent 绑定
        mrc-1；mrc-1 token 通过（owner token 绑定到 mrc-1），mrc-2 token 拒绝。"""
        with mock.patch(
            "kiwi_catalog.api.handlers.agent_catalog._identity_verifier", return_value=_PassVerifier()
        ):
            status, payload = self._claim(self.bound_id, {"owner_token": self.t2})
        self.assertEqual(status, 403, payload)  # mrc-2 token 对 agent 绑定 mrc-1 无效

    # ── service 层（_claim_identity 语义的直接断言）────────────────────────

    def test_claim_identity_requires_token_to_match_body_merchant(self) -> None:
        from kiwi_catalog.api.handlers.agent_catalog import _claim_identity

        with db_session(self.db_path) as conn:
            from kiwi_catalog.agent_catalog.sqlite_repository import require_catalog_agent

            row = require_catalog_agent(conn, self.free_id)
            with self.assertRaises(AuthError):
                _claim_identity(conn, row, {"merchant_id": "mrc-2", "owner_token": self.t1})
            merchant_id, actor = _claim_identity(
                conn, row, {"merchant_id": "mrc-1", "owner_token": self.t1}
            )
        self.assertEqual(merchant_id, "mrc-1")
        self.assertEqual(actor, "merchant:mrc-1")

    def test_service_claim_blocks_cross_merchant_takeover(self) -> None:
        """service 兜底：domain 挑战通过（攻击者真控制域名）也无法把已绑定
        agent 改绑到别的 merchant。"""
        with db_session(self.db_path) as conn:
            with self.assertRaises(ConflictError):
                claim_catalog_agent(
                    conn,
                    catalog_agent_id=self.bound_id,
                    merchant_id="mrc-2",
                    actor="merchant:mrc-2",
                    identity_verifier=_PassVerifier(),
                )


if __name__ == "__main__":
    unittest.main()
