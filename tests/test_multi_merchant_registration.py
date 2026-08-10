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

"""审查 P2（v17 删域名唯一索引后）：多商家共享域名下的注册授权回归。

- 匿名/域名级路径不得选中「最新任意 merchant 行」（created_at 同秒顺序不定）；
  显式冲突规则：域名下已有 merchant 绑定行 → ConflictError；仅匿名行时任一
  active → Conflict、governed 唯一行 → 复用重开。
- merchant 路径按商户主键选目标——永远只操作调用方自己的 agent，不触及其他
  商家的行；共享域名上另一商家的治理行不被复活/改绑。
- HTTP 层：外来商户在共享域名上新建自己的 agent 不再被域名最新行误拦。
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
from kiwi_catalog.core.errors import ConflictError
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent

OWNER_SECRET = "test-multi-merchant-secret"


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


class AnonymousConflictRuleTest(unittest.TestCase):
    """匿名/域名级路径的显式冲突规则（不选中任意 merchant 行）。"""

    def _db(self) -> tuple[Path, object]:
        tmp = tempfile.mkdtemp()
        db = Path(tmp) / "catalog.sqlite"
        conn = open_connection(db)
        return db, conn

    def test_anonymous_conflicts_on_merchant_active_domain(self) -> None:
        _, conn = self._db()
        register_catalog_agent(conn, domain="shared.example", merchant_id="mrc-A", actor="test")
        conn.commit()
        with self.assertRaises(ConflictError):
            register_catalog_agent(conn, domain="shared.example", actor="cli")
        conn.close()

    def test_anonymous_conflicts_on_merchant_governed_domain(self) -> None:
        """匿名不得复活/复用 merchant 的 governed 行（steal 回归）。"""
        _, conn = self._db()
        a = register_catalog_agent(conn, domain="shared.example", merchant_id="mrc-A", actor="test")
        conn.execute(
            "update catalog_agents set administrative_state='suspended' where catalog_agent_id=?",
            (a["catalog_agent_id"],),
        )
        conn.commit()
        with self.assertRaises(ConflictError) as ctx:
            register_catalog_agent(conn, domain="shared.example", actor="cli")
        self.assertIn("already registered", str(ctx.exception))
        # merchant 绑定与治理态未被匿名触碰。
        row = conn.execute(
            "select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?",
            (a["catalog_agent_id"],),
        ).fetchone()
        self.assertEqual(row["merchant_id"], "mrc-A")
        self.assertEqual(row["administrative_state"], "suspended")
        conn.close()

    def test_anonymous_conflicts_on_active_anonymous_domain(self) -> None:
        _, conn = self._db()
        register_catalog_agent(conn, domain="one.example", actor="cli")
        conn.commit()
        with self.assertRaises(ConflictError):
            register_catalog_agent(conn, domain="one.example", actor="cli")
        conn.close()

    def test_anonymous_reopens_governed_unbound_row(self) -> None:
        """仅匿名行 + governed → 复用重开（admin 重注册可恢复的语义保留）。"""
        _, conn = self._db()
        first = register_catalog_agent(conn, domain="anon.example", actor="cli")
        conn.execute(
            "update catalog_agents set administrative_state='rejected' where catalog_agent_id=?",
            (first["catalog_agent_id"],),
        )
        conn.commit()
        reopened = register_catalog_agent(conn, domain="anon.example", actor="cli")
        self.assertEqual(first["catalog_agent_id"], reopened["catalog_agent_id"])
        row = conn.execute(
            "select administrative_state from catalog_agents where catalog_agent_id=?",
            (first["catalog_agent_id"],),
        ).fetchone()
        self.assertEqual(row["administrative_state"], "active")
        conn.close()


class MerchantOwnTargetTest(unittest.TestCase):
    """merchant 路径只操作自己的 agent，不触及其他商家的行。"""

    def test_merchant_reregister_targets_own_agent_only(self) -> None:
        """A active + B governed 同域名：A 重注册只更新自己的行，B 的行不动。"""
        tmp = tempfile.mkdtemp()
        db = Path(tmp) / "catalog.sqlite"
        conn = open_connection(db)
        a = register_catalog_agent(conn, domain="shared.example", merchant_id="mrc-A", actor="test")
        b = register_catalog_agent(conn, domain="shared.example", merchant_id="mrc-B", actor="test")
        conn.execute(
            "update catalog_agents set administrative_state='suspended' where catalog_agent_id=?",
            (b["catalog_agent_id"],),
        )
        conn.commit()
        updated = register_catalog_agent(conn, domain="shared.example", merchant_id="mrc-A", actor="merchant:mrc-A")
        self.assertEqual(updated["catalog_agent_id"], a["catalog_agent_id"])
        b_row = conn.execute(
            "select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?",
            (b["catalog_agent_id"],),
        ).fetchone()
        self.assertEqual(b_row["merchant_id"], "mrc-B")
        self.assertEqual(b_row["administrative_state"], "suspended")
        conn.close()


class MultiMerchantHttpTest(unittest.TestCase):
    """HTTP 层：外来商户在共享域名上新建自己的 agent；匿名被 merchant 域名拒绝。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = str(Path(self.tmp) / "catalog.sqlite")
        self.env = mock.patch.dict(
            os.environ, {"KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET}, clear=False
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.app = create_catalog_app(self.db_path)
        # A 的 governed（suspended）agent 在 shared.example。
        with open_connection(self.db_path) as conn:
            self.a_id = register_catalog_agent(
                conn, domain="shared.example", merchant_id="mrc-A", actor="test"
            )["catalog_agent_id"]
            conn.execute(
                "update catalog_agents set administrative_state='suspended'"
                " where catalog_agent_id=?",
                (self.a_id,),
            )
            conn.commit()

    def _register(self, body: dict) -> tuple[int, dict]:
        return _call_http(self.app, "POST", "/v1/agents/register", json.dumps(body).encode())

    def test_foreign_merchant_creates_own_agent_on_shared_domain(self) -> None:
        """A 有 governed 行：B 带自己 token 注册同域名 → 200（新建自己的 agent），
        A 的治理行保持 suspended + 绑定 A（不再被域名最新行误拦）。"""
        status, payload = self._register(
            {
                "domain": "shared.example",
                "merchant_id": "mrc-B",
                "owner_token": owner_token("mrc-B"),
            }
        )
        self.assertEqual(status, 200, payload)
        b_id = payload["agent"]["catalog_agent_id"]
        self.assertNotEqual(b_id, self.a_id)
        with open_connection(self.db_path) as conn:
            a_row = conn.execute(
                "select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?",
                (self.a_id,),
            ).fetchone()
            b_row = conn.execute(
                "select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?",
                (b_id,),
            ).fetchone()
        self.assertEqual(a_row["administrative_state"], "suspended")
        self.assertEqual(a_row["merchant_id"], "mrc-A")
        self.assertEqual(b_row["administrative_state"], "active")
        self.assertEqual(b_row["merchant_id"], "mrc-B")

    def test_anonymous_http_rejected_on_merchant_governed_domain(self) -> None:
        """匿名 HTTP 注册 merchant 治理域名 → 409（服务层显式冲突）。"""
        status, payload = self._register({"domain": "shared.example"})
        self.assertEqual(status, 409, payload)
        self.assertIn("already registered", str(payload.get("error", "")))

    def test_owner_merchant_reopens_own_governed_agent(self) -> None:
        """绑定商户 A 带自己 token 重注册 → 复活自己的 agent（同 id），绑定保持 A。"""
        status, payload = self._register(
            {
                "domain": "shared.example",
                "merchant_id": "mrc-A",
                "owner_token": owner_token("mrc-A"),
            }
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["agent"]["catalog_agent_id"], self.a_id)
        with open_connection(self.db_path) as conn:
            a_row = conn.execute(
                "select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?",
                (self.a_id,),
            ).fetchone()
        self.assertEqual(a_row["administrative_state"], "active")
        self.assertEqual(a_row["merchant_id"], "mrc-A")


if __name__ == "__main__":
    unittest.main()
