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

"""一商家一 agent 约束测试 (migration v7 + 服务层校验；2026-08-10 规则修订).

注册规则（用户要求 2026-08-10）：**一个域名可注册多个商家，一个商家只能有
一个 agent**。

- 同一 merchant 换域名/换 card URL 重注册 → 更新原 agent（不再是 409）；
- 同一 merchant 名下 suspended agent → 重注册重新打开；
- 不同 merchant 可注册同一域名（v17 删域名唯一索引，一域多商家）；
- 数据层 merchant 唯一索引兜底（绕过服务层给同 merchant 插两行仍失败）；
- claim 到已有 agent 的 merchant → ConflictError；
- 匿名（空 merchant_id）重注册 active 域名 → 仍冲突（无身份防刷）。
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.core.errors import ConflictError
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services.agent_catalog_writes import claim_catalog_agent, register_catalog_agent


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    conn.close()
    return db


class MerchantSingleAgentTest(unittest.TestCase):
    def test_same_merchant_reregister_updates_existing_agent(self) -> None:
        """一商家一 agent：同商家换域名重注册 = 更新原 agent（不再 409，2026-08-10 规则）。"""
        db = _make_db()
        conn = open_connection(db)
        first = register_catalog_agent(conn, domain="one.example", merchant_id="mrc-1", actor="test")
        second = register_catalog_agent(conn, domain="two.example", merchant_id="mrc-1", actor="test")
        self.assertEqual(first["catalog_agent_id"], second["catalog_agent_id"])
        row = conn.execute(
            "select canonical_domain from catalog_agents where catalog_agent_id = ?",
            (first["catalog_agent_id"],),
        ).fetchone()
        self.assertEqual(row["canonical_domain"], "two.example")
        # 一商家一 agent：全库只有这一个 agent。
        n = conn.execute("select count(*) from catalog_agents").fetchone()[0]
        self.assertEqual(n, 1)
        conn.close()

    def test_same_merchant_reregister_updates_card_url(self) -> None:
        """同商家同域名重注册：card URL 原地更新（merchant 重启换公网地址场景）。"""
        db = _make_db()
        conn = open_connection(db)
        first = register_catalog_agent(
            conn,
            domain="one.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="http://127.0.0.1:9000/.well-known/agent-card.json",
        )
        second = register_catalog_agent(
            conn,
            domain="one.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="https://public.example/.well-known/agent-card.json",
        )
        self.assertEqual(first["catalog_agent_id"], second["catalog_agent_id"])
        url = conn.execute(
            "select url from agent_endpoints where catalog_agent_id = ? and kind = 'agent_card'",
            (first["catalog_agent_id"],),
        ).fetchone()
        self.assertEqual(url["url"], "https://public.example/.well-known/agent-card.json")
        conn.close()

    def test_merchant_reregister_reopens_suspended_agent(self) -> None:
        """商家名下 suspended agent → 重注册重新打开（同 agent id，审查 P3 语义）。"""
        db = _make_db()
        conn = open_connection(db)
        first = register_catalog_agent(conn, domain="one.example", merchant_id="mrc-1", actor="test")
        conn.execute(
            "update catalog_agents set administrative_state = 'suspended' where catalog_agent_id = ?",
            (first["catalog_agent_id"],),
        )
        conn.commit()
        reopened = register_catalog_agent(conn, domain="one.example", merchant_id="mrc-1", actor="test")
        self.assertEqual(first["catalog_agent_id"], reopened["catalog_agent_id"])
        row = conn.execute(
            "select administrative_state from catalog_agents where catalog_agent_id = ?",
            (first["catalog_agent_id"],),
        ).fetchone()
        self.assertEqual(row["administrative_state"], "active")
        conn.close()

    def test_different_merchants_each_get_an_agent(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        a = register_catalog_agent(conn, domain="one.example", merchant_id="mrc-1", actor="test")
        b = register_catalog_agent(conn, domain="two.example", merchant_id="mrc-2", actor="test")
        self.assertNotEqual(a["catalog_agent_id"], b["catalog_agent_id"])
        conn.close()

    def test_different_merchants_share_domain(self) -> None:
        """一域多商家：不同商家可注册同一域名（v17 删域名唯一索引）。"""
        db = _make_db()
        conn = open_connection(db)
        a = register_catalog_agent(conn, domain="shared.example", merchant_id="mrc-1", actor="test")
        b = register_catalog_agent(conn, domain="shared.example", merchant_id="mrc-2", actor="test")
        self.assertNotEqual(a["catalog_agent_id"], b["catalog_agent_id"])
        n = conn.execute(
            "select count(*) from catalog_agents where canonical_domain = 'shared.example'"
        ).fetchone()[0]
        self.assertEqual(n, 2)
        conn.close()

    def test_anonymous_reregister_active_domain_rejected(self) -> None:
        """匿名重注册 active 域名 → 仍冲突（无身份防刷同域名重复行）。"""
        db = _make_db()
        conn = open_connection(db)
        register_catalog_agent(conn, domain="one.example", actor="test")
        with self.assertRaises(ConflictError) as ctx:
            register_catalog_agent(conn, domain="one.example", actor="test")
        self.assertIn("already registered", str(ctx.exception))
        conn.close()

    def test_data_layer_allows_same_domain_different_merchants(self) -> None:
        """v17：数据层允许同域名不同商家（域名唯一索引已删，merchant 唯一索引保留）。"""
        db = _make_db()
        conn = open_connection(db)
        register_catalog_agent(conn, domain="dup.example", merchant_id="mrc-1", actor="test")
        ts = "2026-08-07T00:00:00+00:00"
        conn.execute(
            """insert into catalog_agents(
                catalog_agent_id, display_name, canonical_domain, agent_type,
                source_type, lifecycle_status, verification_status, hosting_mode,
                first_seen_at, last_seen_at, created_at, updated_at, merchant_id)
               values ('cagt-y', 'Y', 'dup.example', 'commerce', 'self_registered',
                'active', 'discovered', 'direct', ?, ?, ?, ?, 'mrc-2')""",
            (ts, ts, ts, ts),
        )
        conn.commit()
        n = conn.execute(
            "select count(*) from catalog_agents where canonical_domain = 'dup.example'"
        ).fetchone()[0]
        self.assertEqual(n, 2)
        conn.close()

    def test_anonymous_register_unbounded(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        register_catalog_agent(conn, domain="one.example", actor="test")
        register_catalog_agent(conn, domain="two.example", actor="test")
        n = conn.execute("select count(*) from catalog_agents").fetchone()[0]
        self.assertEqual(n, 2)
        conn.close()

    def test_unique_index_enforces_at_data_layer(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        register_catalog_agent(conn, domain="one.example", merchant_id="mrc-1", actor="test")
        # 绕过服务层直接插入同 merchant 的第二行 → 唯一索引拒绝。
        ts = "2026-08-07T00:00:00+00:00"
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                """insert into catalog_agents(
                    catalog_agent_id, display_name, canonical_domain, agent_type,
                    source_type, lifecycle_status, verification_status, hosting_mode,
                    first_seen_at, last_seen_at, created_at, updated_at, merchant_id)
                   values ('cagt-x', 'X', 'x.example', 'commerce', 'self_registered',
                    'active', 'discovered', 'direct', ?, ?, ?, ?, 'mrc-1')""",
                (ts, ts, ts, ts),
            )
        conn.close()

    def test_claim_to_merchant_with_existing_agent_rejected(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        register_catalog_agent(conn, domain="owned.example", merchant_id="mrc-1", actor="test")
        free = register_catalog_agent(conn, domain="free.example", actor="test")
        with self.assertRaises(ConflictError):
            claim_catalog_agent(
                conn,
                catalog_agent_id=free["catalog_agent_id"],
                merchant_id="mrc-1",
                actor="admin",
                identity_verifier=None,
            )
        conn.close()

    def test_claim_to_fresh_merchant_succeeds(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        free = register_catalog_agent(conn, domain="free.example", actor="test")
        # 无网络环境：identity_verifier 提供假通过。
        class _Pass:
            def verify_domain_control(self, domain: str, declared: dict | None = None) -> object:
                return type("E", (), {"passed": True, "reason": "mock"})

        result = claim_catalog_agent(
            conn,
            catalog_agent_id=free["catalog_agent_id"],
            merchant_id="mrc-new",
            actor="admin",
            identity_verifier=_Pass(),
        )
        self.assertEqual(result["merchant"]["id"], "mrc-new")
        conn.close()


if __name__ == "__main__":
    unittest.main()
