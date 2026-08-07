"""一商家一 agent 约束测试 (migration v7 + 服务层校验).

- 同一 merchant 注册第二个 agent → ConflictError（服务层明确错误）；
- 数据层部分唯一索引兜底（绕过服务层直接插入也失败）；
- 不同 merchant 各自可注册；
- claim 到已有 agent 的 merchant → ConflictError；
- 空 merchant_id 的注册不受约束（公开注册，无 owner 身份）。
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
    def test_same_merchant_second_register_rejected(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        register_catalog_agent(conn, domain="one.example", merchant_id="mrc-1", actor="test")
        with self.assertRaises(ConflictError) as ctx:
            register_catalog_agent(conn, domain="two.example", merchant_id="mrc-1", actor="test")
        self.assertIn("already has a catalog agent", str(ctx.exception))
        conn.close()

    def test_different_merchants_each_get_an_agent(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        a = register_catalog_agent(conn, domain="one.example", merchant_id="mrc-1", actor="test")
        b = register_catalog_agent(conn, domain="two.example", merchant_id="mrc-2", actor="test")
        self.assertNotEqual(a["catalog_agent_id"], b["catalog_agent_id"])
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
        owned = register_catalog_agent(conn, domain="owned.example", merchant_id="mrc-1", actor="test")
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
