"""审查 P1-3 回归：agent_endpoints 的 (catalog_agent_id, kind) 唯一性与原子 upsert。

三处 upsert 此前是 select-then-insert：HTTP handler（sync_cloud_endpoints）与
验证服务并发时两个连接都读到空 → 双 insert → 同一 agent 两条 a2a/agent_card 行，
此后 update 只改首行，重复行永不自愈。v58 迁移先合并历史重复行，再建唯一索引，
upsert 改为 ON CONFLICT 单语句原子写。
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.agent_catalog.sqlite_repository import upsert_profile_endpoints
from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.services.agent_endpoints import _upsert_a2a_endpoint


class AgentEndpointUniquenessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "catalog.sqlite"
        self.conn = open_connection(self.db_path)
        self.addCleanup(lambda: self.conn.close())

    def _rows(self, catalog_agent_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "select endpoint_id, kind, url from agent_endpoints"
            " where catalog_agent_id = ? order by endpoint_id",
            (catalog_agent_id,),
        ).fetchall()

    def test_migration_merges_legacy_duplicates_and_recreates_unique_index(self) -> None:
        # 模拟 v57 旧库：唯一索引尚不存在，且已经因竞态留下两条 a2a 行。
        self.conn.execute("drop index if exists idx_agent_endpoints_agent_kind_unique")
        self.conn.execute("pragma user_version = 57")
        self.conn.execute(
            "insert into agent_endpoints(catalog_agent_id, kind, url, last_checked_at)"
            " values (?, ?, ?, ?)",
            ("cagt_legacy", "a2a", "https://old.example/a2a", "2026-01-01T00:00:00+00:00"),
        )
        self.conn.execute(
            "insert into agent_endpoints(catalog_agent_id, kind, url, last_checked_at)"
            " values (?, ?, ?, ?)",
            ("cagt_legacy", "a2a", "https://new.example/a2a", "2026-01-02T00:00:00+00:00"),
        )
        self.conn.commit()

        self.conn.close()
        self.conn = open_connection(self.db_path)

        rows = self._rows("cagt_legacy")
        self.assertEqual(len(rows), 1, "重复行必须合并为一行")
        # 保留首行（历史 update 分支一直在改的那行）。
        self.assertEqual(rows[0]["url"], "https://old.example/a2a")
        self.assertEqual(
            self.conn.execute("pragma user_version").fetchone()[0], CURRENT_SCHEMA_VERSION
        )
        index = self.conn.execute(
            "select name from sqlite_master where type = ? and name = ?",
            ("index", "idx_agent_endpoints_agent_kind_unique"),
        ).fetchone()
        self.assertIsNotNone(index)

    def test_unique_index_rejects_duplicate_endpoint_rows(self) -> None:
        now = now_iso()
        self.conn.execute(
            "insert into agent_endpoints(catalog_agent_id, kind, url, last_checked_at)"
            " values (?, ?, ?, ?)",
            ("cagt_dup", "a2a", "https://one.example", now),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "insert into agent_endpoints(catalog_agent_id, kind, url, last_checked_at)"
                " values (?, ?, ?, ?)",
                ("cagt_dup", "a2a", "https://two.example", now),
            )
        self.conn.rollback()

    def test_profile_endpoint_upsert_is_atomic_and_updates_in_place(self) -> None:
        upsert_profile_endpoints(
            self.conn,
            "cagt_profile",
            [
                {"kind": "agent_card", "url": "https://card.example/one.json"},
                {"kind": "ucp_profile", "url": "https://ucp.example/one.json"},
            ],
        )
        upsert_profile_endpoints(
            self.conn,
            "cagt_profile",
            [{"kind": "agent_card", "url": "https://card.example/two.json"}],
        )
        rows = self._rows("cagt_profile")
        self.assertEqual([row["kind"] for row in rows], ["agent_card", "ucp_profile"])
        self.assertEqual(rows[0]["url"], "https://card.example/two.json")

    def test_a2a_endpoint_upsert_is_atomic_and_updates_in_place(self) -> None:
        now = now_iso()
        _upsert_a2a_endpoint(self.conn, "cagt_a2a", "https://a2a.example/one", now)
        _upsert_a2a_endpoint(self.conn, "cagt_a2a", "https://a2a.example/two", now)
        rows = self._rows("cagt_a2a")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["url"], "https://a2a.example/two")


if __name__ == "__main__":
    unittest.main()
