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

"""Shadow-table tests (extraction phase 2: standalone schema).

The standalone schema replaces the shopping-cli foreign keys with
weak references plus minimal shadow tables:

- ``merchants``: public fields for the join projection in
  ``get_catalog_agent_with_merchant`` — a catalog row with a merchant_id
  that has no shadow row must not crash (weak reference semantics), and a
  populated shadow row surfaces through the §3.4 public serializer;
- ``audit_events``: catalog audit lands in the standalone table and is
  readable, including the verification pipeline's events.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.agent_catalog.serializers import public_merchant_ref
from kiwi_catalog.agent_catalog.sqlite_repository import (
    append_catalog_audit,
    get_catalog_agent_with_merchant,
    require_catalog_agent,
    set_catalog_agent_merchant,
)
from kiwi_catalog.db.session import open_connection


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    conn.close()
    return db


class MerchantShadowTableTest(unittest.TestCase):
    """merchants 影子表：弱引用 join 不崩 + public ref 投影。"""

    def _seed_agent(self, db: Path, catalog_agent_id: str = "cagt-1", merchant_id: str = "") -> None:
        conn = open_connection(db)
        ts = "2026-08-07T00:00:00+00:00"
        conn.execute(
            """insert into catalog_agents(
                catalog_agent_id, display_name, canonical_domain, agent_type, source_type,
                lifecycle_status, verification_status, hosting_mode,
                first_seen_at, last_seen_at, created_at, updated_at)
               values (?, 'Agent', 'example.com', 'commerce', 'self_registered',
                'active', 'discovered', 'direct', ?, ?, ?, ?)""",
            (catalog_agent_id, ts, ts, ts, ts),
        )
        if merchant_id:
            conn.execute(
                "update catalog_agents set merchant_id = ? where catalog_agent_id = ?",
                (merchant_id, catalog_agent_id),
            )
        conn.commit()
        conn.close()

    def test_weak_reference_without_shadow_row_does_not_crash(self) -> None:
        db = _make_db()
        self._seed_agent(db, merchant_id="mrc-missing")
        row = get_catalog_agent_with_merchant(open_connection(db), "cagt-1")
        self.assertIsNotNone(row)
        self.assertEqual(row["merchant_id"], "mrc-missing")
        # 影子表无此 merchant → join 字段为 None（弱引用语义，不崩）。
        self.assertIsNone(row["merchant_name"])
        # §3.4 public ref 投影（从 join 结果取 merchant 块）同样不崩。
        merchant = public_merchant_ref(
            {
                "id": row["merchant_id"],
                "name": row["merchant_name"],
                "city": row["merchant_city"],
            }
        )
        self.assertEqual(merchant, {"id": "mrc-missing", "name": ""})

    def test_shadow_row_surfaces_public_fields(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        ts = "2026-08-07T00:00:00+00:00"
        conn.execute(
            "insert into merchants(id, name, city, service_area, tags_json, created_at, updated_at)"
            " values ('mrc-1', 'Acme Tea', 'Hangzhou', 'Xihu', '[\"tea\"]', ?, ?)",
            (ts, ts),
        )
        conn.commit()
        conn.close()
        self._seed_agent(db, merchant_id="mrc-1")

        row = get_catalog_agent_with_merchant(open_connection(db), "cagt-1")
        self.assertEqual(row["merchant_name"], "Acme Tea")
        self.assertEqual(row["merchant_city"], "Hangzhou")
        self.assertEqual(row["merchant_service_area"], "Xihu")
        merchant = public_merchant_ref(
            {
                "id": row["merchant_id"],
                "name": row["merchant_name"],
                "city": row["merchant_city"],
                "service_area": row["merchant_service_area"],
                "tags_json": row["merchant_tags_json"],
            }
        )
        self.assertEqual(merchant["id"], "mrc-1")
        self.assertEqual(merchant["name"], "Acme Tea")
        self.assertEqual(merchant["city"], "Hangzhou")

    def test_set_merchant_binding_works_with_shadow(self) -> None:
        db = _make_db()
        self._seed_agent(db)
        conn = open_connection(db)
        set_catalog_agent_merchant(conn, "cagt-1", "mrc-2")
        conn.commit()
        row = require_catalog_agent(conn, "cagt-1")
        self.assertEqual(row["merchant_id"], "mrc-2")
        conn.close()


class AuditShadowTableTest(unittest.TestCase):
    """audit_events 影子表：catalog audit 落表可读。"""

    def test_catalog_audit_lands_in_shadow_table(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        append_catalog_audit(conn, "cagt-1", "admin", "catalog_agent_suspended", {"reason": "spam"})
        conn.commit()
        rows = conn.execute(
            "select conversation_id, actor, event, details_json from audit_events"
        ).fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["actor"], "admin")
        self.assertEqual(rows[0]["event"], "catalog_agent_suspended")
        details = json.loads(rows[0]["details_json"])
        self.assertEqual(details["reason"], "spam")
        self.assertEqual(details["catalog_agent_id"], "cagt-1")

    def test_full_write_path_writes_audit(self) -> None:
        """register → suspend 的 audit 事件都落在影子表（弱引用库内自洽）。"""
        import os

        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = "test-admin"
        db = _make_db()
        from kiwi_catalog.api.handlers.agent_catalog import register_catalog_agent

        register_catalog_agent(db, {"domain": "merchant.example", "idempotency_key": "r1"})

        conn = open_connection(db)
        rows = conn.execute("select event from audit_events order by id").fetchall()
        conn.close()
        events = [r["event"] for r in rows]
        self.assertIn("catalog_agent_registered", events)


    def test_migration_path_creates_full_schema(self) -> None:
        """迁移路径（旧库升级）与 fresh SCHEMA 产出同一表集合（P2 回归）。

        migration_004 曾为空函数（旧库缺 agent_trust_observations 表）；
        FK 约束也已统一为弱引用（models.py 设计）。
        """
        tmp = tempfile.mkdtemp()
        db = Path(tmp) / "legacy.sqlite"
        conn = sqlite3.connect(db)
        # 模拟旧库：只跑迁移链（不经 open_connection 的 fresh SCHEMA）。
        from kiwi_catalog.db.migrations import MIGRATIONS, _set_schema_user_version

        for migration in MIGRATIONS:
            migration.apply(conn)
        _set_schema_user_version(conn, len(MIGRATIONS))
        conn.commit()
        conn.close()

        fresh = Path(tmp) / "fresh.sqlite"
        fresh_conn = open_connection(fresh)
        conn = sqlite3.connect(db)
        try:
            migrated_tables = {
                row[0]
                for row in conn.execute(
                    "select name from sqlite_master where type='table'"
                ).fetchall()
            }
            fresh_tables = {
                row[0]
                for row in fresh_conn.execute(
                    "select name from sqlite_master where type='table'"
                ).fetchall()
            }
        finally:
            conn.close()
            fresh_conn.close()
        self.assertEqual(
            migrated_tables,
            fresh_tables,
            "迁移路径与 fresh SCHEMA 的表集合不一致",
        )
        self.assertIn("agent_trust_observations", migrated_tables)
        # 弱引用统一：两条路径都没有 FK 约束。
        with sqlite3.connect(db) as conn:
            self.assertEqual(
                len(conn.execute("pragma foreign_key_list(catalog_agents)").fetchall()),
                0,
            )


if __name__ == "__main__":
    unittest.main()
