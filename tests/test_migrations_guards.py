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

"""迁移升级守卫回归测试（审查 P2）。

- v7 唯一索引：历史重复 merchant 绑定 → fail-closed 明确错误（而非静默卡死启动）；
- v8 回填：只回填仍持默认值的行——中间版本已写入的真实三域值不得被覆盖；
- v11 canonical_domain 唯一索引：数据层兜底存在，重复写入抛 IntegrityError；
- v23 死列删除：shopping_token_encrypted 从旧库移除，既有行其他列不丢。
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import kiwi_catalog.db.migrations as migrations_mod
from kiwi_catalog.db.migrations import (
    MIGRATIONS,
    Migration,
    _set_schema_user_version,
    migration_007_merchant_single_agent,
    migration_008_three_state_domains,
    migration_011_search_indexes_and_domain_unique,
    migration_023_drop_merchant_shopping_token,
    run_migrations,
    schema_user_version,
)

_TS = "2026-01-01T00:00:00+00:00"


def _legacy_db() -> tuple[Path, sqlite3.Connection]:
    """只跑迁移链的旧库（不经 open_connection 的 fresh SCHEMA）。"""
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "legacy.sqlite"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    for migration in MIGRATIONS:
        migration.apply(conn)
    _set_schema_user_version(conn, len(MIGRATIONS))
    conn.commit()
    return db, conn


def _insert_agent(
    conn: sqlite3.Connection, agent_id: str, domain: str, merchant_id: str = ""
) -> None:
    conn.execute(
        "insert into catalog_agents("
        " catalog_agent_id, canonical_domain, merchant_id, display_name,"
        " source_type, hosting_mode, lifecycle_status, verification_status,"
        " verification_level, freshness_state, administrative_state,"
        " handoff_destination_types, first_seen_at, last_seen_at,"
        " created_at, updated_at)"
        " values (?, ?, ?, ?, 'self_registered', 'direct', 'active',"
        " 'discovered', 'discovered', 'fresh', 'active',"
        " '[]', ?, ?, ?, ?)",
        (agent_id, domain, merchant_id, agent_id, _TS, _TS, _TS, _TS),
    )


class Migration007DuplicateGuardTest(unittest.TestCase):
    def test_duplicate_merchant_bindings_fail_closed_with_listing(self) -> None:
        """审查 P2：v7 建唯一索引前检测重复——给出数据清单而非裸 IntegrityError。"""
        _, conn = _legacy_db()
        try:
            conn.execute("drop index if exists idx_catalog_agents_merchant_unique")
            _insert_agent(conn, "cagt_a", "a.example", "mrc_1")
            _insert_agent(conn, "cagt_b", "b.example", "mrc_1")
            conn.commit()
            with self.assertRaises(RuntimeError) as ctx:
                migration_007_merchant_single_agent(conn)
            message = str(ctx.exception)
            self.assertIn("mrc_1", message)
            self.assertIn("cagt_a", message)
            self.assertIn("cagt_b", message)
        finally:
            conn.close()


class Migration008BackfillGuardTest(unittest.TestCase):
    def test_real_values_not_overwritten_by_backfill(self) -> None:
        """审查 P2：列已存在 + 已写入真实值（中间版本场景）→ 回填不得覆盖。"""
        _, conn = _legacy_db()
        try:
            _insert_agent(conn, "cagt_x", "x.example")
            # 模拟中间版本写入：真实三域值 + legacy 折叠列被置为 suspended
            conn.execute(
                "update catalog_agents set verification_level = 'profile_valid',"
                " freshness_state = 'fresh', administrative_state = 'active',"
                " verification_status = 'suspended' where catalog_agent_id = 'cagt_x'"
            )
            conn.commit()
            migration_008_three_state_domains(conn)
            conn.commit()
            row = conn.execute(
                "select verification_level, administrative_state from catalog_agents"
                " where catalog_agent_id = 'cagt_x'"
            ).fetchone()
            # legacy status='suspended' 推导 admin='suspended'——但真实值
            # 'active' 必须保留（列非默认值 → 回填守卫跳过）
            self.assertEqual(row[0], "profile_valid")
            self.assertEqual(row[1], "active")
        finally:
            conn.close()

    def test_default_rows_still_backfilled(self) -> None:
        """仍持默认值的行（列刚被本次 ALTER 添加的场景）正常回填。"""
        _, conn = _legacy_db()
        try:
            _insert_agent(conn, "cagt_x", "x.example")
            conn.execute(
                "update catalog_agents set verification_status = 'rejected'"
                " where catalog_agent_id = 'cagt_x'"
            )
            conn.commit()
            migration_008_three_state_domains(conn)
            conn.commit()
            row = conn.execute(
                "select administrative_state from catalog_agents"
                " where catalog_agent_id = 'cagt_x'"
            ).fetchone()
            self.assertEqual(row[0], "rejected")
        finally:
            conn.close()


class Migration011DomainUniqueTest(unittest.TestCase):
    def test_duplicate_domain_insert_raises_integrity_error(self) -> None:
        """审查 P2：canonical_domain 部分唯一索引兜底并发注册重复行。"""
        _, conn = _legacy_db()
        try:
            migration_011_search_indexes_and_domain_unique(conn)
            _insert_agent(conn, "cagt_a", "dup.example")
            conn.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                _insert_agent(conn, "cagt_b", "dup.example")
        finally:
            conn.close()


class MigrationAtomicityTest(unittest.TestCase):
    def test_failed_migration_rolls_back_user_version_and_ddl(self) -> None:
        """审查 C-M4：迁移链 SAVEPOINT 原子——中途失败回滚 DDL 与 user_version。"""
        tmp = tempfile.mkdtemp()
        db = Path(tmp) / "atomic.sqlite"
        conn = sqlite3.connect(db)
        try:
            def failing(c: sqlite3.Connection) -> None:
                c.execute("create table tmp_c4_marker (x integer)")
                _set_schema_user_version(c, 1)  # 模拟 apply 后的 user_version 推进
                raise RuntimeError("boom mid-migration")

            fake = [Migration(version=1, name="c4_fake", apply=failing)]
            with mock.patch.object(migrations_mod, "MIGRATIONS", fake):
                with self.assertRaises(RuntimeError):
                    run_migrations(conn)
            # DDL 回滚：失败迁移建的表不存在
            row = conn.execute(
                "select name from sqlite_master where type='table' and name='tmp_c4_marker'"
            ).fetchone()
            self.assertIsNone(row)
            # user_version 回滚到 0（此前中途失败会停在最后成功条）
            self.assertEqual(schema_user_version(conn), 0)
        finally:
            conn.close()


class Migration023DropShoppingTokenTest(unittest.TestCase):
    """审查 P3-05：v23 删除 merchant_tokens.shopping_token_encrypted 死列。"""

    def _db_at_v22(self) -> sqlite3.Connection:
        """只跑到 v22 的旧库（仍含 shopping_token_encrypted 列）。"""
        tmp = tempfile.mkdtemp()
        conn = sqlite3.connect(Path(tmp) / "legacy.sqlite")
        conn.row_factory = sqlite3.Row
        for migration in MIGRATIONS:
            if migration.version > 22:
                break
            migration.apply(conn)
        _set_schema_user_version(conn, 22)
        conn.commit()
        return conn

    def test_column_dropped_and_other_columns_preserved(self) -> None:
        conn = self._db_at_v22()
        try:
            conn.execute(
                "insert into merchant_tokens("
                " merchant_id, token_hash, token_encrypted, shopping_token_encrypted,"
                " status, issued_at, rotated_at, revoked_at)"
                " values ('mkt_a', 'hash-a', 'enc-a', 'shop-enc-a', 'active', ?, 'r1', '')",
                (_TS,),
            )
            conn.commit()
            migration_023_drop_merchant_shopping_token(conn)
            conn.commit()
            columns = {
                str(row[1])
                for row in conn.execute("pragma table_info(merchant_tokens)").fetchall()
            }
            self.assertNotIn("shopping_token_encrypted", columns)
            # 数据保留：既有行的其他列不丢
            row = conn.execute(
                "select * from merchant_tokens where merchant_id = 'mkt_a'"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["token_hash"], "hash-a")
            self.assertEqual(row["token_encrypted"], "enc-a")
            self.assertEqual(row["status"], "active")
            self.assertEqual(row["issued_at"], _TS)
            self.assertEqual(row["rotated_at"], "r1")
            # 幂等：列已不存在再跑不报错
            migration_023_drop_merchant_shopping_token(conn)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
