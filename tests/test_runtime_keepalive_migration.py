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

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION
from kiwi_catalog.db.session import init_db, open_connection


class RuntimeKeepaliveMigrationTest(unittest.TestCase):
    def _v48_database(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        try:
            init_db(conn)
            # Remove exactly the v49 additions and move the version back.
            conn.execute("alter table runtime_keepalive_consents drop column last_attempt_at")
            conn.execute("drop table runtime_keepalive_state")
            conn.execute(
                "insert into runtime_keepalive_consents"
                " (catalog_agent_id,merchant_id,scope,terms_version,granted_at,revoked_at)"
                " values ('cagt_old','mkt_old','directory_keepalive',"
                "'workbuddy-keepalive-v1-2026-11-04','2026-11-01T00:00:00+00:00','')"
            )
            conn.execute("pragma user_version = 48")
            conn.commit()
        finally:
            conn.close()

    def _v47_database(self, path: Path) -> None:
        conn = sqlite3.connect(path)
        try:
            init_db(conn)
            conn.execute(
                "insert into catalog_agents"
                " (catalog_agent_id,merchant_id,display_name,source_type,lifecycle_status,"
                " verification_status,freshness_state,administrative_state,first_seen_at,"
                " last_seen_at,created_at,updated_at)"
                " values ('cagt_v47','mkt_v47','v47','hosted','active','commerce_verified',"
                " 'fresh','active','2026-11-01T00:00:00+00:00','2026-11-01T00:00:00+00:00',"
                " '2026-11-01T00:00:00+00:00','2026-11-01T00:00:00+00:00')"
            )
            conn.execute(
                "insert into runtime_access_consents values"
                " ('cagt_v47','mkt_v47','directory_custody',"
                " 'workbuddy-share-v1-2026-10-27','2026-11-01T00:00:00+00:00','')"
            )
            conn.execute(
                "insert into public_inquiry_consents values"
                " ('cagt_v47','mkt_v47','binding-v47','open-inquiry-v1',"
                " '2026-11-01T00:00:00+00:00','')"
            )
            # v47 did not have either keepalive table.
            conn.execute("drop table runtime_keepalive_consents")
            conn.execute("drop table runtime_keepalive_state")
            conn.execute("pragma user_version = 47")
            conn.commit()
        finally:
            conn.close()

    def test_v47_to_v49_preserves_existing_authorizations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.sqlite"
            backup_path = Path(tmp) / "catalog-v47.sqlite"
            self._v47_database(path)
            source = sqlite3.connect(path)
            target = sqlite3.connect(backup_path)
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()

            conn = open_connection(path)
            try:
                self.assertEqual(conn.execute("pragma user_version").fetchone()[0], 49)
                custody = conn.execute(
                    "select merchant_id,terms_version from runtime_access_consents where catalog_agent_id='cagt_v47'"
                ).fetchone()
                self.assertEqual(custody["merchant_id"], "mkt_v47")
                self.assertEqual(custody["terms_version"], "workbuddy-share-v1-2026-10-27")
                inquiry = conn.execute(
                    "select binding_id,terms_version from public_inquiry_consents where catalog_agent_id='cagt_v47'"
                ).fetchone()
                self.assertEqual(inquiry["binding_id"], "binding-v47")
                self.assertEqual(inquiry["terms_version"], "open-inquiry-v1")
                self.assertEqual(conn.execute("pragma integrity_check").fetchone()[0], "ok")
            finally:
                conn.close()

            restored = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
            try:
                self.assertEqual(restored.execute("pragma user_version").fetchone()[0], 47)
                self.assertEqual(restored.execute("pragma integrity_check").fetchone()[0], "ok")
                self.assertEqual(
                    restored.execute(
                        "select count(*) from runtime_access_consents where catalog_agent_id='cagt_v47'"
                    ).fetchone()[0],
                    1,
                )
                self.assertFalse(
                    restored.execute(
                        "select 1 from sqlite_master where type='table' and name='runtime_keepalive_consents'"
                    ).fetchone()
                )
            finally:
                restored.close()

    def test_v48_to_v49_preserves_rows_and_adds_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.sqlite"
            self._v48_database(path)
            conn = open_connection(path)
            try:
                self.assertEqual(conn.execute("pragma user_version").fetchone()[0], CURRENT_SCHEMA_VERSION)
                row = conn.execute(
                    "select catalog_agent_id,last_attempt_at from runtime_keepalive_consents"
                ).fetchone()
                self.assertEqual(row["catalog_agent_id"], "cagt_old")
                self.assertEqual(row["last_attempt_at"], "")
                state = conn.execute(
                    "select singleton,last_tick_at from runtime_keepalive_state"
                ).fetchone()
                self.assertEqual((state["singleton"], state["last_tick_at"]), (1, ""))
                self.assertEqual(conn.execute("pragma integrity_check").fetchone()[0], "ok")
            finally:
                conn.close()

    def test_backup_restores_v48_after_v49_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.sqlite"
            backup_path = Path(tmp) / "catalog-v48.sqlite"
            self._v48_database(path)
            source = sqlite3.connect(path)
            target = sqlite3.connect(backup_path)
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()
            upgraded = open_connection(path)
            try:
                self.assertEqual(upgraded.execute("pragma user_version").fetchone()[0], 49)
            finally:
                upgraded.close()
            restored = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
            try:
                self.assertEqual(restored.execute("pragma user_version").fetchone()[0], 48)
                self.assertEqual(
                    restored.execute("pragma integrity_check").fetchone()[0], "ok"
                )
                self.assertTrue(
                    restored.execute(
                        "select 1 from sqlite_master where type='table' and name='runtime_keepalive_consents'"
                    ).fetchone()
                )
                self.assertFalse(
                    restored.execute(
                        "select 1 from sqlite_master where type='table' and name='runtime_keepalive_state'"
                    ).fetchone()
                )
            finally:
                restored.close()


if __name__ == "__main__":
    unittest.main()
