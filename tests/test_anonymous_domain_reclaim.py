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

"""审查 P3：未验证的匿名域名占位超过 TTL 后可被新的匿名注册复用。"""

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from kiwi_catalog.core.errors import ConflictError
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent


class AnonymousDomainReclaimTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = open_connection(Path(self.tmp.name) / "catalog.sqlite")
        self.addCleanup(self.conn.close)

    def _register(self) -> str:
        result = register_catalog_agent(self.conn, domain="squat.example")
        self.conn.commit()
        return str(result["catalog_agent_id"])

    def _age_row(self, catalog_agent_id: str, days: int, level: str = "discovered") -> None:
        old = (datetime.now(UTC) - timedelta(days=days)).replace(microsecond=0).isoformat()
        self.conn.execute(
            "update catalog_agents set created_at = ?, verification_level = ?"
            " where catalog_agent_id = ?",
            (old, level, catalog_agent_id),
        )
        self.conn.commit()

    def test_partial_unique_index_guards_concurrent_anonymous_rows(self) -> None:
        row = self.conn.execute(
            "select 1 from sqlite_master where type = 'index'"
            " and name = 'idx_catalog_agents_anonymous_domain'"
        ).fetchone()
        self.assertIsNotNone(row, "anonymous-domain unique index is missing")

    def test_fresh_anonymous_registration_still_blocks_others(self) -> None:
        self._register()
        with self.assertRaises(ConflictError):
            self._register()

    def test_stale_unverified_anonymous_row_can_be_reused(self) -> None:
        first = self._register()
        self._age_row(first, 10)
        second = self._register()
        self.assertEqual(first, second)

    def test_stale_row_already_verified_is_not_reclaimed(self) -> None:
        first = self._register()
        self._age_row(first, 10, level="profile_valid")
        with self.assertRaises(ConflictError):
            self._register()


if __name__ == "__main__":
    unittest.main()
