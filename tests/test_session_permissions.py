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

"""数据目录/文件权限回归测试（审查 P2：CLAUDE.md 0700/0600 约定落地）。"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.db.session import db_session


class SessionPermissionsTest(unittest.TestCase):
    def test_db_file_and_directory_permissions(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "catalog.sqlite"

        with db_session(db_path):
            pass  # 建库 + 迁移 + 写 WAL

        self.assertEqual(
            stat.S_IMODE(db_path.stat().st_mode), 0o600, "catalog.sqlite 必须 0600"
        )
        self.assertEqual(
            stat.S_IMODE(tmp.stat().st_mode), 0o700, "数据目录必须 0700"
        )
        # WAL 边车继承主库权限（SQLite unix 语义）
        wal = Path(f"{db_path}-wal")
        if wal.exists():
            self.assertEqual(stat.S_IMODE(wal.stat().st_mode), 0o600)

    def test_existing_db_file_permissions_normalized_to_0600(self) -> None:
        """已存在但权限过宽的库：打开时收紧到 0600。"""
        tmp = Path(tempfile.mkdtemp())
        db_path = tmp / "catalog.sqlite"
        with db_session(db_path):
            pass
        os.chmod(db_path, 0o644)
        with db_session(db_path):
            pass
        self.assertEqual(stat.S_IMODE(db_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
