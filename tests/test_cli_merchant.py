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

"""catalog merchant CLI 命令测试（docs/kiwi-catalog-token-portal-design-v0.1 §9）。

本地直连 SQLite（信任边界同既有 CLI 约定）；与 HTTP handler 共用
services/merchant_tokens.py——本组测试锁定 CLI 行为与输出契约：
- applications list/approve/reject（approve 明文 token 仅输出一次）；
- token rotate（旧 token 立即失效）/ revoke（幂等）；
- status --token（token 即身份）/ --merchant-id（本地信任边界）。
"""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from kiwi_catalog.cli import build_parser, main
from kiwi_catalog.db.session import db_session, now_iso


class CatalogMerchantCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "catalog.sqlite"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *args: str, expect_fail: bool = False) -> str:
        output = StringIO()
        errors = StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                main(["--db", str(self.db), *args])
            except SystemExit as exc:
                # main 以 SystemExit(str) 报错——消息进 stderr
                if exc.code:
                    errors.write(str(exc.code) + "\n")
                if not expect_fail:
                    raise
        return output.getvalue() + errors.getvalue()

    def _seed_application(self) -> int:
        """直接写 pending 工单（apply 是公开 HTTP 面，CLI 不提供）。"""
        with db_session(self.db) as conn:
            cursor = conn.execute(
                "insert into merchant_applications"
                " (status, domain, agent_name, contact_email, purpose, created_at)"
                " values ('pending', ?, ?, ?, ?, ?)",
                ("seed.example", "Seed Shop", "seed@example.com", "", now_iso()),
            )
            return int(cursor.lastrowid or 0)

    def _approve_first(self) -> dict:
        app_id = self._seed_application()
        out = self._run("catalog", "merchant", "applications", "approve", str(app_id), "--format", "json")
        return json.loads(out)

    # ── 命令注册 ───────────────────────────────────────────────────────────

    def test_merchant_subcommands_registered(self) -> None:
        parser = build_parser()
        subparsers = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        catalog = subparsers.choices["catalog"]
        merchant = catalog._actions[-1].choices["merchant"]
        merchant_cmds = list(merchant._actions[-1].choices.keys())
        self.assertEqual(sorted(merchant_cmds), ["applications", "status", "token"])

    # ── applications list ──────────────────────────────────────────────────

    def test_applications_list_empty(self) -> None:
        out = self._run("catalog", "merchant", "applications", "list")
        self.assertIn("(no applications)", out)

    def test_applications_list_shows_pending(self) -> None:
        self._seed_application()
        out = self._run("catalog", "merchant", "applications", "list")
        self.assertIn("#1", out)
        self.assertIn("pending", out)
        self.assertIn("Seed Shop", out)

    # ── applications approve ───────────────────────────────────────────────

    def test_approve_issues_merchant_and_token_once(self) -> None:
        issued = self._approve_first()
        self.assertTrue(issued["ok"])
        self.assertTrue(issued["merchant_id"].startswith("mkt_"))
        self.assertTrue(issued["token"].startswith("mkt_"))
        self.assertEqual(issued["application_id"], 1)

    def test_approve_twice_conflicts(self) -> None:
        app_id = self._seed_application()
        self._run("catalog", "merchant", "applications", "approve", str(app_id))
        out = self._run(
            "catalog", "merchant", "applications", "approve", str(app_id), expect_fail=True
        )
        self.assertIn("already", out)

    def test_approve_unknown_application(self) -> None:
        out = self._run("catalog", "merchant", "applications", "approve", "999", expect_fail=True)
        self.assertIn("Unknown application", out)

    # ── applications reject ────────────────────────────────────────────────

    def test_reject_marks_application(self) -> None:
        app_id = self._seed_application()
        out = self._run(
            "catalog", "merchant", "applications", "reject", str(app_id), "--note", "domain unverifiable"
        )
        self.assertIn(f"rejected application #{app_id}", out)
        listed = self._run("catalog", "merchant", "applications", "list", "--status", "rejected")
        self.assertIn("Seed Shop", listed)

    # ── token rotate ───────────────────────────────────────────────────────

    def test_rotate_invalidates_old_token(self) -> None:
        issued = self._approve_first()
        mid = issued["merchant_id"]
        out = self._run("catalog", "merchant", "token", "rotate", mid, "--format", "json")
        rotated = json.loads(out)
        self.assertTrue(rotated["ok"])
        self.assertNotEqual(rotated["token"], issued["token"])
        # 旧 token 立即失效（status --token fail-closed）
        out = self._run(
            "catalog", "merchant", "status", "--token", issued["token"], expect_fail=True
        )
        self.assertIn("invalid owner token", out)
        # 新 token 生效
        out = self._run("catalog", "merchant", "status", "--token", rotated["token"])
        self.assertIn(mid, out)
        self.assertIn("active", out)

    # ── token revoke ───────────────────────────────────────────────────────

    def test_revoke_is_idempotent_and_blocks_token(self) -> None:
        issued = self._approve_first()
        mid = issued["merchant_id"]
        out = self._run("catalog", "merchant", "token", "revoke", mid)
        self.assertIn("revoked", out)
        # 重复吊销幂等
        out = self._run("catalog", "merchant", "token", "revoke", mid)
        self.assertIn("revoked", out)
        # 吊销后 token 自查 fail-closed
        out = self._run(
            "catalog", "merchant", "status", "--token", issued["token"], expect_fail=True
        )
        self.assertIn("invalid owner token", out)

    # ── status ─────────────────────────────────────────────────────────────

    def test_status_by_token(self) -> None:
        issued = self._approve_first()
        out = self._run("catalog", "merchant", "status", "--token", issued["token"])
        self.assertIn(issued["merchant_id"], out)
        self.assertIn("token status:   active", out)
        self.assertIn("agents:         0", out)

    def test_status_by_merchant_id_local_trust(self) -> None:
        issued = self._approve_first()
        out = self._run("catalog", "merchant", "status", "--merchant-id", issued["merchant_id"])
        self.assertIn(issued["merchant_id"], out)

    def test_status_invalid_token(self) -> None:
        out = self._run("catalog", "merchant", "status", "--token", "mkt_bogus", expect_fail=True)
        self.assertIn("invalid owner token", out)

    def test_status_json_shape(self) -> None:
        issued = self._approve_first()
        out = self._run("catalog", "merchant", "status", "--token", issued["token"], "--format", "json")
        status = json.loads(out)
        self.assertEqual(status["merchant_id"], issued["merchant_id"])
        self.assertEqual(status["token_status"], "active")
        self.assertIn("agents_count", status)
        self.assertIn("listings_count", status)


if __name__ == "__main__":
    unittest.main()
