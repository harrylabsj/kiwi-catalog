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

"""审查 P1-2 回归：unknown-outcome 围栏的对账闭环。

覆盖：
- 重启恢复后的围栏 agent 在 reconcile 后可再次 enqueue（进程内清除生效）；
- 守卫 UPDATE 拒绝改写已完成行，重复 reconcile 显式失败；
- 模块级 reconcile（独立连接）后终态行可被 cleanup_terminal_tasks 回收；
- CLI list / resolve 与 doctor 围栏清单端到端。
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any

from kiwi_catalog.cli import main
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.services.agent_verification import (
    VerificationQueue,
    VerificationQueueConfig,
    VerificationQueueOutcomeUnknownError,
    reconcile_verification_unknown,
)
from kiwi_catalog.services.verification_queue_ledger import (
    cleanup_terminal_tasks,
    fetch_task_row,
    insert_pending_task,
    mark_task_running,
    mark_task_unknown,
)
from kiwi_catalog.services.verification_stages import VerificationResult


class _StubService:
    """Minimal VerificationService double used by the real queue workers."""

    def verify(self, catalog_agent_id: str, actor: str = "verification_worker") -> VerificationResult:
        return VerificationResult(
            catalog_agent_id=catalog_agent_id,
            previous_status="unverified",
            status="profile_valid",
            stages=(),
        )

    refresh = verify
    mark_stale = verify
    suspend = verify

    def commit(self) -> None:
        return None

    def close(self, commit: bool = True) -> None:
        return None


def _seed_fence(
    db: Path,
    *,
    task_id: str = "vt-fenced",
    catalog_agent_id: str = "cagt_fenced",
    error: str = "process killed during network I/O",
) -> None:
    """Write the exact row mark_task_unknown leaves behind (running + marker)."""
    conn = open_connection(db)
    try:
        insert_pending_task(
            conn,
            task_id=task_id,
            catalog_agent_id=catalog_agent_id,
            kind="verify",
            actor="fixture",
            enqueued_at=time.time(),
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        mark_task_running(conn, task_id=task_id, started_at=time.time(), updated_at=now_iso())
        mark_task_unknown(
            conn,
            task_id=task_id,
            error=error,
            finished_at=time.time(),
            updated_at=now_iso(),
        )
        conn.commit()
    finally:
        conn.close()


def _ledger_row(db: Path, task_id: str) -> dict[str, Any]:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        row = fetch_task_row(conn, task_id)
        return dict(row) if row is not None else {}
    finally:
        conn.close()


class VerificationQueueReconcileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="p1-2-reconcile-")
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "catalog.sqlite"
        # 建迁移后的 schema（对账走 db.session 的 open_connection 路径）。
        conn = open_connection(self.db)
        conn.close()
        self.queues: list[VerificationQueue] = []

    def _queue(self) -> VerificationQueue:
        q = VerificationQueue(
            service_factory=lambda: _StubService(),
            config=VerificationQueueConfig(
                max_pending=10, concurrency=1, task_timeout_seconds=2.0
            ),
            db_path=str(self.db),
        )
        self.queues.append(q)
        return q

    def tearDown(self) -> None:
        for q in self.queues:
            q.shutdown(wait=True, timeout=2)

    def test_restart_fence_blocks_enqueue_until_reconciled(self) -> None:
        _seed_fence(self.db)
        q = self._queue()

        # 重启恢复把 running 行写入 _uncertain_agents：同 agent 的 enqueue 必须 fail-closed。
        with self.assertRaises(VerificationQueueOutcomeUnknownError):
            q.enqueue("cagt_fenced")
        self.assertEqual(q._uncertain_agents.get("cagt_fenced"), {"vt-fenced"})

        summary = q.reconcile_unknown(
            "vt-fenced", outcome="discarded", reason="operator confirmed no durable effect"
        )
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["verification_status"], "reconciled_discarded")
        self.assertIn("reconciled by operator: discarded", summary["error"])
        self.assertIn("operator confirmed no durable effect", summary["error"])
        self.assertNotIn("cagt_fenced", q._uncertain_agents)
        row = _ledger_row(self.db, "vt-fenced")
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["verification_status"], "reconciled_discarded")

        # 围栏清除后同一 agent 可再次入队并正常完成。
        out = q.enqueue("cagt_fenced", wait=True, timeout=2)
        self.assertEqual(out.status, "completed")
        self.assertNotEqual(out.task_id, "vt-fenced")

    def test_agent_stays_fenced_until_every_unknown_task_is_resolved(self) -> None:
        _seed_fence(self.db, task_id="vt-first")
        _seed_fence(self.db, task_id="vt-second")
        q = self._queue()

        q.reconcile_unknown("vt-second", outcome="discarded")
        with self.assertRaises(VerificationQueueOutcomeUnknownError):
            q.enqueue("cagt_fenced")

        q.reconcile_unknown("vt-first", outcome="completed")
        self.assertEqual(q.wait("vt-first", timeout=0).status, "completed")
        self.assertEqual(q.enqueue("cagt_fenced", wait=True, timeout=2).status, "completed")

    def test_completed_task_cannot_be_reconciled_and_ledger_is_unchanged(self) -> None:
        q = self._queue()
        done = q.enqueue("cagt_done", wait=True, timeout=2)
        self.assertEqual(done.status, "completed")
        before = _ledger_row(self.db, done.task_id)
        self.assertEqual(before["status"], "completed")

        from kiwi_catalog.core.errors import ConflictError

        with self.assertRaises(ConflictError):
            q.reconcile_unknown(done.task_id, outcome="discarded")
        after = _ledger_row(self.db, done.task_id)
        self.assertEqual(after, before, "守卫 UPDATE 不得改写已完成行")

    def test_second_reconcile_is_rejected_not_silent(self) -> None:
        _seed_fence(self.db, task_id="vt-once")
        q = self._queue()
        first = q.reconcile_unknown("vt-once", outcome="completed", reason="first")
        self.assertEqual(first["status"], "completed")

        from kiwi_catalog.core.errors import ConflictError

        with self.assertRaises(ConflictError) as ctx:
            q.reconcile_unknown("vt-once", outcome="discarded", reason="second")
        self.assertIn("already resolved", str(ctx.exception))
        row = _ledger_row(self.db, "vt-once")
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["verification_status"], "reconciled_completed")
        self.assertIn("first", row["error"])
        self.assertNotIn("second", row["error"])

    def test_module_reconcile_uses_independent_connection_and_is_gc_reclaimable(self) -> None:
        _seed_fence(self.db, task_id="vt-module", error="unknown outcome")
        summary = reconcile_verification_unknown(
            self.db, "vt-module", outcome="completed", reason="commit confirmed by operator"
        )
        self.assertEqual(summary["task_id"], "vt-module")
        self.assertEqual(summary["catalog_agent_id"], "cagt_fenced")
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["verification_status"], "reconciled_completed")
        self.assertIn("reconciled by operator: completed", summary["error"])

        row = _ledger_row(self.db, "vt-module")
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["verification_status"], "reconciled_completed")

        conn = open_connection(self.db)
        try:
            cleanup_terminal_tasks(conn, time.time() + 86400)
            conn.commit()
            self.assertIsNone(fetch_task_row(conn, "vt-module"))
        finally:
            conn.close()

    def test_module_reconcile_rejects_missing_and_terminal_tasks(self) -> None:
        from kiwi_catalog.core.errors import ConflictError, NotFoundError

        with self.assertRaises(NotFoundError):
            reconcile_verification_unknown(self.db, "vt-missing", outcome="discarded")
        _seed_fence(self.db, task_id="vt-terminal-check")
        reconcile_verification_unknown(self.db, "vt-terminal-check", outcome="discarded")
        with self.assertRaises(ConflictError):
            reconcile_verification_unknown(self.db, "vt-terminal-check", outcome="discarded")

    def test_cli_list_and_resolve_end_to_end(self) -> None:
        # 空态：text 明确无围栏；json 为空清单。
        empty_text = self._run_cli("catalog", "verification-queue", "list")
        self.assertIn("No verification tasks are fenced", empty_text)
        empty_json = json.loads(self._run_cli(
            "catalog", "verification-queue", "list", "--format", "json"
        ))
        self.assertEqual(empty_json["tasks"], [])
        self.assertEqual(empty_json["count"], 0)

        _seed_fence(self.db, task_id="vt-cli", error="killed mid-commit")
        listed = json.loads(self._run_cli(
            "catalog", "verification-queue", "list", "--format", "json"
        ))
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], "vt-cli")
        self.assertEqual(listed["tasks"][0]["catalog_agent_id"], "cagt_fenced")
        self.assertIn("killed mid-commit", listed["tasks"][0]["error"])

        resolved = json.loads(self._run_cli(
            "catalog", "verification-queue", "resolve",
            "--task-id", "vt-cli", "--outcome", "discarded",
            "--reason", "operator review", "--format", "json",
        ))
        self.assertTrue(resolved["ok"])
        self.assertEqual(resolved["reconciliation"]["status"], "failed")
        self.assertEqual(
            resolved["reconciliation"]["verification_status"], "reconciled_discarded"
        )
        row = _ledger_row(self.db, "vt-cli")
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["verification_status"], "reconciled_discarded")

        # 第二次 resolve 必须显式失败（main 把 ShoppingCliError 转成 SystemExit）。
        with self.assertRaises(SystemExit) as ctx:
            self._run_cli(
                "catalog", "verification-queue", "resolve",
                "--task-id", "vt-cli", "--outcome", "completed",
            )
        self.assertIn("already resolved", str(ctx.exception.code))

    def test_doctor_report_exposes_fenced_task_list(self) -> None:
        _seed_fence(self.db, task_id="vt-doctor", error="process killed")
        report = json.loads(self._run_cli("catalog", "doctor", "--format", "json"))
        self.assertEqual(report["unknown_outcome_task_count"], 1)
        self.assertEqual(report["unknown_outcome_tasks"][0]["task_id"], "vt-doctor")
        self.assertEqual(
            report["unknown_outcome_tasks"][0]["catalog_agent_id"], "cagt_fenced"
        )
        # 既有键保持向后兼容。
        for key in ("ok", "healthy", "total_agents", "issues", "warnings", "checked_at"):
            self.assertIn(key, report)
        text = self._run_cli("catalog", "doctor")
        self.assertIn("Fenced verification tasks (1)", text)
        self.assertIn("vt-doctor", text)

    def _run_cli(self, *args: str) -> str:
        output = StringIO()
        with redirect_stdout(output):
            # 不吞 SystemExit：resolve 冲突等失败必须让调用方看到。
            main(["--db", str(self.db), *args])
        return output.getvalue()


if __name__ == "__main__":
    unittest.main()
