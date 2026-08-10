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

"""VerificationQueue 执行模型回归测试（§25 Phase 2）。

覆盖 review 修复的两类缺陷：
- runaway 线程：超时后 daemon 线程不得再把 ledger 从 timeout 改写成
  completed（此前与调用方拿到的结果矛盾）；
- worker 存活：单任务异常（含 ledger 写失败）不得让 worker 线程永久死亡
  （并发预算减一且无恢复，此前 _persist_finish 抛异常 → KeyError 杀线程）。
"""
from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from kiwi_catalog.services.agent_verification import (
    VerificationQueue,
    VerificationQueueConfig,
)


class _StubService:
    """可编程的假 VerificationService（sleep 模拟慢任务；close 可被观察）。"""

    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.closed = False
        self.close_commits: list[bool] = []

    def verify(self, catalog_agent_id: str, actor: str = "verification_worker"):
        if self.delay > 0:
            time.sleep(self.delay)
        return type(
            "Res",
            (),
            {
                "status": "profile_valid",
                "catalog_agent_id": catalog_agent_id,
            },
        )()

    def commit(self) -> None:
        return None

    def close(self, commit: bool = True) -> None:
        # 审查 P2-N：cancelled 路径必须 commit=False（runaway 写随关闭回滚）
        self.close_commits.append(commit)
        self.closed = True


def _make_queue(
    db: Path,
    service_factory,
    timeout: float = 0.3,
) -> VerificationQueue:
    return VerificationQueue(
        service_factory=service_factory,
        config=VerificationQueueConfig(
            max_pending=10, concurrency=1, task_timeout_seconds=timeout
        ),
        db_path=str(db),
    )


class VerificationQueueRunawayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db = Path(self.tmp) / "queue.sqlite"
        conn = sqlite3.connect(self.db)
        conn.execute(
            """
            create table if not exists verification_queue_tasks (
                task_id text primary key,
                catalog_agent_id text not null,
                kind text not null,
                actor text not null default 'verification_worker',
                status text not null default 'pending'
                    check (status in ('pending','running','completed','failed','timeout')),
                enqueued_at real not null,
                started_at real not null default 0,
                finished_at real not null default 0,
                verification_status text not null default '',
                error text not null default '',
                result_json text not null default '{}',
                created_at text not null,
                updated_at text not null
            )
            """
        )
        # 审查 P3：队列构造要求已迁移 schema——手工建表后必须对齐 user_version
        from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION

        conn.execute(f"pragma user_version = {CURRENT_SCHEMA_VERSION}")
        conn.commit()
        conn.close()

    def _ledger_row(self, task_id: str) -> dict:
        conn = sqlite3.connect(self.db)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "select * from verification_queue_tasks where task_id = ?",
                (task_id,),
            ).fetchone()
            return dict(row) if row is not None else {}
        finally:
            conn.close()

    def test_timeout_ledger_stays_timeout_after_runaway_finishes(self) -> None:
        """超时后 runaway 线程完成也不得把 ledger 从 timeout 改写成 completed。"""
        slow_service = _StubService(delay=0.6)  # 远超 0.3s 超时
        q = _make_queue(self.db, lambda: slow_service, timeout=0.3)

        result = q.enqueue("cagt_01", wait=True, timeout=0.5)
        self.assertEqual(result.status, "timeout")

        # 等 runaway 线程真正跑完（sleep 结束、连接关闭）后 ledger 仍是 timeout。
        time.sleep(0.6)
        row = self._ledger_row(result.task_id)
        self.assertEqual(row["status"], "timeout", "runaway 不得改写 ledger")
        self.assertNotEqual(row["status"], "completed")
        # 审查 P2-N：cancelled（timeout）路径 close 必须 commit=False——
        # 此前 finally 无条件 close()（内部先 commit），runaway 写会落库。
        self.assertEqual(slow_service.close_commits, [False])
        q.shutdown(wait=False)

    def test_closed_service_commits_only_on_non_cancelled_path(self) -> None:
        """正常完成路径 close(commit=True)；timeout 路径 close(commit=False)。

        审查 P2-N：VerificationService.close 的 commit 参数——timeout 已返回
        后 runaway 线程的写必须随连接关闭回滚（此前 close 内部先 commit，
        实验复现 timeout 响应后 catalog 状态仍被推进）。
        """
        from kiwi_catalog.services.agent_verification import VerificationService

        class _RecordingConn:
            def __init__(self) -> None:
                self.commits = 0
                self.closed = False

            def commit(self) -> None:
                self.commits += 1

            def close(self) -> None:
                self.closed = True

        cancelled_conn = _RecordingConn()
        VerificationService(cancelled_conn).close(commit=False)
        self.assertEqual(cancelled_conn.commits, 0)
        self.assertTrue(cancelled_conn.closed)

        normal_conn = _RecordingConn()
        VerificationService(normal_conn).close(commit=True)
        self.assertEqual(normal_conn.commits, 1)
        self.assertTrue(normal_conn.closed)

    def test_worker_survives_persistence_error_and_still_serves_next_task(self) -> None:
        """ledger 写失败不得杀 worker（并发预算永久减一）：后续任务仍可执行。"""
        q = _make_queue(self.db, lambda: _StubService(), timeout=1.0)
        failures = {"count": 0}

        real_finish = q._persist_finish

        def flaky_finish(task_id, **kwargs):
            failures["count"] += 1
            if failures["count"] == 1:
                raise sqlite3.OperationalError("database is locked (simulated)")
            return real_finish(task_id, **kwargs)

        with mock.patch.object(q, "_persist_finish", side_effect=flaky_finish):
            first = q.enqueue("cagt_locked", wait=True, timeout=2.0)
            # 结果不丢（box 先于 persist 赋值 → completed 准确返回），
            # 绝不 KeyError 杀 worker（此前 _persist_finish 抛异常时 box
            # 缺失 → 异常传播出 worker 循环 → 并发预算永久减一）。
            self.assertEqual(first.status, "completed")
            self.assertEqual(first.verification_status, "profile_valid")

        # worker 存活：下一个任务正常完成。
        second = q.enqueue("cagt_ok", wait=True, timeout=2.0)
        self.assertEqual(second.status, "completed")
        self.assertEqual(second.verification_status, "profile_valid")
        q.shutdown(wait=False)

    def test_queue_rejects_unmigrated_database(self) -> None:
        """审查 P3：未迁移库构造队列 → 明确 RuntimeError（此前 no such table 崩）。"""
        tmp = Path(tempfile.mkdtemp())
        raw = tmp / "raw.sqlite"
        conn = sqlite3.connect(raw)
        conn.commit()
        conn.close()
        with self.assertRaises(RuntimeError) as ctx:
            _make_queue(raw, lambda: _StubService())
        self.assertIn("schema", str(ctx.exception))

    def test_enqueue_during_shutdown_never_orphans(self) -> None:
        """审查 P3：enqueue 与 shutdown 竞态不允许孤儿任务——成功入队必被
        处理（结果落 _results），拒绝则无残留（_tasks 已清理）。"""
        import threading

        from kiwi_catalog.services.agent_verification import (
            VerificationQueueShutdownError,
        )

        for _ in range(20):
            q = _make_queue(self.db, lambda: _StubService(), timeout=1.0)
            outcomes: list[Any] = []

            def _enqueuer() -> None:
                try:
                    outcomes.append(q.enqueue("cagt_race", wait=True, timeout=0.5))
                except VerificationQueueShutdownError:
                    outcomes.append("shutdown")
                except Exception as exc:  # noqa: BLE001 — 断言非预期异常
                    outcomes.append(exc)

            thread = threading.Thread(target=_enqueuer)
            thread.start()
            q.shutdown(wait=False)
            thread.join(2.0)
            q.shutdown(wait=True, timeout=1.0)
            for outcome in outcomes:
                self.assertNotIsInstance(outcome, Exception, outcome)
            with q._results_cv:
                orphaned = [tid for tid in q._tasks if tid not in q._results]
            self.assertEqual(orphaned, [], "竞态下不得遗留孤儿任务")

    def test_enqueue_dedups_inflight_task_per_agent(self) -> None:
        """审查 P2：同 agent 已有 pending/running 任务时复用 task_id——
        并发 verify 不再基于陈旧快照回退级别。"""
        q = _make_queue(self.db, lambda: _StubService(delay=0.2), timeout=1.0)
        first = q.enqueue("cagt_dup", wait=False)
        self.assertEqual(first.status, "enqueued")
        second = q.enqueue("cagt_dup", wait=False)
        self.assertEqual(second.status, "enqueued")
        self.assertEqual(second.task_id, first.task_id, "同 agent 在途任务必须复用")
        # 另一 agent 不受影响
        other = q.enqueue("cagt_other", wait=False)
        self.assertNotEqual(other.task_id, first.task_id)
        # 任务完成后可再排（_results 中的旧任务不拦截）
        finished = q.enqueue("cagt_dup", wait=True, timeout=2.0)
        self.assertEqual(finished.status, "completed")
        again = q.enqueue("cagt_dup", wait=True, timeout=2.0)
        self.assertNotEqual(again.task_id, finished.task_id)
        q.shutdown(wait=False)

    def test_enqueue_ledger_failure_leaves_no_orphan_task(self) -> None:
        """审查 P2：_persist_insert 失败 → 抛类型化 VerificationQueueLedgerError
        且内存 _tasks 回滚——wait() 不得永久挂死、无孤儿条目。"""
        from kiwi_catalog.services.agent_verification import (
            VerificationQueueLedgerError,
        )

        q = _make_queue(self.db, lambda: _StubService(), timeout=1.0)

        def broken_insert(task):
            raise sqlite3.OperationalError("database is locked (simulated)")

        with mock.patch.object(q, "_persist_insert", side_effect=broken_insert):
            with self.assertRaises(VerificationQueueLedgerError):
                q.enqueue("cagt_orphan")
        self.assertEqual(len(q._tasks), 0, "失败后不得遗留内存孤儿条目")
        # 恢复后正常入队（无残留状态污染）
        ok = q.enqueue("cagt_ok", wait=True, timeout=2.0)
        self.assertEqual(ok.status, "completed")
        q.shutdown(wait=False)

    def test_worker_survives_unexpected_error_and_continues(self) -> None:
        """单任务意外异常不得让 worker 循环退出。"""
        calls = {"n": 0}

        def factory():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("service factory boom")
            return _StubService()

        q = _make_queue(self.db, factory, timeout=1.0)
        first = q.enqueue("cagt_boom", wait=True, timeout=2.0)
        self.assertEqual(first.status, "failed")
        self.assertIn("service factory failed", first.error)

        second = q.enqueue("cagt_ok", wait=True, timeout=2.0)
        self.assertEqual(second.status, "completed")
        q.shutdown(wait=False)


if __name__ == "__main__":
    unittest.main()
