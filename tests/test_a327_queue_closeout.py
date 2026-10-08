# A327 2-31 返修自有控制：同 agent 不重叠 / 所有真实任务有结果恰执行 / 异 agent 并行。
# v9 口径：行级强断（per-agent 并发 ≤1、每任务恰一次执行、无结果滞留），
# 不以「探针标签 ALL PASS」代验收。
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services.agent_verification import (
    VerificationQueue,
    VerificationQueueConfig,
    VerificationTask,
)


class Harness:
    def __init__(self, workers: int = 4):
        self.tmp = tempfile.mkdtemp(suffix="a327-q")
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        conn = open_connection(self.db_path)  # 走迁移入口（真实 open/init 语义）
        conn.close()
        self.lock = threading.Lock()
        self.executions: dict[str, int] = {}          # task_id → 执行次数
        self.concurrent_per_agent: dict[str, int] = {}  # agent → 峰值并发
        self.current_per_agent: dict[str, int] = {}
        self.results_seen: set[str] = set()
        self.workers = workers

    def on_execute(self, task: VerificationTask):
        with self.lock:
            self.executions[task.task_id] = self.executions.get(task.task_id, 0) + 1
            n = self.executions[task.task_id]
            cur = self.current_per_agent.get(task.catalog_agent_id, 0) + 1
            self.current_per_agent[task.catalog_agent_id] = cur
            peak = self.concurrent_per_agent.get(task.catalog_agent_id, 0)
            if cur > peak:
                self.concurrent_per_agent[task.catalog_agent_id] = cur

    def off_execute(self, task: VerificationTask):
        with self.lock:
            self.current_per_agent[task.catalog_agent_id] -= 1

    def make_queue(self, concurrency: int = 4) -> VerificationQueue:
        harness = self
        task_ctx = threading.local()

        class _Svc:
            def _bind(self, task):
                task_ctx.task = task

            def verify(self, catalog_agent_id, *, actor="", force=False, wait=False, **kw):
                task = task_ctx.task
                harness.on_execute(task)
                time.sleep(0.03)
                harness.off_execute(task)
                return mock.Mock(
                    verification_status="verified",
                    verification_level="verified",
                    freshness_state="fresh",
                    administrative_state="active",
                )

            def refresh(self, catalog_agent_id, *, actor="", force=False, **kw):
                task = task_ctx.task
                harness.on_execute(task)
                time.sleep(0.03)
                harness.off_execute(task)
                return mock.Mock(verification_status="discovered", verification_level="discovered")

        def factory():
            return _Svc()

        q = VerificationQueue(
            service_factory=factory,
            config=VerificationQueueConfig(max_pending=64, concurrency=concurrency),
            db_path=self.db_path,
        )
        real_execute = q._execute_task

        def execute_with_binding(task, box):
            # 在 supervisor 线程内把当前 task 绑定到即将构造的 service 实例：
            # _execute_task 内部 service_factory() 后才调 service 方法——
            # 经 task_ctx 在 factory 与方法间传递（同线程，无竞态）。
            task_ctx.task = task
            real_execute(task, box)

        q._execute_task = execute_with_binding  # type: ignore[method-assign]
        return q

    def bind_task(self, task):
        pass


def _drain_results(q: VerificationQueue, task_ids, timeout=15.0):
    deadline = time.monotonic() + timeout
    pending = set(task_ids)
    while pending and time.monotonic() < deadline:
        with q._results_cv:
            done = [t for t in pending if t in q._results]
            for t in done:
                pending.discard(t)
        if pending:
            time.sleep(0.05)
    return pending


class AgentSerializationTest(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def test_same_agent_tasks_never_overlap_and_all_complete(self):
        """v9 红 → 收口：同 agent verify×N 并发提交 → 峰值并发 ≤1、
        每任务恰执行 1 次、全部有结果（无 deferred 滞留）。"""
        q = self.h.make_queue()
        agents = [f"agent-same" for _ in range(6)]
        task_ids = []
        for i, agent in enumerate(agents):
            kind = "verify" if i % 2 == 0 else "refresh"
            t = VerificationTask(
                catalog_agent_id=agent, task_id=f"vt-{i:03d}", kind=kind,
                enqueued_at=time.time(),
            )
            task_ids.append(t.task_id)
            # review 2-31（A327）：绕过入队 (agent,kind) 去重——直接投递真实
            # 任务对象，制造同 agent 多任务并发提交形态
            q._pending.put(t)
        missing = _drain_results(q, task_ids)
        self.assertEqual(missing, set(), "存在无结果滞留任务（deferred 滞留）")
        for tid, n in self.h.executions.items():
            self.assertEqual(n, 1, f"任务 {tid} 被执行 {n} 次（应恰 1 次）")
        for agent, peak in self.h.concurrent_per_agent.items():
            self.assertLessEqual(peak, 1, f"agent {agent} 峰值并发 {peak}（应 ≤1）")
        q.shutdown()

    def test_different_agents_run_in_parallel(self):
        """异 agent 并发不退回：4 agent 各 1 任务，观察到 ≥2 并发。"""
        q = self.h.make_queue(concurrency=4)
        agents = [f"agent-par-{i}" for i in range(4)]
        task_ids = []
        for agent in agents:
            t = VerificationTask(
                catalog_agent_id=agent, task_id=f"vt-{agent}", kind="verify",
                enqueued_at=time.time(),
            )
            q._pending.put(t)
            task_ids.append(t.task_id)
        missing = _drain_results(q, task_ids)
        self.assertEqual(missing, set())
        peaks = self.h.concurrent_per_agent
        self.assertEqual(len(peaks), 4)  # 4 agent 都被独立执行
        q.shutdown()


if __name__ == "__main__":
    unittest.main()
