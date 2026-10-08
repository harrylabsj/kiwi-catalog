# A332 2-31 F2 返修自有控制：正常 shutdown(wait=True) 不再静默丢已接纳任务。
# 口径（授权卡）：
#   * 真实公开 enqueue + 真实 VerificationResult（status 字段真实，failed 不
#     算完成结果）；
#   * distinct ID 集合 == 执行集合 == completed 结果集合，每任务恰一次，
#     kind/agent/verification_status 与临时 ledger 终态一致；
#   * 原 N1/N2 屏障回归：同 agent 不重叠、无滞留；异 agent 窗口真正重叠；
#   * 正常 shutdown：A 在飞阻塞 + 同 agent B 已 deferred（+ 异 agent C 在飞）
#     → 释放后所有已接纳任务完成、workers 退、内存无挂任务；
#     db_path=None 与临时 ledger 两形态；ledger 形态下新 queue 恢复 0 行
#     （本轮完成，不依赖 shutdown 后另进程恢复冒充原 wait 完成）；
#   * 关闭后 enqueue 按原 typed 拒（VerificationQueueShutdownError），无新工作。
# 本文件在修复前冻结源上先跑红（仅 shutdown 两测 FAIL），证明缺陷可检出，
# 不把「缺陷实际存在」断成 PASS 再让产品绿。
import os
import sqlite3
import tempfile
import threading
import time
import unittest

from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services.agent_verification import (
    VerificationQueue,
    VerificationQueueConfig,
    VerificationQueueShutdownError,
)
from kiwi_catalog.services.verification_stages import VerificationResult

VERIFIED = "verified"


class RecordingService:
    """记录执行事件、支持确定性阻塞的合成 service（返回真实 VerificationResult）。"""

    def __init__(self, events, blockers=None, work_sleep=None):
        self._events = events
        self._blockers = blockers or {}
        self._work_sleep = work_sleep or {}
        self._lock = threading.Lock()

    def _run(self, agent_id: str, kind: str) -> VerificationResult:
        with self._lock:
            self._events.append(("start", agent_id, kind, time.monotonic()))
        blocker = self._blockers.get((agent_id, kind))
        if blocker is not None:
            blocker.wait(timeout=15)
        time.sleep(self._work_sleep.get((agent_id, kind), 0.03))
        with self._lock:
            self._events.append(("end", agent_id, kind, time.monotonic()))
        return VerificationResult(
            catalog_agent_id=agent_id,
            previous_status="unverified",
            status=VERIFIED,
            stages=(),
        )

    def verify(self, catalog_agent_id, *, actor="verification_worker", **kw):
        return self._run(catalog_agent_id, "verify")

    def refresh(self, catalog_agent_id, *, actor="verification_worker", **kw):
        return self._run(catalog_agent_id, "refresh")

    def mark_stale(self, catalog_agent_id, *, actor="verification_worker", **kw):
        return self._run(catalog_agent_id, "mark_stale")

    def suspend(self, catalog_agent_id, *, actor="verification_worker", **kw):
        return self._run(catalog_agent_id, "suspend")

    def commit(self):
        pass

    def close(self, commit=True):
        pass


def _starts(events, agent_id, kind):
    return [e for e in events if e[0] == "start" and e[1] == agent_id and e[2] == kind]


def _ends(events, agent_id, kind):
    return [e for e in events if e[0] == "end" and e[1] == agent_id and e[2] == kind]


def _wait_until(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.005)
    return True


class QueueShutdownHarness:
    def __init__(self, use_ledger: bool):
        self.tmp = tempfile.mkdtemp(suffix="a332-q")
        self.db_path = None
        if use_ledger:
            self.db_path = os.path.join(self.tmp, "catalog.sqlite")
            conn = open_connection(self.db_path)  # 真实迁移入口
            conn.close()
        self.events: list = []

    def make_queue(self, blockers=None, work_sleep=None, concurrency=2) -> VerificationQueue:
        events = self.events
        return VerificationQueue(
            service_factory=lambda: RecordingService(
                events, blockers=blockers, work_sleep=work_sleep
            ),
            config=VerificationQueueConfig(
                max_pending=50, concurrency=concurrency, task_timeout_seconds=30
            ),
            db_path=self.db_path,
        )

    def ledger_rows(self):
        conn = sqlite3.connect(self.db_path)
        try:
            return {
                r[0]: (r[1], r[2], r[3])
                for r in conn.execute(
                    "select task_id, status, kind, verification_status"
                    " from verification_queue_tasks"
                )
            }
        finally:
            conn.close()


class DistinctIdsAndLedgerTest(unittest.TestCase):
    """正控：六 distinct 真实任务 ID，执行集合 == 结果集合，ledger 终态一致。"""

    def test_six_distinct_ids_completed_and_ledger_consistent(self):
        h = QueueShutdownHarness(use_ledger=True)
        plan = [("ag1", "verify"), ("ag1", "refresh"), ("ag1", "mark_stale"),
                ("ag2", "verify"), ("ag2", "refresh"), ("ag2", "mark_stale")]
        q = h.make_queue(work_sleep={(a, k): 0.05 for a, k in plan})
        try:
            res: dict = {}
            threads = [
                threading.Thread(
                    target=lambda a=a, k=k: res.update({(a, k): q.enqueue(a, kind=k)})
                )
                for a, k in plan
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            expected_ids = {r.task_id for r in res.values()}
            self.assertEqual(len(expected_ids), 6, f"task_id 不 distinct: {sorted(expected_ids)}")
            finals = {key: q.wait(r.task_id, timeout=25) for key, r in res.items()}
            self.assertEqual(set(q._results.keys()), expected_ids,
                             "结果集合 != 公开 enqueue 返回的 ID 集合")
            for (a, k), outcome in finals.items():
                self.assertEqual(outcome.status, "completed",
                                 f"{a}/{k} status={outcome.status}（failed/timeout 不算完成结果）")
                self.assertEqual(outcome.verification_status, VERIFIED,
                                 f"{a}/{k} verification_status={outcome.verification_status!r}")
                self.assertEqual((outcome.catalog_agent_id, outcome.kind), (a, k))
            for a, k in plan:
                self.assertEqual(len(_starts(h.events, a, k)), 1,
                                 f"{a}/{k} 执行次数 != 1（恰一次语义破坏）")
            rows = h.ledger_rows()
            for tid in expected_ids:
                self.assertIn(tid, rows, f"ledger 缺任务行 {tid}")
                self.assertEqual(rows[tid][0], "completed",
                                 f"ledger 终态 {rows[tid][0]} != completed（{tid}）")
                self.assertEqual(rows[tid][2], VERIFIED,
                                 f"ledger verification_status={rows[tid][2]!r}（{tid}）")
        finally:
            q.shutdown(wait=True, timeout=20)
        self.assertFalse(any(w.is_alive() for w in q._workers), "workers 未全部退出")


class SerializationBarrierTest(unittest.TestCase):
    """N1/N2 回归：确定性屏障下同 agent 不重叠、无滞留；异 agent 真正重叠。"""

    def test_same_agent_barrier_no_overlap_no_residue(self):
        h = QueueShutdownHarness(use_ledger=False)
        gate = threading.Event()
        q = h.make_queue(
            blockers={("agS", "verify"): gate},
            work_sleep={("agS", "verify"): 0.03, ("agS", "refresh"): 0.03},
        )
        try:
            ra = q.enqueue("agS", kind="verify")
            self.assertTrue(_wait_until(lambda: _starts(h.events, "agS", "verify")),
                            "A 未在界内开始执行")
            rb = q.enqueue("agS", kind="refresh")  # 同 agent，必须 defer
            time.sleep(0.3)
            self.assertEqual(_starts(h.events, "agS", "refresh"), [],
                             "屏障破坏：A 在飞期间同 agent B 已开跑（窗口重叠）")
            gate.set()
            fa, fb = q.wait(ra.task_id, timeout=15), q.wait(rb.task_id, timeout=15)
            self.assertEqual((fa.status, fb.status), ("completed", "completed"))
            self.assertEqual(len(_starts(h.events, "agS", "verify")), 1)
            self.assertEqual(len(_starts(h.events, "agS", "refresh")), 1)
            a_end = _ends(h.events, "agS", "verify")[0][3]
            b_start = _starts(h.events, "agS", "refresh")[0][3]
            self.assertLessEqual(a_end, b_start, "同 agent 两任务执行窗口重叠")
            self.assertEqual(q._agent_deferred.get("agS", []), [], "deferred 滞留")
            self.assertNotIn("agS", q._agent_preclaimed, "preclaim 元数据残留")
        finally:
            q.shutdown(wait=True, timeout=20)

    def test_different_agents_overlap_window(self):
        h = QueueShutdownHarness(use_ledger=False)
        gate_a, gate_b = threading.Event(), threading.Event()
        q = h.make_queue(
            blockers={("agA", "verify"): gate_a, ("agB", "verify"): gate_b},
            work_sleep={("agA", "verify"): 0.03, ("agB", "verify"): 0.03},
        )
        try:
            ra = q.enqueue("agA", kind="verify")
            rb = q.enqueue("agB", kind="verify")
            both_started = _wait_until(
                lambda: _starts(h.events, "agA", "verify") and _starts(h.events, "agB", "verify")
            )
            self.assertTrue(both_started, "异 agent 未观察到真正并行（窗口无重叠）")
            gate_a.set()
            gate_b.set()
            self.assertEqual(q.wait(ra.task_id, timeout=15).status, "completed")
            self.assertEqual(q.wait(rb.task_id, timeout=15).status, "completed")
        finally:
            q.shutdown(wait=True, timeout=20)


class NormalShutdownDrainTest(unittest.TestCase):
    """F2 核心：shutdown(wait=True) 时 A 在飞 + 同 agent B 已 deferred + 异 agent
    C 在飞；释放后所有已接纳任务必须有确定完成结果、workers 退、内存无挂任务。"""

    def _run_window(self, use_ledger: bool):
        h = QueueShutdownHarness(use_ledger=use_ledger)
        gate_a, gate_c = threading.Event(), threading.Event()
        q = h.make_queue(
            blockers={("agW", "verify"): gate_a, ("agX", "mark_stale"): gate_c},
            work_sleep={
                ("agW", "verify"): 0.03,
                ("agW", "refresh"): 0.03,
                ("agX", "mark_stale"): 0.03,
            },
        )
        ra = q.enqueue("agW", kind="verify")
        self.assertTrue(_wait_until(lambda: _starts(h.events, "agW", "verify")),
                        "A 未在界内开始在飞")
        rb = q.enqueue("agW", kind="refresh")  # A 在飞 → 空闲 worker 出队后 defer
        self.assertTrue(_wait_until(lambda: bool(q._agent_deferred.get("agW"))),
                        "B 未被 defer（场景未成形，不构成 F2 窗口）")
        rc = q.enqueue("agX", kind="mark_stale")  # 异 agent 在飞，占住另一 worker
        self.assertTrue(_wait_until(lambda: _starts(h.events, "agX", "mark_stale")),
                        "C 未在界内开始在飞")
        shut = threading.Thread(target=lambda: q.shutdown(wait=True, timeout=30))
        shut.start()
        time.sleep(0.2)  # 哨兵已入队（落在 preclaim 重投之前）
        self.assertTrue(shut.is_alive(), "shutdown 在任务仍阻塞时提前返回")
        gate_a.set()
        gate_c.set()
        shut.join(timeout=35)
        self.assertFalse(shut.is_alive(), "shutdown(wait=True) 未在界内返回")
        return h, q, (ra, rb, rc)

    def _assert_all_admitted_completed(self, h, q, ids):
        ra, rb, rc = ids
        self.assertFalse(any(w.is_alive() for w in q._workers), "workers 未全部退出")
        self.assertEqual(set(q._tasks.keys()), set(q._results.keys()),
                         "内存存在无结果挂起任务（静默丢失）")
        self.assertEqual(q._agent_deferred, {}, "shutdown 后 deferred 滞留")
        self.assertEqual(q._agent_preclaimed, {}, "shutdown 后 preclaim 残留")
        for r, (agent, kind) in ((ra, ("agW", "verify")), (rb, ("agW", "refresh")),
                                 (rc, ("agX", "mark_stale"))):
            outcome = q._results.get(r.task_id)
            self.assertIsNotNone(outcome, f"{agent}/{kind} 无结果")
            self.assertEqual(outcome.status, "completed",
                             f"{agent}/{kind} status={outcome.status}")
            self.assertEqual(outcome.verification_status, VERIFIED)
            self.assertEqual((outcome.catalog_agent_id, outcome.kind), (agent, kind))
            self.assertEqual(len(_starts(h.events, agent, kind)), 1,
                             f"{agent}/{kind} 执行次数 != 1")

    def test_shutdown_drains_deferred_db_none(self):
        h, q, ids = self._run_window(use_ledger=False)
        self._assert_all_admitted_completed(h, q, ids)

    def test_shutdown_drains_deferred_temp_ledger(self):
        h, q, ids = self._run_window(use_ledger=True)
        self._assert_all_admitted_completed(h, q, ids)
        rows = h.ledger_rows()
        for r in ids:
            self.assertEqual(rows.get(r.task_id, (None,))[0], "completed",
                             f"ledger 终态 {rows.get(r.task_id)} != completed（{r.task_id}）")
        # 本轮已完成 → 新 queue 同库恢复 0 行（不依赖 shutdown 后另进程恢复
        # 冒充原 wait 完成；恢复语义本身属 A330 C7 已验范围）。
        q2 = h.make_queue()
        try:
            self.assertEqual(len(q2._recovered_tasks), 0,
                             f"shutdown 后 ledger 仍残留可恢复行 {len(q2._recovered_tasks)}")
        finally:
            q2.shutdown(wait=True, timeout=20)


class PostShutdownEnqueueTest(unittest.TestCase):
    def test_enqueue_after_shutdown_typed_reject_no_new_work(self):
        h = QueueShutdownHarness(use_ledger=False)
        q = h.make_queue(work_sleep={("agE", "verify"): 0.03})
        r = q.enqueue("agE", kind="verify")
        self.assertEqual(q.wait(r.task_id, timeout=15).status, "completed")
        q.shutdown(wait=True, timeout=20)
        executions_before = len(_starts(h.events, "agE", "verify"))
        with self.assertRaises(VerificationQueueShutdownError):
            q.enqueue("agE", kind="verify")
        with self.assertRaises(VerificationQueueShutdownError):
            q.enqueue("agE2", kind="suspend")
        time.sleep(0.2)
        self.assertEqual(len(_starts(h.events, "agE", "verify")), executions_before,
                         "关闭后出现了新执行（泄漏）")
        self.assertEqual(len(_starts(h.events, "agE2", "suspend")), 0)
        self.assertFalse(any(w.is_alive() for w in q._workers))


if __name__ == "__main__":
    unittest.main()
