from __future__ import annotations
import shutil
import threading
import unittest
from tests.test_a332_queue_shutdown import QueueShutdownHarness, _starts, _wait_until


class FullRequeueTest(unittest.TestCase):
    def test_real_full_pending_queue_cannot_block_completed_worker_preclaim_handoff(self):
        harness = QueueShutdownHarness(use_ledger=True)
        self.addCleanup(shutil.rmtree, harness.tmp)
        a_gate = threading.Event()
        c_gate = threading.Event()
        q = harness.make_queue(blockers={("a", "verify"): a_gate, ("c", "verify"): c_gate}, concurrency=2)
        q._pending.maxsize = 1
        try:
            first = q.enqueue("a")
            self.assertTrue(_wait_until(lambda: bool(_starts(harness.events, "a", "verify")), timeout=2))
            second = q.enqueue("a", kind="refresh")
            self.assertTrue(_wait_until(lambda: bool(q._agent_deferred.get("a")), timeout=2))
            other = q.enqueue("c")
            self.assertTrue(_wait_until(lambda: bool(_starts(harness.events, "c", "verify")), timeout=2))
            pending = q.enqueue("d")
            self.assertTrue(q._pending.full(), "fixture must hit actual full queue at requeue")
            a_gate.set()
            self.assertEqual(q.wait(first.task_id, timeout=1).status, "completed")
            handed = q.wait(second.task_id, timeout=0.5)
            # The other worker is deliberately still in an independent slow service.
            self.assertFalse(c_gate.is_set())
            self.assertEqual(handed.status, "completed", "requeue worker blocked on full pending queue")
            self.assertEqual(len(_starts(harness.events, "a", "refresh")), 1)
        finally:
            a_gate.set()
            c_gate.set()
            # Normal release rescues the old failed tree without altering expected.
            q.shutdown(wait=True)
        self.assertEqual(set(q._tasks), set(q._results))
        self.assertTrue(all(r.status == "completed" for r in q._results.values()))
        self.assertEqual(q._agent_preclaimed, {})
        self.assertEqual(q._agent_deferred, {})
        self.assertEqual(q._pending.unfinished_tasks, 0)
        self.assertFalse(any(worker.is_alive() for worker in q._workers))
        self.assertEqual(q.wait(other.task_id).status, "completed")
        self.assertEqual(q.wait(pending.task_id).status, "completed")
