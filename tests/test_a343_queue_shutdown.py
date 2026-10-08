"""Small-capacity shutdown controls; safe cleanup even against the frozen defect."""
import queue
import threading
import time
import unittest

from tests.test_a332_queue_shutdown import QueueShutdownHarness, _starts, _wait_until
from kiwi_catalog.services.agent_verification import VerificationQueueConfig


class SmallCapacityShutdownTest(unittest.TestCase):
    def test_drained_workers_before_shutdown_wakeup_does_not_block(self):
        h = QueueShutdownHarness(use_ledger=False)
        gates = [threading.Event(), threading.Event()]
        q = h.make_queue(blockers={("a", "verify"): gates[0], ("b", "verify"): gates[1]})
        # Real bounded queue with both workers already in flight.
        q._pending.maxsize = 1
        for agent in ("a", "b"):
            q.enqueue(agent)
            self.assertTrue(_wait_until(lambda: bool(_starts(h.events, agent, "verify"))))
        entered, resume, done = threading.Event(), threading.Event(), threading.Event()
        real_set = q._shutdown.set
        def pause_after_set():
            real_set()
            entered.set()
            if not resume.wait(5):
                raise AssertionError("shutdown fixture barrier was not released")
        q._shutdown.set = pause_after_set
        errors = []
        def stop():
            try:
                q.shutdown(wait=True)
            except BaseException as exc:
                errors.append(exc)
            finally:
                done.set()
        thread = threading.Thread(target=stop, daemon=True)
        thread.start()
        bounded = False
        try:
            self.assertTrue(entered.wait(2))
            for gate in gates:
                gate.set()
            self.assertTrue(_wait_until(lambda: all(not w.is_alive() for w in q._workers), timeout=3))
            self.assertEqual(set(q._tasks), set(q._results))
            resume.set()
            bounded = done.wait(1)
        finally:
            for gate in gates:
                gate.set()
            resume.set()
            # The old tree blocks putting sentinel #2; rescue without changing
            # the expected safe assertion or leaving a hanging test thread.
            end = time.monotonic() + 3
            while not done.is_set() and time.monotonic() < end:
                try:
                    q._pending.get(timeout=.05)
                    q._pending.task_done()
                except queue.Empty:
                    pass
            thread.join(1)
            while True:
                try:
                    q._pending.get_nowait()
                    q._pending.task_done()
                except queue.Empty:
                    break
        self.assertTrue(done.is_set(), "fixture could not rescue shutdown")
        self.assertEqual(errors, [])
        self.assertTrue(bounded, "normal shutdown blocked after drained workers exited")

    def test_idle_small_queue_shutdown_has_no_unconsumed_wakeups(self):
        h = QueueShutdownHarness(use_ledger=False)
        q = h.make_queue(concurrency=4)
        q._pending.maxsize = 1
        done = threading.Event()
        thread = threading.Thread(target=lambda: (q.shutdown(), done.set()), daemon=True)
        thread.start()
        try:
            self.assertTrue(done.wait(2))
            self.assertFalse(any(w.is_alive() for w in q._workers))
            self.assertTrue(q._pending.empty())
            self.assertEqual(q._pending.unfinished_tasks, 0)
        finally:
            thread.join(1)

    def test_small_capacity_deferred_tasks_finish_this_run(self):
        h = QueueShutdownHarness(use_ledger=False)
        gate = threading.Event()
        q = h.make_queue(blockers={("a", "verify"): gate})
        q._pending.maxsize = 1
        first = q.enqueue("a")
        self.assertTrue(_wait_until(lambda: bool(_starts(h.events, "a", "verify"))))
        second = q.enqueue("a", kind="refresh")
        self.assertTrue(_wait_until(lambda: bool(q._agent_deferred.get("a"))))
        done = threading.Event()
        thread = threading.Thread(target=lambda: (q.shutdown(), done.set()), daemon=True)
        thread.start()
        gate.set()
        try:
            self.assertTrue(done.wait(3))
            self.assertEqual(q.wait(first.task_id).status, "completed")
            self.assertEqual(q.wait(second.task_id).status, "completed")
            self.assertEqual(q._agent_preclaimed, {})
            self.assertEqual(q._agent_deferred, {})
            self.assertFalse(any(w.is_alive() for w in q._workers))
        finally:
            gate.set()
            thread.join(1)
