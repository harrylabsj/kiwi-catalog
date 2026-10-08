"""Fixed daemon resolver workers with physical queued-work accounting."""
from __future__ import annotations

from concurrent.futures import Future, TimeoutError
import queue
import threading
from typing import Any, Callable


class BoundedResolver:
    """At most six admitted work items, including cancelled queued items.

    Cancellation does not remove a Queue item. Only a worker that physically
    removes and finishes/skips it releases its slot. Running DNS is not killed.
    """

    def __init__(self) -> None:
        self.admission = threading.BoundedSemaphore(6)
        self._work_queue: queue.Queue = queue.Queue(maxsize=6)
        self._threads = [threading.Thread(target=self._worker, name=f"kiwi-dns-{i}", daemon=True)
                         for i in range(2)]
        for thread in self._threads:
            thread.start()

    def submit(self, fn: Callable, *args: Any, admission_timeout: float | None = None,
               **kwargs: Any) -> Future:
        if not self.admission.acquire(timeout=admission_timeout):
            raise TimeoutError("DNS admission deadline")
        future: Future = Future()
        try:
            self._work_queue.put_nowait((future, fn, args, kwargs))
        except BaseException:
            self.admission.release()
            raise
        return future

    def _worker(self) -> None:
        while True:
            future, fn, args, kwargs = self._work_queue.get()
            try:
                if future.set_running_or_notify_cancel():
                    try:
                        result = fn(*args, **kwargs)
                    except BaseException as exc:
                        future.set_exception(exc)
                    else:
                        future.set_result(result)
            finally:
                self.admission.release()
                self._work_queue.task_done()
