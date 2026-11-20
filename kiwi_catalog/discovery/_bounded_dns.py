"""Fixed daemon resolver workers with physical queued-work accounting."""
from __future__ import annotations

import json
import logging
import socket
import subprocess
import sys
from concurrent.futures import Future, TimeoutError
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
import queue
import threading
import time
from typing import Any, Callable

DNS_LOOKUP_TIMEOUT_SECONDS = 5.0
_CACHE_TTL_SECONDS = 2.0
_CACHE_SIZE = 128
_CACHE_LOCK = threading.Lock()
_CACHE: OrderedDict[tuple[str, int], tuple[float, tuple[Any, ...]]] = OrderedDict()
_FALLBACK_SLOT = threading.BoundedSemaphore(1)

# Run NSS/system DNS in a process because Python cannot interrupt a thread
# blocked in getaddrinfo. The hostname and port are arguments, never code.
_DNS_LOOKUP_PROGRAM = """\
import json
import socket
import sys

try:
    addresses = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), proto=socket.IPPROTO_TCP)
except socket.gaierror as error:
    print(json.dumps([False, str(error)]))
else:
    print(json.dumps([True, addresses]))
"""


def lookup_address_infos(hostname: str, port: int) -> list[Any]:
    """Reuse fresh local results. Callers still validate every returned address."""
    key = (hostname.lower(), port)
    with _CACHE_LOCK:
        if (cached := _CACHE.pop(key, None)) is not None and time.monotonic() < cached[0]:
            _CACHE[key] = cached
            return list(cached[1])
    answers = _query_system_resolver(hostname, port)
    with _CACHE_LOCK:
        _CACHE[key] = (time.monotonic() + _CACHE_TTL_SECONDS, tuple(answers))
        if len(_CACHE) > _CACHE_SIZE:
            _CACHE.popitem(last=False)
    return answers


def _query_system_resolver(hostname: str, port: int) -> list[Any]:
    if not sys.executable or getattr(sys, "frozen", False):
        return _resolve_without_child(hostname, port)
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", _DNS_LOOKUP_PROGRAM, hostname, str(port)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=DNS_LOOKUP_TIMEOUT_SECONDS, check=True,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run kills and reaps the resolver before raising.
        raise TimeoutError("system DNS execution deadline exceeded") from exc
    except (OSError, subprocess.CalledProcessError):
        return _resolve_without_child(hostname, port)
    ok, payload = json.loads(result.stdout)
    if not ok:
        raise socket.gaierror(payload)
    return list(payload)


@lru_cache(maxsize=1)
def _warn_dns_fallback() -> None:
    logging.getLogger(__name__).warning("DNS child unavailable; using a single bounded in-process lookup slot")


def _resolve_without_child(hostname: str, port: int) -> list[Any]:
    """Keep uninterruptible fallback work out of the main resolver pool."""
    _warn_dns_fallback()
    if not _FALLBACK_SLOT.acquire(blocking=False):
        raise TimeoutError("in-process DNS resolver is busy")
    future: Future[list[Any]] = Future()

    def lookup() -> None:
        try:
            future.set_result(socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP))
        except BaseException as exc:
            future.set_exception(exc)
        finally:
            _FALLBACK_SLOT.release()

    try:
        threading.Thread(target=lookup, name="kiwi-dns-fallback", daemon=True).start()
    except BaseException:
        _FALLBACK_SLOT.release()
        raise
    return future.result(timeout=DNS_LOOKUP_TIMEOUT_SECONDS)


@dataclass
class _Lookup:
    future: Future
    waiters: int = 1


class BoundedResolver:
    """At most six admitted work items, including cancelled queued items.

    Cancellation does not remove a Queue item. Only a worker that physically
    removes and finishes/skips it releases its slot. System DNS resolution
    runs with a hard process timeout, so wedged work cannot retain a slot.
    """

    def __init__(self) -> None:
        self.admission = threading.BoundedSemaphore(6)
        self._lock = threading.Lock()
        self._inflight: dict[tuple[str, int], _Lookup] = {}
        self._work_queue: queue.Queue = queue.Queue(maxsize=6)
        self._threads = [threading.Thread(target=self._worker, name=f"kiwi-dns-{i}", daemon=True)
                         for i in range(2)]
        for thread in self._threads:
            thread.start()

    def submit(self, key: tuple[str, int], fn: Callable, *args: Any, admission_timeout: float | None = None,
               **kwargs: Any) -> Future:
        with self._lock:
            existing = self._join_lookup(key)
            if existing is not None:
                return existing
        if not self.admission.acquire(timeout=admission_timeout):
            raise TimeoutError("DNS admission deadline")
        with self._lock:
            existing = self._join_lookup(key)
            if existing is not None:
                self.admission.release()
                return existing
            future: Future = Future()
            try:
                self._work_queue.put_nowait((key, future, fn, args, kwargs))
            except BaseException:
                self.admission.release()
                raise
            self._inflight[key] = _Lookup(future)
            return future

    def _join_lookup(self, key: tuple[str, int]) -> Future | None:
        lookup = self._inflight.get(key)
        if lookup is None or lookup.future.done():
            return None
        lookup.waiters += 1
        return lookup.future

    def release(self, key: tuple[str, int], future: Future) -> None:
        """Detach a caller. Cancel queued work only if nobody needs it."""
        with self._lock:
            lookup = self._inflight.get(key)
            if lookup is not None and lookup.future is future:
                lookup.waiters -= 1
                if lookup.waiters == 0:
                    future.cancel()

    def _worker(self) -> None:
        while True:
            key, future, fn, args, kwargs = self._work_queue.get()
            try:
                if future.set_running_or_notify_cancel():
                    try:
                        result = fn(*args, **kwargs)
                    except BaseException as exc:
                        future.set_exception(exc)
                    else:
                        future.set_result(result)
            finally:
                with self._lock:
                    lookup = self._inflight.get(key)
                    if lookup is not None and lookup.future is future:
                        del self._inflight[key]
                self.admission.release()
                self._work_queue.task_done()
