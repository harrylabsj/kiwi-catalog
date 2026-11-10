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

"""运营通知的旁路队列（审查 P1-13）。

首次绑定请求的邮件通知此前在 HTTP 请求线程内同步发送：SMTP 故障时每个
请求阻塞最长 15s，且每次成功请求都会发一封（未认证工单可被用来轰炸运营
邮箱）。

本模块把通知移出请求线程：

- 单后台 daemon 线程 + 有界队列（满了直接丢弃——请求行才是事实来源，
  邮件只是旁路），发信失败只记日志；
- 同一 (catalog_agent_id, key_thumbprint) 在去重窗口内只发一封，避免同一
  运行时重试造成重复邮件；
- 队列在进程内，不改变请求结果；多实例部署可能重复发送（可接受）。

注意：这里刻意不引入 SQLite outbox——通知不是关键路径，且 worker 线程
在进程退出时丢弃未发项符合「请求已落库、邮件可丢」的语义。
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable
from typing import Any

_LOGGER = logging.getLogger(__name__)

_QUEUE_MAX = 100
_DEDUPE_WINDOW_SECONDS = 600
_DEDUPE_MAX_ENTRIES = 1024

_queue: queue.Queue[Callable[[], Any]] = queue.Queue(maxsize=_QUEUE_MAX)
_lock = threading.Lock()
_worker_started = False
_last_enqueued: dict[str, float] = {}


def _worker() -> None:
    while True:
        job = _queue.get()
        try:
            job()
        except Exception as exc:  # noqa: BLE001 —— 旁路：永不因通知失败影响请求
            _LOGGER.warning("notification outbox job failed: %r", exc)
        finally:
            _queue.task_done()


def _ensure_worker() -> None:
    global _worker_started
    if _worker_started:
        return
    with _lock:
        if _worker_started:
            return
        thread = threading.Thread(target=_worker, name="kiwi-catalog-notify", daemon=True)
        thread.start()
        _worker_started = True


def _dedupe_key(catalog_agent_id: str, key_thumbprint: str) -> str:
    return f"{catalog_agent_id}:{key_thumbprint}"


def _prune_dedupe(now: float) -> None:
    if len(_last_enqueued) <= _DEDUPE_MAX_ENTRIES:
        return
    cutoff = now - _DEDUPE_WINDOW_SECONDS
    for key, stamp in list(_last_enqueued.items()):
        if stamp < cutoff:
            _last_enqueued.pop(key, None)


def enqueue_admin_binding_request(
    *,
    merchant_id: str,
    catalog_agent_id: str,
    binding_request_id: str,
    runtime_origin: str,
    a2a_endpoint: str,
    key_thumbprint: str,
    expires_at: str = "",
) -> bool:
    """Queue the admin notification; returns False when deduped or dropped.

    Never performs I/O on the caller's thread and never raises.
    """
    key = _dedupe_key(catalog_agent_id, key_thumbprint)
    now = time.monotonic()
    with _lock:
        last = _last_enqueued.get(key)
        if last is not None and now - last < _DEDUPE_WINDOW_SECONDS:
            return False
        _last_enqueued[key] = now
        _prune_dedupe(now)

    def job() -> None:
        from kiwi_catalog.services import accounts as accounts_service

        accounts_service.notify_admin_binding_request(
            merchant_id=merchant_id,
            catalog_agent_id=catalog_agent_id,
            binding_request_id=binding_request_id,
            runtime_origin=runtime_origin,
            a2a_endpoint=a2a_endpoint,
            key_thumbprint=key_thumbprint,
            expires_at=expires_at,
        )

    _ensure_worker()
    try:
        _queue.put_nowait(job)
    except queue.Full:
        _LOGGER.warning("notification outbox full; dropped binding-request notification")
        return False
    return True


def reset_for_tests() -> None:
    """Drop pending jobs and dedupe state (tests only)."""
    with _lock:
        _last_enqueued.clear()
    while True:
        try:
            _queue.get_nowait()
        except queue.Empty:
            break
        else:
            _queue.task_done()
