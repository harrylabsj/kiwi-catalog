"""Rate-limit backend abstraction (§17.4, v3.0-P5).

单一固定窗口限流核心 + 可插拔 backend。 现状（P5 盘点）：

- ``enforce_agent_catalog_rate_limit``（api/idempotency.py）与
  ``enforce_catalog_register_domain_limit``（sqlite_repository.py）此前是
  两份重复的「INSERT ... ON CONFLICT ... WHERE count < limit」实现，窗口
  与表不同但模式相同；本模块收敛为 ``enforce_rate_limit`` + 表参数化
  backend，两个函数改为委托（行为不变，测试锁定）。
- ``RateLimitBackend`` 是接缝：Redis 等分布式实现只需实现
  ``consume(key, window_start, limit) -> bool`` 的原子语义（见
  docs/shopping-cli-a2a-abuse-runbook-v1.0.md 接入点说明）。
- 所有窗口计算使用进程无关的固定窗口（epoch 取模），多实例部署时
  窗口边界天然对齐。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from kiwi_catalog.core.errors import RateLimitError


class RateLimitBackend(Protocol):
    """Fixed-window counter backend (§17.4).

    ``consume`` must be atomic (concurrent callers serialize on the same
    key+window) and return True when the request is under *limit* and False
    when the window budget is exhausted.
    """

    def consume(self, *, key: str, window_start: str, limit: int) -> bool:
        """Record one request against (key, window_start).  True = under limit."""
        ...


class SQLiteRateLimitBackend:
    """Fixed-window counter over a SQLite table (default backend).

    The table must carry ``(key_column, window_start)`` as a unique pair plus
    ``request_count`` and ``updated_at`` — the two production tables
    (``agent_catalog_write_rate_limits`` / ``agent_catalog_register_limits``)
    already do.  Uses ``INSERT ... ON CONFLICT`` so the increment is atomic
    even under concurrent workers (SQLite serializes writers).
    """

    def __init__(self, conn: Any, *, table: str, key_column: str) -> None:
        self._conn = conn
        self._table = table
        self._key_column = key_column

    def consume(self, *, key: str, window_start: str, limit: int) -> bool:
        cursor = self._conn.execute(
            f"""
            insert into {self._table}({self._key_column}, window_start, request_count, updated_at)
            values (?, ?, 1, ?)
            on conflict({self._key_column}, window_start) do update set
                request_count = {self._table}.request_count + 1,
                updated_at = excluded.updated_at
            where {self._table}.request_count < ?
            """,
            (key, window_start, datetime.now().isoformat(), limit),
        )
        return cursor.rowcount == 1


def fixed_window_start(current: datetime, window_seconds: int) -> str:
    """Start of the fixed window containing *current* (epoch 取模对齐)."""
    epoch_seconds = int(current.timestamp())
    window_epoch = epoch_seconds - (epoch_seconds % window_seconds)
    return datetime.fromtimestamp(window_epoch).replace(microsecond=0).isoformat()


def enforce_rate_limit(
    backend: RateLimitBackend,
    *,
    key: str,
    limit: int,
    window_seconds: int,
    description: str,
    current: datetime | None = None,
) -> None:
    """Consume one request against *backend*; raise RateLimitError on breach.

    ``limit <= 0`` disables the limit (no-op).  *description* names the
    budget in the error message (e.g. ``"agent catalog write (60/minute)"``).
    """
    if limit <= 0:
        return
    now = (current or datetime.now()).replace(microsecond=0)
    window_start = fixed_window_start(now, window_seconds)
    if not backend.consume(key=key, window_start=window_start, limit=limit):
        raise RateLimitError(f"{description} rate limit exceeded ({limit}/window)")


__all__ = [
    "RateLimitBackend",
    "SQLiteRateLimitBackend",
    "enforce_rate_limit",
    "fixed_window_start",
]
