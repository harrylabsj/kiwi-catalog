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
- 时间戳统一为 naive-UTC ISO 文本（无时区后缀）：naive ``current`` 按
  UTC 解释、aware ``current`` 按绝对时刻归一到 UTC；``window_start`` /
  ``updated_at`` / prune cutoff 同格式，字符串比较即时间序。
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from kiwi_catalog.core.errors import RateLimitError

# 审查 P2：过期窗口行惰性清理频率与保留期。window_start 是 ISO 文本，
# 字符串比较即时间序；表键空间 = 唯一 actor/domain × 保留期内窗口数。
_RATE_LIMIT_RETENTION_DAYS = 7
_RATE_LIMIT_PRUNE_EVERY = 128


def _utc_now_naive() -> datetime:
    """Current instant as naive UTC wall-clock (no tzinfo).

    窗口键/updated_at/cutoff 统一输出无时区后缀的 ISO 文本——保持既有
    SQLite 行与字符串排序兼容，同时把内部计算钉在显式 UTC（跨实例/跨
    时区窗口边界对齐，不随服务器本地时区漂移）。
    """
    return datetime.now(UTC).replace(tzinfo=None)


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
        self._consume_count = 0

    def consume(self, *, key: str, window_start: str, limit: int) -> bool:
        # 审查 P2：惰性清理——每 N 次消费顺带删过期窗口行（键空间此前只增不删）
        self._consume_count += 1
        if self._consume_count % _RATE_LIMIT_PRUNE_EVERY == 0:
            self._prune_expired_windows()
        cursor = self._conn.execute(
            f"""
            insert into {self._table}({self._key_column}, window_start, request_count, updated_at)
            values (?, ?, 1, ?)
            on conflict({self._key_column}, window_start) do update set
                request_count = {self._table}.request_count + 1,
                updated_at = excluded.updated_at
            where {self._table}.request_count < ?
            """,
            (key, window_start, _utc_now_naive().isoformat(), limit),
        )
        return cursor.rowcount == 1

    def _prune_expired_windows(self) -> None:
        cutoff = (_utc_now_naive() - timedelta(days=_RATE_LIMIT_RETENTION_DAYS)).isoformat()
        try:
            self._conn.execute(
                f"delete from {self._table} where window_start < ?", (cutoff,)
            )
        except sqlite3.Error:
            # 清理失败不影响限流主路径（下一次消费再试）
            pass


def fixed_window_start(current: datetime, window_seconds: int) -> str:
    """Start of the fixed window containing *current* (epoch 取模对齐).

    Naive *current* is interpreted as UTC wall-clock (existing tests/CLI pass
    fixed UTC wall-clock times); aware *current* is normalized by absolute
    instant to UTC.  Returns naive-UTC ISO text (no tz suffix) so
    ``window_start`` strings stay byte-compatible with existing rows.
    """
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    epoch_seconds = int(current.timestamp())
    window_epoch = epoch_seconds - (epoch_seconds % window_seconds)
    return (
        datetime.fromtimestamp(window_epoch, tz=UTC)
        .replace(microsecond=0)
        .replace(tzinfo=None)
        .isoformat()
    )


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
    if current is None:
        # 默认路径：显式 UTC，再剥 tzinfo 输出 naive-UTC 文本（与
        # SQLiteRateLimitBackend 的 updated_at/cutoff 同格式）。
        now = datetime.now(UTC).replace(microsecond=0).replace(tzinfo=None)
    else:
        now = current.replace(microsecond=0)
    window_start = fixed_window_start(now, window_seconds)
    if not backend.consume(key=key, window_start=window_start, limit=limit):
        raise RateLimitError(f"{description} rate limit exceeded ({limit}/window)")


__all__ = [
    "RateLimitBackend",
    "SQLiteRateLimitBackend",
    "enforce_rate_limit",
    "fixed_window_start",
]
