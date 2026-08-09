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

"""Tests for the rate-limit backend abstraction (v3.0-P5, §17.4).

Covers the shared fixed-window core (``enforce_rate_limit`` /
``fixed_window_start``), the default ``SQLiteRateLimitBackend`` (atomic
counter over a table with (key, window_start) uniqueness), the delegation
of the two production enforcers, and the pluggable ``RateLimitBackend``
seam (a fake distributed backend implements the same Protocol).
"""

from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime

from kiwi_catalog.agent_catalog.sqlite_repository import enforce_catalog_register_domain_limit
from kiwi_catalog.api.idempotency import enforce_agent_catalog_rate_limit
from kiwi_catalog.core.errors import RateLimitError
from kiwi_catalog.db.session import init_db
from kiwi_catalog.services.rate_limit import (
    SQLiteRateLimitBackend,
    enforce_rate_limit,
    fixed_window_start,
)

T0 = datetime.fromisoformat("2026-08-06T10:00:00")  # aligned to any window


class _AutoCloseConnection(sqlite3.Connection):
    """测试连接随 GC 自动 close——消除 SQLite ResourceWarning（审查附录 A）。"""

    def __del__(self) -> None:  # noqa: D105
        try:
            self.close()
        except Exception:
            pass


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", factory=_AutoCloseConnection)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


class SQLiteRateLimitBackendTest(unittest.TestCase):
    def test_consume_counts_until_limit_then_rejects(self) -> None:
        conn = _conn()
        backend = SQLiteRateLimitBackend(
            conn, table="agent_catalog_write_rate_limits", key_column="actor_key"
        )
        window = fixed_window_start(T0, 60)
        for i in range(3):
            self.assertTrue(backend.consume(key="actor-1", window_start=window, limit=3), f"req {i}")
        self.assertFalse(backend.consume(key="actor-1", window_start=window, limit=3))
        # A different actor shares the same table but not the budget.
        self.assertTrue(backend.consume(key="actor-2", window_start=window, limit=3))

    def test_new_window_resets_budget(self) -> None:
        conn = _conn()
        backend = SQLiteRateLimitBackend(
            conn, table="agent_catalog_write_rate_limits", key_column="actor_key"
        )
        w1 = fixed_window_start(T0, 60)
        w2 = fixed_window_start(datetime.fromisoformat("2026-08-06T10:01:00"), 60)
        self.assertNotEqual(w1, w2)
        self.assertTrue(backend.consume(key="a", window_start=w1, limit=1))
        self.assertFalse(backend.consume(key="a", window_start=w1, limit=1))
        self.assertTrue(backend.consume(key="a", window_start=w2, limit=1))

    def test_domain_backend_normalizes_via_delegate(self) -> None:
        # Normalization (lowercase + strip trailing dot) happens in the
        # delegate, not the backend — same domain written differently must
        # share one budget.
        conn = _conn()
        enforce_catalog_register_domain_limit(conn, "MERCHANT.EXAMPLE.", limit=1, current=T0)
        with self.assertRaises(RateLimitError):
            enforce_catalog_register_domain_limit(conn, "merchant.example", limit=1, current=T0)


class EnforceRateLimitTest(unittest.TestCase):
    def test_exceeding_limit_raises(self) -> None:
        conn = _conn()
        backend = SQLiteRateLimitBackend(
            conn, table="agent_catalog_write_rate_limits", key_column="actor_key"
        )
        with self.assertRaises(RateLimitError):
            for _ in range(3):
                enforce_rate_limit(
                    backend,
                    key="actor-x",
                    limit=2,
                    window_seconds=60,
                    description="test budget",
                    current=T0,
                )

    def test_zero_limit_disables(self) -> None:
        conn = _conn()
        backend = SQLiteRateLimitBackend(
            conn, table="agent_catalog_write_rate_limits", key_column="actor_key"
        )
        enforce_rate_limit(
            backend, key="actor-x", limit=0, window_seconds=60, description="off"
        )

    def test_fixed_window_start_aligns_to_epoch(self) -> None:
        self.assertEqual(
            fixed_window_start(datetime.fromisoformat("2026-08-06T10:00:30"), 60),
            "2026-08-06T10:00:00",
        )
        self.assertEqual(
            fixed_window_start(datetime.fromisoformat("2026-08-06T10:00:59"), 60),
            "2026-08-06T10:00:00",
        )
        self.assertEqual(
            fixed_window_start(datetime.fromisoformat("2026-08-06T10:01:00"), 60),
            "2026-08-06T10:01:00",
        )

    def test_production_delegates_share_the_same_core(self) -> None:
        conn = _conn()
        with self.assertRaises(RateLimitError):
            for _ in range(3):
                enforce_agent_catalog_rate_limit(conn, "actor-delegate", limit=2, current=T0)
        with self.assertRaises(RateLimitError):
            for _ in range(3):
                enforce_catalog_register_domain_limit(
                    conn, "merchant.example", limit=2, current=T0
                )


class PluggableBackendSeamTest(unittest.TestCase):
    """A distributed backend only needs to implement RateLimitBackend."""

    def test_custom_backend_plugs_into_enforce_rate_limit(self) -> None:
        class MemoryBackend:
            """Stand-in for a Redis fixed-window counter (same Protocol)."""

            def __init__(self) -> None:
                self.counts: dict[tuple[str, str], int] = {}
                self.calls: list[tuple[str, str, int]] = []

            def consume(self, *, key: str, window_start: str, limit: int) -> bool:
                self.calls.append((key, window_start, limit))
                pair = (key, window_start)
                n = self.counts.get(pair, 0) + 1
                if n > limit:
                    return False
                self.counts[pair] = n
                return True

        backend = MemoryBackend()
        # Structural Protocol compliance: enforce_rate_limit only relies on
        # consume() — a distributed backend needs nothing more.
        enforce_rate_limit(backend, key="k", limit=2, window_seconds=60, description="mem", current=T0)
        enforce_rate_limit(backend, key="k", limit=2, window_seconds=60, description="mem", current=T0)
        with self.assertRaises(RateLimitError):
            enforce_rate_limit(backend, key="k", limit=2, window_seconds=60, description="mem", current=T0)
        self.assertEqual(len(backend.calls), 3)


if __name__ == "__main__":
    unittest.main()
