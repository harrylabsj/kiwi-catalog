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

"""Pure SQL persistence helpers for the ``verification_queue_tasks`` ledger.

The ledger is the durable side of the bounded in-process verification queue
(§25 Phase 2, schema v15): enqueued tasks are written through so a process
restart recovers ``pending``/``running`` rows and ``wait()`` can rebuild
outcomes from the ledger.

Each helper is a small, injectable statement runner: the caller passes the
``sqlite3.Connection`` (or transaction) to run against, so the queue can drive
the ledger with its single ``_db_conn`` while holding ``_results_cv``, and
tests can drive it with any scratch connection.  No locking, no queue state
and no time source live here — timestamps (``now_iso`` / the queue's ``_now``)
are computed by the caller and passed as parameters, and nothing commits:
transaction boundaries stay with the caller.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

__all__ = [
    "cleanup_terminal_tasks",
    "delete_task",
    "fetch_task_row",
    "finish_task",
    "insert_pending_task",
    "load_pending_tasks",
    "mark_task_running",
]


def load_pending_tasks(conn: sqlite3.Connection) -> Sequence[sqlite3.Row]:
    """Select pending/running rows, oldest enqueued first (crash recovery)."""
    return conn.execute(
        "select task_id, catalog_agent_id, kind, actor, enqueued_at"
        " from verification_queue_tasks where status in ('pending','running')"
        " order by enqueued_at"
    ).fetchall()


def insert_pending_task(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    catalog_agent_id: str,
    kind: str,
    actor: str,
    enqueued_at: float,
    created_at: str,
    updated_at: str,
) -> None:
    """Insert one pending task into the ledger (fail-closed on error)."""
    conn.execute(
        "insert into verification_queue_tasks("
        " task_id, catalog_agent_id, kind, actor, status, enqueued_at,"
        " created_at, updated_at)"
        " values (?, ?, ?, ?, 'pending', ?, ?, ?)",
        (task_id, catalog_agent_id, kind, actor, enqueued_at, created_at, updated_at),
    )


def delete_task(conn: sqlite3.Connection, task_id: str) -> None:
    """Roll back a ledger insert (e.g. when the memory queue is full)."""
    conn.execute(
        "delete from verification_queue_tasks where task_id = ?", (task_id,)
    )


def mark_task_running(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    started_at: float,
    updated_at: str,
) -> None:
    """Mark a task as running in the ledger."""
    conn.execute(
        "update verification_queue_tasks"
        " set status = 'running', started_at = ?, updated_at = ?"
        " where task_id = ?",
        (started_at, updated_at, task_id),
    )


def finish_task(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    status: str,
    verification_status: str,
    error: str,
    result_json: str,
    finished_at: float,
    updated_at: str,
) -> None:
    """Write the terminal ledger row for a finished task.

    The ``and status = 'running'`` guard is the ledger's write fence: a
    ``timeout`` already persisted by the supervisor cannot be overwritten by
    a runaway task thread that finishes late.
    """
    conn.execute(
        "update verification_queue_tasks"
        " set status = ?, verification_status = ?, error = ?,"
        " result_json = ?, finished_at = ?, updated_at = ?"
        " where task_id = ? and status = 'running'",
        (status, verification_status, error, result_json, finished_at, updated_at, task_id),
    )


def cleanup_terminal_tasks(conn: sqlite3.Connection, cutoff_epoch: float) -> None:
    """Lazily drop terminal rows finished before *cutoff_epoch* (epoch REAL)."""
    conn.execute(
        "delete from verification_queue_tasks"
        " where status in ('completed','failed','timeout')"
        " and finished_at < ?",
        (cutoff_epoch,),
    )


def fetch_task_row(conn: sqlite3.Connection, task_id: str) -> sqlite3.Row | None:
    """Read one ledger row, or None when absent (restart path for wait())."""
    return conn.execute(
        "select * from verification_queue_tasks where task_id = ?", (task_id,)
    ).fetchone()
