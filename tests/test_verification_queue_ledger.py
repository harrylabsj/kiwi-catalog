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

"""Characterization tests for the verification queue ledger SQL helpers.

The helpers are pure statement runners over an injectable connection — they
must keep the exact SQL semantics the queue relies on (recovery load, the
``status = 'running'`` write fence on finish, lazy terminal cleanup) without
touching locks, time sources, or transaction boundaries.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest

from kiwi_catalog.db.migrations import migration_006_verification_queue_tasks
from kiwi_catalog.services import verification_queue_ledger
from kiwi_catalog.services.verification_queue_ledger import (
    cleanup_terminal_tasks,
    delete_task,
    fetch_task_row,
    finish_task,
    insert_pending_task,
    load_pending_tasks,
    mark_task_running,
)


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_006_verification_queue_tasks(c)
    c.commit()
    yield c
    c.close()


def _seed(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    catalog_agent_id: str = "cagt_x",
    kind: str = "verify",
    actor: str = "verification_worker",
    enqueued_at: float = 1.0,
) -> None:
    insert_pending_task(
        conn,
        task_id=task_id,
        catalog_agent_id=catalog_agent_id,
        kind=kind,
        actor=actor,
        enqueued_at=enqueued_at,
        created_at="2026-08-09T00:00:00+00:00",
        updated_at="2026-08-09T00:00:00+00:00",
    )


def _seed_terminal(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    status: str,
    finished_at: float,
) -> None:
    _seed(conn, task_id=task_id)
    mark_task_running(conn, task_id=task_id, started_at=1.5, updated_at="u")
    finish_task(
        conn,
        task_id=task_id,
        status=status,
        verification_status="profile_valid",
        error="",
        result_json="{}",
        finished_at=finished_at,
        updated_at="u",
    )


# ── load_pending_tasks (crash recovery) ─────────────────────────────────────


def test_load_pending_tasks_returns_pending_and_running_oldest_first(conn) -> None:
    _seed(conn, task_id="vt-2", catalog_agent_id="cagt_b", kind="refresh", actor="admin", enqueued_at=20.0)
    _seed(conn, task_id="vt-1", catalog_agent_id="cagt_a", enqueued_at=10.0)
    mark_task_running(conn, task_id="vt-1", started_at=10.5, updated_at="u")
    conn.commit()

    rows = load_pending_tasks(conn)
    assert [r["task_id"] for r in rows] == ["vt-1", "vt-2"]
    assert rows[0]["catalog_agent_id"] == "cagt_a"
    assert rows[0]["kind"] == "verify"
    assert rows[0]["actor"] == "verification_worker"
    assert rows[0]["enqueued_at"] == 10.0
    assert rows[1]["kind"] == "refresh"
    assert rows[1]["actor"] == "admin"


def test_load_pending_tasks_excludes_terminal_rows(conn) -> None:
    _seed(conn, task_id="vt-run", enqueued_at=10.0)
    mark_task_running(conn, task_id="vt-run", started_at=10.5, updated_at="u")
    _seed_terminal(conn, task_id="vt-done", status="completed", finished_at=11.0)
    _seed_terminal(conn, task_id="vt-failed", status="failed", finished_at=11.0)
    _seed_terminal(conn, task_id="vt-timeout", status="timeout", finished_at=11.0)
    conn.commit()

    assert [r["task_id"] for r in load_pending_tasks(conn)] == ["vt-run"]


# ── insert / delete ─────────────────────────────────────────────────────────


def test_insert_pending_task_writes_pending_row(conn) -> None:
    _seed(conn, task_id="vt-1", catalog_agent_id="cagt_a", kind="suspend", actor="admin", enqueued_at=42.0)
    conn.commit()

    row = fetch_task_row(conn, "vt-1")
    assert row is not None
    assert row["status"] == "pending"
    assert row["catalog_agent_id"] == "cagt_a"
    assert row["kind"] == "suspend"
    assert row["actor"] == "admin"
    assert row["enqueued_at"] == 42.0
    assert row["started_at"] == 0.0
    assert row["finished_at"] == 0.0


def test_delete_task_removes_row(conn) -> None:
    _seed(conn, task_id="vt-1")
    conn.commit()
    assert fetch_task_row(conn, "vt-1") is not None

    delete_task(conn, "vt-1")
    conn.commit()
    assert fetch_task_row(conn, "vt-1") is None


# ── mark_task_running ───────────────────────────────────────────────────────


def test_mark_task_running_sets_status_started_and_updated(conn) -> None:
    _seed(conn, task_id="vt-1")
    conn.commit()

    mark_task_running(conn, task_id="vt-1", started_at=1234.5, updated_at="2026-08-09T00:01:00+00:00")
    conn.commit()

    row = fetch_task_row(conn, "vt-1")
    assert row is not None
    assert row["status"] == "running"
    assert row["started_at"] == 1234.5
    assert row["updated_at"] == "2026-08-09T00:01:00+00:00"


# ── finish_task (write fence) ───────────────────────────────────────────────


def test_finish_task_writes_terminal_fields_only_for_running_rows(conn) -> None:
    _seed(conn, task_id="vt-a")
    conn.commit()

    # Not running yet → the fence makes this a no-op (supervisor timeouts
    # cannot be overwritten by a late-finishing runaway thread).
    finish_task(
        conn,
        task_id="vt-a",
        status="completed",
        verification_status="profile_valid",
        error="",
        result_json='{"status":"profile_valid"}',
        finished_at=11.0,
        updated_at="u",
    )
    conn.commit()
    unchanged = fetch_task_row(conn, "vt-a")
    assert unchanged is not None
    assert unchanged["status"] == "pending"

    mark_task_running(conn, task_id="vt-a", started_at=10.5, updated_at="u")
    finish_task(
        conn,
        task_id="vt-a",
        status="completed",
        verification_status="profile_valid",
        error="boom",
        result_json='{"status":"profile_valid"}',
        finished_at=11.0,
        updated_at="2026-08-09T00:02:00+00:00",
    )
    conn.commit()

    row = fetch_task_row(conn, "vt-a")
    assert row is not None
    assert row["status"] == "completed"
    assert row["verification_status"] == "profile_valid"
    assert row["error"] == "boom"
    assert row["result_json"] == '{"status":"profile_valid"}'
    assert row["finished_at"] == 11.0
    assert row["updated_at"] == "2026-08-09T00:02:00+00:00"


# ── cleanup_terminal_tasks (lazy GC) ────────────────────────────────────────


def test_cleanup_terminal_tasks_deletes_only_old_terminal_rows(conn) -> None:
    _seed_terminal(conn, task_id="vt-old-done", status="completed", finished_at=100.0)
    _seed_terminal(conn, task_id="vt-old-failed", status="failed", finished_at=100.0)
    _seed_terminal(conn, task_id="vt-old-timeout", status="timeout", finished_at=100.0)
    _seed_terminal(conn, task_id="vt-fresh-done", status="completed", finished_at=300.0)
    _seed(conn, task_id="vt-pending", enqueued_at=1.0)
    _seed(conn, task_id="vt-running", enqueued_at=1.0)
    mark_task_running(conn, task_id="vt-running", started_at=1.5, updated_at="u")
    conn.commit()

    cleanup_terminal_tasks(conn, cutoff_epoch=200.0)
    conn.commit()

    assert fetch_task_row(conn, "vt-old-done") is None
    assert fetch_task_row(conn, "vt-old-failed") is None
    assert fetch_task_row(conn, "vt-old-timeout") is None
    assert fetch_task_row(conn, "vt-fresh-done") is not None  # finished_at >= cutoff
    assert fetch_task_row(conn, "vt-pending") is not None  # not terminal
    assert fetch_task_row(conn, "vt-running") is not None  # not terminal


# ── fetch_task_row ──────────────────────────────────────────────────────────


def test_fetch_task_row_unknown_task_returns_none(conn) -> None:
    assert fetch_task_row(conn, "vt-nope") is None


# ── transaction boundary (helpers never commit) ─────────────────────────────


def test_helpers_do_not_commit_transaction_boundary_stays_with_caller(tmp_path) -> None:
    db = tmp_path / "ledger.sqlite"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    migration_006_verification_queue_tasks(conn)
    conn.commit()

    _seed(conn, task_id="vt-1")
    # No commit: a second connection must not see the uncommitted write.
    other = sqlite3.connect(db)
    try:
        other.row_factory = sqlite3.Row
        before = other.execute("select count(*) from verification_queue_tasks").fetchone()
        assert before is not None
        assert before[0] == 0
        conn.commit()
        after = other.execute("select count(*) from verification_queue_tasks").fetchone()
        assert after is not None
        assert after[0] == 1
    finally:
        other.close()
    conn.close()


# ── parameterization ────────────────────────────────────────────────────────


def test_helpers_parameterize_values_no_injection(conn) -> None:
    evil = "vt-1' OR '1'='1"
    _seed(conn, task_id=evil)
    conn.commit()

    # Stored verbatim, never spliced into the statement.
    assert fetch_task_row(conn, evil) is not None
    assert fetch_task_row(conn, "vt-1") is None
    assert [r["task_id"] for r in load_pending_tasks(conn)] == [evil]


# ── module surface ──────────────────────────────────────────────────────────


def test_ledger_module_exports_only_sql_helpers() -> None:
    assert set(verification_queue_ledger.__all__) == {
        "load_pending_tasks",
        "insert_pending_task",
        "delete_task",
        "mark_task_running",
        "finish_task",
        "cleanup_terminal_tasks",
        "fetch_task_row",
    }


def test_queue_persist_methods_remain_visible_for_mocking() -> None:
    """The queue keeps its private persist facade so existing mock.patch.object
    call sites (test_verification_queue.py) keep resolving."""
    from kiwi_catalog.services.agent_verification import VerificationQueue

    for name in (
        "_recover_pending_tasks",
        "_persist_insert",
        "_persist_delete",
        "_persist_running",
        "_persist_finish",
        "_ledger_result",
    ):
        assert callable(getattr(VerificationQueue, name)), name
