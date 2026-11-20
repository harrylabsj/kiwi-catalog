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

"""Bounded verification scheduling and durable queue recovery."""

from __future__ import annotations

import itertools
import queue
import sqlite3
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from kiwi_catalog.core.errors import ConflictError, NotFoundError, ShoppingCliError, ValidationError
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.services.verification_stages import VerificationResult
from kiwi_catalog.services.verification_queue_ownership import acquire_worker_lock
from kiwi_catalog.services.verification_queue_ledger import (
    UNKNOWN_OUTCOME_MARKER,
    mark_task_unknown as _mark_task_unknown,
    cleanup_terminal_tasks as _cleanup_terminal_tasks,
    list_unknown_tasks,
)
from kiwi_catalog.services.verification_queue_ledger import delete_task as _delete_task
from kiwi_catalog.services.verification_queue_ledger import (
    fail_pending_task as _fail_pending_task,
    fetch_task_row as _fetch_task_row,
)
from kiwi_catalog.services.verification_queue_ledger import finish_task as _finish_task
from kiwi_catalog.services.verification_queue_ledger import (
    insert_pending_task as _insert_pending_task,
)
from kiwi_catalog.services.verification_queue_ledger import (
    load_pending_tasks as _load_pending_tasks,
)
from kiwi_catalog.services.verification_queue_ledger import (
    mark_task_running as _mark_task_running,
)
from kiwi_catalog.services.verification_queue_ledger import (
    resolve_unknown_task as _resolve_unknown_task,
)
from kiwi_catalog.services.verification_queue_serialization import (
    deserialize_verification_result as _deserialize_verification_result,
)
from kiwi_catalog.services.verification_queue_serialization import (
    serialize_verification_result as _serialize_verification_result,
)
from kiwi_catalog.services.verification_queue_types import (
    VerificationQueueConfig,
    VerificationTask,
    VerificationTaskResult,
)

if TYPE_CHECKING:
    from kiwi_catalog.services.agent_verification import VerificationService

from kiwi_catalog.services.catalog_runtime_metrics import set_queue_depth

# ── Bounded in-process verification queue (§25 Phase 2) ─────────────────────
# Execution model (design §25 Phase 2):
#
#     registration / explicit refresh
#             ↓
#     bounded in-process verification queue
#             ↓
#     single-process worker with concurrency budget
#
# The queue is a bounded ``queue.Queue``; ``concurrency`` worker threads form
# the concurrency budget.  Each worker supervises the real task in a daemon
# sub-thread. A pre-commit deadline returns timeout; a commit already in
# progress returns unknown without blocking the supervisor. Physical runner
# capacity remains held until the real thread exits.  Every task opens its own database connection
# through the injected *service_factory* — a ``VerificationService`` instance
# is never shared across threads (see the service class docstring above).


class VerificationQueueFullError(ShoppingCliError):
    """Raised when the bounded queue is at capacity (fail-closed)."""


class VerificationQueueShutdownError(ShoppingCliError):
    """Raised when enqueueing after :meth:`VerificationQueue.shutdown`."""


class VerificationQueueLedgerError(ShoppingCliError):
    """Raised when the persistent ledger write fails at enqueue time.

    审查 P2：enqueue 的 ledger 写失败必须抛类型化错误（而不是裸 sqlite3
    异常冒泡）——调用方据此知道任务未入队、可安全重试。
    """


class VerificationQueueOutcomeUnknownError(ConflictError):
    """A prior task for this agent needs reconciliation, not another run."""


# 审查 P1-2：对账只允许两个方向——丢弃（把未确认的副作用视为未发生）或
# 认定已完成。两者都把 ``running`` 围栏行改成终态，让后续同 agent 的
# enqueue 重新可用；真正是否重跑由运营者决定（discarded 之后可再验证）。
_RECONCILE_OUTCOMES: dict[str, tuple[str, str]] = {
    "discarded": ("failed", "reconciled_discarded"),
    "completed": ("completed", "reconciled_completed"),
}


def _reconcile_target(outcome: str, reason: str) -> tuple[str, str, str]:
    """Map an operator outcome to the terminal ledger status/error fields."""
    try:
        status, verification_status = _RECONCILE_OUTCOMES[outcome]
    except KeyError:
        raise ValidationError(
            f"unsupported reconciliation outcome {outcome!r}; expected 'discarded' or 'completed'"
        ) from None
    error = f"reconciled by operator: {outcome}"
    if reason:
        error = f"{error}; reason: {reason}"
    return status, verification_status, error


_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "timeout"})


def _fence_conflict_message(task_id: str, status: str, verification_status: str) -> str:
    """Distinguish an already-terminal row from a non-fence running row."""
    detail = f"(status={status!r}, verification_status={verification_status!r})"
    if status in _TERMINAL_TASK_STATUSES:
        return f"verification task {task_id} is already resolved {detail}"
    return (
        f"verification task {task_id} is not an unresolved outcome fence {detail};"
        " only running/queue_outcome_unknown rows can be reconciled"
    )


def reconcile_verification_unknown(
    db_path: str | Path,
    task_id: str,
    *,
    outcome: str,
    reason: str = "",
) -> dict[str, Any]:
    """Operator reconciliation for one fenced (unknown-outcome) task.

    审查 P1-2：``mark_task_unknown`` 把未决任务永久留在
    ``status='running'`` 且 ``verification_status='queue_outcome_unknown'``，
    重启后同 agent 的所有 enqueue 都会 fail-closed 拒绝。本函数是闭环工具：
    用独立连接执行同一条受守卫 UPDATE（只有围栏行可改写），把行推进到
    终态，重启后的队列自然不再把该 agent 写入围栏。

    Args:
        db_path: SQLite catalog database path.
        task_id: Ledger task id returned by the fenced queue outcome.
        outcome: ``discarded`` (status ``failed``) or ``completed``
            (status ``completed``).
        reason: Optional operator note recorded in the ledger error column.

    Raises:
        ValidationError: *outcome* is not supported.
        NotFoundError: no ledger row exists for *task_id*.
        ConflictError: the row exists but is not an unresolved outcome fence.
    """
    status, verification_status, error = _reconcile_target(outcome, reason)
    resolved_at = now_iso()
    path = Path(db_path).expanduser().resolve()
    with closing(open_connection(path, migrate=False)) as conn, closing(acquire_worker_lock(path)), conn:
        row = _fetch_task_row(conn, task_id)
        if row is None:
            raise NotFoundError(f"verification task {task_id} not found")
        if row["status"] != "running":
            raise ConflictError(
                _fence_conflict_message(
                    task_id, str(row["status"]), str(row["verification_status"])
                )
            )
        # When no scheduler owns the ledger, an unmarked running row also
        # came from interrupted work and needs an explicit decision.
        if row["verification_status"] != UNKNOWN_OUTCOME_MARKER:
            _mark_task_unknown(
                conn, task_id=task_id, error="interrupted verification outcome unknown",
                finished_at=time.time(), updated_at=resolved_at,
            )
        updated = _resolve_unknown_task(
            conn,
            task_id=task_id,
            status=status,
            verification_status=verification_status,
            error=error,
            finished_at=time.time(),
            updated_at=resolved_at,
        )
        if not updated:
            current = _fetch_task_row(conn, task_id)
            if current is None:
                raise NotFoundError(f"verification task {task_id} not found")
            raise ConflictError(
                _fence_conflict_message(
                    task_id, str(current["status"]), str(current["verification_status"])
                )
            )
        return {
            "task_id": task_id,
            "catalog_agent_id": str(row["catalog_agent_id"]),
            "kind": str(row["kind"]),
            "outcome": outcome,
            "status": status,
            "verification_status": verification_status,
            "error": error,
            "updated_at": resolved_at,
        }


def list_verification_fences(conn: sqlite3.Connection, db_path: str | Path) -> list[sqlite3.Row]:
    """Include interrupted, unmarked runs only when the scheduler is offline."""
    try:
        lock = acquire_worker_lock(Path(db_path).expanduser().resolve())
    except ConflictError:
        return list(list_unknown_tasks(conn))
    with closing(lock):
        return list(list_unknown_tasks(conn, include_unmarked=True))


class _CommitPermission:
    """Short state decisions only: never hold this lock across service I/O."""

    def __init__(self, deadline: float, cancelled: threading.Event) -> None:
        self._lock = threading.Lock()
        self.deadline = deadline
        self.cancelled = cancelled
        self.state = "running"
        self.result: VerificationTaskResult | None = None

    def claim_commit(self) -> bool:
        with self._lock:
            if self.state != "running":
                return False
            if time.monotonic() >= self.deadline:
                self.state = "timeout"
                self.cancelled.set()
                return False
            self.state = "committing"
            return True

    def finish(self, result: VerificationTaskResult) -> None:
        with self._lock:
            if self.state in ("running", "committing"):
                self.state, self.result = "done", result

    def uncertain(self) -> None:
        with self._lock:
            self.state = "unknown"
            self.cancelled.set()

    def decide_deadline(self) -> tuple[str, VerificationTaskResult | None]:
        with self._lock:
            if self.state == "running":
                self.state = "timeout"
                self.cancelled.set()
            elif self.state == "committing":
                self.state = "unknown"
                self.cancelled.set()
            return self.state, self.result


class VerificationQueue:
    """Bounded in-process verification queue (§25 Phase 2, v3.0-P4).

    Usage::

        queue = make_verification_worker(db_path, config=VerificationQueueConfig(max_pending=50, concurrency=2))
        outcome = queue.enqueue("cagt_123", wait=True)
        # outcome.status == "completed" | "failed" | "timeout" | "unknown"

    The queue is thread-safe and schedules tasks in a bounded in-process
    ``queue.Queue``; ``concurrency`` worker threads form the concurrency
    budget.  With ``db_path`` set (the production path via
    :func:`make_verification_worker`) every task is written through to the
    ``verification_queue_tasks`` ledger (schema v15) so tasks survive a
    process restart: only safe ``pending`` rows are recovered. Old ``running``
    work has an unknown outcome and requires reconciliation before any
    same-agent run. Exactly one live scheduler may open a given database. ``wait()`` can rebuild outcomes from the ledger.  Without ``db_path`` the queue is
    purely in-memory (tests / embedded use).  Call :meth:`shutdown` (or use
    it as a context manager) to stop the worker threads.
    """

    _KINDS = frozenset({"verify", "refresh", "mark_stale", "suspend"})
    # review 2-31 F2：关闭置位后 worker 复核「已接纳任务全部有结果」的周期。
    _SHUTDOWN_POLL_SECONDS = 0.05
    _RESULT_RETENTION_SECONDS = 7 * 86400

    def __init__(
        self,
        *,
        service_factory: Callable[[], VerificationService],
        config: VerificationQueueConfig | None = None,
        now: Callable[[], float] | None = None,
        db_path: str | Path | None = None,
    ) -> None:
        self._config = config or VerificationQueueConfig()
        self._service_factory = service_factory
        self._now = now or time.time
        self._db_path = Path(db_path).expanduser().resolve() if db_path else None
        # Queue state and the ledger connection share one re-entrant lock.
        # Admission and recovery call ledger helpers while holding this lock.
        self._results_cv = threading.Condition(threading.RLock())
        self._db_conn: sqlite3.Connection | None = None
        self._worker_lock: sqlite3.Connection | None = None
        if self._db_path is not None:
            self._db_conn = open_connection(
                self._db_path, migrate=False, check_same_thread=False,
            )
            try:
                self._worker_lock = acquire_worker_lock(self._db_path)
            except BaseException:
                self._db_conn.close()
                self._db_conn = None
                raise

        self._results: dict[str, VerificationTaskResult] = {}
        self._tasks: dict[str, VerificationTask] = {}
        self._active_by_key: dict[tuple[str, str], set[str]] = {}
        self._completed_order: deque[tuple[float, str]] = deque()
        self._uncertain_agents: dict[str, set[str]] = {}
        self._active_runners: set[str] = set()
        # Keep physical daemon runners bounded even after a timeout/unknown.
        # A slot is returned only when the actual runner (including close) exits.
        self._runner_slots = threading.BoundedSemaphore(self._config.concurrency)
        self._shutdown = threading.Event()
        # 审查 P3：enqueue（检查+put）与 shutdown（置位+放哨兵）互斥锁
        self._enqueue_lock = threading.Lock()

        # Crash recovery: only safe pending work is re-enqueued. Running
        # work has an unknown outcome and remains fenced across restarts.  Recovered count
        # may exceed max_pending — the bound exists to stop runaway
        # enqueueing, not to drop recovered work, so the queue is sized to
        # fit both.
        try:
            recovered = self._recover_pending_tasks()
        except BaseException:
            self._close_ledger()
            raise
        self._pending: queue.Queue[VerificationTask | None] = queue.Queue(
            maxsize=max(self._config.max_pending, recovered + 1)
        )
        # review 2-31：同 agent 串行化状态（在 _results_cv 保护下访问）。
        self._agent_running: set[str] = set()
        self._agent_deferred: dict[str, list[VerificationTask]] = {}
        # review 2-31（A327）：preclaim 移交表——完成方在同一 cv 内把串行槽
        # 移交给 deferred 队首任务；该任务出队时凭身份绕过 busy 检查。
        self._agent_preclaimed: dict[str, VerificationTask] = {}
        for task in self._recovered_tasks:
            self._pending.put(task)
        self._id_seq = itertools.count(1)
        self._workers: list[threading.Thread] = []
        self._remaining_workers = self._config.concurrency
        for i in range(self._config.concurrency):
            worker = threading.Thread(
                target=self._run_worker,
                name=f"verification-queue-{i}",
                daemon=True,
            )
            worker.start()
            self._workers.append(worker)
        self._update_depth()

    def _update_depth(self) -> None:
        """Refresh the §24 ``verification_queue_depth`` gauge.

        Depth is the number of tasks enqueued but not yet finished — pending
        plus in-flight — computed from the two lock-guarded dicts (O(1)).
        """
        with self._results_cv:
            depth = len(self._tasks) - len(self._results)
        set_queue_depth(max(depth, 0))

    # ── Persistence ledger (v3.0-P4, schema v15) ──────────────────────────

    def _recover_pending_tasks(self) -> int:
        """Recover safe pending rows; all old running rows remain unresolved.

        A crash may have happened after a commit permission or actual commit.
        No running row is reliable evidence of non-execution. Unresolved rows
        and same-agent pending followers retain identity without being run.
        """
        self._recovered_tasks: list[VerificationTask] = []
        if self._db_conn is None:
            return 0
        with self._results_cv:
            rows = _load_pending_tasks(self._db_conn)
            for row in rows:
                if row["status"] == "running":
                    self._uncertain_agents.setdefault(str(row["catalog_agent_id"]), set()).add(
                        str(row["task_id"])
                    )
            for row in rows:
                task = VerificationTask(catalog_agent_id=str(row["catalog_agent_id"]),
                    task_id=str(row["task_id"]), kind=str(row["kind"]),
                    actor=str(row["actor"]), enqueued_at=float(row["enqueued_at"]))
                self._track_task(task)
                if row["status"] == "running":
                    self._record_result(self._unknown_outcome(
                        task, float(row["started_at"] or 0),
                        str(row["error"] or "recovered running outcome unknown; reconciliation required"),
                    ))
                elif task.catalog_agent_id in self._uncertain_agents:
                    self._record_result(self._reject_pending(
                        task, "blocked_by_unknown", "same-agent outcome unknown; task was not started",
                    ))
                else:
                    self._recovered_tasks.append(task)
        return len(self._recovered_tasks)

    def _persist_insert(self, task: VerificationTask) -> None:
        """Insert one pending task into the ledger (fail-closed on error)."""
        if self._db_conn is None:
            return
        with self._results_cv:
            _insert_pending_task(
                self._db_conn,
                task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id,
                kind=task.kind,
                actor=task.actor,
                enqueued_at=task.enqueued_at,
                created_at=now_iso(),
                updated_at=now_iso(),
            )
            self._db_conn.commit()

    def _persist_delete(self, task_id: str) -> None:
        """Roll back a ledger insert (e.g. when the memory queue is full)."""
        if self._db_conn is None:
            return
        with self._results_cv:
            _delete_task(self._db_conn, task_id)
            self._db_conn.commit()

    def _persist_running(self, task_id: str, started_at: float) -> bool:
        """Claim a pending ledger row before allowing business code to run."""
        if self._db_conn is None:
            return True
        with self._results_cv:
            try:
                claimed = _mark_task_running(
                    self._db_conn, task_id=task_id, started_at=started_at, updated_at=now_iso(),
                )
                self._db_conn.commit()
            except BaseException:
                self._db_conn.rollback()
                raise
            return claimed

    def _reject_pending(self, task: VerificationTask, reason: str, message: str) -> VerificationTaskResult:
        finished_at = self._now()
        with self._results_cv:
            if self._db_conn is not None:
                with self._db_conn:
                    _fail_pending_task(
                        self._db_conn, task_id=task.task_id, verification_status=reason,
                        error=message, finished_at=finished_at, updated_at=now_iso(),
                    )
                    self._prune_ledger(self._db_conn)
        return VerificationTaskResult(
            task_id=task.task_id, catalog_agent_id=task.catalog_agent_id, kind=task.kind,
            status="failed", verification_status=reason, error=message,
            enqueued_at=task.enqueued_at, finished_at=finished_at,
        )

    def _persist_unknown(self, task_id: str, error: str) -> None:
        if self._db_conn is None:
            return
        with self._results_cv:
            # The business connection may still own the SQLite write lock.
            # Never wait for that unknown commit to persist its marker: the
            # already committed running row is itself a restart fence.
            old_timeout = int(self._db_conn.execute("pragma busy_timeout").fetchone()[0])
            self._db_conn.execute("pragma busy_timeout=0")
            try:
                _mark_task_unknown(self._db_conn, task_id=task_id, error=error,
                                   finished_at=self._now(), updated_at=now_iso())
                self._db_conn.commit()
            except Exception:
                self._db_conn.rollback()
                raise
            finally:
                self._db_conn.execute(f"pragma busy_timeout={old_timeout}")

    def _unknown_outcome(self, task: VerificationTask, started_at: float,
                         reason: str) -> VerificationTaskResult:
        with self._results_cv:
            self._uncertain_agents.setdefault(task.catalog_agent_id, set()).add(task.task_id)
        error = reason
        try:
            self._persist_unknown(task.task_id, error)
        except Exception as exc:
            error += (f"; unknown marker persistence failed: {type(exc).__name__}: {exc}; "
                      "original running row retained as restart fence")
        return VerificationTaskResult(task_id=task.task_id,
            catalog_agent_id=task.catalog_agent_id, kind=task.kind, status="unknown",
            verification_status="", error=error, enqueued_at=task.enqueued_at,
            started_at=started_at, finished_at=self._now())

    def _persist_finish(
        self,
        task_id: str,
        *,
        status: str,
        verification_status: str = "",
        error: str = "",
        result: VerificationResult | None = None,
    ) -> None:
        """Write the terminal ledger row for a finished task."""
        if self._db_conn is None:
            return
        with self._results_cv, self._db_conn:
            _finish_task(
                self._db_conn,
                task_id=task_id,
                status=status,
                verification_status=verification_status,
                error=error,
                result_json=_serialize_verification_result(result),
                finished_at=self._now(),
                updated_at=now_iso(),
            )
            self._prune_ledger(self._db_conn)

    def _prune_ledger(self, conn: sqlite3.Connection) -> None:
        self._finish_count = getattr(self, "_finish_count", 0) + 1
        if self._finish_count % 256 == 0:
            try:
                _cleanup_terminal_tasks(conn, self._now() - self._RESULT_RETENTION_SECONDS)
            except sqlite3.Error:
                pass  # Retention cannot prevent recording the current outcome.

    def _ledger_result(self, task_id: str) -> VerificationTaskResult | None:
        """Rebuild a finished result from the ledger (restart path for wait())."""
        if self._db_conn is None:
            return None
        row = _fetch_task_row(self._db_conn, task_id)
        if row is None:
            return None
        if row["status"] == "running" and (
            row["verification_status"] == UNKNOWN_OUTCOME_MARKER or
            str(row["catalog_agent_id"]) in self._uncertain_agents
        ):
            return VerificationTaskResult(task_id=str(row["task_id"]),
                catalog_agent_id=str(row["catalog_agent_id"]), kind=str(row["kind"]),
                status="unknown", verification_status="",
                error=str(row["error"] or "running outcome unknown; reconciliation required"),
                enqueued_at=float(row["enqueued_at"]), started_at=float(row["started_at"]),
                finished_at=float(row["finished_at"]))
        if row["status"] in ("pending", "running"):
            return None
        return VerificationTaskResult(
            task_id=str(row["task_id"]),
            catalog_agent_id=str(row["catalog_agent_id"]),
            kind=str(row["kind"]),
            status=str(row["status"]),
            verification_status=str(row["verification_status"]),
            error=str(row["error"]),
            enqueued_at=float(row["enqueued_at"]),
            started_at=float(row["started_at"]),
            finished_at=float(row["finished_at"]),
            result=_deserialize_verification_result(str(row["result_json"])),
        )

    # ── Public API ───────────────────────────────────────────────────────

    def reconcile_unknown(
        self,
        task_id: str,
        *,
        outcome: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Reconcile one in-process unknown-outcome fence (审查 P1-2).

        Closes the durable fence with the same guarded UPDATE used by the
        standalone :func:`reconcile_verification_unknown`, records a terminal
        result for :meth:`wait`, and clears this agent's in-memory
        `_uncertain_agents` entry so subsequent enqueues are admitted
        again. A restarted process has no memory fence to clear — the terminal
        ledger row alone unblocks it.

        Raises:
            ValidationError: *outcome* is not `discarded`/`completed`.
            NotFoundError: no in-memory task or ledger row matches *task_id*.
            ConflictError: the row is already terminal or *task_id* is not the
                agent's current fence.
        """
        status, verification_status, error = _reconcile_target(outcome, reason)
        resolved_at = now_iso()
        with self._results_cv:
            conn = self._db_conn
            if task_id in self._active_runners:
                raise ConflictError(f"verification task {task_id} still has an active runner")
            task = self._tasks.get(task_id)
            row = _fetch_task_row(conn, task_id) if conn is not None else None
            if task is None and row is None:
                raise NotFoundError(f"verification task {task_id} not found")

            if row is not None and conn is not None:
                known_fences = self._uncertain_agents.get(str(row["catalog_agent_id"]), ())
                if row["status"] != "running" or (
                    row["verification_status"] != UNKNOWN_OUTCOME_MARKER and task_id not in known_fences
                ):
                    raise ConflictError(
                        _fence_conflict_message(
                            task_id, str(row["status"]), str(row["verification_status"])
                        )
                    )
                try:
                    if row["verification_status"] != UNKNOWN_OUTCOME_MARKER:
                        _mark_task_unknown(
                            conn, task_id=task_id, error="verification outcome unknown",
                            finished_at=self._now(), updated_at=resolved_at,
                        )
                    updated = _resolve_unknown_task(
                        conn,
                        task_id=task_id,
                        status=status,
                        verification_status=verification_status,
                        error=error,
                        finished_at=self._now(),
                        updated_at=resolved_at,
                    )
                except Exception:
                    conn.rollback()
                    raise
                if not updated:
                    conn.rollback()
                    current = _fetch_task_row(conn, task_id)
                    if current is None:
                        raise NotFoundError(f"verification task {task_id} not found")
                    # 审查 P1-2：重复对账必须显式失败——静默成功会让运营者
                    # 误以为第二次 outcome 也被采用，而 ledger 实际未变。
                    raise ConflictError(
                        _fence_conflict_message(
                            task_id, str(current["status"]), str(current["verification_status"])
                        )
                    )
                try:
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                catalog_agent_id = str(row["catalog_agent_id"])
                kind = str(row["kind"])
                enqueued_at = float(row["enqueued_at"])
                started_at = float(row["started_at"] or 0.0)
            elif conn is None:
                # 纯内存队列（测试/嵌入）：没有持久围栏，只能核对内存中的
                # agent->task 映射，避免误清另一个任务的围栏。
                if task is None:
                    raise NotFoundError(f"verification task {task_id} not found in memory")
                if task_id not in self._uncertain_agents.get(task.catalog_agent_id, ()):
                    raise ConflictError(
                        f"verification task {task_id} is not an active unknown-outcome fence"
                    )
                catalog_agent_id = task.catalog_agent_id
                kind = task.kind
                enqueued_at = task.enqueued_at
                started_at = 0.0
            else:
                # 持久队列：内存有任务但 ledger 行已不存在，不能假装成功。
                raise NotFoundError(
                    f"verification task {task_id} not found in the durable ledger"
                )

            fences = self._uncertain_agents.get(catalog_agent_id)
            if fences is not None:
                fences.discard(task_id)
            if fences is not None and not fences:
                self._uncertain_agents.pop(catalog_agent_id, None)
            self._record_result(VerificationTaskResult(
                task_id=task_id,
                catalog_agent_id=catalog_agent_id,
                kind=kind,
                status=status,
                verification_status=verification_status,
                error=error,
                enqueued_at=enqueued_at,
                started_at=started_at,
                finished_at=self._now(),
            ))
            self._results_cv.notify_all()
        self._update_depth()
        return {
            "task_id": task_id,
            "catalog_agent_id": catalog_agent_id,
            "kind": kind,
            "outcome": outcome,
            "status": status,
            "verification_status": verification_status,
            "error": error,
            "updated_at": resolved_at,
        }

    def enqueue(
        self,
        catalog_agent_id: str,
        *,
        kind: str = "verify",
        actor: str = "verification_worker",
        wait: bool = False,
        timeout: float | None = None,
    ) -> VerificationTaskResult:
        """Enqueue a verification task for *catalog_agent_id*.

        With ``wait=False`` (default) the call returns immediately with a
        ``status == "enqueued"`` result carrying the ``task_id``.  With
        ``wait=True`` it blocks until the task finishes and returns the final
        outcome (or ``status == "timeout"`` after *timeout* seconds).

        Raises:
            VerificationQueueFullError: the bounded queue is at capacity.
            VerificationQueueShutdownError: the queue has been shut down.
            ValueError: *kind* is not a supported task kind.
        """
        if kind not in self._KINDS:
            raise ValueError(f"unknown verification task kind: {kind!r}")
        with self._enqueue_lock, self._results_cv:
            if self._shutdown.is_set():
                raise VerificationQueueShutdownError("verification queue is shut down")
            self._prune_results()
            fences = self._uncertain_agents.get(catalog_agent_id)
            if fences:
                raise VerificationQueueOutcomeUnknownError(
                    f"verification outcome unknown for {catalog_agent_id} ({min(fences)}); reconciliation required"
                )
            existing = self._active_by_key.get((catalog_agent_id, kind))
            if existing:
                task = self._tasks[next(iter(existing))]
            else:
                if self._pending.full():
                    raise VerificationQueueFullError(
                        f"verification queue is full (max_pending={self._config.max_pending})"
                    )
                task = VerificationTask(
                    catalog_agent_id=catalog_agent_id, kind=kind, actor=actor,
                    task_id=f"vt-{next(self._id_seq):06d}-{uuid.uuid4().hex[:6]}",
                    enqueued_at=self._now(),
                )
                try:
                    self._persist_insert(task)
                except Exception as exc:
                    if self._db_conn is not None:
                        self._db_conn.rollback()
                    raise VerificationQueueLedgerError(
                        f"failed to persist verification task {task.task_id}: {exc}"
                    ) from exc
                # Admission, fencing and de-duplication stay under the same lock.
                try:
                    self._pending.put_nowait(task)
                except queue.Full as exc:
                    self._persist_delete(task.task_id)
                    raise VerificationQueueFullError(
                        f"verification queue is full (max_pending={self._config.max_pending})"
                    ) from exc
                self._track_task(task)
        self._update_depth()
        if wait:
            return self.wait(task.task_id, timeout=timeout)
        return VerificationTaskResult(
            task_id=task.task_id, catalog_agent_id=catalog_agent_id, kind=kind,
            status="enqueued", verification_status="",
            enqueued_at=task.enqueued_at, finished_at=self._now(),
        )

    def wait(self, task_id: str, timeout: float | None = None) -> VerificationTaskResult:
        """Block until the task with *task_id* produces a result.

        Returns a ``VerificationTaskResult`` with ``status == "timeout"`` when
        *timeout* seconds elapse before the task finishes.
        """
        deadline: float | None = None if timeout is None else time.monotonic() + timeout
        with self._results_cv:
            while task_id not in self._results:
                if task_id not in self._tasks:
                    from_ledger = self._ledger_result(task_id)
                    if from_ledger is not None:
                        return from_ledger
                if deadline is None:
                    self._results_cv.wait(0.5)
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Not finished in this process — a restarted queue may
                    # still hold the outcome in the v15 ledger.
                    from_ledger = self._ledger_result(task_id)
                    if from_ledger is not None:
                        return from_ledger
                    task = self._tasks.get(task_id)
                    return VerificationTaskResult(
                        task_id=task_id,
                        catalog_agent_id=task.catalog_agent_id if task else "",
                        kind=task.kind if task else "",
                        status="timeout",
                        verification_status="",
                        error="timed out waiting for verification result",
                        enqueued_at=task.enqueued_at if task else 0.0,
                        finished_at=self._now(),
                    )
                self._results_cv.wait(remaining)
            return self._results[task_id]

    def drain(self, timeout: float | None = None) -> list[VerificationTaskResult]:
        """Wait for each admitted task to have a recorded outcome.

        A commit still in progress may return unknown while its durable
        running fence remains. This does not imply all business I/O stopped.
        *timeout* only bounds this wait for recorded outcomes.
        """
        with self._results_cv:
            pending_ids = [tid for tid in self._tasks if tid not in self._results]
        deadline: float | None = None if timeout is None else time.monotonic() + timeout
        with self._results_cv:
            for tid in pending_ids:
                while tid not in self._results:
                    if deadline is None:
                        self._results_cv.wait(0.2)
                    else:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        self._results_cv.wait(remaining)
            return [self._results[tid] for tid in self._tasks if tid in self._results]

    def shutdown(self, wait: bool = True, timeout: float | None = None) -> None:
        """Stop accepting new tasks and (optionally) wait for workers to exit.

        正常关闭合同（review 2-31 F2）：已接纳的任务（pending / deferred /
        preclaimed）不随关闭丢弃——worker 在全部已接纳任务都有记录结果
        （completed / failed / timeout / unknown）后才退出。unknown仍持久
        保留running围栏，不表示业务I/O已停止；不靠重启重驱补完本轮工作。
        显式 timeout 仍只限制 join 等待，可能在排干前返回。
        """
        # Close admission under the same lock used by enqueue. Worker and
        # runner exit paths release the ledger only once all writes are done.
        with self._enqueue_lock:
            self._shutdown.set()
        if wait:
            deadline = None if timeout is None else time.monotonic() + timeout
            for worker in self._workers:
                remaining = None if deadline is None else max(0, deadline - time.monotonic())
                worker.join(timeout=remaining)

    def _close_ledger(self) -> None:
        for conn in (self._db_conn, self._worker_lock):
            if conn is not None:
                conn.close()
        self._db_conn = self._worker_lock = None

    def _close_if_idle(self) -> None:
        if self._shutdown.is_set() and self._remaining_workers == 0 and not self._active_runners:
            self._close_ledger()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown(wait=True)

    def _track_task(self, task: VerificationTask) -> None:
        self._tasks[task.task_id] = task
        self._active_by_key.setdefault((task.catalog_agent_id, task.kind), set()).add(task.task_id)

    def _prune_results(self) -> None:
        cutoff = self._now() - self._RESULT_RETENTION_SECONDS
        while self._completed_order and self._completed_order[0][0] < cutoff:
            _, task_id = self._completed_order.popleft()
            self._results.pop(task_id, None)
            self._tasks.pop(task_id, None)

    def _record_result(self, result: VerificationTaskResult) -> None:
        self._results[result.task_id] = result
        key = (result.catalog_agent_id, result.kind)
        active = self._active_by_key.get(key)
        if active is not None:
            active.discard(result.task_id)
            if not active:
                self._active_by_key.pop(key)
        if result.status in _TERMINAL_TASK_STATUSES:
            self._completed_order.append((self._now(), result.task_id))
        self._prune_results()

    def _run_worker(self) -> None:
        try:
            self._worker_loop()
        finally:
            with self._results_cv:
                self._remaining_workers -= 1
                self._close_if_idle()

    def _admitted_drained(self) -> bool:
        """正常关闭排干条件：所有已接纳任务（_tasks 登记）均已有结果。

        pending / deferred / preclaimed 任务同样登记在 _tasks 且尚无结果，
        故本条件覆盖全部接纳形态；unknown也有记录结果，但其业务后果
        仍未决，持久running围栏继续阻断重驱。
        """
        with self._results_cv:
            return not self._active_by_key

    def _worker_loop(self) -> None:
        # review 2-31（A327 返修）：同 agent 串行化收口为**单一互斥临界区**——
        # A317 v9 实证旧实现的两个同形屏障：①busy 检查与 running.add 分属两个
        # cv 块，双 worker 均 busyFalse 后同 agent 双执行；②defer 决定/append 与
        # 完成 owner 的 discard/pop 分锁，deferred 任务可能永久滞留（无后续
        # completion 可触发 drain）。现协议：
        #   出队（同一 cv 块内）：busy 且非 preclaim → defer；否则 running.add。
        #   完成（同一 cv 块内）：discard；deferred 队首**原子移交 preclaim**
        #   （agent 保持 running 归属）并经 _pending 重投，其余保持 deferred。
        #   preclaim 任务出队时凭 task_id 身份绕过 busy 检查直接执行。
        # 新到达的同 agent 任务一律 defer（无重叠窗口）；所有真实任务最终
        # 恰执行一次、结果恰记录一次。
        # review 2-31 F2（A332 返修）：正常关闭合同——shutdown 的哨兵只表示
        # 「不再接纳新任务」，不是立即退出信号。完成方的 preclaim 重投经
        # _pending 落在哨兵之后，哨兵即 break 会让已接纳的 deferred/preclaimed
        # 任务静默无结果（db_path=None 不可恢复；临时 ledger 场景则把本轮该
        # 完成的工作推给 shutdown 之后另进程恢复）。worker 必须在所有已接纳
        # 任务都有记录结果后才退出（unknown保持围栏）：关闭置位时用带超时的 get 周期复核排干
        # 条件。A343 不向有界工作队列放哨兵；空闲 get 亦周期检查关闭，
        # 避免 drained worker 先退使 shutdown 阻塞于放哨兵。
        handoff_task: VerificationTask | None = None
        task: VerificationTask | None
        while True:
            if self._shutdown.is_set() and self._admitted_drained():
                break
            from_pending = handoff_task is None
            if handoff_task is not None:
                # A full pending queue cannot make its only available consumer
                # wait to put. This already-admitted deferred task keeps its
                # atomic preclaim and is consumed by this worker locally.
                task, handoff_task = handoff_task, None
            else:
                try:
                    task = self._pending.get(timeout=self._SHUTDOWN_POLL_SECONDS)
                except queue.Empty:
                    continue
            try:
                if task is None:
                    continue
                with self._results_cv:
                    agent = task.catalog_agent_id
                    preclaimed = self._agent_preclaimed.get(agent) is task
                    if preclaimed:
                        # review 2-31 F1：preclaim 移交在出队时消费完毕，清掉
                        # 残留元数据（此前最后完成的 preclaimed 任务残留一条）。
                        self._agent_preclaimed.pop(agent, None)
                    uncertain = agent in self._uncertain_agents
                    if agent in self._agent_running and not preclaimed:
                        self._agent_deferred.setdefault(agent, []).append(task)
                        self._results_cv.notify_all()
                        continue
                    if not preclaimed:
                        self._agent_running.add(agent)
                    # preclaim 任务：归属已在完成方转移（running 未移除）
                try:
                    if uncertain:
                        result = self._reject_pending(
                            task, "blocked_by_unknown", "same-agent outcome unknown; task was not started",
                        )
                    else:
                        result = self._run_task_with_timeout(task)
                except Exception as exc:  # noqa: BLE001 —— 单任务失败不得杀 worker
                    #（并发预算减一且无恢复）；报告 failed 结果并继续循环。
                    result = VerificationTaskResult(
                        task_id=task.task_id,
                        catalog_agent_id=task.catalog_agent_id,
                        kind=task.kind,
                        status="failed",
                        verification_status="",
                        error=f"worker error: {type(exc).__name__}: {exc}",
                        enqueued_at=task.enqueued_at,
                        started_at=0.0,
                        finished_at=self._now(),
                    )
                    try:
                        self._persist_finish(
                            task.task_id, status="failed", error=result.error
                        )
                    except Exception:  # noqa: BLE001 —— ledger 写失败不杀 worker
                        pass
                    try:
                        self._reject_pending(task, "worker_error", result.error)
                    except Exception:
                        pass  # The original error remains available to wait().
                with self._results_cv:
                    # Reconciliation can publish a terminal result as soon as
                    # the runner exits; keep that result if it won the lock.
                    if task.task_id not in self._results:
                        self._record_result(result)
                    self._results_cv.notify_all()
                # review 2-31（A327）：完成收尾在同一 cv 块内——释放或**原子
                # 移交**串行槽给 deferred 队首（preclaim），消除 discard→pop
                # 分锁窗口；cv 外 put_nowait，满队列时本 worker 有界携带同一
                # task，不重建身份/期限；期间 agent 保持 running 归属。
                with self._results_cv:
                    self._results_cv.notify_all()
                    self._agent_running.discard(task.catalog_agent_id)
                    waiting = self._agent_deferred.pop(task.catalog_agent_id, [])
                    requeue = []
                    if waiting:
                        nxt = waiting.pop(0)
                        self._agent_running.add(task.catalog_agent_id)
                        self._agent_preclaimed[task.catalog_agent_id] = nxt
                        requeue.append(nxt)
                        self._agent_deferred[task.catalog_agent_id] = waiting
                        self._results_cv.notify_all()
                for d in requeue:
                    try:
                        self._pending.put_nowait(d)
                    except queue.Full:
                        handoff_task = d
                self._update_depth()
            finally:
                if from_pending:
                    self._pending.task_done()

    def _run_task_with_timeout(self, task: VerificationTask) -> VerificationTaskResult:
        deadline = time.monotonic() + self._config.task_timeout_seconds
        if not self._runner_slots.acquire(timeout=max(0, deadline - time.monotonic())):
            return self._reject_pending(task, "runner_unavailable", "no verification runner became available")
        cancelled = threading.Event()
        runner_ready = threading.Event()
        execution_allowed = threading.Event()
        permission = _CommitPermission(deadline, cancelled)
        box: dict[str, Any] = {"cancelled": cancelled, "permission": permission}

        def execute_and_release() -> None:
            try:
                runner_ready.set()
                execution_allowed.wait()
                if not cancelled.is_set():
                    self._execute_task(task, box)
            finally:
                with self._results_cv:
                    self._active_runners.discard(task.task_id)
                    self._close_if_idle()
                self._runner_slots.release()

        runner_started = False
        claimed = False
        try:
            if time.monotonic() >= deadline:
                return self._reject_pending(task, "runner_unavailable", "no verification runner became available")
            runner = threading.Thread(
                target=execute_and_release, name=f"verification-task-{task.task_id}", daemon=True,
            )
            with self._results_cv:
                self._active_runners.add(task.task_id)
            try:
                runner.start()
                runner_started = True
            except BaseException:
                with self._results_cv:
                    self._active_runners.discard(task.task_id)
                raise
            if not runner_ready.wait(max(0, deadline - time.monotonic())):
                return self._reject_pending(task, "runner_unavailable", "verification runner did not start")
            started_at = self._now()
            box["started_at"] = started_at
            claimed = self._persist_running(task.task_id, started_at)
            if not claimed:
                with self._results_cv:
                    existing = self._ledger_result(task.task_id)
                return existing or VerificationTaskResult(
                    task_id=task.task_id, catalog_agent_id=task.catalog_agent_id, kind=task.kind,
                    status="failed", verification_status="claim_lost", error="verification task could not be claimed",
                    enqueued_at=task.enqueued_at, finished_at=self._now(),
                )
        finally:
            # An actual runner returns its own slot when it exits.
            if not claimed:
                cancelled.set()
            execution_allowed.set()
            if not runner_started:
                self._runner_slots.release()
        runner.join(max(0, deadline - time.monotonic()))
        if not runner.is_alive() and permission.state == "running":
            permission.finish(VerificationTaskResult(task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id, kind=task.kind, status="failed",
                verification_status="",
                error="task ended without a result (persistence/execution error)",
                enqueued_at=task.enqueued_at, started_at=started_at,
                finished_at=self._now()))
        state, result = permission.decide_deadline()
        if state == "unknown":
            return self._unknown_outcome(task, started_at,
                str(box.get("commit_error") or "service commit outcome unknown after deadline; reconciliation required"))
        if result is None:
            result = VerificationTaskResult(task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id, kind=task.kind, status="timeout",
                verification_status="", error="deadline won before service commit permission",
                enqueued_at=task.enqueued_at, started_at=started_at, finished_at=self._now())
        # Only the supervisor publishes ledger outcomes. Late runners never
        # overwrite a timeout/unknown, even if their commit later returns.
        try:
            self._persist_finish(task.task_id, status=result.status,
                verification_status=result.verification_status, error=result.error, result=result.result)
        except Exception as exc:
            if result.status == "completed":
                return self._unknown_outcome(task, started_at,
                    f"commit confirmed but outcome persistence unknown: {type(exc).__name__}: {exc}")
            raise
        return result

    def _execute_task(self, task: VerificationTask, box: dict[str, Any]) -> None:
        started_at = float(box["started_at"])
        cancelled: threading.Event = box["cancelled"]
        permission: _CommitPermission = box["permission"]
        service = None
        factory_finished = False
        commit_started = False
        try:
            service = self._service_factory()
            factory_finished = True
            if cancelled.is_set():
                return
            if task.kind == "refresh":
                res = service.refresh(task.catalog_agent_id, actor=task.actor)
            elif task.kind == "mark_stale":
                res = service.mark_stale(task.catalog_agent_id, actor=task.actor)
            elif task.kind == "suspend":
                res = service.suspend(task.catalog_agent_id, actor=task.actor)
            else:
                res = service.verify(task.catalog_agent_id, actor=task.actor)
            # Independent profile snapshot/index short commits keep their
            # documented semantics. This permission governs the final service
            # transaction, atomically against the supervisor deadline decision.
            if not permission.claim_commit():
                return
            commit_started = True
            commit = getattr(service, "commit", None)
            if commit is not None:
                commit()
            permission.finish(VerificationTaskResult(task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id, kind=task.kind, status="completed",
                verification_status=res.status, enqueued_at=task.enqueued_at,
                started_at=started_at, finished_at=self._now(), result=res))
        except Exception as exc:
            if commit_started:
                box["commit_error"] = f"service commit outcome unknown: {type(exc).__name__}: {exc}"
                permission.uncertain()
            else:
                permission.finish(VerificationTaskResult(task_id=task.task_id,
                    catalog_agent_id=task.catalog_agent_id, kind=task.kind, status="failed",
                    verification_status="", error=(f"service factory failed: {exc}" if not factory_finished
                        else f"{type(exc).__name__}: {exc}"),
                    enqueued_at=task.enqueued_at, started_at=started_at, finished_at=self._now()))
        finally:
            close = getattr(service, "close", None)
            if close is not None:
                try:
                    # Never perform an unpermitted second implicit commit,
                    # including on successful and uncertain commit paths.
                    close(commit=False)
                except Exception:
                    pass
