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

"""Pure value types for the bounded in-process verification queue (§25 Phase 2).

The queue types live here so ``agent_verification.py`` keeps only the queue
*execution* machinery (worker threads, ledger, state transitions) while these
plain-data dataclasses and their validation stay focused and importable
without dragging in the whole verification pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kiwi_catalog.services.agent_verification import VerificationResult


@dataclass(frozen=True)
class VerificationQueueConfig:
    """Tuning knobs for the bounded in-process verification queue (§25 Phase 2)."""

    max_pending: int = 100
    """Maximum number of queued (not yet started) tasks.  Enqueueing beyond
    this raises :class:`VerificationQueueFullError` (fail-closed)."""

    concurrency: int = 2
    """Maximum number of verification tasks executed simultaneously."""

    task_timeout_seconds: float = 30.0
    """Per-task wall-clock deadline.  A task that exceeds it is reported with
    ``status == "timeout"`` and the worker frees its slot for the next task."""

    def __post_init__(self) -> None:
        if self.max_pending < 1:
            raise ValueError("max_pending must be >= 1")
        if self.concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        if self.task_timeout_seconds <= 0:
            raise ValueError("task_timeout_seconds must be > 0")


@dataclass(frozen=True)
class VerificationTask:
    """One queued verification job."""

    catalog_agent_id: str
    task_id: str
    kind: str = "verify"
    actor: str = "verification_worker"
    enqueued_at: float = 0.0


@dataclass(frozen=True)
class VerificationTaskResult:
    """Outcome of a queued verification job."""

    task_id: str
    catalog_agent_id: str
    kind: str
    status: str
    """``enqueued`` | ``completed`` | ``failed`` | ``timeout``."""

    verification_status: str
    """Final ``catalog_agents.verification_status`` (empty unless completed)."""

    error: str = ""
    enqueued_at: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0
    result: VerificationResult | None = None


__all__ = [
    "VerificationQueueConfig",
    "VerificationTask",
    "VerificationTaskResult",
]
