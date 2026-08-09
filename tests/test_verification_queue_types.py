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

"""Focused tests for the verification queue pure value types (§25 Phase 2)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kiwi_catalog.services import verification_queue_types
from kiwi_catalog.services.verification_queue_types import (
    VerificationQueueConfig,
    VerificationTask,
    VerificationTaskResult,
)

# ── VerificationQueueConfig bounds ──────────────────────────────────────────


def test_config_defaults() -> None:
    config = VerificationQueueConfig()
    assert config.max_pending == 100
    assert config.concurrency == 2
    assert config.task_timeout_seconds == 30.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_pending": 0},
        {"max_pending": -1},
        {"concurrency": 0},
        {"concurrency": -2},
        {"task_timeout_seconds": 0},
        {"task_timeout_seconds": -0.5},
    ],
)
def test_config_rejects_out_of_bounds(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        VerificationQueueConfig(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_pending": 1},
        {"concurrency": 1},
        {"task_timeout_seconds": 0.001},
        {"max_pending": 50, "concurrency": 4, "task_timeout_seconds": 15.0},
    ],
)
def test_config_accepts_boundary_values(kwargs: dict[str, object]) -> None:
    config = VerificationQueueConfig(**kwargs)  # type: ignore[arg-type]
    for key, value in kwargs.items():
        assert getattr(config, key) == value


def test_config_validation_mentions_offending_field() -> None:
    with pytest.raises(ValueError, match="max_pending must be >= 1"):
        VerificationQueueConfig(max_pending=0)
    with pytest.raises(ValueError, match="concurrency must be >= 1"):
        VerificationQueueConfig(concurrency=0)
    with pytest.raises(ValueError, match="task_timeout_seconds must be > 0"):
        VerificationQueueConfig(task_timeout_seconds=0)


# ── VerificationTask defaults ───────────────────────────────────────────────


def test_task_requires_ids_and_defaults_optional_fields() -> None:
    task = VerificationTask(catalog_agent_id="cagt_1", task_id="vt-000001-abc123")
    assert task.kind == "verify"
    assert task.actor == "verification_worker"
    assert task.enqueued_at == 0.0


def test_task_accepts_explicit_kind_actor_enqueued_at() -> None:
    task = VerificationTask(
        catalog_agent_id="cagt_2",
        task_id="vt-000002-def456",
        kind="refresh",
        actor="admin",
        enqueued_at=1234.5,
    )
    assert task.kind == "refresh"
    assert task.actor == "admin"
    assert task.enqueued_at == 1234.5


# ── VerificationTaskResult defaults ─────────────────────────────────────────


def test_task_result_requires_core_fields_and_defaults_optional() -> None:
    result = VerificationTaskResult(
        task_id="vt-000001-abc123",
        catalog_agent_id="cagt_1",
        kind="verify",
        status="completed",
        verification_status="domain_verified",
    )
    assert result.error == ""
    assert result.enqueued_at == 0.0
    assert result.started_at == 0.0
    assert result.finished_at == 0.0
    assert result.result is None


def test_task_result_accepts_explicit_optional_fields() -> None:
    result = VerificationTaskResult(
        task_id="vt-000002-def456",
        catalog_agent_id="cagt_2",
        kind="refresh",
        status="failed",
        verification_status="",
        error="worker error: RuntimeError: boom",
        enqueued_at=1.0,
        started_at=2.0,
        finished_at=3.0,
    )
    assert result.error == "worker error: RuntimeError: boom"
    assert result.enqueued_at == 1.0
    assert result.started_at == 2.0
    assert result.finished_at == 3.0


# ── Immutability (frozen) ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "factory",
    [
        lambda: VerificationQueueConfig(),
        lambda: VerificationTask(catalog_agent_id="cagt_1", task_id="vt-1"),
        lambda: VerificationTaskResult(
            task_id="vt-1", catalog_agent_id="cagt_1", kind="verify",
            status="enqueued", verification_status="",
        ),
    ],
)
def test_dataclasses_are_frozen(factory) -> None:
    instance = factory()
    field_name = next(
        name for name in ("max_pending", "actor", "error")
        if hasattr(instance, name)
    )
    with pytest.raises(FrozenInstanceError):
        setattr(instance, field_name, "changed")


# ── Re-export / import surface preservation ────────────────────────────────


def test_classes_are_reexported_from_agent_verification() -> None:
    from kiwi_catalog.services import agent_verification, verification_queue_types

    assert agent_verification.VerificationQueueConfig is verification_queue_types.VerificationQueueConfig
    assert agent_verification.VerificationTask is verification_queue_types.VerificationTask
    assert agent_verification.VerificationTaskResult is verification_queue_types.VerificationTaskResult

    assert "VerificationQueueConfig" in agent_verification.__all__
    assert "VerificationTask" in agent_verification.__all__
    assert "VerificationTaskResult" in agent_verification.__all__


def test_types_module_exports_only_queue_value_types() -> None:
    assert set(verification_queue_types.__all__) == {
        "VerificationQueueConfig",
        "VerificationTask",
        "VerificationTaskResult",
    }
