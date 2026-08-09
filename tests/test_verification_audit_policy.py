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

"""Characterization tests for the extracted verification audit/event policy
(T8/T9 split of ``agent_verification.py``).

These tests lock the pure §23 audit + §24 funnel decision that previously
lived in ``VerificationService._finalize``: which events are written, their
exact details fields (including the pinned ``trust_policy_version``), whether
a ``verified`` funnel increment fires, the empty-stages
``StageResult("verification", failure_kind, status)`` fallback, and the
refreshed-first event order.  The leaf is side-effect free; the facade
delegation tests prove ``_finalize`` still emits the identical audit rows and
funnel counters through ``append_catalog_audit`` / ``record_funnel``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import FrozenInstanceError

import pytest

from kiwi_catalog.db.migrations import (
    migration_001_agent_catalog,
    migration_009_shadow_tables,
)
from kiwi_catalog.discovery.verifier import (
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
    DOMAIN_VERIFIED,
    PROFILE_VALID,
    REJECTED,
    STALE,
)
from kiwi_catalog.services import verification_audit_policy
from kiwi_catalog.services.catalog_runtime_metrics import (
    reset_runtime_metrics,
    snapshot_runtime_metrics,
)
from kiwi_catalog.services.verification_audit_policy import (
    AuditEvent,
    FinalizeAuditPlan,
    FunnelStep,
    finalize_audit_plan,
)
from kiwi_catalog.services.verification_stages import StageResult

POLICY_VERSION = 1  # TrustPolicy.defaults().policy_version


def _profile_stage(snapshot_ids: tuple[int, ...] = (11, 12)) -> StageResult:
    return StageResult(
        "profile", "passed", PROFILE_VALID, snapshot_ids=snapshot_ids
    )


def _failed_stage(stage: str = "domain_control", reason: str = "domain control failed") -> StageResult:
    return StageResult(stage, "rejected", REJECTED, reason=reason)


# ── finalize_audit_plan: success paths ───────────────────────────────────────


def test_success_at_commerce_verified_emits_funnel_then_verified_event() -> None:
    stages = (_profile_stage(), _failed_stage(), StageResult("commerce_capability", "passed", COMMERCE_VERIFIED))
    plan = finalize_audit_plan(
        status=COMMERCE_VERIFIED,
        stages=stages,
        policy_version=POLICY_VERSION,
        failure_kind=None,
    )
    assert plan.steps == (
        AuditEvent(
            "catalog_agent_refreshed",
            {
                "verification_status": COMMERCE_VERIFIED,
                "stage_count": 3,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
        FunnelStep("verified"),
        AuditEvent(
            "catalog_agent_verified",
            {
                "verification_status": COMMERCE_VERIFIED,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
    )


def test_success_at_verified_rung_non_commerce_only_funnels() -> None:
    """Any §24 verified rung counts as verified, but only COMMERCE_VERIFIED
    emits the ``catalog_agent_verified`` audit (e.g. verify_domain_control)."""
    stages = (StageResult("domain_control", "passed", DOMAIN_VERIFIED),)
    plan = finalize_audit_plan(
        status=DOMAIN_VERIFIED,
        stages=stages,
        policy_version=POLICY_VERSION,
        failure_kind=None,
    )
    assert plan.steps == (FunnelStep("verified"),)
    # AGENT_VERIFIED behaves identically.
    assert finalize_audit_plan(
        status=AGENT_VERIFIED,
        stages=(StageResult("agent_identity", "passed", AGENT_VERIFIED),),
        policy_version=POLICY_VERSION,
        failure_kind=None,
    ).steps == (FunnelStep("verified"),)


def test_success_at_non_verified_rung_emits_nothing() -> None:
    """PROFILE_VALID is not a §24 verified rung → no funnel, no audits."""
    plan = finalize_audit_plan(
        status=PROFILE_VALID,
        stages=(_profile_stage(),),
        policy_version=POLICY_VERSION,
        failure_kind=None,
    )
    assert plan.steps == (
        AuditEvent(
            "catalog_agent_refreshed",
            {
                "verification_status": PROFILE_VALID,
                "stage_count": 1,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
    )


# ── finalize_audit_plan: failure paths ───────────────────────────────────────


def test_failure_emits_verification_failed_event() -> None:
    stages = (_profile_stage(), _failed_stage())
    plan = finalize_audit_plan(
        status=REJECTED,
        stages=stages,
        policy_version=POLICY_VERSION,
        failure_kind="rejected",
    )
    assert plan.steps == (
        AuditEvent(
            "catalog_agent_refreshed",
            {
                "verification_status": REJECTED,
                "stage_count": 2,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
        AuditEvent(
            "catalog_agent_verification_failed",
            {
                "failed_stage": "domain_control",
                "reason": "domain control failed",
                "target_status": REJECTED,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
    )


def test_failure_stale_emits_failed_then_stale_event() -> None:
    stages = (StageResult("profile", "stale", STALE, reason="profile fetch failed"),)
    plan = finalize_audit_plan(
        status=STALE,
        stages=stages,
        policy_version=POLICY_VERSION,
        failure_kind=STALE,
    )
    assert plan.steps == (
        AuditEvent(
            "catalog_agent_verification_failed",
            {
                "failed_stage": "profile",
                "reason": "profile fetch failed",
                "target_status": STALE,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
        AuditEvent("catalog_agent_stale", {"reason": "profile fetch failed"}),
    )


def test_failure_non_stale_does_not_emit_stale_event() -> None:
    plan = finalize_audit_plan(
        status=REJECTED,
        stages=(_failed_stage(),),
        policy_version=POLICY_VERSION,
        failure_kind="rejected",
    )
    assert [s.event for s in plan.steps if isinstance(s, AuditEvent)] == [
        "catalog_agent_verification_failed"
    ]


# ── finalize_audit_plan: empty-stages fallback ───────────────────────────────


def test_empty_stages_failure_falls_back_to_verification_stage() -> None:
    """With no stages the failed audit uses the synthetic
    ``StageResult("verification", failure_kind, status)`` fallback."""
    plan = finalize_audit_plan(
        status=REJECTED,
        stages=(),
        policy_version=POLICY_VERSION,
        failure_kind="rejected",
    )
    assert plan.steps == (
        AuditEvent(
            "catalog_agent_verification_failed",
            {
                "failed_stage": "verification",
                "reason": "",
                "target_status": REJECTED,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
    )


def test_empty_stages_stale_failure_uses_fallback_reason() -> None:
    plan = finalize_audit_plan(
        status=STALE,
        stages=(),
        policy_version=POLICY_VERSION,
        failure_kind=STALE,
    )
    assert plan.steps == (
        AuditEvent(
            "catalog_agent_verification_failed",
            {
                "failed_stage": "verification",
                "reason": "",
                "target_status": STALE,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
        AuditEvent("catalog_agent_stale", {"reason": ""}),
    )


def test_empty_stages_success_emits_only_funnel() -> None:
    plan = finalize_audit_plan(
        status=COMMERCE_VERIFIED,
        stages=(),
        policy_version=POLICY_VERSION,
        failure_kind=None,
    )
    assert plan.steps == (
        FunnelStep("verified"),
        AuditEvent(
            "catalog_agent_verified",
            {
                "verification_status": COMMERCE_VERIFIED,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
    )


# ── finalize_audit_plan: refreshed-first ordering ────────────────────────────


def test_refreshed_only_when_first_stage_is_profile_with_snapshots() -> None:
    assert finalize_audit_plan(
        status=COMMERCE_VERIFIED,
        stages=(_profile_stage(snapshot_ids=()), StageResult("commerce_capability", "passed", COMMERCE_VERIFIED)),
        policy_version=POLICY_VERSION,
        failure_kind=None,
    ).steps == (
        FunnelStep("verified"),
        AuditEvent(
            "catalog_agent_verified",
            {
                "verification_status": COMMERCE_VERIFIED,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
    )
    # First stage not named profile → no refreshed event either.
    assert finalize_audit_plan(
        status=COMMERCE_VERIFIED,
        stages=(StageResult("commerce_capability", "passed", COMMERCE_VERIFIED),),
        policy_version=POLICY_VERSION,
        failure_kind=None,
    ).steps == (
        FunnelStep("verified"),
        AuditEvent(
            "catalog_agent_verified",
            {
                "verification_status": COMMERCE_VERIFIED,
                "trust_policy_version": POLICY_VERSION,
            },
        ),
    )


def test_stage_count_counts_all_stages_not_snapshot_count() -> None:
    """The refreshed event's ``stage_count`` is ``len(stages)`` (total run
    stages), not the number of snapshots written."""
    plan = finalize_audit_plan(
        status=COMMERCE_VERIFIED,
        stages=(_profile_stage(snapshot_ids=(1, 2)), StageResult("commerce_capability", "passed", COMMERCE_VERIFIED)),
        policy_version=POLICY_VERSION,
        failure_kind=None,
    )
    refreshed = plan.steps[0]
    assert isinstance(refreshed, AuditEvent)
    assert refreshed.details["stage_count"] == 2


# ── Data shapes ──────────────────────────────────────────────────────────────


def test_plan_types_are_frozen() -> None:
    for obj in (AuditEvent("catalog_agent_verified", {}), FunnelStep("verified"), FinalizeAuditPlan(())):
        with pytest.raises(FrozenInstanceError):
            obj.event = "x"  # type: ignore[misc]


def test_plan_steps_is_a_tuple() -> None:
    plan = finalize_audit_plan(
        status=COMMERCE_VERIFIED,
        stages=(),
        policy_version=POLICY_VERSION,
        failure_kind=None,
    )
    assert isinstance(plan.steps, tuple)


def test_audit_policy_module_exports_only_policy_surface() -> None:
    assert set(verification_audit_policy.__all__) == {
        "AuditEvent",
        "FinalizeAuditPlan",
        "FunnelStep",
        "finalize_audit_plan",
    }


# ── Re-export / import surface preservation ─────────────────────────────────


def test_audit_policy_names_reexported_from_agent_verification() -> None:
    from kiwi_catalog.services import agent_verification
    from kiwi_catalog.services.verification_profile_policy import VERIFIED_RUNGS

    assert agent_verification._finalize_audit_plan is finalize_audit_plan
    assert agent_verification._FunnelStep is FunnelStep
    # _VERIFIED_RUNGS stays importable on the facade (legacy re-export).
    assert agent_verification._VERIFIED_RUNGS is VERIFIED_RUNGS


# ── Facade delegation: VerificationService._finalize ─────────────────────────


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    migration_009_shadow_tables(c)
    c.commit()
    yield c
    c.close()


def _audit_rows(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "select id, event, details_json from audit_events order by id"
    ).fetchall()
    return [{"event": r["event"], "details": json.loads(r["details_json"])} for r in rows]


def _funnel() -> dict[str, int]:
    return snapshot_runtime_metrics()["funnel"]


@pytest.fixture(autouse=True)
def _reset_metrics() -> Iterator[None]:
    reset_runtime_metrics()
    yield
    reset_runtime_metrics()


def test_facade_finalize_success_commerce_writes_refreshed_then_verified(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    service = VerificationService(conn)
    stages = (
        _profile_stage(),
        StageResult("commerce_capability", "passed", COMMERCE_VERIFIED),
    )
    result = service._finalize(
        "cagt_x", "domain_verified", COMMERCE_VERIFIED, stages, "verification_worker", None
    )
    rows = _audit_rows(conn)
    assert [r["event"] for r in rows] == [
        "catalog_agent_refreshed",
        "catalog_agent_verified",
    ]
    assert rows[0]["details"]["verification_status"] == COMMERCE_VERIFIED
    assert rows[0]["details"]["stage_count"] == 2
    assert rows[0]["details"]["trust_policy_version"] == POLICY_VERSION
    assert rows[1]["details"]["verification_status"] == COMMERCE_VERIFIED
    assert _funnel().get("verified") == 1
    assert result.status == COMMERCE_VERIFIED
    assert result.stages == tuple(stages)


def test_facade_finalize_success_verified_rung_funnels_without_verified_audit(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    service = VerificationService(conn)
    service._finalize(
        "cagt_x", "profile_valid", DOMAIN_VERIFIED, (StageResult("domain_control", "passed", DOMAIN_VERIFIED),), "verification_worker", None
    )
    assert _audit_rows(conn) == []
    assert _funnel().get("verified") == 1


def test_facade_finalize_failure_rejected_writes_failed_audit(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    service = VerificationService(conn)
    service._finalize(
        "cagt_x", "profile_valid", REJECTED, (_failed_stage(),), "verification_worker", "rejected"
    )
    rows = _audit_rows(conn)
    assert [r["event"] for r in rows] == ["catalog_agent_verification_failed"]
    assert rows[0]["details"]["failed_stage"] == "domain_control"
    assert rows[0]["details"]["reason"] == "domain control failed"
    assert rows[0]["details"]["target_status"] == REJECTED
    assert rows[0]["details"]["trust_policy_version"] == POLICY_VERSION
    assert _funnel() == {}


def test_facade_finalize_failure_stale_writes_failed_then_stale(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    service = VerificationService(conn)
    service._finalize(
        "cagt_x", "commerce_verified", STALE, (StageResult("profile", "stale", STALE, reason="fetch failed"),), "verification_worker", STALE
    )
    rows = _audit_rows(conn)
    assert [r["event"] for r in rows] == [
        "catalog_agent_verification_failed",
        "catalog_agent_stale",
    ]
    assert rows[1]["details"]["reason"] == "fetch failed"
    assert _funnel() == {}


def test_facade_finalize_empty_stages_failure_uses_fallback(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    service = VerificationService(conn)
    service._finalize("cagt_x", "profile_valid", REJECTED, (), "verification_worker", "rejected")
    rows = _audit_rows(conn)
    assert [r["event"] for r in rows] == ["catalog_agent_verification_failed"]
    assert rows[0]["details"]["failed_stage"] == "verification"
    assert rows[0]["details"]["reason"] == ""
    assert rows[0]["details"]["target_status"] == REJECTED
    assert _funnel() == {}


def test_facade_finalize_audit_details_are_public_only(conn) -> None:
    """The §17.3 public-only boundary: every audit row carries only public
    metadata (status/stage/policy version), never profile content."""
    from kiwi_catalog.services.agent_verification import VerificationService

    service = VerificationService(conn)
    service._finalize(
        "cagt_x", "commerce_verified", STALE, (StageResult("profile", "stale", STALE, reason="fetch failed"),), "verification_worker", STALE
    )
    for row in _audit_rows(conn):
        assert set(row["details"]) <= {
            "schema_version",
            "event_type",
            "catalog_agent_id",
            "verification_status",
            "stage_count",
            "trust_policy_version",
            "failed_stage",
            "reason",
            "target_status",
        }
        assert "capabilities" not in row["details"]
        assert "skills" not in row["details"]
