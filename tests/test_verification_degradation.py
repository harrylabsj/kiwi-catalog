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

"""Characterization tests for the extracted verification failure/degradation
policy (T8/T9 split of ``agent_verification.py``).

These tests lock the v0.3 §7.1 evidence recomputation decision
(``highest_supported_level``) and the §7.2 profile-failure handling plan
(``profile_failure_plan``) that previously lived in ``agent_verification.py``,
plus the re-export surface that keeps the public facade unchanged and the
service facade delegation that proves the extraction is behavior-preserving.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from kiwi_catalog.agent_catalog.sqlite_repository import (
    _insert_catalog_agent,
    require_catalog_agent,
)
from kiwi_catalog.agent_catalog.verification_evidence import insert_verification
from kiwi_catalog.db.migrations import (
    migration_001_agent_catalog,
    migration_008_three_state_domains,
    migration_009_shadow_tables,
)
from kiwi_catalog.discovery.verifier import (
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
    DISCOVERED,
    DOMAIN_VERIFIED,
    REJECTED,
    STALE,
    UNREACHABLE,
)
from kiwi_catalog.services import verification_degradation
from kiwi_catalog.services.verification_degradation import (
    EVIDENCE_KIND_TO_LEVEL,
    FRESHNESS_ONLY_FAILURE_STATUSES,
    ProfileFailurePlan,
    highest_supported_level,
    profile_failure_plan,
)
from kiwi_catalog.services.verification_helpers import iso_from_epoch
from kiwi_catalog.services.verification_profile_policy import ProfileFailure

# Fixed "now" used across the evidence-freshness tests: 2026-08-10T12:00:00Z.
NOW_TS = datetime(2026, 8, 10, 12, 0, 0, tzinfo=UTC).timestamp()


def _iso(timestamp: float) -> str:
    return iso_from_epoch(timestamp)


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    # 三正交状态域（v0.3 §7）：_seed_agent → _insert_catalog_agent 会写
    # verification_level / freshness_state / administrative_state 列，需
    # migration_008 补齐；profile-failure facade 测试走到 _finalize →
    # append_catalog_audit，还需要 migration_009 的 audit_events 表
    # （db.session.open_connection 全量迁移的最小等价集）。
    migration_008_three_state_domains(c)
    migration_009_shadow_tables(c)
    c.commit()
    yield c
    c.close()


def _seed_agent(conn: sqlite3.Connection, level: str) -> None:
    """Insert a catalog agent whose derived verification_level is *level*.

    ``verification_status`` is passed as the legacy ladder status so
    ``_domains_for_legacy_status`` derives the matching three-domain level.
    """
    _insert_catalog_agent(
        conn,
        "cagt_x",
        merchant_id="",
        hosted_runtime_agent_id="",
        display_name="Acme",
        provider_name="Acme Inc",
        canonical_domain="acme.example",
        agent_type="merchant",
        source_type="self_registered",
        lifecycle_status="active",
        verification_status=level,
        hosting_mode="hosted",
    )
    conn.commit()


def _seed_evidence(
    conn: sqlite3.Connection,
    verification_type: str,
    *,
    result: str = "passed",
    expires_at: str = "2026-08-11T00:00:00+00:00",
) -> int:
    return insert_verification(
        conn,
        catalog_agent_id="cagt_x",
        verification_type=verification_type,
        result=result,
        evidence_json=(
            '{"verification_type":' f'"{verification_type}","result":"{result}"'
        ),
        checked_at="2026-08-09T00:00:00+00:00",
        expires_at=expires_at,
    )


# ── EVIDENCE_KIND_TO_LEVEL ──────────────────────────────────────────────────


def test_evidence_kind_to_level_ordered_highest_first() -> None:
    assert EVIDENCE_KIND_TO_LEVEL == (
        ("commerce_capability", COMMERCE_VERIFIED),
        ("agent_identity", AGENT_VERIFIED),
        ("domain_control", DOMAIN_VERIFIED),
    )


def test_freshness_only_failure_statuses_are_stale_and_unreachable() -> None:
    assert FRESHNESS_ONLY_FAILURE_STATUSES == frozenset({STALE, UNREACHABLE})
    assert REJECTED not in FRESHNESS_ONLY_FAILURE_STATUSES


# ── highest_supported_level (v0.3 §7.1 recomputation) ───────────────────────


def test_highest_supported_level_no_evidence_returns_discovered() -> None:
    assert (
        highest_supported_level(
            current_level=COMMERCE_VERIFIED,
            now_ts=NOW_TS,
            can_degrade=lambda a, b: True,
            latest_passed=lambda kind: None,
        )
        == DISCOVERED
    )


def test_highest_supported_level_same_level_evidence_keeps_level() -> None:
    """Same-level passed evidence keeps the current level — and the
    ``can_degrade`` check is never consulted for it (审查 P1-7: same-level
    evidence would otherwise be blocked by the strict-less-than gate)."""
    can_degrade_calls: list[tuple[str, str]] = []

    def can_degrade(a: str, b: str) -> bool:
        can_degrade_calls.append((a, b))
        return True

    level = highest_supported_level(
        current_level=COMMERCE_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=can_degrade,
        latest_passed=lambda kind: (
            {"expires_at": _iso(NOW_TS + 3600)}
            if kind == "commerce_capability"
            else None
        ),
    )
    assert level == COMMERCE_VERIFIED
    assert can_degrade_calls == []


def test_highest_supported_level_lower_level_evidence_unexpired() -> None:
    level = highest_supported_level(
        current_level=COMMERCE_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: True,
        latest_passed=lambda kind: (
            {"expires_at": _iso(NOW_TS + 3600)} if kind == "domain_control" else None
        ),
    )
    assert level == DOMAIN_VERIFIED


def test_highest_supported_level_expired_evidence_skipped() -> None:
    level = highest_supported_level(
        current_level=COMMERCE_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: True,
        latest_passed=lambda kind: {"expires_at": _iso(NOW_TS - 1)},
    )
    assert level == DISCOVERED


def test_highest_supported_level_at_expiry_boundary_keeps_evidence() -> None:
    """now_ts == expires_at keeps evidence: the expiry gate is strict
    less-than (``parsed < now_ts``), so a row expiring exactly at ``now`` is
    still valid — matching the original agent_verification.py behavior."""
    level = highest_supported_level(
        current_level=COMMERCE_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: True,
        latest_passed=lambda kind: {"expires_at": _iso(NOW_TS)},
    )
    assert level == COMMERCE_VERIFIED


def test_highest_supported_level_missing_expires_at_accepts_evidence() -> None:
    """A passed row with no usable ``expires_at`` still pins its level (the
    original code treats empty ``expires_at`` as never-expired)."""
    level = highest_supported_level(
        current_level=AGENT_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: True,
        latest_passed=lambda kind: (
            {"expires_at": ""} if kind == "agent_identity" else None
        ),
    )
    assert level == AGENT_VERIFIED


def test_highest_supported_level_unparseable_expires_at_treated_as_expired() -> None:
    level = highest_supported_level(
        current_level=COMMERCE_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: True,
        latest_passed=lambda kind: {"expires_at": "garbage"},
    )
    assert level == DISCOVERED


def test_highest_supported_level_can_degrade_false_skips_higher_level() -> None:
    """When the state machine forbids a degrade to a higher evidence kind, that
    kind is skipped even with fresh passed evidence."""
    level = highest_supported_level(
        current_level=DOMAIN_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: False,
        latest_passed=lambda kind: (
            {"expires_at": _iso(NOW_TS + 3600)}
            if kind == "commerce_capability"
            else None
        ),
    )
    assert level == DISCOVERED


def test_highest_supported_level_prefers_highest_passed_kind() -> None:
    """Ladder order wins: with commerce expired and both agent_identity and
    domain_control valid, the recomputation pins AGENT_VERIFIED."""
    level = highest_supported_level(
        current_level=COMMERCE_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: True,
        latest_passed=lambda kind: {
            "commerce_capability": {"expires_at": _iso(NOW_TS - 1)},
            "agent_identity": {"expires_at": _iso(NOW_TS + 3600)},
            "domain_control": {"expires_at": _iso(NOW_TS + 3600)},
        }.get(kind),
    )
    assert level == AGENT_VERIFIED


def test_highest_supported_level_honors_custom_ladder() -> None:
    level = highest_supported_level(
        current_level=COMMERCE_VERIFIED,
        now_ts=NOW_TS,
        can_degrade=lambda a, b: True,
        latest_passed=lambda kind: (
            {"expires_at": _iso(NOW_TS + 3600)} if kind == "domain_control" else None
        ),
        ladder=(("domain_control", DOMAIN_VERIFIED),),
    )
    assert level == DOMAIN_VERIFIED


# ── profile_failure_plan (v0.3 §7.2) ────────────────────────────────────────


def test_profile_failure_plan_stale_is_freshness_only() -> None:
    plan = profile_failure_plan(STALE)
    assert plan.failure_kind == STALE
    assert plan.freshness_state == STALE
    assert plan.stage_outcome == "stale"
    assert plan.recompute_level is False


def test_profile_failure_plan_unreachable_is_freshness_only() -> None:
    plan = profile_failure_plan(UNREACHABLE)
    assert plan.failure_kind == UNREACHABLE
    assert plan.freshness_state == UNREACHABLE
    assert plan.stage_outcome == "unreachable"
    assert plan.recompute_level is False


def test_profile_failure_plan_rejected_recomputes_level() -> None:
    plan = profile_failure_plan(REJECTED)
    assert plan.failure_kind == REJECTED
    assert plan.freshness_state == STALE
    assert plan.stage_outcome == "rejected"
    assert plan.recompute_level is True


def test_profile_failure_plan_unknown_status_defaults_to_rejected() -> None:
    plan = profile_failure_plan("mystery")
    assert plan.failure_kind == REJECTED
    assert plan.freshness_state == STALE
    assert plan.stage_outcome == "rejected"
    assert plan.recompute_level is True


def test_profile_failure_plan_is_frozen() -> None:
    plan = profile_failure_plan(REJECTED)
    with pytest.raises(FrozenInstanceError):
        plan.failure_kind = "x"  # type: ignore[misc]


def test_profile_failure_plan_fields_exposed_on_dataclass() -> None:
    assert set(ProfileFailurePlan.__dataclass_fields__) == {
        "failure_kind",
        "freshness_state",
        "stage_outcome",
        "recompute_level",
    }


# ── Re-export / import surface preservation ─────────────────────────────────


def test_degradation_names_reexported_from_agent_verification() -> None:
    from kiwi_catalog.services import agent_verification

    assert agent_verification._highest_supported_level is highest_supported_level
    assert agent_verification._profile_failure_plan is profile_failure_plan
    assert agent_verification._ProfileFailurePlan is ProfileFailurePlan


def test_degradation_module_exports_only_policy_surface() -> None:
    assert set(verification_degradation.__all__) == {
        "EVIDENCE_KIND_TO_LEVEL",
        "FRESHNESS_ONLY_FAILURE_STATUSES",
        "ProfileFailurePlan",
        "highest_supported_level",
        "profile_failure_plan",
    }


# ── Facade delegation: VerificationService._degrade_level_to_supported ──────


def test_facade_degrade_keeps_level_with_same_level_evidence(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn, COMMERCE_VERIFIED)
    _seed_evidence(conn, "commerce_capability", expires_at=_iso(NOW_TS + 3600))
    service = VerificationService(conn, now=lambda: NOW_TS)
    agent = require_catalog_agent(conn, "cagt_x")
    assert service._degrade_level_to_supported(agent) == COMMERCE_VERIFIED


def test_facade_degrade_falls_to_lower_level_when_evidence_expired(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn, COMMERCE_VERIFIED)
    _seed_evidence(conn, "commerce_capability", expires_at=_iso(NOW_TS - 1))
    _seed_evidence(conn, "domain_control", expires_at=_iso(NOW_TS + 3600))
    service = VerificationService(conn, now=lambda: NOW_TS)
    agent = require_catalog_agent(conn, "cagt_x")
    assert service._degrade_level_to_supported(agent) == DOMAIN_VERIFIED


def test_facade_degrade_ignores_failed_evidence(conn) -> None:
    """The recomputation only reads the latest passed row — a newer failed
    row must not shadow historical passed evidence (审查 P1-7)."""
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn, DOMAIN_VERIFIED)
    _seed_evidence(conn, "domain_control", result="failed", expires_at=_iso(NOW_TS + 3600))
    service = VerificationService(conn, now=lambda: NOW_TS)
    agent = require_catalog_agent(conn, "cagt_x")
    assert service._degrade_level_to_supported(agent) == DISCOVERED


def test_facade_degrade_accepts_evidence_without_expires_at(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn, AGENT_VERIFIED)
    _seed_evidence(conn, "agent_identity", expires_at="")
    service = VerificationService(conn, now=lambda: NOW_TS)
    agent = require_catalog_agent(conn, "cagt_x")
    assert service._degrade_level_to_supported(agent) == AGENT_VERIFIED


def test_facade_degrade_from_level_overrides_db_level(conn) -> None:
    """verify() re-entry clears the DB level, so from_level supplies the run's
    original level as the recomputation baseline (审查 P1-7)."""
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn, DISCOVERED)
    _seed_evidence(conn, "domain_control", expires_at=_iso(NOW_TS + 3600))
    service = VerificationService(conn, now=lambda: NOW_TS)
    agent = require_catalog_agent(conn, "cagt_x")
    assert (
        service._degrade_level_to_supported(agent, from_level=COMMERCE_VERIFIED)
        == DOMAIN_VERIFIED
    )


# ── Facade delegation: VerificationService._handle_profile_failure ──────────


def test_facade_profile_failure_stale_is_freshness_only(conn) -> None:
    """STALE fetch failure keeps the level and only rewrites freshness."""
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn, COMMERCE_VERIFIED)
    service = VerificationService(conn, now=lambda: NOW_TS)
    result = service._handle_profile_failure(
        "cagt_x",
        "commerce_verified",
        ProfileFailure(STALE, "profile fetch failed"),
        "verification_worker",
        [],
    )
    row = require_catalog_agent(conn, "cagt_x")
    assert row["verification_level"] == COMMERCE_VERIFIED
    assert row["freshness_state"] == STALE
    assert result.status == STALE
    assert result.stages[0].stage == "profile"
    assert result.stages[0].outcome == "stale"
    assert result.stages[0].reason == "profile fetch failed"


def test_facade_profile_failure_rejected_recomputes_level(conn) -> None:
    """REJECTED (evidence-invalid) recomputes the level from remaining
    evidence and marks freshness STALE so the next /verify re-verifies."""
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn, COMMERCE_VERIFIED)
    _seed_evidence(conn, "domain_control", expires_at=_iso(NOW_TS + 3600))
    service = VerificationService(conn, now=lambda: NOW_TS)
    result = service._handle_profile_failure(
        "cagt_x",
        "commerce_verified",
        ProfileFailure(REJECTED, "profile validation failed: boom"),
        "verification_worker",
        [],
    )
    row = require_catalog_agent(conn, "cagt_x")
    assert row["verification_level"] == DOMAIN_VERIFIED
    assert row["freshness_state"] == STALE
    assert result.status == STALE
    assert result.stages[0].outcome == "rejected"
    assert result.stages[0].reason == "profile validation failed: boom"
