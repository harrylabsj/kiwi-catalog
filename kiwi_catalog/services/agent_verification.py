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

"""Verification pipeline service — orchestrates the §6 verification ladder.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §6, §6.1, §6.2, §23, §25 Phase 2

This is the SERVICE layer of the verification pipeline (module layout §20:
``services/agent_verification.py``).  The PURE core lives in
``discovery/verifier.py`` — state machine, HTTPS domain control, and trust
evaluation — and performs no persistence.  This module performs the
orchestration that pure core deliberately forbids:

* fetch profiles through the SSRF-safe ``ProfileFetcher`` (W1);
* parse/validate through ``AgentCardParser`` / ``UcpProfileParser`` (W2);
* persist ``agent_profile_snapshots`` (§5.5) and per-check evidence in
  ``agent_verifications`` (§5.6) with the catalog repository;
* drive ``catalog_agents.verification_status`` through the §6 state machine,
  rejecting illegal jumps with ``InvalidStateTransitionError``;
* write §23 audit events (``catalog_agent_verified`` /
  ``catalog_agent_verification_failed`` / ``catalog_agent_refreshed`` /
  ``catalog_agent_stale``) without any secret/private profile data;
* enforce the §5.1 publish-state invariant at COMMERCE_VERIFIED.

Secret policy (§17.3): the parsers are constructed with ``reject_on_secret``
so a profile that contains secret-like fields is rejected outright.  The
snapshot ``raw_json`` therefore only ever stores the *raw public projection*
(§5.5 "原始公开 profile snapshot") and never carries credentials or private
auth metadata.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import (
    append_catalog_audit,
    insert_profile_snapshot,
    insert_verification,
    latest_profile_snapshot,
    latest_verification,
    list_endpoints,
    replace_capabilities,
    replace_skills,
    require_catalog_agent,
    set_state_domains,
    upsert_profile_endpoints,
)
from kiwi_catalog.agent_catalog.state_domains import (
    ACTIVE,
    FRESH,
    AdministrativeStateMachine,
    FreshnessStateMachine,
    VerificationLevelStateMachine,
)
from kiwi_catalog.core.errors import (
    ConflictError,
    ValidationError,
)
from kiwi_catalog.db.session import (
    encode_json,
    now_iso,
    open_connection,
)
from kiwi_catalog.discovery._validation import (
    ProfileValidationError,
    canonical_domain_of,
    is_http_url,
    is_same_authority,
)
from kiwi_catalog.discovery.agent_card import AgentCardParser, AgentCardResult
from kiwi_catalog.discovery.cache import compute_content_hash
from kiwi_catalog.discovery.fetcher import (
    FetchError,
    FetchLimitError,
    ProfileFetcher,
    SSRFBlockError,
)
from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.discovery.ucp import UcpProfileParser, UcpProfileResult
from kiwi_catalog.discovery.verifier import (
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
    DISCOVERED,
    DOMAIN_VERIFIED,
    PROFILE_VALID,
    REJECTED,
    STALE,
    SUSPENDED,
    UNREACHABLE,
    IdentityVerifier,
    InvalidStateTransitionError,
    TrustEvaluator,
    VerificationEvidence,
    VerificationStateMachine,
)
from kiwi_catalog.services.agent_catalog import _validate_hosting_invariant
from kiwi_catalog.services.catalog_runtime_metrics import record_funnel
from kiwi_catalog.services.domain_bindings import (
    CHALLENGE_REQUIRED_SOURCE_TYPES,
    CHALLENGE_ROTATION_REQUIRED,
    binding_legacy_allowed,
    challenge_is_current,
    ensure_domain_binding,
    get_domain_binding,
    mark_domain_bound,
    shared_domain_peer_count,
)
from kiwi_catalog.services.verification_audit_policy import (
    FunnelStep as _FunnelStep,
)
from kiwi_catalog.services.verification_audit_policy import (
    finalize_audit_plan as _finalize_audit_plan,
)
from kiwi_catalog.services.verification_degradation import (
    ProfileFailurePlan as _ProfileFailurePlan,
)
from kiwi_catalog.services.verification_degradation import (
    highest_supported_level as _highest_supported_level,
)
from kiwi_catalog.services.verification_degradation import (
    profile_failure_plan as _profile_failure_plan,
)
from kiwi_catalog.services.verification_helpers import iso_from_epoch as _iso_from_epoch
from kiwi_catalog.services.verification_helpers import (
    outcome_for as _outcome_for,  # noqa: F401 —— facade re-export
)
from kiwi_catalog.services.verification_profile_index import (
    ProfileIndex as _ProfileIndex,
)
from kiwi_catalog.services.verification_profile_index import (
    build_profile_index as _build_profile_index,
)
from kiwi_catalog.services.verification_profile_policy import (
    LADDER_RUNGS as _LADDER_RUNGS,
)
from kiwi_catalog.services.verification_profile_policy import (
    VERIFIED_RUNGS as _VERIFIED_RUNGS,  # noqa: F401 —— facade re-export
)
from kiwi_catalog.services.verification_profile_policy import (
    ProfileFailure as _ProfileFailure,
)
from kiwi_catalog.services.verification_profile_policy import (
    Profiles as _Profiles,
)
from kiwi_catalog.services.verification_profile_policy import (
    ReusedSnapshotFetch as _ReusedSnapshotFetch,
)
from kiwi_catalog.services.verification_profile_policy import (
    parse_iso_ts as _parse_iso_ts,  # noqa: F401 —— facade re-export
)
from kiwi_catalog.services.verification_profile_policy import (
    profile_is_stale as _profile_is_stale,
)
from kiwi_catalog.services.verification_queue import (
    VerificationQueue,
    VerificationQueueConfig,
    VerificationQueueFullError,
    VerificationQueueLedgerError as VerificationQueueLedgerError,
    VerificationQueueOutcomeUnknownError,
    VerificationQueueShutdownError,
    VerificationTask,
    VerificationTaskResult,
    reconcile_verification_unknown,
)
from kiwi_catalog.services.verification_stages import (
    StageResult,
    VerificationResult,
)
from kiwi_catalog.services.verification_stages import (
    evidence_payload as _evidence_payload,
)
from kiwi_catalog.services.verification_stages import (
    failed_evidence as _failed_evidence,
)


def _has_active_binding(conn: sqlite3.Connection, catalog_agent_id: str, now_ts: str) -> bool:
    """D5 判定：该 agent 是否有**未过期**的活动运行时绑定（云商家）。"""
    row = conn.execute(
        "select expires_at from runtime_bindings"
        " where catalog_agent_id = ? and status = 'active'"
        " order by binding_version desc limit 1",
        (catalog_agent_id,),
    ).fetchone()
    if row is None:
        return False
    expires_at = str(row["expires_at"] or "")
    if not expires_at:
        return True
    # 审查 P3：裸字符串比较在 "Z" vs "+00:00" 表示下会 fail-open（'Z' 排序
    # 大于 '+'）。按绝对时刻解析；无法解析视为未过期（fail-closed 方向：
    # 无法证明已过期 → 仍按活动绑定处理，避免把已绑定商家错误降级）。
    try:
        from datetime import datetime as _dt

        return _dt.fromisoformat(expires_at) > _dt.fromisoformat(now_ts)
    except (TypeError, ValueError):
        return True


class VerificationService:
    """Runs the §6 verification ladder against a single catalog agent.

    The service is bound to one ``sqlite3.Connection``.  For the bounded
    in-process queue, each task opens its own connection (see
    :func:`make_verification_worker`), so a service instance is never shared
    across threads.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        fetcher: ProfileFetcher | None = None,
        policy: TrustPolicy | None = None,
        agent_card_parser: AgentCardParser | None = None,
        ucp_parser: UcpProfileParser | None = None,
        identity_verifier: IdentityVerifier | None = None,
        trust_evaluator: TrustEvaluator | None = None,
        state_machine: VerificationStateMachine | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._conn = conn
        self._policy = policy or TrustPolicy.defaults()
        self._fetcher = fetcher or ProfileFetcher(self._policy)
        # §17.3: profiles with secret-like fields are rejected, never persisted.
        self._card_parser = agent_card_parser or AgentCardParser(self._policy, reject_on_secret=True)
        self._ucp_parser = ucp_parser or UcpProfileParser(self._policy, reject_on_secret=True)
        self._identity_verifier = identity_verifier or IdentityVerifier(self._fetcher, self._policy)
        self._trust_evaluator = trust_evaluator or TrustEvaluator(self._policy)
        self._state_machine = state_machine or VerificationStateMachine()
        # v0.3 §7 三正交状态域状态机（legacy VerificationStateMachine 保留
        # 供 granular 入口校验；域迁移统一走以下三台）。
        self._level_machine = VerificationLevelStateMachine()
        self._freshness_machine = FreshnessStateMachine()
        self._admin_machine = AdministrativeStateMachine()
        self._now = now or time.time

    # ── Public ladder entry points ─────────────────────────────────────────

    def verify(
        self,
        catalog_agent_id: str,
        *,
        actor: str = "verification_worker",
        reason: str = "explicit",
        force: bool = False,
    ) -> VerificationResult:
        """Run the full §6 ladder for *catalog_agent_id*（v0.3 §7 三域语义）。

        * 行政处置（REJECTED / SUSPENDED）阻止自动管线（fail-closed）；
        * freshness FRESH + 已在阶梯上 → 除非 ``force`` 原样返回；
        * freshness STALE / UNREACHABLE → 重验证，级别从 DISCOVERED 重入
          （与 legacy「STALE → 阶梯重入」语义一致）；
        * profile 抓取失败只动 freshness（保留最后已验证快照，v0.3 §13#14）；
        * SSRF / 校验 / 缺端点失败 → 证据失效，按证据重算降级级别（§7.1）。
        """
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        previous = agent["verification_status"]
        level = agent["verification_level"]
        # 审查 P1-7：重入前保留原级别，作为本 run 证据重算降级的基准——
        # 级别被清空后 _degrade_level_to_supported 以 DISCOVERED 为基准，
        # can_degrade 全拦截，任何阶段瞬时失败都会把已验证级别打到
        # DISCOVERED（§7.1「按最新未过期证据重算」在主链路上失效）。
        original_level = level
        freshness = agent["freshness_state"]
        admin = agent["administrative_state"]

        # §7.3：REJECTED / SUSPENDED 没有自动出向迁移。终态 agent 的重验证
        # 是调用方错误（fail-closed，任何 fetch 副作用之前）。
        if admin != ACTIVE:
            raise InvalidStateTransitionError(
                f"catalog agent {catalog_agent_id} is not administratively active "
                f"(administrative_state={admin!r}); it must be reinstated or re-registered"
            )

        stale_profile_audit = False
        # Freshness gate: only re-verify on-demand when the profile is stale,
        # unless the caller explicitly forces a full re-verification.
        if freshness == FRESH and level in _LADDER_RUNGS:
            binding = (
                get_domain_binding(self._conn, catalog_agent_id)
                if agent["source_type"] in CHALLENGE_REQUIRED_SOURCE_TYPES else None
            )
            challenge_expired = (
                binding is not None
                and not binding_legacy_allowed(binding, str(agent["canonical_domain"] or ""))
                and not challenge_is_current(binding, now=now_iso())
            )
            if not force and not challenge_expired:
                return VerificationResult(catalog_agent_id, previous, previous, ())
            stale_profile_audit = self._is_stale(catalog_agent_id)
        # D5：有活动绑定的云商家跳过域所有权阶梯（不抓卡、不做同源判定）——
        # 信任证据 = 绑定声明（确认时写入的 passed 证据行支撑级别）。
        skipped = self._skip_ladder_for_cloud_binding(
            agent, catalog_agent_id, previous, actor, reason
        )
        if skipped is not None:
            return skipped
        stages: list[StageResult] = []
        try:
            profiles = self._load_profiles(catalog_agent_id)
        except _ProfileFailure as exc:
            if stale_profile_audit:
                self._write_audit(catalog_agent_id, actor, "catalog_agent_stale",
                    {"reason": "profile freshness window expired", "actor_reason": reason})
            return self._handle_profile_failure(catalog_agent_id, previous, exc, actor, stages)

        # Acquire all domain network evidence before reopening a write transaction.
        domain_evidence = self._domain_control_evidence(catalog_agent_id, profiles, expected_agent=agent)
        self._begin_verified_persistence(agent, profiles)
        if stale_profile_audit:
            self._write_audit(catalog_agent_id, actor, "catalog_agent_stale",
                {"reason": "profile freshness window expired", "actor_reason": reason})

        # 抓取成功后才重入阶梯（legacy STALE → 阶梯重入语义一致）。放在抓取
        # 之后：_handle_profile_failure 按设计"只动 freshness、保留最后已验证
        # 级别"，级别若在抓取前被清掉，一次网络抖动就丢失已验证级别。
        if level != DISCOVERED:
            self._apply_level(agent, DISCOVERED)
            level = DISCOVERED

        # 新快照已落盘 → freshness 复位 FRESH（v0.3 §7.2）。
        self._apply_freshness(agent, FRESH)

        profile_target = self._level_machine.transition(level, PROFILE_VALID)
        self._apply_level(agent, profile_target)
        stages.append(
            StageResult("profile", "passed", profile_target, snapshot_ids=profiles.snapshot_ids)
        )

        domain_stage = self._stage_domain(
            catalog_agent_id, profile_target, actor, profiles, from_level=original_level,
            evidence=domain_evidence,
        )
        stages.append(domain_stage)
        if domain_stage.outcome != "passed":
            return self._finalize(
                catalog_agent_id, previous, domain_stage.target_status, stages, actor, domain_stage.outcome
            )

        identity_stage = self._stage_identity(
            catalog_agent_id, domain_stage.target_status, actor, profiles, from_level=original_level
        )
        stages.append(identity_stage)
        if identity_stage.outcome != "passed":
            return self._finalize(
                catalog_agent_id, previous, identity_stage.target_status, stages, actor, identity_stage.outcome
            )

        commerce_stage = self._stage_commerce(
            catalog_agent_id, identity_stage.target_status, actor, profiles, from_level=original_level
        )
        stages.append(commerce_stage)
        failure_kind = None if commerce_stage.outcome == "passed" else commerce_stage.outcome
        return self._finalize(
            catalog_agent_id, previous, commerce_stage.target_status, stages, actor, failure_kind
        )

    def refresh(self, catalog_agent_id: str, *, actor: str = "verification_worker") -> VerificationResult:
        """Re-fetch profiles (conditional GET) and re-run the full ladder.

        This is the explicit-refresh entry point the §25 Phase 2 queue drives.
        """
        return self.verify(catalog_agent_id, actor=actor, reason="refresh", force=True)

    def mark_stale(self, catalog_agent_id: str, *, actor: str = "verification_worker") -> VerificationResult:
        """新鲜度过期：freshness FRESH → STALE（级别不变，v0.3 §7.2）。"""
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        current = agent["verification_status"]
        freshness = agent["freshness_state"]
        if freshness == STALE:
            return VerificationResult(catalog_agent_id, current, current, ())
        target_state = self._freshness_machine.transition(freshness, STALE)
        self._apply_freshness(agent, target_state)
        target = require_catalog_agent(self._conn, catalog_agent_id)["verification_status"]
        self._write_audit(catalog_agent_id, actor, "catalog_agent_stale", {"reason": "profile freshness window expired"})
        return VerificationResult(
            catalog_agent_id,
            current,
            target,
            (StageResult("staleness", "stale", target, reason="profile freshness window expired"),),
        )

    def suspend(self, catalog_agent_id: str, *, actor: str = "admin", reason: str = "") -> VerificationResult:
        """Suspend a catalog agent（行政处置，v0.3 §7.3）。

        Idempotent: an already-suspended agent returns unchanged.  The
        suspension reason is recorded in the §23 audit event.  verification_level
        与 freshness 均保留——恢复后按证据继续（三域正交）。

        治理联动（v0.4 DoD #12 两件事都做）：owned ACTIVE Listings →
        SUSPENDED 与 agent suspend 同事务原子提交（search join 排除半边在
        listings/search.py）。联动在此统一实现——HTTP admin 路径、CLI
        `agent catalog suspend`、队列 suspend 任务共用 service，单点生效。
        """
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        current = agent["verification_status"]
        admin = agent["administrative_state"]
        if admin == SUSPENDED:
            return VerificationResult(catalog_agent_id, current, current, ())
        target_state = self._admin_machine.transition(admin, SUSPENDED)
        self._apply_admin(agent, target_state)
        # Governance changes invalidate every unconsumed enrollment. A worker
        # retry cannot resurrect a suspended/rejected agent after reinstatement.
        self._conn.execute(
            "update enrollments set status='canceled', authorization_epoch=authorization_epoch+1 "
            "where catalog_agent_id=? and status in ('ready_for_authorization','authorized','bound','published')",
            (catalog_agent_id,),
        )
        target = require_catalog_agent(self._conn, catalog_agent_id)["verification_status"]
        self._write_audit(
            catalog_agent_id,
            actor,
            "catalog_agent_suspended",
            {"reason": reason or "operator suspension"},
        )
        self._suspend_owned_listings(catalog_agent_id, actor)
        return VerificationResult(
            catalog_agent_id, current, target, (StageResult("suspend", "suspended", target),)
        )

    def _suspend_owned_listings(self, catalog_agent_id: str, actor: str) -> None:
        """DoD #12 标记半边：owned ACTIVE Listings → SUSPENDED（幂等）。

        已 SUSPENDED/WITHDRAWN 的不再触碰；受影响行数 > 0 时落
        listings_suspended 审计。与 agent suspend 同一事务（本连接未提交
        前不返回——调用方随后 commit 原子提交）。
        """
        from kiwi_catalog.listings.policy import suspend_owned_listings

        count = suspend_owned_listings(self._conn, catalog_agent_id)
        if count:
            self._write_audit(
                catalog_agent_id,
                actor,
                "listings_suspended",
                {"count": count},
            )

    def reinstate(self, catalog_agent_id: str, *, actor: str = "admin", reason: str = "") -> VerificationResult:
        """Reinstate a suspended catalog agent（行政处置，v0.3 §7.3）。

        SUSPENDED → ACTIVE；verification_level 与 freshness **保留**（legacy
        重置为 DISCOVERED 的行为被三域模型取代——证据未失效，级别不应丢失，
        折叠投影在恢复后回到原级别）。

        Fail-closed: agents not in SUSPENDED raise
        InvalidStateTransitionError (reinstate is a SUSPENDED-only action).
        """
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        current = agent["verification_status"]
        admin = agent["administrative_state"]
        if admin != SUSPENDED:
            raise InvalidStateTransitionError(
                f"reinstate requires SUSPENDED administrative state, got {admin!r}"
            )
        target_state = self._admin_machine.transition(admin, ACTIVE)
        self._apply_admin(agent, target_state)
        target = require_catalog_agent(self._conn, catalog_agent_id)["verification_status"]
        self._write_audit(
            catalog_agent_id,
            actor,
            "catalog_agent_reinstated",
            {"reason": reason or "operator reinstate", "previous_status": current},
        )
        return VerificationResult(
            catalog_agent_id, current, target, (StageResult("reinstate", "reinstated", target),)
        )

    # ── Granular stage entry points ────────────────────────────────────────
    # Each advances exactly one rung and rejects illegal jumps.  They exist so
    # callers (and tests) can drive a single stage, or demonstrate that a jump
    # such as DISCOVERED -> COMMERCE_VERIFIED raises InvalidStateTransitionError.

    def _granular_profile_failure(
        self,
        catalog_agent_id: str,
        previous: str,
        exc: _ProfileFailure,
        actor: str,
    ) -> VerificationResult:
        """granular 入口共用的 _ProfileFailure 分流（与 verify() 同语义）。"""
        stages: list[StageResult] = []
        return self._handle_profile_failure(catalog_agent_id, previous, exc, actor, stages)

    def verify_profile(self, catalog_agent_id: str, *, actor: str = "verification_worker") -> VerificationResult:
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        previous = agent["verification_status"]
        # D5：有活动绑定的云商家跳过阶梯（不抓卡、不降级，停在 commerce_verified）
        skipped = self._skip_ladder_for_cloud_binding(
            agent, catalog_agent_id, previous, actor, "granular"
        )
        if skipped is not None:
            return skipped
        current = agent["verification_level"]
        self._level_machine.transition(current, PROFILE_VALID)  # raises on illegal jump
        try:
            profiles = self._load_profiles(catalog_agent_id)
        except _ProfileFailure as exc:
            return self._granular_profile_failure(catalog_agent_id, previous, exc, actor)
        self._apply_freshness(agent, FRESH)
        target = self._level_machine.transition(current, PROFILE_VALID)
        self._apply_level(agent, target)
        stage = StageResult("profile", "passed", target, snapshot_ids=profiles.snapshot_ids)
        return self._finalize(catalog_agent_id, previous, target, (stage,), actor, None)

    def verify_domain_control(self, catalog_agent_id: str, *, actor: str = "verification_worker") -> VerificationResult:
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        previous = agent["verification_status"]
        current = agent["verification_level"]
        self._level_machine.transition(current, DOMAIN_VERIFIED)  # raises on illegal jump
        try:
            profiles = self._load_profiles(catalog_agent_id)
        except _ProfileFailure as exc:
            return self._granular_profile_failure(catalog_agent_id, previous, exc, actor)
        domain_evidence = self._domain_control_evidence(catalog_agent_id, profiles, expected_agent=agent)
        self._begin_verified_persistence(agent, profiles)
        self._apply_freshness(agent, FRESH)
        stage = self._stage_domain(catalog_agent_id, current, actor, profiles, evidence=domain_evidence)
        failure_kind = None if stage.outcome == "passed" else stage.outcome
        return self._finalize(catalog_agent_id, previous, stage.target_status, (stage,), actor, failure_kind)

    def verify_agent_identity(self, catalog_agent_id: str, *, actor: str = "verification_worker") -> VerificationResult:
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        previous = agent["verification_status"]
        current = agent["verification_level"]
        self._level_machine.transition(current, AGENT_VERIFIED)  # raises on illegal jump
        try:
            profiles = self._load_profiles(catalog_agent_id)
        except _ProfileFailure as exc:
            return self._granular_profile_failure(catalog_agent_id, previous, exc, actor)
        self._apply_freshness(agent, FRESH)
        stage = self._stage_identity(catalog_agent_id, current, actor, profiles)
        # 审查 C-5：granular 身份/商务入口在 domain 已通过的前提下刷新索引
        # （profile-only 入口仍不索引，保持 P1-12 的域控制门）。
        if stage.outcome == "passed":
            self._index_profiles(catalog_agent_id, profiles.card, profiles.ucp, profiles.urls)
        failure_kind = None if stage.outcome == "passed" else stage.outcome
        return self._finalize(catalog_agent_id, previous, stage.target_status, (stage,), actor, failure_kind)

    def verify_commerce(self, catalog_agent_id: str, *, actor: str = "verification_worker") -> VerificationResult:
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        previous = agent["verification_status"]
        current = agent["verification_level"]
        self._level_machine.transition(current, COMMERCE_VERIFIED)  # raises on illegal jump
        try:
            profiles = self._load_profiles(catalog_agent_id)
        except _ProfileFailure as exc:
            return self._granular_profile_failure(catalog_agent_id, previous, exc, actor)
        self._apply_freshness(agent, FRESH)
        stage = self._stage_commerce(catalog_agent_id, current, actor, profiles)
        if stage.outcome == "passed":
            self._index_profiles(catalog_agent_id, profiles.card, profiles.ucp, profiles.urls)
        failure_kind = None if stage.outcome == "passed" else stage.outcome
        return self._finalize(catalog_agent_id, previous, stage.target_status, (stage,), actor, failure_kind)

    # ── D5：云商家阶梯短路 ─────────────────────────────────────────────────

    def _skip_ladder_for_cloud_binding(
        self,
        agent: dict[str, Any],
        catalog_agent_id: str,
        previous: str,
        actor: str,
        reason: str,
    ) -> VerificationResult | None:
        """D5：有活动绑定的云商家跳过域所有权阶梯（不抓卡、不做同源判定）。

        域所有权语义在云路径下不适用（卡片托管在 catalog 域、canonical_domain
        是运行时域），硬跑阶梯必然 REJECTED 并触发证据重算降级——把商家从
        commerce_verified 打回 DISCOVERED；而且那条路径会让 catalog 去抓
        **自己**的公开读地址，无谓消耗匿名读预算。信任证据 = 绑定声明：
        绑定确认时写入的两条 passed 证据行（agent_identity /
        commerce_capability）支撑级别，任何一次重算都停在 commerce_verified，
        reducer 无特例。返回 None 表示无活动绑定（走正常阶梯）。
        """
        if not _has_active_binding(self._conn, catalog_agent_id, self._now_iso()):
            return None
        self._apply_freshness(agent, FRESH)
        self._apply_level(agent, COMMERCE_VERIFIED, last_verified_at=self._now_iso())
        self._write_audit(
            catalog_agent_id,
            actor,
            "catalog_agent_verification_skipped",
            {"reason": "skipped: cloud binding", "actor_reason": reason},
        )
        status = require_catalog_agent(self._conn, catalog_agent_id)["verification_status"]
        return VerificationResult(catalog_agent_id, previous, status, ())

    # ── Profile stage ──────────────────────────────────────────────────────

    def _load_profiles(self, catalog_agent_id: str) -> _Profiles:
        """Fetch, validate, and persist both discovery profiles (§5.5, §17.2).

        Raises:
            _ProfileFailure: the semantic terminal status and a safe reason
                when the profile stage cannot complete.
        """
        if self._conn.in_transaction:
            raise ValidationError("network verification requires an idle caller connection; caller transaction preserved")
        endpoints = list_endpoints(self._conn, catalog_agent_id)
        urls = {ep["kind"]: ep["url"] for ep in endpoints if ep["kind"] in ("agent_card", "ucp_profile")}
        if set(urls) != {"agent_card", "ucp_profile"}:
            raise _ProfileFailure(REJECTED, "missing agent_card or ucp_profile endpoints")
        # 审查 P1-01：verification 要求 canonical domain / authority 一致——
        # 抓取与索引之前强制 agent_card/ucp_profile 端点落在 agent 存储的
        # canonical_domain（或其子域）下。否则残留旧域名端点会让管线抓取并
        # 索引旧域名 profile（capabilities/skills/endpoints 被旧域名数据重写，
        # 正是换域名后禁止残留的数据）。
        stored_domain = str(
            require_catalog_agent(self._conn, catalog_agent_id).get("canonical_domain") or ""
        ).strip()
        if not stored_domain:
            raise _ProfileFailure(
                REJECTED,
                "catalog agent has no canonical_domain; profile endpoints cannot be validated",
            )
        for kind, url in urls.items():
            if not is_http_url(url) or not is_same_authority(canonical_domain_of(url), stored_domain):
                raise _ProfileFailure(
                    REJECTED,
                    f"{kind} endpoint '{url}' is not under canonical domain '{stored_domain}'",
                )

        fetched: dict[str, Any] = {}
        for kind in ("agent_card", "ucp_profile"):
            url = urls[kind]
            # 审查 P2：快照存储键是 "ucp"（_write_snapshot / _is_stale 同规），
            # 查询曾用 "ucp_profile" 恒查不到 → etag/last_modified 恒 None，
            # ucp 的 304/ETag 缓存语义永不生效（每次都全量下载 + 新快照落库）。
            snapshot_kind = "ucp" if kind == "ucp_profile" else kind
            latest = latest_profile_snapshot(self._conn, catalog_agent_id, snapshot_kind)
            etag = (latest or {}).get("etag") or None
            last_modified = (latest or {}).get("last_modified") or None
            try:
                result = self._fetcher.fetch(url, etag=etag, last_modified=last_modified)
            except SSRFBlockError as exc:
                raise _ProfileFailure(REJECTED, f"profile fetch blocked by SSRF policy: {exc}") from exc
            except FetchLimitError as exc:
                raise _ProfileFailure(REJECTED, f"profile fetch exceeded limits: {exc}") from exc
            except FetchError as exc:
                if latest is not None:
                    raise _ProfileFailure(
                        STALE, f"profile fetch failed; stale snapshot retained: {exc}"
                    ) from exc
                raise _ProfileFailure(UNREACHABLE, f"profile fetch failed: {exc}") from exc
            if not result.is_success:
                raise _ProfileFailure(UNREACHABLE, f"{kind} returned HTTP {result.status_code}")
            # 304 Not Modified：内容未变，复用最新快照的 raw JSON 恢复 parsed
            # （§18 缓存语义）。此前 parse(None) 抛 ProfileValidationError，任何
            # 未变化的 profile 在重验证时 profile 阶段必失败、阶梯无法推进。
            if result.is_not_modified:
                if latest is None or not latest.get("raw_json"):
                    raise _ProfileFailure(
                        REJECTED, f"{kind} returned 304 but no prior snapshot exists"
                    )
                fetched[kind] = _ReusedSnapshotFetch(result, latest["raw_json"])
            else:
                fetched[kind] = result

        # §17.2: schema → semantic → authority → secret quarantine.
        try:
            card = self._card_parser.parse(fetched["agent_card"].parsed, source_url=urls["agent_card"])
            ucp = self._ucp_parser.parse(fetched["ucp_profile"].parsed, source_url=urls["ucp_profile"])
        except ProfileValidationError as exc:
            raise _ProfileFailure(REJECTED, f"profile validation failed: {exc}") from exc

        snapshot_ids = (
            self._write_snapshot(catalog_agent_id, "agent_card", card, fetched["agent_card"]),
            self._write_snapshot(catalog_agent_id, "ucp", ucp, fetched["ucp_profile"]),
        )
        # 审查 P2（P1-12 延伸）：profile 索引（capabilities/skills/endpoints）
        # 不得在 domain-control 通过前公开——攻击者把行指向受害者 profile 时
        # 仍在 profile 阶段就能把对方能力发布到自己名下。索引改到
        # `_stage_domain` 通过后进行。
        # 审查 P1-5：快照落库后立即提交，关闭写事务——后续 domain 阶段的
        # well-known 抓取（10s 级网络 I/O）不再持有 SQLite 写锁，否则期间全体
        # 并发写入者会在 busy_timeout（5s）后抛 database is locked → 500。
        # 阶梯其余阶段各以短事务写入。幂等 claim 行已在 handler 层持久化，
        # 失败路径的 clear 仍独立生效。
        self._conn.commit()
        return _Profiles(card=card, ucp=ucp, urls=urls, snapshot_ids=snapshot_ids)

    def _write_snapshot(
        self,
        catalog_agent_id: str,
        profile_type: str,
        parsed: AgentCardResult | UcpProfileResult,
        fetch: Any,
    ) -> int:
        """Persist one ``agent_profile_snapshots`` row (§5.5, §18).

        ``raw_json`` stores the raw *public* projection (§5.5 "原始公开 profile
        snapshot") — secret-bearing regions were already rejected/quarantined
        by the parser, so no credentials are ever persisted (§17.3).
        """
        raw_json = encode_json(parsed.public)
        content_hash = compute_content_hash(raw_json)
        fetched_at = _iso_from_epoch(fetch.fetched_at)
        fresh_until = _iso_from_epoch(fetch.compute_fresh_until(self._policy.profile_max_age_seconds))
        return insert_profile_snapshot(
            self._conn,
            catalog_agent_id=catalog_agent_id,
            profile_type=profile_type,
            source_url=fetch.url or parsed.source_url,
            etag=fetch.etag or "",
            last_modified=fetch.last_modified or "",
            content_hash=content_hash,
            raw_json=raw_json,
            fetched_at=fetched_at,
            fresh_until=fresh_until,
            validation_status="valid",
        )

    def _index_profiles(
        self,
        catalog_agent_id: str,
        card: AgentCardResult,
        ucp: UcpProfileResult,
        urls: dict[str, str],
    ) -> None:
        """Index public profile metadata (§5.3, §5.4, §5.2).

        The pure §5.3/§5.4/§5.2 row shaping lives in the side-effect-free
        :func:`verification_profile_index.build_profile_index` leaf; this
        method only executes the three persistence calls in their original
        order, preserving the merged content/order/duplicates, protocol
        versions and preference values.
        """
        index: _ProfileIndex = _build_profile_index(card, ucp, urls)
        replace_capabilities(self._conn, catalog_agent_id, index.capabilities)
        replace_skills(self._conn, catalog_agent_id, index.skills)
        upsert_profile_endpoints(self._conn, catalog_agent_id, index.endpoints)

    # ── Domain / identity / commerce stages ────────────────────────────────

    def _begin_verified_persistence(self, expected_agent: dict[str, Any], profiles: _Profiles) -> None:
        """Take the write lock only after I/O; never commit a caller's transaction."""
        if self._conn.in_transaction:
            raise ValidationError("verification persistence requires an idle caller connection")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = require_catalog_agent(self._conn, str(expected_agent["catalog_agent_id"]))
            binding_fields = (
                "canonical_domain", "merchant_id", "hosted_runtime_agent_id",
                "source_type", "hosting_mode", "lifecycle_status", "administrative_state",
            )
            current_urls = {
                ep["kind"]: ep["url"] for ep in list_endpoints(self._conn, str(expected_agent["catalog_agent_id"]))
                if ep["kind"] in ("agent_card", "ucp_profile")
            }
            if (current["administrative_state"] != ACTIVE
                    or any(current.get(key) != expected_agent.get(key) for key in binding_fields)
                    or current_urls != profiles.urls):
                raise ConflictError("catalog agent identity, administration or endpoints changed during verification")
        except BaseException as exc:
            try:
                self._conn.rollback()
            except sqlite3.Error as rollback_error:
                exc.add_note(f"owned verification rollback failed: {type(rollback_error).__name__}")
            raise

    def _domain_control_evidence(
        self, catalog_agent_id: str, profiles: _Profiles,
        *, expected_agent: dict[str, Any] | None = None,
    ) -> VerificationEvidence:
        """Acquire evidence for the captured subject, never a later live domain."""
        agent = expected_agent if expected_agent is not None else require_catalog_agent(self._conn, catalog_agent_id)
        stored_domain = str(agent.get("canonical_domain") or "").strip()
        if stored_domain and any(
            not is_http_url(url) or not is_same_authority(canonical_domain_of(url), stored_domain)
            for url in profiles.urls.values()
        ):
            raise ConflictError("profile endpoints changed away from the captured verification domain")
        if not stored_domain:
            return _failed_evidence("domain_control",
                "catalog agent has no canonical_domain; domain control cannot be verified",
                {"method": "https_domain_control", "domain_control_method": self._policy.domain_control_method,
                 "canonical_domain": stored_domain})
        # 审查 P1-12：domain-control 必须回指本 catalog_agent 行。绑定行在
        # 网络 I/O 之前落盘并提交，抓取窗口不持有 SQLite 写锁（与 P1-5 同口径）。
        source_type = str(agent.get("source_type") or "")
        challenge_required = source_type in CHALLENGE_REQUIRED_SOURCE_TYPES
        binding = ensure_domain_binding(
            self._conn, catalog_agent_id, stored_domain, now=now_iso()
        )
        self._conn.commit()
        allow_unbound = (not challenge_required) or binding_legacy_allowed(binding, stored_domain)
        unbound_reason = "legacy" if binding_legacy_allowed(binding, stored_domain) else "source_trusted"
        if not allow_unbound and not challenge_is_current(binding, now=now_iso()):
            return _failed_evidence("domain_control", CHALLENGE_ROTATION_REQUIRED,
                                    {"canonical_domain": stored_domain, "domain_binding": "expired"})
        challenge = str(binding.get("challenge") or "")
        evidence = self._identity_verifier.verify_domain_control(
            stored_domain,
            declared={"agent_card": profiles.urls["agent_card"], "ucp_profile": profiles.urls["ucp_profile"]},
            expected_catalog_agent_id=catalog_agent_id,
            challenge=challenge,
            allow_unbound=allow_unbound,
            unbound_reason=unbound_reason,
        )
        if evidence.passed and challenge_required and not allow_unbound:
            marked = mark_domain_bound(
                self._conn, catalog_agent_id, stored_domain, challenge=challenge, now=now_iso()
            )
            self._conn.commit()
            if not marked:
                raise ConflictError("domain-control challenge changed or expired during verification")
        peers = shared_domain_peer_count(self._conn, catalog_agent_id, stored_domain)
        if peers:
            evidence = replace(
                evidence, details={**evidence.details, "shared_domain_agents": peers}
            )
        return evidence

    def _stage_domain(
        self,
        catalog_agent_id: str,
        current: str,
        actor: str,
        profiles: _Profiles,
        *,
        from_level: str | None = None,
        evidence: VerificationEvidence | None = None,
    ) -> StageResult:
        """HTTPS domain-control (§6 MVP identity mechanism；v0.3 级别语义）。

        审查 P1-01：domain-control 必须对 agent **存储的** canonical_domain
        验证，而不是 profile 自己声明的域名——``profiles.card.canonical_domain``
        源自抓取 URL，换域名后残留旧端点会让验证对旧域名成功。declare URL
        落在存储域名之外 → 验证失败（fail-closed）。无 canonical_domain 的
        agent 无法证明域名控制（rejected）。
        """
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        evidence = evidence if evidence is not None else self._domain_control_evidence(catalog_agent_id, profiles)
        if evidence.passed:
            # 审查 P2：只有域控制通过后才把 profile 派生能力/技能/端点公开。
            self._index_profiles(catalog_agent_id, profiles.card, profiles.ucp, profiles.urls)
            target = self._level_machine.transition(current, DOMAIN_VERIFIED)
            self._apply_level(agent, target)
            outcome = "passed"
        else:
            # 证据失效 → 按证据重算降级（v0.3 §7.1；不是行政 REJECTED）。
            # from_level：完整 verify() 传入 run 开始时的原级别（审查 P1-7）。
            target = self._degrade_level_to_supported(agent, from_level=from_level)
            self._apply_level(agent, target)
            outcome = "rejected"
        vid = self._persist_verification(catalog_agent_id, evidence, target)
        return StageResult(
            "domain_control", outcome, target, reason=evidence.reason, verification_id=vid, evidence=_evidence_payload(evidence, self._policy)
        )

    def _stage_identity(
        self,
        catalog_agent_id: str,
        current: str,
        actor: str,
        profiles: _Profiles,
        *,
        from_level: str | None = None,
    ) -> StageResult:
        """Agent identity threshold (§6 AGENT_VERIFIED；v0.3 级别语义）。

        审查 P1-01：身份绑定以 agent **存储的** canonical_domain 为准——
        否则卡片/ucp 的 identity URL 会绑定到 profile 自称的域名（换域名后
        残留旧 profile 时绑定旧域名）。空存储域名回退到 profile 声明的域名
        （granular 入口兼容），主链路在 domain 阶段已 fail-closed。
        """
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        stored_domain = str(agent.get("canonical_domain") or "").strip()
        evidence = self._trust_evaluator.evaluate_agent_identity(
            profiles.card, profiles.ucp, stored_domain or profiles.card.canonical_domain
        )
        if evidence.passed:
            target = self._level_machine.transition(current, AGENT_VERIFIED)
            self._apply_level(agent, target)
            outcome = "passed"
        else:
            # 审查 P1-7：同 _stage_domain，降级基准 = run 原级别。
            target = self._degrade_level_to_supported(agent, from_level=from_level)
            self._apply_level(agent, target)
            outcome = "rejected"
        vid = self._persist_verification(catalog_agent_id, evidence, target)
        return StageResult(
            "agent_identity", outcome, target, reason=evidence.reason, verification_id=vid, evidence=_evidence_payload(evidence, self._policy)
        )

    def _stage_commerce(
        self,
        catalog_agent_id: str,
        current: str,
        actor: str,
        profiles: _Profiles,
        *,
        from_level: str | None = None,
    ) -> StageResult:
        """Commerce capability intersection + §5.1 publish-state invariant."""
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        stored_domain = str(agent.get("canonical_domain") or "").strip()
        evidence = self._trust_evaluator.evaluate_commerce_capabilities(
            profiles.card, profiles.ucp, stored_domain or profiles.card.canonical_domain
        )
        if not evidence.passed:
            # 审查 P1-7：同 _stage_domain，降级基准 = run 原级别。
            target = self._degrade_level_to_supported(agent, from_level=from_level)
            self._apply_level(agent, target)
            vid = self._persist_verification(catalog_agent_id, evidence, target)
            return StageResult(
                "commerce_capability", "rejected", target, reason=evidence.reason,
                verification_id=vid, evidence=_evidence_payload(evidence, self._policy),
            )

        # §5.1: the publish-state invariant gates the final COMMERCE_VERIFIED
        # transition.  A violation means the record cannot be published.
        try:
            _validate_hosting_invariant(
                agent["source_type"],
                COMMERCE_VERIFIED,
                agent["hosted_runtime_agent_id"] or "",
            )
        except ValidationError as exc:
            target = self._degrade_level_to_supported(agent, from_level=from_level)
            self._apply_level(agent, target)
            failed_evidence = _failed_evidence(
                evidence.verification_type,
                f"§5.1 publish invariant failed: {exc}",
                dict(evidence.details),
            )
            vid = self._persist_verification(catalog_agent_id, failed_evidence, target)
            return StageResult(
                "commerce_capability", "rejected", target, reason=failed_evidence.reason,
                verification_id=vid, evidence=_evidence_payload(failed_evidence, self._policy),
            )

        target = self._level_machine.transition(current, COMMERCE_VERIFIED)
        self._apply_level(agent, target, last_verified_at=self._now_iso())
        vid = self._persist_verification(catalog_agent_id, evidence, target)
        return StageResult(
            "commerce_capability", "passed", target, verification_id=vid, evidence=_evidence_payload(evidence, self._policy)
        )

    # ── Persistence helpers ────────────────────────────────────────────────

    def _persist_verification(self, catalog_agent_id: str, evidence: VerificationEvidence, target: str) -> int:
        """Write one ``agent_verifications`` row (§5.6), pinning §6.1 policy version."""
        payload = _evidence_payload(evidence, self._policy)
        checked_at = self._now_iso()
        expires_at = _iso_from_epoch(self._now() + evidence.expires_in_seconds)
        return insert_verification(
            self._conn,
            catalog_agent_id=catalog_agent_id,
            verification_type=evidence.verification_type,
            result=evidence.result,
            evidence_json=encode_json(payload),
            checked_at=checked_at,
            expires_at=expires_at,
        )

    def _apply_level(self, agent: dict[str, Any], level: str, *, last_verified_at: str | None = None) -> None:
        set_state_domains(
            self._conn,
            str(agent["catalog_agent_id"]),
            verification_level=level,
            last_verified_at=last_verified_at,
        )

    def _apply_freshness(self, agent: dict[str, Any], state: str) -> None:
        set_state_domains(self._conn, str(agent["catalog_agent_id"]), freshness_state=state)

    def _apply_admin(self, agent: dict[str, Any], state: str) -> None:
        set_state_domains(self._conn, str(agent["catalog_agent_id"]), administrative_state=state)

    def _handle_profile_failure(
        self,
        catalog_agent_id: str,
        previous: str,
        exc: _ProfileFailure,
        actor: str,
        stages: Sequence[StageResult],
    ) -> VerificationResult:
        """_ProfileFailure 分流（verify() 与 granular 入口共用）。

        * target ∈ {STALE, UNREACHABLE}（抓取失败）→ 只动 freshness，
          保留最后已验证快照与级别（v0.3 §13#14）；
        * target == REJECTED（SSRF / 校验 / 缺端点）→ 证据失效，按证据
          重算降级 verification_level（v0.3 §7.1）。

        The §7.2 handling plan is decided by the pure
        :func:`verification_degradation.profile_failure_plan` leaf; this
        method only drives the persistence it prescribes.
        """
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        plan: _ProfileFailurePlan = _profile_failure_plan(exc.target_status)
        if plan.recompute_level:
            # 审查 P3：REJECTED（证据失效）后 freshness 置 STALE——否则 freshness
            # 仍 FRESH + 级别在阶梯上时，/verify（永不 force）被 freshness 门短路
            # 成 no-op，agent 只能靠 /refresh 恢复；置 STALE 让下次 verify 真正
            # 重验证（与「抓取失败只动 freshness」的 STALE/UNREACHABLE 分支一致）。
            degraded = self._degrade_level_to_supported(agent)
            self._apply_level(agent, degraded)
        self._apply_freshness(agent, plan.freshness_state)
        target = require_catalog_agent(self._conn, catalog_agent_id)["verification_status"]
        stages = [*stages, StageResult("profile", plan.stage_outcome, target, reason=exc.reason)]
        return self._finalize(catalog_agent_id, previous, target, stages, actor, plan.failure_kind)

    def _degrade_level_to_supported(
        self, agent: dict[str, Any], *, from_level: str | None = None
    ) -> str:
        """v0.3 §7.1：按最新未过期证据重算「最高仍支持的较低级别」。

        检查基准级以下各级对应的证据类型（domain_control / agent_identity /
        commerce_capability）；最新一条 **passed** 且未过期 → 该级；否则
        DISCOVERED。历史证据保持可审计，降级不删除既有观察。

        审查 P1-7：
        - from_level 显式指定降级基准（完整 verify() 重入清级后，DB 级已被
          清零——基准必须是 run 开始时的原级别，否则 can_degrade 全拦截）；
          granular 入口不传 → 以 DB 当前级为基准（行为不变）。
        - 证据只认最新 passed 行（failed 行不得屏蔽历史 passed 证据）。

        The decision itself lives in the pure
        :func:`verification_degradation.highest_supported_level` leaf; this
        method supplies the DB evidence lookup and the state-machine
        ``can_degrade`` check.
        """
        agent_id = str(agent["catalog_agent_id"])
        return _highest_supported_level(
            current_level=from_level or str(agent["verification_level"]),
            now_ts=self._now(),
            can_degrade=self._level_machine.can_degrade,
            latest_passed=lambda kind: latest_verification(
                self._conn, agent_id, kind, result="passed"
            ),
        )

    def _finalize(
        self,
        catalog_agent_id: str,
        previous: str,
        status: str,
        stages: Sequence[StageResult],
        actor: str,
        failure_kind: str | None,
    ) -> VerificationResult:
        """Write the §23 audit events for a completed pipeline run.

        The pure decision — which events, their details, the §24 funnel, and
        the empty-stages fallback — lives in the side-effect-free
        :func:`verification_audit_policy.finalize_audit_plan` leaf.  This
        method only executes the plan's steps in order (``append_catalog_audit``
        then ``record_funnel``), preserving the pre-extraction event order,
        details fields, pinned ``trust_policy_version`` and public-data-only
        §17.3 boundary.
        """
        plan = _finalize_audit_plan(
            status=status,
            stages=stages,
            policy_version=self._policy.policy_version,
            failure_kind=failure_kind,
        )
        for step in plan.steps:
            if isinstance(step, _FunnelStep):
                record_funnel(step.stage)
            else:
                self._write_audit(catalog_agent_id, actor, step.event, step.details)
        return VerificationResult(catalog_agent_id, previous, status, tuple(stages))

    def _write_audit(self, catalog_agent_id: str, actor: str, event: str, details: dict[str, Any]) -> None:
        append_catalog_audit(self._conn, catalog_agent_id, actor, event, details)

    # ── Staleness ──────────────────────────────────────────────────────────

    def _is_stale(self, catalog_agent_id: str) -> bool:
        """True when the latest profile snapshot has passed its fresh_until."""
        fresh_untils: list[str] = []
        for kind in ("agent_card", "ucp"):
            snapshot = latest_profile_snapshot(self._conn, catalog_agent_id, kind)
            # on the ladder with no snapshot → needs re-verification (§7.2).
            fresh_untils.append(
                str(snapshot.get("fresh_until") or "") if snapshot is not None else ""
            )
        return _profile_is_stale(fresh_untils, self._now())

    def _now_iso(self) -> str:
        return _iso_from_epoch(self._now())

    def commit(self) -> None:
        """Flush all pending writes to the database connection.

        A queue-owned connection is opened with the default SQLite isolation
        level (no autocommit), so nothing is durable until ``commit`` runs.
        The bounded queue calls this after a successful task so a persistence
        failure surfaces as ``status == "failed"`` instead of being silently
        rolled back on ``close``.
        """
        self._conn.commit()

    def close(self, commit: bool = True) -> None:
        """Commit pending writes and close the underlying connection.

        The bounded verification queue creates one service (and therefore one
        connection) per task through the service factory, then calls ``close``
        when the task finishes so connections are never leaked across threads.

        ``commit`` runs here as a safety net for callers that finish a
        transaction simply by closing the service; the queue itself commits
        explicitly after each task so it can report a persistence failure.

        ``commit=False`` 用于 cancelled/runaway 路径（审查 P2-N）：timeout
        已返回后线程仍在跑的写必须随连接关闭回滚——此前 finally 无条件
        close()，close 内部先 commit，timeout 响应后 catalog 状态仍被推进
        （调用方按「timeout=未执行」重试会与仍在跑的 runaway 写交叠）。
        """
        try:
            if commit:
                self._conn.commit()
        finally:
            self._conn.close()


def make_verification_worker(
    db_path: str | Path,
    *,
    policy: TrustPolicy | None = None,
    config: VerificationQueueConfig | None = None,
) -> VerificationQueue:
    """Create a bounded in-process verification queue bound to *db_path*.

    This is the §25 Phase 2 execution model: each queued task opens its own
    ``sqlite3.Connection`` and runs a fresh :class:`VerificationService`, so no
    connection is ever shared across threads.  The returned queue is ready to
    use — call :meth:`VerificationQueue.enqueue` to drive verification.
    """
    def _service_factory() -> VerificationService:
        conn = open_connection(db_path)
        return VerificationService(conn, policy=policy)

    return VerificationQueue(service_factory=_service_factory, config=config, db_path=db_path)


__all__ = [
    "AGENT_VERIFIED",
    "COMMERCE_VERIFIED",
    "DISCOVERED",
    "DOMAIN_VERIFIED",
    "PROFILE_VALID",
    "REJECTED",
    "STALE",
    "SUSPENDED",
    "UNREACHABLE",
    "InvalidStateTransitionError",
    "StageResult",
    "VerificationQueue",
    "VerificationQueueConfig",
    "VerificationQueueOutcomeUnknownError",
    "VerificationQueueFullError",
    "VerificationQueueShutdownError",
    "VerificationResult",
    "VerificationService",
    "VerificationTask",
    "VerificationTaskResult",
    "make_verification_worker",
    "reconcile_verification_unknown",
]
