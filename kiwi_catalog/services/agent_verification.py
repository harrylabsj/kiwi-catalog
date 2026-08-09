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

import itertools
import json
import queue
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
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
from kiwi_catalog.core.errors import ShoppingCliError, ValidationError
from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION
from kiwi_catalog.db.session import SQLITE_BUSY_TIMEOUT_MS, encode_json, now_iso
from kiwi_catalog.discovery._validation import ProfileValidationError
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
from kiwi_catalog.services.catalog_runtime_metrics import record_funnel, set_queue_depth
from kiwi_catalog.services.verification_helpers import iso_from_epoch as _iso_from_epoch
from kiwi_catalog.services.verification_helpers import outcome_for as _outcome_for

# The ladder rungs that carry a persisted profile (anything above DISCOVERED).
_LADDER_RUNGS: frozenset[str] = frozenset(
    {PROFILE_VALID, DOMAIN_VERIFIED, AGENT_VERIFIED, COMMERCE_VERIFIED}
)

# Rungs that count as "verified" for the §24 funnel (domain-control proof §6).
_VERIFIED_RUNGS: frozenset[str] = frozenset(
    {DOMAIN_VERIFIED, AGENT_VERIFIED, COMMERCE_VERIFIED}
)


@dataclass(frozen=True)
class StageResult:
    """Outcome of one verification stage in the §6 ladder."""

    stage: str
    """Stage identifier: ``profile``, ``domain_control``, ``agent_identity``,
    ``commerce_capability``, ``staleness``, ``suspend``."""

    outcome: str
    """``passed``, ``rejected``, ``unreachable``, or ``stale``."""

    target_status: str
    """The ``verification_status`` this stage persisted."""

    reason: str = ""
    """Human-readable failure reason (only set when not passed)."""

    verification_id: int | None = None
    """Row id of the ``agent_verifications`` evidence written for this stage."""

    snapshot_ids: tuple[int, ...] = ()
    """Row ids of ``agent_profile_snapshots`` written by the profile stage."""

    evidence: dict[str, Any] | None = None
    """The evidence payload written to ``agent_verifications`` (no secrets)."""


@dataclass(frozen=True)
class VerificationResult:
    """Full result of a verification pipeline run."""

    catalog_agent_id: str
    previous_status: str
    status: str
    stages: tuple[StageResult, ...]


class _ProfileFailure(Exception):
    """Raised internally when the profile stage cannot complete.

    Carries the semantic target status (§6: rejected / unreachable / stale)
    so the caller can apply the correct terminal transition.
    """

    def __init__(self, target_status: str, reason: str) -> None:
        super().__init__(reason)
        self.target_status = target_status
        self.reason = reason


@dataclass
class _Profiles:
    """Validated profile pair shared across the ladder stages."""

    card: AgentCardResult
    ucp: UcpProfileResult
    urls: dict[str, str]
    snapshot_ids: tuple[int, ...]


class _ReusedSnapshotFetch:
    """304 Not Modified 的包装：从存储的 raw_json 恢复 parsed（§18 缓存语义）。

    形状对齐 FetchResult 的消费字段（parsed/url/etag/last_modified/etag 等），
    使下游 parse/快照逻辑无需区分 200 与 304。
    """

    def __init__(self, fetch: Any, raw_json: str) -> None:
        self.url = fetch.url
        self.status_code = fetch.status_code
        self.etag = fetch.etag
        self.last_modified = fetch.last_modified
        self.cache_control = fetch.cache_control
        self.max_age = fetch.max_age
        self.fetched_at = fetch.fetched_at
        try:
            self.parsed = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise _ProfileFailure(
                REJECTED, f"stored snapshot raw_json is not valid JSON: {exc}"
            ) from exc

    @property
    def is_not_modified(self) -> bool:
        return True

    @property
    def is_success(self) -> bool:
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

        # Freshness gate: only re-verify on-demand when the profile is stale,
        # unless the caller explicitly forces a full re-verification.
        if freshness == FRESH and level in _LADDER_RUNGS:
            if not force:
                return VerificationResult(catalog_agent_id, previous, previous, ())
            if self._is_stale(catalog_agent_id):
                self._write_audit(
                    catalog_agent_id,
                    actor,
                    "catalog_agent_stale",
                    {"reason": "profile freshness window expired", "actor_reason": reason},
                )
        stages: list[StageResult] = []
        try:
            profiles = self._load_profiles(catalog_agent_id)
        except _ProfileFailure as exc:
            return self._handle_profile_failure(catalog_agent_id, previous, exc, actor, stages)

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
            catalog_agent_id, profile_target, actor, profiles, from_level=original_level
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
        self._apply_freshness(agent, FRESH)
        stage = self._stage_domain(catalog_agent_id, current, actor, profiles)
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
        failure_kind = None if stage.outcome == "passed" else stage.outcome
        return self._finalize(catalog_agent_id, previous, stage.target_status, (stage,), actor, failure_kind)

    # ── Profile stage ──────────────────────────────────────────────────────

    def _load_profiles(self, catalog_agent_id: str) -> _Profiles:
        """Fetch, validate, and persist both discovery profiles (§5.5, §17.2).

        Raises:
            _ProfileFailure: the semantic terminal status and a safe reason
                when the profile stage cannot complete.
        """
        endpoints = list_endpoints(self._conn, catalog_agent_id)
        urls = {ep["kind"]: ep["url"] for ep in endpoints if ep["kind"] in ("agent_card", "ucp_profile")}
        if set(urls) != {"agent_card", "ucp_profile"}:
            raise _ProfileFailure(REJECTED, "missing agent_card or ucp_profile endpoints")

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
        self._index_profiles(catalog_agent_id, card, ucp, urls)
        # 审查 P1-5：快照/索引落库后立即提交，关闭写事务——后续 domain 阶段的
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
        """Index public profile metadata (§5.3, §5.4, §5.2)."""
        capabilities = list(card.capabilities) + list(ucp.capabilities)
        skills = list(card.skills) + list(ucp.skills)
        replace_capabilities(self._conn, catalog_agent_id, capabilities)
        replace_skills(self._conn, catalog_agent_id, skills)
        upsert_profile_endpoints(
            self._conn,
            catalog_agent_id,
            [
                {
                    "kind": "agent_card",
                    "url": urls["agent_card"],
                    "protocol": "a2a",
                    "protocol_version": card.version,
                    "preference": 1,
                },
                {
                    "kind": "ucp_profile",
                    "url": urls["ucp_profile"],
                    "protocol": "ucp",
                    "protocol_version": ucp.specification_version,
                    "preference": 1,
                },
            ],
        )

    # ── Domain / identity / commerce stages ────────────────────────────────

    def _stage_domain(
        self,
        catalog_agent_id: str,
        current: str,
        actor: str,
        profiles: _Profiles,
        *,
        from_level: str | None = None,
    ) -> StageResult:
        """HTTPS domain-control (§6 MVP identity mechanism；v0.3 级别语义）。"""
        canonical_domain = profiles.card.canonical_domain
        declared = {
            "agent_card": profiles.urls["agent_card"],
            "ucp_profile": profiles.urls["ucp_profile"],
        }
        evidence = self._identity_verifier.verify_domain_control(canonical_domain, declared=declared)
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        if evidence.passed:
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
        """Agent identity threshold (§6 AGENT_VERIFIED；v0.3 级别语义）。"""
        evidence = self._trust_evaluator.evaluate_agent_identity(
            profiles.card, profiles.ucp, profiles.card.canonical_domain
        )
        agent = require_catalog_agent(self._conn, catalog_agent_id)
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
        evidence = self._trust_evaluator.evaluate_commerce_capabilities(
            profiles.card, profiles.ucp, profiles.card.canonical_domain
        )
        agent = require_catalog_agent(self._conn, catalog_agent_id)
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
        """
        agent = require_catalog_agent(self._conn, catalog_agent_id)
        if exc.target_status in (STALE, UNREACHABLE):
            self._apply_freshness(agent, exc.target_status)
            target = require_catalog_agent(self._conn, catalog_agent_id)["verification_status"]
            stages = [*stages, StageResult("profile", _outcome_for(exc.target_status), target, reason=exc.reason)]
            return self._finalize(catalog_agent_id, previous, target, stages, actor, exc.target_status)
        degraded = self._degrade_level_to_supported(agent)
        self._apply_level(agent, degraded)
        # 审查 P3：REJECTED（证据失效）后 freshness 置 STALE——否则 freshness
        # 仍 FRESH + 级别在阶梯上时，/verify（永不 force）被 freshness 门短路
        # 成 no-op，agent 只能靠 /refresh 恢复；置 STALE 让下次 verify 真正
        # 重验证（与「抓取失败只动 freshness」的 STALE/UNREACHABLE 分支一致）。
        self._apply_freshness(agent, STALE)
        target = require_catalog_agent(self._conn, catalog_agent_id)["verification_status"]
        stages = [*stages, StageResult("profile", "rejected", target, reason=exc.reason)]
        return self._finalize(catalog_agent_id, previous, target, stages, actor, REJECTED)

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
        """
        agent_id = str(agent["catalog_agent_id"])
        current = from_level or agent["verification_level"]
        now_ts = self._now()
        for kind, level in (
            ("commerce_capability", COMMERCE_VERIFIED),
            ("agent_identity", AGENT_VERIFIED),
            ("domain_control", DOMAIN_VERIFIED),
        ):
            # 允许「严格更低」+「同级」：passed 证据支撑当前级时应保持同级
            # （审查 P1-7——can_degrade 是严格小于，同级证据会被拦成 DISCOVERED）。
            if level != current and not self._level_machine.can_degrade(current, level):
                continue
            row = latest_verification(self._conn, agent_id, kind, result="passed")
            if row is None:
                continue
            expires_at = str(row.get("expires_at") or "")
            if expires_at:
                parsed = self._parse_iso_ts(expires_at)
                if parsed is None or parsed < now_ts:
                    continue
            return level
        return DISCOVERED

    def _finalize(
        self,
        catalog_agent_id: str,
        previous: str,
        status: str,
        stages: Sequence[StageResult],
        actor: str,
        failure_kind: str | None,
    ) -> VerificationResult:
        """Write the §23 audit events for a completed pipeline run."""
        # The profile stage wrote snapshots → the run refreshed the profile cache.
        if stages and stages[0].stage == "profile" and stages[0].snapshot_ids:
            self._write_audit(
                catalog_agent_id,
                actor,
                "catalog_agent_refreshed",
                {
                    "verification_status": status,
                    "stage_count": len(stages),
                    "trust_policy_version": self._policy.policy_version,
                },
            )

        if failure_kind is None:
            # §24 funnel: a run reaching any verified rung counts as verified.
            if status in _VERIFIED_RUNGS:
                record_funnel("verified")
            if status == COMMERCE_VERIFIED:
                self._write_audit(
                    catalog_agent_id,
                    actor,
                    "catalog_agent_verified",
                    {
                        "verification_status": status,
                        "trust_policy_version": self._policy.policy_version,
                    },
                )
        else:
            last_stage = stages[-1] if stages else StageResult("verification", failure_kind, status)
            self._write_audit(
                catalog_agent_id,
                actor,
                "catalog_agent_verification_failed",
                {
                    "failed_stage": last_stage.stage,
                    "reason": last_stage.reason,
                    "target_status": status,
                    "trust_policy_version": self._policy.policy_version,
                },
            )
            if failure_kind == STALE:
                self._write_audit(
                    catalog_agent_id,
                    actor,
                    "catalog_agent_stale",
                    {"reason": last_stage.reason},
                )

        return VerificationResult(catalog_agent_id, previous, status, tuple(stages))

    def _write_audit(self, catalog_agent_id: str, actor: str, event: str, details: dict[str, Any]) -> None:
        append_catalog_audit(self._conn, catalog_agent_id, actor, event, details)

    # ── Staleness ──────────────────────────────────────────────────────────

    def _is_stale(self, catalog_agent_id: str) -> bool:
        """True when the latest profile snapshot has passed its fresh_until."""
        now_ts = self._now()
        for kind in ("agent_card", "ucp"):
            snapshot = latest_profile_snapshot(self._conn, catalog_agent_id, kind)
            if snapshot is None:
                return True  # on the ladder with no snapshot → needs re-verification
            fresh_until_ts = self._parse_iso_ts(str(snapshot.get("fresh_until") or ""))
            if fresh_until_ts is None or now_ts >= fresh_until_ts:
                return True
        return False

    @staticmethod
    def _parse_iso_ts(value: str) -> float | None:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

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

    def close(self) -> None:
        """Commit pending writes and close the underlying connection.

        The bounded verification queue creates one service (and therefore one
        connection) per task through the service factory, then calls ``close``
        when the task finishes so connections are never leaked across threads.

        ``commit`` runs here as a safety net for callers that finish a
        transaction simply by closing the service; the queue itself commits
        explicitly after each task so it can report a persistence failure.
        """
        try:
            self._conn.commit()
        finally:
            self._conn.close()


def _evidence_payload(evidence: VerificationEvidence, policy: TrustPolicy) -> dict[str, Any]:
    """The §5.6 evidence payload — always pins the §6.1 trust_policy_version."""
    return {
        "verification_type": evidence.verification_type,
        "result": evidence.result,
        "reason": evidence.reason,
        "trust_policy_version": policy.policy_version,
        "details": dict(evidence.details),
    }


def _failed_evidence(verification_type: str, reason: str, details: dict[str, Any]) -> VerificationEvidence:
    from kiwi_catalog.discovery.verifier import VerificationEvidence as _VE

    return _VE(
        verification_type=verification_type,
        result="failed",
        reason=reason,
        details=dict(details),
    )


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
# sub-thread so a hung task is reported as a timeout (per-task deadline) and
# cannot stall the pipeline.  Every task opens its own database connection
# through the injected *service_factory* — a ``VerificationService`` instance
# is never shared across threads (see the service class docstring above).


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


def _serialize_verification_result(result: VerificationResult | None) -> str:
    """Serialize a VerificationResult for the v15 queue ledger (result_json)."""
    if result is None:
        return "{}"
    return encode_json(
        {
            "catalog_agent_id": result.catalog_agent_id,
            "previous_status": result.previous_status,
            "status": result.status,
            "stages": [
                {
                    "stage": stage.stage,
                    "outcome": stage.outcome,
                    "target_status": stage.target_status,
                    "reason": stage.reason,
                    "verification_id": stage.verification_id,
                    "snapshot_ids": list(stage.snapshot_ids),
                    "evidence": stage.evidence,
                }
                for stage in result.stages
            ],
        }
    )


def _deserialize_verification_result(raw: str) -> VerificationResult | None:
    """Rebuild a VerificationResult from ledger result_json (or None)."""
    if not raw or raw == "{}":
        return None
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return VerificationResult(
        catalog_agent_id=str(payload.get("catalog_agent_id", "")),
        previous_status=str(payload.get("previous_status", "")),
        status=str(payload.get("status", "")),
        stages=tuple(
            StageResult(
                stage=str(s.get("stage", "")),
                outcome=str(s.get("outcome", "")),
                target_status=str(s.get("target_status", "")),
                reason=str(s.get("reason", "") or ""),
                verification_id=s.get("verification_id"),
                snapshot_ids=tuple(int(x) for x in (s.get("snapshot_ids") or [])),
                evidence=s.get("evidence"),
            )
            for s in (payload.get("stages") or [])
        ),
    )


class VerificationQueueFullError(ShoppingCliError):
    """Raised when the bounded queue is at capacity (fail-closed)."""


class VerificationQueueShutdownError(ShoppingCliError):
    """Raised when enqueueing after :meth:`VerificationQueue.shutdown`."""


class VerificationQueueLedgerError(ShoppingCliError):
    """Raised when the persistent ledger write fails at enqueue time.

    审查 P2：enqueue 的 ledger 写失败必须抛类型化错误（而不是裸 sqlite3
    异常冒泡）——调用方据此知道任务未入队、可安全重试。
    """


class VerificationQueue:
    """Bounded in-process verification queue (§25 Phase 2, v3.0-P4).

    Usage::

        queue = make_verification_worker(db_path, config=VerificationQueueConfig(max_pending=50, concurrency=2))
        outcome = queue.enqueue("cagt_123", wait=True)
        # outcome.status == "completed" | "failed" | "timeout"

    The queue is thread-safe and schedules tasks in a bounded in-process
    ``queue.Queue``; ``concurrency`` worker threads form the concurrency
    budget.  With ``db_path`` set (the production path via
    :func:`make_verification_worker`) every task is written through to the
    ``verification_queue_tasks`` ledger (schema v15) so tasks survive a
    process restart: ``pending`` / ``running`` rows are recovered into a new
    queue instance on startup (verification tasks are idempotent — refresh /
    verify / mark_stale / suspend are safe to re-run), and ``wait()`` can
    rebuild outcomes from the ledger.  Without ``db_path`` the queue is
    purely in-memory (tests / embedded use).  Call :meth:`shutdown` (or use
    it as a context manager) to stop the worker threads.
    """

    _KINDS = frozenset({"verify", "refresh", "mark_stale", "suspend"})

    def __init__(
        self,
        *,
        service_factory: Callable[[], "VerificationService"],
        config: VerificationQueueConfig | None = None,
        now: Callable[[], float] | None = None,
        db_path: str | Path | None = None,
    ) -> None:
        self._config = config or VerificationQueueConfig()
        self._service_factory = service_factory
        self._now = now or time.time
        self._db_path = Path(db_path) if db_path else None
        self._results_cv = threading.Condition()

        # Persistence ledger (v15).  All ledger access happens under
        # _results_cv — a single queue thread touches it at a time plus the
        # worker threads, which is exactly the sqlite3 serialization model.
        self._db_conn: sqlite3.Connection | None = None
        if self._db_path is not None:
            self._db_conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._db_conn.row_factory = sqlite3.Row  # ledger rows are column-accessed
            # 与 open_connection 的 5s busy timeout 对齐（否则并发写等待行为不一致，
            # 多 worker 部署下 SQLITE_BUSY 概率性失败）。
            self._db_conn.execute(f"pragma busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            # 审查 P3：裸连接不跑迁移——未迁移库会在 _recover_pending_tasks 的
            # SELECT 上 no such table 崩。fail-closed 给出明确诊断（应用内路径
            # 先经 db.session.open_connection 迁移，只有 CLI/嵌入直用才踩中）。
            version_row = self._db_conn.execute("pragma user_version").fetchone()
            ledger_version = int(version_row[0] or 0) if version_row is not None else 0
            if ledger_version < CURRENT_SCHEMA_VERSION:
                raise RuntimeError(
                    f"verification queue requires schema v{CURRENT_SCHEMA_VERSION}, "
                    f"found v{ledger_version}; open the database through "
                    f"kiwi_catalog.db.session.open_connection first (it runs migrations)"
                )

        self._results: dict[str, VerificationTaskResult] = {}
        self._tasks: dict[str, VerificationTask] = {}
        self._shutdown = threading.Event()
        # 审查 P3：enqueue（检查+put）与 shutdown（置位+放哨兵）互斥锁
        self._enqueue_lock = threading.Lock()

        # Crash recovery: pending/running rows from a previous process are
        # re-enqueued so no task is lost across a restart.  Recovered count
        # may exceed max_pending — the bound exists to stop runaway
        # enqueueing, not to drop recovered work, so the queue is sized to
        # fit both.
        recovered = self._recover_pending_tasks()
        self._pending: queue.Queue[VerificationTask | None] = queue.Queue(
            maxsize=max(self._config.max_pending, recovered + 1)
        )
        for task in self._recovered_tasks:
            self._pending.put(task)
        self._id_seq = itertools.count(1)
        self._workers: list[threading.Thread] = []
        for i in range(self._config.concurrency):
            worker = threading.Thread(
                target=self._worker_loop,
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
        """Re-enqueue pending/running ledger rows from a previous process.

        Returns the number of recovered tasks (they land in
        ``self._recovered_tasks``).  Running rows are re-run too — every task
        kind (verify / refresh / mark_stale / suspend) is idempotent, so a
        crash mid-task leaves no duplicate side effects.  Terminal rows
        (completed / failed / timeout) are left as an audit trail.
        """
        self._recovered_tasks: list[VerificationTask] = []
        if self._db_conn is None:
            return 0
        with self._results_cv:
            rows = self._db_conn.execute(
                "select task_id, catalog_agent_id, kind, actor, enqueued_at"
                " from verification_queue_tasks where status in ('pending','running')"
                " order by enqueued_at"
            ).fetchall()
            for row in rows:
                task = VerificationTask(
                    catalog_agent_id=str(row["catalog_agent_id"]),
                    task_id=str(row["task_id"]),
                    kind=str(row["kind"]),
                    actor=str(row["actor"]),
                    enqueued_at=float(row["enqueued_at"]),
                )
                self._tasks[task.task_id] = task
                self._recovered_tasks.append(task)
        return len(self._recovered_tasks)

    def _persist_insert(self, task: VerificationTask) -> None:
        """Insert one pending task into the ledger (fail-closed on error)."""
        if self._db_conn is None:
            return
        with self._results_cv:
            self._db_conn.execute(
                "insert into verification_queue_tasks("
                " task_id, catalog_agent_id, kind, actor, status, enqueued_at,"
                " created_at, updated_at)"
                " values (?, ?, ?, ?, 'pending', ?, ?, ?)",
                (
                    task.task_id,
                    task.catalog_agent_id,
                    task.kind,
                    task.actor,
                    task.enqueued_at,
                    now_iso(),
                    now_iso(),
                ),
            )
            self._db_conn.commit()

    def _persist_delete(self, task_id: str) -> None:
        """Roll back a ledger insert (e.g. when the memory queue is full)."""
        if self._db_conn is None:
            return
        with self._results_cv:
            self._db_conn.execute(
                "delete from verification_queue_tasks where task_id = ?", (task_id,)
            )
            self._db_conn.commit()

    def _persist_running(self, task_id: str, started_at: float) -> None:
        """Mark a task as running in the ledger."""
        if self._db_conn is None:
            return
        with self._results_cv:
            self._db_conn.execute(
                "update verification_queue_tasks"
                " set status = 'running', started_at = ?, updated_at = ?"
                " where task_id = ?",
                (started_at, now_iso(), task_id),
            )
            self._db_conn.commit()

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
        with self._results_cv:
            self._db_conn.execute(
                "update verification_queue_tasks"
                " set status = ?, verification_status = ?, error = ?,"
                " result_json = ?, finished_at = ?, updated_at = ?"
                " where task_id = ? and status = 'running'",
                (
                    status,
                    verification_status,
                    error,
                    _serialize_verification_result(result),
                    self._now(),
                    now_iso(),
                    task_id,
                ),
            )
            # 审查 P2：惰性清理终态行（键空间此前只增不删；finished_at 是
            # epoch REAL，与 _now() 同单位）
            self._finish_count = getattr(self, "_finish_count", 0) + 1
            if self._finish_count % 256 == 0:
                try:
                    self._db_conn.execute(
                        "delete from verification_queue_tasks"
                        " where status in ('completed','failed','timeout')"
                        " and finished_at < ?",
                        (self._now() - 7 * 86400,),
                    )
                except sqlite3.Error:
                    pass  # 清理失败不影响任务结果写
            self._db_conn.commit()

    def _ledger_result(self, task_id: str) -> VerificationTaskResult | None:
        """Rebuild a finished result from the ledger (restart path for wait())."""
        if self._db_conn is None:
            return None
        row = self._db_conn.execute(
            "select * from verification_queue_tasks where task_id = ?", (task_id,)
        ).fetchone()
        if row is None or row["status"] in ("pending", "running"):
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
        if self._shutdown.is_set():
            raise VerificationQueueShutdownError("verification queue is shut down")
        if kind not in self._KINDS:
            raise ValueError(f"unknown verification task kind: {kind!r}")
        # 审查 P2：同 agent 任务去重——已有 pending/running 任务时复用，不
        # 新建。并发任务各自基于入口处陈旧快照读-改-写，后写者可把已晋升
        # 级别回退（队列任务 + 同步 /verify 请求并发时的真实竞态）。
        # finished 的旧任务（已进 _results）不拦截新一轮验证。
        with self._results_cv:
            existing_id = next(
                (
                    task_id
                    for task_id, task in self._tasks.items()
                    if task.catalog_agent_id == catalog_agent_id
                    and task_id not in self._results
                ),
                None,
            )
        if existing_id is not None:
            existing_task = self._tasks[existing_id]
            if wait:
                return self.wait(existing_id, timeout=timeout)
            return VerificationTaskResult(
                task_id=existing_id,
                catalog_agent_id=catalog_agent_id,
                kind=kind,
                status="enqueued",
                verification_status="",
                enqueued_at=existing_task.enqueued_at,
                finished_at=self._now(),
            )
        task_id = f"vt-{next(self._id_seq):06d}-{uuid.uuid4().hex[:6]}"
        enqueued_at = self._now()
        task = VerificationTask(
            catalog_agent_id=catalog_agent_id,
            task_id=task_id,
            kind=kind,
            actor=actor,
            enqueued_at=enqueued_at,
        )
        with self._results_cv:
            self._tasks[task_id] = task
        try:
            self._persist_insert(task)
        except Exception as exc:
            # 审查 P2：ledger 写失败必须回滚内存条目——否则 _tasks 留下无人
            # 消费的孤儿任务，wait(task_id) 永久挂死。抛类型化错误，调用方
            # 可安全重试（register 幂等键机制保证不产生重复副作用）。
            with self._results_cv:
                self._tasks.pop(task_id, None)
            raise VerificationQueueLedgerError(
                f"failed to persist verification task {task_id}: {exc}"
            ) from exc
        try:
            # 审查 P3（enqueue/shutdown 竞态）：检查 _shutdown 与 put 必须在
            # 与 shutdown() 的「置位+放哨兵」同一把锁内原子完成——否则检查通过
            # 后 shutdown 先置位放哨兵、本任务再入队落在哨兵之后无人消费，
            # wait() 永久挂死。
            with self._enqueue_lock:
                if self._shutdown.is_set():
                    self._persist_delete(task_id)
                    with self._results_cv:
                        self._tasks.pop(task_id, None)
                    raise VerificationQueueShutdownError(
                        "verification queue is shut down"
                    )
                self._pending.put_nowait(task)
        except queue.Full as exc:
            self._persist_delete(task_id)
            with self._results_cv:
                self._tasks.pop(task_id, None)
            self._update_depth()
            raise VerificationQueueFullError(
                f"verification queue is full (max_pending={self._config.max_pending})"
            ) from exc
        self._update_depth()
        if not wait:
            return VerificationTaskResult(
                task_id=task_id,
                catalog_agent_id=catalog_agent_id,
                kind=kind,
                status="enqueued",
                verification_status="",
                enqueued_at=enqueued_at,
                finished_at=self._now(),
            )
        return self.wait(task_id, timeout=timeout)

    def wait(self, task_id: str, timeout: float | None = None) -> VerificationTaskResult:
        """Block until the task with *task_id* produces a result.

        Returns a ``VerificationTaskResult`` with ``status == "timeout"`` when
        *timeout* seconds elapse before the task finishes.
        """
        deadline: float | None = None if timeout is None else time.monotonic() + timeout
        with self._results_cv:
            while task_id not in self._results:
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
        """Wait for every enqueued task to finish and return its result.

        Timed-out tasks are already reported with ``status == "timeout"`` by
        the per-task deadline, so *timeout* only bounds the *wait* for the
        queue to be fully processed.
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
        """Stop accepting new tasks and (optionally) wait for workers to exit."""
        if self._shutdown.is_set():
            return
        # 审查 P3：置位 + 放哨兵与 enqueue 的「检查+put」互斥（_enqueue_lock）——
        # 否则哨兵之后仍可能入队无人消费的任务。
        with self._enqueue_lock:
            self._shutdown.set()
            for _ in self._workers:
                self._pending.put(None)
        if wait:
            for worker in self._workers:
                worker.join(timeout=timeout)
            # 审查 P3：仅在所有 worker 退出后关 ledger 连接（此前连接随进程
            # 泄漏；wait=False 时不 close——在途任务仍要写 ledger）。close 与
            # enqueue 清理路径互斥（_enqueue_lock），避免撞已关闭连接。
            with self._enqueue_lock:
                if self._db_conn is not None:
                    try:
                        self._db_conn.close()
                    except sqlite3.Error:
                        pass
                    self._db_conn = None

    def __enter__(self) -> "VerificationQueue":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.shutdown(wait=True)

    def __del__(self) -> None:
        """GC 兜底：wait=False 的调用方负责最终 shutdown，但若对象被丢弃
        前未关 ledger 连接（测试/短期嵌入场景），随 GC 关闭防泄漏
        （审查附录 A ResourceWarning）。worker 为 daemon 线程，此时无在途写。
        """
        try:
            conn = self._db_conn
            if conn is not None and not self._shutdown.is_set():
                conn.close()
                self._db_conn = None
        except Exception:  # noqa: BLE001 —— GC 路径绝不抛
            pass

    # ── Internals ────────────────────────────────────────────────────────

    def _worker_loop(self) -> None:
        while True:
            task = self._pending.get()
            try:
                if task is None:
                    break
                try:
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
                with self._results_cv:
                    self._results[task.task_id] = result
                    self._results_cv.notify_all()
                self._update_depth()
            finally:
                self._pending.task_done()

    def _run_task_with_timeout(self, task: VerificationTask) -> VerificationTaskResult:
        """Run *task* under the per-task deadline, reporting timeouts."""
        started_at = self._now()
        self._persist_running(task.task_id, started_at)
        # "cancelled" 事件是 supervisor 通知 runaway 线程的取消信号：超时后
        # 线程不得再写 ledger（否则会把 supervisor 已落的 timeout 改写成
        # completed，与调用方拿到的结果矛盾）。
        box: dict[str, Any] = {"started_at": started_at, "cancelled": threading.Event()}
        runner = threading.Thread(
            target=self._execute_task,
            args=(task, box),
            name=f"verification-task-{task.task_id}",
            daemon=True,
        )
        runner.start()
        runner.join(self._config.task_timeout_seconds)
        if runner.is_alive():
            # The task exceeded its deadline.  The supervisor frees its slot
            # and reports a timeout; signal the runaway daemon thread to
            # abandon (no ledger writes, no result publication).
            box["cancelled"].set()
            result = VerificationTaskResult(
                task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id,
                kind=task.kind,
                status="timeout",
                verification_status="",
                error=f"verification task exceeded {self._config.task_timeout_seconds}s",
                enqueued_at=task.enqueued_at,
                started_at=started_at,
                finished_at=self._now(),
            )
            self._persist_finish(task.task_id, status="timeout", error=result.error)
            return result
        # box["result"] 缺失 = 执行线程在落结果前异常退出（如 ledger 写失败）：
        # 兜底 failed 结果，绝不 KeyError 杀 worker（并发预算减一且无恢复）。
        result = box.get("result")
        if result is None:
            result = VerificationTaskResult(
                task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id,
                kind=task.kind,
                status="failed",
                verification_status="",
                error="task ended without a result (persistence/execution error)",
                enqueued_at=task.enqueued_at,
                started_at=started_at,
                finished_at=self._now(),
            )
            try:
                self._persist_finish(
                    task.task_id, status="failed", error=result.error
                )
            except Exception:  # noqa: BLE001 —— ledger 写失败不杀 worker
                pass
        return result

    def _execute_task(self, task: VerificationTask, box: dict[str, Any]) -> None:
        started_at = float(box["started_at"])
        cancelled: threading.Event = box["cancelled"]
        try:
            service = self._service_factory()
        except Exception as exc:  # noqa: BLE001 — reported to the caller
            if cancelled.is_set():
                return  # supervisor 已落 timeout；runaway 不得改写 ledger
            box["result"] = VerificationTaskResult(
                task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id,
                kind=task.kind,
                status="failed",
                verification_status="",
                error=f"service factory failed: {exc}",
                enqueued_at=task.enqueued_at,
                started_at=started_at,
                finished_at=self._now(),
            )
            try:
                self._persist_finish(
                    task.task_id,
                    status="failed",
                    error=f"service factory failed: {exc}",
                )
            except Exception:  # noqa: BLE001 —— ledger 写失败不杀线程（恢复路径兜底）
                pass
            return
        try:
            if task.kind == "refresh":
                res = service.refresh(task.catalog_agent_id, actor=task.actor)
            elif task.kind == "mark_stale":
                res = service.mark_stale(task.catalog_agent_id, actor=task.actor)
            elif task.kind == "suspend":
                res = service.suspend(task.catalog_agent_id, actor=task.actor)
            else:
                res = service.verify(task.catalog_agent_id, actor=task.actor)
            # 审查 P2（超时语义）：supervisor 已置 cancelled 时不得 commit——
            # 此前 runner 先 commit 后查 cancelled，timeout 已返回后 catalog
            # 状态仍被推进（调用方按「timeout=未执行」重试会叠加重叠验证）。
            # 不 commit → 连接关闭时回滚，catalog 三域/审计保持原样
            # （_load_profiles 的快照缓存可能已刷新——文档化语义：timeout
            # = catalog 状态不被推进，快照缓存可能已刷新）。
            if cancelled.is_set():
                return
            commit = getattr(service, "commit", None)
            if commit is not None:
                commit()
        except Exception as exc:  # noqa: BLE001 — reported to the caller
            if cancelled.is_set():
                return  # supervisor 已落 timeout；runaway 不得改写 ledger
            box["result"] = VerificationTaskResult(
                task_id=task.task_id,
                catalog_agent_id=task.catalog_agent_id,
                kind=task.kind,
                status="failed",
                verification_status="",
                error=f"{type(exc).__name__}: {exc}",
                enqueued_at=task.enqueued_at,
                started_at=started_at,
                finished_at=self._now(),
            )
            try:
                self._persist_finish(
                    task.task_id,
                    status="failed",
                    error=f"{type(exc).__name__}: {exc}",
                )
            except Exception:  # noqa: BLE001 —— ledger 写失败不杀线程（恢复路径兜底）
                pass
            return
        finally:
            close = getattr(service, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:  # noqa: BLE001 — cleanup must not mask results
                    pass
        if cancelled.is_set():
            return  # supervisor 已落 timeout；runaway 不得改写 ledger
        box["result"] = VerificationTaskResult(
            task_id=task.task_id,
            catalog_agent_id=task.catalog_agent_id,
            kind=task.kind,
            status="completed",
            verification_status=res.status,
            enqueued_at=task.enqueued_at,
            started_at=started_at,
            finished_at=self._now(),
            result=res,
        )
        try:
            self._persist_finish(
                task.task_id,
                status="completed",
                verification_status=res.status,
                result=res,
            )
        except Exception:  # noqa: BLE001 —— ledger 写失败不杀线程（恢复路径兜底）
            pass


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
    from kiwi_catalog.db.session import open_connection

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
    "StageResult",
    "VerificationResult",
    "VerificationService",
    "VerificationQueue",
    "VerificationQueueConfig",
    "VerificationQueueFullError",
    "VerificationQueueShutdownError",
    "VerificationTask",
    "VerificationTaskResult",
    "make_verification_worker",
    "InvalidStateTransitionError",
]
