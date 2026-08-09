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

"""Catalog agent 三正交状态域（产品文档 kiwi-catalog v0.3 §7）。

legacy 模型把验证证据、新鲜度和治理处置塞进单一 ``verification_status``
（discovered…commerce_verified / stale / unreachable / suspended / rejected）。
v0.3 拆成三个正交域，各自独立迁移，MUST NOT 坍缩为一个状态机：

* VerificationLevel —— 证据链级别（可沿阶梯晋升；证据失效时重算到
  最高仍支持的较低级，历史证据可审计）；
* FreshnessState —— profile 新鲜度 / 可达性（FRESH / STALE / UNREACHABLE；
  UNREACHABLE 是可达性事实，不是声誉判断）；
* AdministrativeState —— 治理处置（ACTIVE / SUSPENDED / REJECTED 终态）。

为保持 legacy 消费方（/v1/agent-catalog/*、metrics、kiwi 侧
resolve.ts 的 BLOCKED 过滤）不变，``fold_verification_status`` 在每次任一
域迁移后把三域折叠回单一 ``verification_status`` 投影列。折叠优先级：
rejected > suspended > unreachable > stale > verification_level。
"""

from __future__ import annotations

from typing import ClassVar

from kiwi_catalog.core.errors import ShoppingCliError

# ── VerificationLevel（v0.3 §7.1）──────────────────────────────────────────

DISCOVERED = "discovered"
PROFILE_VALID = "profile_valid"
DOMAIN_VERIFIED = "domain_verified"
AGENT_VERIFIED = "agent_verified"
COMMERCE_VERIFIED = "commerce_verified"

VERIFICATION_LEVELS: tuple[str, ...] = (
    DISCOVERED,
    PROFILE_VALID,
    DOMAIN_VERIFIED,
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
)
_VERIFICATION_LEVEL_INDEX: dict[str, int] = {
    level: i for i, level in enumerate(VERIFICATION_LEVELS)
}

# ── FreshnessState（v0.3 §7.2）─────────────────────────────────────────────

FRESH = "fresh"
STALE = "stale"
UNREACHABLE = "unreachable"

FRESHNESS_STATES: tuple[str, ...] = (FRESH, STALE, UNREACHABLE)

# ── AdministrativeState（v0.3 §7.3）───────────────────────────────────────

ACTIVE = "active"
SUSPENDED = "suspended"
REJECTED = "rejected"

ADMINISTRATIVE_STATES: tuple[str, ...] = (ACTIVE, SUSPENDED, REJECTED)

# ── KTH destination_type 词表（架构 rev1.4.1 §35A 单一来源）────────────────
# 与 kiwi 仓 contracts/kiwi-catalog/1.0/agent-record.schema.json 的 enum
# 逐值一致（tests/test_state_domains.py 有断言）；禁止 supports_* 平行词表。

HANDOFF_DESTINATION_TYPES: tuple[str, ...] = (
    "ucp_checkout",
    "ucp_order",
    "external_checkout_url",
    "merchant_checkout_session",
    "platform_deep_link",
    "buyer_erp_request",
    "procurement_request",
    "purchase_order_draft",
    "quote_document",
    "merchant_contact",
    "sales_handoff",
)


class InvalidStateTransitionError(ShoppingCliError):
    """Raised when a domain state transition is not in the v0.3 table."""


def _member(values: tuple[str, ...], name: str) -> None:
    if name not in values:
        raise InvalidStateTransitionError(f"unknown {name!r}: not one of {values}")


def fold_verification_status(
    verification_level: str,
    freshness_state: str,
    administrative_state: str,
) -> str:
    """三正交域 → legacy 单一 status 投影（折叠优先级见模块 docstring）。"""
    if administrative_state == REJECTED:
        return "rejected"
    if administrative_state == SUSPENDED:
        return "suspended"
    if freshness_state == UNREACHABLE:
        return "unreachable"
    if freshness_state == STALE:
        return "stale"
    return verification_level


# ── VerificationLevel 迁移（v0.3 §7.1）─────────────────────────────────────


class VerificationLevelStateMachine:
    """验证级别阶梯：promote 只允许自环或 +1；降级走独立 degrade 通道。

    任何不在表中的 (from, to) 抛 InvalidStateTransitionError（fail-closed）。
    降级由服务层按证据重算（v0.3 §7.1 material invalidation → 重算到最高
    仍支持的较低级），本机只约束目标级别合法性。
    """

    def can_transition(self, current: str, target: str) -> bool:
        _member(VERIFICATION_LEVELS, current)
        _member(VERIFICATION_LEVELS, target)
        return _VERIFICATION_LEVEL_INDEX[target] in (
            _VERIFICATION_LEVEL_INDEX[current],
            _VERIFICATION_LEVEL_INDEX[current] + 1,
        )

    def transition(self, current: str, target: str) -> str:
        if not self.can_transition(current, target):
            raise InvalidStateTransitionError(
                f"illegal verification_level transition {current!r} -> {target!r}"
            )
        return target

    def can_degrade(self, current: str, target: str) -> bool:
        _member(VERIFICATION_LEVELS, current)
        _member(VERIFICATION_LEVELS, target)
        return _VERIFICATION_LEVEL_INDEX[target] < _VERIFICATION_LEVEL_INDEX[current]

    def degrade(self, current: str, target: str) -> str:
        """证据失效重算降级（仅允许到较低级，不允许跳级晋升）。"""
        if not self.can_degrade(current, target):
            raise InvalidStateTransitionError(
                f"illegal verification_level degradation {current!r} -> {target!r}"
            )
        return target


# ── FreshnessState 迁移（v0.3 §7.2）────────────────────────────────────────


class FreshnessStateMachine:
    """新鲜度 / 可达性迁移表（v0.3 §7.2）。

    FRESH          → FRESH（刷新成功）/ STALE（TTL 过期）/ UNREACHABLE（连续失败）
    STALE          → FRESH（刷新成功）/ UNREACHABLE（连续失败）
    UNREACHABLE    → FRESH（刷新成功）/ STALE（部分可达，按策略）
    """

    _TRANSITIONS: ClassVar[dict[str, frozenset[str]]] = {
        FRESH: frozenset({FRESH, STALE, UNREACHABLE}),
        STALE: frozenset({FRESH, UNREACHABLE}),
        UNREACHABLE: frozenset({FRESH, STALE}),
    }

    def can_transition(self, current: str, target: str) -> bool:
        _member(FRESHNESS_STATES, current)
        _member(FRESHNESS_STATES, target)
        return target in self._TRANSITIONS[current]

    def transition(self, current: str, target: str) -> str:
        if not self.can_transition(current, target):
            raise InvalidStateTransitionError(
                f"illegal freshness_state transition {current!r} -> {target!r}"
            )
        return target


# ── AdministrativeState 迁移（v0.3 §7.3）───────────────────────────────────


class AdministrativeStateMachine:
    """治理处置迁移表（v0.3 §7.3）。

    ACTIVE     → SUSPENDED（临时处置）/ REJECTED（治理终审）
    SUSPENDED  → ACTIVE（授权恢复）
    REJECTED   → ∅（终态；仅显式申诉/治理流程可产生新的行政决定）
    """

    _TRANSITIONS: ClassVar[dict[str, frozenset[str]]] = {
        ACTIVE: frozenset({SUSPENDED, REJECTED}),
        SUSPENDED: frozenset({ACTIVE}),
        REJECTED: frozenset(),
    }

    def can_transition(self, current: str, target: str) -> bool:
        _member(ADMINISTRATIVE_STATES, current)
        _member(ADMINISTRATIVE_STATES, target)
        return target in self._TRANSITIONS[current]

    def transition(self, current: str, target: str) -> str:
        if not self.can_transition(current, target):
            raise InvalidStateTransitionError(
                f"illegal administrative_state transition {current!r} -> {target!r}"
            )
        return target
