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

"""三正交状态域测试（产品文档 kiwi-catalog v0.3 §7）。

覆盖：
- fold_verification_status 折叠优先级：rejected > suspended > unreachable
  > stale > verification_level；
- VerificationLevelStateMachine：一次一级晋升、非法跳级拒绝、degrade 通道；
- FreshnessStateMachine / AdministrativeStateMachine 迁移表；
- HANDOFF_DESTINATION_TYPES 与 kiwi 仓 agent-record schema 枚举逐值一致
  （跨仓单一词表契约，禁止 supports_* 平行词表）。
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from kiwi_catalog.agent_catalog.state_domains import (
    ACTIVE,
    COMMERCE_VERIFIED,
    DISCOVERED,
    DOMAIN_VERIFIED,
    FRESH,
    PROFILE_VALID,
    REJECTED,
    STALE,
    SUSPENDED,
    UNREACHABLE,
    AGENT_VERIFIED,
    HANDOFF_DESTINATION_TYPES,
    AdministrativeStateMachine,
    FreshnessStateMachine,
    InvalidStateTransitionError,
    VerificationLevelStateMachine,
    fold_verification_status,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_KIWI_SCHEMA = (
    _REPO_ROOT.parent
    / "kiwi"
    / "contracts"
    / "kiwi-catalog"
    / "1.0"
    / "agent-record.schema.json"
)
# 审查 C-M5：golden fixture（kiwi schema enum 的最近快照）——CI 无 sibling kiwi
# 仓时 schema 检查 self-skip，enum 漂移不被捕获；golden 检查**始终运行**。
_GOLDEN_FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "handoff_destination_types.json"


class FoldVerificationStatusTest(unittest.TestCase):
    def test_fold_priority_rejected(self) -> None:
        self.assertEqual(fold_verification_status(COMMERCE_VERIFIED, FRESH, REJECTED), "rejected")

    def test_fold_priority_suspended(self) -> None:
        self.assertEqual(fold_verification_status(COMMERCE_VERIFIED, UNREACHABLE, SUSPENDED), "suspended")

    def test_fold_priority_unreachable(self) -> None:
        self.assertEqual(fold_verification_status(COMMERCE_VERIFIED, UNREACHABLE, ACTIVE), "unreachable")

    def test_fold_priority_stale(self) -> None:
        self.assertEqual(fold_verification_status(COMMERCE_VERIFIED, STALE, ACTIVE), "stale")

    def test_fold_priority_level(self) -> None:
        self.assertEqual(fold_verification_status(DOMAIN_VERIFIED, FRESH, ACTIVE), "domain_verified")
        self.assertEqual(fold_verification_status(DISCOVERED, FRESH, ACTIVE), "discovered")


class VerificationLevelStateMachineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.machine = VerificationLevelStateMachine()

    def test_promote_one_step_only(self) -> None:
        self.assertEqual(self.machine.transition(DISCOVERED, PROFILE_VALID), PROFILE_VALID)
        self.assertEqual(self.machine.transition(PROFILE_VALID, DOMAIN_VERIFIED), DOMAIN_VERIFIED)
        self.assertEqual(self.machine.transition(DOMAIN_VERIFIED, AGENT_VERIFIED), AGENT_VERIFIED)
        self.assertEqual(
            self.machine.transition(AGENT_VERIFIED, COMMERCE_VERIFIED), COMMERCE_VERIFIED
        )

    def test_self_transition_allowed(self) -> None:
        self.assertEqual(self.machine.transition(COMMERCE_VERIFIED, COMMERCE_VERIFIED), COMMERCE_VERIFIED)

    def test_skip_promotion_rejected(self) -> None:
        with self.assertRaises(InvalidStateTransitionError):
            self.machine.transition(DISCOVERED, COMMERCE_VERIFIED)
        with self.assertRaises(InvalidStateTransitionError):
            self.machine.transition(PROFILE_VALID, AGENT_VERIFIED)

    def test_degrade_to_any_lower_allowed(self) -> None:
        self.assertEqual(self.machine.degrade(COMMERCE_VERIFIED, DOMAIN_VERIFIED), DOMAIN_VERIFIED)
        self.assertEqual(self.machine.degrade(AGENT_VERIFIED, DISCOVERED), DISCOVERED)

    def test_degrade_to_higher_or_equal_rejected(self) -> None:
        with self.assertRaises(InvalidStateTransitionError):
            self.machine.degrade(DOMAIN_VERIFIED, AGENT_VERIFIED)
        with self.assertRaises(InvalidStateTransitionError):
            self.machine.degrade(COMMERCE_VERIFIED, COMMERCE_VERIFIED)

    def test_unknown_level_rejected(self) -> None:
        with self.assertRaises(InvalidStateTransitionError):
            self.machine.transition("totally_legit", DISCOVERED)


class FreshnessStateMachineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.machine = FreshnessStateMachine()

    def test_fresh_transitions(self) -> None:
        self.assertEqual(self.machine.transition(FRESH, FRESH), FRESH)
        self.assertEqual(self.machine.transition(FRESH, STALE), STALE)
        self.assertEqual(self.machine.transition(FRESH, UNREACHABLE), UNREACHABLE)

    def test_stale_transitions(self) -> None:
        self.assertEqual(self.machine.transition(STALE, FRESH), FRESH)
        self.assertEqual(self.machine.transition(STALE, UNREACHABLE), UNREACHABLE)
        with self.assertRaises(InvalidStateTransitionError):
            self.machine.transition(STALE, STALE)

    def test_unreachable_transitions(self) -> None:
        self.assertEqual(self.machine.transition(UNREACHABLE, FRESH), FRESH)
        self.assertEqual(self.machine.transition(UNREACHABLE, STALE), STALE)


class AdministrativeStateMachineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.machine = AdministrativeStateMachine()

    def test_active_transitions(self) -> None:
        self.assertEqual(self.machine.transition(ACTIVE, SUSPENDED), SUSPENDED)
        self.assertEqual(self.machine.transition(ACTIVE, REJECTED), REJECTED)

    def test_suspended_reversible(self) -> None:
        self.assertEqual(self.machine.transition(SUSPENDED, ACTIVE), ACTIVE)

    def test_rejected_terminal(self) -> None:
        for target in (ACTIVE, SUSPENDED, REJECTED):
            with self.assertRaises(InvalidStateTransitionError):
                self.machine.transition(REJECTED, target)


class HandoffVocabularyContractTest(unittest.TestCase):
    def test_destination_types_match_kiwi_schema_enum(self) -> None:
        """跨仓单一词表：HANDOFF_DESTINATION_TYPES 与 kiwi 仓 agent-record
        schema 的 enum 逐值一致（顺序也一致）。"""
        # 审查 C-M5：先做 golden fixture 断言（始终运行，CI 无 sibling kiwi 仓也
        # 捕获本仓词表漂移）；有 sibling schema 时再做跨仓精确核对。
        golden = json.loads(_GOLDEN_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(
            list(HANDOFF_DESTINATION_TYPES),
            golden,
            "HANDOFF_DESTINATION_TYPES 与 golden fixture 漂移——若是有意改词表，"
            "须同步更新 tests/fixtures/handoff_destination_types.json（及 kiwi 仓 schema）",
        )
        if not _KIWI_SCHEMA.exists():
            self.skipTest("kiwi repo schema not present (golden fixture check still ran)")
        schema = json.loads(_KIWI_SCHEMA.read_text(encoding="utf-8"))
        schema_enum = schema["properties"]["handoff_destination_types"]["items"]["enum"]
        self.assertEqual(list(HANDOFF_DESTINATION_TYPES), schema_enum)

    def test_no_supports_parallel_vocabulary(self) -> None:
        self.assertFalse(any(v.startswith("supports_") for v in HANDOFF_DESTINATION_TYPES))


if __name__ == "__main__":
    unittest.main()
