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

"""Characterization tests for the extracted verification stage results +
evidence policy (T8/T9 split of ``agent_verification.py``).

These tests lock the behaviour of the pure ``StageResult`` /
``VerificationResult`` dataclasses and the §5.6 evidence shaping functions
that previously lived in ``agent_verification.py``, plus the re-export
surface that keeps the public facade unchanged.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.discovery.verifier import VerificationEvidence
from kiwi_catalog.services import verification_stages
from kiwi_catalog.services.verification_stages import (
    StageResult,
    VerificationResult,
    evidence_payload,
    failed_evidence,
)


def _evidence(
    verification_type: str = "domain_control",
    result: str = "passed",
    reason: str = "domain token matches",
    details: dict[str, object] | None = None,
) -> VerificationEvidence:
    return VerificationEvidence(
        verification_type=verification_type,
        result=result,
        reason=reason,
        details=details if details is not None else {"domain": "example.com"},
    )


# ── evidence_payload: §5.6 shaping ──────────────────────────────────────────


def test_evidence_payload_pins_all_evidence_fields_and_policy_version() -> None:
    evidence = _evidence()
    policy = TrustPolicy(policy_version=3)
    payload = evidence_payload(evidence, policy)
    assert payload == {
        "verification_type": "domain_control",
        "result": "passed",
        "reason": "domain token matches",
        "trust_policy_version": 3,
        "details": {"domain": "example.com"},
    }


def test_evidence_payload_uses_default_policy_version_when_not_overridden() -> None:
    payload = evidence_payload(_evidence(), TrustPolicy())
    assert payload["trust_policy_version"] == 1


def test_evidence_payload_copies_details_dict() -> None:
    """Mutating the source evidence details after shaping must not leak into
    the persisted payload (the §5.6 evidence JSON is stored verbatim)."""
    details = {"domain": "example.com"}
    evidence = _evidence(details=details)
    payload = evidence_payload(evidence, TrustPolicy())
    details["domain"] = "evil.example.com"
    assert payload["details"] == {"domain": "example.com"}
    # the payload's own nested dict is independent of the evidence's too
    payload["details"]["domain"] = "again.example.com"
    assert evidence.details == {"domain": "evil.example.com"}


def test_evidence_payload_empty_details_yields_empty_dict() -> None:
    payload = evidence_payload(_evidence(details={}), TrustPolicy())
    assert payload["details"] == {}


# ── failed_evidence: §5.1 / rejection shaping ──────────────────────────────


def test_failed_evidence_builds_failed_verification_evidence() -> None:
    failed = failed_evidence(
        "commerce_capability",
        "§5.1 publish invariant failed",
        {"hosted_runtime_agent_id": ""},
    )
    assert isinstance(failed, VerificationEvidence)
    assert failed.result == "failed"
    assert failed.passed is False
    assert failed.verification_type == "commerce_capability"
    assert failed.reason == "§5.1 publish invariant failed"
    assert failed.details == {"hosted_runtime_agent_id": ""}


def test_failed_evidence_copies_details_dict() -> None:
    details = {"hosted_runtime_agent_id": ""}
    failed = failed_evidence("commerce_capability", "rejected", details)
    details["hosted_runtime_agent_id"] = "cagt_2"
    assert failed.details == {"hosted_runtime_agent_id": ""}


def test_failed_evidence_empty_details_yields_empty_dict() -> None:
    assert failed_evidence("agent_identity", "no trust", {}).details == {}


# ── StageResult dataclass ───────────────────────────────────────────────────


def test_stage_result_requires_core_fields_and_defaults_optional() -> None:
    stage = StageResult(stage="profile", outcome="passed", target_status="profile_valid")
    assert stage.reason == ""
    assert stage.verification_id is None
    assert stage.snapshot_ids == ()
    assert stage.evidence is None


def test_stage_result_accepts_explicit_optional_fields() -> None:
    stage = StageResult(
        stage="domain_control",
        outcome="passed",
        target_status="domain_verified",
        reason="domain token matches",
        verification_id=7,
        snapshot_ids=(11, 22),
        evidence={"verification_type": "domain_control", "result": "passed"},
    )
    assert stage.reason == "domain token matches"
    assert stage.verification_id == 7
    assert stage.snapshot_ids == (11, 22)
    assert stage.evidence == {"verification_type": "domain_control", "result": "passed"}


def test_stage_result_snapshot_ids_are_ordered_and_immutable() -> None:
    stage = StageResult(
        stage="profile", outcome="passed", target_status="profile_valid", snapshot_ids=(11, 22)
    )
    assert stage.snapshot_ids == (11, 22)


# ── VerificationResult dataclass ────────────────────────────────────────────


def test_verification_result_holds_stages_tuple() -> None:
    stage = StageResult(stage="profile", outcome="passed", target_status="profile_valid")
    result = VerificationResult(
        catalog_agent_id="cagt_1",
        previous_status="discovered",
        status="profile_valid",
        stages=(stage,),
    )
    assert result.catalog_agent_id == "cagt_1"
    assert result.previous_status == "discovered"
    assert result.status == "profile_valid"
    assert result.stages == (stage,)


def test_verification_result_empty_stages_allowed() -> None:
    result = VerificationResult("cagt_1", "discovered", "discovered", ())
    assert result.stages == ()


# ── Immutability (frozen) ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "factory,field",
    [
        (
            lambda: StageResult(stage="profile", outcome="passed", target_status="profile_valid"),
            "reason",
        ),
        (
            lambda: VerificationResult("cagt_1", "discovered", "discovered", ()),
            "status",
        ),
    ],
)
def test_stage_and_result_dataclasses_are_frozen(factory, field) -> None:
    instance = factory()
    with pytest.raises(FrozenInstanceError):
        setattr(instance, field, "changed")


# ── Re-export / import surface preservation ─────────────────────────────────


def test_dataclasses_and_helpers_are_reexported_from_agent_verification() -> None:
    from kiwi_catalog.services import agent_verification

    assert agent_verification.StageResult is StageResult
    assert agent_verification.VerificationResult is VerificationResult
    # 内部私有别名保持同一函数对象——agent_verification 内的调用点继续工作。
    assert agent_verification._evidence_payload is evidence_payload
    assert agent_verification._failed_evidence is failed_evidence

    assert "StageResult" in agent_verification.__all__
    assert "VerificationResult" in agent_verification.__all__


def test_stages_module_exports_only_stage_surface() -> None:
    assert set(verification_stages.__all__) == {
        "StageResult",
        "VerificationResult",
        "evidence_payload",
        "failed_evidence",
    }


def test_serialization_resolves_stage_types_from_stages_module() -> None:
    """The queue serialization helpers construct the dataclasses from the new
    module (not lazily from agent_verification) — the round trip still holds."""
    from kiwi_catalog.services.verification_queue_serialization import (
        deserialize_verification_result,
        serialize_verification_result,
    )

    result = VerificationResult(
        catalog_agent_id="cagt_x",
        previous_status="discovered",
        status="profile_valid",
        stages=(
            StageResult(
                stage="profile",
                outcome="passed",
                target_status="profile_valid",
                snapshot_ids=(1, 2),
            ),
        ),
    )
    assert deserialize_verification_result(serialize_verification_result(result)) == result
