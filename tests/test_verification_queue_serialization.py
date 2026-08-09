"""Focused tests for the verification queue ledger serialization helpers."""

from __future__ import annotations

from kiwi_catalog.services.agent_verification import StageResult, VerificationResult
from kiwi_catalog.services.verification_queue_serialization import (
    deserialize_verification_result,
    serialize_verification_result,
)


def test_round_trip_full_result_preserves_all_fields() -> None:
    result = VerificationResult(
        catalog_agent_id="cagt_1",
        previous_status="discovered",
        status="domain_verified",
        stages=(
            StageResult(
                stage="profile",
                outcome="passed",
                target_status="profile_valid",
                snapshot_ids=(11, 22),
            ),
            StageResult(
                stage="domain_control",
                outcome="passed",
                target_status="domain_verified",
                reason="",
                verification_id=7,
                evidence={
                    "verification_type": "domain_control",
                    "result": "passed",
                    "details": {"domain": "example.com"},
                },
            ),
            StageResult(
                stage="commerce_capability",
                outcome="rejected",
                target_status="discovered",
                reason="publish invariant failed",
                verification_id=8,
                snapshot_ids=(),
                evidence={"verification_type": "commerce_capability", "result": "failed"},
            ),
        ),
    )

    assert deserialize_verification_result(serialize_verification_result(result)) == result


def test_round_trip_stale_result_with_reason() -> None:
    result = VerificationResult(
        catalog_agent_id="cagt_2",
        previous_status="domain_verified",
        status="stale",
        stages=(
            StageResult(
                stage="profile",
                outcome="stale",
                target_status="stale",
                reason="profile fetch failed; stale snapshot retained",
            ),
        ),
    )

    assert deserialize_verification_result(serialize_verification_result(result)) == result


def test_serialize_none_returns_empty_object() -> None:
    assert serialize_verification_result(None) == "{}"


def test_deserialize_empty_and_empty_object_returns_none() -> None:
    assert deserialize_verification_result("") is None
    assert deserialize_verification_result("{}") is None


def test_deserialize_none_input_returns_none() -> None:
    # The queue ledger column may be NULL; the helper treats falsy raw as absent.
    assert deserialize_verification_result(None) is None  # type: ignore[arg-type]


def test_deserialize_malformed_json_returns_none() -> None:
    assert deserialize_verification_result("not json") is None
    assert deserialize_verification_result("{invalid") is None
    # str(None) is what the ledger path passes when the result_json column is NULL.
    assert deserialize_verification_result("None") is None


def test_deserialize_missing_optional_fields_use_defaults() -> None:
    payload = (
        '{"catalog_agent_id":"cagt_x","previous_status":"discovered",'
        '"status":"profile_valid",'
        '"stages":[{"stage":"profile","outcome":"passed","target_status":"profile_valid"}]}'
    )
    result = deserialize_verification_result(payload)
    assert result is not None
    assert result.catalog_agent_id == "cagt_x"
    assert result.previous_status == "discovered"
    assert result.status == "profile_valid"
    assert result.stages == (
        StageResult(stage="profile", outcome="passed", target_status="profile_valid"),
    )
