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

"""Pure stage results and evidence policy for the §6 verification ladder.

Extracted from ``agent_verification.py`` (T8/T9 hotspot convergence): the
plain-data ``StageResult`` / ``VerificationResult`` dataclasses plus the
evidence shaping functions that produce the §5.6 evidence payload and
failed-evidence records.  ``agent_verification.py`` keeps only the pipeline
*orchestration* (stage drivers, state transitions, persistence) and re-exports
these names, so the public facade and queue serialization stay unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.discovery.verifier import VerificationEvidence


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


def evidence_payload(evidence: VerificationEvidence, policy: TrustPolicy) -> dict[str, Any]:
    """The §5.6 evidence payload — always pins the §6.1 trust_policy_version."""
    return {
        "verification_type": evidence.verification_type,
        "result": evidence.result,
        "reason": evidence.reason,
        "trust_policy_version": policy.policy_version,
        "details": dict(evidence.details),
    }


def failed_evidence(
    verification_type: str,
    reason: str,
    details: dict[str, Any],
) -> VerificationEvidence:
    """Build a ``failed`` evidence record for a stage whose check could not pass."""
    return VerificationEvidence(
        verification_type=verification_type,
        result="failed",
        reason=reason,
        details=dict(details),
    )


__all__ = [
    "StageResult",
    "VerificationResult",
    "evidence_payload",
    "failed_evidence",
]
