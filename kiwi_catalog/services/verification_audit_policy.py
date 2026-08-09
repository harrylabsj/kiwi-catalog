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

"""Pure §23 audit + §24 funnel policy for the verification pipeline terminal decision.

Extracted from ``agent_verification.py`` (T8/T9 hotspot convergence): the pure
"verification result -> audit event / metrics action" decision that ends every
pipeline run in ``_finalize``.  Given the terminal ``status``, the run's
``stages``, the §6.1 ``policy_version`` and the ``failure_kind``, the leaf
computes the ordered side-effect plan: the §23 ``audit_events`` to write and
the §24 ``verified`` funnel increment.

The leaf is side-effect free by construction — it never opens a SQLite
connection, never calls ``record_funnel``, never mutates state, and never
commits a transaction.  ``agent_verification.py`` (the facade) iterates the
returned plan and executes each step in order (``append_catalog_audit`` /
``record_funnel``), so the event order, event names, details fields, the
empty-stages ``StageResult("verification", failure_kind, status)`` fallback,
the pinned ``trust_policy_version`` and the public/private data boundary are
identical to the pre-extraction code.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from kiwi_catalog.discovery.verifier import COMMERCE_VERIFIED, STALE
from kiwi_catalog.services.verification_profile_policy import VERIFIED_RUNGS
from kiwi_catalog.services.verification_stages import StageResult


@dataclass(frozen=True)
class AuditEvent:
    """One §23 audit write: the event name plus its details payload.

    ``details`` only ever carries public metadata — the verification status,
    stage count, failure stage/reason, target status and the §6.1 policy
    version.  No secret/private profile data crosses this boundary (§17.3).
    """

    event: str
    details: dict[str, Any]


@dataclass(frozen=True)
class FunnelStep:
    """Marker for a §24 funnel increment (``record_funnel(stage)``).

    Kept as an ordered step rather than a side flag so the facade executes the
    funnel exactly where the pre-extraction ``_finalize`` did — between the
    profile-refresh audit and the ``catalog_agent_verified`` event.
    """

    stage: str


@dataclass(frozen=True)
class FinalizeAuditPlan:
    """Ordered side-effect steps for one completed pipeline run.

    The facade walks ``steps`` in order: an ``AuditEvent`` becomes
    ``append_catalog_audit(conn, id, actor, event, details)`` and a
    ``FunnelStep`` becomes ``record_funnel(stage)``.
    """

    steps: tuple[AuditEvent | FunnelStep, ...]


def finalize_audit_plan(
    *,
    status: str,
    stages: Sequence[StageResult],
    policy_version: str | int,
    failure_kind: str | None,
) -> FinalizeAuditPlan:
    """Plan the §23 audit events + §24 funnel for a completed pipeline run.

    Mirrors the pre-extraction ``_finalize`` decision exactly:

    * a ``profile`` first stage that wrote snapshots emits
      ``catalog_agent_refreshed`` first (the run refreshed the profile cache);
    * no failure → a ``verified`` funnel step for any §24 verified rung, plus
      ``catalog_agent_verified`` at COMMERCE_VERIFIED;
    * failure → ``catalog_agent_verification_failed`` with the last stage's
      ``failed_stage`` / ``reason`` and the ``target_status``, falling back to
      ``StageResult("verification", failure_kind, status)`` on empty stages,
      and a ``catalog_agent_stale`` event when the failure kind is STALE.
    """
    steps: list[AuditEvent | FunnelStep] = []
    if stages and stages[0].stage == "profile" and stages[0].snapshot_ids:
        steps.append(
            AuditEvent(
                "catalog_agent_refreshed",
                {
                    "verification_status": status,
                    "stage_count": len(stages),
                    "trust_policy_version": policy_version,
                },
            )
        )
    if failure_kind is None:
        if status in VERIFIED_RUNGS:
            steps.append(FunnelStep("verified"))
        if status == COMMERCE_VERIFIED:
            steps.append(
                AuditEvent(
                    "catalog_agent_verified",
                    {
                        "verification_status": status,
                        "trust_policy_version": policy_version,
                    },
                )
            )
    else:
        last_stage = (
            stages[-1] if stages else StageResult("verification", failure_kind, status)
        )
        steps.append(
            AuditEvent(
                "catalog_agent_verification_failed",
                {
                    "failed_stage": last_stage.stage,
                    "reason": last_stage.reason,
                    "target_status": status,
                    "trust_policy_version": policy_version,
                },
            )
        )
        if failure_kind == STALE:
            steps.append(AuditEvent("catalog_agent_stale", {"reason": last_stage.reason}))
    return FinalizeAuditPlan(tuple(steps))


__all__ = [
    "AuditEvent",
    "FinalizeAuditPlan",
    "FunnelStep",
    "finalize_audit_plan",
]
