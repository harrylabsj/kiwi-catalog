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

"""Pure failure/degradation policy for the §6 verification ladder.

Extracted from ``agent_verification.py`` (T8/T9 hotspot convergence): the
v0.3 §7.1 evidence recomputation decision (``highest_supported_level``) and
the §7.2 profile-failure handling plan (``profile_failure_plan``).  These
are the pure *decisions* that shape how a failed run rewrites the
verification level and freshness — the state-machine legality check
(``can_degrade``) and the evidence lookup are injected by the caller so the
leaf stays side-effect free, while ``agent_verification.py`` keeps the DB
reads, the state transitions and the audit writes unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kiwi_catalog.discovery.verifier import (
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
    DISCOVERED,
    DOMAIN_VERIFIED,
    REJECTED,
    STALE,
    UNREACHABLE,
)
from kiwi_catalog.services.verification_helpers import outcome_for
from kiwi_catalog.services.verification_profile_policy import parse_iso_ts

# Evidence types, highest supported level first — the §7.1 recomputation
# returns the FIRST kind whose latest passed evidence still supports its level.
EVIDENCE_KIND_TO_LEVEL: tuple[tuple[str, str], ...] = (
    ("commerce_capability", COMMERCE_VERIFIED),
    ("agent_identity", AGENT_VERIFIED),
    ("domain_control", DOMAIN_VERIFIED),
)

# §7.2: fetch failures (STALE / UNREACHABLE) are freshness-only — they must
# not clear the persisted verification level.  REJECTED (SSRF / validation /
# missing endpoints) invalidates the evidence and recomputes the level.
FRESHNESS_ONLY_FAILURE_STATUSES: frozenset[str] = frozenset({STALE, UNREACHABLE})


def highest_supported_level(
    *,
    current_level: str,
    now_ts: float,
    can_degrade: Callable[[str, str], bool],
    latest_passed: Callable[[str], Mapping[str, Any] | None],
    ladder: Sequence[tuple[str, str]] = EVIDENCE_KIND_TO_LEVEL,
) -> str:
    """v0.3 §7.1：按最新未过期证据重算「最高仍支持的较低级」。

    Checks the evidence kinds in *ladder* order; the latest **passed** row of
    a kind that is still unexpired (or carries no usable ``expires_at``) pins
    that level, otherwise DISCOVERED.  Historical evidence stays auditable —
    degradation never deletes existing observations.

    The state-machine legality check is injected as ``can_degrade`` and the
    evidence lookup as ``latest_passed`` so the decision stays pure.  ``can_degrade``
    is only consulted when ``level != current_level`` — same-level passed
    evidence keeps the current level (审查 P1-7: ``can_degrade`` is strict less-than,
    and a same-level check would otherwise collapse to DISCOVERED).
    """
    for kind, level in ladder:
        if level != current_level and not can_degrade(current_level, level):
            continue
        row = latest_passed(kind)
        if row is None:
            continue
        expires_at = str(row.get("expires_at") or "")
        if expires_at:
            parsed = parse_iso_ts(expires_at)
            if parsed is None or parsed < now_ts:
                continue
        return level
    return DISCOVERED


@dataclass(frozen=True)
class ProfileFailurePlan:
    """How a _ProfileFailure terminal status rewrites the agent state (§7.2).

    * freshness-only (STALE / UNREACHABLE): keep the level, set freshness to
      the failure status, stage outcome = stale/unreachable;
    * evidence-invalid (REJECTED): recompute the level from remaining
      evidence, set freshness STALE, stage outcome = rejected.
    """

    failure_kind: str
    """Terminal failure kind fed to ``_finalize`` (the failure status or REJECTED)."""

    freshness_state: str
    """Freshness to persist (the failure status, or STALE for REJECTED)."""

    stage_outcome: str
    """The profile ``StageResult`` outcome (stale / unreachable / rejected)."""

    recompute_level: bool
    """REJECTED → recompute the verification level from remaining evidence."""


def profile_failure_plan(target_status: str) -> ProfileFailurePlan:
    """The §7.2 handling plan for a profile-stage terminal status."""
    if target_status in FRESHNESS_ONLY_FAILURE_STATUSES:
        return ProfileFailurePlan(
            failure_kind=target_status,
            freshness_state=target_status,
            stage_outcome=outcome_for(target_status),
            recompute_level=False,
        )
    return ProfileFailurePlan(
        failure_kind=REJECTED,
        freshness_state=STALE,
        stage_outcome="rejected",
        recompute_level=True,
    )


__all__ = [
    "EVIDENCE_KIND_TO_LEVEL",
    "FRESHNESS_ONLY_FAILURE_STATUSES",
    "ProfileFailurePlan",
    "highest_supported_level",
    "profile_failure_plan",
]
