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

"""Pure serialization helpers for the verification queue ledger (result_json)."""

from __future__ import annotations

import json

from kiwi_catalog.db.session import encode_json
from kiwi_catalog.services.verification_stages import StageResult, VerificationResult


def serialize_verification_result(result: VerificationResult | None) -> str:
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


def deserialize_verification_result(raw: str) -> VerificationResult | None:
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
