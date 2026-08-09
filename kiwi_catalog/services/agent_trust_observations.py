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

"""Private-only Agent Trust Observation service (§5.7).

This module is the ONLY application-level read/write path for
``agent_trust_observations`` rows.  It sits above the storage functions in
``kiwi_catalog.agent_catalog.sqlite_repository`` and adds §5.7 validation.

PRIVATE-ONLY
------------
Observations are commercial reputation / protocol trust data.  They MUST never
appear in a public serializer, a search response, or any public API output
(§3.4, §5.7).  The Public Catalog only exposes verification status, capability,
freshness, and hosting mode.  No public handler, serializer, or service may
import this module — the CLI stats/doctor aggregates below intentionally stop at
opaque counts and never surface observation content.

SEPARATION
----------
Commercial Reputation and Protocol Trust stay separate: every observation is an
independent, kind-tagged record with a single numeric ``value``.  They are never
merged into a combined reputation score.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import (
    TRUST_OBSERVATION_KINDS,
    count_trust_observations,
    insert_trust_observation,
    list_trust_observations,
    trust_observation_counts_by_kind,
)
from kiwi_catalog.core.errors import ValidationError


def record_observation(
    conn: Any,
    *,
    catalog_agent_id: str,
    kind: str,
    value: float,
    source: str = "",
    evidence_ref: str = "",
    observed_at: str = "",
    expires_at: str = "",
) -> dict[str, Any]:
    """Append one validated private observation and return its stored row.

    *kind* must be a §5.7 kind; *value* must be a finite non-negative number
    (NaN/Inf are rejected so garbage never enters the private store).  When
    *source* is omitted it defaults to ``"local"`` — the design only stores
    local observations, never global claims.
    """
    kind = str(kind or "").strip()
    if kind not in TRUST_OBSERVATION_KINDS:
        raise ValidationError(
            f"invalid trust observation kind {kind!r}; expected one of "
            + ", ".join(sorted(TRUST_OBSERVATION_KINDS))
        )
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"trust observation value must be numeric: {value!r}") from exc
    if not math.isfinite(numeric) or numeric < 0:
        raise ValidationError(f"trust observation value must be a finite non-negative number: {value!r}")

    # 审查 P3：observed_at/expires_at 必须 ISO-8601（可解析）——非法日期此前
    # 直接落库，污染 list_trust_observations 排序与未来的过期判断。
    for label, raw in (("observed_at", observed_at), ("expires_at", expires_at)):
        text = str(raw or "").strip()
        if text:
            try:
                # Python >=3.11 的 fromisoformat 原生接受尾部 "Z"（等价 UTC），
                # 无需手写 "Z" → "+00:00" 替换（FURB162）。
                datetime.fromisoformat(text)
            except ValueError as exc:
                raise ValidationError(
                    f"{label} must be ISO-8601, got {text!r}"
                ) from exc

    source = str(source or "").strip() or "local"
    observation_id = insert_trust_observation(
        conn,
        catalog_agent_id=str(catalog_agent_id).strip(),
        kind=kind,
        value=numeric,
        source=source,
        evidence_ref=str(evidence_ref or "").strip(),
        observed_at=str(observed_at or "").strip(),
        expires_at=str(expires_at or "").strip(),
    )
    row = conn.execute(
        "select * from agent_trust_observations where observation_id = ?",
        (observation_id,),
    ).fetchone()
    return dict(row) if row is not None else {"observation_id": observation_id}


def list_observations(
    conn: Any,
    catalog_agent_id: str = "",
    kind: str = "",
) -> list[dict[str, Any]]:
    """Private read path.  Callers MUST NOT place the result in public output."""
    return list_trust_observations(
        conn,
        catalog_agent_id=str(catalog_agent_id or "").strip(),
        kind=str(kind or "").strip(),
    )


def observation_stats(
    conn: Any,
    catalog_agent_id: str = "",
) -> dict[str, Any]:
    """Opaque local aggregate counts (§5.7) — no observation content.

    Returns totals + counts per kind.  Kinds remain separate (no merged
    reputation score) and the payload contains only numbers, never
    evidence_ref/source/values.  Suitable for the local CLI stats command.
    """
    return {
        "total": count_trust_observations(conn, catalog_agent_id=str(catalog_agent_id or "").strip()),
        "by_kind": trust_observation_counts_by_kind(
            conn, catalog_agent_id=str(catalog_agent_id or "").strip()
        ),
    }
