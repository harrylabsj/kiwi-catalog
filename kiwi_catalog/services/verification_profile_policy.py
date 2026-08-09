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

"""Pure profile-stage policy and shapes for the §6 verification ladder.

Extracted from ``agent_verification.py`` (T8/T9 hotspot convergence): the
rung classification constants, the ``ProfileFailure`` / ``Profiles`` /
``ReusedSnapshotFetch`` profile-stage data shapes, and the snapshot
freshness/staleness policy (ISO ``fresh_until`` parsing + the §7.2 gate).
``agent_verification.py`` keeps the DB reads and the state-machine
orchestration and delegates the pure decisions here, so the public facade
and compatible entry points stay unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from kiwi_catalog.discovery.agent_card import AgentCardResult
from kiwi_catalog.discovery.ucp import UcpProfileResult
from kiwi_catalog.discovery.verifier import (
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
    DOMAIN_VERIFIED,
    PROFILE_VALID,
    REJECTED,
)

# The ladder rungs that carry a persisted profile (anything above DISCOVERED).
LADDER_RUNGS: frozenset[str] = frozenset(
    {PROFILE_VALID, DOMAIN_VERIFIED, AGENT_VERIFIED, COMMERCE_VERIFIED}
)

# Rungs that count as "verified" for the §24 funnel (domain-control proof §6).
VERIFIED_RUNGS: frozenset[str] = frozenset(
    {DOMAIN_VERIFIED, AGENT_VERIFIED, COMMERCE_VERIFIED}
)


class ProfileFailure(Exception):
    """Raised internally when the profile stage cannot complete.

    Carries the semantic target status (§6: rejected / unreachable / stale)
    so the caller can apply the correct terminal transition.
    """

    def __init__(self, target_status: str, reason: str) -> None:
        super().__init__(reason)
        self.target_status = target_status
        self.reason = reason


@dataclass
class Profiles:
    """Validated profile pair shared across the ladder stages."""

    card: AgentCardResult
    ucp: UcpProfileResult
    urls: dict[str, str]
    snapshot_ids: tuple[int, ...]


class ReusedSnapshotFetch:
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
            raise ProfileFailure(
                REJECTED, f"stored snapshot raw_json is not valid JSON: {exc}"
            ) from exc

    @property
    def is_not_modified(self) -> bool:
        return True

    @property
    def is_success(self) -> bool:
        return True


def parse_iso_ts(value: str) -> float | None:
    """Parse an ISO timestamp to epoch seconds; naive timestamps are UTC.

    Returns ``None`` for empty or unparseable input so callers can treat a
    missing ``fresh_until`` / ``expires_at`` as an expired window (fail-open
    to re-verification).
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def profile_is_stale(fresh_until_iso_values: Sequence[str], now_ts: float) -> bool:
    """True when any required profile snapshot is missing or past its fresh_until.

    ``fresh_until_iso_values`` holds one ``fresh_until`` ISO string per required
    snapshot kind (agent_card, ucp).  An empty or unparseable value means the
    snapshot is missing or has no usable ``fresh_until`` and therefore counts as
    stale (the §7.2 gate falls open to re-verification).
    """
    for value in fresh_until_iso_values:
        parsed = parse_iso_ts(value)
        if parsed is None or now_ts >= parsed:
            return True
    return False


__all__ = [
    "LADDER_RUNGS",
    "VERIFIED_RUNGS",
    "ProfileFailure",
    "Profiles",
    "ReusedSnapshotFetch",
    "parse_iso_ts",
    "profile_is_stale",
]
