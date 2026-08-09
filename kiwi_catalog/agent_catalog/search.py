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

"""Catalog agent search — hard filters + deterministic ranking (§8.3).

Phase 1 uses SQLite WHERE clauses for hard filters and a deterministic
ORDER BY for ranking.  LLM-based ranking is explicitly deferred to a
future phase.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import (
    search_catalog_agents as _repo_search,
)
from kiwi_catalog.services.catalog_runtime_metrics import record_search


def search_catalog_agents(
    conn: sqlite3.Connection,
    q: str = "",
    category: str = "",
    skill: str = "",
    capability: str = "",
    protocol: str = "",
    hosting_mode: str = "",
    verification_status: str = "",
    verified_after: str = "",
    verification_level: str = "",
    freshness_state: str = "",
    administrative_state: str = "",
    handoff_destination_types: str = "",
    limit: int = 20,
    cursor: str = "",
) -> tuple[list[dict[str, Any]], str | None]:
    """Hard-filtered, deterministically-ordered agent catalog search.

    Filters are AND-ed: every non-empty filter narrows the result set.
    Ordering (§8.3): verification_status rank → last_verified_at desc →
    display_name → catalog_agent_id.

    Records §24 runtime metrics (``catalog_search_latency`` +
    ``catalog_search_result_count``).  Exceptions are not instrumented —
    a search that raises is a caller bug, not a runtime signal.

    Returns (results, next_cursor).  next_cursor is None at the last page.

    TODO(Phase 2): region / delivery_coverage filters when data model supports them.
    """
    start = time.monotonic()
    results, next_cursor = _repo_search(
        conn,
        q=q,
        category=category,
        skill=skill,
        capability=capability,
        protocol=protocol,
        hosting_mode=hosting_mode,
        verification_status=verification_status,
        verified_after=verified_after,
        verification_level=verification_level,
        freshness_state=freshness_state,
        administrative_state=administrative_state,
        handoff_destination_types=handoff_destination_types,
        limit=limit,
        cursor=cursor,
    )
    record_search(time.monotonic() - start, len(results))
    return results, next_cursor
