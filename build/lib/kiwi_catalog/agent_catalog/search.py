"""Catalog agent search — hard filters + deterministic ranking (§8.3).

Phase 1 uses SQLite WHERE clauses for hard filters and a deterministic
ORDER BY for ranking.  LLM-based ranking is explicitly deferred to a
future phase.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import search_catalog_agents as _repo_search
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
        limit=limit,
        cursor=cursor,
    )
    record_search(time.monotonic() - start, len(results))
    return results, next_cursor
