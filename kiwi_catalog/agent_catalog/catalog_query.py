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

"""Pure SQL construction for the catalog agent list/search page queries.

Extracted from ``agent_catalog/sqlite_repository.py`` (T8/T9 hotspot
convergence): the three list/search entry points (``search_catalog_agents``,
``list_catalog_agents``, ``list_catalog_agents_by_merchant``) each duplicated
the same merchant-joined base ``SELECT`` fragment, the same §8.3
deterministic ``ORDER BY`` (verification_status rank → last_verified_at desc
→ display_name → catalog_agent_id), the same legacy single-key list cursor
predicate, and the same ``limit + 1`` page-boundary convention.

This helper only assembles SQL fragments and parameter lists; it never
touches the connection, commits, locks, or transactions.  The §8.3 ordering
is composed from the same rank/sort-name constants the keyset cursor
predicate uses (``pagination``), so the cursor predicate and the sort key
share one source of truth.  ``sqlite_repository`` keeps its public entry
points unchanged and re-exports nothing public from here.
"""

from __future__ import annotations

from typing import Any

from kiwi_catalog.agent_catalog.pagination import (
    AGENT_SORT_NAME,
    AGENT_STATUS_RANK_CASE,
)

__all__ = [
    "AGENT_BASE_SELECT",
    "AGENT_ORDER_BY",
    "agent_list_cursor_clause",
    "agent_page_query",
]


# Base projection shared by every catalog list/search page query: the catalog
# agent row plus its merchant display columns (left join — agents without a
# merchant still appear).
AGENT_BASE_SELECT = (
    "select ca.*, m.name as merchant_name, m.city as merchant_city,\n"
    "       m.service_area as merchant_service_area,\n"
    "       m.tags_json as merchant_tags_json\n"
    "from catalog_agents ca\n"
    "left join merchants m on m.id = ca.merchant_id"
)

# §8.3 deterministic ordering.  Composed from the same rank case and sort
# name the keyset cursor predicate uses (pagination.agent_cursor_predicate)
# so the cursor predicate and the ORDER BY can never drift apart — the
# historical bug class P1-6 (cursor encoded only catalog_agent_id, dropping/
# duplicating rows across rank/last_verified_at groups).
AGENT_ORDER_BY = (
    "order by\n"
    + AGENT_STATUS_RANK_CASE.strip()
    + ",\n"
    + "    ca.last_verified_at desc,\n"
    + "    "
    + AGENT_SORT_NAME
    + ",\n"
    + "    ca.catalog_agent_id"
)


def agent_list_cursor_clause(cursor: str) -> tuple[str, list[Any]]:
    """Legacy single-key list cursor: continue after *cursor* (by id).

    Used by the plain list entry points (``list_catalog_agents`` /
    ``list_catalog_agents_by_merchant``), which page strictly on
    ``catalog_agent_id``.  Search uses the v2 keyset predicate instead.
    """
    return "ca.catalog_agent_id > ?", [cursor]


def agent_page_query(
    where_clause: str,
    params: list[Any],
    limit: int,
) -> tuple[str, list[Any]]:
    """Assemble a deterministic catalog-agent list/search page query.

    Appends the ``limit + 1`` sentinel row (page-boundary detection) so every
    caller runs the same SQL with the same parameter ordering: where-clause
    params first, then the limit marker.
    """
    page_params = list(params)
    page_params.append(limit + 1)
    sql = (
        AGENT_BASE_SELECT
        + " "
        + where_clause
        + " "
        + AGENT_ORDER_BY
        + " limit ?"
    )
    return sql, page_params
