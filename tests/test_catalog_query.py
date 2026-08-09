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

"""Characterization tests for the extracted catalog list/search query SQL
construction (T8/T9 split of ``agent_catalog/sqlite_repository.py``).

``catalog_query`` only assembles SQL fragments and parameter lists — it never
touches the connection, commit, locks, or transaction boundary.  These tests
lock the composed SQL semantics the three repository list/search entry points
depend on:

* the merchant-joined base projection (``AGENT_BASE_SELECT``);
* the §8.3 deterministic ORDER BY (rank → last_verified_at desc →
  display_name → catalog_agent_id), composed from the same sort-key
  constants the keyset cursor predicate uses;
* the legacy single-key list cursor predicate;
* the ``limit + 1`` page-boundary convention and parameter ordering.

The end-to-end tests run the composed SQL through the actual repository
functions against a real in-memory schema so behaviour is pinned exactly.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest

from kiwi_catalog.agent_catalog import catalog_query, sqlite_repository
from kiwi_catalog.agent_catalog.catalog_query import (
    AGENT_BASE_SELECT,
    AGENT_ORDER_BY,
    agent_list_cursor_clause,
    agent_page_query,
)
from kiwi_catalog.db.migrations import (
    migration_001_agent_catalog,
    migration_008_three_state_domains,
    migration_009_shadow_tables,
)


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    migration_008_three_state_domains(c)
    migration_009_shadow_tables(c)
    c.commit()
    yield c
    c.close()


# ── module surface ──────────────────────────────────────────────────────────


def test_catalog_query_module_exports_only_query_surface() -> None:
    assert catalog_query.__all__ == [
        "AGENT_BASE_SELECT",
        "AGENT_ORDER_BY",
        "agent_list_cursor_clause",
        "agent_page_query",
    ]


# ── base fragments ──────────────────────────────────────────────────────────


def test_base_select_joins_merchant_columns() -> None:
    assert "ca.*" in AGENT_BASE_SELECT
    assert "m.name as merchant_name" in AGENT_BASE_SELECT
    assert "m.tags_json as merchant_tags_json" in AGENT_BASE_SELECT
    assert "left join merchants m on m.id = ca.merchant_id" in AGENT_BASE_SELECT


def test_order_by_covers_full_deterministic_sort_key() -> None:
    # §8.3 sort key: verification_status rank → last_verified_at desc →
    # display_name → catalog_agent_id.  The rank case and sort name come from
    # pagination so the cursor predicate and ORDER BY share one source.
    assert "order by" in AGENT_ORDER_BY
    assert "last_verified_at desc" in AGENT_ORDER_BY
    assert "coalesce(ca.display_name, '')" in AGENT_ORDER_BY
    assert "ca.catalog_agent_id" in AGENT_ORDER_BY
    # Every rank literal the cursor predicate knows must be ranked here.
    for status in (
        "commerce_verified",
        "agent_verified",
        "domain_verified",
        "profile_valid",
        "discovered",
        "stale",
        "unreachable",
        "suspended",
        "rejected",
    ):
        assert f"when '{status}' then" in AGENT_ORDER_BY


def test_order_by_and_cursor_predicate_share_sort_key_constants() -> None:
    # Drift guard (P1-6): the ORDER BY must be keyed identically to the v2
    # cursor predicate — both derive from pagination.AGENT_STATUS_RANK_CASE /
    # AGENT_SORT_NAME, so they can never disagree.
    assert catalog_query.AGENT_ORDER_BY
    from kiwi_catalog.agent_catalog import pagination

    assert pagination.AGENT_STATUS_RANK_CASE
    assert pagination.AGENT_SORT_NAME in AGENT_ORDER_BY


# ── agent_list_cursor_clause ────────────────────────────────────────────────


def test_agent_list_cursor_clause_is_single_key_gt_predicate() -> None:
    assert agent_list_cursor_clause("cagt_9") == (
        "ca.catalog_agent_id > ?",
        ["cagt_9"],
    )


def test_agent_list_cursor_clause_handles_empty_and_invalid_cursor() -> None:
    # The clause is a pure predicate over the raw cursor value — empty or
    # arbitrary strings are passed through untouched (the caller decides
    # whether a cursor is present at all).
    assert agent_list_cursor_clause("") == ("ca.catalog_agent_id > ?", [""])
    assert agent_list_cursor_clause("v2:not-a-real-cursor") == (
        "ca.catalog_agent_id > ?",
        ["v2:not-a-real-cursor"],
    )


# ── agent_page_query: SQL shape and parameter order ─────────────────────────


def test_agent_page_query_appends_limit_marker_and_keeps_param_order() -> None:
    sql, params = agent_page_query(
        "where ca.merchant_id = ? and ca.verification_status = ?",
        ["m_1", "commerce_verified"],
        20,
    )

    assert sql.startswith(AGENT_BASE_SELECT)
    assert "where ca.merchant_id = ? and ca.verification_status = ?" in sql
    assert AGENT_ORDER_BY in sql
    assert "limit ?" in sql
    # limit + 1 sentinel is appended after the where-clause params.
    assert params == ["m_1", "commerce_verified", 21]


def test_agent_page_query_with_empty_where_has_no_where_keyword() -> None:
    sql, params = agent_page_query("", [], 20)

    assert "where" not in sql
    assert params == [21]


def test_agent_page_query_placeholders_match_params() -> None:
    where = (
        "where ca.hosting_mode = ? and (ca.display_name like ? escape '\\'"
        " or ca.provider_name like ? escape '\\')"
    )
    params = ["hosted", "a%", "a%"]
    sql, page_params = agent_page_query(where, params, 5)

    # 3 where placeholders + 1 limit marker.
    assert sql.count("?") == 4
    assert len(page_params) == 4
    assert page_params[:3] == params
    assert page_params[3] == 6


def test_agent_page_query_does_not_mutate_caller_params() -> None:
    original = ["m_1"]
    _, page_params = agent_page_query("where ca.merchant_id = ?", original, 20)

    assert original == ["m_1"]
    assert page_params == ["m_1", 21]


# ── end-to-end: deterministic ordering and pagination semantics ─────────────


def _seed_agent(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    *,
    merchant_id: str = "",
    display_name: str,
    verification_status: str,
    last_verified_at: str = "",
    handoff_destination_types: str = "[]",
    merchant_tags_json: str = "[]",
) -> None:
    conn.execute(
        """
        insert into catalog_agents(
            catalog_agent_id, merchant_id, hosted_runtime_agent_id, display_name,
            provider_name, canonical_domain, agent_type, source_type, lifecycle_status,
            verification_status, hosting_mode, verification_level, freshness_state,
            administrative_state, handoff_destination_types, last_refresh_attempt_at,
            last_refresh_result, first_seen_at, last_seen_at, last_verified_at,
            created_at, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            catalog_agent_id,
            merchant_id or None,
            None,
            display_name,
            f"provider-{catalog_agent_id}",
            f"{catalog_agent_id}.example",
            "agent",
            "hosted",
            "active",
            verification_status,
            "hosted",
            verification_status
            if verification_status
            in ("discovered", "profile_valid", "domain_verified", "agent_verified", "commerce_verified")
            else "discovered",
            "stale" if verification_status == "stale" else "fresh",
            "rejected"
            if verification_status == "rejected"
            else "suspended"
            if verification_status == "suspended"
            else "active",
            handoff_destination_types,
            "",
            "",
            "2026-08-01T00:00:00",
            "2026-08-01T00:00:00",
            last_verified_at,
            "2026-08-01T00:00:00",
            "2026-08-01T00:00:00",
        ),
    )
    if merchant_id:
        conn.execute(
            """
            insert or ignore into merchants(id, name, city, service_area, contact, hours,
                automation_boundaries, tags_json, created_at, updated_at)
            values (?, ?, '', '', '', '', '', ?, ?, ?)
            """,
            (merchant_id, f"merchant-{merchant_id}", merchant_tags_json,
             "2026-08-01T00:00:00", "2026-08-01T00:00:00"),
        )
    conn.commit()


def test_search_catalog_agents_orders_by_verification_rank(conn) -> None:
    _seed_agent(conn, "cagt_rejected", display_name="Zeta", verification_status="rejected")
    _seed_agent(conn, "cagt_discovered", display_name="Alpha", verification_status="discovered")
    _seed_agent(
        conn,
        "cagt_commerce",
        display_name="Beta",
        verification_status="commerce_verified",
        last_verified_at="2026-08-01T00:00:00",
    )

    results, next_cursor = sqlite_repository.search_catalog_agents(conn)

    assert [r["catalog_agent_id"] for r in results] == [
        "cagt_commerce",
        "cagt_discovered",
        "cagt_rejected",
    ]
    assert next_cursor is None


def test_search_catalog_agents_within_same_rank_sorts_by_lva_desc_then_name(conn) -> None:
    _seed_agent(
        conn, "cagt_b", display_name="Beta", verification_status="commerce_verified",
        last_verified_at="2026-08-01T00:00:00",
    )
    _seed_agent(
        conn, "cagt_a", display_name="Alpha", verification_status="commerce_verified",
        last_verified_at="2026-08-02T00:00:00",
    )

    results, _ = sqlite_repository.search_catalog_agents(conn)

    # Same rank: later last_verified_at first, then display_name.
    assert [r["catalog_agent_id"] for r in results] == ["cagt_a", "cagt_b"]


def test_list_catalog_agents_pages_with_legacy_cursor(conn) -> None:
    for i in range(5):
        _seed_agent(
            conn,
            f"cagt_{i:02d}",
            display_name=f"Agent {i}",
            verification_status="discovered",
        )

    page1, cursor1 = sqlite_repository.list_catalog_agents(conn, limit=2)
    assert [r["catalog_agent_id"] for r in page1] == ["cagt_00", "cagt_01"]
    assert cursor1 is not None

    # The list entry point pages on the legacy single-key cursor
    # (catalog_query.agent_list_cursor_clause → ca.catalog_agent_id > ?).
    # Feed the previous page's last id back as the raw cursor value.
    page2, cursor2 = sqlite_repository.list_catalog_agents(
        conn, limit=2, cursor="cagt_01"
    )
    assert [r["catalog_agent_id"] for r in page2] == ["cagt_02", "cagt_03"]
    assert cursor2 is not None

    page3, cursor3 = sqlite_repository.list_catalog_agents(
        conn, limit=2, cursor="cagt_03"
    )
    assert [r["catalog_agent_id"] for r in page3] == ["cagt_04"]
    assert cursor3 is None


def test_list_catalog_agents_by_merchant_filters_and_pages(conn) -> None:
    _seed_agent(
        conn, "cagt_m1", merchant_id="m_1", display_name="Owned",
        verification_status="discovered",
    )
    _seed_agent(
        conn, "cagt_m2", merchant_id="m_1", display_name="Owned 2",
        verification_status="discovered",
    )
    _seed_agent(
        conn, "cagt_other", merchant_id="m_2", display_name="Other",
        verification_status="discovered",
    )

    results, next_cursor = sqlite_repository.list_catalog_agents_by_merchant(conn, "m_1")
    assert [r["catalog_agent_id"] for r in results] == ["cagt_m1", "cagt_m2"]
    assert next_cursor is None


def test_search_filters_by_q_and_merchant_category(conn) -> None:
    _seed_agent(conn, "cagt_acme", display_name="Acme Foods", verification_status="discovered")
    _seed_agent(conn, "cagt_other", display_name="Other", verification_status="discovered")
    _seed_agent(
        conn, "cagt_cat", merchant_id="m_cat", display_name="Categorized",
        verification_status="discovered", merchant_tags_json='["食品"]',
    )

    by_q, _ = sqlite_repository.search_catalog_agents(conn, q="acme")
    assert [r["catalog_agent_id"] for r in by_q] == ["cagt_acme"]

    by_category, _ = sqlite_repository.search_catalog_agents(conn, category="食品")
    assert [r["catalog_agent_id"] for r in by_category] == ["cagt_cat"]


def test_search_like_metacharacters_are_escaped(conn) -> None:
    _seed_agent(conn, "cagt_percent", display_name="100% pure", verification_status="discovered")
    _seed_agent(conn, "cagt_plain", display_name="100 pure", verification_status="discovered")

    # q="100%" must match only the literal percent row, not every name
    # starting with "100" (escape '\\' + _like_escaped).
    results, _ = sqlite_repository.search_catalog_agents(conn, q="100%")
    assert [r["catalog_agent_id"] for r in results] == ["cagt_percent"]
