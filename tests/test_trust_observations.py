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

"""Characterization tests for the extracted trust observation persistence
(T8/T9 split of ``agent_catalog/sqlite_repository.py``).

The helpers are pure statement runners over an injectable connection — they
must keep the exact §5.7 SQL semantics ``services/agent_trust_observations``
relies on (kind-tagged append, observed_at defaulting to ``now_iso()``, the
optional agent/kind filter set, the per-kind group-by) without committing or
owning a transaction boundary.  These tests also lock the re-export surface
that keeps the ``sqlite_repository`` facade and the ``CatalogRepository``
mapping intact.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime
from unittest import mock

import pytest

from kiwi_catalog.agent_catalog import sqlite_repository, trust_observations
from kiwi_catalog.agent_catalog.trust_observations import (
    TRUST_OBSERVATION_KINDS,
    count_trust_observations,
    insert_trust_observation,
    list_trust_observations,
    trust_observation_counts_by_kind,
)
from kiwi_catalog.db.migrations import (
    migration_001_agent_catalog,
    migration_004_agent_trust_observations,
)


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    migration_004_agent_trust_observations(c)
    c.commit()
    yield c
    c.close()


def _seed_observation(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str = "cagt_x",
    kind: str = "protocol_compliance",
    value: float = 1.0,
    source: str = "local",
    evidence_ref: str = "",
    observed_at: str = "",
    expires_at: str = "",
) -> int:
    return insert_trust_observation(
        conn,
        catalog_agent_id=catalog_agent_id,
        kind=kind,
        value=value,
        source=source,
        evidence_ref=evidence_ref,
        observed_at=observed_at,
        expires_at=expires_at,
    )


# ── TRUST_OBSERVATION_KINDS (§5.7) ──────────────────────────────────────────


def test_trust_observation_kinds_match_schema_check(conn) -> None:
    assert TRUST_OBSERVATION_KINDS == frozenset({
        "protocol_compliance",
        "timeout_rate",
        "schema_error_rate",
        "successful_exchange",
        "local_asserted_dispute",
    })


# ── insert_trust_observation (§5.7) ─────────────────────────────────────────


def test_insert_trust_observation_returns_id_and_persists_columns(conn) -> None:
    oid = _seed_observation(
        conn,
        kind="timeout_rate",
        value=0.5,
        source="verifier",
        evidence_ref="domain-check/abc123",
        observed_at="2026-08-09T00:00:00+00:00",
        expires_at="2026-08-10T00:00:00+00:00",
    )
    conn.commit()

    row = conn.execute(
        "select * from agent_trust_observations where observation_id = ?", (oid,)
    ).fetchone()
    assert row is not None
    assert row["catalog_agent_id"] == "cagt_x"
    assert row["kind"] == "timeout_rate"
    assert row["value"] == 0.5
    assert row["source"] == "verifier"
    assert row["evidence_ref"] == "domain-check/abc123"
    assert row["observed_at"] == "2026-08-09T00:00:00+00:00"
    assert row["expires_at"] == "2026-08-10T00:00:00+00:00"


def test_insert_trust_observation_coerces_value_to_float(conn) -> None:
    oid = _seed_observation(conn, kind="schema_error_rate", value=3)
    conn.commit()

    row = conn.execute(
        "select value from agent_trust_observations where observation_id = ?", (oid,)
    ).fetchone()
    assert row is not None
    assert isinstance(row["value"], float)
    assert row["value"] == 3.0


def test_insert_trust_observation_defaults_observed_at_to_now_iso(conn) -> None:
    oid = _seed_observation(conn, source="", evidence_ref="")
    conn.commit()

    row = conn.execute(
        "select observed_at, source, evidence_ref, expires_at"
        " from agent_trust_observations where observation_id = ?",
        (oid,),
    ).fetchone()
    assert row is not None
    # observed_at omitted → time default now_iso() (UTC, ISO-8601, no microseconds).
    assert row["observed_at"]
    datetime.fromisoformat(str(row["observed_at"]))
    # remaining text columns default to ''.
    assert row["source"] == ""
    assert row["evidence_ref"] == ""
    assert row["expires_at"] == ""


def test_insert_trust_observation_respects_explicit_observed_at(conn) -> None:
    oid = _seed_observation(conn, observed_at="2026-08-01T01:00:00+00:00")
    conn.commit()

    row = conn.execute(
        "select observed_at from agent_trust_observations where observation_id = ?", (oid,)
    ).fetchone()
    assert row is not None
    assert row["observed_at"] == "2026-08-01T01:00:00+00:00"


def test_insert_trust_observation_raises_when_lastrowid_missing() -> None:
    fake_conn = mock.Mock(spec=sqlite3.Connection)
    fake_conn.execute.return_value.lastrowid = None
    with pytest.raises(RuntimeError, match="did not return an id"):
        insert_trust_observation(
            fake_conn,
            catalog_agent_id="cagt_x",
            kind="timeout_rate",
            value=1.0,
        )


# ── list_trust_observations (§5.7) ──────────────────────────────────────────


def test_list_trust_observations_orders_by_observed_at_then_id(conn) -> None:
    # Insert order deliberately differs from chronological order.
    last = _seed_observation(conn, kind="timeout_rate", observed_at="2026-08-09T02:00:00+00:00")
    mid = _seed_observation(conn, kind="schema_error_rate", observed_at="2026-08-09T01:00:00+00:00")
    first = _seed_observation(conn, kind="protocol_compliance", observed_at="2026-08-09T00:00:00+00:00")
    conn.commit()

    rows = list_trust_observations(conn)
    assert [r["observation_id"] for r in rows] == [first, mid, last]
    assert [r["kind"] for r in rows] == [
        "protocol_compliance",
        "schema_error_rate",
        "timeout_rate",
    ]


def test_list_trust_observations_tie_breaks_same_timestamp_by_id(conn) -> None:
    a = _seed_observation(conn, observed_at="2026-08-09T00:00:00+00:00")
    b = _seed_observation(conn, observed_at="2026-08-09T00:00:00+00:00")
    conn.commit()

    assert [r["observation_id"] for r in list_trust_observations(conn)] == [a, b]


def test_list_trust_observations_filters_by_agent(conn) -> None:
    _seed_observation(conn, catalog_agent_id="cagt_a")
    _seed_observation(conn, catalog_agent_id="cagt_b")
    conn.commit()

    rows_a = list_trust_observations(conn, catalog_agent_id="cagt_a")
    assert [r["catalog_agent_id"] for r in rows_a] == ["cagt_a"]


def test_list_trust_observations_filters_by_kind(conn) -> None:
    _seed_observation(conn, kind="timeout_rate")
    _seed_observation(conn, kind="schema_error_rate")
    conn.commit()

    rows = list_trust_observations(conn, kind="schema_error_rate")
    assert [r["kind"] for r in rows] == ["schema_error_rate"]


def test_list_trust_observations_filters_by_agent_and_kind(conn) -> None:
    _seed_observation(conn, catalog_agent_id="cagt_a", kind="timeout_rate")
    _seed_observation(conn, catalog_agent_id="cagt_a", kind="schema_error_rate")
    _seed_observation(conn, catalog_agent_id="cagt_b", kind="timeout_rate")
    conn.commit()

    rows = list_trust_observations(conn, catalog_agent_id="cagt_a", kind="timeout_rate")
    assert len(rows) == 1
    assert rows[0]["catalog_agent_id"] == "cagt_a"
    assert rows[0]["kind"] == "timeout_rate"


def test_list_trust_observations_no_filters_returns_all(conn) -> None:
    _seed_observation(conn, catalog_agent_id="cagt_a")
    _seed_observation(conn, catalog_agent_id="cagt_b")
    conn.commit()

    assert len(list_trust_observations(conn)) == 2


# ── count_trust_observations (§5.7) ─────────────────────────────────────────


def test_count_trust_observations_total(conn) -> None:
    _seed_observation(conn, catalog_agent_id="cagt_a")
    _seed_observation(conn, catalog_agent_id="cagt_a")
    _seed_observation(conn, catalog_agent_id="cagt_b")
    conn.commit()

    assert count_trust_observations(conn) == 3


def test_count_trust_observations_scoped_to_agent(conn) -> None:
    _seed_observation(conn, catalog_agent_id="cagt_a")
    _seed_observation(conn, catalog_agent_id="cagt_a")
    _seed_observation(conn, catalog_agent_id="cagt_b")
    conn.commit()

    assert count_trust_observations(conn, catalog_agent_id="cagt_a") == 2
    assert count_trust_observations(conn, catalog_agent_id="cagt_c") == 0


# ── trust_observation_counts_by_kind (§5.7) ─────────────────────────────────


def test_trust_observation_counts_by_kind_groups_and_orders_by_kind(conn) -> None:
    _seed_observation(conn, kind="local_asserted_dispute")
    _seed_observation(conn, kind="protocol_compliance")
    _seed_observation(conn, kind="protocol_compliance")
    _seed_observation(conn, kind="timeout_rate")
    conn.commit()

    assert trust_observation_counts_by_kind(conn) == {
        "local_asserted_dispute": 1,
        "protocol_compliance": 2,
        "timeout_rate": 1,
    }
    # dict preserves group-by ORDER BY kind ordering.
    assert list(trust_observation_counts_by_kind(conn)) == [
        "local_asserted_dispute",
        "protocol_compliance",
        "timeout_rate",
    ]


def test_trust_observation_counts_by_kind_scoped_to_agent(conn) -> None:
    _seed_observation(conn, catalog_agent_id="cagt_a", kind="protocol_compliance")
    _seed_observation(conn, catalog_agent_id="cagt_a", kind="protocol_compliance")
    _seed_observation(conn, catalog_agent_id="cagt_b", kind="timeout_rate")
    conn.commit()

    assert trust_observation_counts_by_kind(conn, catalog_agent_id="cagt_a") == {
        "protocol_compliance": 2
    }
    assert trust_observation_counts_by_kind(conn, catalog_agent_id="cagt_c") == {}


# ── transaction boundary (helpers never commit) ─────────────────────────────


def test_helpers_do_not_commit_transaction_boundary_stays_with_caller(tmp_path) -> None:
    db = tmp_path / "trust.sqlite"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    migration_001_agent_catalog(conn)
    migration_004_agent_trust_observations(conn)
    conn.commit()

    _seed_observation(conn)
    _seed_observation(conn, kind="timeout_rate")
    # No commit: a second connection must not see the uncommitted writes.
    other = sqlite3.connect(db)
    try:
        other.row_factory = sqlite3.Row
        before = other.execute("select count(*) from agent_trust_observations").fetchone()
        assert before is not None and before[0] == 0
        conn.commit()
        after = other.execute("select count(*) from agent_trust_observations").fetchone()
        assert after is not None and after[0] == 2
    finally:
        other.close()
    conn.close()


# ── parameterization ────────────────────────────────────────────────────────


def test_helpers_parameterize_values_no_injection(conn) -> None:
    evil = "cagt_1' OR '1'='1"
    _seed_observation(conn, catalog_agent_id=evil, kind="timeout_rate")
    conn.commit()

    assert len(list_trust_observations(conn, catalog_agent_id=evil)) == 1
    assert len(list_trust_observations(conn, catalog_agent_id="cagt_1")) == 0
    assert count_trust_observations(conn, catalog_agent_id=evil) == 1
    assert count_trust_observations(conn) == 1
    assert trust_observation_counts_by_kind(conn, catalog_agent_id=evil) == {"timeout_rate": 1}


# ── module surface and facade re-export ─────────────────────────────────────


def test_trust_observations_module_exports_only_persistence_helpers() -> None:
    assert set(trust_observations.__all__) == {
        "TRUST_OBSERVATION_KINDS",
        "insert_trust_observation",
        "list_trust_observations",
        "count_trust_observations",
        "trust_observation_counts_by_kind",
    }


def test_repository_reexports_leaf_names_unchanged() -> None:
    """The ``sqlite_repository`` facade must keep exposing the same objects so
    existing callers and the ``CatalogRepository`` abstraction mapping keep
    resolving by identity."""
    for name in trust_observations.__all__:
        assert getattr(sqlite_repository, name, None) is getattr(trust_observations, name), name
