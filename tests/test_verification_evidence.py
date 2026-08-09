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

"""Characterization tests for the extracted verification evidence persistence
(T8/T9 split of ``agent_catalog/sqlite_repository.py``).

The helpers are pure statement runners over an injectable connection — they
must keep the exact §5.5/§5.6 SQL semantics the verification ladder relies on
(append-only snapshots, latest-by-checked_at evidence, the optional result
filter used by the v0.3 §7.1 level recomputation) without committing or owning
a transaction boundary.  These tests also lock the re-export surface that keeps
the ``sqlite_repository`` facade and the ``CatalogRepository`` mapping intact.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

import pytest

from kiwi_catalog.agent_catalog import sqlite_repository, verification_evidence
from kiwi_catalog.agent_catalog.verification_evidence import (
    insert_profile_snapshot,
    insert_verification,
    latest_profile_snapshot,
    latest_verification,
    list_profile_snapshots,
    list_verifications,
)
from kiwi_catalog.db.migrations import migration_001_agent_catalog


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    c.commit()
    yield c
    c.close()


def _seed_snapshot(
    conn: sqlite3.Connection,
    *,
    profile_type: str = "agent_card",
    catalog_agent_id: str = "cagt_x",
    fetched_at: str = "2026-08-09T00:00:00+00:00",
) -> int:
    return insert_profile_snapshot(
        conn,
        catalog_agent_id=catalog_agent_id,
        profile_type=profile_type,
        source_url="https://acme.example/.well-known/agent-card.json",
        etag='"abc"',
        last_modified="2026-08-09T00:00:00+00:00",
        content_hash="sha256:deadbeef",
        raw_json='{"display_name":"Acme"}',
        fetched_at=fetched_at,
        fresh_until="2026-08-10T00:00:00+00:00",
        validation_status="valid",
    )


def _seed_verification(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str = "cagt_x",
    verification_type: str = "domain_control",
    result: str = "passed",
    checked_at: str = "2026-08-09T00:00:00+00:00",
) -> int:
    return insert_verification(
        conn,
        catalog_agent_id=catalog_agent_id,
        verification_type=verification_type,
        result=result,
        evidence_json='{"verification_type":"domain_control","result":"passed"}',
        checked_at=checked_at,
        expires_at="2026-08-10T00:00:00+00:00",
    )


# ── insert_profile_snapshot (§5.5) ──────────────────────────────────────────


def test_insert_profile_snapshot_returns_id_and_persists_columns(conn) -> None:
    sid = _seed_snapshot(conn)
    conn.commit()

    row = conn.execute(
        "select * from agent_profile_snapshots where snapshot_id = ?", (sid,)
    ).fetchone()
    assert row is not None
    assert row["catalog_agent_id"] == "cagt_x"
    assert row["profile_type"] == "agent_card"
    assert row["source_url"] == "https://acme.example/.well-known/agent-card.json"
    assert row["etag"] == '"abc"'
    assert row["last_modified"] == "2026-08-09T00:00:00+00:00"
    assert row["content_hash"] == "sha256:deadbeef"
    assert row["raw_json"] == '{"display_name":"Acme"}'
    assert row["fetched_at"] == "2026-08-09T00:00:00+00:00"
    assert row["fresh_until"] == "2026-08-10T00:00:00+00:00"
    assert row["validation_status"] == "valid"


def test_insert_profile_snapshot_is_append_only_history(conn) -> None:
    _seed_snapshot(conn, fetched_at="2026-08-09T00:00:00+00:00")
    _seed_snapshot(conn, fetched_at="2026-08-09T01:00:00+00:00")
    conn.commit()

    rows = conn.execute(
        "select snapshot_id from agent_profile_snapshots order by snapshot_id"
    ).fetchall()
    assert len(rows) == 2


# ── latest_profile_snapshot (§5.5) ──────────────────────────────────────────


def test_latest_profile_snapshot_returns_newest_for_profile_type(conn) -> None:
    _seed_snapshot(conn, profile_type="agent_card", fetched_at="2026-08-09T00:00:00+00:00")
    latest_id = _seed_snapshot(conn, profile_type="agent_card", fetched_at="2026-08-09T02:00:00+00:00")
    _seed_snapshot(conn, profile_type="ucp", fetched_at="2026-08-09T03:00:00+00:00")
    conn.commit()

    latest = latest_profile_snapshot(conn, "cagt_x", "agent_card")
    assert latest is not None
    assert latest["snapshot_id"] == latest_id
    assert latest["fetched_at"] == "2026-08-09T02:00:00+00:00"


def test_latest_profile_snapshot_returns_none_when_type_missing(conn) -> None:
    _seed_snapshot(conn, profile_type="agent_card")
    conn.commit()

    assert latest_profile_snapshot(conn, "cagt_x", "ucp") is None
    assert latest_profile_snapshot(conn, "cagt_other", "agent_card") is None


def test_latest_profile_snapshot_returns_mapping_with_all_columns(conn) -> None:
    _seed_snapshot(conn)
    conn.commit()

    latest = latest_profile_snapshot(conn, "cagt_x", "agent_card")
    assert latest is not None
    assert set(latest) == {
        "snapshot_id",
        "catalog_agent_id",
        "profile_type",
        "source_url",
        "etag",
        "last_modified",
        "content_hash",
        "raw_json",
        "fetched_at",
        "fresh_until",
        "validation_status",
    }


# ── list_profile_snapshots (§5.5) ───────────────────────────────────────────


def test_list_profile_snapshots_orders_by_snapshot_id(conn) -> None:
    _seed_snapshot(conn, fetched_at="2026-08-09T02:00:00+00:00")
    first = _seed_snapshot(conn, fetched_at="2026-08-09T00:00:00+00:00")
    conn.commit()

    rows = list_profile_snapshots(conn, "cagt_x")
    assert [r["snapshot_id"] for r in rows] == [first - 1, first]  # insert order


def test_list_profile_snapshots_scoped_to_agent(conn) -> None:
    _seed_snapshot(conn, catalog_agent_id="cagt_a")
    _seed_snapshot(conn, catalog_agent_id="cagt_b")
    conn.commit()

    assert len(list_profile_snapshots(conn, "cagt_a")) == 1
    assert len(list_profile_snapshots(conn, "cagt_b")) == 1


# ── insert_verification (§5.6) ──────────────────────────────────────────────


def test_insert_verification_returns_id_and_persists_columns(conn) -> None:
    vid = _seed_verification(conn)
    conn.commit()

    row = conn.execute(
        "select * from agent_verifications where verification_id = ?", (vid,)
    ).fetchone()
    assert row is not None
    assert row["catalog_agent_id"] == "cagt_x"
    assert row["verification_type"] == "domain_control"
    assert row["result"] == "passed"
    assert row["evidence_json"] == '{"verification_type":"domain_control","result":"passed"}'
    assert row["checked_at"] == "2026-08-09T00:00:00+00:00"
    assert row["expires_at"] == "2026-08-10T00:00:00+00:00"


# ── latest_verification (§5.6, §7.1 evidence recomputation) ────────────────


def test_latest_verification_returns_newest_by_checked_at(conn) -> None:
    _seed_verification(conn, checked_at="2026-08-09T00:00:00+00:00")
    latest_id = _seed_verification(conn, checked_at="2026-08-09T02:00:00+00:00")
    conn.commit()

    latest = latest_verification(conn, "cagt_x", "domain_control")
    assert latest is not None
    assert latest["verification_id"] == latest_id
    assert latest["checked_at"] == "2026-08-09T02:00:00+00:00"


def test_latest_verification_result_filter_only_matches_passed_evidence(conn) -> None:
    """审查 P1-7: 降级重算只认「最新 passed 证据」——failed 行不得屏蔽历史 passed 证据."""
    passed_id = _seed_verification(conn, result="passed", checked_at="2026-08-09T00:00:00+00:00")
    _seed_verification(conn, result="failed", checked_at="2026-08-09T02:00:00+00:00")
    conn.commit()

    latest = latest_verification(conn, "cagt_x", "domain_control", result="passed")
    assert latest is not None
    assert latest["verification_id"] == passed_id
    assert latest["result"] == "passed"


def test_latest_verification_result_filter_none_when_no_match(conn) -> None:
    _seed_verification(conn, result="failed")
    conn.commit()

    assert latest_verification(conn, "cagt_x", "domain_control", result="passed") is None


def test_latest_verification_returns_none_when_type_absent(conn) -> None:
    _seed_verification(conn, verification_type="domain_control")
    conn.commit()

    assert latest_verification(conn, "cagt_x", "commerce_capability") is None


def test_latest_verification_tie_breaks_by_verification_id(conn) -> None:
    a = _seed_verification(conn, checked_at="2026-08-09T00:00:00+00:00")
    b = _seed_verification(conn, checked_at="2026-08-09T00:00:00+00:00")
    conn.commit()

    latest = latest_verification(conn, "cagt_x", "domain_control")
    assert latest is not None
    assert latest["verification_id"] == max(a, b)


# ── list_verifications (§5.6) ───────────────────────────────────────────────


def test_list_verifications_orders_by_verification_id(conn) -> None:
    _seed_verification(conn, verification_type="agent_identity")
    first = _seed_verification(conn, verification_type="commerce_capability")
    conn.commit()

    rows = list_verifications(conn, "cagt_x")
    assert [r["verification_id"] for r in rows] == [first - 1, first]


def test_list_verifications_scoped_to_agent(conn) -> None:
    _seed_verification(conn, catalog_agent_id="cagt_a")
    _seed_verification(conn, catalog_agent_id="cagt_b")
    conn.commit()

    assert len(list_verifications(conn, "cagt_a")) == 1
    assert len(list_verifications(conn, "cagt_b")) == 1


# ── transaction boundary (helpers never commit) ─────────────────────────────


def test_helpers_do_not_commit_transaction_boundary_stays_with_caller(tmp_path) -> None:
    db = tmp_path / "evidence.sqlite"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    migration_001_agent_catalog(conn)
    conn.commit()

    _seed_snapshot(conn)
    _seed_verification(conn)
    # No commit: a second connection must not see the uncommitted writes.
    other = sqlite3.connect(db)
    try:
        other.row_factory = sqlite3.Row
        before_snap = other.execute(
            "select count(*) from agent_profile_snapshots"
        ).fetchone()
        before_ver = other.execute(
            "select count(*) from agent_verifications"
        ).fetchone()
        assert before_snap is not None and before_snap[0] == 0
        assert before_ver is not None and before_ver[0] == 0
        conn.commit()
        after_snap = other.execute(
            "select count(*) from agent_profile_snapshots"
        ).fetchone()
        after_ver = other.execute(
            "select count(*) from agent_verifications"
        ).fetchone()
        assert after_snap is not None and after_snap[0] == 1
        assert after_ver is not None and after_ver[0] == 1
    finally:
        other.close()
    conn.close()


# ── parameterization ────────────────────────────────────────────────────────


def test_helpers_parameterize_values_no_injection(conn) -> None:
    evil = "cagt_1' OR '1'='1"
    _seed_snapshot(conn, catalog_agent_id=evil)
    _seed_verification(conn, catalog_agent_id=evil)
    conn.commit()

    assert latest_profile_snapshot(conn, evil, "agent_card") is not None
    assert latest_profile_snapshot(conn, "cagt_1", "agent_card") is None
    assert [r["catalog_agent_id"] for r in list_verifications(conn, evil)] == [evil]


# ── module surface and facade re-export ─────────────────────────────────────


def test_evidence_module_exports_only_persistence_helpers() -> None:
    assert set(verification_evidence.__all__) == {
        "insert_profile_snapshot",
        "latest_profile_snapshot",
        "list_profile_snapshots",
        "insert_verification",
        "latest_verification",
        "list_verifications",
    }


def test_repository_reexports_leaf_functions_unchanged() -> None:
    """The ``sqlite_repository`` facade must keep exposing the same function
    objects so existing callers and the ``CatalogRepository`` abstraction
    mapping keep resolving."""
    for name in verification_evidence.__all__:
        assert callable(getattr(sqlite_repository, name, None)), name
        assert getattr(sqlite_repository, name) is getattr(verification_evidence, name), name
