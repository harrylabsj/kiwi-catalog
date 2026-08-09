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

"""Characterization tests for the extracted catalog audit persistence
(T8/T9 split of ``agent_catalog/sqlite_repository.py``).

``append_catalog_audit`` is a stateless statement runner over an injectable
connection — it must keep the exact ``audit_events`` semantics the
verification / merchant-token / listings services rely on (the
``schema_version`` / ``event_type`` / ``catalog_agent_id`` payload defaults,
caller-dict isolation, the returned new event id) without committing or
owning a transaction boundary.  These tests also lock the re-export surface
that keeps the ``sqlite_repository`` facade and the ``CatalogRepository``
mapping intact.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import datetime
from typing import Any
from unittest import mock

import pytest

from kiwi_catalog.agent_catalog import catalog_audit, sqlite_repository
from kiwi_catalog.agent_catalog.catalog_audit import append_catalog_audit
from kiwi_catalog.db.migrations import (
    migration_001_agent_catalog,
    migration_009_shadow_tables,
)


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    migration_009_shadow_tables(c)
    c.commit()
    yield c
    c.close()


def _seed_audit(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str = "cagt_x",
    actor: str = "admin",
    event: str = "catalog_agent_suspended",
    details: dict[str, Any] | None = None,
) -> int:
    return append_catalog_audit(conn, catalog_agent_id, actor, event, details)


# ── append_catalog_audit: base row ──────────────────────────────────────────


def test_append_catalog_audit_returns_id_and_persists_columns(conn) -> None:
    event_id = _seed_audit(
        conn,
        catalog_agent_id="cagt-1",
        actor="admin",
        event="catalog_agent_suspended",
        details={"reason": "spam"},
    )
    conn.commit()

    row = conn.execute(
        "select id, conversation_id, actor, event, details_json, created_at"
        " from audit_events where id = ?",
        (event_id,),
    ).fetchone()
    assert row is not None
    assert row["conversation_id"] == ""
    assert row["actor"] == "admin"
    assert row["event"] == "catalog_agent_suspended"
    details = json.loads(row["details_json"])
    assert details["reason"] == "spam"
    assert details["catalog_agent_id"] == "cagt-1"
    assert details["schema_version"] == 1
    assert details["event_type"] == "catalog_agent_suspended"
    # created_at is the shared UTC ISO-8601 no-microsecond default.
    assert row["created_at"]
    datetime.fromisoformat(str(row["created_at"]))
    assert "." not in row["created_at"]


def test_append_catalog_audit_returns_increasing_ids(conn) -> None:
    first = _seed_audit(conn, event="catalog_agent_registered")
    second = _seed_audit(conn, event="catalog_agent_suspended")
    conn.commit()

    assert first < second


# ── payload defaults (§7.6) ─────────────────────────────────────────────────


def test_payload_defaults_injected_when_details_none(conn) -> None:
    event_id = _seed_audit(
        conn,
        catalog_agent_id="cagt-7",
        actor="verifier",
        event="catalog_agent_verified",
        details=None,
    )
    conn.commit()

    row = conn.execute(
        "select details_json from audit_events where id = ?", (event_id,)
    ).fetchone()
    assert row is not None
    details = json.loads(row["details_json"])
    assert details["schema_version"] == 1
    assert details["event_type"] == "catalog_agent_verified"
    assert details["catalog_agent_id"] == "cagt-7"


def test_payload_defaults_do_not_override_explicit_details(conn) -> None:
    event_id = _seed_audit(
        conn,
        catalog_agent_id="cagt-7",
        event="catalog_agent_verified",
        details={
            "schema_version": 9,
            "event_type": "custom_event",
            "catalog_agent_id": "cagt-override",
            "reason": "explicit wins",
        },
    )
    conn.commit()

    row = conn.execute(
        "select details_json from audit_events where id = ?", (event_id,)
    ).fetchone()
    assert row is not None
    details = json.loads(row["details_json"])
    assert details["schema_version"] == 9
    assert details["event_type"] == "custom_event"
    assert details["catalog_agent_id"] == "cagt-override"
    assert details["reason"] == "explicit wins"


def test_payload_event_type_defaults_to_empty_string_when_event_empty(conn) -> None:
    event_id = append_catalog_audit(conn, "cagt_x", "admin", "", {"note": "bare"})
    conn.commit()

    row = conn.execute(
        "select event, details_json from audit_events where id = ?", (event_id,)
    ).fetchone()
    assert row is not None
    assert row["event"] == ""
    details = json.loads(row["details_json"])
    assert details["event_type"] == ""
    assert details["catalog_agent_id"] == "cagt_x"
    assert details["schema_version"] == 1


# ── details isolation ───────────────────────────────────────────────────────


def test_details_dict_is_not_mutated_by_helper(conn) -> None:
    original: dict[str, Any] = {"reason": "spam"}
    snapshot = dict(original)

    _seed_audit(conn, details=original)
    conn.commit()

    # The caller's dict must not gain the injected defaults.
    assert original == snapshot
    assert "schema_version" not in original
    assert "event_type" not in original
    assert "catalog_agent_id" not in original


# ── lastrowid error ─────────────────────────────────────────────────────────


def test_append_catalog_audit_raises_when_lastrowid_missing() -> None:
    fake_conn = mock.Mock(spec=sqlite3.Connection)
    fake_conn.execute.return_value.lastrowid = None
    with pytest.raises(RuntimeError, match="did not return an id"):
        append_catalog_audit(fake_conn, "cagt_x", "admin", "catalog_agent_suspended")


# ── transaction boundary (helper never commits) ─────────────────────────────


def test_helper_does_not_commit_transaction_boundary_stays_with_caller(tmp_path) -> None:
    db = tmp_path / "audit.sqlite"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    migration_001_agent_catalog(conn)
    migration_009_shadow_tables(conn)
    conn.commit()

    _seed_audit(conn)
    # No commit: a second connection must not see the uncommitted write.
    other = sqlite3.connect(db)
    try:
        other.row_factory = sqlite3.Row
        before = other.execute("select count(*) from audit_events").fetchone()
        assert before is not None and before[0] == 0
        conn.commit()
        after = other.execute("select count(*) from audit_events").fetchone()
        assert after is not None and after[0] == 1
    finally:
        other.close()
    conn.close()


# ── parameterization ────────────────────────────────────────────────────────


def test_helper_parameterizes_values_no_injection(conn) -> None:
    evil_actor = "admin' OR '1'='1"
    evil_event = "catalog_agent_suspended' OR '1'='1"
    evil_note = "note') OR ('1'='1"
    _seed_audit(
        conn,
        catalog_agent_id="cagt-1' OR '1'='1",
        actor=evil_actor,
        event=evil_event,
        details={"note": evil_note},
    )
    conn.commit()

    rows = conn.execute("select actor, event, details_json from audit_events").fetchall()
    assert len(rows) == 1
    assert rows[0]["actor"] == evil_actor
    assert rows[0]["event"] == evil_event
    details = json.loads(rows[0]["details_json"])
    assert details["note"] == evil_note
    # The quote-bearing actor/event must be stored literally, not expanded.
    assert conn.execute(
        "select count(*) from audit_events where actor = 'admin'"
    ).fetchone()[0] == 0


# ── module surface and facade re-export ─────────────────────────────────────


def test_catalog_audit_module_exports_only_append_helper() -> None:
    assert catalog_audit.__all__ == ["append_catalog_audit"]


def test_repository_reexports_leaf_function_unchanged() -> None:
    """The ``sqlite_repository`` facade must keep exposing the same function
    object so existing callers and the ``CatalogRepository`` abstraction
    mapping keep resolving by identity."""
    exported = getattr(sqlite_repository, "append_catalog_audit", None)
    assert callable(exported)
    assert exported is catalog_audit.append_catalog_audit
    assert exported is append_catalog_audit
