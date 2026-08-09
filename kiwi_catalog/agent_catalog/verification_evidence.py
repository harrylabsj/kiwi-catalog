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

"""Pure SQLite persistence for the verification evidence tables (§5.5, §5.6).

Extracted from ``agent_catalog/sqlite_repository.py`` (T8/T9 hotspot
convergence): the append-only ``agent_profile_snapshots`` rows and the
per-check ``agent_verifications`` evidence rows written by the §6
verification ladder and re-read for the v0.3 §7.1 evidence recomputation.

These helpers are stateless statement runners over an injectable
``sqlite3.Connection``: no locking, no time source, and no transaction
boundary live here — the caller drives commits.  ``sqlite_repository``
re-exports every name so the repository facade and the
``CatalogRepository`` abstraction mapping stay unchanged.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from kiwi_catalog.agent_catalog.row_serialization import row_to_dict

__all__ = [
    "insert_profile_snapshot",
    "insert_verification",
    "latest_profile_snapshot",
    "latest_verification",
    "list_profile_snapshots",
    "list_verifications",
]


# ── agent_profile_snapshots (§5.5) ──────────────────────────────────────────


def insert_profile_snapshot(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    profile_type: str,
    source_url: str,
    etag: str,
    last_modified: str,
    content_hash: str,
    raw_json: str,
    fetched_at: str,
    fresh_until: str,
    validation_status: str = "valid",
) -> int:
    """Insert a new agent_profile_snapshots row (history is append-only)."""
    cursor = conn.execute(
        """
        insert into agent_profile_snapshots(
            catalog_agent_id, profile_type, source_url, etag, last_modified,
            content_hash, raw_json, fetched_at, fresh_until, validation_status
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            catalog_agent_id,
            profile_type,
            source_url,
            etag,
            last_modified,
            content_hash,
            raw_json,
            fetched_at,
            fresh_until,
            validation_status,
        ),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("profile snapshot insert did not return an id")
    return cursor.lastrowid


def latest_profile_snapshot(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    profile_type: str,
) -> dict[str, Any] | None:
    """Return the most recent snapshot row for a profile type, or None."""
    row = conn.execute(
        """
        select * from agent_profile_snapshots
        where catalog_agent_id = ? and profile_type = ?
        order by snapshot_id desc
        limit 1
        """,
        (catalog_agent_id, profile_type),
    ).fetchone()
    return row_to_dict(row) if row is not None else None


def list_profile_snapshots(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select * from agent_profile_snapshots
        where catalog_agent_id = ?
        order by snapshot_id
        """,
        (catalog_agent_id,),
    ).fetchall()
    return [row_to_dict(r) for r in rows]


# ── agent_verifications (§5.6) ──────────────────────────────────────────────


def insert_verification(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    verification_type: str,
    result: str,
    evidence_json: str,
    checked_at: str,
    expires_at: str,
) -> int:
    """Insert a new agent_verifications row.  Returns the verification id."""
    cursor = conn.execute(
        """
        insert into agent_verifications(
            catalog_agent_id, verification_type, result, evidence_json,
            checked_at, expires_at
        ) values (?, ?, ?, ?, ?, ?)
        """,
        (catalog_agent_id, verification_type, result, evidence_json, checked_at, expires_at),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("verification insert did not return an id")
    return cursor.lastrowid


def latest_verification(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    verification_type: str,
    result: str | None = None,
) -> dict[str, Any] | None:
    """最新一条指定类型的验证证据（v0.3 §7.1 级别重算依据）。

    审查 P1-7：降级重算必须按「最新 passed 证据」而非「最新一条证据」——
    否则一次失败的验证写入的 failed 行会屏蔽历史 passed 证据，后续重算
    持续退化到 DISCOVERED。
    """
    if result is not None:
        row = conn.execute(
            "select * from agent_verifications"
            " where catalog_agent_id = ? and verification_type = ? and result = ?"
            " order by checked_at desc, verification_id desc limit 1",
            (catalog_agent_id, verification_type, result),
        ).fetchone()
    else:
        row = conn.execute(
            "select * from agent_verifications"
            " where catalog_agent_id = ? and verification_type = ?"
            " order by checked_at desc, verification_id desc limit 1",
            (catalog_agent_id, verification_type),
        ).fetchone()
    return None if row is None else row_to_dict(row)


def list_verifications(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select * from agent_verifications
        where catalog_agent_id = ?
        order by verification_id
        """,
        (catalog_agent_id,),
    ).fetchall()
    return [row_to_dict(r) for r in rows]
