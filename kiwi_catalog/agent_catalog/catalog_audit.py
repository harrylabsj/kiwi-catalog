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

"""Pure SQLite persistence for catalog-scoped ``audit_events`` rows.

Extracted from ``agent_catalog/sqlite_repository.py`` (T8/T9 hotspot
convergence): the append-only audit rows written by the verification
pipeline, merchant-token lifecycle, listing operations, and the register/
claim write paths.

This helper is a stateless statement runner over a caller-supplied
``sqlite3.Connection``: locking and the transaction boundary are
caller-owned, and the caller drives commits.  The legacy ``now_iso()``
timestamp is preserved inside ``append_catalog_audit``.
``sqlite_repository`` re-exports the name so the repository facade and
the ``CatalogRepository`` abstraction mapping stay unchanged.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from kiwi_catalog.db.session import encode_json, now_iso

__all__ = ["append_catalog_audit"]


# ── audit_events (catalog-scoped audit) ──────────────────────────────────────


def append_catalog_audit(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    actor: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> int:
    """Write a catalog-scoped audit event.  Returns the new event id."""
    payload = dict(details or {})
    payload.setdefault("schema_version", 1)
    payload.setdefault("event_type", str(event or ""))
    payload.setdefault("catalog_agent_id", catalog_agent_id)

    cursor = conn.execute(
        """
        insert into audit_events(conversation_id, actor, event, details_json, created_at)
        values (?, ?, ?, ?, ?)
        """,
        ("", actor, event, encode_json(payload), now_iso()),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("audit event insert did not return an id")
    return cursor.lastrowid
