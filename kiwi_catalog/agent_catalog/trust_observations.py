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

"""Pure SQLite persistence for the private ``agent_trust_observations`` table (§5.7).

Extracted from ``agent_catalog/sqlite_repository.py`` (T8/T9 hotspot
convergence): the kind-tagged observation rows written by
``services/agent_trust_observations`` and re-read for opaque local aggregates.

PRIVATE-ONLY
------------
Commercial reputation and protocol trust observations.  Never exposed through
a public serializer, a search response, or any public API output (§3.4, §5.7).
The Public Catalog only exposes verification status, capability, freshness, and
hosting mode.  Observations are stored as independent, kind-tagged records and
are never merged into a combined reputation score — commercial reputation and
protocol trust stay separate.

These helpers are stateless statement runners over an injectable
``sqlite3.Connection``: no locking and no transaction boundary live here —
the caller drives commits, and may provide ``observed_at``; when absent the
legacy default ``now_iso()`` is preserved.  ``sqlite_repository`` re-exports
every name so the repository facade and the ``CatalogRepository`` abstraction
mapping stay unchanged.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from kiwi_catalog.agent_catalog.row_serialization import row_to_dict
from kiwi_catalog.db.session import now_iso

__all__ = [
    "TRUST_OBSERVATION_KINDS",
    "count_trust_observations",
    "insert_trust_observation",
    "list_trust_observations",
    "trust_observation_counts_by_kind",
]


# ── agent_trust_observations (§5.7, private-only) ─────────────────────────────


TRUST_OBSERVATION_KINDS = frozenset({
    "protocol_compliance",
    "timeout_rate",
    "schema_error_rate",
    "successful_exchange",
    "local_asserted_dispute",
})


def insert_trust_observation(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    kind: str,
    value: float,
    source: str = "",
    evidence_ref: str = "",
    observed_at: str = "",
    expires_at: str = "",
) -> int:
    """Append one private trust observation (§5.7).  Returns the observation id.

    The caller is responsible for kind/value validation (see
    ``kiwi_catalog.services.agent_trust_observations``).  ``value`` is a single
    numeric field — observations are never aggregated into a reputation score.
    """
    ts = observed_at or now_iso()
    cursor = conn.execute(
        """
        insert into agent_trust_observations(
            catalog_agent_id, kind, value, source, evidence_ref, observed_at, expires_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        """,
        (catalog_agent_id, kind, float(value), source, evidence_ref, ts, expires_at),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("trust observation insert did not return an id")
    return cursor.lastrowid


def list_trust_observations(
    conn: sqlite3.Connection,
    catalog_agent_id: str = "",
    kind: str = "",
) -> list[dict[str, Any]]:
    """Private read path for §5.7 observations.

    NOT for public use: the results must never reach a public serializer,
    search response, or any public API output.
    """
    clauses: list[str] = []
    params: list[Any] = []
    if catalog_agent_id:
        clauses.append("catalog_agent_id = ?")
        params.append(catalog_agent_id)
    if kind:
        clauses.append("kind = ?")
        params.append(kind)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"select * from agent_trust_observations {where} order by observed_at, observation_id",
        params,
    ).fetchall()
    return [row_to_dict(r) for r in rows]


def count_trust_observations(
    conn: sqlite3.Connection,
    catalog_agent_id: str = "",
) -> int:
    """Total number of stored observations (private aggregate; no content)."""
    clauses: list[str] = []
    params: list[Any] = []
    if catalog_agent_id:
        clauses.append("catalog_agent_id = ?")
        params.append(catalog_agent_id)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    row = conn.execute(
        f"select count(*) from agent_trust_observations {where}",
        params,
    ).fetchone()
    return int(row[0] or 0)


def trust_observation_counts_by_kind(
    conn: sqlite3.Connection,
    catalog_agent_id: str = "",
) -> dict[str, int]:
    """Counts per §5.7 kind — kept separate, never merged into one score."""
    clauses: list[str] = []
    params: list[Any] = []
    if catalog_agent_id:
        clauses.append("catalog_agent_id = ?")
        params.append(catalog_agent_id)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"select kind, count(*) as n from agent_trust_observations {where} group by kind order by kind",
        params,
    ).fetchall()
    return {str(r["kind"]): int(r["n"]) for r in rows}
