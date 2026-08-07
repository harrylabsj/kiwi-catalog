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

"""Local Agent Catalog metrics — stats and doctor (§24).

Both are LOCAL observability helpers used by the CLI (``agent catalog stats`` /
``agent catalog doctor``).  They compute counts over the local SQLite store and
deliberately do NOT go through the public §8.2 serializer — they report
aggregate numbers, never observation content, and never private merchant state.
"""

from __future__ import annotations

from typing import Any

from kiwi_catalog.db.session import now_iso
from kiwi_catalog.services.catalog_runtime_metrics import (
    derived_metrics,
    snapshot_runtime_metrics,
)

# verification_status values reached after at least domain-control proof (§6).
_VERIFIED_STATUSES = frozenset({"domain_verified", "agent_verified", "commerce_verified"})

# verification_status values that are "registered but never verified".
_UNVERIFIED_REGISTRATION_STATUSES = frozenset({"discovered"})

# statuses that signal a broken/misbehaving agent (doctor issues).
_ISSUE_STATUSES = frozenset({"stale", "unreachable", "suspended", "rejected"})


def _scalar(conn: Any, sql: str, *params: Any) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0] or 0)


def _grouped_counts(conn: Any, column: str) -> dict[str, int]:
    rows = conn.execute(
        f"select {column}, count(*) as n from catalog_agents group by {column} order by {column}"
    ).fetchall()
    return {str(r[column]): int(r["n"]) for r in rows}


def _runtime_metrics_subtree(hosting_mode_distribution: dict[str, int]) -> dict[str, Any]:
    """Assemble the ``runtime_metrics`` subtree for ``catalog_stats``.

    Combines the process-wide runtime registry snapshot (counters / latency /
    gauges / funnel) with derived metrics.  ``direct_a2a_ratio`` and
    ``hosted_gateway_ratio`` are derived from the catalog's hosting_mode
    distribution (decision fixed in catalog_runtime_metrics docstring: there
    is no direct A2A runtime call path yet, so ratios are data-form derived);
    ``unknown`` mode is excluded from both denominators.
    """
    snapshot = snapshot_runtime_metrics()
    mode_total = (
        hosting_mode_distribution.get("direct", 0)
        + hosting_mode_distribution.get("hosted", 0)
        + hosting_mode_distribution.get("hybrid", 0)
    )
    direct_ratio = (
        hosting_mode_distribution.get("direct", 0) / mode_total if mode_total else 0.0
    )
    hosted_ratio = (
        hosting_mode_distribution.get("hosted", 0) / mode_total if mode_total else 0.0
    )
    return {
        **snapshot,
        "derived": {
            **derived_metrics(snapshot),
            "direct_a2a_ratio": round(direct_ratio, 6),
            "hosted_gateway_ratio": round(hosted_ratio, 6),
        },
    }


def catalog_stats(conn: Any) -> dict[str, Any]:
    """Local §24 metric subset for the ``agent catalog stats`` command."""
    total = _scalar(conn, "select count(*) from catalog_agents")
    verified = _scalar(
        conn,
        "select count(*) from catalog_agents where verification_status in ('domain_verified','agent_verified','commerce_verified')",
    )
    stale = _scalar(conn, "select count(*) from catalog_agents where verification_status = 'stale'")
    hosting_mode_distribution = _grouped_counts(conn, "hosting_mode")

    return {
        "catalog_agent_count": total,
        "verified_agent_count": verified,
        "unverified_agent_count": _scalar(
            conn,
            "select count(*) from catalog_agents where verification_status in ('discovered','profile_valid')",
        ),
        "stale_agent_count": stale,
        "suspended_agent_count": _scalar(
            conn, "select count(*) from catalog_agents where verification_status = 'suspended'"
        ),
        "rejected_agent_count": _scalar(
            conn, "select count(*) from catalog_agents where verification_status = 'rejected'"
        ),
        "verification_status_distribution": _grouped_counts(conn, "verification_status"),
        "hosting_mode_distribution": hosting_mode_distribution,
        "source_type_distribution": _grouped_counts(conn, "source_type"),
        "lifecycle_status_distribution": _grouped_counts(conn, "lifecycle_status"),
        "capability_count": _scalar(conn, "select count(*) from agent_capabilities"),
        "endpoint_count": _scalar(conn, "select count(*) from agent_endpoints"),
        "skill_count": _scalar(conn, "select count(*) from agent_skills"),
        "profile_snapshot_count": _scalar(conn, "select count(*) from agent_profile_snapshots"),
        "runtime_metrics": _runtime_metrics_subtree(hosting_mode_distribution),
    }


def catalog_doctor_report(conn: Any, *, checked_at: str = "") -> dict[str, Any]:
    """Run the local catalog health check and return a structured report.

    Health is derived ONLY from public verification metadata — stale count,
    unverified registrations, expired profile snapshots, unreachable/suspended/
    rejected agents, and data-integrity gaps (missing canonical domain, no
    endpoints).  Private trust observations (§5.7) are NOT consulted here:
    commercial reputation never influences public health state.
    """
    checked = checked_at or now_iso()

    total = _scalar(conn, "select count(*) from catalog_agents")
    counts: dict[str, int] = {}
    for status in ("stale", "unreachable", "suspended", "rejected"):
        counts[status] = _scalar(
            conn, "select count(*) from catalog_agents where verification_status = ?", status
        )
    counts["discovered"] = _scalar(
        conn,
        "select count(*) from catalog_agents where verification_status = 'discovered'",
    )

    expired_snapshots = _scalar(
        conn,
        "select count(*) from agent_profile_snapshots where fresh_until != '' and fresh_until < ?",
        checked,
    )
    missing_domain = _scalar(
        conn,
        "select count(*) from catalog_agents where canonical_domain = ''",
    )
    no_endpoints = _scalar(
        conn,
        """select count(*) from catalog_agents ca
           where not exists (select 1 from agent_endpoints ae where ae.catalog_agent_id = ca.catalog_agent_id)""",
    )

    issues: list[str] = []
    warnings: list[str] = []
    if counts["stale"]:
        issues.append(f"{counts['stale']} stale agent(s)")
    if counts["discovered"]:
        issues.append(f"{counts['discovered']} unverified registration(s)")
    if expired_snapshots:
        issues.append(f"{expired_snapshots} expired profile snapshot(s)")
    if counts["unreachable"]:
        issues.append(f"{counts['unreachable']} unreachable agent(s)")
    if counts["suspended"]:
        issues.append(f"{counts['suspended']} suspended agent(s)")
    if counts["rejected"]:
        issues.append(f"{counts['rejected']} rejected agent(s)")
    if missing_domain:
        issues.append(f"{missing_domain} agent(s) missing canonical domain")
    if no_endpoints:
        warnings.append(f"{no_endpoints} agent(s) without any endpoint")

    return {
        "ok": True,
        "healthy": not issues,
        "total_agents": total,
        "stale_agents": counts["stale"],
        "unverified_registrations": counts["discovered"],
        "unreachable_agents": counts["unreachable"],
        "suspended_agents": counts["suspended"],
        "rejected_agents": counts["rejected"],
        "expired_profile_snapshots": expired_snapshots,
        "missing_canonical_domain": missing_domain,
        "agents_without_endpoints": no_endpoints,
        "issues": issues,
        "warnings": warnings,
        "checked_at": checked,
    }
