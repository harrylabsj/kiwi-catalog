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

"""运营 Dashboard 数据聚合（admin 专用，docs §dashboard）。

三个查询面（只读，所有调用方必须先过 admin token）：
- ``dashboard_summary``：KPI 计数 + 最近 N 天使用趋势 + 最近申请；
- ``merchant_list``：全部商家（影子表 + agent/listing/token 聚合）；
- ``merchant_report``：单商家报告（资料 / agents / listings / token
  生命周期 / 审计事件）。
"""

from __future__ import annotations

import sqlite3
from typing import Any

from kiwi_catalog.core.errors import NotFoundError
from kiwi_catalog.services import usage_metrics

DEFAULT_DAYS = 14
MAX_DAYS = 90


def dashboard_summary(conn: sqlite3.Connection, days: int = DEFAULT_DAYS) -> dict[str, Any]:
    """运营总览：计数 + 使用趋势 + 最近申请。"""
    days = max(1, min(int(days or DEFAULT_DAYS), MAX_DAYS))

    def _count(sql: str) -> int:
        row = conn.execute(sql).fetchone()
        return int(row[0]) if row is not None else 0

    applications = conn.execute(
        "select status, count(*) as n from merchant_applications group by status"
    ).fetchall()
    tokens = conn.execute(
        "select status, count(*) as n from merchant_tokens group by status"
    ).fetchall()
    listings = conn.execute(
        "select publication_state, count(*) as n from commerce_listings group by publication_state"
    ).fetchall()

    recent = conn.execute(
        "select * from merchant_applications order by application_id desc limit 10"
    ).fetchall()
    from kiwi_catalog.services.merchant_tokens import application_row

    return {
        "counts": {
            "merchants": _count("select count(*) from merchants"),
            "agents": _count("select count(*) from catalog_agents"),
            "listings": _count("select count(*) from commerce_listings"),
            "pending_applications": _count(
                "select count(*) from merchant_applications where status = 'pending'"
            ),
            "active_tokens": _count(
                "select count(*) from merchant_tokens where status = 'active'"
            ),
            "applications_by_status": {
                str(r["status"]): int(r["n"]) for r in applications
            },
            "tokens_by_status": {str(r["status"]): int(r["n"]) for r in tokens},
            "listings_by_state": {str(r["publication_state"]): int(r["n"]) for r in listings},
        },
        "usage": usage_metrics.usage_series(conn, days=days),
        "recent_applications": [application_row(r) for r in recent],
    }


def merchant_list(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    """全部商家：id / 名称 / agent 数 / listing 数 / token 状态 / 最近活动。"""
    limit = max(1, min(int(limit or 100), 500))
    rows = conn.execute(
        """
        select m.id as merchant_id, m.name, m.created_at,
               m.updated_at,
               (select count(*) from catalog_agents ca where ca.merchant_id = m.id) as agents,
               (select count(*) from commerce_listings cl where cl.merchant_id = m.id) as listings,
               (select status from merchant_tokens mt where mt.merchant_id = m.id) as token_status,
               (select issued_at from merchant_tokens mt2 where mt2.merchant_id = m.id) as token_issued_at,
               (select count(*) from audit_events ae where ae.details_json like '%' || m.id || '%') as audit_events
        from merchants m
        order by m.updated_at desc
        limit ?
        """,
        (limit,),
    ).fetchall()
    result = []
    for r in rows:
        result.append(
            {
                "merchant_id": r["merchant_id"],
                "name": r["name"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "agents_count": int(r["agents"]),
                "listings_count": int(r["listings"]),
                "token_status": r["token_status"] or "none",
                "token_issued_at": r["token_issued_at"] or "",
            }
        )
    return result


def merchant_report(conn: sqlite3.Connection, merchant_id: str) -> dict[str, Any]:
    """单商家报告：资料 / agents / listings / token 生命周期 / 审计事件。"""
    merchant = conn.execute(
        "select * from merchants where id = ?", (merchant_id,)
    ).fetchone()
    if merchant is None:
        raise NotFoundError(f"Unknown merchant: {merchant_id}")

    agents = conn.execute(
        "select catalog_agent_id, display_name, canonical_domain,"
        " verification_level, administrative_state, created_at, updated_at"
        " from catalog_agents where merchant_id = ? order by created_at",
        (merchant_id,),
    ).fetchall()

    listings = conn.execute(
        "select listing_id, listing_type, title, category, publication_state,"
        " listing_freshness_state, published_at, updated_at"
        " from commerce_listings where merchant_id = ? order by updated_at desc",
        (merchant_id,),
    ).fetchall()

    tokens = conn.execute(
        "select status, issued_at, rotated_at, revoked_at from merchant_tokens"
        " where merchant_id = ?",
        (merchant_id,),
    ).fetchall()

    audit = conn.execute(
        "select id, actor, event, details_json, created_at from audit_events"
        " where details_json like ? order by id desc limit 50",
        (f"%{merchant_id}%",),
    ).fetchall()

    # 邮箱：优先 merchant_applications.contact_email（申请工单），回退 account email。
    contact_email = ""
    application = conn.execute(
        "select contact_email from merchant_applications where merchant_id = ?"
        " order by application_id desc limit 1",
        (merchant_id,),
    ).fetchone()
    if application is not None:
        contact_email = str(application["contact_email"] or "")
    account_email = ""
    account = conn.execute(
        "select email from merchant_accounts where merchant_id = ? order by account_id desc limit 1",
        (merchant_id,),
    ).fetchone()
    if account is not None:
        account_email = str(account["email"] or "")

    return {
        "merchant": {
            "merchant_id": merchant["id"],
            "name": merchant["name"],
            "created_at": merchant["created_at"],
            "contact_email": contact_email,
            "account_email": account_email,
            "updated_at": merchant["updated_at"],
            "city": merchant["city"],
            "service_area": merchant["service_area"],
            "contact": merchant["contact"],
        },
        "agents": [
            {
                "catalog_agent_id": a["catalog_agent_id"],
                "display_name": a["display_name"],
                "canonical_domain": a["canonical_domain"],
                "verification_level": a["verification_level"],
                "administrative_state": a["administrative_state"],
                "created_at": a["created_at"],
                "updated_at": a["updated_at"],
            }
            for a in agents
        ],
        "listings": [
            {
                "listing_id": listing["listing_id"],
                "listing_type": listing["listing_type"],
                "title": listing["title"],
                "category": listing["category"],
                "publication_state": listing["publication_state"],
                "freshness_state": listing["listing_freshness_state"],
                "published_at": listing["published_at"],
                "updated_at": listing["updated_at"],
            }
            for listing in listings
        ],
        "tokens": [
            {
                "status": t["status"],
                "issued_at": t["issued_at"],
                "rotated_at": t["rotated_at"],
                "revoked_at": t["revoked_at"],
            }
            for t in tokens
        ],
        "audit_events": [
            {
                "id": e["id"],
                "actor": e["actor"],
                "event": e["event"],
                "details": e["details_json"],
                "created_at": e["created_at"],
            }
            for e in audit
        ],
    }
