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

四个查询面（只读，所有调用方必须先过 admin token）：
- ``dashboard_summary``：KPI 计数 + 最近 N 天使用趋势 + 最近申请；
- ``merchant_list``：全部商家（影子表 + agent/listing/token 聚合）；
- ``merchant_report``：单商家报告（资料 / agents / listings / token
  生命周期 / 审计事件）；
- ``buyer_stats_summary``：每日去重买家（buyer_stats）× 事件总量
  （usage_metrics）合并视图——含未识别身份事件数（总量 − 已识别）；
- ``access_insights``：搜→看漏斗 + 详情热度榜 + 登录失败信号（access_log）。
"""

from __future__ import annotations

import sqlite3
from typing import Any

from kiwi_catalog.core.errors import NotFoundError
from kiwi_catalog.services import buyer_stats, usage_metrics

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


def buyer_stats_summary(conn: sqlite3.Connection, days: int = DEFAULT_DAYS) -> dict[str, Any]:
    """每日去重买家统计 + 关键词排行（admin）。

    每天按买家搜索两个指标（buyer_agent_search / buyer_listing_search）给出：
    - ``distinct_buyers``：去重买家数（buyer_search_daily 行数，日作用域
      pseudonymous hash——隐私设计见 services/buyer_stats.py）；
    - ``identified_events``：已识别身份的搜索事件数（count 求和）；
    - ``total_events``：搜索事件总量（usage_metrics，含匿名）；
    - ``unidentified_events``：未识别身份事件数（总量 − 已识别，下限 0）。

    另附窗口内关键词聚合（buyer_keyword_daily，各取前 20；关键词跨搜索类型
    合并为一行，agent_searches/listing_searches 分列两类计数）：
    ``top_keywords``（按搜索次数）与 ``zero_hit_keywords``（按未命中次数——
    供需缺口信号，运营招商据此）。
    """
    days = max(1, min(int(days or DEFAULT_DAYS), MAX_DAYS))
    buyer_series = buyer_stats.buyer_daily_series(conn, days=days)
    usage_by_day = {
        str(item["day"]): item["counts"]
        for item in usage_metrics.usage_series(conn, days=days)
    }
    series = []
    for item in buyer_series:
        day = str(item["day"])
        usage_counts = usage_by_day.get(day, {})
        identified = item["identified_events"]
        total_events = {
            metric: int(usage_counts.get(metric, 0) or 0)
            for metric in buyer_stats.BUYER_METRICS
        }
        series.append(
            {
                "day": day,
                "distinct_buyers": item["distinct_buyers"],
                "identified_events": identified,
                "total_events": total_events,
                "unidentified_events": {
                    metric: max(0, total_events[metric] - identified[metric])
                    for metric in buyer_stats.BUYER_METRICS
                },
            }
        )
    return {
        "days": days,
        "series": series,
        "today": series[-1],
        "top_keywords": _keyword_ranking(conn, days=days, limit=20),
        "zero_hit_keywords": _keyword_ranking(
            conn, days=days, limit=20, sort="zero_results"
        ),
    }


def _keyword_ranking(
    conn: sqlite3.Connection,
    days: int = DEFAULT_DAYS,
    limit: int = 20,
    sort: str = "searches",
) -> list[dict[str, Any]]:
    """关键词排行数据源分派（Phase 3 Step A）。

    默认从 access_log 派生（``top_keywords_from_access_log``——单一事实源）；
    env ``KIWI_CATALOG_KEYWORD_SOURCE=buyer_keyword_daily`` 回退旧聚合表
    （``top_keywords``）。
    """
    if buyer_stats.keyword_source() == buyer_stats._KEYWORD_SOURCE_ACCESS_LOG:
        return buyer_stats.top_keywords_from_access_log(
            conn, days=days, limit=limit, sort=sort
        )
    return buyer_stats.top_keywords(conn, days=days, limit=limit, sort=sort)


def access_insights(conn: sqlite3.Connection, days: int = DEFAULT_DAYS) -> dict[str, Any]:
    """访问洞察（admin）：基于 access_log(v28 个体访问日志)的运营视图。

    三个查询面：
    - ``funnel``：搜→看转化。窗口内每日 buyer_search / buyer_detail 事件数,
      外加窗口合计与转化率(详情查看 ÷ 搜索,下限/上限防护);
    - ``top_viewed_agents`` / ``top_viewed_listings``：详情面按 target_id
      聚合的被查看热度榜(各前 10),join catalog_agents / commerce_listings
      补名称;views 为总查看数,viewers 为带身份去重查看者数(匿名不计);
    - ``login_failures``：登录安全信号。今日 /v1/accounts/login 失败(4xx)
      次数 + 窗口内按 IP 前缀的失败 Top(防爆破监测;只存 /24 前缀)。
    """
    import datetime as _dt

    days = max(1, min(int(days or DEFAULT_DAYS), MAX_DAYS))
    today = _dt.datetime.now(_dt.UTC).date()
    start = today - _dt.timedelta(days=days - 1)
    cutoff = start.isoformat()

    # ── funnel:每日分面事件数(buyer_search / buyer_detail)─────────────────
    rows = conn.execute(
        "select substr(occurred_at, 1, 10) as day, surface, count(*) as n"
        " from access_log"
        " where occurred_at >= ? and surface in ('buyer_search', 'buyer_detail')"
        " group by day, surface",
        (cutoff,),
    ).fetchall()
    by_day: dict[str, dict[str, int]] = {}
    for row in rows:
        by_day.setdefault(str(row["day"]), {})[str(row["surface"])] = int(row["n"])
    daily: list[dict[str, Any]] = []
    for offset in range(days):
        day = (start + _dt.timedelta(days=offset)).isoformat()
        bucket = by_day.get(day, {})
        searches = bucket.get("buyer_search", 0)
        views = bucket.get("buyer_detail", 0)
        daily.append(
            {
                "day": day,
                "searches": searches,
                "detail_views": views,
                "conversion": round(views / searches, 4) if searches > 0 else None,
            }
        )
    total_searches = sum(item["searches"] for item in daily)
    total_views = sum(item["detail_views"] for item in daily)
    funnel = {
        "daily": daily,
        "total_searches": total_searches,
        "total_detail_views": total_views,
        "conversion": round(total_views / total_searches, 4) if total_searches > 0 else None,
    }

    # ── 详情热度榜:按 target_id 聚合,join 名称;viewers = 带身份去重 ────────
    def _top_viewed(path_prefixes: tuple[str, ...], name_sql: str) -> list[dict[str, Any]]:
        likes = " or ".join(["path like ?"] * len(path_prefixes))
        params: list[Any] = [cutoff, *[p + "%" for p in path_prefixes]]
        viewed = conn.execute(
            "select target_id, count(*) as views,"
            " count(distinct nullif(actor_key, '')) as viewers"
            " from access_log"
            " where occurred_at >= ? and surface = 'buyer_detail'"
            " and target_id <> '' and (" + likes + ")"
            " group by target_id order by views desc, target_id limit 10",
            params,
        ).fetchall()
        out = []
        for v in viewed:
            name_row = conn.execute(name_sql, (str(v["target_id"]),)).fetchone()
            out.append(
                {
                    "target_id": str(v["target_id"]),
                    "name": str(name_row[0]) if name_row is not None and name_row[0] else "",
                    "views": int(v["views"]),
                    "viewers": int(v["viewers"]),
                }
            )
        return out

    top_viewed_agents = _top_viewed(
        ("/v1/agents/", "/v1/agent-catalog/agents/", "/v1/hosted/agents/"),
        "select display_name from catalog_agents where catalog_agent_id = ?",
    )
    top_viewed_listings = _top_viewed(
        ("/v1/listings/",),
        "select title from commerce_listings where listing_id = ?",
    )

    # ── 登录失败:今日失败数 + 窗口内 IP 前缀 Top(防爆破信号)──────────────
    login_today = conn.execute(
        "select count(*) as n from access_log"
        " where path = '/v1/accounts/login' and status >= 400"
        " and substr(occurred_at, 1, 10) = ?",
        (today.isoformat(),),
    ).fetchone()
    login_by_ip = conn.execute(
        "select ip_prefix, count(*) as n from access_log"
        " where path = '/v1/accounts/login' and status >= 400"
        " and occurred_at >= ? and ip_prefix <> ''"
        " group by ip_prefix order by n desc, ip_prefix limit 10",
        (cutoff,),
    ).fetchall()

    return {
        "days": days,
        "funnel": funnel,
        "top_viewed_agents": top_viewed_agents,
        "top_viewed_listings": top_viewed_listings,
        "login_failures": {
            "today": int(login_today["n"]) if login_today is not None else 0,
            "by_ip_prefix": [
                {"ip_prefix": str(r["ip_prefix"]), "failures": int(r["n"])}
                for r in login_by_ip
            ],
        },
    }


def merchant_list(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    """全部商家：id / 名称 / agent 数 / listing 数 / token 状态 / 最近活动。

    token_status 语义（注册即商家，无需审批即可出现在本列表）：
    ``active`` = 有有效令牌；``revoked`` = 曾签发后被吊销（真实 token 行）；
    ``none`` = 未申请/未签发令牌——注册时种入的 revoked 占位行（空 hash）
    不算已签发，显示 none 而非 revoked。
    """
    limit = max(1, min(int(limit or 100), 500))
    rows = conn.execute(
        """
        select m.id as merchant_id, m.name, m.created_at,
               m.updated_at,
               (select count(*) from catalog_agents ca where ca.merchant_id = m.id) as agents,
               (select count(*) from commerce_listings cl where cl.merchant_id = m.id) as listings,
               (select case
                   when count(*) = 0 then 'none'
                   when max(case when status = 'active' then 1 else 0 end) = 1 then 'active'
                   when max(length(token_hash)) > 0 then 'revoked'
                   else 'none'
                 end from merchant_tokens mt where mt.merchant_id = m.id) as token_status,
               (select issued_at from merchant_tokens mt2
                 where mt2.merchant_id = m.id and mt2.token_hash <> ''
                 order by issued_at desc limit 1) as token_issued_at,
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
