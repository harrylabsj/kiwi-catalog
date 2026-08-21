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

"""运营 Dashboard API（admin token 保护，fail-closed）。

5 条路由：dashboard 总览 / merchant 列表 / 单商家报告 / 买家搜索事件 /
每日去重买家统计。全部只读聚合，数据来自 services/admin_reports.py 等；
页面（/portal/dashboard、/portal/admin/*）与 CLI 之外的唯一数据入口。
GET 无 body，admin token 经 query string（审查 P2 惯例）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import admin_reports, buyer_search_events


def _parse_int_query(raw: Any, default: int, name: str) -> int:
    """解析可选整数 query 参数；非数字/负值 → ValidationError（400）。

    审查 P3：此前 int(raw) 对非数字输入抛 ValueError → 未类型化 500。
    """
    if raw is None or str(raw) == "":
        return default
    try:
        value = int(str(raw))
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be an integer") from None
    if value < 0:
        raise ValidationError(f"{name} must be a non-negative integer")
    return value


def dashboard(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/dashboard?days=14（admin）——运营总览。"""
    api_auth.require_admin_token(payload)
    # 审查 P3：非数字参数此前 int() 抛 ValueError → 未类型化 500。映射 400。
    days = _parse_int_query(query.get("days"), admin_reports.DEFAULT_DAYS, "days")
    with db_session(db_path) as conn:
        summary = admin_reports.dashboard_summary(conn, days=days)
        return {"ok": True, **summary}


def merchant_list(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/merchants?limit=100（admin）——商家列表。"""
    api_auth.require_admin_token(payload)
    limit = _parse_int_query(query.get("limit"), 100, "limit")
    with db_session(db_path) as conn:
        return {"ok": True, "results": admin_reports.merchant_list(conn, limit=limit)}


def merchant_report(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/merchants/{merchant_id}/report（admin）——商家报告。"""
    api_auth.require_admin_token(payload)
    with db_session(db_path) as conn:
        return {"ok": True, **admin_reports.merchant_report(conn, merchant_id)}


def search_events(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/searches?limit=100（admin）——最近买家搜索事件（运营数据源）。

    每条含 search_type / query / filters / result_count / result_summary /
    created_at；result_count==0 即未命中（供需缺口信号）。
    """
    api_auth.require_admin_token(payload)
    limit = _parse_int_query(query.get("limit"), 100, "limit")
    with db_session(db_path) as conn:
        return {
            "ok": True,
            "results": buyer_search_events.list_recent_search_events(conn, limit=limit),
        }


def buyer_stats(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/buyer-stats?days=14（admin）——每日去重买家统计 + 关键词排行。

    每天按买家搜索两个指标给出：distinct_buyers（去重买家数）/
    identified_events（已识别事件）/ total_events（事件总量）/
    unidentified_events（未识别 = 总量 − 已识别）；``today`` 为当日同形状。
    另附窗口内 top_keywords（热门）与 zero_hit_keywords（未命中 = 供需缺口）。
    """
    api_auth.require_admin_token(payload)
    days = _parse_int_query(query.get("days"), admin_reports.DEFAULT_DAYS, "days")
    with db_session(db_path) as conn:
        return {"ok": True, **admin_reports.buyer_stats_summary(conn, days=days)}
