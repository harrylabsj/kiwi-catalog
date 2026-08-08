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

3 条路由：dashboard 总览 / merchant 列表 / 单商家报告。全部只读聚合，
数据来自 services/admin_reports.py；页面（/portal/dashboard）与 CLI 之外
的唯一数据入口。GET 无 body，admin token 经 query string（审查 P2 惯例）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.handlers.merchants import _auth_payload_with_query_token
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import admin_reports


def dashboard(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/dashboard?days=14（admin）——运营总览。"""
    api_auth.require_admin_token(_auth_payload_with_query_token(payload, query))
    days = int(query.get("days") or admin_reports.DEFAULT_DAYS)
    with db_session(db_path) as conn:
        summary = admin_reports.dashboard_summary(conn, days=days)
        return {"ok": True, **summary}


def merchant_list(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/merchants?limit=100（admin）——商家列表。"""
    api_auth.require_admin_token(_auth_payload_with_query_token(payload, query))
    limit = int(query.get("limit") or 100)
    with db_session(db_path) as conn:
        return {"ok": True, "results": admin_reports.merchant_list(conn, limit=limit)}


def merchant_report(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/merchants/{merchant_id}/report（admin）——商家报告。"""
    api_auth.require_admin_token(_auth_payload_with_query_token(payload, query))
    with db_session(db_path) as conn:
        return {"ok": True, **admin_reports.merchant_report(conn, merchant_id)}
