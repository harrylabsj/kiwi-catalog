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

8 条路由：dashboard 总览 / merchant 列表 / 单商家报告 / 买家搜索事件 /
某一日的买家搜索（buyer-day）/ 每日去重买家统计 / 个体访问日志 /
**admin token 轮换**（rotate，2026-09-26；唯一一条写路由）。前 7 条只读聚合，
数据来自 services/admin_reports.py、services/access_log.py 等；页面
（/portal/dashboard、/portal/admin/*）与 CLI 之外的唯一数据入口。
GET 无 body，admin token 经 query string（审查 P2 惯例）。
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import access_log as access_log_service
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services import admin_credentials, admin_reports, buyer_search_events


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
    api_auth.require_admin_token(payload, db_path)
    # 审查 P3：非数字参数此前 int() 抛 ValueError → 未类型化 500。映射 400。
    days = _parse_int_query(query.get("days"), admin_reports.DEFAULT_DAYS, "days")
    with db_session(db_path) as conn:
        summary = admin_reports.dashboard_summary(conn, days=days)
        return {"ok": True, **summary}


def merchant_list(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/merchants?limit=100（admin）——商家列表。"""
    api_auth.require_admin_token(payload, db_path)
    limit = _parse_int_query(query.get("limit"), 100, "limit")
    with db_session(db_path) as conn:
        return {"ok": True, "results": admin_reports.merchant_list(conn, limit=limit)}


def merchant_report(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/merchants/{merchant_id}/report（admin）——商家报告。"""
    api_auth.require_admin_token(payload, db_path)
    with db_session(db_path) as conn:
        return {"ok": True, **admin_reports.merchant_report(conn, merchant_id)}


def search_events(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/searches?limit=100（admin）——最近买家搜索事件（运营数据源）。

    每条含 search_type / query / filters / result_count / result_summary /
    created_at；result_count==0 即未命中（供需缺口信号）。
    """
    api_auth.require_admin_token(payload, db_path)
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
    api_auth.require_admin_token(payload, db_path)
    days = _parse_int_query(query.get("days"), admin_reports.DEFAULT_DAYS, "days")
    with db_session(db_path) as conn:
        return {"ok": True, **admin_reports.buyer_stats_summary(conn, days=days)}


def buyer_day(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/buyer-day?day=YYYY-MM-DD&limit=200（admin）——某一天的买家搜索。

    关键词来自日聚合表（任意历史日期可得）；明细事件来自有界事件流（超出保留
    窗口则空 + ``events_note`` 说明）。``day`` 必须是合法日历日（UTC），
    否则 400——不允许把任意字符串当作日期查询。
    """
    api_auth.require_admin_token(payload, db_path)
    raw_day = str(query.get("day") or "").strip()
    try:
        parsed = date.fromisoformat(raw_day)
    except ValueError:
        raise ValidationError("day must be a calendar date in YYYY-MM-DD form") from None
    if parsed.isoformat() != raw_day:
        raise ValidationError("day must be a calendar date in YYYY-MM-DD form")
    limit = _parse_int_query(query.get("limit"), 200, "limit")
    with db_session(db_path) as conn:
        return {"ok": True, **admin_reports.buyer_day_report(conn, raw_day, limit=limit)}


def access_log(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/access-log?surface=&days=&limit=（admin）——个体访问日志。

    按时间倒序返回 access_log 行（不含任何凭据——库里本就不存凭据本体）。
    surface 可选过滤（buyer_search/buyer_detail/merchant_write/account_portal/
    admin）；days 默认 7 上限 90，limit 默认 100 上限 500（服务层钳制兜底）。
    """
    api_auth.require_admin_token(payload, db_path)
    surface = str(query.get("surface") or "").strip()
    days = _parse_int_query(query.get("days"), 7, "days")
    limit = _parse_int_query(query.get("limit"), 100, "limit")
    with db_session(db_path) as conn:
        return {
            "ok": True,
            "results": access_log_service.list_access_log(
                conn, surface=surface, days=days, limit=limit
            ),
        }


def access_insights(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/admin/access-insights?days=14（admin）——访问洞察聚合视图。

    搜→看漏斗（每日 buyer_search/buyer_detail + 转化率）+ 详情热度榜
    （被查看商家/商品 Top 10）+ 登录失败信号（今日失败数 + IP 前缀 Top）。
    数据来自 access_log（v28）。
    """
    api_auth.require_admin_token(payload, db_path)
    days = _parse_int_query(query.get("days"), admin_reports.DEFAULT_DAYS, "days")
    with db_session(db_path) as conn:
        return {"ok": True, **admin_reports.access_insights(conn, days=days)}


def rotate_admin_token(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/admin/token/rotate（admin）——轮换运营 admin token。

    语义（2026-09-26，迁移 v37）：

    - 必须带**当前** admin token（fail-closed）。轮换后旧值立即失效——env 里
      的 `KIWI_CATALOG_ADMIN_TOKEN` 退回"首次引导"角色。
    - body 的 `new_token` 可选：给了就校验并用它（≥24 字符、不含空白）；没给
      由服务端生成（32 随机字节 urlsafe）。
    - **明文只在本次响应里返回一次**；库里只存 SHA-256 摘要。
    - 恢复路径：删掉 admin_credentials 的单例行 + 重启（运维动作，不设 HTTP 口）。

    审计：本请求本身进 access_log（谁在什么时候调的），轮换行记 rotated_at /
    rotated_by / rotation_count，另发一封**通知邮件**——轮换会让旧值立即失效，
    若是攻击者所为，这封信是运营唯一的即时信号。
    """
    with db_session(db_path) as conn:
        api_auth.require_admin_token(payload, conn)
        provided = payload.get("new_token")
        generated = provided is None or str(provided) == ""
        new_token = (
            admin_credentials.generate_admin_token() if generated else str(provided)
        )
        result = admin_credentials.rotate(
            conn, new_token=new_token, actor="admin", now=now_iso()
        )
    # 事务提交后再发信（与商家申请通知同一纪律）：库里已经换了，信发不出去不回滚。
    accounts_service.notify_admin_token_rotated(
        rotated_at=str(result["rotated_at"]),
        rotation_count=result["rotation_count"],
        generated=generated,
        actor="admin",
    )
    return {
        "ok": True,
        "token": new_token,
        "rotated_at": result["rotated_at"],
        "rotation_count": result["rotation_count"],
        "generated": generated,
    }
