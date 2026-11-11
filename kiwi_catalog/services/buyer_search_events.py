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

"""买家搜索事件保留（运营数据源，v18）。

每次 buyer 搜索（agent / listing）记一条：搜了什么（query/filters）、返回了
什么（result_count + 前 N 条摘要）、命中与否（result_count==0 = 供需缺口信号，
运营 portal 据此看需求）。有界保留最近 MAX_RETAINED_EVENTS 条（插入后裁剪）。
"""

from __future__ import annotations

import json
import os
import sqlite3

from kiwi_catalog.db.session import now_iso

#: 默认保留最近 2 万条（原 5000 条）。运营需要更长的逐条追溯窗口时，用 env
#: ``KIWI_CATALOG_BUYER_SEARCH_EVENT_RETENTION`` 调大（上限 20 万，防误配把
#: SQLite 撑爆）。日聚合/usage_metrics 不受影响。
MAX_RETAINED_EVENTS = 20_000
_MAX_RETAINED_EVENTS_CEILING = 200_000
_RETENTION_ENV = "KIWI_CATALOG_BUYER_SEARCH_EVENT_RETENTION"
#: 超出上限多少条才触发一次裁剪——避免每条 insert 都跑一次 count/delete。
#: 裁剪后仍保留 max_retained_events() 条，只是允许短暂多出 *_PRUNE_SLACK 条。
_PRUNE_SLACK = 500
#: 每 N 条插入才检查一次（按 lastrowid 取模，无状态）；否则每次 insert 都
#: count 全表，在 2 万条量级会明显拖慢搜索。
_PRUNE_EVERY_N = 200


def max_retained_events() -> int:
    """当前保留条数：env 覆盖 → 默认 20000 → 上限 200000。"""
    raw = str(os.environ.get(_RETENTION_ENV) or "").strip()
    if not raw:
        return MAX_RETAINED_EVENTS
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return MAX_RETAINED_EVENTS
    if value <= 0:
        return MAX_RETAINED_EVENTS
    return min(value, _MAX_RETAINED_EVENTS_CEILING)


SUMMARY_CAP = 10
_QUERY_CAP = 500
_FILTERS_CAP = 2000
_SUMMARY_CAP = 8000


def _bounded_json(value: object, cap: int) -> str:
    """Serialize *value* to ≤ *cap* chars while ALWAYS producing valid JSON.

    审查 P2-06：直接 ``json.dumps(...)[:cap]`` 会在字符串/结构中间切断，落库的
    filters_json / result_summary_json 成为非法 JSON（读取端 json.loads 失败被
    静默丢弃）。改为先按预算收缩结构（字符串值截断、容器宽度限制）再序列化——
    收缩只会缩短字符串 / 截断尾部元素，产物永远是合法 JSON。
    """
    encoded = json.dumps(value, ensure_ascii=False)
    if len(encoded) <= cap:
        return encoded
    budget = cap
    while budget > 32:
        encoded = json.dumps(_shrink_json_value(value, budget), ensure_ascii=False)
        if len(encoded) <= cap:
            return encoded
        budget //= 2
    # 病理输入兜底：极端深/宽结构仍放不下 → 空容器（合法 JSON）。
    empty: object = {} if isinstance(value, dict) else ([] if isinstance(value, list) else "")
    return json.dumps(empty, ensure_ascii=False)


def _shrink_json_value(value: object, budget: int) -> object:
    """按 *budget* 收缩 *value*（只缩短字符串 / 截断容器宽度，保持合法 JSON）。"""
    if isinstance(value, str):
        return value[: max(0, budget - 2)]
    if isinstance(value, dict):
        max_keys = max(1, budget // 16)
        out: dict[str, object] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= max_keys:
                break
            out[str(k)[: max(0, budget // 4)]] = _shrink_json_value(v, max(0, budget // 4))
        return out
    if isinstance(value, list):
        max_items = max(1, budget // 16)
        return [_shrink_json_value(v, max(0, budget // 4)) for v in value[:max_items]]
    return value


def record_search_event(
    conn: sqlite3.Connection,
    *,
    search_type: str,
    buyer_source: str = "",
    query: str = "",
    filters: dict | None = None,
    result_count: int = 0,
    result_summary: list[dict] | None = None,
) -> None:
    """记录一次买家搜索事件（插入 + 有界裁剪）。

    result_summary 应传前 SUMMARY_CAP 条结果的可投影字段
    （listing: listing_id/title；agent: catalog_agent_id/display_name），
    运营端据此看买家实际看到了什么。
    """
    rowid = conn.execute(
        "insert into buyer_search_events"
        " (search_type, buyer_source, query, filters_json, result_count,"
        "  result_summary_json, created_at)"
        " values (?, ?, ?, ?, ?, ?, ?)",
        (
            str(search_type or "")[:32],
            str(buyer_source or "")[:64],
            str(query or "")[:_QUERY_CAP],
            _bounded_json(filters or {}, _FILTERS_CAP),
            int(result_count or 0),
            _bounded_json((result_summary or [])[:SUMMARY_CAP], _SUMMARY_CAP),
            now_iso(),
        ),
    ).lastrowid
    # 有界保留：每 _PRUNE_EVERY_N 条检查一次，且超过上限 + slack 才裁。
    if rowid and rowid % _PRUNE_EVERY_N == 0:
        limit = max_retained_events()
        row = conn.execute("select count(*) from buyer_search_events").fetchone()
        if row is not None and int(row[0] or 0) > limit + _PRUNE_SLACK:
            conn.execute(
                "delete from buyer_search_events where event_id <= ("
                " select event_id from buyer_search_events"
                " order by event_id desc limit 1 offset ?"
                ")",
                (limit,),
            )


def _serialize_event_rows(rows) -> list[dict]:
    """事件行 → dict（filters/result_summary 反序列化为对象）。"""
    out: list[dict] = []
    for row in rows:
        item = dict(row)
        item["filters"] = _parse_json(item.pop("filters_json", ""), {})
        item["result_summary"] = _parse_json(item.pop("result_summary_json", ""), [])
        out.append(item)
    return out


_EVENT_COLUMNS = (
    "select event_id, search_type, buyer_source, query, filters_json, result_count,"
    " result_summary_json, created_at from buyer_search_events"
)


def list_recent_search_events(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    """返回最近买家搜索事件（倒序），filters/result_summary 反序列化为对象。"""
    limit = max(1, min(int(limit or 100), 500))
    rows = conn.execute(
        f"{_EVENT_COLUMNS} order by created_at desc, event_id desc limit ?",
        (limit,),
    ).fetchall()
    return _serialize_event_rows(rows)


def list_search_events_for_day(
    conn: sqlite3.Connection, day: str, limit: int = 200
) -> list[dict]:
    """返回某一天（UTC，``YYYY-MM-DD``）的买家搜索事件（倒序）。

    注意事件流是**全局最近 MAX_RETAINED_EVENTS 条**的有界保留：早于该窗口的日期
    会返回空列表——调用方必须结合 ``buyer_keyword_daily``（无保留上限）判断
    「此前没有搜索」还是「明细已被裁剪」，不得把空列表当成「当天没有搜索」。
    """
    limit = max(1, min(int(limit or 200), 500))
    rows = conn.execute(
        f"{_EVENT_COLUMNS} where substr(created_at, 1, 10) = ?"
        " order by created_at desc, event_id desc limit ?",
        (day, limit),
    ).fetchall()
    return _serialize_event_rows(rows)


def _parse_json(text: str, default: object):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default
