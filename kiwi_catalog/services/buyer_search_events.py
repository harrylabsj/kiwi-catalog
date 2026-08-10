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
import sqlite3

from kiwi_catalog.db.session import now_iso

MAX_RETAINED_EVENTS = 5000
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
    conn.execute(
        "insert into buyer_search_events"
        " (search_type, query, filters_json, result_count, result_summary_json, created_at)"
        " values (?, ?, ?, ?, ?, ?)",
        (
            str(search_type or "")[:32],
            str(query or "")[:_QUERY_CAP],
            _bounded_json(filters or {}, _FILTERS_CAP),
            int(result_count or 0),
            _bounded_json((result_summary or [])[:SUMMARY_CAP], _SUMMARY_CAP),
            now_iso(),
        ),
    )
    # 有界保留：超上限删最旧（event_id 自增单调，limit 子查询在 5000 量级可接受）。
    conn.execute(
        "delete from buyer_search_events where event_id not in ("
        " select event_id from buyer_search_events order by event_id desc limit ?"
        ")",
        (MAX_RETAINED_EVENTS,),
    )


def list_recent_search_events(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    """返回最近买家搜索事件（倒序），filters/result_summary 反序列化为对象。"""
    limit = max(1, min(int(limit or 100), 500))
    rows = conn.execute(
        "select event_id, search_type, query, filters_json, result_count, result_summary_json, created_at"
        " from buyer_search_events order by created_at desc, event_id desc limit ?",
        (limit,),
    ).fetchall()
    out: list[dict] = []
    for row in rows:
        item = dict(row)
        item["filters"] = _parse_json(item.pop("filters_json", ""), {})
        item["result_summary"] = _parse_json(item.pop("result_summary_json", ""), [])
        out.append(item)
    return out


def _parse_json(text: str, default: object):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default
