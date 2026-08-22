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

"""每日去重买家统计 + 搜索关键词统计（admin 运营 dashboard 数据源，v26/v27）。

两张日聚合表，原子 INSERT ON CONFLICT 累加（与 usage_metrics 同一模式）：

- buyer_search_daily：day × metric × buyer_hash——回答「每天有多少个不同
  买家在搜」；
- buyer_keyword_daily：day × search_type × keyword——回答「买家每天在搜
  什么关键词、多少没搜到」（zero_results = 供需缺口信号，运营据此招商）。
  与 buyer_search_events 的原始事件流（有界 5000 条裁剪）不同：本表是
  日聚合、无保留上限。

隐私设计（与 usage_metrics 的最小化原则一致，catalog 不存 buyer 原始身份）：
- 身份来源：Authorization Bearer token，或 X-Buyer-Id 头（buyer agent
  自选标识），都没有则视为匿名；
- 落库的只有 ``HMAC-SHA256(salt, "{day}:{identity}")`` 截断 16 hex 的
  pseudonymous hash——原始身份永不出现在库中；
- key 混入 UTC 日期 ⇒ 同一买家跨天是两条互不相关的 hash，**跨天不可关联**
  （防止长期行为画像），当天内可去重；
- 匿名搜索不计入买家数——仍经 usage_metrics 反映在事件总量里，admin 端点
  用「总量 − 已识别」给出未识别事件数；
- salt 来自 env ``KIWI_CATALOG_STATS_SALT``（默认 dev 值，生产必须配置；
  轮换 salt 会使存量 hash 全部失效——只影响历史去重口径，不丢事件数）；
- keyword 是买家输入的搜索词（归一化后），不是身份数据——与
  buyer_search_events 已记录的 query 同一暴露面。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import unicodedata
from typing import Any

from kiwi_catalog.db.session import now_iso
from kiwi_catalog.services import usage_metrics

_STATS_SALT_ENV = "KIWI_CATALOG_STATS_SALT"
_DEFAULT_SALT = "kiwi-catalog-dev-salt"

# 只统计买家搜索两个指标（与 usage_metrics 词表对齐）；其余 metric 静默跳过。
BUYER_METRICS = (
    usage_metrics.METRIC_BUYER_AGENT_SEARCH,
    usage_metrics.METRIC_BUYER_LISTING_SEARCH,
)

# 时区：UTC 日期（与全库 now_iso UTC 一致）
_DAY_PREFIX_LEN = 10

_HASH_HEX_LEN = 16

# 关键词统计的 search_type 词表与 buyer_search_events 一致（agent/listing）。
SEARCH_TYPES = ("agent", "listing")

_KEYWORD_CAP = 80


# 关键词排行数据源（Phase 3 Step A）：默认从 access_log 派生（单一事实源），
# env KIWI_CATALOG_KEYWORD_SOURCE=buyer_keyword_daily 回退旧聚合表。
_KEYWORD_SOURCE_ENV = "KIWI_CATALOG_KEYWORD_SOURCE"
_KEYWORD_SOURCE_ACCESS_LOG = "access_log"
_KEYWORD_SOURCE_TABLE = "buyer_keyword_daily"

# 搜索路径 → search_type（与写入端同一推导：agent 两路径、listing 一路径）
_SEARCH_PATH_TYPE = (
    ("/v1/agents/search", "agent"),
    ("/v1/agent-catalog/agents/search", "agent"),
    ("/v1/listings/search", "listing"),
)

# 零宽字符（zero-width space / non-joiner / joiner / BOM）——归一化时删除
_ZERO_WIDTH_STRIP = {ord(c): None for c in ("\u200b", "\u200c", "\u200d", "\ufeff")}


def buyer_identity_from_payload(payload: dict[str, Any] | None) -> str:
    """从 transport 合并后的 payload 提取买家身份（原始串，不落库）。

    优先 Authorization Bearer（payload["_auth_token"]，fallback/FastAPI 双栈
    都会合并），其次 X-Buyer-Id（payload["_buyer_id"]）；都没有 → 空串
    （匿名，调用方跳过统计）。
    """
    payload = payload or {}
    return str(payload.get("_auth_token") or payload.get("_buyer_id") or "").strip()


def _stats_salt() -> str:
    return str(os.environ.get(_STATS_SALT_ENV) or "").strip() or _DEFAULT_SALT


def _buyer_hash(day: str, identity: str) -> str:
    """日作用域 pseudonymous hash：跨天不可关联，原始身份不可逆推。"""
    digest = hmac.new(
        _stats_salt().encode("utf-8"),
        f"{day}:{identity}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:_HASH_HEX_LEN]


def record_buyer_search(
    conn: sqlite3.Connection, metric: str, identity: str | None
) -> None:
    """原子 +1（今日窗口，按 buyer_hash 去重）。

    未知 metric 或匿名（identity 为空）静默跳过——与 record_usage 同一
    容错语义：统计失败绝不阻断搜索。
    """
    if metric not in BUYER_METRICS:
        return
    identity = str(identity or "").strip()
    if not identity:
        return
    day = now_iso()[:_DAY_PREFIX_LEN]
    conn.execute(
        "insert into buyer_search_daily(day, metric, buyer_hash, count, updated_at)"
        " values (?, ?, ?, 1, ?)"
        " on conflict(day, metric, buyer_hash) do update set"
        " count = buyer_search_daily.count + 1, updated_at = excluded.updated_at",
        (day, metric, _buyer_hash(day, identity), now_iso()),
    )


def buyer_daily_series(conn: sqlite3.Connection, days: int = 14) -> list[dict[str, Any]]:
    """最近 *days* 天每日买家统计（含 0 的日期补齐——dashboard 画连续趋势）。

    每天两个视图：``distinct_buyers``（去重买家数 = 行数）与
    ``identified_events``（已识别事件数 = count 求和）。
    """
    import datetime as _dt

    today = _dt.datetime.now(_dt.UTC).date()
    start = today - _dt.timedelta(days=days - 1)
    rows = conn.execute(
        "select day, metric, count(*) as buyers, sum(count) as events"
        " from buyer_search_daily where day >= ? group by day, metric",
        (start.isoformat(),),
    ).fetchall()
    buyers_by_day: dict[str, dict[str, int]] = {}
    events_by_day: dict[str, dict[str, int]] = {}
    for row in rows:
        day = str(row["day"])
        metric = str(row["metric"])
        buyers_by_day.setdefault(day, {})[metric] = int(row["buyers"])
        events_by_day.setdefault(day, {})[metric] = int(row["events"])
    series = []
    for offset in range(days):
        day = (start + _dt.timedelta(days=offset)).isoformat()
        series.append(
            {
                "day": day,
                "distinct_buyers": {
                    metric: buyers_by_day.get(day, {}).get(metric, 0)
                    for metric in BUYER_METRICS
                },
                "identified_events": {
                    metric: events_by_day.get(day, {}).get(metric, 0)
                    for metric in BUYER_METRICS
                },
            }
        )
    return series


# ── 搜索关键词统计（buyer_keyword_daily，v27）─────────────────────────────────


def _normalize_keyword(query: object) -> str:
    """关键词归一化：Unicode NFKC + 去零宽字符 + trim + 折叠内部空白 +
    小写 + 截断 80 字符。

    NFKC 把全角/半角与兼容字符折到同一形式（ＡＢＣ → abc），零宽字符
    （U+200B/200C/200D/FEFF）直接删除——否则视觉相同的关键词会落多行
    （2026-08-22 修复重复行报告）。归一化后为空（空串/纯空白/非字符串）
    → 返回空串（调用方跳过——filter-only 搜索不算关键词）。
    """
    if not isinstance(query, str):
        return ""
    text = unicodedata.normalize("NFKC", query)
    text = text.translate(_ZERO_WIDTH_STRIP)
    return " ".join(text.split()).lower()[:_KEYWORD_CAP]


def record_buyer_keyword(
    conn: sqlite3.Connection,
    search_type: str,
    query: object,
    result_count: object,
) -> None:
    """关键词日聚合原子累加：searches +1；result_count==0 时 zero_results +1。

    未知 search_type 或归一化后为空的关键词静默跳过——与 record_buyer_search
    同一容错语义：统计失败绝不阻断搜索。
    """
    if search_type not in SEARCH_TYPES:
        return
    keyword = _normalize_keyword(query)
    if not keyword:
        return
    try:
        # result_count 为 object（int 或 str）——先归一为 str 再 int，mypy 可接受
        zero_hit = 1 if int(str(result_count or 0)) == 0 else 0
    except (TypeError, ValueError):
        zero_hit = 0
    conn.execute(
        "insert into buyer_keyword_daily(day, search_type, keyword, searches, zero_results, updated_at)"
        " values (?, ?, ?, 1, ?, ?)"
        " on conflict(day, search_type, keyword) do update set"
        " searches = buyer_keyword_daily.searches + 1,"
        " zero_results = buyer_keyword_daily.zero_results + excluded.zero_results,"
        " updated_at = excluded.updated_at",
        (now_iso()[:_DAY_PREFIX_LEN], search_type, keyword, zero_hit, now_iso()),
    )


def top_keywords(
    conn: sqlite3.Connection,
    days: int = 14,
    limit: int = 20,
    sort: str = "searches",
) -> list[dict[str, Any]]:
    """最近 *days* 天关键词聚合排行（跨搜索类型合并——每关键词一行）。

    同一关键词在找商家（agent）与找商品（listing）两类搜索下的计数合并，
    分列返回 ``agent_searches`` / ``listing_searches``（2026-08-22 修复：
    此前按 (keyword, search_type) 分组，同关键词在两张排行表里出现重复行；
    查询期合并同时把归一化升级前的历史存量行也并掉）。

    sort="searches"（默认，热门关键词）按搜索次数降序；sort="zero_results"
    （未命中关键词——供需缺口信号）按未命中次数降序。
    """
    import datetime as _dt

    days = max(1, min(int(days or 14), 90))
    limit = max(1, min(int(limit or 20), 100))
    order_column = "zero_results" if sort == "zero_results" else "searches"
    start = _dt.datetime.now(_dt.UTC).date() - _dt.timedelta(days=days - 1)
    rows = conn.execute(
        "select keyword, sum(searches) as searches,"
        " sum(zero_results) as zero_results,"
        " sum(case when search_type = 'agent' then searches else 0 end) as agent_searches,"
        " sum(case when search_type = 'listing' then searches else 0 end) as listing_searches"
        " from buyer_keyword_daily where day >= ?"
        " group by keyword"
        f" order by {order_column} desc, searches desc, keyword asc limit ?",
        (start.isoformat(), limit),
    ).fetchall()
    return [
        {
            "keyword": str(row["keyword"]),
            "searches": int(row["searches"]),
            "zero_results": int(row["zero_results"]),
            "agent_searches": int(row["agent_searches"]),
            "listing_searches": int(row["listing_searches"]),
        }
        for row in rows
    ]


# ── 关键词排行：从 access_log 派生（Phase 3 Step A，单一事实源）──────────────


def keyword_source() -> str:
    """关键词排行数据源：默认 ``access_log``（派生），env 回退 ``buyer_keyword_daily``。"""
    return str(os.environ.get(_KEYWORD_SOURCE_ENV) or "").strip() or _KEYWORD_SOURCE_ACCESS_LOG


def _search_type_from_path(path: object) -> str | None:
    """搜索路径 → search_type（agent/listing）；非搜索路径 → None。"""
    path = str(path or "").split("?", 1)[0]
    for candidate, search_type in _SEARCH_PATH_TYPE:
        if path == candidate:
            return search_type
    return None


def top_keywords_from_access_log(
    conn: sqlite3.Connection,
    days: int = 14,
    limit: int = 20,
    sort: str = "searches",
) -> list[dict[str, Any]]:
    """从 access_log 派生关键词排行——与 ``top_keywords`` 同形状。

    逐行读取 access_log 的 buyer_search 面：解析 query_summary 的 ``q``，
    重放 ``_normalize_keyword``（与写入端同一归一化 → 同口径），path 推导
    search_type，按 (day, search_type, keyword) 聚合：searches +1、
    result_count==0 时 zero_results +1；再跨 search_type 合并排行。

    归一化后为空（filter-only 搜索 / 空 q）的行跳过——与旧表
    ``record_buyer_keyword`` 的空关键词跳过语义一致。
    """
    import datetime as _dt

    days = max(1, min(int(days or 14), 90))
    limit = max(1, min(int(limit or 20), 100))
    start = _dt.datetime.now(_dt.UTC).date() - _dt.timedelta(days=days - 1)
    rows = conn.execute(
        "select substr(occurred_at, 1, 10) as day, path, query_summary, result_count"
        " from access_log"
        " where surface = 'buyer_search' and occurred_at >= ?",
        (start.isoformat(),),
    ).fetchall()
    # (keyword, search_type) → [searches, zero_results]
    agg: dict[tuple[str, str], list[int]] = {}
    for row in rows:
        search_type = _search_type_from_path(row["path"])
        if search_type is None:
            continue
        try:
            summary = json.loads(str(row["query_summary"] or "") or "{}")
        except (TypeError, ValueError):
            continue
        keyword = _normalize_keyword(summary.get("q") if isinstance(summary, dict) else "")
        if not keyword:
            continue  # filter-only / 空 q → 跳过（与旧表语义一致）
        zero_hit = 1 if int(row["result_count"] or 0) == 0 else 0
        bucket = agg.setdefault((keyword, search_type), [0, 0])
        bucket[0] += 1
        bucket[1] += zero_hit
    # 跨 search_type 合并（与 top_keywords 的查询期合并一致）
    merged: dict[str, dict[str, Any]] = {}
    for (keyword, search_type), (searches, zero_results) in agg.items():
        item = merged.setdefault(
            keyword,
            {
                "keyword": keyword,
                "searches": 0,
                "zero_results": 0,
                "agent_searches": 0,
                "listing_searches": 0,
            },
        )
        item["searches"] += searches
        item["zero_results"] += zero_results
        item[f"{search_type}_searches"] += searches
    # 与 SQL 版 top_keywords 排序语义一致：{order} DESC, searches DESC,
    # keyword ASC——主键与 searches 取负模拟降序，keyword 原序（升序）。
    order_key = sort if sort == "zero_results" else "searches"
    ranked = sorted(
        merged.values(),
        key=lambda item: (
            -item[order_key],
            -item["searches"],
            item["keyword"],
        ),
    )
    return ranked[:limit]
