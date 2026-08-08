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

"""Listing 搜索（升级计划 §6；v0.4 §8/§12）。

- JSON1 结构化过滤：只对白名单路径 json_extract（attributes 路径格式约束
  见 domain.py ATTRIBUTE_PATH_SEGMENT_RE；commercial_hints 键白名单）；
- agent join 排除：owner suspended/rejected 的 Listing 直接不返回
  （EXISTS 子查询，DoD #12 suppress 半边）；
- 默认 publication_state='ACTIVE'（withdrawn/suspended 不返回）；
- 确定性 ranking：hard filter → match → freshness → agent 状态 →
  id DESC tie-breaker（v0.4 §12；无声誉混入）；
- cursor 分页：(updated_at, id) 组合游标（复用 agent_catalog/search.py 模式）。
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

import sqlite3

from kiwi_catalog.db.session import now_iso
from kiwi_catalog.listings.domain import (
    ACTIVE,
    ATTRIBUTE_PATH_SEGMENT_RE,
    COMMERCIAL_HINTS_KEYS,
    LISTING_FRESHNESS_STATES,
    LISTING_TYPES,
    MAX_ATTRIBUTE_PATH_DEPTH,
)
from kiwi_catalog.listings.sqlite_repository import (
    decode_cursor,
    encode_cursor,
    expire_stale_listings,
)

# ── 搜索分页游标（审查 P1-6）──────────────────────────────────────────────
# 搜索的排序键是 (freshness rank, updated_at desc, id desc)；旧游标只编码
# (updated_at, id)，STALE 行跨页不可达。新格式 "rank|updated_at|listing_id"
# 与 encode_cursor（list-by-owner 用，其排序键就是 (updated_at, id)）分开。
# 旧格式（2 段）解码时 rank=None → 谓词退化为旧行为。


def _encode_search_cursor(freshness_state: str, updated_at: str, listing_id: str) -> str:
    rank = "0" if freshness_state == "FRESH" else "1"
    return urllib.parse.quote(f"{rank}|{updated_at}|{listing_id}", safe="")


def _decode_search_cursor(cursor: str) -> tuple[str | None, str, str]:
    """→ (rank|None, updated_at, listing_id)；畸形抛 ValueError（→ 4xx）。"""
    parts = urllib.parse.unquote(str(cursor)).split("|")
    if len(parts) == 3:
        rank, updated_at, listing_id = parts
        if rank not in ("0", "1"):
            raise ValueError("unknown freshness rank in cursor")
        return rank, updated_at, listing_id
    if len(parts) == 2:
        return None, parts[0], parts[1]
    raise ValueError("malformed cursor")


class SearchQueryError(ValueError):
    """搜索 query 非法（fail-closed：未知键/非法值拒绝，不静默忽略）。"""


_SEARCH_QUERY_KEYS = frozenset({
    "q",
    "listing_type",
    "category",
    "brand",
    "region",
    "tag",
    "min_moq",
    "max_moq",
    "supports_bulk_quote",
    "supports_customization",
    "freshness_state",
    "handoff_destination_type",
    "limit",
    "cursor",
})

# attribute.<path>=<value> 前缀
_ATTRIBUTE_FILTER_PREFIX = "attribute."


def _validate_attribute_path(path: str) -> str:
    segments = path.split(".")
    if not 1 <= len(segments) <= MAX_ATTRIBUTE_PATH_DEPTH:
        raise SearchQueryError(
            f"attribute filter path must have 1..{MAX_ATTRIBUTE_PATH_DEPTH} segments: {path!r}"
        )
    for segment in segments:
        if not re.fullmatch(ATTRIBUTE_PATH_SEGMENT_RE, segment):
            raise SearchQueryError(f"attribute filter path segment {segment!r} is invalid")
    return path


def _json_scalar_match(column: str, key: str, value: str) -> tuple[str, Any]:
    """构造 json_extract 过滤条件 + 绑定值。

    MVP 语义（升级计划 §6）：attribute 过滤只做**文本精确匹配**——JSON1
    extract 返回类型与存储值绑定（数字→REAL、字符串→TEXT、布尔→1/0），
    查询端无法知道存储类型；数字范围过滤走 min_moq/max_moq 等结构化路径。
    true/false 显式转 1/0（JSON1 布尔返回 INTEGER）。
    """
    path = f"$.{key}"
    if value in ("true", "false"):
        return f"json_extract({column}, '{path}') = ?", 1 if value == "true" else 0
    return f"json_extract({column}, '{path}') = ?", value


def search_listings(
    conn: sqlite3.Connection,
    query: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    """按结构化 query 搜索 listing（默认 ACTIVE + agent 状态 join 排除）。

    Returns (rows, next_cursor)。rows 为 wire 字段形状的 dict 列表
    （json 列已解码；序列化由 serialization.py 负责）。
    """
    from kiwi_catalog.listings.sqlite_repository import _row_to_listing

    unknown = {key for key in query if not key.startswith(_ATTRIBUTE_FILTER_PREFIX)}
    unknown = unknown - _SEARCH_QUERY_KEYS
    if unknown:
        raise SearchQueryError(f"unknown listing search query keys: {sorted(unknown)}")
    # attribute.<path> 过滤键单独收集
    attribute_filters: list[tuple[str, str]] = []
    for key in query:
        if key.startswith(_ATTRIBUTE_FILTER_PREFIX):
            path = _validate_attribute_path(key[len(_ATTRIBUTE_FILTER_PREFIX):])
            attribute_filters.append((path, str(query[key])))

    limit = 20
    raw_limit = query.get("limit")
    if raw_limit is not None:
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError) as exc:
            raise SearchQueryError("limit must be an integer") from exc
        if not 1 <= limit <= 100:
            raise SearchQueryError("limit must be between 1 and 100")
    cursor = str(query.get("cursor") or "")

    # on-read 惰性翻转（v0.4 §15.1）：先过期再查，fresh_until 索引路径生效
    expire_stale_listings(conn, now_iso())

    where: list[str] = ["publication_state = ?"]
    values: list[Any] = [ACTIVE]

    q = str(query.get("q") or "").strip()
    if q:
        where.append("(title like ? or category like ? or brand like ? or summary like ?)")
        pattern = f"%{q}%"
        values.extend([pattern, pattern, pattern, pattern])

    listing_type = str(query.get("listing_type") or "").strip()
    if listing_type:
        if listing_type not in LISTING_TYPES:
            raise SearchQueryError(f"listing_type must be one of {LISTING_TYPES}")
        where.append("listing_type = ?")
        values.append(listing_type)

    for column, key in (("category", "category"), ("brand", "brand")):
        raw = str(query.get(key) or "").strip()
        if raw:
            where.append(f"{column} = ?")
            values.append(raw)

    region = str(query.get("region") or "").strip()
    if region:
        where.append("exists (select 1 from json_each(regions_json) where json_each.value = ?)")
        values.append(region)

    tag = str(query.get("tag") or "").strip()
    if tag:
        where.append("exists (select 1 from json_each(tags_json) where json_each.value = ?)")
        values.append(tag)

    for key in ("min_moq", "max_moq"):
        raw = query.get(key)
        if raw in (None, ""):  # FastAPI 默认参数传空字符串，视为未提供
            continue
        try:
            number = int(raw)
        except (TypeError, ValueError) as exc:
            raise SearchQueryError(f"{key} must be an integer") from exc
        if number < 1:
            raise SearchQueryError(f"{key} must be a positive integer")
        op = ">=" if key == "min_moq" else "<="
        # 绑定 int：SQLite 数值比较（json() 包装会产生 TEXT vs INTEGER 不匹配）
        where.append(f"json_extract(commercial_hints_json, '$.moq') {op} ?")
        values.append(number)

    for key in ("supports_bulk_quote", "supports_customization"):
        raw = query.get(key)
        if raw in (None, ""):  # FastAPI 默认参数传空字符串，视为未提供
            continue
        if raw not in (True, False, "true", "false", "1", "0"):
            raise SearchQueryError(f"{key} must be a boolean")
        flag = 1 if raw in (True, "true", "1") else 0
        # JSON1 布尔返回 INTEGER 1/0：绑定 int（'true' 文本比较会失败）
        where.append(f"json_extract(commercial_hints_json, '$.{key}') = ?")
        values.append(flag)

    freshness = str(query.get("freshness_state") or "").strip()
    if freshness:
        if freshness not in LISTING_FRESHNESS_STATES:
            raise SearchQueryError(f"freshness_state must be one of {LISTING_FRESHNESS_STATES}")
        where.append("listing_freshness_state = ?")
        values.append(freshness)

    handoff = str(query.get("handoff_destination_type") or "").strip()
    if handoff:
        where.append(
            "exists (select 1 from json_each(handoff_destination_types_json)"
            " where json_each.value = ?)"
        )
        values.append(handoff)

    for path, value in attribute_filters:
        condition, bound = _json_scalar_match("attributes_json", path, value)
        where.append(condition)
        values.append(bound)

    # agent join 排除（DoD #12）：owner suspended/rejected 直接不返回
    where.append(
        "not exists (select 1 from catalog_agents ca"
        " where ca.catalog_agent_id = commerce_listings.owner_agent_id"
        " and ca.administrative_state in ('suspended','rejected'))"
    )

    if cursor:
        try:
            rank, updated_at, listing_id = _decode_search_cursor(cursor)
        except ValueError as exc:
            raise SearchQueryError(f"malformed cursor: {exc}") from exc
        if rank is None:
            # 旧格式游标（在途分页会话）：保持旧谓词（审查 P1-6 前的行为）
            where.append(
                "(updated_at, id) < (?, (select id from commerce_listings where listing_id = ?))"
            )
            values.extend([updated_at, listing_id])
        else:
            # 键集谓词与排序键（freshness rank asc, updated_at desc, id desc）
            # 严格同键（审查 P1-6）：rank 更大整组在界后；同 rank 按
            # updated_at/id 递减比较。两条 rank 分支是互斥 OR——必须包在
            # 单个 where 项里，否则被 ' and ' 连接后恒为空集。
            where.append(
                "(case when listing_freshness_state = 'FRESH' then 0 else 1 end) > ?"
                " or ("
                "(case when listing_freshness_state = 'FRESH' then 0 else 1 end) = ?"
                " and (updated_at < ?"
                " or (updated_at = ? and id <"
                " (select id from commerce_listings where listing_id = ?)))"
                ")"
            )
            values.extend([int(rank), int(rank), updated_at, updated_at, listing_id])

    # deterministic ranking（v0.4 §12）：无声誉混入；id DESC 稳定 tie-breaker
    rows = conn.execute(
        f"""
        select * from commerce_listings
        where {' and '.join(where)}
        order by
          (case when listing_freshness_state = 'FRESH' then 0 else 1 end) asc,
          updated_at desc,
          id desc
        limit ?
        """,
        (*values, limit + 1),
    ).fetchall()

    results = [_row_to_listing(row) for row in rows[:limit]]
    next_cursor = ""
    if len(rows) > limit and results:
        last = results[-1]
        next_cursor = _encode_search_cursor(
            str(last["listing_freshness_state"] or ""),
            str(last["updated_at"]),
            str(last["listing_id"]),
        )
    return results, next_cursor
