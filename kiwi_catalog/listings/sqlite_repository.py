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

"""commerce_listings SQLite 实现（裸 sqlite3，无 ORM；镜像 agent_catalog 模式）。

行模型约定：所有 *_json 列落库前经 encode_json 序列化；读取后经 decode_json
还原为 Python 对象。公开函数必须进 tests/test_repository_abstraction.py 的
``_LISTING_MAPPING``（Protocol ↔ 实现双向校验）。
"""

from __future__ import annotations

import sqlite3
from typing import Any

from kiwi_catalog.db.session import decode_json, encode_json, now_iso
from kiwi_catalog.listings.domain import FRESH, LISTING_FRESHNESS_STATES

_JSON_COLUMNS = (
    "attributes_json",
    "regions_json",
    "tags_json",
    "commercial_hints_json",
    "handoff_destination_types_json",
)

_LISTING_COLUMNS = (
    "id",
    "listing_id",
    "listing_type",
    "owner_agent_id",
    "merchant_id",
    "source_product_ref",
    "publisher_listing_key",
    "source_revision",
    "title",
    "summary",
    "category",
    "brand",
    "attributes_json",
    "regions_json",
    "tags_json",
    "commercial_hints_json",
    "handoff_destination_types_json",
    "listing_digest",
    "publication_state",
    "listing_freshness_state",
    "published_at",
    "updated_at",
    "fresh_until",
    "created_at",
)


def _row_to_listing(row: sqlite3.Row) -> dict[str, Any]:
    """Row → dict；json 列解码（wire 层字段名，序列化器直接透传）。"""
    data = dict(row)
    for column in _JSON_COLUMNS:
        data[column] = decode_json(data.get(column), {})
    return data


def get_listing(conn: sqlite3.Connection, listing_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "select * from commerce_listings where listing_id = ?",
        (str(listing_id).strip(),),
    ).fetchone()
    return _row_to_listing(row) if row is not None else None


def get_listing_by_upsert_key(
    conn: sqlite3.Connection,
    listing_type: str,
    owner_agent_id: str,
    upsert_key: str,
) -> dict[str, Any] | None:
    """合并 source_product_ref / publisher_listing_key 两列定位。

    partial unique index 保证 (owner, type, key) 唯一；NULL 行（capability 缺
    publisher_listing_key）不参与 upsert key 定位（按 id 幂等新建）。
    """
    row = conn.execute(
        """
        select * from commerce_listings
        where owner_agent_id = ? and listing_type = ?
          and (source_product_ref = ? or publisher_listing_key = ?)
        order by id desc limit 1
        """,
        (owner_agent_id, listing_type, upsert_key, upsert_key),
    ).fetchone()
    return _row_to_listing(row) if row is not None else None


def insert_listing(
    conn: sqlite3.Connection,
    *,
    listing_id: str,
    listing_type: str,
    owner_agent_id: str,
    merchant_id: str,
    listing_digest: str,
    fresh_until: str,
    created_at: str,
    updated_at: str,
    **fields: Any,
) -> dict[str, Any]:
    columns = [
        "listing_id",
        "listing_type",
        "owner_agent_id",
        "merchant_id",
        "source_product_ref",
        "publisher_listing_key",
        "source_revision",
        "title",
        "summary",
        "category",
        "brand",
        "attributes_json",
        "regions_json",
        "tags_json",
        "commercial_hints_json",
        "handoff_destination_types_json",
        "listing_digest",
        "publication_state",
        "listing_freshness_state",
        "published_at",
        "updated_at",
        "fresh_until",
        "created_at",
    ]
    values: list[Any] = [
        listing_id,
        listing_type,
        owner_agent_id,
        merchant_id,
        fields.get("source_product_ref"),
        fields.get("publisher_listing_key"),
        fields.get("source_revision", ""),
        fields["title"],
        fields.get("summary", ""),
        fields["category"],
        fields.get("brand", ""),
        encode_json(fields.get("attributes", {})),
        encode_json(fields.get("regions", [])),
        encode_json(fields.get("tags", [])),
        encode_json(fields.get("commercial_hints", {})),
        encode_json(fields.get("handoff_destination_types", [])),
        listing_digest,
        "ACTIVE",
        FRESH,
        created_at,
        updated_at,
        fresh_until,
        created_at,
    ]
    conn.execute(
        f"insert into commerce_listings({', '.join(columns)}) values({', '.join('?' * len(columns))})",
        values,
    )
    row = conn.execute(
        "select * from commerce_listings where listing_id = ?", (listing_id,)
    ).fetchone()
    return _row_to_listing(row)


def update_listing(
    conn: sqlite3.Connection,
    listing_id: str,
    *,
    updated_at: str,
    fresh_until: str,
    listing_digest: str,
    **fields: Any,
) -> dict[str, Any] | None:
    """按 listing_id 全量刷新内容字段；publication_state 重置为 ACTIVE
    （重发布 = 重新激活，WITHDRAWN 后同 key 重发布回到可发现状态）。"""
    assignments = [
        "source_product_ref = ?",
        "publisher_listing_key = ?",
        "source_revision = ?",
        "title = ?",
        "summary = ?",
        "category = ?",
        "brand = ?",
        "attributes_json = ?",
        "regions_json = ?",
        "tags_json = ?",
        "commercial_hints_json = ?",
        "handoff_destination_types_json = ?",
        "listing_digest = ?",
        "publication_state = 'ACTIVE'",
        "listing_freshness_state = ?",
        "published_at = ?",
        "updated_at = ?",
        "fresh_until = ?",
    ]
    row = get_listing(conn, listing_id)
    if row is None:
        return None
    now = now_iso()
    values: list[Any] = [
        fields.get("source_product_ref"),
        fields.get("publisher_listing_key"),
        fields.get("source_revision", ""),
        fields["title"],
        fields.get("summary", ""),
        fields["category"],
        fields.get("brand", ""),
        encode_json(fields.get("attributes", {})),
        encode_json(fields.get("regions", [])),
        encode_json(fields.get("tags", [])),
        encode_json(fields.get("commercial_hints", {})),
        encode_json(fields.get("handoff_destination_types", [])),
        listing_digest,
        FRESH,
        row.get("published_at") or now,
        updated_at,
        fresh_until,
    ]
    conn.execute(
        f"update commerce_listings set {', '.join(assignments)} where listing_id = ?",
        (*values, listing_id),
    )
    fresh = conn.execute(
        "select * from commerce_listings where listing_id = ?", (listing_id,)
    ).fetchone()
    return _row_to_listing(fresh)


def set_publication_state(
    conn: sqlite3.Connection, listing_id: str, publication_state: str
) -> None:
    from kiwi_catalog.listings.domain import require_publication_state

    state = require_publication_state(publication_state)
    conn.execute(
        "update commerce_listings set publication_state = ?, updated_at = ? where listing_id = ?",
        (state, now_iso(), listing_id),
    )


def expire_stale_listings(conn: sqlite3.Connection, now: str) -> int:
    """On-read 惰性翻转（v0.4 §15.1）：FRESH 且 fresh_until < now → STALE。

    幂等 UPDATE（WHERE 已限定 freshness_state='FRESH'），返回翻转行数；
    无后台进程。调用方每次读 listing / 搜索前执行。
    """
    cursor = conn.execute(
        "update commerce_listings set listing_freshness_state = 'STALE', updated_at = ?"
        " where listing_freshness_state = 'FRESH' and fresh_until < ?",
        (now, now),
    )
    return cursor.rowcount


def list_listings_by_owner(
    conn: sqlite3.Connection,
    owner_agent_id: str,
    *,
    freshness_state: str | None = None,
    limit: int = 20,
    cursor: str | None = None,
) -> tuple[list[dict[str, Any]], str]:
    from kiwi_catalog.listings.domain import LISTING_FRESHNESS_STATES

    limit = max(1, min(int(limit), 100))
    clauses = ["owner_agent_id = ?"]
    values: list[Any] = [str(owner_agent_id).strip()]
    if freshness_state is not None:
        if freshness_state not in LISTING_FRESHNESS_STATES:
            raise ValueError(
                f"unknown listing_freshness_state {freshness_state!r}: not one of {LISTING_FRESHNESS_STATES}"
            )
        clauses.append("listing_freshness_state = ?")
        values.append(freshness_state)
    if cursor:
        # cursor 编码 "updated_at|listing_id"（ISO 时间戳含冒号，不能用 ":"）
        updated_at, listing_id = cursor.split("|", 1)
        clauses.append("(updated_at, id) < (?, (select id from commerce_listings where listing_id = ?))")
        values.extend([updated_at, listing_id])
    rows = conn.execute(
        f"""
        select * from commerce_listings
        where {' and '.join(clauses)}
        order by updated_at desc, id desc
        limit ?
        """,
        (*values, limit + 1),
    ).fetchall()
    result = [_row_to_listing(row) for row in rows[:limit]]
    next_cursor = ""
    if len(rows) > limit and result:
        last = result[-1]
        next_cursor = f"{last['updated_at']}|{last['listing_id']}"
    return result, next_cursor
