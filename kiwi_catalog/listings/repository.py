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

"""ListingRepository Protocol（适配接缝，镜像 agent_catalog/repository.py 模式）。

SQLite 实现见 sqlite_repository.py；tests/test_repository_abstraction.py 的
``_LISTING_MAPPING`` 双向校验 Protocol 方法 ↔ 实现函数（新增公开函数必须进
映射表，防漂移）。
"""

from __future__ import annotations

import sqlite3
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ListingRepository(Protocol):
    """commerce_listings 的持久化面（listing_id 定位 + upsert key 定位 + 状态写）。"""

    def get_listing(self, conn: sqlite3.Connection, listing_id: str) -> dict[str, Any] | None:
        """By listing_id. 返回含全部列的 dict 行（json 列已解码）。"""
        ...

    def get_listing_by_upsert_key(
        self,
        conn: sqlite3.Connection,
        listing_type: str,
        owner_agent_id: str,
        upsert_key: str,
    ) -> dict[str, Any] | None:
        """By (owner_agent_id, listing_type, upsert_key)。

        upsert_key = source_product_ref（product）或 publisher_listing_key
        （capability）；两列合并定位（行级幂等 upsert 的前提）。
        """
        ...

    def insert_listing(
        self,
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
        """插入新 listing 行。**fields 为其余列（source_product_ref /
        publisher_listing_key / title / category / summary / brand /
        attributes / regions / tags / commercial_hints /
        handoff_destination_types / source_revision）。"""
        ...

    def update_listing(
        self,
        conn: sqlite3.Connection,
        listing_id: str,
        *,
        updated_at: str,
        fresh_until: str,
        listing_digest: str,
        **fields: Any,
    ) -> dict[str, Any] | None:
        """按 listing_id 全量刷新内容字段（upsert 的 update 半边）。"""
        ...

    def set_publication_state(
        self, conn: sqlite3.Connection, listing_id: str, publication_state: str
    ) -> None:
        """发布状态写（withdraw → WITHDRAWN；governance → SUSPENDED；reinstate 受限）。"""
        ...

    def expire_stale_listings(self, conn: sqlite3.Connection, now: str) -> int:
        """On-read 惰性翻转（v0.4 §15.1）：FRESH 且 fresh_until < now → STALE。

        幂等 UPDATE，返回翻转行数；无后台进程。序列化以翻转后列值为准。
        """
        ...

    def list_listings_by_owner(
        self,
        conn: sqlite3.Connection,
        owner_agent_id: str,
        *,
        freshness_state: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str]:
        """publisher 自查（GET /v1/agents/{id}/listings）。cursor 为上一页
        (updated_at, id) 组合游标；返回 (rows, next_cursor)。"""
        ...
