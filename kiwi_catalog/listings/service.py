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

"""Listing 写服务（升级计划 §5；产品文档 v0.4 §6/§13）。

- ``publish_listing``：canonical 字段 → digest → 行级幂等 upsert
  （product→source_product_ref、capability→publisher_listing_key；缺省按 id
  新建）→ fresh_until = publisher 声明或服务端默认（24h/7d）→ 刷新 FRESH；
- ``withdraw_listing`` / ``reinstate_listing``：owner token 校验（publisher
  自治）；reinstate 仅 SUSPENDED 且 owner Agent 未 suspended/rejected。

请求级幂等（五步模板：replay→rate limit→claim→work→complete→clear）在
api/handlers/listings.py；本模块只做事务窗口内的业务写。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from kiwi_catalog.core.errors import NotFoundError, PermissionDenied
from kiwi_catalog.db.session import now_iso
from kiwi_catalog.listings import sqlite_repository as repo
from kiwi_catalog.listings.domain import (
    ACTIVE,
    PRODUCT,
    SUSPENDED,
    WITHDRAWN,
    DEFAULT_TTL_HOURS,
)
from kiwi_catalog.listings.serialization import new_listing_id


def _compute_listing_digest(canonical: dict[str, Any]) -> str:
    """内容字段 canonical JSON + sha256（不含 listing_id/digest/时间戳/状态）。

    同内容 digest 不变——shopping-cli 侧发布去重与服务端幂等 upsert 的锚点。
    """
    content = {key: value for key, value in canonical.items() if key != "fresh_until"}
    serialized = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _default_fresh_until(listing_type: str, published_fresh_until: str | None = None) -> str:
    """fresh_until：publisher 声明优先；无声明用服务端默认 TTL（评审 P1-2 拍板）。"""
    if published_fresh_until:
        return published_fresh_until
    hours = DEFAULT_TTL_HOURS.get(listing_type, DEFAULT_TTL_HOURS[PRODUCT])
    # 与 now_iso() 同格式（UTC + 无微秒）：expire 比较是纯字符串比较，
    # 微秒/时区不一致会让 TTL 偏移（历史教训）。
    return (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=hours)).isoformat()


def _owner_agent(conn: sqlite3.Connection, owner_agent_id: str) -> dict[str, Any] | None:
    return conn.execute(
        "select * from catalog_agents where catalog_agent_id = ?", (owner_agent_id,)
    ).fetchone()


def owner_agent_merchant_id(conn: sqlite3.Connection, owner_agent_id: str) -> str:
    """owner agent 绑定的 merchant_id（未绑定返回空串；agent 不存在也返回空串）。

    供读面接口（GET /v1/agents/{id}/listings）做 owner 身份解析——绑定关系是
    该面授权判断的依据。
    """
    row = _owner_agent(conn, owner_agent_id)
    return str(row["merchant_id"] or "") if row is not None else ""


def _require_owner_active(
    conn: sqlite3.Connection,
    owner_agent_id: str,
    merchant_id: str,
) -> None:
    """发布前提：owner Agent 存在且未 suspended/rejected（fail-closed）。"""
    row = _owner_agent(conn, owner_agent_id)
    if row is None:
        raise NotFoundError(f"Unknown owner catalog agent: {owner_agent_id}")
    administrative = str(row["administrative_state"] or "active")
    if administrative in ("suspended", "rejected"):
        raise PermissionDenied(
            f"owner catalog agent {owner_agent_id} is {administrative}; listing cannot be published"
        )
    merchant = str(row["merchant_id"] or "")
    if merchant and merchant != merchant_id:
        raise PermissionDenied(
            f"owner catalog agent {owner_agent_id} is bound to merchant {merchant}, not {merchant_id}"
        )


def publish_listing(
    conn: sqlite3.Connection,
    canonical: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    """upsert 一条 listing（行级幂等，见模块 docstring）。

    Returns (row, created: bool)。
    """
    listing_type = canonical["listing_type"]
    owner_agent_id = canonical["owner_agent_id"]
    merchant_id = canonical["merchant_id"]
    _require_owner_active(conn, owner_agent_id, merchant_id)

    upsert_key = canonical.get("source_product_ref") or canonical.get("publisher_listing_key")
    existing: dict[str, Any] | None = None
    if upsert_key:
        existing = repo.get_listing_by_upsert_key(
            conn, listing_type, owner_agent_id, str(upsert_key)
        )

    digest = _compute_listing_digest(canonical)
    fresh_until = _default_fresh_until(listing_type, canonical.get("fresh_until"))
    timestamp = now_iso()
    # 显式传参的键（listing_type/owner_agent_id/merchant_id）从内容字段中排除，
    # 避免 insert_listing 收到重复 kwargs
    _FIXED_FIELDS = frozenset({"listing_type", "owner_agent_id", "merchant_id"})
    content_fields = {
        key: value
        for key, value in canonical.items()
        if key not in _FIXED_FIELDS and key != "fresh_until"
    }

    if existing is None:
        created = True
        try:
            row = repo.insert_listing(
                conn,
                listing_id=new_listing_id(),
                listing_type=listing_type,
                owner_agent_id=owner_agent_id,
                merchant_id=merchant_id,
                listing_digest=digest,
                fresh_until=fresh_until,
                created_at=timestamp,
                updated_at=timestamp,
                **content_fields,
            )
        except sqlite3.IntegrityError:
            # 审查 P2：check-then-act 竞态窗口（两个连接同时读到「不存在」，
            # 后到者撞部分唯一索引）——重读一次走 update 半边，干净的行级
            # upsert 而非 500。
            raced = (
                repo.get_listing_by_upsert_key(conn, listing_type, owner_agent_id, str(upsert_key))
                if upsert_key
                else None
            )
            if raced is None:
                raise
            existing = raced
            created = False
            row = repo.update_listing(
                conn,
                str(existing["listing_id"]),
                updated_at=timestamp,
                fresh_until=fresh_until,
                listing_digest=digest,
                **content_fields,
            )
    else:
        row = repo.update_listing(
            conn,
            str(existing["listing_id"]),
            updated_at=timestamp,
            fresh_until=fresh_until,
            listing_digest=digest,
            **content_fields,
        )
        created = False
        assert row is not None  # update 后立即重读，事务窗口内必存在
    return row, created


def withdraw_listing(
    conn: sqlite3.Connection,
    listing_id: str,
    *,
    actor: str,
    merchant_id: str,
) -> dict[str, Any]:
    """publisher 主动下架（v0.4 §7.1 WITHDRAWN）。owner 校验在 handler 完成。"""
    row = repo.get_listing(conn, listing_id)
    if row is None:
        raise NotFoundError(f"Unknown listing: {listing_id}")
    if str(row.get("merchant_id") or "") != merchant_id:
        raise PermissionDenied("listing is owned by a different merchant")
    if row.get("publication_state") == WITHDRAWN:
        return row
    repo.set_publication_state(conn, listing_id, WITHDRAWN)
    return repo.get_listing(conn, listing_id) or row


def reinstate_listing(
    conn: sqlite3.Connection,
    listing_id: str,
    *,
    actor: str,
    merchant_id: str,
) -> dict[str, Any]:
    """SUSPENDED → ACTIVE（仅 publisher/governance policy；v0.4 §13）。

    前置：owner Agent 未 suspended/rejected（fail-closed）。WITHDRAWN 的
    listing 不能 reinstate——需重新 publish（同 key upsert 回到 ACTIVE）。
    """
    row = repo.get_listing(conn, listing_id)
    if row is None:
        raise NotFoundError(f"Unknown listing: {listing_id}")
    if str(row.get("merchant_id") or "") != merchant_id:
        raise PermissionDenied("listing is owned by a different merchant")
    if row.get("publication_state") != SUSPENDED:
        raise PermissionDenied(f"only SUSPENDED listings can be reinstated (got {row.get('publication_state')})")
    _require_owner_active(conn, str(row.get("owner_agent_id") or ""), merchant_id)
    repo.set_publication_state(conn, listing_id, ACTIVE)
    return repo.get_listing(conn, listing_id) or row
