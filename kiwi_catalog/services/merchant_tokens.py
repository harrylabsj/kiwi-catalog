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

"""Merchant token 分发核心逻辑（docs/kiwi-catalog-token-portal-design-v0.1 §4）。

HTTP handler（api/handlers/merchants.py）与本地 CLI（cli_merchant_commands.py）
共用同一实现：handler 负责 admin 校验/限流 + 组织响应，本模块只做数据操作。
所有写操作自带审计（append_catalog_audit，明文 token 永不进审计）。

明文 token 只在 approve / rotate 的返回值里出现一次；库中只存 SHA-256 摘要。
"""

from __future__ import annotations

import re
import secrets
import sqlite3
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.core.errors import ConflictError, NotFoundError
from kiwi_catalog.core.tokens import (
    generate_merchant_token,
    token_digest,
    token_matches,
)
from kiwi_catalog.db.session import now_iso

APPLICATION_STATUSES = ("pending", "approved", "rejected")
TOKEN_STATUSES = ("active", "revoked")


def _slug_from_name(name: str) -> str:
    """宽松降级 slug：agent_name → [a-z0-9-]，空则 'm'，截断 16 字符。"""
    slug = re.sub(r"[^a-z0-9-]+", "-", str(name or "").lower()).strip("-")
    return (slug or "m")[:16]


def new_platform_merchant_id(agent_name: str) -> str:
    """平台签发 merchant_id：``mkt_<slug>_<rand>``（防撞名、防枚举）。"""
    return f"mkt_{_slug_from_name(agent_name)}_{secrets.token_urlsafe(8)}"


def application_row(row: sqlite3.Row) -> dict[str, Any]:
    """merchant_applications 行的 public 投影（wire 形状，handler/CLI 共用）。"""
    return {
        "application_id": row["application_id"],
        "status": row["status"],
        "domain": row["domain"],
        "agent_name": row["agent_name"],
        "contact_email": row["contact_email"],
        "purpose": row["purpose"],
        "merchant_id": row["merchant_id"],
        "review_note": row["review_note"],
        "created_at": row["created_at"],
        "reviewed_at": row["reviewed_at"],
    }


def list_applications(
    conn: sqlite3.Connection, status: str = "", limit: int = 50
) -> list[dict[str, Any]]:
    """工单列表（倒序）；status 为空返回全部。"""
    if status:
        rows = conn.execute(
            "select * from merchant_applications where status = ?"
            " order by application_id desc limit ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "select * from merchant_applications order by application_id desc limit ?",
            (limit,),
        ).fetchall()
    return [application_row(row) for row in rows]


def get_application(conn: sqlite3.Connection, application_id: int) -> dict[str, Any]:
    row = conn.execute(
        "select * from merchant_applications where application_id = ?", (application_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Unknown application: {application_id}")
    return application_row(row)


def approve_application(conn: sqlite3.Connection, application_id: int) -> dict[str, Any]:
    """原子签发：平台 merchant_id → 影子 merchants 行 → merchant_tokens active
    行 → 工单置 approved。返回含明文 token（仅此一次）。重复 approve → 409。"""
    row = conn.execute(
        "select * from merchant_applications where application_id = ?", (application_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Unknown application: {application_id}")
    if str(row["status"]) != "pending":
        raise ConflictError(f"application {application_id} already {row['status']}")
    agent_name = str(row["agent_name"])
    merchant_id = new_platform_merchant_id(agent_name)
    now = now_iso()
    conn.execute(
        "insert or ignore into merchants(id, name, created_at, updated_at)"
        " values (?, ?, ?, ?)",
        (merchant_id, agent_name, now, now),
    )
    token = generate_merchant_token()
    conn.execute(
        "insert or replace into merchant_tokens"
        " (merchant_id, token_hash, status, issued_at) values (?, ?, 'active', ?)",
        (merchant_id, token_digest(token), now),
    )
    conn.execute(
        "update merchant_applications set status = 'approved', merchant_id = ?,"
        " reviewed_at = ? where application_id = ?",
        (merchant_id, now, application_id),
    )
    append_catalog_audit(
        conn,
        "",
        "admin",
        "merchant_token_issued",
        {
            "application_id": application_id,
            "merchant_id": merchant_id,
            "token_prefix": token[:24],
        },
    )
    return {
        "application_id": application_id,
        "merchant_id": merchant_id,
        "token": token,
        "token_prefix": token[:24],
    }


def reject_application(
    conn: sqlite3.Connection, application_id: int, review_note: str = ""
) -> None:
    """工单置 rejected + review_note；仅 pending 可拒（否则 409）。"""
    row = conn.execute(
        "select * from merchant_applications where application_id = ?", (application_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Unknown application: {application_id}")
    if str(row["status"]) != "pending":
        raise ConflictError(f"application {application_id} already {row['status']}")
    conn.execute(
        "update merchant_applications set status = 'rejected', review_note = ?,"
        " reviewed_at = ? where application_id = ?",
        (review_note, now_iso(), application_id),
    )
    append_catalog_audit(
        conn, "", "admin", "merchant_application_rejected", {"application_id": application_id}
    )


def require_token_row(conn: sqlite3.Connection, merchant_id: str) -> sqlite3.Row:
    row = conn.execute(
        "select * from merchant_tokens where merchant_id = ?", (merchant_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"No merchant token for {merchant_id}")
    return row


def rotate_token(conn: sqlite3.Connection, merchant_id: str) -> dict[str, Any]:
    """新随机 token 覆盖（旧 hash 作废），rotated_at = now；明文仅此一次。

    故意只走 admin（泄露场景下旧 token 可能在攻击者手里，自助轮换
    = 攻击者也能轮换）。
    """
    require_token_row(conn, merchant_id)
    now = now_iso()
    token = generate_merchant_token()
    conn.execute(
        "update merchant_tokens set token_hash = ?, status = 'active',"
        " rotated_at = ? where merchant_id = ?",
        (token_digest(token), now, merchant_id),
    )
    append_catalog_audit(
        conn,
        "",
        "admin",
        "merchant_token_rotated",
        {"merchant_id": merchant_id, "token_prefix": token[:24]},
    )
    return {"merchant_id": merchant_id, "token": token, "token_prefix": token[:24]}


def revoke_token(conn: sqlite3.Connection, merchant_id: str) -> str:
    """active 行置 revoked；之后所有带该 token 的写请求 fail-closed。
    已 revoked 重复吊销幂等返回。返回当前状态。"""
    row = require_token_row(conn, merchant_id)
    if str(row["status"]) == "revoked":
        return "revoked"
    conn.execute(
        "update merchant_tokens set status = 'revoked', revoked_at = ?"
        " where merchant_id = ?",
        (now_iso(), merchant_id),
    )
    append_catalog_audit(conn, "", "admin", "merchant_token_revoked", {"merchant_id": merchant_id})
    return "revoked"


def resolve_merchant_by_token(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    """按呈现 token 的 SHA-256 恒时匹配 merchant_tokens active 行（token 即身份）。

    只认 active：已吊销 token 自查同样 fail-closed（与写路径一致）。
    """
    digest = token_digest(token)
    for row in conn.execute("select * from merchant_tokens where status = 'active'").fetchall():
        if token_matches(digest, str(row["token_hash"])):
            return row
    return None


def merchant_status(
    conn: sqlite3.Connection, token_row: sqlite3.Row
) -> dict[str, Any]:
    """merchant 自查投影：merchant_id、token 状态与名下 agent / listing 计数。"""
    merchant_id = str(token_row["merchant_id"])
    agents = conn.execute(
        "select count(*) as n from catalog_agents where merchant_id = ?", (merchant_id,)
    ).fetchone()
    listings = conn.execute(
        "select count(*) as n from commerce_listings where merchant_id = ?", (merchant_id,)
    ).fetchone()
    return {
        "merchant_id": merchant_id,
        "token_status": token_row["status"],
        "issued_at": token_row["issued_at"],
        "rotated_at": token_row["rotated_at"],
        "revoked_at": token_row["revoked_at"],
        "agents_count": int(agents["n"]),
        "listings_count": int(listings["n"]),
    }
