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

"""Merchant token 分发 API（docs/kiwi-catalog-token-portal-design-v0.1 §4）。

7 条路由：applications 提交（公开）/ 列表（admin）/ approve（admin 签发，
明文 token 仅此一次）/ reject（admin）；merchant token rotate / revoke
（admin）；/v1/merchants/self 自查（token 即身份）。

认证：admin 端点 fail-closed（无默认 token，未配置即拒绝）；公开申请面
按联系邮箱限流。明文 token 永不落库、不进审计（审计只记 merchant_id +
token_prefix 指纹）。
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.handlers.common import require_field
from kiwi_catalog.core.errors import (
    AuthError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from kiwi_catalog.core.tokens import (
    generate_merchant_token,
    token_digest,
    token_matches,
)
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services.agent_catalog_writes import normalize_canonical_domain
from kiwi_catalog.services.rate_limit import (
    SQLiteRateLimitBackend,
    enforce_rate_limit,
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_APPLY_RATE_LIMIT_PER_HOUR_ENV = "KIWI_CATALOG_APPLY_RATE_LIMIT_PER_HOUR"

_APPLICATION_STATUSES = ("pending", "approved", "rejected")
_TOKEN_STATUSES = ("active", "revoked")


def _apply_rate_limit_per_hour() -> int:
    raw = os.environ.get(_APPLY_RATE_LIMIT_PER_HOUR_ENV) or ""
    try:
        return max(0, int(raw))
    except ValueError:
        return 5


def _slug_from_name(name: str) -> str:
    """宽松降级 slug：agent_name → [a-z0-9-]，空则 'm'，截断 16 字符。"""
    slug = re.sub(r"[^a-z0-9-]+", "-", str(name or "").lower()).strip("-")
    return (slug or "m")[:16]


def _new_platform_merchant_id(agent_name: str) -> str:
    """平台签发 merchant_id：``mkt_<slug>_<rand>``（防撞名、防枚举）。"""
    return f"mkt_{_slug_from_name(agent_name)}_{secrets.token_urlsafe(8)}"


def _application_row(row: sqlite3.Row) -> dict[str, Any]:
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


def submit_application(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/merchants/applications（公开）。

    校验域名（bare hostname）/ 名称 / 邮箱；按邮箱限流（固定窗口）；
    写 pending 工单。响应不含任何凭证。
    """
    domain = normalize_canonical_domain(require_field(payload, "domain"))
    agent_name = str(require_field(payload, "agent_name")).strip()
    contact_email = str(require_field(payload, "contact_email")).strip()
    purpose = str(payload.get("purpose") or "").strip()
    if not agent_name:
        raise ValidationError("agent_name is required")
    if not _EMAIL_RE.match(contact_email):
        raise ValidationError("contact_email must be a valid email address")
    if len(agent_name) > 200 or len(contact_email) > 200 or len(purpose) > 2000:
        raise ValidationError("application fields exceed size limits")

    with db_session(db_path) as conn:
        limit = _apply_rate_limit_per_hour()
        if limit > 0:
            backend = SQLiteRateLimitBackend(
                conn, table="merchant_application_limits", key_column="actor_key"
            )
            enforce_rate_limit(
                backend,
                key=f"apply:{contact_email.lower()}",
                limit=limit,
                window_seconds=3600,
                description=f"merchant application submit ({limit}/hour per email)",
            )
        cursor = conn.execute(
            """
            insert into merchant_applications
                (status, domain, agent_name, contact_email, purpose, created_at)
            values ('pending', ?, ?, ?, ?, ?)
            """,
            (domain, agent_name, contact_email, purpose, now_iso()),
        )
        application_id = int(cursor.lastrowid or 0)
        row = conn.execute(
            "select * from merchant_applications where application_id = ?",
            (application_id,),
        ).fetchone()
        return {"ok": True, "application": _application_row(row)}


def _auth_payload_with_query_token(
    payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET 无 body，admin token 经 query string 传递（审查 P2 既有惯例：
    listings 自查端点同构；token 经 query 已记录 CLAUDE.md 不修）。"""
    merged = dict(payload or {})
    q_token = str(query.get("admin_token") or "").strip()
    if q_token:
        merged["admin_token"] = q_token
    return merged


def list_applications(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/merchants/applications?status=…（admin）。

    供门户后台渲染待审列表；status 过滤可选，不传返回全部（倒序）。
    """
    api_auth.require_admin_token(_auth_payload_with_query_token(payload, query))
    status = str(query.get("status") or "").strip()
    if status and status not in _APPLICATION_STATUSES:
        raise ValidationError(f"status must be one of {_APPLICATION_STATUSES}")
    limit = min(int(query.get("limit") or "50"), 100)
    with db_session(db_path) as conn:
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
        return {"ok": True, "results": [_application_row(row) for row in rows]}


def approve_application(
    db_path: str | Path, application_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/applications/{id}/approve（admin 签发）。

    原子完成：平台签发 merchant_id → 影子 merchants 行（INSERT OR IGNORE，
    不覆盖外部业务字段）→ merchant_tokens active 行 → 工单置 approved。
    响应含明文 token —— 仅此一次；审计只记 merchant_id + token_prefix。
    重复 approve → ConflictError。
    """
    api_auth.require_admin_token(payload)
    try:
        app_id = int(str(application_id).strip())
    except ValueError as exc:
        raise ValidationError("application_id must be an integer") from exc

    with db_session(db_path) as conn:
        row = conn.execute(
            "select * from merchant_applications where application_id = ?", (app_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"Unknown application: {app_id}")
        if str(row["status"]) != "pending":
            raise ConflictError(
                f"application {app_id} already {row['status']}"
            )
        agent_name = str(row["agent_name"])
        merchant_id = _new_platform_merchant_id(agent_name)
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
            (merchant_id, now, app_id),
        )
        append_catalog_audit(
            conn,
            "",
            "admin",
            "merchant_token_issued",
            {
                "application_id": app_id,
                "merchant_id": merchant_id,
                "token_prefix": token[:24],
            },
        )
        return {
            "ok": True,
            "application_id": app_id,
            "merchant_id": merchant_id,
            "token": token,
            "token_prefix": token[:24],
        }


def reject_application(
    db_path: str | Path, application_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/applications/{id}/reject（admin）。"""
    api_auth.require_admin_token(payload)
    try:
        app_id = int(str(application_id).strip())
    except ValueError as exc:
        raise ValidationError("application_id must be an integer") from exc
    review_note = str(payload.get("review_note") or "").strip()
    if len(review_note) > 2000:
        raise ValidationError("review_note exceeds size limit")

    with db_session(db_path) as conn:
        row = conn.execute(
            "select * from merchant_applications where application_id = ?", (app_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"Unknown application: {app_id}")
        if str(row["status"]) != "pending":
            raise ConflictError(f"application {app_id} already {row['status']}")
        now = now_iso()
        conn.execute(
            "update merchant_applications set status = 'rejected', review_note = ?,"
            " reviewed_at = ? where application_id = ?",
            (review_note, now, app_id),
        )
        append_catalog_audit(
            conn, "", "admin", "merchant_application_rejected", {"application_id": app_id}
        )
        return {"ok": True, "application_id": app_id, "status": "rejected"}


def _require_token_row(conn: sqlite3.Connection, merchant_id: str) -> sqlite3.Row:
    row = conn.execute(
        "select * from merchant_tokens where merchant_id = ?", (merchant_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"No merchant token for {merchant_id}")
    return row


def rotate_token(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/{merchant_id}/rotate（admin）。

    新随机 token 覆盖（旧 hash 作废），rotated_at = now。明文 token 仅此
    一次。故意走 admin（泄露场景下旧 token 可能在攻击者手里，自助轮换
    = 攻击者也能轮换）。
    """
    api_auth.require_admin_token(payload)
    merchant_id = str(merchant_id).strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required")
    with db_session(db_path) as conn:
        _require_token_row(conn, merchant_id)
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
        return {
            "ok": True,
            "merchant_id": merchant_id,
            "token": token,
            "token_prefix": token[:24],
        }


def revoke_token(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/{merchant_id}/revoke（admin）。

    active 行置 revoked；之后所有带该 token 的写请求 fail-closed。已
    revoked 重复吊销幂等返回 ok（不报错）。
    """
    api_auth.require_admin_token(payload)
    merchant_id = str(merchant_id).strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required")
    with db_session(db_path) as conn:
        row = _require_token_row(conn, merchant_id)
        if str(row["status"]) == "revoked":
            return {"ok": True, "merchant_id": merchant_id, "token_status": "revoked"}
        now = now_iso()
        conn.execute(
            "update merchant_tokens set status = 'revoked', revoked_at = ?"
            " where merchant_id = ?",
            (now, merchant_id),
        )
        append_catalog_audit(
            conn,
            "",
            "admin",
            "merchant_token_revoked",
            {"merchant_id": merchant_id},
        )
        return {"ok": True, "merchant_id": merchant_id, "token_status": "revoked"}


def _resolve_merchant_by_token(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    """按呈现 token 的 SHA-256 恒时匹配 merchant_tokens active 行（token 即身份）。

    只认 active：已吊销 token 自查同样 fail-closed（与写路径一致）。
    """
    digest = token_digest(token)
    for row in conn.execute(
        "select * from merchant_tokens where status = 'active'"
    ).fetchall():
        if token_matches(digest, str(row["token_hash"])):
            return row
    return None


def self_status(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/merchants/self?owner_token=…（token 即身份，商家自查）。

    返回 merchant_id、token 状态与名下 agent / listing 计数。GET 无 body，
    token 经 query string（审查 P2：已记录 CLAUDE.md 不修）。admin 可带
    admin_token + merchant_id 查任意商家。
    """
    merchant_id = str(query.get("merchant_id") or "").strip()
    presented = str(query.get("owner_token") or payload.get("owner_token") or "").strip()
    auth_payload = _auth_payload_with_query_token(payload, query)
    with db_session(db_path) as conn:
        if merchant_id:
            api_auth.require_admin_token(auth_payload)
            token_row: sqlite3.Row | None = _require_token_row(conn, merchant_id)
        else:
            if not presented:
                raise AuthError("invalid owner token")
            token_row = _resolve_merchant_by_token(conn, presented)
            if token_row is None:
                raise AuthError("invalid owner token")
            merchant_id = str(token_row["merchant_id"])
        assert token_row is not None  # 两条分支都保证非空（fail-closed）
        agents = conn.execute(
            "select count(*) as n from catalog_agents where merchant_id = ?",
            (merchant_id,),
        ).fetchone()
        listings = conn.execute(
            "select count(*) as n from commerce_listings where merchant_id = ?",
            (merchant_id,),
        ).fetchone()
        return {
            "ok": True,
            "merchant_id": merchant_id,
            "token_status": token_row["status"],
            "issued_at": token_row["issued_at"],
            "rotated_at": token_row["rotated_at"],
            "revoked_at": token_row["revoked_at"],
            "agents_count": int(agents["n"]),
            "listings_count": int(listings["n"]),
        }
