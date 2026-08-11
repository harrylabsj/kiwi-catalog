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

薄封装：admin 校验（fail-closed，无默认 token 未配置即拒绝）+ 申请面按
邮箱限流 + 响应组织；核心数据操作在 services/merchant_tokens.py（本地 CLI
直连同一 service）。明文 token 永不落库、不进审计（审计只记 merchant_id +
token_prefix 指纹）。
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.handlers.common import require_field
from kiwi_catalog.core.errors import AuthError, ValidationError
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import merchant_tokens as tokens_service
from kiwi_catalog.services import usage_metrics
from kiwi_catalog.services.agent_catalog_writes import normalize_canonical_domain
from kiwi_catalog.services.merchant_tokens import APPLICATION_STATUSES
from kiwi_catalog.services.rate_limit import (
    SQLiteRateLimitBackend,
    enforce_rate_limit,
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_APPLY_RATE_LIMIT_PER_HOUR_ENV = "KIWI_CATALOG_APPLY_RATE_LIMIT_PER_HOUR"


def _apply_rate_limit_per_hour() -> int:
    raw = os.environ.get(_APPLY_RATE_LIMIT_PER_HOUR_ENV) or ""
    try:
        return max(0, int(raw))
    except ValueError:
        return 5


def submit_application(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/merchants/applications（公开）。

    校验域名（bare hostname）/ 名称 / 邮箱；按邮箱限流（固定窗口）；
    写 pending 工单。响应不含任何凭证。
    """
    domain = normalize_canonical_domain(require_field(payload, "domain"))
    agent_name = str(require_field(payload, "agent_name")).strip()
    # v21 — 申请必填 agent_id（商家指定自己的 agent 标识，如 merchant-001）
    agent_id = str(require_field(payload, "agent_id")).strip()
    contact_email = str(require_field(payload, "contact_email")).strip()
    purpose = str(payload.get("purpose") or "").strip()
    phone = str(payload.get("phone") or "").strip()
    if not agent_name:
        raise ValidationError("agent_name is required")
    if not agent_id:
        raise ValidationError("agent_id is required")
    if not _EMAIL_RE.match(contact_email):
        raise ValidationError("contact_email must be a valid email address")
    if len(agent_name) > 200 or len(contact_email) > 200 or len(purpose) > 2000 or len(phone) > 40:
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
                (status, domain, agent_name, agent_id, contact_email, purpose, phone, created_at)
            values ('pending', ?, ?, ?, ?, ?, ?, ?)
            """,
            (domain, agent_name, agent_id, contact_email, purpose, phone, now_iso()),
        )
        application_id = int(cursor.lastrowid or 0)
        application = tokens_service.get_application(conn, application_id)
        return {"ok": True, "application": application}


def list_applications(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/merchants/applications?status=…（admin）。

    供门户后台渲染待审列表；status 过滤可选，不传返回全部（倒序）。
    admin token 只经 Authorization header（KC-SEC-02：凭据不得进 query——
    会落入访问日志/浏览器历史；fallback 栈已合并 header 为 _auth_token）。
    """
    api_auth.require_admin_token(payload)
    status = str(query.get("status") or "").strip()
    if status and status not in APPLICATION_STATUSES:
        raise ValidationError(f"status must be one of {APPLICATION_STATUSES}")
    limit = min(int(query.get("limit") or "50"), 100)
    with db_session(db_path) as conn:
        results = tokens_service.list_applications(conn, status=status, limit=limit)
        return {"ok": True, "results": results}


def approve_application(
    db_path: str | Path, application_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/applications/{id}/approve（admin 签发）。

    原子完成见 services.merchant_tokens.approve_application；响应含明文
    token —— 仅此一次。重复 approve → 409（ConflictError）。
    """
    api_auth.require_admin_token(payload)
    try:
        app_id = int(str(application_id).strip())
    except ValueError as exc:
        raise ValidationError("application_id must be an integer") from exc
    with db_session(db_path) as conn:
        issued = tokens_service.approve_application(conn, app_id)
        return {"ok": True, **issued}


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
        tokens_service.reject_application(conn, app_id, review_note)
        return {"ok": True, "application_id": app_id, "status": "rejected"}


def rotate_token(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/{merchant_id}/rotate（admin）。

    新随机 token 覆盖（旧 hash 作废），明文 token 仅此一次。故意走 admin
    （泄露场景下旧 token 可能在攻击者手里，自助轮换 = 攻击者也能轮换）。
    """
    api_auth.require_admin_token(payload)
    merchant_id = str(merchant_id).strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required")
    with db_session(db_path) as conn:
        rotated = tokens_service.rotate_token(conn, merchant_id)
        return {"ok": True, **rotated}


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
        token_status = tokens_service.revoke_token(conn, merchant_id)
        return {"ok": True, "merchant_id": merchant_id, "token_status": token_status}


def self_status(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/merchants/self?owner_token=…（token 即身份，商家自查）。

    返回 merchant_id、token 状态与名下 agent / listing 计数。owner token
    经 query string（token 即身份的既有语义，CLAUDE.md 记录）；admin 查询
    任意商家时 admin token 只经 Authorization header（KC-SEC-02）。
    """
    merchant_id = str(query.get("merchant_id") or "").strip()
    presented = str(query.get("owner_token") or payload.get("owner_token") or "").strip()
    with db_session(db_path) as conn:
        if merchant_id:
            api_auth.require_admin_token(payload)
            token_row: sqlite3.Row | None = tokens_service.require_token_row(conn, merchant_id)
        else:
            if not presented:
                raise AuthError("invalid owner token")
            token_row = tokens_service.resolve_merchant_by_token(conn, presented)
            if token_row is None:
                raise AuthError("invalid owner token")
            merchant_id = str(token_row["merchant_id"])
            # 埋点只记商家自查动作（token 即身份的路径），admin 查询不计
            usage_metrics.record_usage(conn, usage_metrics.METRIC_MERCHANT_SELF_CHECK)
        assert token_row is not None  # 两条分支都保证非空（fail-closed）
        status = tokens_service.merchant_status(conn, token_row)
        return {"ok": True, **status}
