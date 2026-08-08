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

"""商家账号体系（注册/登录/会话 + token 加密存储）。

设计（docs §account）：
- **注册即 merchant 注册**：基本信息（域名/商家名/邮箱/密码）注册 →
  自动创建待审工单（dashboard 审批流复用）；批准后 merchant_id 回填账号；
- **会话**：登录签发随机 session token（SHA-256 落库 + 7 天过期），
  httpOnly cookie 传递（服务端渲染的页面用 cookie，API 端到端测试用 header）；
- **token 找回**：merchant_tokens.token_encrypted 存 Fernet 加密明文——
  登录后"我的"随时可查（解决签发即丢失）；Fernet key 从
  KIWI_CATALOG_OWNER_TOKEN_SECRET 经 HKDF-SHA256 派生（零新配置）；
- 密码 hash：PBKDF2-HMAC-SHA256（200k 迭代 + 随机盐）。

依赖例外：cryptography（Fernet）——标准库无可逆加密；安全存储商家
凭证的必要例外，已记入 pyproject dependencies。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from kiwi_catalog.core.errors import ConflictError, ValidationError
from kiwi_catalog.core.tokens import token_digest
from kiwi_catalog.db.session import now_iso
from kiwi_catalog.services import merchant_tokens as tokens_service

_SESSION_TTL_DAYS = 7
_PBKDF2_ITERATIONS = 200_000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_OWNER_SECRET_ENV = "KIWI_CATALOG_OWNER_TOKEN_SECRET"


# ── 密码 hash（PBKDF2，标准库）───────────────────────────────────────────


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", str(password).encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return f"pbkdf2${_PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = str(stored).split("$", 3)
        if scheme != "pbkdf2":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = hashlib.pbkdf2_hmac(
            "sha256", str(password).encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


# ── token 加密（Fernet，key 从 owner secret 派生）────────────────────────


def _fernet() -> Any:
    from cryptography.fernet import Fernet

    secret = os.environ.get(_OWNER_SECRET_ENV) or ""
    if not secret:
        raise RuntimeError("KIWI_CATALOG_OWNER_TOKEN_SECRET is not configured")
    key = base64.urlsafe_b64encode(
        hashlib.sha256(("kiwi-token-fernet:" + secret).encode("utf-8")).digest()
    )
    return Fernet(key)


def encrypt_merchant_token(token: str) -> str:
    return _fernet().encrypt(str(token).encode("utf-8")).decode("ascii")


def decrypt_merchant_token(encrypted: str) -> str:
    if not encrypted:
        return ""
    try:
        return _fernet().decrypt(str(encrypted).encode("ascii")).decode("utf-8")
    except Exception:  # noqa: BLE001 —— 解密失败（key 轮换/数据损坏）按空处理
        return ""


# ── 账号 CRUD ─────────────────────────────────────────────────────────────


def register_account(
    conn: sqlite3.Connection,
    *,
    email: str,
    password: str,
    domain: str,
    agent_name: str,
    purpose: str = "",
) -> dict[str, Any]:
    """注册：校验 → 建账号 → 自动创建待审工单（application 复用）。

    返回账号 + 工单信息。工单 pending，approve 后 merchant_id 回填账号。
    """
    email = str(email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise ValidationError("email must be a valid email address")
    if len(password) < 8:
        raise ValidationError("password must be at least 8 characters")
    if len(password) > 200:
        raise ValidationError("password too long")
    agent_name = str(agent_name or "").strip()
    if not agent_name:
        raise ValidationError("agent_name is required")
    from kiwi_catalog.services.agent_catalog_writes import normalize_canonical_domain

    canonical_domain = normalize_canonical_domain(domain)

    existing = conn.execute(
        "select account_id from merchant_accounts where email = ?", (email,)
    ).fetchone()
    if existing is not None:
        raise ConflictError("email already registered")

    now = now_iso()
    cursor = conn.execute(
        "insert into merchant_accounts(email, password_hash, status, created_at, updated_at)"
        " values (?, ?, 'active', ?, ?)",
        (email, hash_password(password), now, now),
    )
    account_id = int(cursor.lastrowid or 0)

    app_cursor = conn.execute(
        """
        insert into merchant_applications
            (status, domain, agent_name, contact_email, purpose, account_id, created_at)
        values ('pending', ?, ?, ?, ?, ?, ?)
        """,
        (canonical_domain, agent_name, email, purpose, account_id, now),
    )
    application_id = int(app_cursor.lastrowid or 0)
    conn.execute(
        "update merchant_accounts set application_id = ? where account_id = ?",
        (application_id, account_id),
    )
    return {
        "account_id": account_id,
        "email": email,
        "application_id": application_id,
        "status": "pending_review",
    }


def authenticate(conn: sqlite3.Connection, email: str, password: str) -> dict[str, Any] | None:
    """邮箱 + 密码校验；成功返回账号行 dict，失败返回 None。"""
    row = conn.execute(
        "select * from merchant_accounts where email = ?",
        (str(email or "").strip().lower(),),
    ).fetchone()
    if row is None:
        return None
    if not verify_password(str(password or ""), str(row["password_hash"])):
        return None
    if str(row["status"]) != "active":
        return None
    return dict(row)


# ── 会话 ──────────────────────────────────────────────────────────────────


def create_session(conn: sqlite3.Connection, account_id: int) -> str:
    """签发会话：返回明文 session token（落库 SHA-256 + 7 天过期）。"""
    session_token = secrets.token_urlsafe(32)
    expires_at = (
        datetime.now(UTC) + timedelta(days=_SESSION_TTL_DAYS)
    ).replace(microsecond=0).isoformat()
    conn.execute(
        "insert into account_sessions(session_token_hash, account_id, expires_at, created_at)"
        " values (?, ?, ?, ?)",
        (token_digest(session_token), account_id, expires_at, now_iso()),
    )
    return session_token


def resolve_session(
    conn: sqlite3.Connection, session_token: str
) -> dict[str, Any] | None:
    """会话 → 账号（未过期）；过期/未知返回 None。"""
    if not session_token:
        return None
    row = conn.execute(
        "select account_id, expires_at from account_sessions"
        " where session_token_hash = ?",
        (token_digest(session_token),),
    ).fetchone()
    if row is None:
        return None
    if str(row["expires_at"]) < now_iso():
        conn.execute(
            "delete from account_sessions where session_token_hash = ?",
            (token_digest(session_token),),
        )
        return None
    account = conn.execute(
        "select * from merchant_accounts where account_id = ?", (row["account_id"],)
    ).fetchone()
    return dict(account) if account is not None else None


def destroy_session(conn: sqlite3.Connection, session_token: str) -> None:
    conn.execute(
        "delete from account_sessions where session_token_hash = ?",
        (token_digest(session_token),),
    )


# ── 账号视图（"我的"）────────────────────────────────────────────────────


def account_view(conn: sqlite3.Connection, account: dict[str, Any]) -> dict[str, Any]:
    """登录态账号视图：资料 + merchant + token（解密明文）+ 计数。

    token 只在 status=active 时解密展示；工单状态一并返回（pending 审批中）。
    """
    merchant_id = str(account.get("merchant_id") or "")
    application_id = int(account.get("application_id") or 0)

    application: dict[str, Any] | None = None
    if application_id:
        row = conn.execute(
            "select * from merchant_applications where application_id = ?",
            (application_id,),
        ).fetchone()
        if row is not None:
            application = tokens_service.application_row(row)

    token_info: dict[str, Any] | None = None
    if merchant_id:
        row = conn.execute(
            "select * from merchant_tokens where merchant_id = ?", (merchant_id,)
        ).fetchone()
        if row is not None:
            plaintext = ""
            if str(row["status"]) == "active":
                plaintext = decrypt_merchant_token(str(row["token_encrypted"] or ""))
            token_info = {
                "merchant_id": merchant_id,
                "status": row["status"],
                "issued_at": row["issued_at"],
                "rotated_at": row["rotated_at"],
                "revoked_at": row["revoked_at"],
                "token": plaintext if str(row["status"]) == "active" else "",
            }

    counts = {"agents": 0, "listings": 0}
    if merchant_id:
        agents = conn.execute(
            "select count(*) as n from catalog_agents where merchant_id = ?",
            (merchant_id,),
        ).fetchone()
        listings = conn.execute(
            "select count(*) as n from commerce_listings where merchant_id = ?",
            (merchant_id,),
        ).fetchone()
        counts = {"agents": int(agents["n"]), "listings": int(listings["n"])}

    return {
        "account_id": account["account_id"],
        "email": account["email"],
        "merchant_id": merchant_id,
        "application": application,
        "token": token_info,
        "agents_count": counts["agents"],
        "listings_count": counts["listings"],
    }


def request_token(conn: sqlite3.Connection, account: dict[str, Any]) -> dict[str, Any]:
    """"我的"里申请 token：已有 active → 返回现状；已有 pending 工单 →
    提示等待；否则建工单（域名/名称复用账号申请信息）。"""
    view = account_view(conn, account)
    if view["token"] and view["token"]["status"] == "active":
        return {"status": "active", "message": "token already issued", **view}
    if view["application"] and view["application"]["status"] == "pending":
        return {"status": "pending", "message": "application pending review", **view}
    if view["application"] and view["application"]["status"] == "rejected":
        raise ConflictError("previous application was rejected; contact operations")
    # 建新工单：复用账号已填信息
    application = view["application"] or {}
    now = now_iso()
    cursor = conn.execute(
        """
        insert into merchant_applications
            (status, domain, agent_name, contact_email, purpose, account_id, created_at)
        values ('pending', ?, ?, ?, ?, ?, ?)
        """,
        (
            application.get("domain") or "",
            application.get("agent_name") or "",
            account["email"],
            application.get("purpose") or "",
            account["account_id"],
            now,
        ),
    )
    application_id = int(cursor.lastrowid or 0)
    conn.execute(
        "update merchant_accounts set application_id = ? where account_id = ?",
        (application_id, account["account_id"]),
    )
    return {"status": "pending", "message": "application submitted", "application_id": application_id}


def session_cookie_value(session_token: str) -> str:
    """Set-Cookie 值（httpOnly + Secure + SameSite=Lax，7 天）。"""
    return (
        f"kiwi_session={session_token}; Path=/; HttpOnly; SameSite=Lax; Secure;"
        f" Max-Age={_SESSION_TTL_DAYS * 86400}"
    )


def session_token_from_cookie(cookie_header: str) -> str:
    """从 Cookie 头提取 kiwi_session（缺失返回空串）。"""
    for part in str(cookie_header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == "kiwi_session":
            return value
    return ""
