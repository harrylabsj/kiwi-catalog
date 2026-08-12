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

设计（docs/accounts.md）：
- **注册即 merchant 注册**：注册完成即分配平台 merchant_id
  （mkt_<slug>_<rand>，与审批签发同一 id 空间；存量账号会话解析时懒回填）；
  申请 token 自动创建待审工单（dashboard 审批流复用），批准后沿用该
  merchant_id 签发 owner token；
- **会话**：登录签发随机 session token（SHA-256 落库 + 7 天过期），
  httpOnly cookie 传递（服务端渲染的页面用 cookie，API 端到端测试用 header）；
- **token 找回**：merchant_tokens.token_encrypted 存 Fernet 加密明文——
  登录后"我的"随时可查（解决签发即丢失）；Fernet key 从
  KIWI_CATALOG_OWNER_TOKEN_SECRET 加固定盐前缀经 SHA-256 派生（零新配置）；
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
from kiwi_catalog.core.tokens import token_digest, token_matches
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


# ── 邮箱验证（验证码 + SMTP 发送）────────────────────────────────────────


def _verification_mode() -> str:
    """邮件验证模式：smtp（生产发邮件）/ console（开发：验证码随注册响应
    返回）/ 其他或未配置 → fail-closed（注册拒绝，见 register_account）。"""
    return str(os.environ.get("KIWI_CATALOG_EMAIL_VERIFICATION_MODE") or "").strip().lower()


def generate_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def store_verification_code(
    conn: sqlite3.Connection, account_id: int, code: str
) -> None:
    """验证码 SHA-256 落库 + 15 分钟过期（不存明文）。"""
    expires_at = (
        datetime.now(UTC) + timedelta(minutes=15)
    ).replace(microsecond=0).isoformat()
    conn.execute(
        "update merchant_accounts set verification_code_hash = ?,"
        " verification_expires_at = ?, updated_at = ? where account_id = ?",
        (token_digest(code), expires_at, now_iso(), account_id),
    )


def send_verification_email(email: str, code: str) -> None:
    """发送验证邮件（标准库 smtplib；SMTP 凭据走 env）。

    env：KIWI_CATALOG_SMTP_HOST / _PORT / _USER / _PASSWORD / _FROM。
    发送失败抛 RuntimeError（注册事务回滚）。
    """
    host = os.environ.get("KIWI_CATALOG_SMTP_HOST") or ""
    if not host:
        raise RuntimeError("SMTP is not configured")
    import smtplib
    from email.message import EmailMessage

    port = int(os.environ.get("KIWI_CATALOG_SMTP_PORT") or "587")
    user = os.environ.get("KIWI_CATALOG_SMTP_USER") or ""
    password = os.environ.get("KIWI_CATALOG_SMTP_PASSWORD") or ""
    from_addr = os.environ.get("KIWI_CATALOG_SMTP_FROM") or user

    message = EmailMessage()
    message["Subject"] = "Kiwi 商家账号邮箱验证码"
    message["From"] = from_addr
    message["To"] = email
    message.set_content(
        f"你的 Kiwi 商家账号验证码是：{code}\n\n15 分钟内有效。如果不是你注册的，请忽略此邮件。"
    )
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(message)


def issue_verification(
    conn: sqlite3.Connection, account_id: int, email: str
) -> str:
    """生成验证码、落库、按模式发送。console 模式返回验证码明文（开发用）；
    smtp 模式返回空串（验证码只进邮箱）。"""
    code = generate_verification_code()
    store_verification_code(conn, account_id, code)
    mode = _verification_mode()
    if mode == "console":
        return code
    if mode == "smtp":
        send_verification_email(email, code)
        return ""
    raise RuntimeError("email verification is not configured (KIWI_CATALOG_EMAIL_VERIFICATION_MODE)")


def verify_email_code(
    conn: sqlite3.Connection, account_id: int, code: str
) -> bool:
    """校验验证码：恒时比较 + 未过期；成功置 email_verified=1 并清码。"""
    row = conn.execute(
        "select verification_code_hash, verification_expires_at from merchant_accounts"
        " where account_id = ?",
        (account_id,),
    ).fetchone()
    if row is None:
        return False
    stored_hash = str(row["verification_code_hash"] or "")
    if not stored_hash or not token_matches(token_digest(str(code or "").strip()), stored_hash):
        return False
    if str(row["verification_expires_at"] or "") < now_iso():
        return False
    conn.execute(
        "update merchant_accounts set email_verified = 1,"
        " verification_code_hash = '', verification_expires_at = '', updated_at = ?"
        " where account_id = ?",
        (now_iso(), account_id),
    )
    return True


def account_by_email(conn: sqlite3.Connection, email: str) -> dict[str, Any] | None:
    row = conn.execute(
        "select * from merchant_accounts where email = ?",
        (str(email or "").strip().lower(),),
    ).fetchone()
    return dict(row) if row is not None else None


# ── 账号 CRUD ─────────────────────────────────────────────────────────────


def ensure_merchant_id(conn: sqlite3.Connection, account_id: int, name_hint: str = "") -> str:
    """为账号分配平台 merchant_id（mkt_<slug>_<rand>，与审批签发同一 id 空间）。

    注册完成即调用；存量无 merchant_id 的账号在会话解析时懒回填。幂等：
    已有 id 直接返回，绝不重复分配（approve_application 亦复用此 id）。
    """
    row = conn.execute(
        "select merchant_id from merchant_accounts where account_id = ?",
        (account_id,),
    ).fetchone()
    if row is None:
        return ""
    existing = str(row["merchant_id"] or "").strip()
    if existing:
        return existing
    merchant_id = tokens_service.new_platform_merchant_id(
        name_hint or f"account-{account_id}"
    )
    conn.execute(
        "update merchant_accounts set merchant_id = ?, updated_at = ?"
        " where account_id = ? and merchant_id = ''",
        (merchant_id, now_iso(), account_id),
    )
    return merchant_id


def register_account(
    conn: sqlite3.Connection, *, email: str, password: str
) -> dict[str, Any]:
    """注册（极简：仅邮箱 + 密码）→ 建账号 + 签发邮箱验证码。

    不建商家工单——商家基本信息在「我的账户」申请令牌时填写
    （request_token 带 domain/agent_name 建工单）。发送验证码失败 →
    RuntimeError → 注册事务回滚（fail-closed）。
    """
    email = str(email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise ValidationError("email must be a valid email address")
    if len(password) < 8:
        raise ValidationError("password must be at least 8 characters")
    if len(password) > 200:
        raise ValidationError("password too long")

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
    # 注册完成即分配平台 merchant_id（免费通道与审批商家同一身份空间）
    merchant_id = ensure_merchant_id(conn, account_id, email.split("@", 1)[0])
    verification_code = issue_verification(conn, account_id, email)
    return {
        "account_id": account_id,
        "email": email,
        "merchant_id": merchant_id,
        "status": "pending_review",
        "email_verified": False,
        "verification_code": verification_code,  # console 模式才有值
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
    if account is None:
        return None
    account = dict(account)
    if not str(account.get("merchant_id") or "").strip():
        # 存量账号懒回填：注册即分配 merchant_id 之前的历史行首次使用时补齐
        account["merchant_id"] = ensure_merchant_id(
            conn,
            int(account["account_id"]),
            str(account.get("email") or "").split("@", 1)[0],
        )
    return account


def destroy_session(conn: sqlite3.Connection, session_token: str) -> None:
    conn.execute(
        "delete from account_sessions where session_token_hash = ?",
        (token_digest(session_token),),
    )


# ── 账号视图（"我的"）────────────────────────────────────────────────────


def account_view(conn: sqlite3.Connection, account: dict[str, Any]) -> dict[str, Any]:
    """登录态账号视图：资料 + merchant + token（解密明文）+ 计数。

    active token 会在每次已认证账号视图中解密展示（可恢复模型）；工单状态一并返回。
    调用方必须将会话视为敏感凭据，疑似泄露时应轮换 token。
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
        "merchant_name": account.get("merchant_name") or "",
        "phone": account.get("phone") or "",
        "created_at": account.get("created_at") or "",
        "merchant_id": merchant_id,
        "application": application,
        "token": token_info,
        "agents_count": counts["agents"],
        "listings_count": counts["listings"],
    }


def request_token(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    *,
    domain: str = "",
    agent_name: str = "",
    agent_id: str = "",
    phone: str = "",
    purpose: str = "",
) -> dict[str, Any]:
    """"我的"里申请 token：已有 active → 返回现状；已有 pending 工单 →
    提示等待；被拒后可重新申请（新建 pending 工单，原被拒工单保留为
    审计记录）；否则用本次填写的商家基本信息建工单（注册极简，基本信息
    在此一步补齐），并回填账户基本信息（商家名称/电话）。"""
    # fail-closed 纵深防御（2026-08-12 关闭匿名申请通道）：申请必须绑定已
    # 分配 merchant_id 的账号；正常路径 resolve_session 已懒回填，为空说明
    # 账号未完成注册，直接拒绝。
    if not str(account.get("merchant_id") or "").strip():
        raise ValidationError("account has no merchant_id — complete registration first")
    view = account_view(conn, account)
    if view["token"] and view["token"]["status"] == "active":
        return {"status": "active", "message": "token already issued", **view}
    if view["application"] and view["application"]["status"] == "pending":
        return {"status": "pending", "message": "application pending review", **view}
    from kiwi_catalog.services.agent_catalog_writes import normalize_canonical_domain

    domain = normalize_canonical_domain(domain)
    agent_name = str(agent_name or "").strip()
    agent_id = str(agent_id or "").strip()
    if not agent_name:
        raise ValidationError("agent_name is required to apply for a token")
    if not agent_id:
        raise ValidationError("agent_id is required to apply for a token")
    phone = str(phone or "").strip()
    now = now_iso()
    cursor = conn.execute(
        """
        insert into merchant_applications
            (status, domain, agent_name, agent_id, contact_email, purpose, phone, account_id, created_at)
        values ('pending', ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, agent_name, agent_id, account["email"], str(purpose or "").strip(), phone, account["account_id"], now),
    )
    application_id = int(cursor.lastrowid or 0)
    conn.execute(
        "update merchant_accounts set application_id = ?, updated_at = ? where account_id = ?",
        (application_id, now, account["account_id"]),
    )
    # 回填账户基本信息（v16：商家名称/电话）
    conn.execute(
        "update merchant_accounts set merchant_name = ?, phone = ?, updated_at = ?"
        " where account_id = ?",
        (agent_name, phone, now, account["account_id"]),
    )
    return {"status": "pending", "message": "application submitted", "application_id": application_id}


def update_profile(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    *,
    merchant_name: str = "",
    phone: str = "",
    agent_id: str = "",
) -> dict[str, Any]:
    """更新账户基本信息（商家名称/电话/agent_id，均非空才覆盖）。"""
    merchant_name = str(merchant_name or "").strip()
    phone = str(phone or "").strip()
    agent_id = str(agent_id or "").strip()
    if merchant_name and len(merchant_name) > 200:
        raise ValidationError("merchant_name too long")
    if phone and len(phone) > 40:
        raise ValidationError("phone too long")
    if agent_id and len(agent_id) > 200:
        raise ValidationError("agent_id too long")
    if merchant_name:
        conn.execute(
            "update merchant_accounts set merchant_name = ?, updated_at = ?"
            " where account_id = ?",
            (merchant_name, now_iso(), account["account_id"]),
        )
    if phone:
        conn.execute(
            "update merchant_accounts set phone = ?, updated_at = ?"
            " where account_id = ?",
            (phone, now_iso(), account["account_id"]),
        )
    if agent_id:
        # agent_id 落在该账号名下的最新申请工单（商家可自行修改/增添自己的 agent ID）
        conn.execute(
            "update merchant_applications set agent_id = ?"
            " where account_id = ? and application_id = ("
            "   select application_id from merchant_applications"
            "   where account_id = ? order by application_id desc limit 1)",
            (agent_id, account["account_id"], account["account_id"]),
        )
    # 重查账号行（更新后的 merchant_name/phone 进视图）
    fresh = conn.execute(
        "select * from merchant_accounts where account_id = ?",
        (account["account_id"],),
    ).fetchone()
    return account_view(conn, dict(fresh))


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
