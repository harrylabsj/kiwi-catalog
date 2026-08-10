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

"""商家账号 API（docs/accounts.md）：注册/登录/登出/我的/申请 token。

- register / login 公开（限流防爆破）；登录签发会话 cookie
  （httpOnly + Secure + SameSite=Lax，7 天）；
- me / token-request 需会话（cookie kiwi_session）；
- token 明文仅在已登录会话 `/me` 返回（merchant_tokens.token_encrypted 解密）；
- cookie 传输：fallback 经 payload["_cookie"]，FastAPI 经 request.cookies。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.api.handlers.common import require_field
from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services.rate_limit import (
    SQLiteRateLimitBackend,
    enforce_rate_limit,
)

_LOGIN_RATE_LIMIT_PER_15MIN_ENV = "KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN"


def _audit_token_view(conn: Any, account: dict[str, Any], view: dict[str, Any]) -> None:
    """Record a token reveal without ever putting the bearer value in the audit log."""
    token = view.get("token")
    if not isinstance(token, dict) or token.get("status") != "active":
        return
    merchant_id = str(token.get("merchant_id") or view.get("merchant_id") or "")
    if not merchant_id:
        return
    append_catalog_audit(
        conn,
        "",
        f"account:{account.get('account_id')}",
        "merchant_token_viewed",
        {"merchant_id": merchant_id, "surface": "authenticated_account_view"},
    )


def _login_rate_limit_per_15min() -> int:
    import os

    raw = os.environ.get(_LOGIN_RATE_LIMIT_PER_15MIN_ENV) or ""
    try:
        return max(0, int(raw))
    except ValueError:
        return 10


def _session_token(payload: dict[str, Any]) -> str:
    """从请求取会话 token：cookie 优先（页面），X-Kiwi-Session header 备选。"""
    cookie = accounts_service.session_token_from_cookie(
        str(payload.get("_cookie") or "")
    )
    return cookie or str(payload.get("kiwi_session") or "")


def _require_session(
    db_path: str | Path, payload: dict[str, Any]
) -> tuple[Any, Any, dict[str, Any]]:
    """会话 → (db_session 上下文, 已 enter 的 conn, account dict)。

    调用方负责 finally 里 _ctx.__exit__；无效/过期抛 AuthError（会话前
    已 enter 的上下文在异常路径自行 exit，避免连接泄漏）。
    """
    session_token = _session_token(payload)
    if not session_token:
        raise AuthError("login required")
    _ctx = db_session(db_path)
    conn = _ctx.__enter__()
    account = accounts_service.resolve_session(conn, session_token)
    if account is None:
        _ctx.__exit__(None, None, None)
        raise AuthError("session expired or invalid")
    return _ctx, conn, account


def register(
    db_path: str | Path, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/accounts/register（公开）——极简注册：仅邮箱 + 密码。

    建账号 + 签发邮箱验证码；不自动登录（verify-email 通过后才可登录）。
    console 模式响应含 verification_code（开发/演示）；smtp 模式发邮件。
    """
    email = str(require_field(payload, "email")).strip()
    password = str(require_field(payload, "password"))

    with db_session(db_path) as conn:
        limit = _login_rate_limit_per_15min()
        if limit > 0:
            backend = SQLiteRateLimitBackend(
                conn, table="merchant_application_limits", key_column="actor_key"
            )
            enforce_rate_limit(
                backend,
                key=f"register:{email.lower()}",
                limit=limit,
                window_seconds=900,
                description=f"account register ({limit}/15min per email)",
            )
        registered = accounts_service.register_account(
            conn, email=email, password=password
        )
        return {
            "ok": True,
            "account_id": registered["account_id"],
            "email": registered["email"],
            "email_verified": False,
            # console 模式才返回明文验证码（smtp 模式为空串）
            "verification_code": registered.get("verification_code") or "",
        }


def login(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/accounts/login（公开）——校验 + 签发会话 cookie。

    邮箱未验证 → 403（提示先验证邮箱）。
    """
    email = str(require_field(payload, "email")).strip()
    password = str(require_field(payload, "password"))

    with db_session(db_path) as conn:
        limit = _login_rate_limit_per_15min()
        if limit > 0:
            backend = SQLiteRateLimitBackend(
                conn, table="merchant_application_limits", key_column="actor_key"
            )
            enforce_rate_limit(
                backend,
                key=f"login:{email.lower()}",
                limit=limit,
                window_seconds=900,
                description=f"account login ({limit}/15min per email)",
            )
        account = accounts_service.authenticate(conn, email, password)
        if account is None:
            raise AuthError("invalid email or password")
        if int(account.get("email_verified") or 0) != 1:
            raise AuthError("email not verified — check your inbox for the code")
        session_token = accounts_service.create_session(conn, int(account["account_id"]))
        view = accounts_service.account_view(conn, account)
        _audit_token_view(conn, account, view)
        return {
            "ok": True,
            **view,
            "__cookies__": [accounts_service.session_cookie_value(session_token)],
        }


def verify_email(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/accounts/verify-email（公开）——验证码校验，通过后自动登录。"""
    email = str(require_field(payload, "email")).strip().lower()
    code = str(require_field(payload, "code")).strip()

    with db_session(db_path) as conn:
        account = accounts_service.account_by_email(conn, email)
        if account is None:
            raise AuthError("invalid verification code")
        if int(account.get("email_verified") or 0) == 1:
            raise AuthError("email already verified")
        if not accounts_service.verify_email_code(conn, int(account["account_id"]), code):
            raise AuthError("invalid or expired verification code")
        session_token = accounts_service.create_session(conn, int(account["account_id"]))
        view = accounts_service.account_view(conn, account)
        _audit_token_view(conn, account, view)
        return {
            "ok": True,
            **view,
            "__cookies__": [accounts_service.session_cookie_value(session_token)],
        }


def resend_code(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/accounts/resend-code（公开）——重新签发验证码。"""
    email = str(require_field(payload, "email")).strip().lower()
    with db_session(db_path) as conn:
        account = accounts_service.account_by_email(conn, email)
        if account is None:
            raise AuthError("unknown email")
        if int(account.get("email_verified") or 0) == 1:
            raise AuthError("email already verified")
        code = accounts_service.issue_verification(
            conn, int(account["account_id"]), email
        )
        return {
            "ok": True,
            "email": email,
            "verification_code": code,  # console 模式才有值
        }


def logout(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/accounts/logout（会话）——销毁会话。"""
    session_token = _session_token(payload)
    with db_session(db_path) as conn:
        if session_token:
            accounts_service.destroy_session(conn, session_token)
        return {"ok": True, "message": "logged out"}


def me(db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/accounts/me（会话）——账号视图（含 token 明文，仅 active）。"""
    _ctx, conn, account = _require_session(db_path, payload)
    try:
        view = accounts_service.account_view(conn, account)
        _audit_token_view(conn, account, view)
        return {"ok": True, **view}
    finally:
        _ctx.__exit__(None, None, None)


def token_request(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/accounts/token-request（会话）——"我的"里申请 token。

    已有 active → 返回现状；已有 pending → 提示等待；否则用本次填写的
    商家基本信息（domain/agent_name）建工单。
    """
    _ctx, conn, account = _require_session(db_path, payload)
    try:
        # 审查 P3：token-request 此前无限流——被拒/被吊销商户可循环重申请
        # 无限刷 admin 工单（每张需人工 reject）。复用登录限流的 env 值
        # （0 = 禁用），按账号维度限流。
        limit = _login_rate_limit_per_15min()
        if limit > 0:
            backend = SQLiteRateLimitBackend(
                conn, table="merchant_application_limits", key_column="actor_key"
            )
            enforce_rate_limit(
                backend,
                key=f"token-request:{str(account.get('id') or account.get('email') or 'unknown')}",
                limit=limit,
                window_seconds=900,
                description=f"token request ({limit}/15min per account)",
            )
        result = accounts_service.request_token(
            conn,
            account,
            domain=str(payload.get("domain") or ""),
            agent_name=str(payload.get("agent_name") or ""),
            phone=str(payload.get("phone") or ""),
            purpose=str(payload.get("purpose") or ""),
        )
        return {"ok": True, **result}
    finally:
        _ctx.__exit__(None, None, None)


def profile(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/accounts/profile（会话）——更新账户基本信息（商家名称/电话）。"""
    _ctx, conn, account = _require_session(db_path, payload)
    try:
        view = accounts_service.update_profile(
            conn,
            account,
            merchant_name=str(payload.get("merchant_name") or ""),
            phone=str(payload.get("phone") or ""),
        )
        return {"ok": True, **view}
    finally:
        _ctx.__exit__(None, None, None)
