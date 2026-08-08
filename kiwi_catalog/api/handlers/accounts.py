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

"""商家账号 API（docs §account）：注册/登录/登出/我的/申请 token。

- register / login 公开（限流防爆破）；登录签发会话 cookie
  （httpOnly + Secure + SameSite=Lax，7 天）；
- me / token-request 需会话（cookie kiwi_session）；
- token 明文只在登录态 /me 返回（merchant_tokens.token_encrypted 解密）；
- cookie 传输：fallback 经 payload["_cookie"]，FastAPI 经 request.cookies。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.api.handlers.common import require_field
from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services.rate_limit import (
    SQLiteRateLimitBackend,
    enforce_rate_limit,
)

_LOGIN_RATE_LIMIT_PER_15MIN_ENV = "KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN"


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
    """POST /v1/accounts/register（公开）——注册即建账号 + 待审工单。

    成功后自动登录（签发会话 cookie），返回账号视图。
    """
    email = str(require_field(payload, "email")).strip()
    password = str(require_field(payload, "password"))
    domain = str(require_field(payload, "domain")).strip()
    agent_name = str(require_field(payload, "agent_name")).strip()
    purpose = str(payload.get("purpose") or "").strip()

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
            conn,
            email=email,
            password=password,
            domain=domain,
            agent_name=agent_name,
            purpose=purpose,
        )
        session_token = accounts_service.create_session(
            conn, registered["account_id"]
        )
        account = conn.execute(
            "select * from merchant_accounts where account_id = ?",
            (registered["account_id"],),
        ).fetchone()
        view = accounts_service.account_view(conn, dict(account))
        return {
            "ok": True,
            **view,
            "__cookies__": [accounts_service.session_cookie_value(session_token)],
        }


def login(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/accounts/login（公开）——校验 + 签发会话 cookie。"""
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
        session_token = accounts_service.create_session(conn, int(account["account_id"]))
        view = accounts_service.account_view(conn, account)
        return {
            "ok": True,
            **view,
            "__cookies__": [accounts_service.session_cookie_value(session_token)],
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
        return {"ok": True, **view}
    finally:
        _ctx.__exit__(None, None, None)


def token_request(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/accounts/token-request（会话）——"我的"里申请 token。

    已有 active → 返回现状；已有 pending → 提示等待；否则建工单。
    """
    _ctx, conn, account = _require_session(db_path, payload)
    try:
        result = accounts_service.request_token(conn, account)
        return {"ok": True, **result}
    finally:
        _ctx.__exit__(None, None, None)
