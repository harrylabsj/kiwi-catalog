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

"""商家连接器一次性身份授权 API handlers（kiwi 仓 merchant-buddy 第 1 版设计
§3.2 / 商家连接器发布计划 §3.1）。

4 条路由，两类鉴权互不混用：

- **connector token**（机器，env ``KIWI_CATALOG_CONNECTOR_TOKEN``）：
  ``POST /v1/connector-identity/requests``（创建挂起请求，返回门户登录地址）
  与 ``POST /v1/connector-identity/exchange``（单次兑换已验证商家身份）；
- **商家账号会话**（浏览器）：``GET /v1/connector-identity/requests/{id}``
  （门户确认页读取状态）与 ``POST .../{id}/decision``（同意/拒绝）。

硬边界：入口永远拿不到目录密码；merchant_id 由 approve 时从服务端会话落库；
code 只在回跳 URL 中出现一次（库中只存 sha256 摘要）；未验证邮箱的账号不能授权。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.api.auth import require_connector_token
from kiwi_catalog.core.errors import AuthError, ValidationError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services import connector_identity as identity_service
from kiwi_catalog.services.rate_limit import SQLiteRateLimitBackend, enforce_rate_limit

_CREATE_RATE_LIMIT_PER_15MIN_ENV = "KIWI_CATALOG_CONNECTOR_CREATE_RATE_LIMIT_PER_15MIN"
_EXCHANGE_RATE_LIMIT_PER_15MIN_ENV = "KIWI_CATALOG_CONNECTOR_EXCHANGE_RATE_LIMIT_PER_15MIN"


def _limit_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name) or ""
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def _portal_base_url() -> str:
    """门户对外地址（确认页登录链接的基准）。

    与 hosted_publication.hosted_base_url 分开解析：那里的
    ``KIWI_CATALOG_HOSTED_A2A_BASE_URL`` 是托管 A2A 广告地址，不能拿来做门户
    链接。此处只看 ``KIWI_CATALOG_PUBLIC_BASE_URL``（遗留 ``SHOPPING_*`` 名
    仍兼容）；未配置回退本地开发地址。
    """
    raw = (
        os.environ.get("KIWI_CATALOG_PUBLIC_BASE_URL")
        or os.environ.get("SHOPPING_PUBLIC_BASE_URL")
        or ""
    )
    return str(raw).strip().rstrip("/") or "http://localhost:8600"


def _login_url(request_id: str) -> str:
    return f"{_portal_base_url()}/portal/connect?{urlencode({'request_id': request_id})}"


def _session_token(payload: dict[str, Any]) -> str:
    """从请求取会话 token：cookie 优先（页面），kiwi_session 字段备选。"""
    cookie = accounts_service.session_token_from_cookie(str(payload.get("_cookie") or ""))
    return cookie or str(payload.get("kiwi_session") or "")


def _require_session_account(conn: Any, payload: dict[str, Any]) -> dict[str, Any]:
    session_token = _session_token(payload)
    if not session_token:
        raise AuthError("login required")
    account = accounts_service.resolve_session(conn, session_token)
    if account is None:
        raise AuthError("session expired or invalid")
    return account


def _append_redirect(url: str, params: dict[str, str]) -> str:
    """在入口回跳地址上追加查询参数（保留原查询串，不改 origin/路径）。"""
    split = urlsplit(url)
    query = split.query
    extra = urlencode(params)
    combined = f"{query}&{extra}" if query else extra
    return urlunsplit((split.scheme, split.netloc, split.path, combined, ""))


def _enforce_rate_limit(conn: Any, *, key: str, limit: int, description: str) -> None:
    if limit <= 0:
        return
    backend = SQLiteRateLimitBackend(
        conn, table="merchant_application_limits", key_column="actor_key"
    )
    enforce_rate_limit(
        backend, key=key, limit=limit, window_seconds=900, description=description
    )


def create_identity_request(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/connector-identity/requests（connector token）。

    入参：``return_url``（入口回跳地址，必须落在运维白名单 origin 内）、
    ``client_label``（可选展示名）。返回 request_id、登录地址与过期时间。
    """
    require_connector_token(payload)
    return_url = str(payload.get("return_url") or "").strip()
    client_label = str(payload.get("client_label") or "").strip()
    with db_session(db_path) as conn:
        _enforce_rate_limit(
            conn,
            key="connector-identity:create",
            limit=_limit_from_env(_CREATE_RATE_LIMIT_PER_15MIN_ENV, 300),
            description="connector identity request create (300/15min)",
        )
        record = identity_service.create_request(
            conn, return_url=return_url, client_label=client_label
        )
        append_catalog_audit(
            conn,
            "",
            "connector",
            "connector_identity_request_created",
            {
                "request_id": record["request_id"],
                "return_origin": urlsplit(record["return_url"]).netloc,
                "client_label": record["client_label"],
                "expires_at": record["expires_at"],
            },
        )
        return {
            "ok": True,
            "request": {
                "request_id": record["request_id"],
                "status": "pending",
                "created_at": record["created_at"],
                "expires_at": record["expires_at"],
            },
            "login_url": _login_url(record["request_id"]),
        }


def get_identity_request(
    db_path: str | Path, request_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/connector-identity/requests/{request_id}（商家会话）——确认页视图。"""
    with db_session(db_path) as conn:
        account = _require_session_account(conn, payload)
        view = identity_service.request_view(conn, request_id, account)
        return {"ok": True, "request": view}


def decide_identity_request(
    db_path: str | Path, request_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/connector-identity/requests/{request_id}/decision（商家会话）。

    ``decision`` = ``approve`` | ``deny``。返回入口回跳地址：approve 携带一次性
    code，deny 携带 ``error=access_denied``（OAuth 语义，入口据此结束授权）。
    """
    with db_session(db_path) as conn:
        account = _require_session_account(conn, payload)
        decision = str(payload.get("decision") or "").strip().lower()
        if decision not in ("approve", "deny"):
            raise ValidationError("decision must be approve or deny")
        record = identity_service.load_request(conn, request_id)
        actor = f"account:{account.get('account_id')}"
        if decision == "deny":
            identity_service.deny_request(conn, request_id=request_id, account=account)
            append_catalog_audit(
                conn,
                "",
                actor,
                "connector_identity_request_denied",
                {"request_id": record["request_id"], "client_label": record["client_label"]},
            )
            return {
                "ok": True,
                "decision": "deny",
                "redirect_url": _append_redirect(
                    record["return_url"], {"error": "access_denied"}
                ),
            }
        approved = identity_service.approve_request(conn, request_id=request_id, account=account)
        append_catalog_audit(
            conn,
            "",
            actor,
            "connector_identity_request_approved",
            {
                "request_id": record["request_id"],
                "merchant_id": approved["merchant_id"],
                "client_label": record["client_label"],
            },
        )
        return {
            "ok": True,
            "decision": "approve",
            "redirect_url": _append_redirect(
                record["return_url"],
                {"request_id": record["request_id"], "code": approved["code"]},
            ),
        }


def exchange_identity_request(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/connector-identity/exchange（connector token）。

    入参：``request_id`` + ``code``。成功返回已验证商家身份（单次消费）。
    """
    require_connector_token(payload)
    request_id = str(payload.get("request_id") or "").strip()
    code = str(payload.get("code") or "")
    with db_session(db_path) as conn:
        # 兑换尝试按请求限流：code 是高熵随机串，这里只是把暴力猜测的成本拉到
        # 不可能（并对同一请求的重放给出 429 而不是无限次 403）。
        _enforce_rate_limit(
            conn,
            key=f"connector-identity:exchange:{request_id or 'unknown'}",
            limit=_limit_from_env(_EXCHANGE_RATE_LIMIT_PER_15MIN_ENV, 60),
            description="connector identity exchange (60/15min per request)",
        )
        identity = identity_service.exchange(conn, request_id=request_id, code=code)
        append_catalog_audit(
            conn,
            "",
            "connector",
            "connector_identity_request_consumed",
            {"request_id": request_id, "merchant_id": identity["merchant_id"]},
        )
        return {
            "ok": True,
            "identity": {
                "merchant_id": identity["merchant_id"],
                "merchant_name": identity["merchant_name"],
            },
            # merchant_id 已在服务端确认；凭据只代表该商家，明文只在此返回一次
            # （库中存 sha256）。入口以 Authorization: Bearer cmt_… 使用。
            "credential": {
                "access_token": identity["access_token"],
                "scope": identity["scope"],
                "expires_at": identity["expires_at"],
            },
        }


def revoke_identity_token(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/connector-identity/revoke（Bearer cmt_…，凭据自身）。

    商家断开连接或轮换时，入口撤销自己持有的凭据；撤销后该凭据立刻失效。
    """
    token = str(payload.get("_auth_token") or "")
    with db_session(db_path) as conn:
        if not token.startswith(identity_service.MERCHANT_TOKEN_PREFIX):
            raise AuthError("invalid connector merchant token")
        identity = identity_service.verify_merchant_token(conn, token)
        if identity is None:
            raise AuthError("invalid or expired connector merchant token")
        revoked = identity_service.revoke_merchant_token(conn, token)
        append_catalog_audit(
            conn,
            "",
            f"connector:{identity['merchant_id']}",
            "connector_merchant_token_revoked",
            {"merchant_id": identity["merchant_id"]},
        )
        return {"ok": True, "revoked": revoked}
