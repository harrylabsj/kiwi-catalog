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

"""商家连接器（「Kiwi 商家运营」）的一次性身份授权（kiwi 仓 merchant-buddy
第 1 版设计 §3.2 / §8.3，商家连接器发布计划 §3.1）。

流程（授权码语义，但密码只进门户表单）：

1. 商家连接器的远程入口（WorkBuddy 侧已验证的 OAuth 授权请求尚未建立会话时）以 connector
   token 调 ``create_request`` 创建挂起请求，拿到 ``request_id`` 与门户登录地址；
2. 商家的浏览器在 catalog 门户 ``/portal/connect`` 登录/注册（邮箱验证）并**显式
   确认**后，``approve_request`` 落库 account_id / merchant_id 并签发一次性 code
   （库中只存 sha256 摘要，明文只在回跳 URL 里出现一次）；
3. 入口服务端用 connector token 调 ``exchange`` 换回
   ``{merchant_id, merchant_name, account_id}``——单次消费，之后同一 code 或同一
   请求再次兑换一律拒绝。

硬边界（对齐第 1 版设计 §2 / §4）：

- ``merchant_id`` 只能来自本表（服务端会话确认后落库），**绝不接受客户端自述的
  merchant_id、店铺链接或 URL 参数**；
- ``return_url`` 必须是运维白名单里的 origin（``KIWI_CATALOG_CONNECTOR_RETURN_URLS``），
  否则拒绝创建——目录不得充当开放重定向器；
- 未验证邮箱的账号不能授权（登录本身也拒绝未验证账号，这里是第二道门）；
- 门户密码/验证码永不经过入口；入口只拿到一次性的兑换结果。
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from kiwi_catalog.core.errors import AuthError, ConflictError, NotFoundError, PermissionDenied, ValidationError
from kiwi_catalog.core.tokens import token_digest, token_matches
from kiwi_catalog.db.session import now_iso

# 授权请求 TTL：与 kiwi 侧 OAuth 挂起授权请求（10 分钟）对齐；更短会让商家
# 来不及走完注册+验证邮箱，更长会拉大未消费 code 的暴露窗口。
CONNECTOR_REQUEST_TTL_SECONDS = 600
CONNECTOR_REQUEST_TTL_MIN_SECONDS = 60
CONNECTOR_REQUEST_TTL_MAX_SECONDS = 1800

# 过期行保留窗口（审计靠 audit_events；行本身只作运行期状态）。
CONNECTOR_REQUEST_RETENTION_SECONDS = 24 * 60 * 60

_RETURN_URLS_ENV = "KIWI_CATALOG_CONNECTOR_RETURN_URLS"
_REQUEST_TTL_ENV = "KIWI_CATALOG_CONNECTOR_REQUEST_TTL_SECONDS"


def connector_return_url_origins() -> tuple[str, ...]:
    """运维白名单：允许回跳的商家连接器入口 origin 列表（逗号分隔）。

    未配置时返回空元组——创建请求 fail-closed（不猜默认入口）。
    """
    raw = str(os.environ.get(_RETURN_URLS_ENV) or "")
    origins: list[str] = []
    for part in raw.split(","):
        value = part.strip().rstrip("/")
        if not value:
            continue
        split = urlsplit(value)
        if split.scheme not in ("http", "https") or not split.netloc:
            continue
        origins.append(f"{split.scheme}://{split.netloc}")
    return tuple(dict.fromkeys(origins))


def request_ttl_seconds() -> int:
    raw = str(os.environ.get(_REQUEST_TTL_ENV) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        return CONNECTOR_REQUEST_TTL_SECONDS
    return max(CONNECTOR_REQUEST_TTL_MIN_SECONDS, min(CONNECTOR_REQUEST_TTL_MAX_SECONDS, value))


def _origin_of(url: str) -> str:
    split = urlsplit(url)
    return f"{split.scheme}://{split.netloc}"


def validate_return_url(url: str) -> str:
    """校验商家连接器入口的回跳地址：绝对 http/https、无 userinfo、origin 在白名单内。"""
    value = str(url or "").strip()
    if not value:
        raise ValidationError("return_url is required")
    if len(value) > 2048:
        raise ValidationError("return_url is too long")
    split = urlsplit(value)
    if split.scheme not in ("http", "https") or not split.netloc:
        raise ValidationError("return_url must be an absolute http(s) URL")
    if split.username or split.password:
        raise ValidationError("return_url must not carry userinfo")
    if split.fragment:
        raise ValidationError("return_url must not carry a fragment")
    if _origin_of(value) not in connector_return_url_origins():
        # 不区分「未配置白名单」与「不在白名单」——配置状态泄漏会辅助探测
        # （与 admin token 校验同一口径）。
        raise ValidationError("return_url origin is not an allowed connector origin")
    return value


def _expired(row: sqlite3.Row | dict[str, Any]) -> bool:
    return str(row["expires_at"]) < now_iso()


def _iso_after(instant: str, seconds: int) -> str:
    """ISO 时刻 + 秒（统一 UTC、秒级，与 now_iso 同格式——逐字符比较的前提）。"""
    base = datetime.fromisoformat(str(instant)).astimezone(timezone.utc)
    return (base + timedelta(seconds=seconds)).replace(microsecond=0).isoformat()


def _purge_stale(conn: sqlite3.Connection) -> None:
    """惰性清理保留窗口外已过期的请求行（运行期状态，审计在 audit_events）。"""
    cutoff = _iso_after(now_iso(), -CONNECTOR_REQUEST_RETENTION_SECONDS)
    conn.execute("delete from connector_identity_requests where expires_at < ?", (cutoff,))


def create_request(
    conn: sqlite3.Connection,
    *,
    return_url: str,
    client_label: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    """创建挂起授权请求；返回 request_id / return_url / created_at / expires_at。"""
    allowed_return_url = validate_return_url(return_url)
    _purge_stale(conn)
    request_id = f"creq_{secrets.token_urlsafe(24)}"
    created_at = now or now_iso()
    expires_at = _iso_after(created_at, request_ttl_seconds())
    conn.execute(
        """
        insert into connector_identity_requests(
            request_id, client_label, return_url, status, created_at, expires_at)
        values (?, ?, ?, 'pending', ?, ?)
        """,
        (request_id, str(client_label or "")[:120], allowed_return_url, created_at, expires_at),
    )
    return {
        "request_id": request_id,
        "return_url": allowed_return_url,
        "client_label": str(client_label or "")[:120],
        "status": "pending",
        "created_at": created_at,
        "expires_at": expires_at,
    }


def load_request(conn: sqlite3.Connection, request_id: str) -> dict[str, Any]:
    """读取未过期请求；未知/过期一律 NotFoundError（不区分，防枚举）。"""
    value = str(request_id or "").strip()
    if not value:
        raise NotFoundError("connector identity request not found")
    row = conn.execute(
        "select * from connector_identity_requests where request_id = ?", (value,)
    ).fetchone()
    if row is None:
        raise NotFoundError("connector identity request not found")
    record = dict(row)
    if _expired(record):
        raise NotFoundError("connector identity request not found")
    return record


def request_view(
    conn: sqlite3.Connection, request_id: str, account: dict[str, Any] | None = None
) -> dict[str, Any]:
    """门户页面视图：只暴露确认所需的最小字段。

    ``account`` 为当前会话账号（可选）：仅用于判断「该请求是否属于当前登录
    商家」，不返回任何其他账号信息。approved 状态下不回显 code——code 只经
    回跳 URL 交给入口，页面不落痕迹。
    """
    record = load_request(conn, request_id)
    account_id = account.get("account_id") if account else None
    approved_for_account = (
        account_id is not None
        and record["account_id"] is not None
        and int(record["account_id"]) == int(account_id)
    )
    return {
        "request_id": record["request_id"],
        "client_label": record["client_label"],
        "status": record["status"],
        "created_at": record["created_at"],
        "expires_at": record["expires_at"],
        "merchant_name": record["merchant_name"] if approved_for_account else "",
        "approved_for_current_account": approved_for_account,
    }


def approve_request(
    conn: sqlite3.Connection, *, request_id: str, account: dict[str, Any]
) -> dict[str, Any]:
    """商家确认授权：落 account_id/merchant_id，签发一次性 code（返回明文一次）。"""
    record = load_request(conn, request_id)
    if record["status"] != "pending":
        raise ConflictError(f"connector identity request is already {record['status']}")
    if not int(account.get("email_verified") or 0):
        raise PermissionDenied("email verification required before connecting a connector")
    account_id = int(account["account_id"])
    merchant_id = str(account.get("merchant_id") or "").strip()
    if not merchant_id:
        raise PermissionDenied("account has no merchant_id — complete registration first")
    merchant_name = str(account.get("merchant_name") or "").strip()
    code = secrets.token_urlsafe(32)
    conn.execute(
        """
        update connector_identity_requests
           set status = 'approved', account_id = ?, merchant_id = ?, merchant_name = ?,
               code_digest = ?, decided_at = ?
         where request_id = ? and status = 'pending'
        """,
        (account_id, merchant_id, merchant_name, token_digest(code), now_iso(), record["request_id"]),
    )
    return {"request_id": record["request_id"], "code": code, "merchant_id": merchant_id}


def deny_request(conn: sqlite3.Connection, *, request_id: str, account: dict[str, Any]) -> None:
    """商家拒绝授权：终态 denied，不签发 code（入口据此回 access_denied）。"""
    record = load_request(conn, request_id)
    if record["status"] != "pending":
        raise ConflictError(f"connector identity request is already {record['status']}")
    conn.execute(
        """
        update connector_identity_requests
           set status = 'denied', account_id = ?, decided_at = ?
         where request_id = ? and status = 'pending'
        """,
        (int(account["account_id"]), now_iso(), record["request_id"]),
    )


def exchange(
    conn: sqlite3.Connection, *, request_id: str, code: str
) -> dict[str, Any]:
    """入口兑换：approved + code 匹配 → 单次消费并返回已验证商家身份。"""
    record = load_request(conn, request_id)
    if record["status"] != "approved":
        raise ConflictError(f"connector identity request is {record['status']}, not approved")
    presented = token_digest(str(code or ""))
    expected = str(record["code_digest"] or "")
    if not expected or not token_matches(presented, expected):
        raise AuthError("invalid connector identity code")
    cursor = conn.execute(
        """
        update connector_identity_requests
           set status = 'consumed', consumed_at = ?
         where request_id = ? and status = 'approved'
        """,
        (now_iso(), record["request_id"]),
    )
    if cursor.rowcount != 1:
        # 并发兑换：只有第一个能拿到身份（单次消费）。
        raise ConflictError("connector identity request was already consumed")
    issued = issue_merchant_token(
        conn,
        account_id=int(record["account_id"]),
        merchant_id=str(record["merchant_id"]),
        request_id=record["request_id"],
    )
    return {
        "account_id": int(record["account_id"]),
        "merchant_id": str(record["merchant_id"]),
        "merchant_name": str(record["merchant_name"]),
        "access_token": issued["access_token"],
        "scope": issued["scope"],
        "expires_at": issued["expires_at"],
    }


# ── 商家连接器作用域凭据（schema v32）────────────────────────────────────────

# 明文前缀：入口以 Authorization: Bearer cmt_… 使用；前缀同时让目录侧把
# 「商家连接器凭据」与 admin token / owner token / 会话 cookie 区分开。
MERCHANT_TOKEN_PREFIX = "cmt_"
# 商家目录令牌作用域：读写本商家的公开资料（发布仍须商家在门户确认页批准，
# 令牌本身不能直接把 draft 变成 published）。
DEFAULT_MERCHANT_TOKEN_SCOPE = "catalog:read catalog:write"
# 缺省有效期 90 天（对齐入口对 WorkBuddy 的 refresh 生命周期；过期后商家需
# 重新走一次连接流程，撤销即时生效）。
MERCHANT_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60
MERCHANT_TOKEN_TTL_MIN_SECONDS = 60 * 60
MERCHANT_TOKEN_TTL_MAX_SECONDS = 365 * 24 * 60 * 60

_MERCHANT_TOKEN_TTL_ENV = "KIWI_CATALOG_CONNECTOR_MERCHANT_TOKEN_TTL_SECONDS"


def merchant_token_ttl_seconds() -> int:
    raw = str(os.environ.get(_MERCHANT_TOKEN_TTL_ENV) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        return MERCHANT_TOKEN_TTL_SECONDS
    return max(MERCHANT_TOKEN_TTL_MIN_SECONDS, min(MERCHANT_TOKEN_TTL_MAX_SECONDS, value))


def issue_merchant_token(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    merchant_id: str,
    scope: str = DEFAULT_MERCHANT_TOKEN_SCOPE,
    request_id: str = "",
    now: str | None = None,
) -> dict[str, Any]:
    """签发绑定 (account_id, merchant_id) 的作用域令牌；明文只返回一次。"""
    if not merchant_id:
        raise ValidationError("merchant_id is required to issue a connector token")
    created_at = now or now_iso()
    expires_at = _iso_after(created_at, merchant_token_ttl_seconds())
    token = f"{MERCHANT_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    conn.execute(
        """
        insert into connector_merchant_tokens(
            token_hash, account_id, merchant_id, scope, request_id, created_at, expires_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token_digest(token),
            int(account_id),
            merchant_id,
            scope,
            request_id,
            created_at,
            expires_at,
        ),
    )
    return {
        "access_token": token,
        "scope": scope,
        "created_at": created_at,
        "expires_at": expires_at,
    }


def verify_merchant_token(conn: sqlite3.Connection, token: str) -> dict[str, Any] | None:
    """校验商家连接器凭据；无效/过期/已撤销返回 None（fail-closed）。"""
    presented = str(token or "")
    if not presented.startswith(MERCHANT_TOKEN_PREFIX):
        return None
    digest = token_digest(presented)
    row = conn.execute(
        "select * from connector_merchant_tokens where token_hash = ?", (digest,)
    ).fetchone()
    if row is None:
        return None
    record = dict(row)
    if record["revoked_at"] != "":
        return None
    if str(record["expires_at"]) < now_iso():
        return None
    conn.execute(
        "update connector_merchant_tokens set last_used_at = ? where token_hash = ?",
        (now_iso(), digest),
    )
    return {
        "account_id": int(record["account_id"]),
        "merchant_id": str(record["merchant_id"]),
        "scope": str(record["scope"]),
        "expires_at": str(record["expires_at"]),
    }


def revoke_merchant_token(conn: sqlite3.Connection, token: str) -> bool:
    """撤销商家连接器凭据（断开连接/轮换）；已撤销或未知返回 False。"""
    presented = str(token or "")
    if not presented.startswith(MERCHANT_TOKEN_PREFIX):
        return False
    cursor = conn.execute(
        """
        update connector_merchant_tokens
           set revoked_at = ?
         where token_hash = ? and revoked_at = ''
        """,
        (now_iso(), token_digest(presented)),
    )
    return cursor.rowcount == 1
