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

"""kiwi-catalog authentication (阶段 3 认证改造, 方案 i).

独立产品的认证体系，不依赖 marketplace 的 merchants/api_tokens 表：

- **admin token**：env ``KIWI_CATALOG_ADMIN_TOKEN``——平台运营（注册治理/
  suspend/reinstate 等 moderation 动作）；
- **catalog-owner token**（方案 i）：env ``KIWI_CATALOG_OWNER_TOKEN_SECRET``
  派生 HMAC——``owner_token(merchant_id)`` 生成、
  ``require_owner_token(payload, merchant_id)`` 校验——替代 shopping-cli
  的 merchant token（claim/refresh 的 owner 语义）。owner 身份通过影子
  merchants 表的 id 表达。

所有比较走 constant-time ``token_matches``（core/tokens.py）。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from typing import Any

from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.core.tokens import token_digest, token_matches

_OWNER_SECRET_ENV = "KIWI_CATALOG_OWNER_TOKEN_SECRET"
_ADMIN_TOKEN_ENV = "KIWI_CATALOG_ADMIN_TOKEN"


def payload_token(payload: dict[str, Any]) -> str:
    """The bearer token presented in the payload (auth header alias)."""
    return str(payload.get("_auth_token") or payload.get("admin_token") or "")


def payload_with_auth(payload: dict[str, Any], authorization: str, idempotency_key: str) -> dict[str, Any]:
    """Merge transport auth headers into the payload (fallback ASGI path)."""
    merged = dict(payload or {})
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if token:
        merged["_auth_token"] = token
    if idempotency_key:
        merged["idempotency_key"] = idempotency_key
    return merged


def configured_admin_token() -> str:
    return str(os.environ.get(_ADMIN_TOKEN_ENV) or "").strip()


def require_admin_token(payload: dict[str, Any]) -> None:
    """Raise AuthError unless the payload carries a valid admin token."""
    expected = configured_admin_token()
    if not expected:
        # 审查 P3：不区分「未配置」与「无效」——配置状态泄漏会辅助枚举性探测
        raise AuthError("invalid admin token")
    token = payload_token(payload)
    if not token:
        raise AuthError("invalid admin token")
    if not token_matches(token, expected):
        raise AuthError("invalid admin token")


def _owner_secret() -> str:
    secret = str(os.environ.get(_OWNER_SECRET_ENV) or "").strip()
    if not secret:
        raise AuthError("catalog owner token secret is not configured")
    return secret


def owner_token(merchant_id: str) -> str:
    """Derive the catalog-owner token for *merchant_id* (HMAC-SHA256)."""
    secret = _owner_secret()
    material = f"kiwi-catalog-owner:{merchant_id}".encode()
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def require_owner_token(payload: dict[str, Any], merchant_id: str) -> None:
    """Raise AuthError unless the payload's owner_token matches *merchant_id*.

    The owner_token field is carried in the request body (not the bearer
    header, which is reserved for admin).  Merchant identity comes from the
    catalog_agents.merchant_id (shadow merchants table in the standalone
    schema).
    """
    if not merchant_id:
        raise AuthError("merchant id required for owner authorization")
    presented = str((payload or {}).get("owner_token") or "")
    if not presented:
        raise AuthError("invalid owner token")
    try:
        expected = owner_token(merchant_id)
    except AuthError:
        # 审查 P3：secret 未配置不向调用方泄漏（配置状态辅助枚举探测）
        raise AuthError("invalid owner token") from None
    if not token_matches(presented, expected):
        raise AuthError("invalid owner token")


def require_merchant_token(
    payload: dict[str, Any], merchant_id: str, conn: sqlite3.Connection | None = None
) -> None:
    """Dual-path merchant credential check (docs §5).

    - 随机 token 落库路径（v12）：merchant_tokens 表 active 行，SHA-256
      恒时比较——支持签发/轮换/吊销；
    - 未命中 fallback HMAC 派生路径（require_owner_token）——存量调用方/
      CLI/测试兼容。

    *conn* 缺省时只走 HMAC fallback（无 DB 的调用点行为不变）。
    """
    # owner_token（body 直传）或 _auth_token（Authorization 头经 transport 合并）
    presented = str(
        (payload or {}).get("owner_token")
        or (payload or {}).get("_auth_token")
        or ""
    )
    if presented and conn is not None:
        rows = conn.execute(
            "select token_hash, status from merchant_tokens where merchant_id = ?",
            (merchant_id,),
        ).fetchall()
        if rows:
            # 商户已进入 token 体系（签发过随机 token）：凭证以 active 行为
            # 唯一权威。revoked/rotated 后不得经 HMAC 派生路径复活——否则
            # admin 吊销对存量 HMAC 调用方完全无效（审查 P2-1：fallback
            # 不查 status，吊销后旧派生 token 仍可认证全部写接口）。
            for row in rows:
                if str(row["status"]) == "active":
                    digest = token_digest(presented)
                    if token_matches(digest, str(row["token_hash"])):
                        return
            raise AuthError("invalid owner token")
    # 无任何 token 记录（存量商户未上 token 体系）→ HMAC 派生路径
    # （含未配置 fail-closed；conn 缺省的无 DB 调用点行为不变）
    require_owner_token(payload, merchant_id)
