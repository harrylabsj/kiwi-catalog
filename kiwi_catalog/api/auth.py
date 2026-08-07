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
from typing import Any

from kiwi_catalog.core.errors import AuthError
from kiwi_catalog.core.tokens import token_matches

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
        raise AuthError("admin token is not configured")
    token = payload_token(payload)
    if not token:
        raise AuthError("admin token required")
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
    material = f"kiwi-catalog-owner:{merchant_id}".encode("utf-8")
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
        raise AuthError("owner token required")
    if not token_matches(presented, owner_token(merchant_id)):
        raise AuthError("invalid owner token")
