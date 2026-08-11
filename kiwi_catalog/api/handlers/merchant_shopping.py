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

"""商家"我的商品"自助（owner/admin 保护，代理 shopping-cli 商品 CRUD）。

商家在 portal 绑定自己的 SHOPPING_MERCHANT_TOKEN，然后在本页列出/新增/编辑
商品（含成交入口 handoff_destination），写回 shopping-cli（服务代理）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import merchant_shopping


def _require_merchant_control(conn, merchant_id: str, payload: dict[str, Any]) -> None:
    """校验调用方控制该商家（owner token 或 admin token）。

    必须传 conn：随机 owner token 的 SHA-256 落库路径需要 DB 查询（不传 conn
    只走 HMAC 派生，随机 token 会被误拒）。
    """
    try:
        api_auth.require_admin_token(payload)
    except api_auth.AuthError:
        api_auth.require_merchant_token(payload, merchant_id, conn)


def _require_merchant_id(merchant_id: str) -> str:
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required")
    return merchant_id


def bind_shopping_token(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """PUT /v1/merchants/{merchant_id}/shopping-token（owner/admin）——绑定 shopping-cli token。"""
    merchant_id = _require_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        token = str(payload.get("shopping_cli_token") or "").strip()
        if not token:
            raise ValidationError("shopping_cli_token is required")
        return merchant_shopping.bind_shopping_token(conn, merchant_id, token)


def shopping_token_status(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/merchants/{merchant_id}/shopping-token/status（owner/admin）——是否已绑定（不回显 token）。"""
    merchant_id = _require_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        token = merchant_shopping.get_shopping_token(conn, merchant_id)
        return {"ok": True, "merchant_id": merchant_id, "bound": bool(token)}


def list_products(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any], query: dict[str, Any] | None = None
) -> dict[str, Any]:
    """GET /v1/merchants/{merchant_id}/products（owner/admin）——列商家商品（shopping-cli 投影）。"""
    merchant_id = _require_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        results = merchant_shopping.list_products(conn, merchant_id)
        return {"ok": True, "results": results}


def create_product(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/{merchant_id}/products（owner/admin）——新增商品（写回 shopping-cli）。"""
    merchant_id = _require_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        result = merchant_shopping.create_product(conn, merchant_id, payload)
        return {"ok": True, **result}


def update_product(
    db_path: str | Path, merchant_id: str, sku: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """PATCH /v1/merchants/{merchant_id}/products/{sku}（owner/admin）——更新商品。"""
    merchant_id = _require_merchant_id(merchant_id)
    sku = str(sku or "").strip()
    if not sku:
        raise ValidationError("sku is required")
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        result = merchant_shopping.update_product(conn, merchant_id, sku, payload)
        return {"ok": True, **result}
