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

"""商家"我的商品"自助服务（写回 shopping-cli）。

商家在 portal 绑定自己的 SHOPPING_MERCHANT_TOKEN（Fernet 加密存
merchant_tokens.shopping_token_encrypted）；本模块代理商品 CRUD 到
shopping-cli API（Bearer 鉴权），商家自行维护商品与成交入口。

shopping-cli base URL 由 KIWI_SHOPPING_BASE_URL 覆盖（默认 127.0.0.1:8765）。

免费通道：未签发 owner token 的商家经 portal 账号会话，以共享代理凭据
（KIWI_CATALOG_PROXY_TOKEN，与 shopping-cli 共享）操作临时商家 id
mkt_free_<account_id> 的商品；shopping-cli 侧原子执行 10 件在售配额，
超限返回 403 引导文案（原样透传给 portal）。
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.services.accounts import decrypt_merchant_token, encrypt_merchant_token

_SHOPPING_BASE_URL_ENV = "KIWI_SHOPPING_BASE_URL"
_DEFAULT_SHOPPING_BASE_URL = "http://127.0.0.1:8765"
_PROXY_TOKEN_ENV = "KIWI_CATALOG_PROXY_TOKEN"


def shopping_base_url() -> str:
    return (os.environ.get(_SHOPPING_BASE_URL_ENV) or _DEFAULT_SHOPPING_BASE_URL).rstrip("/")


def _proxy_token() -> str:
    """免费通道代理凭据（与 shopping-cli 共享的 Bearer token）；未配置返回空串。"""
    return str(os.environ.get(_PROXY_TOKEN_ENV) or "").strip()


def free_merchant_id(account_id: int | str) -> str:
    """免费通道临时商家 id：mkt_free_<account_id>（shopping-cli 仅对该前缀放行代理凭据）。"""
    return f"mkt_free_{account_id}"


def bind_shopping_token(conn, merchant_id: str, token: str) -> dict:
    """商家绑定自己的 shopping-cli token（Fernet 加密存储）。"""
    token = str(token or "").strip()
    if not token:
        raise ValidationError("shopping_cli_token 不能为空")
    row = conn.execute(
        "select 1 from merchant_tokens where merchant_id = ?", (merchant_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Unknown merchant: {merchant_id}")
    conn.execute(
        "update merchant_tokens set shopping_token_encrypted = ? where merchant_id = ?",
        (encrypt_merchant_token(token), merchant_id),
    )
    return {"ok": True, "merchant_id": merchant_id, "bound": True}


def get_shopping_token(conn, merchant_id: str) -> str:
    """解密返回商家的 shopping-cli token；未绑定返回空串。"""
    row = conn.execute(
        "select shopping_token_encrypted from merchant_tokens where merchant_id = ?",
        (merchant_id,),
    ).fetchone()
    if row is None:
        return ""
    return decrypt_merchant_token(str(row["shopping_token_encrypted"] or ""))


def _require_token(conn, merchant_id: str) -> str:
    """统一令牌（方案A）：用 catalog owner token 调 shopping-cli（跨服务校验）。

    shopping-cli 配置了 KIWI_CATALOG_AUTH_URL 后，商家 owner token 即通用
    凭据——无需单独绑定 SHOPPING_MERCHANT_TOKEN。

    凭据解析顺序：owner token（有则用，行为不变）→ 免费通道代理凭据
    （KIWI_CATALOG_PROXY_TOKEN 已配置时）→ 原有 ValidationError/NotFoundError。
    """
    row = conn.execute(
        "select token_encrypted from merchant_tokens where merchant_id = ?",
        (merchant_id,),
    ).fetchone()
    if row is not None:
        token = decrypt_merchant_token(str(row["token_encrypted"] or ""))
        if token:
            return token
    proxy = _proxy_token()
    if proxy:
        # 免费通道：无 owner token（含 mkt_free_ 临时商家无 merchant_tokens 行）
        # 时以共享代理凭据调 shopping-cli，配额由 shopping-cli 侧原子执行。
        return proxy
    if row is None:
        raise NotFoundError(f"Unknown merchant: {merchant_id}")
    raise ValidationError("商家尚未签发 owner token——请先在 My Account 申请令牌")


def _shopping_request(method: str, path: str, token: str, body: dict | None = None) -> dict:
    url = f"{shopping_base_url()}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        msg = payload.get("error") or payload.get("message") or f"HTTP {exc.code}"
        raise ValidationError(f"shopping-cli 返回 {exc.code}: {msg}") from exc
    except urllib.error.URLError as exc:
        raise ValidationError(f"shopping-cli 不可达: {exc.reason}") from exc


def list_products(conn, merchant_id: str) -> list[dict]:
    """列商家商品（shopping-cli 投影，含 handoff_destination）。"""
    token = _require_token(conn, merchant_id)
    result = _shopping_request(
        "GET",
        f"/v1/merchant/listings/projections?merchant_id={urllib.parse.quote(merchant_id)}",
        token,
    )
    return list(result.get("results") or [])


def create_product(conn, merchant_id: str, payload: dict) -> dict:
    """新增商品（写回 shopping-cli）。payload 允许 sku/title/price/stock/currency/
    category/tags/description/delivery_attributes/handoff_destination。"""
    token = _require_token(conn, merchant_id)
    body = dict(payload)
    # 会话凭据只用于 catalog 侧鉴权，不转发给 shopping-cli
    body.pop("kiwi_session", None)
    body.pop("_cookie", None)
    body["merchant_id"] = merchant_id
    return _shopping_request("POST", "/products", token, body)


def update_product(conn, merchant_id: str, sku: str, payload: dict) -> dict:
    """更新商品（写回 shopping-cli）。"""
    token = _require_token(conn, merchant_id)
    body = dict(payload)
    body.pop("kiwi_session", None)
    body.pop("_cookie", None)
    body["merchant_id"] = merchant_id
    return _shopping_request("PATCH", f"/products/{urllib.parse.quote(sku)}", token, body)
