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

"""发现条目 API（架构转向：catalog 本地目录，替代 shopping-cli 代理通道）。

商家路由（owner token / admin token / portal 账号会话——会话仅能操作账号
自己的 merchant_id）：
- POST   /v1/merchants/{merchant_id}/discovery-entries
- GET    /v1/merchants/{merchant_id}/discovery-entries
- DELETE /v1/merchants/{merchant_id}/discovery-entries/{entry_id}

买家路由（匿名 + 固定窗口限流，与既有 rate-limit 服务同一模式）：
- GET    /v1/discovery/search?q=<text>&limit=
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.handlers.common import result_limit
from kiwi_catalog.core.errors import PermissionDenied, ValidationError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.listings.serialization import merchant_projection
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services import discovery_entries as entries_service
from kiwi_catalog.services.rate_limit import SQLiteRateLimitBackend, enforce_rate_limit

_SEARCH_RATE_LIMIT_PER_MINUTE_ENV = "KIWI_CATALOG_DISCOVERY_SEARCH_RATE_LIMIT_PER_MINUTE"
_SEARCH_GLOBAL_RATE_LIMIT_PER_MINUTE_ENV = (
    "KIWI_CATALOG_DISCOVERY_SEARCH_GLOBAL_RATE_LIMIT_PER_MINUTE"
)


def _search_rate_limit_per_minute() -> int:
    from kiwi_catalog.services.buyer_bootstrap import rate_limit_per_minute

    return rate_limit_per_minute(
        os.environ.get(_SEARCH_RATE_LIMIT_PER_MINUTE_ENV), default=60, maximum=2**63 - 1
    )


def _search_global_rate_limit_per_minute() -> int:
    from kiwi_catalog.services.buyer_bootstrap import rate_limit_per_minute

    # 总量兜底默认 600/min：必须高于 per-IP 默认（60），否则退化为共享单桶
    return rate_limit_per_minute(
        os.environ.get(_SEARCH_GLOBAL_RATE_LIMIT_PER_MINUTE_ENV),
        default=600,
        maximum=2**63 - 1,
    )


def _search_client_bucket(query: dict[str, Any]) -> str:
    """限流分桶键：transport 注入的客户端 IP（``_client_ip``，X-Forwarded-For
    首跳优先、无代理时取直连对端）；缺失（无头/CLI 直调）兜底匿名共享桶。"""
    client_ip = str(query.get("_client_ip") or "").strip()
    if client_ip:
        return f"discovery_search:ip:{client_ip}"
    return "discovery_search:anonymous"


def _session_account(conn, payload: dict[str, Any]) -> dict[str, Any] | None:
    """portal 账号会话 → 账号 dict（无会话/已过期返回 None）。

    与 accounts.py handler 同一取法：cookie 优先，kiwi_session 字段备选。
    """
    session_token = accounts_service.session_token_from_cookie(
        str(payload.get("_cookie") or "")
    ) or str(payload.get("kiwi_session") or "")
    if not session_token:
        return None
    return accounts_service.resolve_session(conn, session_token)


def _require_merchant_control(conn, merchant_id: str, payload: dict[str, Any]) -> None:
    """校验调用方控制该商家（owner token / admin token / portal 账号会话）。

    必须传 conn：随机 owner token 的 SHA-256 落库路径需要 DB 查询（不传 conn
    只走 HMAC 派生，随机 token 会被误拒）。

    账号会话仅能操作账号自己的 merchant_id（注册即分配，resolve_session 对
    存量账号懒回填）；其余商家 id 一律 403。
    """
    try:
        api_auth.require_admin_token(payload)
        return
    except api_auth.AuthError:
        pass
    try:
        api_auth.require_merchant_token(payload, merchant_id, conn)
        return
    except api_auth.AuthError as owner_error:
        account = _session_account(conn, payload)
        if account is None:
            raise owner_error from None
    if merchant_id != str(account.get("merchant_id") or ""):
        raise PermissionDenied("无权操作该商家的发现条目")


def _require_merchant_id(merchant_id: str) -> str:
    merchant_id = str(merchant_id or "").strip()
    if not merchant_id:
        raise ValidationError("merchant_id is required")
    return merchant_id


def create_entry(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchants/{merchant_id}/discovery-entries——上传商品名称。"""
    merchant_id = _require_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        entry = entries_service.create_entry(
            conn, merchant_id, str(payload.get("name") or "")
        )
        return {"ok": True, "entry": entry}


def list_entries(
    db_path: str | Path, merchant_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/merchants/{merchant_id}/discovery-entries——列自己的条目。"""
    merchant_id = _require_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        results = entries_service.list_entries(conn, merchant_id)
        return {"ok": True, "results": results}


def delete_entry(
    db_path: str | Path, merchant_id: str, entry_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """DELETE /v1/merchants/{merchant_id}/discovery-entries/{entry_id}。"""
    merchant_id = _require_merchant_id(merchant_id)
    with db_session(db_path) as conn:
        _require_merchant_control(conn, merchant_id, payload)
        entries_service.delete_entry(conn, merchant_id, entry_id)
        return {"ok": True, "entry_id": str(entry_id).strip()}


def _search_result(row: dict[str, Any]) -> dict[str, Any]:
    """单行搜索结果：entry + merchant/agent 公开投影（与 listing 搜索同构）。

    agent 投影复用既有公开字段（catalog_agent_id + canonical_domain + 三态），
    买家据此解析 agent URL；不引入任何私有字段。
    """
    agent: dict[str, Any] | None = None
    if row.get("agent_catalog_agent_id"):
        agent = {
            "catalog_agent_id": str(row.get("agent_catalog_agent_id") or ""),
            "canonical_domain": str(row.get("agent_canonical_domain") or ""),
            "verification_level": str(row.get("agent_verification_level") or ""),
            "freshness_state": str(row.get("agent_freshness_state") or ""),
            "administrative_state": str(row.get("agent_administrative_state") or ""),
        }
    merchant_row = None
    if row.get("merchant_shadow_id"):
        merchant_row = {
            "id": str(row.get("merchant_shadow_id") or ""),
            "name": str(row.get("merchant_shadow_name") or ""),
        }
    return {
        "entry": entries_service.entry_record(row),
        "merchant": merchant_projection(merchant_row),
        "agent": agent,
    }


def search_discovery(db_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/discovery/search（匿名，限流）——买家 agent 检索商品名称。"""
    limit = result_limit(query.get("limit"), default=20)
    with db_session(db_path) as conn:
        # 审查 P3-06：按客户端 IP 分桶（此前全匿名共享单桶——一个客户端即可
        # 耗尽全体预算对所有人 429）；同时保留 global 总量桶作分布式滥用兜底。
        backend = SQLiteRateLimitBackend(
            conn, table="agent_catalog_write_rate_limits", key_column="actor_key"
        )
        enforce_rate_limit(
            backend,
            key=_search_client_bucket(query),
            limit=_search_rate_limit_per_minute(),
            window_seconds=60,
            description="discovery search (per client IP)",
        )
        enforce_rate_limit(
            backend,
            key="discovery_search:global",
            limit=_search_global_rate_limit_per_minute(),
            window_seconds=60,
            description="discovery search (global)",
        )
        rows = entries_service.search_entries(conn, str(query.get("q") or ""), limit=limit)
        return {"ok": True, "results": [_search_result(row) for row in rows]}
