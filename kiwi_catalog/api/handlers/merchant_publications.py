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

"""商家公开资料 API handlers（M0 工作包 A，docs/accounts.md §publications）。

4 条路由：create（保存草稿/确认发布）/ search（公开检索）/ get（公开详情）/
withdraw（撤回）。写端点用**商家账号会话**鉴权（cookie kiwi_session 或
kiwi_session 字段，与 accounts handlers 同一机制）——不是 owner token：
merchant_id 一律取自服务端会话，不信客户端传值。审计事件落 audit_events
影子表（发布/更新/撤回/私密字段拒绝）。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.core.errors import AuthError, NotFoundError, ValidationError
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services import buyer_follows as follows_service
from kiwi_catalog.services import connector_identity as identity_service
from kiwi_catalog.services import merchant_publications as publications_service
from kiwi_catalog.services.rate_limit import SQLiteRateLimitBackend, enforce_rate_limit

_PUBLICATION_RATE_LIMIT_PER_15MIN_ENV = "KIWI_CATALOG_PUBLICATION_RATE_LIMIT_PER_15MIN"


def _publication_rate_limit_per_15min() -> int:
    raw = os.environ.get(_PUBLICATION_RATE_LIMIT_PER_15MIN_ENV) or ""
    try:
        return max(0, int(raw))
    except ValueError:
        return 30


def _session_token(payload: dict[str, Any]) -> str:
    """从请求取会话 token：cookie 优先（页面），kiwi_session 字段备选。"""
    cookie = accounts_service.session_token_from_cookie(str(payload.get("_cookie") or ""))
    return cookie or str(payload.get("kiwi_session") or "")


def _require_session_account(conn: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """会话 → 账号（无效/过期抛 AuthError）。"""
    session_token = _session_token(payload)
    if not session_token:
        raise AuthError("login required")
    account = accounts_service.resolve_session(conn, session_token)
    if account is None:
        raise AuthError("session expired or invalid")
    return account


def _optional_session_account(conn: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
    """可选会话（公开详情的商家本人视角）：无会话/无效返回 None，不抛错。"""
    session_token = _session_token(payload)
    if not session_token:
        return None
    return accounts_service.resolve_session(conn, session_token)


def _connector_actor(conn: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
    """商家连接器凭据（``Authorization: Bearer cmt_…``）→ 商家主体；不匹配返回 None。

    merchant_id 只来自凭据记录（商家在门户确认连接时落库），不接受请求体自述值。
    """
    token = str(payload.get("_auth_token") or "")
    if not token.startswith(identity_service.MERCHANT_TOKEN_PREFIX):
        return None
    identity = identity_service.verify_merchant_token(conn, token)
    if identity is None:
        raise AuthError("invalid or expired connector merchant token")
    return {
        "account_id": identity["account_id"],
        "merchant_id": identity["merchant_id"],
        "merchant_name": "",
        "email_verified": 1,
        "actor": f"connector:{identity['merchant_id']}",
    }


def _require_merchant_actor(conn: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """商家写路径主体：商家连接器凭据优先，其次浏览器会话。"""
    connector = _connector_actor(conn, payload)
    if connector is not None:
        return connector
    account = _require_session_account(conn, payload)
    return {**account, "actor": f"account:{account.get('account_id')}"}


def _optional_merchant_actor(conn: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
    """可选主体（公开详情的商家本人视角）：凭据或会话都无效时返回 None。"""
    connector = _connector_actor(conn, payload)
    if connector is not None:
        return connector
    return _optional_session_account(conn, payload)


def _enforce_write_rate_limit(conn: Any, merchant_id: str) -> None:
    """按商家限流（复用 merchant_application_limits 表，15min 窗口）。"""
    limit = _publication_rate_limit_per_15min()
    if limit <= 0:
        return
    backend = SQLiteRateLimitBackend(
        conn, table="merchant_application_limits", key_column="actor_key"
    )
    enforce_rate_limit(
        backend,
        key=f"publication:{merchant_id}",
        limit=limit,
        window_seconds=900,
        description=f"merchant publication write ({limit}/15min per merchant)",
    )


def create_publication(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/merchant-publications（会话）——保存草稿（action=draft，缺省）
    或确认发布（action=publish）。

    会话归属校验先行（merchant_id 取自服务端会话）；字段/长度/链接安全校验
    在 services 层；私密字段扫描 fail-closed + 审计；同一商家同名商品幂等
    更新（不产生重复主体）。响应回执含 publication_id、版本、发布时间。
    """
    with db_session(db_path) as conn:
        account = _require_merchant_actor(conn, payload)
        merchant_id = str(account.get("merchant_id") or "").strip()
        if not merchant_id:
            raise AuthError("account has no merchant_id — complete registration first")
        actor = str(account.get("actor") or f"account:{account.get('account_id')}")
        canonical, action = publications_service.validate_payload(payload)
        # 私密字段扫描（fail-closed + 审计）：明显的邮箱/手机号模式不得进入
        # 公开字段（注册账户的联系方式绝不自动进入公开投影的写入侧防线）。
        hits = publications_service.scan_private_fields(canonical)
        if hits:
            append_catalog_audit(
                conn,
                "",
                actor,
                "merchant_publication_private_field_rejected",
                {"merchant_id": merchant_id, "fields": hits},
            )
            # 拒绝也要留审计：显式提交后再抛错（db_session 异常路径不提交，
            # 否则拒绝事件随回滚丢失）。
            conn.commit()
            raise ValidationError(
                "public fields must not contain private contact info "
                f"(email or phone patterns rejected in: {', '.join(hits)})"
            )
        _enforce_write_rate_limit(conn, merchant_id)
        row, created, idempotent = publications_service.upsert_publication(
            conn, merchant_id=merchant_id, canonical=canonical, action=action
        )
        event = "merchant_publication_published" if action == "publish" else "merchant_publication_saved"
        if not created:
            event = (
                "merchant_publication_republished"
                if action == "publish"
                else "merchant_publication_updated"
            )
        append_catalog_audit(
            conn,
            str(row["publication_id"]),
            actor,
            event,
            {
                "merchant_id": merchant_id,
                "publication_id": row["publication_id"],
                "status": row["status"],
                "version": row["version"],
            },
        )
        return {
            "ok": True,
            "publication": publications_service.public_projection(row),
            "created": created,
            "idempotent": idempotent,
            "message": (
                "publication with the same title already exists — updated in place"
                if idempotent
                else ""
            ),
        }


def search_publications(
    db_path: str | Path, query: dict[str, Any], auth_payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    """GET /v1/merchant-publications/search（公开）——按商品名/类目检索。

    只返回 status=published 且未过期的记录；排序分页沿用 listings 搜索约定
    （确定性排序 + cursor）。结果恒带 inquiry_available=false（第 0 版商家
    资料可查，不可实时询价）。
    """
    with db_session(db_path) as conn:
        try:
            rows, next_cursor = publications_service.search_publications(conn, query or {})
        except publications_service.SearchQueryError as exc:
            raise ValidationError(str(exc)) from exc
        return {
            "ok": True,
            "results": [publications_service.public_projection(row) for row in rows],
            "next_cursor": next_cursor,
        }


def get_publication(
    db_path: str | Path, publication_id: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    """GET /v1/merchant-publications/{id}（公开）——公开详情。

    仅 published 且未过期对匿名可见；商家本人（会话归属一致）可见自己的
    draft/withdrawn。匿名访问非公开行返回 404（不泄漏存在性）。
    """
    publication_id = str(publication_id).strip()
    if not publication_id:
        raise ValidationError("publication_id is required")
    with db_session(db_path) as conn:
        row = publications_service.get_publication(conn, publication_id)
        if row is None:
            raise NotFoundError(f"Unknown publication: {publication_id}")
        if not publications_service.is_publicly_visible(row, now_iso()):
            account = _optional_merchant_actor(conn, payload or {})
            owner_merchant = str((account or {}).get("merchant_id") or "")
            if not owner_merchant or owner_merchant != str(row["merchant_id"]):
                raise NotFoundError(f"Unknown publication: {publication_id}")
        else:
            # 浏览计数（M4 商家匿名汇总数据源）：只计非商家本人的公开可见
            # 浏览——本人查看自己的资料不计入。
            account = _optional_merchant_actor(conn, payload or {})
            owner_merchant = str((account or {}).get("merchant_id") or "")
            if owner_merchant != str(row["merchant_id"]):
                publications_service.record_public_view(conn, publication_id)
        return {"ok": True, "publication": publications_service.public_projection(row)}


def publication_stats(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/merchant-publications/stats（会话）——商家本人的匿名汇总。

    只读、仅本人 merchant_id（取自服务端会话）：活跃关注者**总数** + 各公开
    资料的浏览计数。**不返回任何买家身份**（buyer_subject/关注列表永不暴露
    给商家）；不提供向关注者写消息的通道。
    """
    with db_session(db_path) as conn:
        account = _require_merchant_actor(conn, payload)
        merchant_id = str(account.get("merchant_id") or "").strip()
        if not merchant_id:
            raise AuthError("account has no merchant_id — complete registration first")
        rows = conn.execute(
            "select publication_id, title, status, view_count, published_at"
            " from merchant_publications where merchant_id = ?"
            " order by updated_at desc, publication_id desc",
            (merchant_id,),
        ).fetchall()
        publications = [
            {
                "publication_id": str(row["publication_id"]),
                "title": str(row["title"]),
                "status": str(row["status"]),
                "view_count": int(row["view_count"] or 0),
                "published_at": str(row["published_at"] or ""),
            }
            for row in rows
        ]
        followers_total = follows_service.follower_count(conn, merchant_id)
        return {
            "ok": True,
            "stats": {
                "merchant_id": merchant_id,
                "followers_total": followers_total,
                "views_total": sum(item["view_count"] for item in publications),
                "publications": publications,
            },
        }


def withdraw_publication(
    db_path: str | Path, publication_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/merchant-publications/{id}/withdraw（会话）——撤回（终态）。

    会话归属校验：只能撤回自己 merchant_id 名下的资料（账号 A 不能改账号 B）。
    """
    with db_session(db_path) as conn:
        account = _require_merchant_actor(conn, payload)
        merchant_id = str(account.get("merchant_id") or "").strip()
        if not merchant_id:
            raise AuthError("account has no merchant_id — complete registration first")
        _enforce_write_rate_limit(conn, merchant_id)
        row = publications_service.withdraw_publication(
            conn, publication_id=publication_id, merchant_id=merchant_id
        )
        append_catalog_audit(
            conn,
            str(row["publication_id"]),
            str(account.get("actor") or f"account:{account.get('account_id')}"),
            "merchant_publication_withdrawn",
            {"merchant_id": merchant_id, "publication_id": row["publication_id"]},
        )
        return {"ok": True, "publication": publications_service.public_projection(row)}
