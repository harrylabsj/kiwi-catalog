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

"""Listing API handlers（产品文档 v0.4 §8/§13；升级计划 §4）。

6 条路由：search / get / list-by-owner（publisher 自查）/ publish / withdraw /
reinstate。publish 复用五步幂等模板（replay → rate limit → claim → work →
complete → clear，参照 agent_catalog.py register_catalog_agent）；owner token
语义复用 api/auth.py（owner_token 字段在请求体）；审计事件写入 audit_events。
"""

from __future__ import annotations

import sqlite3
import base64
import json
from pathlib import Path
from datetime import UTC, datetime, timedelta
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api import idempotency as api_idempotency
from kiwi_catalog.api.handlers.common import result_limit
from kiwi_catalog.core.errors import AuthError, PermissionDenied, ValidationError
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.listings import sqlite_repository as repo
from kiwi_catalog.listings.contracts import validate_publish_payload
from kiwi_catalog.listings.domain import LISTING_FRESHNESS_STATES
from kiwi_catalog.listings.search import SearchQueryError
from kiwi_catalog.listings.search import search_listings as _search_listings
from kiwi_catalog.listings.serialization import (
    agent_projection,
    listing_record,
    listing_search_result,
    merchant_projection,
)
from kiwi_catalog.listings.service import owner_agent_merchant_id
from kiwi_catalog.services import buyer_search_events, buyer_stats, usage_metrics

PUBLISH_ENDPOINT = "/v1/listings/publish"
WITHDRAW_ENDPOINT = "/v1/listings/{id}/withdraw"
REINSTATE_ENDPOINT = "/v1/listings/{id}/reinstate"
_LISTINGS_ENTITLEMENT_REQUIRED = (
    "LISTINGS_ENTITLEMENT_REQUIRED: a verified account, listing plan and published binding are required"
)


def _runtime_listing_actor_key(agent_id: str, binding_id: str) -> str:
    """Stable per-agent/per-binding idempotency and rate-limit bucket."""
    from kiwi_catalog.core.tokens import token_digest

    return "runtime-listing:" + token_digest(f"{agent_id}:{binding_id}")


def _untrusted_jws_claims(jws: str) -> dict[str, Any]:
    """Decode bounded JWS claims for pre-verification expiry rejection only."""
    if not isinstance(jws, str) or len(jws) > 16_384 or jws.count(".") != 2:
        raise PermissionDenied("invalid runtime listing signature")
    try:
        segment = jws.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, json.JSONDecodeError) as exc:
        raise PermissionDenied("invalid runtime listing signature") from exc
    if not isinstance(payload, dict):
        raise PermissionDenied("invalid runtime listing signature")
    return payload


def _validate_runtime_listing_exp(claims: dict[str, Any]) -> None:
    try:
        expires = datetime.fromisoformat(str(claims.get("exp", "")))
    except ValueError as exc:
        raise PermissionDenied("runtime listing signature has invalid exp") from exc
    now = datetime.now(UTC)
    if expires.tzinfo is None or expires <= now or expires > now + timedelta(minutes=2):
        raise PermissionDenied("runtime listing signature expired or has excessive lifetime")


def _verify_runtime_listing_signature(
    conn: sqlite3.Connection,
    *,
    signature: str,
    agent_id: str,
    merchant_id: str,
    signed_fields: dict[str, Any],
) -> tuple[str, str, str]:
    from kiwi_catalog.a2a.request_signature import verify_runtime_request

    claims = _untrusted_jws_claims(signature)
    _validate_runtime_listing_exp(claims)
    agent = conn.execute(
        "select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?",
        (agent_id,),
    ).fetchone()
    active = conn.execute(
        "select * from runtime_bindings where catalog_agent_id=? and status='active' "
        "order by binding_version desc limit 1",
        (agent_id,),
    ).fetchone()
    if (agent is None or active is None or str(agent["merchant_id"] or "") != merchant_id
            or str(active["merchant_id"] or "") != merchant_id
            or str(agent["administrative_state"] or "active") != "active"):
        raise PermissionDenied(_LISTINGS_ENTITLEMENT_REQUIRED)
    binding_id = str(active["binding_id"])
    key_id = str(active["key_id"])
    expected = {
        "method": "POST",
        "audience": "kiwi-catalog",
        "agent_id": agent_id,
        "merchant_id": merchant_id,
        "binding_id": binding_id,
        "key_id": key_id,
        **signed_fields,
    }
    verify_runtime_request(
        conn,
        catalog_agent_id=agent_id,
        jws=signature,
        expected_fields=expected,
    )

    return f"runtime:{agent_id}:{binding_id}", _runtime_listing_actor_key(agent_id, binding_id), binding_id


def _require_current_listing_entitlement(
    conn: sqlite3.Connection, agent_id: str, merchant_id: str, binding_id: str
) -> None:
    """Derive listings:publish from the current enrollment and current admin grant."""
    enrollment = conn.execute(
        "select enrollment_id from enrollments where catalog_agent_id=? and merchant_id=? "
        "and binding_id=? and status='published' order by authorized_at desc limit 1",
        (agent_id, merchant_id, binding_id),
    ).fetchone()
    if enrollment is None:
        raise PermissionDenied(_LISTINGS_ENTITLEMENT_REQUIRED)

    from kiwi_catalog.services.listing_entitlements import capacity
    capacity(conn, merchant_id)  # Existing entitlement; token state is irrelevant.


def _require_runtime_listing_grant(
    conn: sqlite3.Connection,
    payload: dict[str, Any],
    canonical: dict[str, Any],
    idempotency_key: str,
) -> tuple[str, str, str]:
    """Verify a signed listing publish and its live narrow entitlement."""
    from kiwi_catalog.a2a.enrollment_canonical import canonical_digest

    agent_id = str(canonical["owner_agent_id"])
    merchant_id = str(canonical["merchant_id"])
    if not idempotency_key:
        raise ValidationError("Idempotency-Key is required for binding-signed listing publish")
    actor, actor_key, binding_id = _verify_runtime_listing_signature(
        conn,
        signature=str(payload.get("_binding_jws") or "").strip(),
        agent_id=agent_id,
        merchant_id=merchant_id,
        signed_fields={
            "path": PUBLISH_ENDPOINT,
            "listing_digest": canonical_digest(canonical),
            "idempotency_key": idempotency_key,
        },
    )
    _require_current_listing_entitlement(conn, agent_id, merchant_id, binding_id)
    return actor, actor_key, binding_id


def _write_rate_limit_per_minute() -> int:
    import os

    from kiwi_catalog.services.buyer_bootstrap import rate_limit_per_minute

    raw = (
        os.environ.get("KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE")
        or os.environ.get("SHOPPING_AGENT_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE")
    )
    return rate_limit_per_minute(raw, default=60, maximum=2**63 - 1)


def _require_owner_token_for_merchant(
    payload: dict[str, Any],
    merchant_id: str,
    db_path: str | Path | None = None,
    conn: Any | None = None,
) -> str:
    """owner token 双路径校验（admin 可豁免）；返回 actor 串。

    随机 token 落库校验（docs §5）需要连接：调用点在 db_session 块内传
    conn=；在块外传 db_path=（helper 自开短连接）；两者都缺省时退化为
    HMAC 派生路径（行为同旧版）。
    """
    try:
        api_auth.require_admin_token(payload, conn if conn is not None else db_path)
        return "admin"
    except AuthError:
        pass
    if conn is not None:
        api_auth.require_merchant_token(payload, merchant_id, conn)
    elif db_path is not None:
        with db_session(db_path) as token_conn:
            api_auth.require_merchant_token(payload, merchant_id, token_conn)
    else:
        api_auth.require_merchant_token(payload, merchant_id, None)
    return f"merchant:{merchant_id}"


def _reject_account_owner_token_listing(conn: sqlite3.Connection, merchant_id: str, actor: str) -> None:
    """Runtime binding is the default Listings identity; legacy is opt-in only."""
    if actor == "admin":
        return
    import os
    if (conn.execute("select 1 from merchant_accounts where merchant_id=?", (merchant_id,)).fetchone()
            or os.environ.get("KIWI_CATALOG_ENABLE_LEGACY_LISTINGS", "").lower() != "on"):
        raise PermissionDenied("LISTINGS_BINDING_REQUIRED: connect a Runtime; owner token cannot publish Listings")


def _listing_request_hash(values: dict[str, Any]) -> str:
    """publish 请求级 request_hash（内容字段全集）。"""
    return api_idempotency.request_hash(values)


# ── Read handlers ───────────────────────────────────────────────────────────


_LISTING_SEARCH_FILTER_KEYS = (
    "category",
    "region",
    "tag",
    "listing_type",
    "handoff_destination_type",
)


def _record_listing_search_event(
    conn: Any, query: dict[str, Any], results: list[dict[str, Any]]
) -> None:
    """买家搜 listing 埋点（运营数据源）：query/filters + 返回摘要（前 N 条）。"""
    buyer_search_events.record_search_event(
        conn,
        search_type="listing",
        query=str(query.get("q") or ""),
        filters={
            k: query[k] for k in _LISTING_SEARCH_FILTER_KEYS if str(query.get(k) or "").strip()
        },
        result_count=len(results),
        result_summary=[
            {
                "listing_id": (r.get("listing") or {}).get("listing_id") or "",
                "title": (r.get("listing") or {}).get("title") or "",
            }
            for r in (results or [])[:buyer_search_events.SUMMARY_CAP]
        ],
    )
    # 关键词日聚合（v27）：空 q（filter-only 搜索）由服务层归一化跳过。
    buyer_stats.record_buyer_keyword(conn, "listing", query.get("q"), len(results))


def v1_search_listings(
    db_path: str | Path,
    query: dict[str, Any],
    auth_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """GET /v1/listings/search —— 结构化过滤 + 确定性排序 + cursor。

    auth_payload：transport 合并后的身份头（Bearer / X-Buyer-Id），仅用于
    每日去重买家统计（services/buyer_stats.py，不落原始身份）。
    """
    limit = result_limit(query.get("limit"), default=20)
    normalized = dict(query or {})
    normalized["limit"] = limit
    with db_session(db_path) as conn:
        usage_metrics.record_usage(conn, usage_metrics.METRIC_BUYER_LISTING_SEARCH)
        buyer_stats.record_buyer_search(
            conn,
            usage_metrics.METRIC_BUYER_LISTING_SEARCH,
            buyer_stats.buyer_identity_from_payload(auth_payload),
        )
        try:
            rows, next_cursor = _search_listings(conn, normalized)
        except SearchQueryError as exc:
            raise ValidationError(str(exc)) from exc
        results: list[dict[str, Any]] = []
        for row in rows:
            merchant_row = conn.execute(
                "select * from merchants where id = ?", (row.get("merchant_id"),)
            ).fetchone()
            agent_row = conn.execute(
                "select * from catalog_agents where catalog_agent_id = ?",
                (row.get("owner_agent_id"),),
            ).fetchone()
            results.append(
                listing_search_result(
                    row,
                    merchant_projection(dict(merchant_row) if merchant_row is not None else None),
                    agent_projection(dict(agent_row) if agent_row is not None else None),
                )
            )
        _record_listing_search_event(conn, normalized, results)
        return {
            "ok": True,
            "results": results,
            "next_cursor": next_cursor,
        }


def v1_get_listing(db_path: str | Path, listing_id: str) -> dict[str, Any]:
    """GET /v1/listings/{listing_id} —— 单条公开投影。"""
    listing_id = str(listing_id).strip()
    if not listing_id:
        raise ValidationError("listing_id is required")
    with db_session(db_path) as conn:
        repo.expire_stale_listings(conn, now_iso())
        row = repo.get_listing(conn, listing_id)
        if row is None:
            from kiwi_catalog.core.errors import NotFoundError

            raise NotFoundError(f"Unknown listing: {listing_id}")
        return {"ok": True, "listing": listing_record(row)}


def v1_list_agent_listings(
    db_path: str | Path,
    agent_id: str,
    query: dict[str, Any],
    auth_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """GET /v1/agents/{agent_id}/listings —— publisher 自查（v0.4 §7.2）。

    支持 ?freshness_state=STALE 过滤过期项（v0.4 §15.1 闭环的自查半边）。

    授权与 withdraw/reinstate 一致（owner token 或 admin token；admin 豁免）：
    - owner_token 仍经 query 传递（?owner_token=…，legacy 自查兼容，GET 无
      body 的必然妥协，CLAUDE.md 记录为不修的设计取舍）；
    - admin token 只经 Authorization: Bearer 传递（KC-SEC-02：凭据不得进
      query——会落入访问日志/浏览器历史）。query 中的 admin_token 一律忽略，
      由 transport 层把 header 合并为 payload["_auth_token"]（fallback 栈
      payload_with_auth 与 FastAPI 路由都会合并）。
    agent 未绑定 merchant 时不存在可归属 owner——仅 admin 可读，防止任意
    访客枚举任意 merchant 的 listing 清单与治理状态（SUSPENDED/WITHDRAWN）。
    """
    owner_agent_id = str(agent_id).strip()
    limit = result_limit(query.get("limit"), default=20)
    freshness_state = str(query.get("freshness_state") or "").strip() or None
    if freshness_state is not None and freshness_state not in LISTING_FRESHNESS_STATES:
        raise ValidationError(f"freshness_state must be one of {LISTING_FRESHNESS_STATES}")

    # query 派生 auth 只认 owner_token（自查兼容）；admin 凭据不得出现在
    # query 派生的 auth 中——admin 只从 transport 的 _auth_token 读取。
    auth_payload = dict(auth_payload or {})
    binding_signature = str(auth_payload.get("_binding_jws") or "").strip()
    q_owner_token = str(query.get("owner_token") or "").strip()
    if binding_signature and q_owner_token:
        raise PermissionDenied("binding-signed self-list must not include owner_token in query")
    if q_owner_token and not binding_signature:
        auth_payload["owner_token"] = q_owner_token
    with db_session(db_path) as conn:
        merchant_id = owner_agent_merchant_id(conn, owner_agent_id)
        if binding_signature:
            from kiwi_catalog.a2a.enrollment_canonical import canonical_digest

            signed_query = {
                "limit": limit,
                "cursor": str(query.get("cursor") or "").strip(),
                "freshness_state": freshness_state or "",
            }
            _actor, actor_key, binding_id = _verify_runtime_listing_signature(
                conn,
                signature=binding_signature,
                agent_id=owner_agent_id,
                merchant_id=merchant_id,
                signed_fields={
                    "method": "GET",
                    "path": f"/v1/agents/{owner_agent_id}/listings",
                    "query_digest": canonical_digest(signed_query),
                },
            )
            _require_current_listing_entitlement(conn, owner_agent_id, merchant_id, binding_id)
        elif merchant_id:
            # Admin reads; accountless legacy token reads require an explicit migration switch.
            actor = _require_owner_token_for_merchant(auth_payload, merchant_id, conn=conn)
            _reject_account_owner_token_listing(conn, merchant_id, actor)
        else:
            try:
                api_auth.require_admin_token(auth_payload, db_path)
            except AuthError as exc:
                raise AuthError(
                    f"agent {owner_agent_id} has no merchant binding; only admin may read its listings"
                ) from exc
        repo.expire_stale_listings(conn, now_iso())
        try:
            rows, next_cursor = repo.list_listings_by_owner(
                conn,
                owner_agent_id,
                freshness_state=freshness_state,
                limit=limit,
                cursor=str(query.get("cursor") or "").strip() or None,
            )
        except ValueError as exc:
            raise ValidationError(f"malformed cursor: {exc}") from exc
        return {
            "ok": True,
            "agent_id": owner_agent_id,
            "results": [listing_record(row) for row in rows],
            "next_cursor": next_cursor,
        }


# ── Write handlers（五步幂等模板）───────────────────────────────────────────


def v1_publish_listing(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/listings/publish —— 行级幂等 upsert（升级计划 §5/§7）。

    请求级幂等（endpoint/actor/idempotency_key + request_hash）+ 行级 upsert
    key（source_product_ref / publisher_listing_key）双轨（评审 P1-4/P2-8）。
    """
    canonical = validate_publish_payload(payload)
    # Runtime proof is selected by header presence and can never fall back to a
    # body owner token. Legacy token use is disabled by default.
    binding_signature = str(payload.get("_binding_jws") or "").strip()
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    request_hash = _listing_request_hash(canonical)

    response: dict[str, Any] = {}
    with db_session(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if binding_signature:
            actor, actor_key, _binding_id = _require_runtime_listing_grant(
                conn, payload, canonical, idempotency_key
            )
        else:
            # Authentication remains before replay/rate budget consumption;
            # accountless legacy migration may opt in; account merchants cannot.
            actor = _require_owner_token_for_merchant(
                payload, str(canonical.get("merchant_id") or ""), conn=conn
            )
            _reject_account_owner_token_listing(conn, str(canonical.get("merchant_id") or ""), actor)
            actor_key = api_idempotency.catalog_write_actor_key(payload)
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, PUBLISH_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _write_rate_limit_per_minute()
        )
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, PUBLISH_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            row, created = _publish_listing_inline(conn, canonical, actor=actor)
            response = {
                "ok": True,
                "listing": listing_record(row),
                "created": created,
                "idempotent": False,
            }
            api_idempotency.complete_catalog_write_idempotency(
                conn, PUBLISH_ENDPOINT, actor_key, idempotency_key, request_hash, response
            )
            usage_metrics.record_usage(conn, usage_metrics.METRIC_LISTING_PUBLISH)
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, PUBLISH_ENDPOINT, actor_key, idempotency_key, request_hash
            )
            raise
    return response


def _publish_listing_inline(
    conn: sqlite3.Connection, canonical: dict[str, Any], *, actor: str
) -> tuple[dict[str, Any], bool]:
    """事务窗口内 publish（service 层编排 + 审计）。"""
    from kiwi_catalog.listings.service import publish_listing

    row, created = publish_listing(conn, canonical, actor=actor)
    append_catalog_audit(
        conn,
        str(row.get("owner_agent_id") or ""),
        actor,
        "listing_published" if created else "listing_republished",
        {"listing_id": row.get("listing_id"), "listing_type": row.get("listing_type")},
    )
    return row, created


def v1_withdraw_listing(db_path: str | Path, listing_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/listings/{id}/withdraw —— publisher 主动下架。"""
    listing_id = str(listing_id).strip()
    signature = str(payload.get("_binding_jws") or "").strip()
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    request_hash = _listing_request_hash({"listing_id": listing_id, "action": "withdraw"})

    response: dict[str, Any] = {}
    with db_session(db_path) as conn:
        row = repo.get_listing(conn, listing_id)
        if row is None:
            from kiwi_catalog.core.errors import NotFoundError

            raise NotFoundError(f"Unknown listing: {listing_id}")
        merchant_id = str(row.get("merchant_id") or "")
        owner_agent_id = str(row.get("owner_agent_id") or "")
        if signature:
            from kiwi_catalog.a2a.enrollment_canonical import canonical_digest

            if not idempotency_key:
                raise ValidationError("Idempotency-Key is required for binding-signed listing withdraw")
            body_fields = {
                key for key in payload
                if key not in {"_binding_jws", "_auth_token", "_idempotency_key", "idempotency_key"}
            }
            if body_fields:
                raise ValidationError("binding-signed listing withdraw body must be empty")
            actor, actor_key, binding_id = _verify_runtime_listing_signature(
                conn,
                signature=signature,
                agent_id=owner_agent_id,
                merchant_id=merchant_id,
                signed_fields={
                    "method": "POST",
                    "path": f"/v1/listings/{listing_id}/withdraw",
                    "listing_id": listing_id,
                    "body_digest": canonical_digest({}),
                    "idempotency_key": idempotency_key,
                },
            )
            _require_current_listing_entitlement(conn, owner_agent_id, merchant_id, binding_id)
        else:
            # Admin or explicitly enabled accountless migration only.
            actor = _require_owner_token_for_merchant(payload, merchant_id, conn=conn)
            _reject_account_owner_token_listing(conn, merchant_id, actor)
            actor_key = api_idempotency.catalog_write_actor_key(payload)
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, WITHDRAW_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _write_rate_limit_per_minute()
        )
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, WITHDRAW_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            from kiwi_catalog.listings.service import withdraw_listing

            withdrawn = withdraw_listing(conn, listing_id, actor=actor, merchant_id=merchant_id)
            append_catalog_audit(
                conn,
                owner_agent_id,
                actor,
                "listing_withdrawn",
                {"listing_id": listing_id},
            )
            response = {"ok": True, "listing": listing_record(withdrawn), "idempotent": False}
            api_idempotency.complete_catalog_write_idempotency(
                conn, WITHDRAW_ENDPOINT, actor_key, idempotency_key, request_hash, response
            )
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, WITHDRAW_ENDPOINT, actor_key, idempotency_key, request_hash
            )
            raise
    return response


def v1_reinstate_listing(db_path: str | Path, listing_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/listings/{id}/reinstate —— SUSPENDED → ACTIVE（publisher/governance）。"""
    listing_id = str(listing_id).strip()
    # 认证先行（与 publish/withdraw 一致）：行存在性 + owner token 校验在
    # 限流/幂等预算消耗之前。
    with db_session(db_path) as conn:
        row = repo.get_listing(conn, listing_id)
        if row is None:
            from kiwi_catalog.core.errors import NotFoundError

            raise NotFoundError(f"Unknown listing: {listing_id}")
        merchant_id = str(row.get("merchant_id") or "")
        owner_agent_id = str(row.get("owner_agent_id") or "")
    actor = _require_owner_token_for_merchant(payload, merchant_id, db_path=db_path)
    with db_session(db_path) as conn:
        _reject_account_owner_token_listing(conn, merchant_id, actor)

    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = _listing_request_hash({"listing_id": listing_id, "action": "reinstate"})

    response: dict[str, Any] = {}
    with db_session(db_path) as conn:
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, REINSTATE_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _write_rate_limit_per_minute()
        )
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, REINSTATE_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            from kiwi_catalog.listings.service import reinstate_listing

            reinstated = reinstate_listing(conn, listing_id, actor=actor, merchant_id=merchant_id)
            append_catalog_audit(
                conn,
                owner_agent_id,
                actor,
                "listing_reinstated",
                {"listing_id": listing_id},
            )
            response = {"ok": True, "listing": listing_record(reinstated), "idempotent": False}
            api_idempotency.complete_catalog_write_idempotency(
                conn, REINSTATE_ENDPOINT, actor_key, idempotency_key, request_hash, response
            )
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, REINSTATE_ENDPOINT, actor_key, idempotency_key, request_hash
            )
            raise
    return response
