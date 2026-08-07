"""Listing API handlers（产品文档 v0.4 §8/§13；升级计划 §4）。

6 条路由：search / get / list-by-owner（publisher 自查）/ publish / withdraw /
reinstate。publish 复用五步幂等模板（replay → rate limit → claim → work →
complete → clear，参照 agent_catalog.py register_catalog_agent）；owner token
语义复用 api/auth.py（owner_token 字段在请求体）；审计事件写入 audit_events。
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
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
from kiwi_catalog.listings.search import SearchQueryError, search_listings as _search_listings
from kiwi_catalog.listings.serialization import (
    agent_projection,
    listing_record,
    listing_search_result,
    merchant_projection,
)

PUBLISH_ENDPOINT = "/v1/listings/publish"
WITHDRAW_ENDPOINT = "/v1/listings/{id}/withdraw"
REINSTATE_ENDPOINT = "/v1/listings/{id}/reinstate"


def _write_rate_limit_per_minute() -> int:
    import os

    from kiwi_catalog.services.buyer_bootstrap import rate_limit_per_minute

    raw = (
        os.environ.get("KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE")
        or os.environ.get("SHOPPING_AGENT_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE")
    )
    return rate_limit_per_minute(raw, default=60, maximum=2**63 - 1)


def _require_owner_token_for_merchant(payload: dict[str, Any], merchant_id: str) -> str:
    """owner token 校验（admin 可豁免）；返回 actor 串。"""
    try:
        api_auth.require_admin_token(payload)
        return "admin"
    except AuthError:
        pass
    api_auth.require_owner_token(payload, merchant_id)
    return f"merchant:{merchant_id}"


def _listing_request_hash(values: dict[str, Any]) -> str:
    """publish 请求级 request_hash（内容字段全集）。"""
    return api_idempotency.request_hash(values)


# ── Read handlers ───────────────────────────────────────────────────────────


def v1_search_listings(db_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/listings/search —— 结构化过滤 + 确定性排序 + cursor。"""
    limit = result_limit(query.get("limit"), default=20)
    normalized = dict(query or {})
    normalized["limit"] = limit
    with db_session(db_path) as conn:
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


def v1_list_agent_listings(db_path: str | Path, agent_id: str, query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/agents/{agent_id}/listings —— publisher 自查（v0.4 §7.2）。

    支持 ?freshness_state=STALE 过滤过期项（v0.4 §15.1 闭环的自查半边）。
    """
    owner_agent_id = str(agent_id).strip()
    limit = result_limit(query.get("limit"), default=20)
    freshness_state = str(query.get("freshness_state") or "").strip() or None
    if freshness_state is not None and freshness_state not in LISTING_FRESHNESS_STATES:
        raise ValidationError(f"freshness_state must be one of {LISTING_FRESHNESS_STATES}")
    with db_session(db_path) as conn:
        repo.expire_stale_listings(conn, now_iso())
        rows, next_cursor = repo.list_listings_by_owner(
            conn,
            owner_agent_id,
            freshness_state=freshness_state,
            limit=limit,
            cursor=str(query.get("cursor") or "").strip() or None,
        )
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
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = _listing_request_hash(canonical)

    response: dict[str, Any] = {}
    with db_session(db_path) as conn:
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
            actor = _require_owner_token_for_merchant(
                payload, str(canonical.get("merchant_id") or "")
            )
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
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = _listing_request_hash({"listing_id": listing_id, "action": "withdraw"})

    response: dict[str, Any] = {}
    with db_session(db_path) as conn:
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
            row = repo.get_listing(conn, listing_id)
            if row is None:
                from kiwi_catalog.core.errors import NotFoundError

                raise NotFoundError(f"Unknown listing: {listing_id}")
            actor = _require_owner_token_for_merchant(
                payload, str(row.get("merchant_id") or "")
            )
            from kiwi_catalog.listings.service import withdraw_listing

            withdrawn = withdraw_listing(conn, listing_id, actor=actor, merchant_id=str(row.get("merchant_id") or ""))
            append_catalog_audit(
                conn,
                str(row.get("owner_agent_id") or ""),
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
            row = repo.get_listing(conn, listing_id)
            if row is None:
                from kiwi_catalog.core.errors import NotFoundError

                raise NotFoundError(f"Unknown listing: {listing_id}")
            actor = _require_owner_token_for_merchant(
                payload, str(row.get("merchant_id") or "")
            )
            from kiwi_catalog.listings.service import reinstate_listing

            reinstated = reinstate_listing(
                conn, listing_id, actor=actor, merchant_id=str(row.get("merchant_id") or "")
            )
            append_catalog_audit(
                conn,
                str(row.get("owner_agent_id") or ""),
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
