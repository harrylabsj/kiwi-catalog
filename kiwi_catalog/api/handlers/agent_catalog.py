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

"""Agent Catalog API handlers (§10.1 read, §10.2–§10.4 writes).

v2.1 scope: public read-only.  v2.2 (Phase 2) adds the four write routes:
register (§10.2), refresh/verify (§10.3), and claim (§10.4) — with real
idempotency claim/replay, per-actor + per-domain rate limits (§17.4), §23
audit, and the §6.2 claim proof.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import ValidationError as SchemaValidationError

from kiwi_catalog.agent_catalog.serializers import (
    catalog_agent_record,
    catalog_search_result,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    _list_capabilities_by_agent,
    _list_endpoints_by_agent,
    _list_skills_by_agent,
    append_catalog_audit,
    enforce_catalog_register_domain_limit,
    get_catalog_agent_by_domain,
    get_catalog_agent_with_merchant,
    list_capabilities,
    list_endpoints,
    list_skills,
    require_catalog_agent,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    list_catalog_agents as _list_catalog_agents,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    list_catalog_agents_by_merchant as _list_catalog_agents_by_merchant,
)
from kiwi_catalog.agent_catalog.sqlite_repository import (
    search_catalog_agents as _repo_search_catalog_agents,
)
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api import idempotency as api_idempotency
from kiwi_catalog.api.handlers.common import (
    MAX_SQLITE_INTEGER,
    require_field,
    result_limit,
)
from kiwi_catalog.core.errors import (
    AuthError,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from kiwi_catalog.core.tokens import token_matches
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import agent_catalog_writes, usage_metrics
from kiwi_catalog.services.agent_catalog import (
    search_catalog_agents as _search_catalog_agents_service,
)

# 审查 P1-8：VerificationQueueFullError 必须在模块级可见——此前只在
# _verification_queue 函数内导入，队列满的 except 分支求值时抛 NameError
# → 500，优雅降级（verification_enqueued=False）是死代码。
from kiwi_catalog.services.agent_verification import VerificationQueueFullError


def _serialize_row(
    row: dict[str, Any],
    conn: Any,
    caps_map: dict[str, list[dict[str, Any]]] | None = None,
    eps_map: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Serialize a catalog agent row + merchant join through public serializer."""
    cagt_id = str(row.get("catalog_agent_id", ""))
    # 审查 P3：批量路径传预取的 map（一次 IN 查询），单行路径回退逐行查询。
    if caps_map is not None:
        caps = caps_map.get(cagt_id, [])
    else:
        caps = list_capabilities(conn, cagt_id)
    if eps_map is not None:
        eps = eps_map.get(cagt_id, [])
    else:
        eps = list_endpoints(conn, cagt_id)
    merchant: dict[str, Any] = {
        "id": row.get("merchant_id", ""),
        "name": row.get("merchant_name", ""),
        "city": row.get("merchant_city", ""),
        "service_area": row.get("merchant_service_area", ""),
        "tags_json": row.get("merchant_tags_json", "[]"),
    }
    return catalog_search_result(
        catalog_agent=row,
        merchant=merchant,
        capabilities=caps,
        endpoints=eps,
    )


def _serialize_rows(rows: list[dict[str, Any]], conn: Any) -> list[dict[str, Any]]:
    """批量序列化（审查 P3：N+1 → 每类一次 IN 查询）。"""
    ids = [str(r.get("catalog_agent_id", "")) for r in rows]
    caps_map = _list_capabilities_by_agent(conn, ids)
    eps_map = _list_endpoints_by_agent(conn, ids)
    return [_serialize_row(row, conn, caps_map, eps_map) for row in rows]


def list_catalog_agents(db_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/agent-catalog/agents — paginated list."""
    limit = result_limit(query.get("limit"), default=20)
    cursor = str(query.get("cursor") or "").strip()
    with db_session(db_path) as conn:
        rows, next_cursor = _list_catalog_agents(conn, limit=limit, cursor=cursor)
        results = _serialize_rows(rows, conn)
        return {
            "ok": True,
            "results": results,
            "next_cursor": next_cursor,
        }


def get_catalog_agent(db_path: str | Path, catalog_agent_id: str) -> dict[str, Any]:
    """GET /v1/agent-catalog/agents/{catalog_agent_id} — detail."""
    with db_session(db_path) as conn:
        row = get_catalog_agent_with_merchant(conn, str(catalog_agent_id).strip())
        if row is None:
            raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")
        return {
            "ok": True,
            "catalog_agent": _serialize_row(row, conn),
        }


def search_agent_catalog(db_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/agent-catalog/agents/search — filtered search (§8.2)."""
    limit = result_limit(query.get("limit"), default=20)
    with db_session(db_path) as conn:
        usage_metrics.record_usage(conn, usage_metrics.METRIC_BUYER_AGENT_SEARCH)
        result = _search_catalog_agents_service(
            conn=conn,
            q=str(query.get("q") or ""),
            category=str(query.get("category") or ""),
            skill=str(query.get("skill") or ""),
            capability=str(query.get("capability") or ""),
            protocol=str(query.get("protocol") or ""),
            hosting_mode=str(query.get("hosting_mode") or ""),
            verification_status=str(query.get("verification_status") or ""),
            verified_after=str(query.get("verified_after") or ""),
            limit=limit,
            cursor=str(query.get("cursor") or "").strip(),
        )
        result["ok"] = True
        return result


def list_merchant_catalog_agents(
    db_path: str | Path, merchant_id: str, query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/agent-catalog/merchants/{merchant_id}/agents — paginated list."""
    limit = result_limit(query.get("limit"), default=20)
    cursor = str(query.get("cursor") or "").strip()
    with db_session(db_path) as conn:
        rows, next_cursor = _list_catalog_agents_by_merchant(
            conn, merchant_id=str(merchant_id).strip(), limit=limit, cursor=cursor
        )
        results = _serialize_rows(rows, conn)
        return {
            "ok": True,
            "results": results,
            "next_cursor": next_cursor,
        }


# ═══════════════════════════════════════════════════════════════════════════
# v2.2 write routes (§10.2–§10.4)
# ═══════════════════════════════════════════════════════════════════════════

REGISTER_ENDPOINT = "/v1/agent-catalog/agents/register"
REFRESH_ENDPOINT = "/v1/agent-catalog/agents/{id}/refresh"
VERIFY_ENDPOINT = "/v1/agent-catalog/agents/{id}/verify"
CLAIM_ENDPOINT = "/v1/agent-catalog/agents/{id}/claim"
SUSPEND_ENDPOINT = "/v1/agent-catalog/agents/{id}/suspend"
REINSTATE_ENDPOINT = "/v1/agent-catalog/agents/{id}/reinstate"

# In-process bounded verification queue (§25 Phase 2), one per db_path.  Tests
# patch ``_verification_queue`` so no worker thread ever touches the wire.
_QUEUE_LOCK = threading.Lock()
_QUEUES: dict[str, Any] = {}


# ── Dependency factories (patch points for tests) ──────────────────────────


def _verification_queue(db_path: str | Path) -> Any:
    """Return the bounded in-process verification queue for *db_path* (§25)."""
    key = str(db_path)
    with _QUEUE_LOCK:
        queue = _QUEUES.get(key)
        if queue is None:
            from kiwi_catalog.services.agent_verification import (
                VerificationQueueConfig,
                make_verification_worker,
            )

            queue = make_verification_worker(db_path, config=VerificationQueueConfig())
            _QUEUES[key] = queue
        return queue


def _verification_service(db_path: str | Path, conn: Any) -> Any:
    """Build a VerificationService bound to an open connection (§6)."""
    from kiwi_catalog.discovery.trust import TrustPolicy
    from kiwi_catalog.services.agent_verification import VerificationService

    return VerificationService(conn, policy=TrustPolicy.defaults())


def _identity_verifier() -> Any:
    """Build an IdentityVerifier for the HTTPS domain-control challenge (§6)."""
    from kiwi_catalog.discovery.fetcher import ProfileFetcher
    from kiwi_catalog.discovery.trust import TrustPolicy
    from kiwi_catalog.discovery.verifier import IdentityVerifier

    policy = TrustPolicy.defaults()
    return IdentityVerifier(ProfileFetcher(policy), policy)


# ── Rate-limit / auth configuration ────────────────────────────────────────


def _catalog_write_rate_limit_per_minute() -> int:
    from kiwi_catalog.services.buyer_bootstrap import rate_limit_per_minute

    # 本库 env 名优先，提取遗留的 SHOPPING_ 名兼容回退。
    raw = (
        os.environ.get("KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE")
        or os.environ.get("SHOPPING_AGENT_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE")
    )
    return rate_limit_per_minute(
        raw,
        default=60,
        maximum=MAX_SQLITE_INTEGER,
    )


def _catalog_register_domain_limit_per_hour() -> int:
    raw = str(os.environ.get("SHOPPING_AGENT_CATALOG_REGISTER_DOMAIN_LIMIT_PER_HOUR") or "").strip()
    if not raw:
        return 20
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        return 20
    # 审查 P2：0 视为误配回退默认——enforce_rate_limit 把 limit<=0 解释为
    # 「禁用限流」，env 误配 0 会静默关掉公开 register 的 SSRF 放大防护。
    if limit <= 0:
        return 20
    return min(limit, 10000)


def _verification_worker_token() -> str:
    return str(os.environ.get("SHOPPING_VERIFICATION_WORKER_TOKEN") or "").strip()


def _require_catalog_write_auth(conn: Any, agent: dict[str, Any], payload: dict[str, Any]) -> str:
    """Enforce §10.3 auth: owner merchant / admin / verification worker.

    Returns an actor string used for §23 audit.
    """
    try:
        api_auth.require_admin_token(payload)
        return "admin"
    except AuthError:
        pass

    expected_worker = _verification_worker_token()
    presented = api_auth.payload_token(payload)
    if expected_worker and presented and token_matches(presented, expected_worker):
        return "verification_worker"

    merchant_id = str(agent.get("merchant_id") or "").strip()
    if merchant_id:
        try:
            api_auth.require_merchant_token(payload, merchant_id, conn)
            return f"merchant:{merchant_id}"
        except AuthError:
            pass
    raise PermissionDenied(
        "admin, verification worker, or owner merchant authorization required for catalog writes"
    )


def _register_actor(conn: Any, payload: dict[str, Any], merchant_id: str) -> str:
    """Resolve the register actor and authorize an optional merchant binding.

    Register is public (§10.2).  When *merchant_id* is supplied, the caller
    must present a valid merchant token (or admin token) for that merchant so
    public registration cannot squat on an existing merchant's catalog entry.
    """
    try:
        api_auth.require_admin_token(payload)
        return "admin"
    except AuthError:
        pass
    if merchant_id:
        api_auth.require_merchant_token(payload, merchant_id, conn)
        return f"merchant:{merchant_id}"
    return "cli"


def _claim_identity(conn: Any, agent: dict[str, Any], payload: dict[str, Any]) -> tuple[str, str]:
    """Resolve the claiming merchant + actor for the claim route (§10.4).

    Admin may claim for any merchant (via ``merchant_id`` or the agent's
    current binding).  A merchant token claims for the token's merchant.
    """
    try:
        api_auth.require_admin_token(payload)
    except AuthError:
        pass
    else:
        merchant_id = str(payload.get("merchant_id") or agent.get("merchant_id") or "").strip()
        if not merchant_id:
            raise ValidationError("merchant_id is required to claim a catalog agent")
        return merchant_id, "admin"

    merchant_id = str(payload.get("merchant_id") or agent.get("merchant_id") or "").strip()
    if not merchant_id:
        raise PermissionDenied("merchant_id is required to claim a catalog agent")
    api_auth.require_merchant_token(payload, merchant_id, conn)
    return merchant_id, f"merchant:{merchant_id}"


def _enqueue_verification(db_path: str | Path, catalog_agent_id: str, *, kind: str, actor: str) -> Any:
    return _verification_queue(db_path).enqueue(catalog_agent_id, kind=kind, actor=actor, wait=False)


def _verification_response(
    result: Any,
    db_path: str | Path | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """验证结果信封（legacy 折叠 verification_status + v0.3 三正交域）。

    三域必须从调用方的事务连接读取（conn 优先）：WAL 模式下新连接读快照
    看不到未提交的验证写入，跨连接读会返回验证前的旧三域值。
    """
    response: dict[str, Any] = {
        "ok": True,
        "catalog_agent_id": result.catalog_agent_id,
        "previous_status": result.previous_status,
        "verification_status": result.status,
        "stages": [
            {
                "stage": stage.stage,
                "outcome": stage.outcome,
                "target_status": stage.target_status,
                "reason": stage.reason,
                "verification_id": stage.verification_id,
                "snapshot_ids": list(stage.snapshot_ids),
            }
            for stage in result.stages
        ],
        "idempotent": False,
    }
    if db_path is not None:
        if conn is not None:
            row = require_catalog_agent(conn, str(result.catalog_agent_id))
        else:
            with db_session(db_path) as fresh_conn:
                row = require_catalog_agent(fresh_conn, str(result.catalog_agent_id))
        response["verification_level"] = row["verification_level"]
        response["freshness_state"] = row["freshness_state"]
        response["administrative_state"] = row["administrative_state"]
    return response


# ── Handlers ───────────────────────────────────────────────────────────────

# 认证/幂等字段在校验前剥离（与 listings contracts.py 的 _AUTH_FIELDS 同模式）。
_REGISTER_AUTH_FIELDS = {
    "owner_token",
    "_auth_token",
    "admin_token",
    "idempotency_key",
    "_idempotency_key",
}

_REGISTER_INPUT_SCHEMA: jsonschema.Draft7Validator | None = None


def _register_input_schema() -> jsonschema.Draft7Validator:
    """模块级惰性加载 register-input.schema.json（CD #8 schema 硬拒落盘）。"""
    global _REGISTER_INPUT_SCHEMA
    if _REGISTER_INPUT_SCHEMA is None:
        schema_path = (
            Path(__file__).resolve().parent.parent.parent / "contracts" / "register-input.schema.json"
        )
        with open(schema_path, encoding="utf-8") as fh:
            _REGISTER_INPUT_SCHEMA = jsonschema.Draft7Validator(json.load(fh))
    return _REGISTER_INPUT_SCHEMA


def _validate_register_input(payload: dict[str, Any]) -> None:
    """register 输入契约硬校验（additionalProperties:false）。

    完成定义 #8：注册输入只能是 schema 声明的公开字段——私有经营数据
    （成本/底价/私密库存/凭据）在 schema 层拒绝，未知字段一律 422。
    认证/幂等字段剥离后再校验；domain 的 hostname 形态由
    normalize_canonical_domain 负责（schema 只查存在性）。
    """
    candidate = {k: v for k, v in (payload or {}).items() if k not in _REGISTER_AUTH_FIELDS}
    try:
        _register_input_schema().validate(candidate)
    except SchemaValidationError as exc:
        raise ValidationError(f"register payload invalid: {exc.message}") from exc


def register_catalog_agent(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agent-catalog/agents/register (§10.2).

    Creates a DISCOVERED self_registered record (with optional profile
    endpoints / merchant binding) and enqueues a verification task into the
    bounded in-process queue.  Idempotency claim/replay is real; per-actor and
    per-domain rate limits (§17.4) are enforced before any side effect.
    """
    # CD #8 schema 硬拒（additionalProperties:false）——未知字段/私有字段
    # 在幂等/限流预算之前 fail-fast。
    _validate_register_input(payload)
    canonical = agent_catalog_writes.normalize_canonical_domain(require_field(payload, "domain"))
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = api_idempotency.catalog_register_request_hash(payload)

    response: dict[str, Any] = {}
    cagt_id = ""
    actor = "cli"
    with db_session(db_path) as conn:
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, REGISTER_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _catalog_write_rate_limit_per_minute()
        )
        # §17.4 per-domain budget — the public register route must not become an
        # SSRF scanner across arbitrary domains.
        enforce_catalog_register_domain_limit(conn, canonical, _catalog_register_domain_limit_per_hour())
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, REGISTER_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            merchant_id = str(payload.get("merchant_id") or "").strip()
            actor = _register_actor(conn, payload, merchant_id)
            # 审查 P1-4b：重注册已治理 agent（suspended / rejected）= 复活，
            # 必须证明控制权——admin token，或既有绑定商户的 owner token。
            # 匿名重注册不得静默撤销 admin 处置（suspend 端点「唯一出向
            # admin reinstate」语义）；新域注册不受影响。
            existing_row = get_catalog_agent_by_domain(conn, canonical)
            if (
                existing_row is not None
                and str(existing_row.get("administrative_state") or "")
                in agent_catalog_writes.RE_REGISTERABLE_ADMIN
                and actor == "cli"
            ):
                bound = str(existing_row.get("merchant_id") or "").strip()
                if bound:
                    api_auth.require_merchant_token(payload, bound, conn)
                else:
                    api_auth.require_admin_token(payload)
            result = agent_catalog_writes.register_catalog_agent(
                conn,
                domain=canonical,
                agent_card_url=str(payload.get("agent_card_url") or ""),
                ucp_profile_url=str(payload.get("ucp_profile_url") or ""),
                merchant_id=merchant_id,
                actor=actor,
                display_name=str(payload.get("display_name") or ""),
                hosting_mode=str(payload.get("hosting_mode") or ""),
                handoff_destination_types=(
                    list(payload["handoff_destination_types"])
                    if isinstance(payload.get("handoff_destination_types"), list)
                    else None
                ),
                capabilities=(
                    list(payload["capabilities"])
                    if isinstance(payload.get("capabilities"), list)
                    else None
                ),
                skills=(
                    list(payload["skills"]) if isinstance(payload.get("skills"), list) else None
                ),
            )
            cagt_id = str(result.get("catalog_agent_id") or "")
            response = {
                "ok": True,
                "catalog_agent": result,
                "verification_enqueued": True,
                "task_id": "",
                "idempotent": False,
            }
            api_idempotency.complete_catalog_write_idempotency(
                conn, REGISTER_ENDPOINT, actor_key, idempotency_key, request_hash, response
            )
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, REGISTER_ENDPOINT, actor_key, idempotency_key, request_hash
            )
            raise
    # Enqueue AFTER the transaction commits: the persistent queue (v3.0-P4)
    # writes its ledger through a second connection, which would deadlock
    # against the still-open write transaction.  The task_id is returned in
    # the response but not cached in the idempotency row (a replay is a
    # fresh outcome, not the same run).
    try:
        enqueued = _enqueue_verification(db_path, cagt_id, kind="verify", actor=actor)
        response["task_id"] = getattr(enqueued, "task_id", "")
    except VerificationQueueFullError:
        # 队列满：注册本身已成功（事务已提交）——返回 400 会让调用方重试，
        # 幂等重放得到 task_id="" 且验证永不执行。改为显式标注未入队。
        response["verification_enqueued"] = False
        response["queue_reason"] = "verification queue full; verify later via the verify endpoint"
    return response


def refresh_catalog_agent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agent-catalog/agents/{id}/refresh (§10.3).

    Enqueues an explicit-refresh task into the bounded verification queue.
    Auth: owner merchant / admin / verification worker.
    """
    catalog_agent_id = str(catalog_agent_id).strip()
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = api_idempotency.catalog_agent_action_request_hash(payload, catalog_agent_id)

    with db_session(db_path) as conn:
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, REFRESH_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _catalog_write_rate_limit_per_minute()
        )
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, REFRESH_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            agent = require_catalog_agent(conn, catalog_agent_id)
            actor = _require_catalog_write_auth(conn, agent, payload)
            response = {
                "ok": True,
                "catalog_agent_id": catalog_agent_id,
                "verification_status": agent["verification_status"],
                "refresh_enqueued": True,
                "task_id": "",
                "idempotent": False,
            }
            api_idempotency.complete_catalog_write_idempotency(
                conn, REFRESH_ENDPOINT, actor_key, idempotency_key, request_hash, response
            )
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, REFRESH_ENDPOINT, actor_key, idempotency_key, request_hash
            )
            raise
    # Enqueue AFTER the transaction commits — see register_catalog_agent
    # for the ledger write-lock rationale (v3.0-P4 persistent queue).
    enqueued = _enqueue_verification(db_path, catalog_agent_id, kind="refresh", actor=actor)
    response["task_id"] = getattr(enqueued, "task_id", "")
    return response


def verify_catalog_agent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agent-catalog/agents/{id}/verify (§10.3).

    Runs the §6 verification ladder synchronously and returns the stage result.
    Auth: owner merchant / admin / verification worker.  §23 audit events
    (verified / verification_failed / refreshed / stale) are written by the
    VerificationService.
    """
    catalog_agent_id = str(catalog_agent_id).strip()
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = api_idempotency.catalog_agent_action_request_hash(payload, catalog_agent_id)

    with db_session(db_path) as conn:
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, VERIFY_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _catalog_write_rate_limit_per_minute()
        )
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, VERIFY_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            agent = require_catalog_agent(conn, catalog_agent_id)
            actor = _require_catalog_write_auth(conn, agent, payload)
            service = _verification_service(db_path, conn)
            result = service.verify(catalog_agent_id, actor=actor)
            # 复用外层事务连接读三域（验证写入未 commit，跨连接读不到）。
            response = _verification_response(result, db_path, conn)
            api_idempotency.complete_catalog_write_idempotency(
                conn, VERIFY_ENDPOINT, actor_key, idempotency_key, request_hash, response
            )
            return response
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, VERIFY_ENDPOINT, actor_key, idempotency_key, request_hash
            )
            raise


def claim_catalog_agent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agent-catalog/agents/{id}/claim (§10.4, §6.2).

    Proves ownership via hosted identity (merchant/admin) or an HTTPS
    domain-control challenge for self_registered/discovered agents, then binds
    the agent to the claiming merchant.  Knowing the Agent Card URL is never
    proof of ownership.
    """
    catalog_agent_id = str(catalog_agent_id).strip()
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = api_idempotency.catalog_agent_action_request_hash(payload, catalog_agent_id)

    with db_session(db_path) as conn:
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, CLAIM_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _catalog_write_rate_limit_per_minute()
        )
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, CLAIM_ENDPOINT, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            agent = require_catalog_agent(conn, catalog_agent_id)
            merchant_id, actor = _claim_identity(conn, agent, payload)
            result = agent_catalog_writes.claim_catalog_agent(
                conn,
                catalog_agent_id=catalog_agent_id,
                merchant_id=merchant_id,
                actor=actor,
                identity_verifier=_identity_verifier(),
            )
            response: dict[str, Any] = {
                "ok": True,
                "catalog_agent": result,
                "idempotent": False,
            }
            api_idempotency.complete_catalog_write_idempotency(
                conn, CLAIM_ENDPOINT, actor_key, idempotency_key, request_hash, response
            )
            return response
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, CLAIM_ENDPOINT, actor_key, idempotency_key, request_hash
            )
            raise


def _moderation_action(
    db_path: str | Path,
    catalog_agent_id: str,
    payload: dict[str, Any],
    *,
    endpoint: str,
    action: str,
    reason: str = "",
    after_work: Any = None,
) -> dict[str, Any]:
    """Shared v3.0 moderation write path: suspend / reinstate.

    Both actions are admin-only (marketplace moderation, §10.4 P2): the
    payload must carry a valid admin bootstrap token, which also resolves
    the audit actor.  Idempotency and per-actor rate limits mirror the
    other catalog write routes (§17.4).
    """
    catalog_agent_id = str(catalog_agent_id).strip()
    idempotency_key = api_idempotency.idempotency_key_from_payload(payload)
    actor_key = api_idempotency.catalog_write_actor_key(payload)
    request_hash = api_idempotency.catalog_agent_action_request_hash(payload, catalog_agent_id)

    with db_session(db_path) as conn:
        replayed = api_idempotency.replay_catalog_write_idempotency(
            conn, endpoint, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        api_idempotency.enforce_agent_catalog_rate_limit(
            conn, actor_key, _catalog_write_rate_limit_per_minute()
        )
        replayed = api_idempotency.claim_catalog_write_idempotency(
            conn, endpoint, actor_key, idempotency_key, request_hash
        )
        if replayed is not None:
            return replayed
        try:
            # Admin-only: moderation must never be driven by a merchant owner
            # or the verification worker (raises AuthError → 401/403).
            api_auth.require_admin_token(payload)
            require_catalog_agent(conn, catalog_agent_id)  # 404 on unknown id
            service = _verification_service(db_path, conn)
            result = getattr(service, action)(catalog_agent_id, actor="admin", reason=reason)
            if after_work is not None:
                # 同事务窗口内的治理联动（v0.4 DoD #12）：agent suspend 与其
                # owned Listings 标记原子提交，要么都成功要么都回滚；幂等
                # replay 提前 return 不会重复执行（联动本身幂等）。
                after_work(conn, catalog_agent_id)
            response: dict[str, Any] = {
                "ok": True,
                "catalog_agent_id": catalog_agent_id,
                "previous_status": result.previous_status,
                "verification_status": result.status,
                "stages": [
                    {
                        "stage": stage.stage,
                        "outcome": stage.outcome,
                        "target_status": stage.target_status,
                        "reason": stage.reason,
                    }
                    for stage in result.stages
                ],
                "idempotent": False,
            }
            api_idempotency.complete_catalog_write_idempotency(
                conn, endpoint, actor_key, idempotency_key, request_hash, response
            )
            return response
        except Exception:
            api_idempotency.clear_catalog_write_idempotency_claim(
                conn, endpoint, actor_key, idempotency_key, request_hash
            )
            raise


def _payload_reason(payload: dict[str, Any]) -> str:
    """Optional operator reason from the request body (recorded in §23 audit)."""
    return str((payload or {}).get("reason") or "").strip()


def suspend_catalog_agent(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/agent-catalog/agents/{id}/suspend (v3.0 moderation, §10.4 P2).

    Suspends an agent (admin-only, idempotent).  A suspended agent keeps its
    catalog row but is excluded from verification promotion; the only way
    back is an explicit admin reinstate.

    治理联动（DoD #12 owned Listings → SUSPENDED）已在 VerificationService.
    suspend 内部统一实现（CLI/队列/HTTP 共用 service，单点生效），此处不再
    传 after_work——避免与 service 内联动双写 audit。
    """
    return _moderation_action(
        db_path,
        catalog_agent_id,
        payload,
        endpoint=SUSPEND_ENDPOINT,
        action="suspend",
        reason=_payload_reason(payload),
    )


def reinstate_catalog_agent(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/agent-catalog/agents/{id}/reinstate (v3.0 moderation, §10.4 P2).

    Admin-only reinstate: SUSPENDED → ACTIVE，**保留** verification_level
    with freshness（三域模型：证据未失效，级别不应丢失；折叠投影恢复后回到
    discovery 验证路径）。The enqueued task id is returned as
    ``verify_task_id``.
    """
    response = _moderation_action(
        db_path,
        catalog_agent_id,
        payload,
        endpoint=REINSTATE_ENDPOINT,
        action="reinstate",
        reason=_payload_reason(payload),
    )
    # Auto-queue one verification run (idempotent replays return early inside
    # _moderation_action, so this only runs on the fresh reinstate path).
    if response.get("verification_status") == "discovered":
        enqueued = _enqueue_verification(db_path, catalog_agent_id, kind="verify", actor="admin")
        response["verify_enqueued"] = True
        response["verify_task_id"] = getattr(enqueued, "task_id", "")
    return response


# ── /v1/agents（v0.3 新 API：三正交状态域 record）─────────────────────────


def _record_row(
    row: dict[str, Any],
    conn: Any,
    caps_map: dict[str, list[dict[str, Any]]] | None = None,
    eps_map: dict[str, list[dict[str, Any]]] | None = None,
    skills_map: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Serialize a catalog agent row → CatalogAgentRecord（含 skills）。"""
    cagt_id = str(row.get("catalog_agent_id", ""))
    # 审查 P3：批量路径传预取 map；单行路径回退逐行查询。
    if caps_map is not None:
        caps = caps_map.get(cagt_id, [])
    else:
        caps = list_capabilities(conn, cagt_id)
    if eps_map is not None:
        eps = eps_map.get(cagt_id, [])
    else:
        eps = list_endpoints(conn, cagt_id)
    if skills_map is not None:
        skills = skills_map.get(cagt_id, [])
    else:
        skills = list_skills(conn, cagt_id)
    merchant: dict[str, Any] = {
        "id": row.get("merchant_id", ""),
        "name": row.get("merchant_name", ""),
        "city": row.get("merchant_city", ""),
        "service_area": row.get("merchant_service_area", ""),
        "tags_json": row.get("merchant_tags_json", "[]"),
    }
    return catalog_agent_record(
        catalog_agent=row,
        merchant=merchant,
        capabilities=caps,
        endpoints=eps,
        skills=skills,
    )


def _record_rows(rows: list[dict[str, Any]], conn: Any) -> list[dict[str, Any]]:
    """批量序列化 record（审查 P3：N+1 → 每类一次 IN 查询）。"""
    ids = [str(r.get("catalog_agent_id", "")) for r in rows]
    caps_map = _list_capabilities_by_agent(conn, ids)
    eps_map = _list_endpoints_by_agent(conn, ids)
    skills_map = _list_skills_by_agent(conn, ids)
    return [_record_row(row, conn, caps_map, eps_map, skills_map) for row in rows]


def v1_list_agents(db_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/agents — paginated list（record 形状）。"""
    limit = result_limit(query.get("limit"), default=20)
    cursor = str(query.get("cursor") or "").strip()
    with db_session(db_path) as conn:
        rows, next_cursor = _list_catalog_agents(conn, limit=limit, cursor=cursor)
        results = _record_rows(rows, conn)
        return {"ok": True, "results": results, "next_cursor": next_cursor}


def v1_search_agents(db_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    """GET /v1/agents/search — 三态域 + handoff 词表搜索（v0.3 §8）。"""
    limit = result_limit(query.get("limit"), default=20)
    # canonical hosting_mode（direct_only/hosted_only）归一化为 legacy 存储值。
    hosting_mode = agent_catalog_writes.normalize_hosting_mode(
        str(query.get("hosting_mode") or "")
    )
    with db_session(db_path) as conn:
        usage_metrics.record_usage(conn, usage_metrics.METRIC_BUYER_AGENT_SEARCH)
        rows, next_cursor = _repo_search_catalog_agents(
            conn,
            q=str(query.get("q") or ""),
            capability=str(query.get("capability") or ""),
            protocol=str(query.get("protocol") or ""),
            hosting_mode=hosting_mode,
            verification_level=str(query.get("verification_level") or ""),
            freshness_state=str(query.get("freshness_state") or ""),
            administrative_state=str(query.get("administrative_state") or ""),
            handoff_destination_types=str(query.get("handoff_destination_types") or ""),
            limit=limit,
            cursor=str(query.get("cursor") or "").strip(),
        )
        results = _record_rows(rows, conn)
        return {"ok": True, "results": results, "next_cursor": next_cursor}


def v1_get_agent(db_path: str | Path, catalog_agent_id: str) -> dict[str, Any]:
    """GET /v1/agents/{catalog_agent_id} — detail（record 形状）。"""
    with db_session(db_path) as conn:
        row = get_catalog_agent_with_merchant(conn, str(catalog_agent_id).strip())
        if row is None:
            raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")
        return {"ok": True, "agent": _record_row(row, conn)}


def v1_register_agent(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agents/register — 复用 legacy 写路径（幂等/限流/审计同一套），
    响应换 CatalogAgentRecord（v0.3 §9）。"""
    legacy = register_catalog_agent(db_path, payload)
    cagt_id = str(legacy["catalog_agent"]["catalog_agent_id"])
    with db_session(db_path) as conn:
        row = get_catalog_agent_with_merchant(conn, cagt_id)
        record = _record_row(row, conn) if row is not None else None
    return {
        "ok": True,
        "agent": record,
        "verification_enqueued": legacy.get("verification_enqueued", True),
        "task_id": legacy.get("task_id", ""),
        "queue_reason": legacy.get("queue_reason", ""),
        "idempotent": legacy.get("idempotent", False),
    }


def v1_refresh_agent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agents/{id}/refresh — 响应换 record + 三域。"""
    legacy = refresh_catalog_agent(db_path, catalog_agent_id, payload)
    with db_session(db_path) as conn:
        row = get_catalog_agent_with_merchant(conn, str(catalog_agent_id).strip())
        record = _record_row(row, conn) if row is not None else None
    return {
        "ok": True,
        "agent": record,
        "refresh_enqueued": legacy.get("refresh_enqueued", True),
        "task_id": legacy.get("task_id", ""),
        "idempotent": legacy.get("idempotent", False),
    }


def v1_verify_agent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agents/{id}/verify — legacy 信封（含三域）+ record 视图。"""
    legacy = verify_catalog_agent(db_path, catalog_agent_id, payload)
    with db_session(db_path) as conn:
        row = get_catalog_agent_with_merchant(conn, str(catalog_agent_id).strip())
        record = _record_row(row, conn) if row is not None else None
    return {**legacy, "agent": record}


def v1_claim_agent(db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/agents/{id}/claim — 响应换 record。"""
    legacy = claim_catalog_agent(db_path, catalog_agent_id, payload)
    with db_session(db_path) as conn:
        row = get_catalog_agent_with_merchant(conn, str(catalog_agent_id).strip())
        record = _record_row(row, conn) if row is not None else None
    return {"ok": True, "agent": record, "idempotent": legacy.get("idempotent", False)}
