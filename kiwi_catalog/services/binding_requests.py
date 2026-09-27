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

"""首次绑定的「请求 → 商家门户确认」两步闭环（D1/D2；设计 §4.3③/§6/§10）。

- 运行时首绑（endpoint_policy → 持钥证明 → nonce 防重放全部通过）落一条
  **待确认接入请求**（``runtime_binding_requests``，迁移 38），不签发
  active 绑定——未确认期间公开读 ``/runtime-binding`` 仍 404，Catalog 不得
  提前背书（绑定声明是 Catalog 用自己的名字签发的，背书的依据必须是
  **商家的同意**，见 §4.3「为什么确认不能省」）。
- 未决请求带 TTL（默认 72h）与每 agent 未决上限（默认 3 条）；过期视为
  不存在（读路径过滤 + 惰性标 expired）。
- 商家门户确认：**同一事务**里写 active 绑定（binding_version = 该 agent
  现有最大值 +1）→ 消费请求行 → 同行其他未决请求失效（§10「确认后旧请求
  即失效」）→ D2 回填 ``canonical_domain`` = runtime_origin 的 canonical
  host → 审计留痕（actor=``merchant:<merchant_id>``）。
- 已决请求重复决策 → 409；非本商家 → 404（与不存在不可区分）。
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit
from kiwi_catalog.core.errors import ConflictError, NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso
from kiwi_catalog.discovery._validation import canonical_domain_of
from kiwi_catalog.services.account_agents import _require_owned_agent

_TTL_HOURS_ENV = "KIWI_CATALOG_BINDING_REQUEST_TTL_HOURS"
_MAX_PENDING_ENV = "KIWI_CATALOG_BINDING_REQUEST_MAX_PENDING"


def ttl_hours() -> int:
    """未决请求 TTL（小时，默认 72；env 覆盖，非法值回退默认）。"""
    raw = os.environ.get(_TTL_HOURS_ENV) or ""
    try:
        return max(1, int(raw)) if raw else 72
    except ValueError:
        return 72


def max_pending() -> int:
    """每 agent 未决请求上限（默认 3；env 覆盖，非法值回退默认）。"""
    raw = os.environ.get(_MAX_PENDING_ENV) or ""
    try:
        return max(1, int(raw)) if raw else 3
    except ValueError:
        return 3


def new_binding_request_id() -> str:
    return f"breq_{secrets.token_urlsafe(9)}"


def record_active_binding_evidence(
    conn: sqlite3.Connection, *, catalog_agent_id: str, binding_id: str,
    key_thumbprint: str, runtime_origin: str, a2a_endpoint: str, checked_at: str,
) -> str:
    """Record the same cloud binding evidence and verification promotion for every bind path."""
    from kiwi_catalog.agent_catalog.verification_evidence import insert_verification
    from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

    active = conn.execute("select expires_at from runtime_bindings where binding_id=? and status='active'", (binding_id,)).fetchone()
    if active is None:
        raise ConflictError("active binding disappeared while recording evidence")
    binding_expires = str(active["expires_at"] or "")
    evidence_expires = binding_expires or (
        datetime.now(UTC).replace(microsecond=0) + timedelta(days=90)
    ).isoformat()
    evidence = {
        "binding_id": binding_id,
        "key_thumbprint": key_thumbprint,
        "runtime_origin": runtime_origin,
        "a2a_endpoint": a2a_endpoint,
        "issuer_kid": str(os.environ.get("KIWI_CATALOG_ISSUER_KID") or ""),
        "exp": evidence_expires,
    }
    for verification_type in ("agent_identity", "commerce_capability"):
        insert_verification(
            conn, catalog_agent_id=catalog_agent_id, verification_type=verification_type,
            result="passed", evidence_json=json.dumps(evidence, ensure_ascii=False),
            checked_at=checked_at, expires_at=evidence_expires,
        )
    # For hosted runtimes, merchant authorization plus proof of key/origin
    # control is the evidence path; domain-control steps do not apply.
    set_state_domains(
        conn, catalog_agent_id, verification_level="commerce_verified",
        freshness_state="fresh", last_verified_at=checked_at,
    )
    return evidence_expires


def _expire_stale(conn: sqlite3.Connection, catalog_agent_id: str, now: str) -> None:
    """惰性过期：过 TTL 的 pending 行标 expired（此后视为不存在）。"""
    conn.execute(
        "update runtime_binding_requests set status = 'expired', decided_at = ?"
        " where catalog_agent_id = ? and status = 'pending' and expires_at <= ?",
        (now, catalog_agent_id, now),
    )


def create_request(
    conn: sqlite3.Connection,
    *,
    agent: sqlite3.Row,
    binding: dict[str, Any],
    key_jwk: dict[str, Any],
    thumbprint: str,
    signed_payload: dict[str, Any],
) -> dict[str, Any]:
    """落一条待确认接入请求（首绑分支；闸门已在 handler 全部通过）。

    顺序：惰性过期 → 未决上限 → **消费 nonce**（全部校验通过后才消费——无效
    请求不得烧掉合法请求的 nonce，与 verify_runtime_request 同一纪律）→ 插行
    → 审计 ``runtime_binding_requested``。邮件通知由 handler 在事务提交后发
    （旁路）。
    """
    agent_id = str(agent["catalog_agent_id"])
    now = now_iso()
    _expire_stale(conn, agent_id, now)
    pending_count = conn.execute(
        "select count(*) from runtime_binding_requests"
        " where catalog_agent_id = ? and status = 'pending'",
        (agent_id,),
    ).fetchone()[0]
    if int(pending_count) >= max_pending():
        raise ConflictError(f"too many pending binding requests (max {max_pending()})")
    nonce = signed_payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ValidationError("request signature missing nonce")
    from kiwi_catalog.a2a.request_signature import consume_request_nonce

    consume_request_nonce(
        conn,
        key_id=str(binding["key_id"]),
        nonce=nonce,
        issued_at=str(signed_payload.get("issued_at", "")),
    )
    request_id = new_binding_request_id()
    expires_at = (
        datetime.now(UTC).replace(microsecond=0) + timedelta(hours=ttl_hours())
    ).isoformat()
    conn.execute(
        "insert into runtime_binding_requests"
        " (binding_request_id, catalog_agent_id, merchant_id, runtime_origin, a2a_endpoint,"
        " key_id, key_thumbprint, key_jwk_json, generation, service_epoch, nonce,"
        " status, requested_at, expires_at)"
        " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
        (
            request_id,
            agent_id,
            str(agent["merchant_id"] or ""),
            str(binding["runtime_origin"]),
            str(binding["a2a_endpoint"]),
            str(binding["key_id"]),
            thumbprint,
            json.dumps(key_jwk),
            int(binding["generation"]),
            int(binding["service_epoch"]),
            nonce,
            now,
            expires_at,
        ),
    )
    append_catalog_audit(
        conn,
        catalog_agent_id=agent_id,
        actor=f"possession:{binding['key_id']}",
        event="runtime_binding_requested",
        details={
            "binding_request_id": request_id,
            "runtime_origin": str(binding["runtime_origin"]),
            "key_thumbprint": thumbprint,
            "expires_at": expires_at,
        },
    )
    return {
        "status": "pending_confirmation",
        "message": "绑定请求已记录，待商家在门户确认后生效",
        "binding_request_id": request_id,
        "catalog_agent_id": agent_id,
        "merchant_id": str(agent["merchant_id"] or ""),
        "runtime_origin": str(binding["runtime_origin"]),
        "a2a_endpoint": str(binding["a2a_endpoint"]),
        "key_thumbprint": thumbprint,
        "expires_at": expires_at,
        # 公开轮询入口：确认前该地址仍 404（Catalog 未背书）
        "poll_url": f"/v1/agents/{agent_id}/runtime-binding",
    }


def _request_item(row: sqlite3.Row) -> dict[str, Any]:
    """待确认请求的展示投影（含门户确认页需要的分辨信息）。"""
    thumbprint = str(row["key_thumbprint"])
    return {
        "binding_request_id": str(row["binding_request_id"]),
        "runtime_origin": str(row["runtime_origin"]),
        "a2a_endpoint": str(row["a2a_endpoint"]),
        "key_id": str(row["key_id"]),
        "key_thumbprint": thumbprint,
        "key_thumbprint_short": thumbprint[:16],
        "generation": int(row["generation"]),
        "service_epoch": int(row["service_epoch"]),
        "requested_at": str(row["requested_at"]),
        "expires_at": str(row["expires_at"]),
    }


def pending_request_items(conn: sqlite3.Connection, catalog_agent_id: str) -> list[dict[str, Any]]:
    """未决请求列表（惰性过期后；按请求时间倒序）。"""
    _expire_stale(conn, catalog_agent_id, now_iso())
    rows = conn.execute(
        "select * from runtime_binding_requests"
        " where catalog_agent_id = ? and status = 'pending'"
        " order by requested_at desc",
        (catalog_agent_id,),
    ).fetchall()
    return [_request_item(row) for row in rows]


def list_pending_requests(
    conn: sqlite3.Connection, account: dict[str, Any], catalog_agent_id: str
) -> dict[str, Any]:
    """GET 待确认请求列表（归属检查：非本商家 404）。"""
    row = _require_owned_agent(conn, account, catalog_agent_id)
    return {"ok": True, "results": pending_request_items(conn, str(row["catalog_agent_id"]))}


def _load_pending_request(
    conn: sqlite3.Connection, agent_id: str, request_id: str, now: str
) -> sqlite3.Row:
    """取未决请求：不存在/已过期（惰性标记后）→ 404；已决 → 409。"""
    _expire_stale(conn, agent_id, now)
    req = conn.execute(
        "select * from runtime_binding_requests"
        " where binding_request_id = ? and catalog_agent_id = ?",
        (str(request_id or "").strip(), agent_id),
    ).fetchone()
    if req is None or str(req["status"]) == "expired":
        raise NotFoundError("binding request not found")
    if str(req["status"]) != "pending":
        raise ConflictError(f"binding request already {req['status']}")
    return req


def confirm_request(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    catalog_agent_id: str,
    request_id: str,
) -> dict[str, Any]:
    """商家确认接入（D1）：**同一事务**完成全部副作用。

    校验未决+归属+未过期 → 写 ``runtime_bindings``（active，binding_version =
    现有最大值 +1；若竞态下已有 active 绑定则按轮换语义置 revoked，保住
    「一次只有一个 active」不变量）→ 消费请求行 → 同行其他 pending 失效
    （§10「确认后旧请求即失效」）→ D2 回填 canonical_domain（仅当为空，
    不覆盖 direct 商家已有域名）→ §4.5 同步 a2a 端点行 → D5 写两条
    passed 证据行（绑定声明即证据）→ 审计。
    """
    row = _require_owned_agent(conn, account, catalog_agent_id)
    agent_id = str(row["catalog_agent_id"])
    merchant_id = str(row["merchant_id"] or "").strip()
    now = now_iso()
    req = _load_pending_request(conn, agent_id, request_id, now)
    max_row = conn.execute(
        "select max(binding_version) as v from runtime_bindings where catalog_agent_id = ?",
        (agent_id,),
    ).fetchone()
    version = int(max_row["v"] or 0) + 1
    binding_id = f"bind_{agent_id[-8:]}_{version}"
    if conn.execute(
        "select 1 from runtime_bindings where binding_id = ?", (binding_id,)
    ).fetchone():
        raise ConflictError(f"binding_id already exists: {binding_id}")
    active = conn.execute(
        "select binding_id from runtime_bindings where catalog_agent_id = ? and status = 'active'",
        (agent_id,),
    ).fetchone()
    conn.execute(
        "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
        " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
        " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
        " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', '', ?, ?)",
        (
            binding_id,
            agent_id,
            merchant_id,
            str(req["runtime_origin"]),
            str(req["a2a_endpoint"]),
            str(req["key_id"]),
            str(req["key_thumbprint"]),
            str(req["key_jwk_json"]),
            version,
            int(req["service_epoch"]),
            now,
            now,
        ),
    )
    if active is not None:
        conn.execute(
            "update runtime_bindings set status = 'revoked', updated_at = ? where binding_id = ?",
            (now, str(active["binding_id"])),
        )
    conn.execute(
        "update runtime_binding_requests set status = 'confirmed', decided_at = ?"
        " where binding_request_id = ?",
        (now, request_id),
    )
    conn.execute(
        "update runtime_binding_requests set status = 'expired', decided_at = ?, decided_note = ?"
        " where catalog_agent_id = ? and status = 'pending'",
        (now, f"superseded by confirmed request {request_id}", agent_id),
    )
    # D2：回填 canonical_domain = runtime_origin 的 canonical host（仅当为空）。
    canonical = str(row["canonical_domain"] or "").strip()
    if not canonical:
        canonical = canonical_domain_of(str(req["runtime_origin"]))
        conn.execute(
            "update catalog_agents set canonical_domain = ?, updated_at = ?"
            " where catalog_agent_id = ?",
            (canonical, now, agent_id),
        )
    # §4.5：绑定确认 → 同事务写 a2a 端点行（此时通常还没有卡，不写 agent_card 行）。
    from kiwi_catalog.services.agent_endpoints import sync_cloud_endpoints

    sync_cloud_endpoints(conn, agent_id, now)
    # D5：绑定声明即证据——写两条 passed 证据行（agent_identity +
    # commerce_capability），此后任何一次级别重算都停在 commerce_verified，
    # reducer 无需特例。expires_at 取绑定到期时间；绑定无到期给 90 天窗口，
    # 由「重新确认 / 轮换 / 心跳」续期。
    record_active_binding_evidence(
        conn, catalog_agent_id=agent_id, binding_id=binding_id,
        key_thumbprint=str(req["key_thumbprint"]), runtime_origin=str(req["runtime_origin"]),
        a2a_endpoint=str(req["a2a_endpoint"]), checked_at=now,
    )
    append_catalog_audit(
        conn,
        catalog_agent_id=agent_id,
        actor=f"merchant:{merchant_id}",
        event="runtime_binding_confirmed",
        details={
            "binding_id": binding_id,
            "binding_version": version,
            "binding_request_id": request_id,
            "key_thumbprint": str(req["key_thumbprint"]),
        },
    )
    return {
        "ok": True,
        "status": "active",
        "binding_id": binding_id,
        "binding_version": version,
        "canonical_domain": canonical,
    }


def reject_request(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    catalog_agent_id: str,
    request_id: str,
    *,
    note: str,
) -> dict[str, Any]:
    """商家拒绝接入：带理由标记 rejected 留痕 + 审计（不删行）。"""
    row = _require_owned_agent(conn, account, catalog_agent_id)
    note = str(note or "").strip()
    if not note:
        raise ValidationError("decision note is required")
    agent_id = str(row["catalog_agent_id"])
    merchant_id = str(row["merchant_id"] or "").strip()
    now = now_iso()
    _load_pending_request(conn, agent_id, request_id, now)
    conn.execute(
        "update runtime_binding_requests set status = 'rejected', decided_at = ?, decided_note = ?"
        " where binding_request_id = ?",
        (now, note[:500], request_id),
    )
    append_catalog_audit(
        conn,
        catalog_agent_id=agent_id,
        actor=f"merchant:{merchant_id}",
        event="runtime_binding_rejected",
        details={"binding_request_id": request_id, "note": note[:500]},
    )
    return {"ok": True, "status": "rejected", "binding_request_id": request_id}
