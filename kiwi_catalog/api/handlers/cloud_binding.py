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

"""Runtime 绑定与绑定声明（M3；设计 §11.2/§11.4/§11.6）。

    POST /v1/agents/{id}/runtime-bindings                → 创建/轮换绑定（持钥证明）
    POST /v1/agents/{id}/runtime-bindings/{bid}/revoke   → 撤销绑定
    GET  /v1/agents/{id}/runtime-binding                 → 公开读：Catalog 签发的声明 + 治理状态

授权模型（如实记录）：

- **首次绑定**：请求由 Runtime 私钥签名（请求体自带公钥）——证明持钥；另需
  **管理员凭据**（`admin_token`）作为"受控注册"闸门。M4 的开通向导/一次性配对落地后，
  闸门将换成商家授权 + 端点挑战（设计 §6.3），本接口形状保持不变。
- **轮换绑定**：必须由**当前活动绑定**的私钥签名（或管理员）。
- 撤销：同上（当前活动绑定私钥或管理员）；撤销后签发立即停止（声明读取会拒签）。

声明读取不含平台 applicationId、用户 ID 等控制面私有信息。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint, read_runtime_binding
from kiwi_catalog.a2a.endpoint_policy import assert_safe_binding_targets
from kiwi_catalog.a2a.public_read_limit import enforce_public_read_limit
from kiwi_catalog.a2a.request_signature import verify_binding_possession, verify_runtime_request
from kiwi_catalog.agent_catalog.catalog_audit import append_catalog_audit
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.api.auth import AuthError
from kiwi_catalog.core.errors import (
    ConflictError,
    NotFoundError,
    ValidationError,
)
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import merchant_tokens as tokens_service

SIGNATURE_HEADER = "x-kiwi-binding-jws"


def read_runtime_binding_document(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    """GET /v1/agents/{id}/runtime-binding —— 公开读，**按客户端 IP 限流**（计划 B3）。

    每次读取都要做一次 Ed25519 签名，因此这一侧的限流不是可选项：不限流等于把
    Catalog 的私钥运算开放给任何匿名来源。
    """
    with db_session(db_path) as conn:
        enforce_public_read_limit(conn, payload, surface="runtime-binding read")
        return read_runtime_binding(conn, str(catalog_agent_id or "").strip())


def read_management_descriptor(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/cloud-enrollments/{id}/management-descriptor（BD §6.3）。

    **私有只读绑定对象**：给已认证的商家入口提供"我这台 Runtime 的管理页在哪"。
    三条纪律：

    1. **归属鉴权**：商家 owner token 解析出的 merchant_id 必须与绑定的 merchant_id
       一致；不一致一律 **404**（与"不存在"不可区分，避免枚举他人 agent）。
    2. **绝不含凭据**：只有绑定元数据——Token/Cookie/平台密钥/商家私钥/底价都不在
       这里，也永远不该出现在这里。它不是认证凭据：打开地址本身不授予管理权限。
    3. **未声明即拒**：运行时没在绑定里声明管理面元数据 → **409**，绝不用 Catalog
       的默认值伪造一个地址（那会把商家导到错的地方，且看起来"能用"）。
    """
    agent_id = str(catalog_agent_id or "").strip()
    # 凭据只从 Authorization header 注入的 payload 读取；不接受 URL query，避免
    # token 进入访问日志、代理缓存和浏览器历史。
    presented = str(payload.get("_auth_token") or "").strip()
    # 仅兼容本地 fallback ASGI 的旧调用约定；生产 FastAPI 路由不设置该标记，
    # 因而不会从 URL 读取凭据。
    if not presented and payload.get("_allow_query_owner_token") is True:
        presented = str(query.get("owner_token") or "").strip()
    if not presented:
        raise AuthError("invalid owner token")
    with db_session(db_path) as conn:
        token_row = tokens_service.resolve_merchant_by_token(conn, presented)
        if token_row is None:
            raise AuthError("invalid owner token")
        merchant_id = str(token_row["merchant_id"])

        binding = conn.execute(
            "select * from runtime_bindings where catalog_agent_id = ? and status = 'active'"
            " order by binding_version desc limit 1",
            (agent_id,),
        ).fetchone()
        # 不存在 / 不属本商家 / 无活动绑定：统一 404（不可区分）
        if binding is None or str(binding["merchant_id"]) != merchant_id:
            raise NotFoundError("management descriptor not found")

        base_path = str(binding["management_base_path"] or "")
        api_major = int(binding["management_api_major"] or 0)
        if base_path == "" or api_major < 1:
            raise ConflictError(
                "runtime has not declared management metadata for this binding"
            )

        descriptor: dict[str, Any] = {
            "binding_ref": str(binding["binding_id"]),
            "merchant_id": merchant_id,
            "agent_id": agent_id,
            "runtime_origin": str(binding["runtime_origin"]),
            "management_base_path": base_path,
            "binding_version": int(binding["binding_version"]),
            "deployment_generation": int(binding["service_epoch"]),
            "status": str(binding["status"]),
            "expires_at": str(binding["expires_at"] or ""),
            "management_api_major": api_major,
        }
        # 可选 MCP 路径：B07 通过前运行时不声明，这里就不返回（schema 里是可选字段）。
        mcp_path = str(binding["mcp_path"] or "")
        if mcp_path != "":
            descriptor["mcp_path"] = mcp_path
        # 绑定未设到期时间时，descriptor 的 expires_at 需是合法 date-time；
        # 用"长期有效"的表达而不是空串（空串过不了 schema，也会让入口误判过期）。
        if descriptor["expires_at"] == "":
            descriptor["expires_at"] = "9999-12-31T00:00:00+00:00"
        return descriptor


def _binding_required(payload: dict[str, Any]) -> dict[str, Any]:
    binding = payload.get("binding")
    if not isinstance(binding, dict):
        raise ValidationError("binding must be a JSON object")
    for field in ("runtime_origin", "a2a_endpoint", "key_jwk", "key_id"):
        if not binding.get(field):
            raise ValidationError(f"binding.{field} is required")
    key_jwk = binding.get("key_jwk")
    if not isinstance(key_jwk, dict):
        raise ValidationError("binding.key_jwk must be a JWK object")
    # T035：绑定声明会被 Catalog 原样交给 Buyer（并经 Catalog 签名背书），
    # 因此私网 / loopback / cloud metadata / 保留主机名等危险目标在这里就拒绝，
    # 绝不进入签发链路。DNS 解析到内网的情形由连接时复查兜底（见 endpoint_policy）。
    assert_safe_binding_targets(binding)
    if not isinstance(binding.get("generation"), int):
        raise ValidationError("binding.generation must be an integer")
    if not isinstance(binding.get("service_epoch"), int):
        raise ValidationError("binding.service_epoch must be an integer")
    return binding


def _management_declaration(binding: dict[str, Any]) -> dict[str, Any]:
    """运行时在绑定里声明的**管理面元数据**（BD §6.3）。

    为什么必须由运行时声明、而不是 Catalog 猜：门户要拿它导航到管理页；猜一个
    "/merchant/" 等于把"约定"当"事实"，一旦运行时换了基路径就会把商家导到错的地方。
    未声明 → 描述符端点 409（fail-closed），绝不用默认值伪造。

    可选字段：老运行时（M3 形态）不带它，绑定仍然成立，只是描述符不可用。
    """
    raw = binding.get("management")
    if raw is None:
        return {"management_base_path": "", "management_api_major": 0, "mcp_path": ""}
    if not isinstance(raw, dict):
        raise ValidationError("binding.management must be a JSON object")
    base_path = _safe_management_path(raw.get("base_path"), field="management.base_path")
    mcp_path = _safe_management_path(raw.get("mcp_path"), field="management.mcp_path")
    api_major = raw.get("api_major")
    if not isinstance(api_major, int) or isinstance(api_major, bool) or api_major < 1:
        raise ValidationError("binding.management.api_major must be a positive integer")
    return {
        "management_base_path": base_path,
        "management_api_major": api_major,
        "mcp_path": mcp_path,
    }


def _safe_management_path(value: Any, *, field: str) -> str:
    """管理路径必须是**规范化绝对路径**：防目录穿越与重定向到别处。"""
    if value is None or value == "":
        return ""
    text = str(value).strip()
    if not text.startswith("/"):
        raise ValidationError(f"binding.{field} must start with /")
    if ".." in text or "//" in text or "?" in text or "#" in text:
        raise ValidationError(f"binding.{field} must be a normalized absolute path")
    if len(text) > 64:
        raise ValidationError(f"binding.{field} is too long")
    return text


def _current_active_binding(conn, catalog_agent_id: str):
    return conn.execute(
        "select * from runtime_bindings where catalog_agent_id = ? and status = 'active'"
        " order by binding_version desc limit 1",
        (catalog_agent_id,),
    ).fetchone()


def _insert_active_binding(
    conn: Any,
    *,
    agent: Any,
    binding: dict[str, Any],
    key_jwk: dict[str, Any],
    thumbprint: str,
    management: dict[str, Any],
    existing: Any,
    actor: str,
) -> dict[str, Any]:
    """落 active 绑定（首绑的 admin 兜底 / 轮换共用）：version 前进 + 旧绑定失效 + 审计。"""
    agent_id = str(agent["catalog_agent_id"])
    version = int(existing["binding_version"]) + 1 if existing is not None else 1
    binding_id = str(binding.get("binding_id") or f"bind_{agent_id[-8:]}_{version}")
    if conn.execute(
        "select 1 from runtime_bindings where binding_id = ?", (binding_id,)
    ).fetchone():
        raise ConflictError(f"binding_id already exists: {binding_id}")
    stamp = now_iso()
    conn.execute(
        "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
        " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
        " binding_version, service_epoch, status, expires_at, created_at, updated_at,"
        " management_base_path, management_api_major, mcp_path)"
        " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)",
        (
            binding_id,
            agent_id,
            str(agent["merchant_id"] or ""),
            str(binding["runtime_origin"]),
            str(binding["a2a_endpoint"]),
            str(binding["key_id"]),
            thumbprint,
            json.dumps(key_jwk),
            version,
            int(binding["service_epoch"]),
            str(binding.get("expires_at") or ""),
            stamp,
            stamp,
            management["management_base_path"],
            management["management_api_major"],
            management["mcp_path"],
        ),
    )
    if existing is not None:
        # 轮换：旧绑定立即失效（旧私钥不能再签发布/轮换请求）。
        conn.execute(
            "update runtime_bindings set status = 'revoked', updated_at = ? where binding_id = ?",
            (stamp, str(existing["binding_id"])),
        )
    # §4.5：轮换后 a2a 端点行指向新绑定（同事务、幂等）。
    from kiwi_catalog.services.agent_endpoints import sync_cloud_endpoints

    sync_cloud_endpoints(conn, agent_id, stamp)
    append_catalog_audit(
        conn,
        catalog_agent_id=agent_id,
        actor=actor,
        event="runtime_binding_created",
        details={"binding_id": binding_id, "binding_version": version, "key_thumbprint": thumbprint},
    )
    return {
        "binding_id": binding_id,
        "binding_version": version,
        "key_thumbprint": thumbprint,
        "superseded_binding_id": str(existing["binding_id"]) if existing is not None else None,
    }


def create_runtime_binding(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """创建或轮换 Runtime 绑定（持钥证明 + 受控闸门）。

    **首次绑定（D1，设计 §4.3③）**：不再要求 admin token——既有闸门
    （endpoint_policy → 持钥证明 → nonce 防重放）全部通过后落一条
    **待确认接入请求**（runtime_binding_requests），由商家在门户确认后才
    签发 active 绑定；确认前公开读 /runtime-binding 仍 404，Catalog 不提前
    背书。admin token + 持钥证明仍可直接落 active 绑定（运维兜底，旧语义）。
    **轮换**（已有 active 绑定）不受影响：现役私钥签或 admin。
    """
    agent_id = str(catalog_agent_id or "").strip()
    if payload.get("enrollment_id"):
        return _create_enrollment_binding(db_path, agent_id, payload)
    binding = _binding_required(payload)
    jws = str(payload.get("_binding_jws") or "").strip()
    if not jws:
        raise ValidationError(f"missing request signature header ({SIGNATURE_HEADER})")
    key_jwk = dict(binding["key_jwk"])
    thumbprint = jwk_thumbprint(key_jwk)
    management = _management_declaration(binding)
    signed_fields = {
        "agent_id": agent_id,
        "key_id": str(binding["key_id"]),
        "key_thumbprint": thumbprint,
        "runtime_origin": str(binding["runtime_origin"]),
        "a2a_endpoint": str(binding["a2a_endpoint"]),
        "generation": int(binding["generation"]),
        "service_epoch": int(binding["service_epoch"]),
    }
    notify_request: dict[str, Any] | None = None
    with db_session(db_path) as conn:
        agent = conn.execute(
            "select * from catalog_agents where catalog_agent_id = ?", (agent_id,)
        ).fetchone()
        if agent is None:
            raise NotFoundError("catalog agent not found")
        existing = _current_active_binding(conn, agent_id)
        if existing is None:
            # 首次绑定：持钥证明（闸门不变）。
            possession = verify_binding_possession(
                jws=jws, public_jwk=key_jwk, expected_fields=signed_fields
            )
            admin_token = str(payload.get("admin_token") or "")
            if not (admin_token and api_auth.admin_token_matches(admin_token, conn)):
                # D1：落「待确认接入请求」（不写 active 绑定，不提前背书）
                from kiwi_catalog.services import binding_requests as binding_requests_service

                result = binding_requests_service.create_request(
                    conn,
                    agent=agent,
                    binding=binding,
                    key_jwk=key_jwk,
                    thumbprint=thumbprint,
                    signed_payload=possession,
                )
                notify_request = result
            else:
                # 运维兜底：admin + 持钥证明直接落 active 绑定（旧语义保留）。
                result = _insert_active_binding(
                    conn,
                    agent=agent,
                    binding=binding,
                    key_jwk=key_jwk,
                    thumbprint=thumbprint,
                    management=management,
                    existing=None,
                    actor=f"admin+possession:{binding['key_id']}",
                )
        else:
            # 轮换：必须由**当前活动绑定**的私钥签名（或管理员）。
            admin_token = str(payload.get("admin_token") or "")
            is_admin = bool(admin_token) and api_auth.admin_token_matches(admin_token, conn)
            if is_admin:
                verify_binding_possession(
                    jws=jws, public_jwk=key_jwk, expected_fields=signed_fields
                )
                actor = f"admin+possession:{binding['key_id']}"
            else:
                verify_runtime_request(
                    conn,
                    catalog_agent_id=agent_id,
                    jws=jws,
                    expected_fields={
                        **signed_fields,
                        # 授权这次轮换的**当前活动绑定**（签名必须覆盖它）。
                        "binding_id": str(existing["binding_id"]),
                    },
                )
                actor = f"runtime:{existing['binding_id']}"
            result = _insert_active_binding(
                conn,
                agent=agent,
                binding=binding,
                key_jwk=key_jwk,
                thumbprint=thumbprint,
                management=management,
                existing=existing,
                actor=actor,
            )
    if notify_request is not None:
        # 邮件通知运营（D1）：旁路——必须在事务提交之后，发信失败不影响请求。
        from kiwi_catalog.services import accounts as accounts_service

        accounts_service.notify_admin_binding_request(
            merchant_id=str(notify_request["merchant_id"]),
            catalog_agent_id=agent_id,
            binding_request_id=str(notify_request["binding_request_id"]),
            runtime_origin=str(notify_request["runtime_origin"]),
            a2a_endpoint=str(notify_request["a2a_endpoint"]),
            key_thumbprint=str(notify_request["key_thumbprint"]),
            expires_at=str(notify_request["expires_at"]),
        )
    return result


def _create_enrollment_binding(db_path: str | Path, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """持 enrollment grant + 完整请求签名 + 外部端点挑战自动首绑。"""
    import hashlib
    import secrets
    from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
    from kiwi_catalog.a2a.request_signature import consume_request_nonce
    from kiwi_catalog.discovery.fetcher import FetchError, ProfileFetcher
    from kiwi_catalog.discovery.trust import TrustPolicy
    from kiwi_catalog.core.errors import PermissionDenied
    from kiwi_catalog.services.enrollments import validate_public_jwk

    binding = _binding_required(payload)
    if not isinstance(binding.get("key_id"), str) or not binding["key_id"].strip():
        raise ValidationError("binding.key_id must be a non-empty string")
    for field in ("runtime_origin", "a2a_endpoint"):
        if not isinstance(binding.get(field), str) or not binding[field].strip():
            raise ValidationError(f"binding.{field} must be a non-empty string")
    enrollment_id, grant = str(payload.get("enrollment_id") or ""), str(payload.get("grant") or "")
    jws = str(payload.get("_binding_jws") or "")
    if not enrollment_id or not grant or not jws:
        raise ValidationError("enrollment_id, grant and x-kiwi-binding-jws are required")
    body = {k: v for k, v in payload.items() if not str(k).startswith("_")}
    with db_session(db_path) as conn:
        row = conn.execute("select * from enrollments where enrollment_id=?", (enrollment_id,)).fetchone()
        agent = conn.execute("select * from catalog_agents where catalog_agent_id=?", (agent_id,)).fetchone()
        if row is None or agent is None or row["catalog_agent_id"] != agent_id:
            raise NotFoundError("enrollment not found")
        if row["status"] not in ("authorized", "bound") or (row["status"] == "authorized" and row["grant_expires_at"] <= now_iso()):
            raise PermissionDenied("enrollment grant is expired or unavailable")
        if hashlib.sha256(grant.encode()).hexdigest() != row["grant_hash"]:
            raise PermissionDenied("invalid enrollment grant")
        if row["merchant_id"] != agent["merchant_id"] or str(binding["runtime_origin"]) != row["runtime_origin"] or str(binding["a2a_endpoint"]) != row["a2a_endpoint"]:
            raise PermissionDenied("binding material does not match approved enrollment")
        thumb = validate_public_jwk(dict(binding["key_jwk"]))
        if thumb != row["key_thumbprint"] or str(binding["key_id"]) != row["key_id"]:
            raise PermissionDenied("binding key does not match approved enrollment")
        if int(binding["generation"]) != int(row["generation"]) or int(binding["service_epoch"]) != int(row["service_epoch"]):
            raise PermissionDenied("binding generation does not match approved enrollment")
        if "runtime:bind" not in json.loads(row["scopes_json"]):
            raise PermissionDenied("enrollment grant does not include runtime:bind")
        signed = verify_binding_possession(jws=jws, public_jwk=json.loads(row["key_jwk_json"]), expected_fields={
            "method": "POST", "path": f"/v1/agents/{agent_id}/runtime-bindings", "audience": "kiwi-catalog",
            "body_digest": canonical_digest(body), "enrollment_id": enrollment_id,
            "grant_hash": hashlib.sha256(grant.encode()).hexdigest(), "catalog_agent_id": agent_id,
            "key_id": row["key_id"],
            "key_thumbprint": thumb, "runtime_origin": row["runtime_origin"], "a2a_endpoint": row["a2a_endpoint"],
            "generation": int(binding["generation"]), "service_epoch": int(binding["service_epoch"]),
            "authorization_epoch": int(row["authorization_epoch"]),
        })
        _check_enrollment_exp(signed)
        consume_request_nonce(conn, key_id=str(row["key_id"]), nonce=str(signed.get("nonce", "")), issued_at=str(signed.get("issued_at", "")))
        if row["status"] == "bound" and row["binding_id"]:
            active = conn.execute("select status from runtime_bindings where binding_id=?", (row["binding_id"],)).fetchone()
            if active is None or active["status"] != "active" or agent["administrative_state"] != "active":
                raise PermissionDenied("bound enrollment is no longer active")
            return _enrollment_binding_result(conn, agent_id, row)
        challenge = secrets.token_urlsafe(32)
        origin = str(row["runtime_origin"]).rstrip("/")
        challenge_request = {"enrollment_id": enrollment_id, "challenge": challenge, "origin": origin,
            "key_thumbprint": thumb, "audience": "kiwi-catalog", "issued_at": now_iso(),
            "expires_at": (datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=60)).isoformat()}
    # Network challenge outside SQL transaction. ProfileFetcher pins verified public IP, bounds body and rejects redirects.
    try:
        result = ProfileFetcher(TrustPolicy.defaults(), timeout=5).post_json(
            origin + "/.well-known/kiwi-binding-challenge", challenge_request, timeout=5)
    except FetchError as exc:
        raise ConflictError("runtime endpoint challenge failed; retry when the public HTTPS service is reachable") from exc
    if result.status_code != 200:
        raise PermissionDenied("runtime endpoint challenge failed")
    try:
        response = json.loads(result.body)
    except (ValueError, TypeError) as exc:
        raise PermissionDenied("runtime endpoint challenge returned invalid JSON") from exc
    if not isinstance(response, dict) or set(response) != {"enrollment_id", "challenge", "origin", "key_thumbprint", "audience", "issued_at", "expires_at", "key_id", "signature"}:
        raise PermissionDenied("runtime endpoint challenge response shape is invalid")
    for key, value in challenge_request.items():
        if response.get(key) != value:
            raise PermissionDenied("runtime endpoint challenge response mismatch")
    if datetime.fromisoformat(str(challenge_request["expires_at"])) <= datetime.now(UTC):
        raise PermissionDenied("runtime endpoint challenge expired")
    verify_binding_possession(jws=str(response["signature"]), public_jwk=json.loads(row["key_jwk_json"]), expected_fields={
        **{k: response[k] for k in challenge_request}, "key_id": row["key_id"], "purpose": "kiwi-binding-challenge"})
    challenge_jws_payload = _read_jws_payload(str(response["signature"]))
    _check_enrollment_exp({**challenge_jws_payload, "exp": response["expires_at"]})
    with db_session(db_path) as conn:
        row = conn.execute("select * from enrollments where enrollment_id=?", (enrollment_id,)).fetchone()
        agent = conn.execute("select * from catalog_agents where catalog_agent_id=?", (agent_id,)).fetchone()
        if datetime.fromisoformat(str(challenge_request["expires_at"])) <= datetime.now(UTC):
            raise PermissionDenied("runtime endpoint challenge expired")
        if row is None or row["status"] != "authorized" or row["grant_expires_at"] <= now_iso() or row["merchant_id"] != agent["merchant_id"] or agent["administrative_state"] != "active":
            raise PermissionDenied("enrollment authorization changed during endpoint challenge")
        if hashlib.sha256(grant.encode()).hexdigest() != row["grant_hash"] or int(binding["generation"]) != int(row["generation"]) or int(binding["service_epoch"]) != int(row["service_epoch"]) or "runtime:bind" not in json.loads(row["scopes_json"]):
            raise PermissionDenied("enrollment grant changed during endpoint challenge")
        consume_request_nonce(conn, key_id=str(row["key_id"]), nonce=str(challenge_jws_payload.get("nonce", "")), issued_at=str(challenge_jws_payload.get("issued_at", "")))
        version = int(conn.execute("select coalesce(max(binding_version),0)+1 from runtime_bindings where catalog_agent_id=?", (agent_id,)).fetchone()[0])
        if version != int(row["expected_binding_version"]):
            raise ConflictError("binding version changed since enrollment authorization")
        outcome = _insert_active_binding(conn, agent=agent, binding=binding, key_jwk=dict(binding["key_jwk"]),
            thumbprint=thumb, management=_management_declaration(binding), existing=_current_active_binding(conn, agent_id), actor=f"enrollment:{enrollment_id}")
        changed = conn.execute("update enrollments set status='bound',binding_id=?,consumed_at=? where enrollment_id=? and status='authorized'",
                               (outcome["binding_id"], now_iso(), enrollment_id)).rowcount
        if changed != 1:
            raise ConflictError("enrollment grant was concurrently consumed")
        from kiwi_catalog.discovery._validation import canonical_domain_of
        conn.execute("update catalog_agents set canonical_domain=?, updated_at=? where catalog_agent_id=?",
                     (canonical_domain_of(str(row["runtime_origin"])), now_iso(), agent_id))
        from kiwi_catalog.services.binding_requests import record_active_binding_evidence
        record_active_binding_evidence(
            conn, catalog_agent_id=agent_id, binding_id=str(outcome["binding_id"]),
            key_thumbprint=thumb, runtime_origin=str(row["runtime_origin"]),
            a2a_endpoint=str(row["a2a_endpoint"]), checked_at=now_iso(),
        )
        return _enrollment_binding_result(conn, agent_id, conn.execute("select * from enrollments where enrollment_id=?", (enrollment_id,)).fetchone(), outcome)


def _check_enrollment_exp(signed: dict[str, Any]) -> None:
    try:
        expires = datetime.fromisoformat(str(signed.get("exp", "")))
        if expires.tzinfo is None or expires <= datetime.now(UTC) or expires > datetime.now(UTC) + timedelta(minutes=2):
            raise ValidationError("request signature expired or has excessive lifetime")
    except ValueError as exc:
        raise ValidationError("request signature exp is missing or malformed") from exc


def _read_jws_payload(jws: str) -> dict[str, Any]:
    import base64
    try:
        segment = jws.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except Exception as exc:
        raise ValidationError("malformed possession JWS") from exc


def _enrollment_binding_result(conn: Any, agent_id: str, row: Any, outcome: dict[str, Any] | None = None) -> dict[str, Any]:
    binding_id = str(row["binding_id"])
    binding = conn.execute("select * from runtime_bindings where binding_id=?", (binding_id,)).fetchone()
    from kiwi_catalog.a2a.binding_claims import read_runtime_binding
    declaration = read_runtime_binding(conn, agent_id)
    return {"status": "bound", "enrollment_id": row["enrollment_id"], "binding_id": binding_id,
        "binding_version": int(binding["binding_version"]), "key_thumbprint": row["key_thumbprint"],
        "catalog_agent_id": agent_id, "binding_claim": declaration,
        "superseded_binding_id": (outcome or {}).get("superseded_binding_id")}


def revoke_runtime_binding(
    db_path: str | Path, catalog_agent_id: str, binding_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """撤销绑定（当前活动绑定私钥或管理员）。撤销后声明签发立即停止。"""
    agent_id = str(catalog_agent_id or "").strip()
    target = str(binding_id or "").strip()
    jws = str(payload.get("_binding_jws") or "").strip()
    with db_session(db_path) as conn:
        row = conn.execute(
            "select * from runtime_bindings where catalog_agent_id = ? and binding_id = ?",
            (agent_id, target),
        ).fetchone()
        if row is None:
            raise NotFoundError("runtime binding not found")
        if str(row["status"]) == "revoked":
            return {"binding_id": target, "status": "revoked", "changed": False}
        admin_token = str(payload.get("admin_token") or "")
        is_admin = bool(admin_token) and api_auth.admin_token_matches(admin_token, conn)
        if is_admin:
            actor = "admin"
        else:
            if not jws:
                raise ValidationError(f"missing request signature header ({SIGNATURE_HEADER})")
            verify_runtime_request(
                conn,
                catalog_agent_id=agent_id,
                jws=jws,
                expected_fields={
                    "agent_id": agent_id,
                    "binding_id": target,
                    "publication_state": "REVOKED",
                },
            )
            actor = "runtime"
        conn.execute(
            "update runtime_bindings set status = 'revoked', updated_at = ? where binding_id = ?",
            (now_iso(), target),
        )
        # §4.5：撤销后同步端点行——无其他活动绑定时 a2a 与 agent_card 行一并
        # 删除（不再可被发现）；admin 撤销同路（同一函数）。
        from kiwi_catalog.services.agent_endpoints import sync_cloud_endpoints

        sync_cloud_endpoints(conn, agent_id, now_iso())
        append_catalog_audit(
            conn,
            catalog_agent_id=agent_id,
            actor=actor,
            event="runtime_binding_revoked",
            details={"binding_id": target},
        )
        return {"binding_id": target, "status": "revoked", "changed": True}
