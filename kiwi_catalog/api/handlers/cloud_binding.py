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
    PermissionDenied,
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


def create_runtime_binding(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """创建或轮换 Runtime 绑定（持钥证明 + 受控闸门）。"""
    agent_id = str(catalog_agent_id or "").strip()
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
    with db_session(db_path) as conn:
        agent = conn.execute(
            "select * from catalog_agents where catalog_agent_id = ?", (agent_id,)
        ).fetchone()
        if agent is None:
            raise NotFoundError("catalog agent not found")
        existing = _current_active_binding(conn, agent_id)
        if existing is None:
            # 首次绑定：持钥证明 + 管理员闸门（受控注册）。
            admin_token = str(payload.get("admin_token") or "")
            if not admin_token or not api_auth.token_matches(
                admin_token, api_auth.configured_admin_token()
            ):
                raise PermissionDenied("first runtime binding requires a valid admin token")
            verify_binding_possession(
                jws=jws, public_jwk=key_jwk, expected_fields=signed_fields
            )
            actor = f"admin+possession:{binding['key_id']}"
        else:
            # 轮换：必须由**当前活动绑定**的私钥签名（或管理员）。
            admin_token = str(payload.get("admin_token") or "")
            is_admin = bool(admin_token) and api_auth.token_matches(
                admin_token, api_auth.configured_admin_token()
            )
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
        is_admin = bool(admin_token) and api_auth.token_matches(
            admin_token, api_auth.configured_admin_token()
        )
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
        append_catalog_audit(
            conn,
            catalog_agent_id=agent_id,
            actor=actor,
            event="runtime_binding_revoked",
            details={"binding_id": target},
        )
        return {"binding_id": target, "status": "revoked", "changed": True}
