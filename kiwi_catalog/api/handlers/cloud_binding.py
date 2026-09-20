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
from kiwi_catalog.a2a.request_signature import verify_binding_possession, verify_runtime_request
from kiwi_catalog.agent_catalog.catalog_audit import append_catalog_audit
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.core.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from kiwi_catalog.db.session import db_session, now_iso

SIGNATURE_HEADER = "x-kiwi-binding-jws"


def read_runtime_binding_document(db_path: str | Path, catalog_agent_id: str) -> dict[str, Any]:
    """GET /v1/agents/{id}/runtime-binding —— 公开读（限流由 ASGI 层负责）。"""
    with db_session(db_path) as conn:
        return read_runtime_binding(conn, str(catalog_agent_id or "").strip())


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
    if not str(binding["runtime_origin"]).startswith("https://"):
        raise ValidationError("binding.runtime_origin must be https")
    if not str(binding["a2a_endpoint"]).startswith("https://"):
        raise ValidationError("binding.a2a_endpoint must be https")
    if not isinstance(binding.get("generation"), int):
        raise ValidationError("binding.generation must be an integer")
    if not isinstance(binding.get("service_epoch"), int):
        raise ValidationError("binding.service_epoch must be an integer")
    return binding


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
            " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
            " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
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
