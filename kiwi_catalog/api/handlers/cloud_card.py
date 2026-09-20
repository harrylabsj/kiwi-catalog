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

"""云端名片托管 API（M3；设计 §11.2/§11.3/§14.1）。

读路径（公开、稳定地址）：
    GET /v1/agents/{catalog_agent_id}/agent-card.json   → 原始 Card JSON（不套 ok 信封）
    撤回后 → 410（GoneError，不重定向）；ETag/304 由 ASGI 层统一处理。

写路径（**绑定 Runtime 请求签名**，不接受 owner token）：
    POST /v1/agents/{catalog_agent_id}/card-publications  → 创建不可变 revision
    POST /v1/agents/{catalog_agent_id}/publish            → CAS 原子激活
    POST /v1/agents/{catalog_agent_id}/pause              → 暂停（公开信息保留）
    POST /v1/agents/{catalog_agent_id}/withdraw           → 撤回（稳定地址 410）
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.a2a.card_store import (
    activate_card,
    create_card_revision,
    read_active_card,
    set_publication_state,
)
from kiwi_catalog.a2a.request_signature import verify_runtime_request
from kiwi_catalog.agent_catalog.catalog_audit import append_catalog_audit
from kiwi_catalog.core.errors import ValidationError
from kiwi_catalog.db.session import db_session, now_iso

SIGNATURE_HEADER = "x-kiwi-binding-jws"


def _signature_of(payload: dict[str, Any]) -> str:
    """取绑定 Runtime 的请求签名（两栈都经 payload_with_auth 合并为 `_binding_jws`）。"""
    value = payload.get("_binding_jws")
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ValidationError(f"missing request signature header ({SIGNATURE_HEADER})")


def published_agent_card(db_path: str | Path, catalog_agent_id: str) -> dict[str, Any]:
    """GET /v1/agents/{id}/agent-card.json —— 返回**原始 Card JSON**（不套 ok 信封）。"""
    with db_session(db_path) as conn:
        card, _etag, _state = read_active_card(conn, str(catalog_agent_id or "").strip())
        return card


def _signed_fields(payload: dict[str, Any], catalog_agent_id: str) -> dict[str, Any]:
    publication = payload.get("publication")
    if not isinstance(publication, dict):
        raise ValidationError("publication must be a JSON object")
    return {
        "agent_id": str(publication.get("agent_id", "")).strip() or catalog_agent_id,
        "binding_id": str(publication.get("binding_id", "")),
        "card_digest": str(publication.get("card_digest", "")),
        "expected_revision": publication.get("expected_revision"),
        "generation": publication.get("generation"),
    }


def create_card_publication(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/agents/{id}/card-publications —— 创建不可变 revision（不激活）。"""
    agent_id = str(catalog_agent_id or "").strip()
    jws = _signature_of(payload)
    publication = payload.get("publication")
    if not isinstance(publication, dict):
        raise ValidationError("publication must be a JSON object")
    with db_session(db_path) as conn:
        actor_payload = verify_runtime_request(
            conn,
            catalog_agent_id=agent_id,
            jws=jws,
            expected_fields=_signed_fields(payload, agent_id),
        )
        actor = f"runtime:{actor_payload.get('binding_id', '')}"
        created = create_card_revision(
            conn,
            catalog_agent_id=agent_id,
            publication=publication,
            actor=actor,
            now=now_iso(),
        )
        append_catalog_audit(
            conn,
            catalog_agent_id=agent_id,
            actor=actor,
            event="card_revision_created",
            details={
                "card_revision": created["card_revision"],
                "card_digest": created["card_digest"],
                "expected_revision": publication.get("expected_revision"),
            },
        )
        return created


def activate_card_publication(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """POST /v1/agents/{id}/publish —— CAS 原子激活指定 revision。"""
    agent_id = str(catalog_agent_id or "").strip()
    jws = _signature_of(payload)
    revision = payload.get("card_revision")
    expected = payload.get("expected_revision")
    if not isinstance(revision, int) or isinstance(revision, bool):
        raise ValidationError("card_revision must be an integer")
    if not isinstance(expected, int) or isinstance(expected, bool):
        raise ValidationError("expected_revision must be an integer")
    with db_session(db_path) as conn:
        actor_payload = verify_runtime_request(
            conn,
            catalog_agent_id=agent_id,
            jws=jws,
            expected_fields={
                "agent_id": agent_id,
                "binding_id": str(payload.get("binding_id", "")),
                "card_revision": revision,
                "expected_revision": expected,
            },
        )
        actor = f"runtime:{actor_payload.get('binding_id', '')}"
        result = activate_card(
            conn,
            catalog_agent_id=agent_id,
            revision=revision,
            expected_revision=expected,
            actor=actor,
            now=now_iso(),
        )
        append_catalog_audit(
            conn,
            catalog_agent_id=agent_id,
            actor=actor,
            event="card_publication_activated",
            details={"active_revision": result["active_revision"], "etag": result["etag"]},
        )
        return result


def set_card_publication_state(
    db_path: str | Path, catalog_agent_id: str, payload: dict[str, Any], state: str
) -> dict[str, Any]:
    """POST /v1/agents/{id}/pause | /withdraw —— CAS 保护的状态切换。"""
    agent_id = str(catalog_agent_id or "").strip()
    jws = _signature_of(payload)
    expected = payload.get("expected_revision")
    if not isinstance(expected, int) or isinstance(expected, bool):
        raise ValidationError("expected_revision must be an integer")
    with db_session(db_path) as conn:
        actor_payload = verify_runtime_request(
            conn,
            catalog_agent_id=agent_id,
            jws=jws,
            expected_fields={
                "agent_id": agent_id,
                "binding_id": str(payload.get("binding_id", "")),
                "expected_revision": expected,
                "publication_state": state,
            },
        )
        actor = f"runtime:{actor_payload.get('binding_id', '')}"
        result = set_publication_state(
            conn,
            catalog_agent_id=agent_id,
            state=state,
            expected_revision=expected,
            actor=actor,
            now=now_iso(),
        )
        append_catalog_audit(
            conn,
            catalog_agent_id=agent_id,
            actor=actor,
            event=f"card_publication_{state.lower()}",
            details={"active_revision": result["active_revision"]},
        )
        return result
