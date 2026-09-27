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

"""商家自助接入记录与名片只读视图（D3；设计 §4.3①/§5.1/§5.2）。

- 创建（或取回）接入记录：一商家一 agent（既有不变量），upsert
  ``source_type='self_registered'`` / ``hosting_mode='direct'`` /
  ``canonical_domain=''``（D2：绑定确认时才回填）。已有记录原地返回，
  **不复活治理行**（suspended/rejected 的恢复是 admin reinstate 语义）。
- 列表 / 名片详情：纯读投影（catalog_agents + card_publications +
  agent_card_versions + runtime_bindings，均 v33 表）。门户不产出内容——
  本模块没有任何写名片/写绑定的路径。
- 归属检查：会话 merchant_id 必须等于 agent 的 merchant_id，不一致一律
  404（与不存在不可区分，沿用 management-descriptor 的写法）。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from kiwi_catalog.agent_catalog.sqlite_repository import (
    append_catalog_audit,
    list_catalog_agents_by_merchant,
    new_catalog_agent_id,
    upsert_catalog_agent,
)
from kiwi_catalog.core.errors import ConflictError, NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso


def stable_card_url(base_url: str, catalog_agent_id: str) -> str:
    """预留的稳定读地址（名片发布前读取会 404——诚实语义）。"""
    return f"{base_url.rstrip('/')}/v1/agents/{catalog_agent_id}/agent-card.json"


def _latest_binding(conn: sqlite3.Connection, catalog_agent_id: str) -> dict[str, Any] | None:
    """绑定摘要：最新一条（任一状态；一次只有一个 active 是既有不变量）。"""
    row = conn.execute(
        "select binding_id, runtime_origin, a2a_endpoint, binding_version, status"
        " from runtime_bindings where catalog_agent_id = ?"
        " order by binding_version desc limit 1",
        (catalog_agent_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "binding_id": str(row["binding_id"]),
        "runtime_origin": str(row["runtime_origin"]),
        "a2a_endpoint": str(row["a2a_endpoint"]),
        "binding_version": int(row["binding_version"]),
        "status": str(row["status"]),
    }


def _publication_summary(conn: sqlite3.Connection, catalog_agent_id: str) -> dict[str, Any]:
    """名片发布摘要：无发布记录 → state='none' + 空字段（诚实空态）。"""
    publication = conn.execute(
        "select active_revision, publication_state, etag, updated_at"
        " from card_publications where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    if publication is None:
        return {"state": "none", "active_revision": 0, "digest": "", "etag": "", "updated_at": ""}
    version = conn.execute(
        "select digest from agent_card_versions where catalog_agent_id = ? and card_revision = ?",
        (catalog_agent_id, int(publication["active_revision"])),
    ).fetchone()
    return {
        "state": str(publication["publication_state"]),
        "active_revision": int(publication["active_revision"]),
        "digest": str(version["digest"]) if version is not None else "",
        "etag": str(publication["etag"]),
        "updated_at": str(publication["updated_at"]),
    }


def _card_public_fields(card: dict[str, Any]) -> dict[str, Any]:
    """卡片公开字段投影（与公开读地址一致，任何人都能看到）。"""
    return {
        "name": card.get("name") or "",
        "description": card.get("description") or "",
        "url": card.get("url") or "",
        "supportedInterfaces": card.get("supportedInterfaces") or [],
        "skills": card.get("skills") or [],
    }


def _active_card(conn: sqlite3.Connection, catalog_agent_id: str) -> dict[str, Any] | None:
    """读活动版本卡片 JSON；无发布/无版本 → None（不报 410，状态由 summary 表达）。"""
    publication = conn.execute(
        "select active_revision from card_publications where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    if publication is None:
        return None
    version = conn.execute(
        "select canonical_bytes from agent_card_versions"
        " where catalog_agent_id = ? and card_revision = ?",
        (catalog_agent_id, int(publication["active_revision"])),
    ).fetchone()
    if version is None:
        return None
    card = json.loads(str(version["canonical_bytes"]))
    return card if isinstance(card, dict) else None


def _require_owned_agent(
    conn: sqlite3.Connection, account: dict[str, Any], catalog_agent_id: str
) -> dict[str, Any]:
    """归属检查：agent 不存在 / 不属本会话商家 → 统一 404（不可区分）。"""
    merchant_id = str(account.get("merchant_id") or "").strip()
    row = conn.execute(
        "select * from catalog_agents where catalog_agent_id = ?",
        (str(catalog_agent_id or "").strip(),),
    ).fetchone()
    if row is None or str(row["merchant_id"] or "").strip() != merchant_id:
        raise NotFoundError("catalog agent not found")
    return dict(row)


def _agent_list_item(
    conn: sqlite3.Connection, row: dict[str, Any], base_url: str
) -> dict[str, Any]:
    catalog_agent_id = str(row["catalog_agent_id"])
    publication = _publication_summary(conn, catalog_agent_id)
    return {
        "catalog_agent_id": catalog_agent_id,
        "display_name": str(row.get("display_name") or ""),
        "hosting_mode": str(row.get("hosting_mode") or ""),
        "source_type": str(row.get("source_type") or ""),
        "canonical_domain": str(row.get("canonical_domain") or ""),
        "administrative_state": str(row.get("administrative_state") or ""),
        "card_state": publication["state"],
        "card_revision": publication["active_revision"],
        "card_digest": publication["digest"],
        "binding": _latest_binding(conn, catalog_agent_id),
        "card_url": stable_card_url(base_url, catalog_agent_id),
    }


def ensure_my_catalog_agent(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    *,
    base_url: str,
) -> dict[str, Any]:
    """创建（或取回）我的接入记录（D3，upsert 幂等）。

    一商家一 agent：名下已有记录（任一治理态）→ 原地返回，不改任何字段
    （治理行不复活）；没有 → 新建 self_registered/direct、domain 留空。
    """
    merchant_id = str(account.get("merchant_id") or "").strip()
    if not merchant_id:
        raise ValidationError("account has no merchant_id — complete registration first")
    display_name = str(account.get("merchant_name") or "").strip() or merchant_id
    owned, _ = list_catalog_agents_by_merchant(conn, merchant_id)
    if owned:
        return {
            "ok": True,
            "created": False,
            "card_url_note": "预留的稳定读地址：名片发布前读取会 404（诚实语义）",
            **_agent_list_item(conn, owned[0], base_url),
        }
    catalog_agent_id = new_catalog_agent_id()
    try:
        upsert_catalog_agent(
            conn,
            catalog_agent_id=catalog_agent_id,
            merchant_id=merchant_id,
            hosted_runtime_agent_id="",
            display_name=display_name,
            provider_name="",
            canonical_domain="",
            agent_type="commerce",
            source_type="self_registered",
            lifecycle_status="active",
            verification_status="discovered",
            hosting_mode="direct",
        )
    except sqlite3.IntegrityError as exc:
        # check-then-act 竞态窗口由数据层 merchant 唯一索引兜底（与注册路径一致）
        raise ConflictError("concurrent duplicate registration") from exc
    # merchants 影子行自维护（搜索 join 投影；注册路径同一约定，幂等）
    now = now_iso()
    conn.execute(
        "insert or ignore into merchants(id, name, created_at, updated_at) values (?, ?, ?, ?)",
        (merchant_id, display_name, now, now),
    )
    append_catalog_audit(
        conn,
        catalog_agent_id,
        f"merchant:{merchant_id}",
        "catalog_agent_registered",
        {
            "canonical_domain": "",
            "source_type": "self_registered",
            "merchant_id": merchant_id,
            "surface": "merchant_portal",
        },
    )
    row = _require_owned_agent(conn, account, catalog_agent_id)
    return {
        "ok": True,
        "created": True,
        "card_url_note": "预留的稳定读地址：名片发布前读取会 404（诚实语义）",
        **_agent_list_item(conn, row, base_url),
    }


def list_my_catalog_agents(
    conn: sqlite3.Connection, account: dict[str, Any], *, base_url: str
) -> dict[str, Any]:
    """我的接入记录列表（一商家一 agent，实际至多一条）。"""
    merchant_id = str(account.get("merchant_id") or "").strip()
    if not merchant_id:
        raise ValidationError("account has no merchant_id — complete registration first")
    owned, _ = list_catalog_agents_by_merchant(conn, merchant_id)
    return {
        "ok": True,
        "results": [_agent_list_item(conn, row, base_url) for row in owned],
    }


def get_my_agent_card(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    catalog_agent_id: str,
    *,
    base_url: str,
) -> dict[str, Any]:
    """名片详情（归属检查后）：发布状态 + 版本 + etag + 绑定摘要 + 卡片公开字段。"""
    row = _require_owned_agent(conn, account, catalog_agent_id)
    agent_id = str(row["catalog_agent_id"])
    card = _active_card(conn, agent_id)
    return {
        "ok": True,
        "catalog_agent_id": agent_id,
        "display_name": str(row.get("display_name") or ""),
        "hosting_mode": str(row.get("hosting_mode") or ""),
        "source_type": str(row.get("source_type") or ""),
        "canonical_domain": str(row.get("canonical_domain") or ""),
        "administrative_state": str(row.get("administrative_state") or ""),
        "card_url": stable_card_url(base_url, agent_id),
        "publication": _publication_summary(conn, agent_id),
        "binding": _latest_binding(conn, agent_id),
        "card": _card_public_fields(card) if card is not None else None,
        # 待确认接入请求（D1：运行时首绑 → 商家在门户确认/拒绝）
        "pending_bindings": _pending_binding_items(conn, agent_id),
    }


def _pending_binding_items(conn: sqlite3.Connection, catalog_agent_id: str) -> list[dict[str, Any]]:
    # 局部 import：binding_requests 顶层已 import 本模块（_require_owned_agent），
    # 顶层互引会成环。
    from kiwi_catalog.services.binding_requests import pending_request_items

    return pending_request_items(conn, catalog_agent_id)


_CARD_GOVERN_STATES = {"pause": "PAUSED", "withdraw": "WITHDRAWN"}


def set_my_card_state(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    catalog_agent_id: str,
    *,
    action: str,
    expected_revision: Any,
) -> dict[str, Any]:
    """门户名片治理（P1；设计 §5.2/§5.3）：pause / resume / withdraw。

    与运行时签名面（cloud_card）**同一状态转移核心**——pause/withdraw 走
    `set_publication_state`，resume 走 `activate_card`（运行时侧的恢复就是
    /publish 重新激活当前版本，见 test_cloud_card_publication 的
    ACTIVE→"publish" 映射）。CAS：`expected_revision` 必须等于当前活动版本，
    不匹配 → 409（核心抛 ConflictError）；非本商家 → 404；审计 actor =
    `merchant:<merchant_id>`，事件名 card_publication_paused/resumed/withdrawn。
    """
    if action not in ("pause", "resume", "withdraw"):
        raise ValidationError(f"unknown card governance action: {action}")
    if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
        raise ValidationError("expected_revision must be an integer")
    row = _require_owned_agent(conn, account, catalog_agent_id)
    agent_id = str(row["catalog_agent_id"])
    merchant_id = str(row["merchant_id"] or "").strip()
    actor = f"merchant:{merchant_id}"
    from kiwi_catalog.a2a.card_store import activate_card, set_publication_state

    if action == "resume":
        # 恢复 = 重新激活当前版本（revision == expected_revision，即只允许
        # 把「当前活动版本」切回 ACTIVE；etag 由核心重算，与运行时 /publish 一致）
        result = activate_card(
            conn,
            catalog_agent_id=agent_id,
            revision=expected_revision,
            expected_revision=expected_revision,
            actor=actor,
            now=now_iso(),
        )
        event = "card_publication_resumed"
        details: dict[str, Any] = {
            "active_revision": result["active_revision"],
            "etag": result["etag"],
        }
    else:
        state = _CARD_GOVERN_STATES[action]
        result = set_publication_state(
            conn,
            catalog_agent_id=agent_id,
            state=state,
            expected_revision=expected_revision,
            actor=actor,
            now=now_iso(),
        )
        # Explicit pause/withdraw outranks outstanding automatic enrollment retries.
        conn.execute(
            "update enrollments set status='canceled', authorization_epoch=authorization_epoch+1 "
            "where catalog_agent_id=? and status in ('ready_for_authorization','authorized','bound','published')",
            (agent_id,),
        )
        event = f"card_publication_{state.lower()}"
        details = {"active_revision": result["active_revision"]}
    append_catalog_audit(conn, agent_id, actor, event, details)
    return {"ok": True, **result}
