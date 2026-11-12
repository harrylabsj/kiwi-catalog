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
  本模块只有两处写路径：名片治理（pause/resume/withdraw，与运行时同核心）
  和解除连接（撤销当前绑定，与运行时签名面同一结果）。
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
    """名片发布摘要：无发布记录 → state='none' + 空字段（诚实空态）。

    已签名版本若被检测到分享码链接，摘要带 ``quarantined`` /
    ``republish_required``：**不改写 digest/etag**，只提示商家用新内容重新发布。
    """
    publication = conn.execute(
        "select active_revision, publication_state, etag, updated_at"
        " from card_publications where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    if publication is None:
        return {
            "state": "none",
            "active_revision": 0,
            "digest": "",
            "etag": "",
            "updated_at": "",
            "quarantined": False,
            "republish_required": False,
        }
    version = conn.execute(
        "select digest, canonical_bytes from agent_card_versions"
        " where catalog_agent_id = ? and card_revision = ?",
        (catalog_agent_id, int(publication["active_revision"])),
    ).fetchone()
    quarantined = False
    if version is not None:
        from kiwi_catalog.a2a.card_store import card_contains_share_code

        try:
            card = json.loads(str(version["canonical_bytes"] or "{}"))
        except (TypeError, ValueError):
            card = None
        quarantined = card_contains_share_code(card) if isinstance(card, dict) else True
    return {
        "state": str(publication["publication_state"]),
        "active_revision": int(publication["active_revision"]),
        "digest": str(version["digest"]) if version is not None else "",
        "etag": str(publication["etag"]),
        "updated_at": str(publication["updated_at"]),
        "quarantined": quarantined,
        "republish_required": quarantined,
    }


def _card_public_fields(card: dict[str, Any]) -> dict[str, Any]:
    """商家自查的卡片公开字段投影（不是公开稳定读地址）。

    ``url``/``supportedInterfaces[].url`` 是服务地址，允许 WorkBuddy 主机，
    但不允许携带分享码参数/路径段；历史名片里的分享码 URL 在这里清空，
    仅用于商户自查展示。已签名内容被污染时不会走本函数（公开读隔离）。
    文本字段同时移除明显的联系方式与危险公开链接。
    """
    from kiwi_catalog.services.merchant_publications import (
        contains_share_code_url,
        redact_public_text,
    )

    def _text(value: Any) -> Any:
        return redact_public_text(str(value)) if isinstance(value, str) else value

    def _service_url(value: Any) -> Any:
        text = str(value or "")
        return "" if contains_share_code_url(text) else text

    interfaces: list[Any] = []
    for item in card.get("supportedInterfaces") or []:
        if isinstance(item, dict):
            cleaned = dict(item)
            if "url" in cleaned:
                cleaned["url"] = _service_url(cleaned["url"])
            interfaces.append(cleaned)
        else:
            interfaces.append(item)
    skills: list[Any] = []
    for item in card.get("skills") or []:
        if isinstance(item, dict):
            skills.append({key: _text(value) for key, value in item.items()})
        elif isinstance(item, str):
            skills.append(_text(item))
        else:
            skills.append(item)
    return {
        "name": _text(card.get("name") or ""),
        "description": _text(card.get("description") or ""),
        "url": _service_url(card.get("url") or ""),
        "supportedInterfaces": interfaces,
        "skills": skills,
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
    from kiwi_catalog.services import merchant_publications as publications_service

    catalog_agent_id = str(row["catalog_agent_id"])
    publication = _publication_summary(conn, catalog_agent_id)
    merchant_id = str(row.get("merchant_id") or "")
    has_active_binding = publications_service.merchant_has_active_binding(conn, merchant_id)
    return {
        "catalog_agent_id": catalog_agent_id,
        "public_home_url": (
            publications_service.public_merchant_home_url_for(conn, merchant_id)
            if has_active_binding
            else ""
        ),
        "display_name": str(row.get("display_name") or ""),
        "hosting_mode": str(row.get("hosting_mode") or ""),
        "source_type": str(row.get("source_type") or ""),
        "canonical_domain": str(row.get("canonical_domain") or ""),
        "administrative_state": str(row.get("administrative_state") or ""),
        "card_state": publication["state"],
        "card_revision": publication["active_revision"],
        "card_digest": publication["digest"],
        "card_quarantined": bool(publication.get("quarantined")),
        "card_republish_required": bool(publication.get("republish_required")),
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
    """名片详情（归属检查后）：发布状态 + 版本 + etag + 绑定摘要 + 卡片公开字段。

    ``runtime_access`` 是**已生效**的访问门禁公开投影（provider/access_mode/
    parameter_name/版本），与 ``/v1/agents`` 公开面同源同字段：不含分享码、密文
    或加密密钥。商家后台用它区分「服务地址只是入口」与「入口还带 WorkBuddy
    分享码门禁」，页面不得据此拼接或回显任何凭据。

    ``public_shop_url`` 是商家在**公开资料**里填写的店铺链接（published 且未过期
    的最新一条），是目录现有数据里唯一可指向商家自己公开店铺页的字段；目录
    不托管该页面。它是外部链接，不是商家管理后台，也不是分享码 URL。
    """
    row = _require_owned_agent(conn, account, catalog_agent_id)
    agent_id = str(row["catalog_agent_id"])
    card = _active_card(conn, agent_id)
    publication = _publication_summary(conn, agent_id)
    from kiwi_catalog.services import merchant_publications as publications_service
    from kiwi_catalog.services import runtime_access as runtime_access_service

    active_access = runtime_access_service.active_runtime_access(conn, agent_id)
    binding = _latest_binding(conn, agent_id)
    has_active_binding = conn.execute(
        "select 1 from runtime_bindings where catalog_agent_id = ? and status = 'active' limit 1",
        (agent_id,),
    ).fetchone() is not None
    # 公开主页是商家级页面：链接门禁按商家名下是否有活动绑定判断。
    has_public_binding = publications_service.merchant_has_active_binding(
        conn, str(row.get("merchant_id") or "")
    )
    withdrawn = str(publication.get("state") or "") == "WITHDRAWN"
    # 已撤回/已断开的名片不再投影给门户：卡片内容属于商家应用，解除连接后
    # 不能继续当作当前对外展示内容。公开稳定读地址对 WITHDRAWN 同样 410。
    card_available = (
        card is not None
        and not publication["quarantined"]
        and not withdrawn
        and has_active_binding
    )
    # 服务地址/卡片地址/目录基址都不是「公开店铺页」：读侧精确比较并拒绝。
    blocked_shop_urls = tuple(
        value
        for value in (
            str((card or {}).get("url") or ""),
            str((binding or {}).get("runtime_origin") or ""),
            str((binding or {}).get("a2a_endpoint") or ""),
            str(base_url or ""),
        )
        if value
    )
    return {
        "ok": True,
        "catalog_agent_id": agent_id,
        "display_name": str(row.get("display_name") or ""),
        "hosting_mode": str(row.get("hosting_mode") or ""),
        "source_type": str(row.get("source_type") or ""),
        "canonical_domain": str(row.get("canonical_domain") or ""),
        "administrative_state": str(row.get("administrative_state") or ""),
        "card_url": stable_card_url(base_url, agent_id),
        "publication": publication,
        "binding": binding,
        # 隔离的已签名内容不返回任何字段投影（清洗后配原 digest = 伪造摘要）；
        # 商家只看到 publication.republish_required 提示。已撤回或没有活动
        # 绑定的名片同理不再投影。
        "card": _card_public_fields(card) if card is not None and card_available else None,
        # 公开店铺页（外部、商家填写；无 published 资料/链接时为空串）。
        "public_shop_url": publications_service.latest_public_shop_url(
            conn,
            str(row.get("merchant_id") or ""),
            blocked_urls=blocked_shop_urls,
        ),
        # 目录托管的公开商家主页：无外部 shop_url 也能打开的稳定页面；
        # 没有可公开内容时为空串（页面本身会 404，不给假链接）。
        # 没有活动绑定时不给链接：旧应用留下的 ACTIVE 商品不应继续被门户
        # 当作「当前对外展示内容」的入口。
        "public_home_url": (
            publications_service.public_merchant_home_url_for(
                conn, str(row.get("merchant_id") or "")
            )
            if has_public_binding
            else ""
        ),
        # 访问门禁（None = 未启用/应用已断开）。已是公开投影，绝不包含分享码/密文。
        "runtime_access": (
            runtime_access_service.public_projection(active_access)
            if has_active_binding and not withdrawn
            else None
        ),
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


def disconnect_my_binding(
    conn: sqlite3.Connection,
    account: dict[str, Any],
    catalog_agent_id: str,
    binding_id: str,
) -> dict[str, Any]:
    """门户「取消连接」（会话）：撤销本商家的当前绑定。

    与运行时签名面 `cloud_binding.revoke_runtime_binding` 同一结果：绑定置
    revoked、该应用已发布的名片撤下（ACTIVE/PAUSED → WITHDRAWN，稳定读 410）、
    按当前库状态同步端点行（无其他活动绑定时 a2a / agent_card 行被删除）、
    写 catalog 审计（actor = `merchant:<merchant_id>`，事件
    `runtime_binding_revoked` / `card_publication_withdrawn`）。重复解除幂等
    （`changed:false`），不存在的绑定或非本商家 agent 一律 404。

    不在这里删依赖行：目录代管、开放询价、保活、访问配置的判定都要求活动
    绑定，撤销后自然 fail-closed；保留行作为历史，便于商家重新连接后核对。
    """
    from kiwi_catalog.a2a.card_store import withdraw_publication_on_binding_revoke
    from kiwi_catalog.services.agent_endpoints import sync_cloud_endpoints

    row = _require_owned_agent(conn, account, catalog_agent_id)
    agent_id = str(row["catalog_agent_id"])
    merchant_id = str(row["merchant_id"] or "").strip()
    target = str(binding_id or "").strip()
    if not target:
        raise ValidationError("binding_id is required")
    binding = conn.execute(
        "select binding_id, status from runtime_bindings"
        " where catalog_agent_id = ? and binding_id = ?",
        (agent_id, target),
    ).fetchone()
    if binding is None:
        raise NotFoundError("runtime binding not found")
    if str(binding["status"]) == "revoked":
        return {"binding_id": target, "status": "revoked", "changed": False}
    now = now_iso()
    conn.execute(
        "update runtime_bindings set status = 'revoked', updated_at = ? where binding_id = ?",
        (now, target),
    )
    # 解除连接 = 该应用发布的名片不再对外展示。撤下（而非删除）保留历史，
    # 稳定读地址随 WITHDRAWN 返回 410；重新连接后由运行时重新发布。
    withdrawn = withdraw_publication_on_binding_revoke(
        conn,
        catalog_agent_id=agent_id,
        actor=f"merchant:{merchant_id}",
        now=now,
    )
    if withdrawn is not None:
        append_catalog_audit(
            conn,
            agent_id,
            f"merchant:{merchant_id}",
            "card_publication_withdrawn",
            {
                "active_revision": withdrawn["active_revision"],
                "reason": "binding_disconnected",
            },
        )
    sync_cloud_endpoints(conn, agent_id, now)
    append_catalog_audit(
        conn,
        agent_id,
        f"merchant:{merchant_id}",
        "runtime_binding_revoked",
        {"binding_id": target, "channel": "portal"},
    )
    return {"binding_id": target, "status": "revoked", "changed": True}
