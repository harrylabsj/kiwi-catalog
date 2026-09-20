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

"""云端名片托管存储（M3；设计 v0.1.2 §11.2 / §11.3）。

职责边界：

- **不可变版本**：每次 `card-publications` 落一行 `agent_card_versions`，永不改写；
- **原子激活**：`card_publications.active_revision` 只经 CAS 前进（`expected_revision`
  不匹配即 409），任一失败不覆盖旧活动名片；
- **治理状态**：ACTIVE / PAUSED（公开信息保留、停止新询价）/ WITHDRAWN（稳定地址 410）；
- **泄漏拒绝**：发布对象里出现 token/成本/底价等私密字段 → 拒绝整次发布，旧版本不受影响。

**关于 digest 与规范化（重要取舍）**：Catalog **不做 JCS 规范化**——设计要求
「不自行用普通 JSON 字符串排序假冒完整 JCS」（§11.3）。因此：

- `card_digest` 由 **Runtime 计算**（TS 侧经审查的 JCS 实现），随发布请求一并提交，
  并由**绑定 Runtime 的请求签名**背书；Catalog 只存储与回读，不重算；
- `etag` 是 Catalog 自己算的缓存校验值（稳定序列化后的 sha256），**不等同 card_digest**，
  只用于 HTTP 缓存协商（If-None-Match → 304）。

跨语言 digest 一致性（Runtime ↔ Buyer）由 TS 两侧的 JCS 保证；Catalog 不参与重算，
因此不存在「Python 侧近似 JCS」这一风险面。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from kiwi_catalog.core.errors import ConflictError, GoneError, NotFoundError, ValidationError
from kiwi_catalog.discovery._validation import scan_secrets
from kiwi_catalog.discovery.cache import compute_etag as _http_etag

WIRE_PROFILE = "a2a-1.0"
PUBLICATION_STATES = ("ACTIVE", "PAUSED", "WITHDRAWN")

#: 发布对象里**绝不允许**出现的字段名片段（私密经营数据；§11.3 泄漏字段注入）。
_PRIVATE_KEY_PATTERNS = (
    "cost",
    "floor",
    "min_unit_price",
    "price_floor",
    "private",
    "margin",
    "wholesale",
    "supplier",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "credential",
)


def _storage_json(value: Any) -> str:
    """入库用的稳定序列化（排序键 + 紧凑分隔符）。

    **不是** JCS：只保证「同一对象 → 同一字节」，不对外声称规范化等价；
    `card_digest` 一律由发布方（Runtime，TS 侧经审查的 JCS）计算并经其签名背书。
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_card_bytes(card: dict[str, Any]) -> bytes:
    """公开名片读地址的**规范响应体字节**。

    这是 `card_etag` 的承诺对象：`compute_etag(card)` 与两栈实际发出的字节都必须是它。
    fallback 栈的 `_send_json` 天然是 `json.dumps(..., ensure_ascii=False,
    sort_keys=True)`，与之逐字节相同；FastAPI 栈默认用紧凑分隔符 + 插入序，**不同**，
    因此 FastAPI 路由必须显式发这份字节（否则承诺的 `card_etag` 永远匹配不上响应头，
    `If-None-Match` 重验证在 FastAPI 栈上静默失效——契约级双栈漂移）。
    """
    return json.dumps(card, ensure_ascii=False, sort_keys=True).encode("utf-8")


def compute_etag(card: dict[str, Any]) -> str:
    """ETag：与 ASGI 层（fallback 与 FastAPI 双栈）对同一响应体算出的值**一致**。

    两栈都对 `canonical_card_bytes(card)` 调 `discovery.cache.compute_etag`，这里照
    同一口径计算，避免"库里存一个、响应里发另一个"。
    """
    return _http_etag(canonical_card_bytes(card))


def scan_publication_leaks(publication: dict[str, Any]) -> list[str]:
    """扫描发布对象里的私密字段（密钥类 + 经营类）。返回 JSON 路径列表（空 = 干净）。"""
    hits = list(scan_secrets(publication))
    leaks: list[str] = []

    def _walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = str(key)
                lowered = key_text.lower()
                if any(pattern in lowered for pattern in _PRIVATE_KEY_PATTERNS):
                    leaks.append(f"{path}.{key_text}" if path else key_text)
                _walk(item, f"{path}.{key_text}" if path else key_text)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                _walk(item, f"{path}.{index}")

    _walk(publication, "")
    return sorted(set(hits) | set(leaks))


def _require_agent(conn: sqlite3.Connection, catalog_agent_id: str) -> sqlite3.Row:
    row = conn.execute(
        "select * from catalog_agents where catalog_agent_id = ?", (catalog_agent_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError("catalog agent not found")
    return row


def _active_binding(conn: sqlite3.Connection, catalog_agent_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "select * from runtime_bindings where catalog_agent_id = ? and status = 'active'"
        " order by binding_version desc limit 1",
        (catalog_agent_id,),
    ).fetchone()


def validate_publication(
    publication: dict[str, Any],
    *,
    catalog_agent_id: str,
    binding: sqlite3.Row | None,
) -> tuple[dict[str, Any], str]:
    """两层校验：外层发布对象 + 内层 Agent Card；返回 (card, card_digest)。

    外层字段按 `card-publication` 契约（schema_version/agent_id/binding_id/generation/
    expected_revision/wire_profile/card_digest/agent_card）；内层 Card 必须：
      - 是 JSON 对象且带 name/version/url；
      - `supportedInterfaces[*].url` 指向**绑定的 Runtime 端点**（不得指向 Catalog 自己）；
      - 不含私密字段（泄漏扫描）。
    """
    if not isinstance(publication, dict):
        raise ValidationError("publication must be a JSON object")
    required = (
        "schema_version",
        "agent_id",
        "binding_id",
        "generation",
        "expected_revision",
        "wire_profile",
        "card_digest",
        "agent_card",
    )
    missing = [field for field in required if field not in publication]
    if missing:
        raise ValidationError(f"publication missing required field(s): {', '.join(missing)}")
    if publication["schema_version"] != "0.1.2":
        raise ValidationError("unsupported card-publication schema_version")
    if str(publication["agent_id"]).strip() != catalog_agent_id:
        raise ValidationError("publication agent_id does not match the route agent")
    if publication["wire_profile"] != WIRE_PROFILE:
        raise ValidationError(f"unsupported wire_profile: {publication['wire_profile']}")
    digest = str(publication["card_digest"] or "")
    if not digest.startswith("sha256:") or len(digest) != len("sha256:") + 64:
        raise ValidationError("card_digest must be sha256:<64 hex>")

    leaks = scan_publication_leaks(publication)
    if leaks:
        # 拒绝整次发布；旧活动名片不受影响（调用方在同一事务里，异常即回滚）。
        raise ValidationError(f"publication contains private field(s): {', '.join(leaks[:8])}")

    card = publication["agent_card"]
    if not isinstance(card, dict):
        raise ValidationError("agent_card must be a JSON object")
    for field in ("name", "version", "url"):
        if not isinstance(card.get(field), str) or not card[field].strip():
            raise ValidationError(f"agent_card.{field} must be a non-empty string")

    if binding is not None:
        endpoint = str(binding["a2a_endpoint"])
        origin = str(binding["runtime_origin"])
        interfaces = card.get("supportedInterfaces")
        if not isinstance(interfaces, list) or not interfaces:
            raise ValidationError("agent_card.supportedInterfaces must be a non-empty array")
        urls = [str(item.get("url", "")) for item in interfaces if isinstance(item, dict)]
        if endpoint not in urls:
            raise ValidationError(
                "agent_card.supportedInterfaces must point at the bound runtime endpoint"
            )
        card_url = str(card.get("url", ""))
        if card_url and card_url.startswith(origin) is False and endpoint not in card_url:
            # Card 的 url 可以是名片地址或 Runtime origin；但绝不能指向 Catalog 自己。
            raise ValidationError("agent_card.url must not point at the catalog host")
    return card, digest


def create_card_revision(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    publication: dict[str, Any],
    actor: str,
    now: str,
) -> dict[str, Any]:
    """创建**不可变**名片版本（不激活）。返回 {card_revision, digest, etag}。"""
    _require_agent(conn, catalog_agent_id)
    binding = _active_binding(conn, catalog_agent_id)
    card, digest = validate_publication(
        publication, catalog_agent_id=catalog_agent_id, binding=binding
    )
    row = conn.execute(
        "select coalesce(max(card_revision), 0) as rev from agent_card_versions"
        " where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    revision = int(row["rev"]) + 1
    conn.execute(
        "insert into agent_card_versions"
        " (catalog_agent_id, card_revision, wire_profile, canonical_bytes, digest, created_by, created_at)"
        " values (?, ?, ?, ?, ?, ?, ?)",
        (
            catalog_agent_id,
            revision,
            WIRE_PROFILE,
            _storage_json(card),
            digest,
            actor,
            now,
        ),
    )
    return {"card_revision": revision, "card_digest": digest, "etag": compute_etag(card)}


def activate_card(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    revision: int,
    expected_revision: int,
    actor: str,
    now: str,
) -> dict[str, Any]:
    """原子激活一个已存在的版本（CAS：`expected_revision` 必须等于当前活动版本）。"""
    _require_agent(conn, catalog_agent_id)
    version = conn.execute(
        "select * from agent_card_versions where catalog_agent_id = ? and card_revision = ?",
        (catalog_agent_id, int(revision)),
    ).fetchone()
    if version is None:
        raise NotFoundError(f"card revision {revision} not found")
    current = conn.execute(
        "select * from card_publications where catalog_agent_id = ?", (catalog_agent_id,)
    ).fetchone()
    current_revision = int(current["active_revision"]) if current is not None else 0
    if current_revision != int(expected_revision):
        raise ConflictError(
            f"expected_revision {expected_revision} does not match active revision {current_revision}"
        )
    card = json.loads(str(version["canonical_bytes"]))
    etag = compute_etag(card)
    if current is None:
        conn.execute(
            "insert into card_publications"
            " (catalog_agent_id, active_revision, publication_state, etag, updated_at)"
            " values (?, ?, 'ACTIVE', ?, ?)",
            (catalog_agent_id, int(revision), etag, now),
        )
    else:
        updated = conn.execute(
            "update card_publications set active_revision = ?, publication_state = 'ACTIVE',"
            " etag = ?, updated_at = ? where catalog_agent_id = ? and active_revision = ?",
            (int(revision), etag, now, catalog_agent_id, int(expected_revision)),
        )
        if updated.rowcount != 1:
            # 并发激活：另一请求已把 active_revision 推走 → CAS 失败（旧版本不被覆盖）。
            raise ConflictError("concurrent activation detected (CAS failed)")
    return {
        "catalog_agent_id": catalog_agent_id,
        "active_revision": int(revision),
        "publication_state": "ACTIVE",
        "etag": etag,
        "activated_by": actor,
    }


def set_publication_state(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    state: str,
    expected_revision: int,
    actor: str,
    now: str,
) -> dict[str, Any]:
    """暂停 / 恢复 / 撤回（CAS 保护：`expected_revision` 必须等于当前活动版本）。"""
    if state not in PUBLICATION_STATES:
        raise ValidationError(f"unknown publication state: {state}")
    current = conn.execute(
        "select * from card_publications where catalog_agent_id = ?", (catalog_agent_id,)
    ).fetchone()
    if current is None:
        raise NotFoundError("no publication for this agent")
    if int(current["active_revision"]) != int(expected_revision):
        raise ConflictError(
            f"expected_revision {expected_revision} does not match active revision {current['active_revision']}"
        )
    conn.execute(
        "update card_publications set publication_state = ?, updated_at = ?"
        " where catalog_agent_id = ? and active_revision = ?",
        (state, now, catalog_agent_id, int(expected_revision)),
    )
    return {
        "catalog_agent_id": catalog_agent_id,
        "active_revision": int(current["active_revision"]),
        "publication_state": state,
        "changed_by": actor,
    }


def read_active_card(conn: sqlite3.Connection, catalog_agent_id: str) -> tuple[dict[str, Any], str, str]:
    """读活动名片：返回 (card, etag, publication_state)。

    - 无发布记录 / 无该版本 → NotFoundError(404)；
    - WITHDRAWN → GoneError(410)，**不重定向**（§11.5）；
    - PAUSED → 仍返回名片（公开信息保留），治理状态由 runtime-binding 通道表达。
    """
    _require_agent(conn, catalog_agent_id)
    publication = conn.execute(
        "select * from card_publications where catalog_agent_id = ?", (catalog_agent_id,)
    ).fetchone()
    if publication is None:
        raise NotFoundError("no published card for this agent")
    state = str(publication["publication_state"])
    if state == "WITHDRAWN":
        raise GoneError("agent card withdrawn")
    version = conn.execute(
        "select * from agent_card_versions where catalog_agent_id = ? and card_revision = ?",
        (catalog_agent_id, int(publication["active_revision"])),
    ).fetchone()
    if version is None:
        raise NotFoundError("active card revision is missing")
    return json.loads(str(version["canonical_bytes"])), str(publication["etag"]), state
