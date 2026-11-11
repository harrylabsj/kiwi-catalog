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

"""商家接入方式 → 买家路由的公开、非凭据投影。

设计边界（与 WorkBuddy 分享码/代管完全分离）：

- 本表只保存商家**显式选择的接入方式**（`auto` / `share_code` /
  `no_share_code`），不保存分享码、链接、Cookie、密文或任何凭据。
- 写入只能由当前 active runtime binding 的私钥签名完成（见
  ``api/handlers/cloud_binding.py::update_buyer_access``）。公开写路径
  （register/claim/refresh）永远不能设置该状态。
- 公开投影必须同时满足：agent 仍 active + 写入行仍属于**当前** active
  binding + 当前时间未超过绑定有效期。撤销/轮换/过期后旧行不再被信任，
  买家看到 ``unknown`` 并 fail-closed；行本身保留作审计，不删分享码。
- 平台没有公开的"已加白"验证 API，因此投影永远标记
  ``platform_verification: "unverified"``。`direct` 只表示商家显式选择了
  无分享码接入，**不是**平台白名单背书。

路由状态口径：

- 显式 `share_code` → `relay`（买家经目录中继传输，中继只传输不决定磋商）
- 显式 `no_share_code` → `direct`（买家无码直连；失败由买家 fail-closed）
- 显式/缺省 `auto` → 按目录既有公开事实保守回退：
  active `runtime_access` → `relay`，否则 → `direct`（legacy 行为）。
- 无法确认（binding 撤销/轮换/过期、agent 非 active）→ `unknown`。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kiwi_catalog.core.errors import ConflictError, ValidationError

BUYER_ACCESS_MODES = ("auto", "share_code", "no_share_code")
BUYER_ACCESS_PUBLIC_STATES = ("relay", "direct", "unknown")
BUYER_ACCESS_SCHEMA_VERSION = 1
PLATFORM_VERIFICATION = "unverified"

_MODE_SET = frozenset(BUYER_ACCESS_MODES)

_BUYER_ACCESS_ROUTES_DDL = (
    """
create table if not exists buyer_access_routes (
        catalog_agent_id text primary key,
        mode text not null check(mode in ('auto','share_code','no_share_code')),
        revision integer not null check(revision >= 1),
        binding_id text not null,
        merchant_id text not null default '',
        created_at text not null,
        updated_at text not null
    ) without rowid
    """,
    """
create index if not exists idx_buyer_access_routes_binding
        on buyer_access_routes(binding_id)
    """,
)


def ensure_schema(conn: Any) -> None:
    """惰性、幂等地补齐新表。

    这是**回滚安全**的选择：不提升 schema user_version，旧版本 Catalog 仍能
    打开同一个库；新版本首次读写时补建 additive 表。全新库由 models.py 的
    DDL 直接创建，两条路径结果一致。
    """
    exists = conn.execute(
        "select 1 from sqlite_master where type = 'table' and name = 'buyer_access_routes'"
    ).fetchone()
    if exists is not None:
        return
    for statement in _BUYER_ACCESS_ROUTES_DDL:
        conn.execute(statement)


def is_mode(value: Any) -> bool:
    return isinstance(value, str) and value in _MODE_SET


def _binding_is_live(row: Any, now: datetime) -> bool:
    expires_at = str(row["expires_at"] or "")
    if not expires_at:
        return True
    try:
        parsed = datetime.fromisoformat(expires_at)
    except ValueError:
        # 无法解析的有效期不能当作"永不过期"。
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed > now


def active_binding(conn: Any, catalog_agent_id: str) -> Any:
    """当前 active 且未过期的 runtime binding；不返回任何密钥材料。"""
    now = datetime.now(UTC)
    rows = conn.execute(
        "select binding_id, catalog_agent_id, merchant_id, key_id, runtime_origin,"
        " service_epoch, binding_version, expires_at, status"
        " from runtime_bindings where catalog_agent_id = ? and status = 'active'"
        " order by binding_version desc",
        (catalog_agent_id,),
    ).fetchall()
    for row in rows:
        if _binding_is_live(row, now):
            return row
    return None


def active_bindings(conn: Any, catalog_agent_ids: list[str]) -> dict[str, Any]:
    if not catalog_agent_ids:
        return {}
    now = datetime.now(UTC)
    placeholders = ",".join("?" for _ in catalog_agent_ids)
    rows = conn.execute(
        "select binding_id, catalog_agent_id, merchant_id, key_id, runtime_origin,"
        " service_epoch, binding_version, expires_at, status"
        f" from runtime_bindings where catalog_agent_id in ({placeholders})"
        " and status = 'active' order by binding_version desc",
        tuple(catalog_agent_ids),
    ).fetchall()
    result: dict[str, Any] = {}
    for row in rows:
        agent_id = str(row["catalog_agent_id"])
        if agent_id not in result and _binding_is_live(row, now):
            result[agent_id] = row
    return result


def route_row(conn: Any, catalog_agent_id: str) -> Any:
    ensure_schema(conn)
    return conn.execute(
        "select catalog_agent_id, mode, revision, binding_id, merchant_id,"
        " created_at, updated_at from buyer_access_routes where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()


def route_rows(conn: Any, catalog_agent_ids: list[str]) -> dict[str, Any]:
    if not catalog_agent_ids:
        return {}
    ensure_schema(conn)
    placeholders = ",".join("?" for _ in catalog_agent_ids)
    rows = conn.execute(
        "select catalog_agent_id, mode, revision, binding_id, merchant_id,"
        " created_at, updated_at from buyer_access_routes"
        f" where catalog_agent_id in ({placeholders})",
        tuple(catalog_agent_ids),
    ).fetchall()
    return {str(row["catalog_agent_id"]): row for row in rows}


def public_projection(
    *,
    catalog_agent_id: str,
    administrative_state: str,
    runtime_access: dict[str, Any] | None,
    route: Any,
    binding: Any,
) -> dict[str, Any]:
    """非凭据的 wire 投影。调用方负责批量取 route/binding。"""
    base: dict[str, Any] = {
        "schema_version": BUYER_ACCESS_SCHEMA_VERSION,
        "state": "unknown",
        "source": "agent_inactive",
        "revision": 0,
        "platform_verification": PLATFORM_VERIFICATION,
    }
    if route is not None:
        base["revision"] = int(route["revision"])
        base["updated_at"] = str(route["updated_at"])
        base["mode"] = str(route["mode"])

    if str(administrative_state) != "active":
        return base

    if route is not None:
        # 写入行只对**写入它的那个 active binding** 有效。撤销/轮换/过期后
        # 旧行保留审计，但不再影响买家路由。
        if (
            binding is None
            or str(route["binding_id"]) != str(binding["binding_id"])
            or str(route["merchant_id"]) != str(binding["merchant_id"])
        ):
            return {**base, "state": "unknown", "source": "authorization_changed"}
        mode = str(route["mode"])
        if mode == "share_code":
            return {**base, "state": "relay", "source": "merchant_setting"}
        if mode == "no_share_code":
            return {**base, "state": "direct", "source": "merchant_setting"}
        # auto：没有平台白名单 API，不能把"商家选择自动"解释成已加白；
        # 按目录既有事实保守回退（有 active 分享码 → 中继，否则无码）。
        if runtime_access is not None:
            return {**base, "state": "relay", "source": "legacy_runtime_access"}
        return {**base, "state": "direct", "source": "legacy_no_share_code"}

    # 旧记录/旧客户端：没有显式行时沿用既有语义。旧记录不会因此被标成
    # "平台已验证直连"；`platform_verification` 仍是 unverified。
    base.pop("mode", None)
    if runtime_access is not None:
        return {**base, "state": "relay", "source": "legacy_runtime_access"}
    return {**base, "state": "direct", "source": "legacy_no_share_code"}


def public_projections(
    conn: Any,
    rows: list[dict[str, Any]],
    runtime_access_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """批量公开投影（list/search 用；每类一次 IN 查询）。"""
    ids = [str(row.get("catalog_agent_id", "")) for row in rows]
    routes = route_rows(conn, ids)
    bindings = active_bindings(conn, ids)
    access = runtime_access_map or {}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        agent_id = str(row.get("catalog_agent_id", ""))
        result[agent_id] = public_projection(
            catalog_agent_id=agent_id,
            administrative_state=str(row.get("administrative_state") or ""),
            runtime_access=access.get(agent_id),
            route=routes.get(agent_id),
            binding=bindings.get(agent_id),
        )
    return result


def owner_state(conn: Any, catalog_agent_id: str) -> dict[str, Any]:
    """签名读：返回商家自己的权威状态（仍是脱敏、非凭据）。"""
    row = route_row(conn, catalog_agent_id)
    if row is None:
        return {
            "ok": True,
            "mode": None,
            "revision": 0,
            "updated_at": None,
            "public_state": "unknown",
            "__no_store__": True,
        }
    agent = conn.execute(
        "select administrative_state from catalog_agents where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    binding = active_binding(conn, catalog_agent_id)
    from kiwi_catalog.services.runtime_access import active_public_projections

    runtime_access = active_public_projections(conn, [catalog_agent_id]).get(catalog_agent_id)
    projection = public_projection(
        catalog_agent_id=catalog_agent_id,
        administrative_state=str(agent["administrative_state"] if agent is not None else ""),
        runtime_access=runtime_access,
        route=row,
        binding=binding,
    )
    return {
        "ok": True,
        "mode": str(row["mode"]),
        "revision": int(row["revision"]),
        "updated_at": str(row["updated_at"]),
        "public_state": str(projection["state"]),
        "__no_store__": True,
    }


def update_mode(
    conn: Any,
    *,
    catalog_agent_id: str,
    mode: Any,
    expected_revision: Any,
    binding_id: str,
    merchant_id: str,
) -> Any:
    """CAS 写入。调用方必须先完成签名与 active binding 校验。"""
    ensure_schema(conn)
    if not is_mode(mode):
        raise ValidationError("mode must be one of auto, share_code, no_share_code")
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
        raise ValidationError("expected_revision must be a non-negative integer")
    current = route_row(conn, catalog_agent_id)
    current_revision = int(current["revision"]) if current is not None else 0
    if expected_revision != current_revision:
        raise ConflictError(
            f"buyer access revision changed (expected {expected_revision}, head {current_revision})"
        )
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    if current is None:
        cursor = conn.execute(
            "insert into buyer_access_routes"
            " (catalog_agent_id, mode, revision, binding_id, merchant_id, created_at, updated_at)"
            " values (?, ?, 1, ?, ?, ?, ?)"
            " on conflict(catalog_agent_id) do nothing",
            (catalog_agent_id, str(mode), binding_id, merchant_id, now, now),
        )
        if cursor.rowcount != 1:
            raise ConflictError("buyer access was concurrently created")
    else:
        cursor = conn.execute(
            "update buyer_access_routes set mode = ?, revision = revision + 1,"
            " binding_id = ?, merchant_id = ?, updated_at = ?"
            " where catalog_agent_id = ? and revision = ?",
            (str(mode), binding_id, merchant_id, now, catalog_agent_id, current_revision),
        )
        if cursor.rowcount != 1:
            raise ConflictError("buyer access was concurrently updated")
    return route_row(conn, catalog_agent_id)
