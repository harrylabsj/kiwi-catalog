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

"""SQLite-backed CatalogRepository — MVP persistence adapter.

Follows the same patterns as shopping_cli/core/catalog.py and
shopping_cli/services/agents.py: raw sqlite3.Connection with row_factory
already set to sqlite3.Row by the session layer.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from kiwi_catalog.agent_catalog.pagination import (
    agent_cursor_predicate as _agent_cursor_predicate,
)
from kiwi_catalog.agent_catalog.pagination import (
    paginate_agent_rows as _paginate_agent_rows,
)
from kiwi_catalog.agent_catalog.row_serialization import row_to_dict as _row_to_dict
from kiwi_catalog.agent_catalog.state_domains import (
    ACTIVE,
    ADMINISTRATIVE_STATES,
    DISCOVERED,
    FRESH,
    FRESHNESS_STATES,
    REJECTED,
    STALE,
    SUSPENDED,
    UNREACHABLE,
    VERIFICATION_LEVELS,
)
from kiwi_catalog.agent_catalog.state_domains import (
    fold_verification_status as _fold_verification_status,
)
from kiwi_catalog.agent_catalog.verification_evidence import (
    insert_profile_snapshot,  # noqa: F401 —— facade re-export
    insert_verification,  # noqa: F401 —— facade re-export
    latest_profile_snapshot,  # noqa: F401 —— facade re-export
    latest_verification,  # noqa: F401 —— facade re-export
    list_profile_snapshots,  # noqa: F401 —— facade re-export
    list_verifications,  # noqa: F401 —— facade re-export
)
from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso

# ── §8.3 keyset pagination（审查 P1-6）─────────────────────────────────────
# 三处列表/搜索共用同一排序键：verification_status rank → last_verified_at
# desc → display_name → catalog_agent_id。键集分页谓词必须与排序键完全同键，
# 历史 bug：游标只编码 catalog_agent_id，跨 rank/lva 组丢行/重行。

def _like_escaped(term: str) -> str:
    """LIKE 通配符转义（审查 P2）：用户输入里的 % / _ / \\ 是 SQL LIKE 元字符，
    不转义会让 q="%" 匹配全表、q="a_" 匹配任意单字符后缀。所有 LIKE 谓词必须
    配 ``escape '\\'`` 使用。"""
    escaped = str(term).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ── catalog_agents ──────────────────────────────────────────────────────────


def _insert_catalog_agent(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    merchant_id: str,
    hosted_runtime_agent_id: str,
    display_name: str,
    provider_name: str,
    canonical_domain: str,
    agent_type: str,
    source_type: str,
    lifecycle_status: str,
    verification_status: str,
    hosting_mode: str,
) -> dict[str, Any]:
    ts = now_iso()
    # Empty-string FK values must become None to satisfy SQLite FK pragma:
    # a non-NULL '' value triggers the FK check and fails when no matching
    # parent row exists.
    _mrc = merchant_id or None
    _hri = hosted_runtime_agent_id or None
    # legacy 单状态 → 三正交域派生（v0.3 §7）：阶梯值归 verification_level，
    # stale/unreachable 归 freshness，suspended/rejected 归 administrative。
    _level, _fresh, _admin = _domains_for_legacy_status(verification_status)
    conn.execute(
        """
        insert into catalog_agents(
            catalog_agent_id, merchant_id, hosted_runtime_agent_id,
            display_name, provider_name, canonical_domain, agent_type,
            source_type, lifecycle_status, verification_status, hosting_mode,
            verification_level, freshness_state, administrative_state,
            handoff_destination_types, last_refresh_attempt_at, last_refresh_result,
            first_seen_at, last_seen_at, last_verified_at, created_at, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            catalog_agent_id,
            _mrc,
            _hri,
            display_name,
            provider_name,
            canonical_domain,
            agent_type,
            source_type,
            lifecycle_status,
            verification_status,
            hosting_mode,
            _level,
            _fresh,
            _admin,
            "[]",
            "",
            "",
            ts,
            ts,
            ts if verification_status == "commerce_verified" else "",
            ts,
            ts,
        ),
    )
    return require_catalog_agent(conn, catalog_agent_id)


def _domains_for_legacy_status(
    verification_status: str,
) -> tuple[str, str, str]:
    """legacy 单状态 → (verification_level, freshness_state, administrative_state)。

    供 _insert 与 set_verification_status 复用：任何写入折叠列的地方都先
    映射到三域，保证折叠投影与三域永不漂移。
    """
    if verification_status in VERIFICATION_LEVELS:
        return (verification_status, FRESH, ACTIVE)
    if verification_status == STALE:
        return (DISCOVERED, STALE, ACTIVE)
    if verification_status == UNREACHABLE:
        return (DISCOVERED, UNREACHABLE, ACTIVE)
    if verification_status == SUSPENDED:
        return (DISCOVERED, FRESH, SUSPENDED)
    if verification_status == REJECTED:
        return (DISCOVERED, FRESH, REJECTED)
    return (DISCOVERED, FRESH, ACTIVE)


def _update_catalog_agent(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    **fields: Any,
) -> dict[str, Any]:
    allowed = {
        "merchant_id",
        "hosted_runtime_agent_id",
        "display_name",
        "provider_name",
        "canonical_domain",
        "agent_type",
        "source_type",
        "lifecycle_status",
        "verification_status",
        "hosting_mode",
        "verification_level",
        "freshness_state",
        "administrative_state",
        "handoff_destination_types",
        "last_refresh_attempt_at",
        "last_refresh_result",
        "last_seen_at",
        "last_verified_at",
    }
    # legacy 单状态 → 三正交域派生（v0.3 §7）：任何写 verification_status 的
    # 路径都必须同步三域（_insert/set_verification_status 同规）。否则治理处置
    # 的 agent（suspended/rejected）经 re-register 的更新分支会以 "discovered"
    # 复活在公开列表，且 verify 抛 InvalidStateTransitionError 永久失败。
    # 调用方显式传三域时（setdefault）尊重显式值。
    if fields.get("verification_status") is not None:
        _level, _fresh, _admin = _domains_for_legacy_status(fields["verification_status"])
        fields.setdefault("verification_level", _level)
        fields.setdefault("freshness_state", _fresh)
        fields.setdefault("administrative_state", _admin)
    # 审查 P3（折叠漂移面）：只写三域字段、不带 verification_status 时反向
    # 重算折叠列——任何三域写入都不得让折叠列漂移（CLAUDE.md 契约）。
    elif any(
        f in fields for f in ("verification_level", "freshness_state", "administrative_state")
    ):
        fields["verification_status"] = _fold_verification_status(
            str(fields.get("verification_level") or ""),
            str(fields.get("freshness_state") or ""),
            str(fields.get("administrative_state") or ""),
        )
    # 审查 P3（last_verified_at 不刷新）：hosted 投影反复同步 commerce_verified
    # 时刷新 last_verified_at——否则该行永远排在同 rank 老位置、verified_after
    # 过滤失真（搜索排序键的一部分）。
    if (
        fields.get("verification_status") == "commerce_verified"
        and fields.get("last_verified_at") is None
    ):
        fields["last_verified_at"] = now_iso()
    updates: list[str] = []
    values: list[Any] = []
    for col, val in fields.items():
        if col in allowed and val is not None:
            updates.append(f"{col} = ?")
            values.append(val)
    if not updates:
        return require_catalog_agent(conn, catalog_agent_id)
    updates.append("updated_at = ?")
    values.append(now_iso())
    values.append(catalog_agent_id)
    conn.execute(
        f"update catalog_agents set {', '.join(updates)} where catalog_agent_id = ?",
        values,
    )
    return require_catalog_agent(conn, catalog_agent_id)


def upsert_catalog_agent(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    merchant_id: str = "",
    hosted_runtime_agent_id: str = "",
    display_name: str = "",
    provider_name: str = "",
    canonical_domain: str = "",
    agent_type: str = "",
    source_type: str = "hosted",
    lifecycle_status: str = "active",
    verification_status: str = "discovered",
    hosting_mode: str = "unknown",
) -> dict[str, Any]:
    existing = conn.execute(
        "select catalog_agent_id from catalog_agents where catalog_agent_id = ?",
        (catalog_agent_id,),
    ).fetchone()
    if existing is None:
        return _insert_catalog_agent(
            conn,
            catalog_agent_id=catalog_agent_id,
            merchant_id=merchant_id,
            hosted_runtime_agent_id=hosted_runtime_agent_id,
            display_name=display_name,
            provider_name=provider_name,
            canonical_domain=canonical_domain,
            agent_type=agent_type,
            source_type=source_type,
            lifecycle_status=lifecycle_status,
            verification_status=verification_status,
            hosting_mode=hosting_mode,
        )
    return _update_catalog_agent(
        conn,
        catalog_agent_id,
        merchant_id=merchant_id,
        hosted_runtime_agent_id=hosted_runtime_agent_id,
        display_name=display_name,
        provider_name=provider_name,
        canonical_domain=canonical_domain,
        agent_type=agent_type,
        source_type=source_type,
        lifecycle_status=lifecycle_status,
        verification_status=verification_status,
        hosting_mode=hosting_mode,
        last_seen_at=now_iso(),
    )


def require_catalog_agent(conn: sqlite3.Connection, catalog_agent_id: str) -> dict[str, Any]:
    row = conn.execute(
        "select * from catalog_agents where catalog_agent_id = ?", (catalog_agent_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError(f"Unknown catalog agent: {catalog_agent_id}")
    return _row_to_dict(row)


def new_catalog_agent_id() -> str:
    """Generate a unique public catalog agent id (``cagt_`` + random suffix)."""
    import secrets

    return f"cagt_{secrets.token_urlsafe(9)}"


def get_catalog_agent_by_domain(conn: sqlite3.Connection, canonical_domain: str) -> dict[str, Any] | None:
    """Return the catalog agent row for a canonical domain, if any (cooldown check §17.4)."""
    row = conn.execute(
        "select * from catalog_agents where canonical_domain = ? order by created_at desc limit 1",
        (canonical_domain.lower().rstrip("."),),
    ).fetchone()
    return _row_to_dict(row) if row is not None else None


def get_catalog_agent_with_merchant(
    conn: sqlite3.Connection, catalog_agent_id: str
) -> dict[str, Any] | None:
    row = conn.execute(
        """
        select ca.*, m.name as merchant_name, m.city as merchant_city,
               m.service_area as merchant_service_area,
               m.tags_json as merchant_tags_json
        from catalog_agents ca
        left join merchants m on m.id = ca.merchant_id
        where ca.catalog_agent_id = ?
        """,
        (catalog_agent_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


# ── agent_capabilities ──────────────────────────────────────────────────────


def list_capabilities(conn: sqlite3.Connection, catalog_agent_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select * from agent_capabilities
        where catalog_agent_id = ?
        order by namespace, capability_id
        """,
        (catalog_agent_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def _list_capabilities_by_agent(
    conn: sqlite3.Connection, catalog_agent_ids: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """批量取 capabilities（审查 P3：搜索/列表每行 N+1 → 一次 IN 查询分组）。"""
    ids = [i for i in catalog_agent_ids if i]
    if not ids:
        return {}
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"""
        select * from agent_capabilities
        where catalog_agent_id in ({placeholders})
        order by namespace, capability_id
        """,
        ids,
    ).fetchall()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["catalog_agent_id"]), []).append(_row_to_dict(row))
    return grouped


def replace_capabilities(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    capabilities: list[dict[str, Any]],
) -> None:
    """Atomically replace all capabilities for a catalog agent."""
    conn.execute(
        "delete from agent_capabilities where catalog_agent_id = ?",
        (catalog_agent_id,),
    )
    ts = now_iso()
    for cap in capabilities:
        conn.execute(
            """
            insert into agent_capabilities(
                catalog_agent_id, namespace, capability_id, version,
                required, source, schema_url, spec_url, last_verified_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                catalog_agent_id,
                cap["namespace"],
                cap["capability_id"],
                cap.get("version", ""),
                int(cap.get("required", 0)),
                cap.get("source", ""),
                cap.get("schema_url", ""),
                cap.get("spec_url", ""),
                cap.get("last_verified_at", ts),
            ),
        )


# ── agent_endpoints ─────────────────────────────────────────────────────────


def list_endpoints(conn: sqlite3.Connection, catalog_agent_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "select * from agent_endpoints where catalog_agent_id = ? order by preference desc, endpoint_id",
        (catalog_agent_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def _list_endpoints_by_agent(
    conn: sqlite3.Connection, catalog_agent_ids: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """批量取 endpoints（审查 P3：N+1 → 一次 IN 查询分组）。"""
    ids = [i for i in catalog_agent_ids if i]
    if not ids:
        return {}
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"""
        select * from agent_endpoints
        where catalog_agent_id in ({placeholders})
        order by preference desc, endpoint_id
        """,
        ids,
    ).fetchall()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["catalog_agent_id"]), []).append(_row_to_dict(row))
    return grouped


def _list_skills_by_agent(
    conn: sqlite3.Connection, catalog_agent_ids: list[str]
) -> dict[str, list[dict[str, Any]]]:
    """批量取 skills（审查 P3：N+1 → 一次 IN 查询分组）。"""
    ids = [i for i in catalog_agent_ids if i]
    if not ids:
        return {}
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"""
        select * from agent_skills
        where catalog_agent_id in ({placeholders})
        order by skill_id
        """,
        ids,
    ).fetchall()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["catalog_agent_id"]), []).append(_row_to_dict(row))
    return grouped


# ── Search ──────────────────────────────────────────────────────────────────


def search_catalog_agents(
    conn: sqlite3.Connection,
    q: str = "",
    category: str = "",
    skill: str = "",
    capability: str = "",
    protocol: str = "",
    hosting_mode: str = "",
    verification_status: str = "",
    verified_after: str = "",
    verification_level: str = "",
    freshness_state: str = "",
    administrative_state: str = "",
    handoff_destination_types: str = "",
    limit: int = 20,
    cursor: str = "",
) -> tuple[list[dict[str, Any]], str | None]:
    """Hard-filtered, deterministically-ordered catalog agent search.

    三正交状态域过滤（v0.3 §7/§8）：verification_level / freshness_state /
    administrative_state 精确匹配各自域；handoff_destination_types 为
    逗号分隔的 KTH destination_type 词表（精确匹配，JSON 数组成员）。

    Returns (results, next_cursor).  next_cursor is None at the last page.
    """
    clauses: list[str] = []
    params: list[Any] = []

    # ── hard filters ────────────────────────────────────────────────────
    if hosting_mode:
        clauses.append("ca.hosting_mode = ?")
        params.append(hosting_mode)

    if verification_status:
        clauses.append("ca.verification_status = ?")
        params.append(verification_status)

    if verification_level:
        clauses.append("ca.verification_level = ?")
        params.append(verification_level)

    if freshness_state:
        clauses.append("ca.freshness_state = ?")
        params.append(freshness_state)

    if administrative_state:
        clauses.append("ca.administrative_state = ?")
        params.append(administrative_state)

    if handoff_destination_types:
        for dest in handoff_destination_types.split(","):
            dest = dest.strip()
            if not dest:
                continue
            clauses.append(
                "exists (select 1 from json_each(ca.handoff_destination_types) where json_each.value = ?)"
            )
            params.append(dest)

    if verified_after:
        clauses.append("ca.last_verified_at >= ?")
        params.append(verified_after)

    # q: free-text search across display_name, provider_name, canonical_domain
    if q:
        clauses.append(
            "(ca.display_name like ? escape '\\' or ca.provider_name like ? escape '\\'"
            " or ca.canonical_domain like ? escape '\\')"
        )
        like_q = _like_escaped(q)
        params.extend([like_q, like_q, like_q])

    # category: match against merchant tags（独立 schema 无 products 表——
    # 从 shopping-cli 提取时的遗留引用已在 v0.3 修复：products.category 子查询
    # 会 500（no such table: products），只保留 merchants.tags_json 匹配）。
    if category:
        clauses.append(
            "exists (select 1 from merchants m2 where m2.id = ca.merchant_id"
            " and m2.tags_json like ? escape '\\')"
        )
        params.append(_like_escaped(category))

    # capability: match against agent_capabilities
    if capability:
        clauses.append(
            """exists (
            select 1 from agent_capabilities ac
            where ac.catalog_agent_id = ca.catalog_agent_id
              and (ac.capability_id = ? or ac.namespace || ':' || ac.capability_id = ?)
            )"""
        )
        params.extend([capability, capability])

    # skill: match against agent_skills
    if skill:
        clauses.append(
            """exists (
            select 1 from agent_skills ask
            where ask.catalog_agent_id = ca.catalog_agent_id
              and (ask.skill_id = ? or ask.name like ? escape '\\')
            )"""
        )
        params.extend([skill, _like_escaped(skill)])

    # protocol: match against agent_endpoints
    if protocol:
        clauses.append(
            """exists (
            select 1 from agent_endpoints ae
            where ae.catalog_agent_id = ca.catalog_agent_id
              and (ae.protocol = ? or ae.protocol_version = ?)
            )"""
        )
        params.extend([protocol, protocol])

    # ── cursor（键集分页：谓词与 §8.3 排序键同键，审查 P1-6）───────────
    if cursor:
        cursor_clause, cursor_params = _agent_cursor_predicate(cursor)
        clauses.append(cursor_clause)
        params.extend(cursor_params)

    where = ""
    if clauses:
        where = "where " + " and ".join(clauses)

    # ── deterministic ordering (§8.3) ───────────────────────────────────
    # Priority: verification_status rank → last_verified_at desc → display_name → catalog_agent_id
    order = """
    order by
        case ca.verification_status
            when 'commerce_verified' then 0
            when 'agent_verified' then 1
            when 'domain_verified' then 2
            when 'profile_valid' then 3
            when 'discovered' then 4
            when 'stale' then 5
            when 'unreachable' then 6
            when 'suspended' then 7
            when 'rejected' then 8
            else 9
        end,
        ca.last_verified_at desc,
        coalesce(ca.display_name, ''),
        ca.catalog_agent_id
    """

    sql = f"""
        select ca.*, m.name as merchant_name, m.city as merchant_city,
               m.service_area as merchant_service_area,
               m.tags_json as merchant_tags_json
        from catalog_agents ca
        left join merchants m on m.id = ca.merchant_id
        {where}
        {order}
        limit ?
    """
    params.append(limit + 1)  # fetch one extra to detect next page

    rows = conn.execute(sql, params).fetchall()

    return _paginate_agent_rows(rows, limit)


# ── List (paginated) ─────────────────────────────────────────────────────────


def list_catalog_agents(
    conn: sqlite3.Connection,
    limit: int = 20,
    cursor: str = "",
) -> tuple[list[dict[str, Any]], str | None]:
    """Paginated list of all catalog agents, deterministically ordered."""
    clauses: list[str] = []
    params: list[Any] = []

    if cursor:
        clauses.append("ca.catalog_agent_id > ?")
        params.append(cursor)

    where = ""
    if clauses:
        where = "where " + " and ".join(clauses)

    order = """
    order by
        case ca.verification_status
            when 'commerce_verified' then 0
            when 'agent_verified' then 1
            when 'domain_verified' then 2
            when 'profile_valid' then 3
            when 'discovered' then 4
            when 'stale' then 5
            when 'unreachable' then 6
            when 'suspended' then 7
            when 'rejected' then 8
            else 9
        end,
        ca.last_verified_at desc,
        coalesce(ca.display_name, ''),
        ca.catalog_agent_id
    """

    sql = f"""
        select ca.*, m.name as merchant_name, m.city as merchant_city,
               m.service_area as merchant_service_area,
               m.tags_json as merchant_tags_json
        from catalog_agents ca
        left join merchants m on m.id = ca.merchant_id
        {where}
        {order}
        limit ?
    """
    params.append(limit + 1)

    rows = conn.execute(sql, params).fetchall()

    return _paginate_agent_rows(rows, limit)


def list_catalog_agents_by_merchant(
    conn: sqlite3.Connection,
    merchant_id: str,
    limit: int = 20,
    cursor: str = "",
) -> tuple[list[dict[str, Any]], str | None]:
    """Paginated list of catalog agents for a specific merchant."""
    clauses: list[str] = ["ca.merchant_id = ?"]
    params: list[Any] = [merchant_id]

    if cursor:
        clauses.append("ca.catalog_agent_id > ?")
        params.append(cursor)

    order = """
    order by
        case ca.verification_status
            when 'commerce_verified' then 0
            when 'agent_verified' then 1
            when 'domain_verified' then 2
            when 'profile_valid' then 3
            when 'discovered' then 4
            when 'stale' then 5
            when 'unreachable' then 6
            when 'suspended' then 7
            when 'rejected' then 8
            else 9
        end,
        ca.last_verified_at desc,
        coalesce(ca.display_name, ''),
        ca.catalog_agent_id
    """

    sql = f"""
        select ca.*, m.name as merchant_name, m.city as merchant_city,
               m.service_area as merchant_service_area,
               m.tags_json as merchant_tags_json
        from catalog_agents ca
        left join merchants m on m.id = ca.merchant_id
        where {' and '.join(clauses)}
        {order}
        limit ?
    """
    params.append(limit + 1)

    rows = conn.execute(sql, params).fetchall()

    return _paginate_agent_rows(rows, limit)


# ── Verification / snapshot persistence (W3) ────────────────────────────────
# These functions support the verification pipeline (§5.5, §5.6, §23).  They
# are intentionally narrow: snapshots keep public profile evidence with cache
# metadata, and verifications record domain-control/identity/commerce checks.


def set_verification_status(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    verification_status: str,
    *,
    last_verified_at: str | None = None,
) -> None:
    """Update a catalog agent's verification_status (legacy 单状态语义）。

    写入口统一映射到三正交域（v0.3 §7）：阶梯值 → verification_level，
    stale/unreachable → freshness_state，suspended/rejected →
    administrative_state；折叠投影列与三域同步写入，永不漂移。
    """
    level, fresh, admin = _domains_for_legacy_status(verification_status)
    set_state_domains(
        conn,
        catalog_agent_id,
        verification_level=level,
        freshness_state=fresh,
        administrative_state=admin,
        last_verified_at=last_verified_at,
    )


def set_state_domains(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    *,
    verification_level: str | None = None,
    freshness_state: str | None = None,
    administrative_state: str | None = None,
    handoff_destination_types: list[str] | None = None,
    last_verified_at: str | None = None,
    last_refresh_attempt_at: str | None = None,
    last_refresh_result: str | None = None,
) -> dict[str, Any]:
    """三正交状态域 + 折叠投影同步写入（v0.3 §7）。

    任一无参 domain 保持现状；全部校验枚举成员（fail-closed）。迁移合法性
    由服务层状态机约束，本函数只负责持久化。
    """
    current = require_catalog_agent(conn, catalog_agent_id)
    level = verification_level if verification_level is not None else current["verification_level"]
    fresh = freshness_state if freshness_state is not None else current["freshness_state"]
    admin = administrative_state if administrative_state is not None else current["administrative_state"]
    if level not in VERIFICATION_LEVELS:
        raise ValidationError(f"invalid verification_level: {level!r}")
    if fresh not in FRESHNESS_STATES:
        raise ValidationError(f"invalid freshness_state: {fresh!r}")
    if admin not in ADMINISTRATIVE_STATES:
        raise ValidationError(f"invalid administrative_state: {admin!r}")
    if handoff_destination_types is not None:
        for value in handoff_destination_types:
            if not isinstance(value, str) or not value:
                raise ValidationError(f"invalid handoff_destination_types entry: {value!r}")
    fields: dict[str, Any] = {
        "verification_level": level,
        "freshness_state": fresh,
        "administrative_state": admin,
        "verification_status": _fold_verification_status(level, fresh, admin),
    }
    if handoff_destination_types is not None:
        fields["handoff_destination_types"] = json.dumps(handoff_destination_types)
    if last_verified_at is not None:
        fields["last_verified_at"] = last_verified_at
    if last_refresh_attempt_at is not None:
        fields["last_refresh_attempt_at"] = last_refresh_attempt_at
    if last_refresh_result is not None:
        fields["last_refresh_result"] = last_refresh_result
    return _update_catalog_agent(conn, catalog_agent_id, **fields)


def set_catalog_agent_merchant(conn: sqlite3.Connection, catalog_agent_id: str, merchant_id: str) -> None:
    """Bind a catalog agent to a merchant (claim/ownership change §6.2)."""
    _update_catalog_agent(conn, catalog_agent_id, merchant_id=str(merchant_id or ""))


# ── agent_trust_observations (§5.7, private-only) ─────────────────────────────
# Commercial reputation and protocol trust observations.  PRIVATE-ONLY: never
# exposed through a public serializer, a search response, or any public API
# output (§3.4, §5.7).  The Public Catalog only exposes verification status,
# capability, freshness, and hosting mode.  Observations are stored as
# independent, kind-tagged records and are never merged into a combined
# reputation score — commercial reputation and protocol trust stay separate.

TRUST_OBSERVATION_KINDS = frozenset({
    "protocol_compliance",
    "timeout_rate",
    "schema_error_rate",
    "successful_exchange",
    "local_asserted_dispute",
})


def insert_trust_observation(
    conn: sqlite3.Connection,
    *,
    catalog_agent_id: str,
    kind: str,
    value: float,
    source: str = "",
    evidence_ref: str = "",
    observed_at: str = "",
    expires_at: str = "",
) -> int:
    """Append one private trust observation (§5.7).  Returns the observation id.

    The caller is responsible for kind/value validation (see
    ``kiwi_catalog.services.agent_trust_observations``).  ``value`` is a single
    numeric field — observations are never aggregated into a reputation score.
    """
    ts = observed_at or now_iso()
    cursor = conn.execute(
        """
        insert into agent_trust_observations(
            catalog_agent_id, kind, value, source, evidence_ref, observed_at, expires_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        """,
        (catalog_agent_id, kind, float(value), source, evidence_ref, ts, expires_at),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("trust observation insert did not return an id")
    return cursor.lastrowid


def list_trust_observations(
    conn: sqlite3.Connection,
    catalog_agent_id: str = "",
    kind: str = "",
) -> list[dict[str, Any]]:
    """Private read path for §5.7 observations.

    NOT for public use: the results must never reach a public serializer,
    search response, or any public API output.
    """
    clauses: list[str] = []
    params: list[Any] = []
    if catalog_agent_id:
        clauses.append("catalog_agent_id = ?")
        params.append(catalog_agent_id)
    if kind:
        clauses.append("kind = ?")
        params.append(kind)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"select * from agent_trust_observations {where} order by observed_at, observation_id",
        params,
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def count_trust_observations(
    conn: sqlite3.Connection,
    catalog_agent_id: str = "",
) -> int:
    """Total number of stored observations (private aggregate; no content)."""
    clauses: list[str] = []
    params: list[Any] = []
    if catalog_agent_id:
        clauses.append("catalog_agent_id = ?")
        params.append(catalog_agent_id)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    row = conn.execute(
        f"select count(*) from agent_trust_observations {where}",
        params,
    ).fetchone()
    return int(row[0] or 0)


def trust_observation_counts_by_kind(
    conn: sqlite3.Connection,
    catalog_agent_id: str = "",
) -> dict[str, int]:
    """Counts per §5.7 kind — kept separate, never merged into one score."""
    clauses: list[str] = []
    params: list[Any] = []
    if catalog_agent_id:
        clauses.append("catalog_agent_id = ?")
        params.append(catalog_agent_id)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"select kind, count(*) as n from agent_trust_observations {where} group by kind order by kind",
        params,
    ).fetchall()
    return {str(r["kind"]): int(r["n"]) for r in rows}


# ── agent_skills (§5.4) ─────────────────────────────────────────────────────


def replace_skills(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    skills: list[dict[str, Any]],
) -> None:
    """Atomically replace all skills for a catalog agent (public skills only)."""
    conn.execute(
        "delete from agent_skills where catalog_agent_id = ?",
        (catalog_agent_id,),
    )
    for skill in skills:
        conn.execute(
            """
            insert into agent_skills(
                catalog_agent_id, skill_id, name, description,
                tags_json, input_modes_json, output_modes_json
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                catalog_agent_id,
                skill.get("skill_id", ""),
                skill.get("name", ""),
                skill.get("description", ""),
                skill.get("tags_json", "[]"),
                skill.get("input_modes_json", "[]"),
                skill.get("output_modes_json", "[]"),
            ),
        )


def list_skills(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        select * from agent_skills
        where catalog_agent_id = ?
        order by skill_id
        """,
        (catalog_agent_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


# ── agent_endpoints (profile endpoints) ─────────────────────────────────────


def upsert_profile_endpoints(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    endpoints: list[dict[str, Any]],
) -> None:
    """Upsert agent_card/ucp_profile endpoints, preserving other endpoint kinds.

    Only ``kind`` in (agent_card, ucp_profile) is managed here so unrelated
    endpoints (a2a, hosted_gateway) are never deleted by the verifier.
    """
    for ep in endpoints:
        kind = str(ep.get("kind", ""))
        if kind not in ("agent_card", "ucp_profile"):
            continue
        row = conn.execute(
            "select endpoint_id from agent_endpoints where catalog_agent_id = ? and kind = ?",
            (catalog_agent_id, kind),
        ).fetchone()
        ts = now_iso()
        if row is None:
            conn.execute(
                """
                insert into agent_endpoints(
                    catalog_agent_id, kind, url, protocol, protocol_version,
                    preference, auth_summary_json, status, last_checked_at
                ) values (?, ?, ?, ?, ?, ?, '{}', 'active', ?)
                """,
                (
                    catalog_agent_id,
                    kind,
                    ep.get("url", ""),
                    ep.get("protocol", ""),
                    ep.get("protocol_version", ""),
                    int(ep.get("preference", 0)),
                    ts,
                ),
            )
        else:
            conn.execute(
                """
                update agent_endpoints
                set url = ?, protocol = ?, protocol_version = ?, preference = ?,
                    last_checked_at = ?
                where endpoint_id = ?
                """,
                (
                    ep.get("url", ""),
                    ep.get("protocol", ""),
                    ep.get("protocol_version", ""),
                    int(ep.get("preference", 0)),
                    ts,
                    row["endpoint_id"],
                ),
            )


# ── Audit ───────────────────────────────────────────────────────────────────


def append_catalog_audit(
    conn: sqlite3.Connection,
    catalog_agent_id: str,
    actor: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> int:
    """Write a catalog-scoped audit event.  Returns the new event id."""
    from kiwi_catalog.db.session import encode_json as _encode

    payload = dict(details or {})
    payload.setdefault("schema_version", 1)
    payload.setdefault("event_type", str(event or ""))
    payload.setdefault("catalog_agent_id", catalog_agent_id)

    cursor = conn.execute(
        """
        insert into audit_events(conversation_id, actor, event, details_json, created_at)
        values (?, ?, ?, ?, ?)
        """,
        ("", actor, event, _encode(payload), now_iso()),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("audit event insert did not return an id")
    return cursor.lastrowid


# ── Registration abuse controls (§17.4) ─────────────────────────────────────

CATALOG_REGISTER_WINDOW_SECONDS = 3600


def enforce_catalog_register_domain_limit(
    conn: sqlite3.Connection,
    canonical_domain: str,
    limit: int,
    current: Any = None,
) -> None:
    """Raise RateLimitError when *canonical_domain* exceeds its hourly register budget.

    Prevents using the public register route as a large-scale SSRF scanner
    (§17.4 per-domain limits): the same canonical domain may only trigger a
    bounded number of registrations (and therefore profile fetches) per hour.

    Delegates to the shared fixed-window core (v3.0-P5) — see
    ``kiwi_catalog.services.rate_limit`` for the backend abstraction.
    """
    from kiwi_catalog.services.rate_limit import (
        SQLiteRateLimitBackend,
        enforce_rate_limit,
    )

    backend = SQLiteRateLimitBackend(
        conn, table="agent_catalog_register_limits", key_column="canonical_domain"
    )
    enforce_rate_limit(
        backend,
        key=canonical_domain.lower().rstrip("."),
        limit=limit,
        window_seconds=CATALOG_REGISTER_WINDOW_SECONDS,
        description=f"catalog registration for domain {canonical_domain}",
        current=current,
    )
