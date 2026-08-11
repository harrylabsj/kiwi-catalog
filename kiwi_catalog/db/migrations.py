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

"""kiwi-catalog schema migrations (阶段 2 独立库).

Catalog migration chain extracted from shopping-cli db/migrations.py
(v10–v15), renumbered 1–6.  The two repos now evolve their schema versions
independently.  Table DDL that already lives in db/models.py is re-created
idempotently here (create table if not exists), matching the shopping-cli
split between models.py and migrations.

Extraction date: 2026-08-06.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

CURRENT_SCHEMA_VERSION = 22


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def schema_user_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("pragma user_version").fetchone()
    return int(row[0] or 0) if row is not None else 0


def _set_schema_user_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(f"pragma user_version = {int(version)}")


# v1 — agent catalog foundation (shopping-cli v10)
_AGENT_CATALOG_DDL = [
    """
    create table if not exists catalog_agents (
        catalog_agent_id text primary key,
        merchant_id text,
        hosted_runtime_agent_id text,
        display_name text not null,
        provider_name text not null default '',
        canonical_domain text not null default '',
        agent_type text not null default '',
        source_type text not null
            check(source_type in ('hosted','self_registered','discovered','imported','admin_curated')),
        lifecycle_status text not null default 'active'
            check(lifecycle_status in ('active','inactive','deprecated')),
        verification_status text not null default 'discovered'
            check(verification_status in (
                'discovered','profile_valid','domain_verified','agent_verified',
                'commerce_verified','stale','rejected','suspended','unreachable'
            )),
        hosting_mode text not null default 'unknown'
            check(hosting_mode in ('direct','hosted','hybrid','unknown')),
        first_seen_at text not null,
        last_seen_at text not null,
        last_verified_at text not null default '',
        created_at text not null,
        updated_at text not null
    )
    """,
    """
    create table if not exists agent_endpoints (
        endpoint_id integer primary key autoincrement,
        catalog_agent_id text not null,
        kind text not null check(kind in ('a2a','agent_card','ucp_profile','hosted_gateway')),
        url text not null default '',
        protocol text not null default '',
        protocol_version text not null default '',
        preference integer not null default 0,
        auth_summary_json text not null default '{}',
        status text not null default 'active',
        last_checked_at text not null default ''
    )
    """,
    """
    create table if not exists agent_capabilities (
        catalog_agent_id text not null,
        namespace text not null,
        capability_id text not null,
        version text not null default '',
        required integer not null default 0,
        source text not null default '',
        schema_url text not null default '',
        spec_url text not null default '',
        last_verified_at text not null default '',
        primary key (catalog_agent_id, namespace, capability_id)    )
    """,
    """
    create table if not exists agent_skills (
        catalog_agent_id text not null,
        skill_id text not null,
        name text not null,
        description text not null default '',
        tags_json text not null default '[]',
        input_modes_json text not null default '[]',
        output_modes_json text not null default '[]',
        primary key (catalog_agent_id, skill_id)    )
    """,
    """
    create table if not exists agent_profile_snapshots (
        snapshot_id integer primary key autoincrement,
        catalog_agent_id text not null,
        profile_type text not null check(profile_type in ('agent_card','ucp')),
        source_url text not null default '',
        etag text not null default '',
        last_modified text not null default '',
        content_hash text not null default '',
        raw_json text not null default '{}',
        fetched_at text not null default '',
        fresh_until text not null default '',
        validation_status text not null default 'pending'    )
    """,
    """
    create table if not exists agent_verifications (
        verification_id integer primary key autoincrement,
        catalog_agent_id text not null,
        verification_type text not null,
        result text not null default '',
        evidence_json text not null default '{}',
        checked_at text not null default '',
        expires_at text not null default ''
    )
    """,
]

# v5 — a2a inbound idempotency ledger (shopping-cli v14)
_A2A_INBOUND_IDEMPOTENCY_DDL = """
    create table if not exists a2a_inbound_idempotency (
        sender_identity text not null,
        message_id text not null,
        digest text not null,
        status text not null default 'processing',
        response_json text not null default '{}',
        created_at text not null,
        updated_at text not null,
        primary key (sender_identity, message_id)
    )
"""

# v6 — persistent verification queue ledger (shopping-cli v15)
_VERIFICATION_QUEUE_TASKS_DDL = """
    create table if not exists verification_queue_tasks (
        task_id text primary key,
        catalog_agent_id text not null,
        kind text not null,
        actor text not null default 'verification_worker',
        status text not null default 'pending'
            check (status in ('pending','running','completed','failed','timeout')),
        enqueued_at real not null,
        started_at real not null default 0,
        finished_at real not null default 0,
        verification_status text not null default '',
        error text not null default '',
        result_json text not null default '{}',
        created_at text not null,
        updated_at text not null
    );
"""
_VERIFICATION_QUEUE_RECOVERY_INDEX_DDL = """
    create index if not exists idx_verification_queue_recovery
        on verification_queue_tasks(status)
"""

def migration_001_agent_catalog(conn: sqlite3.Connection) -> None:
    for statement in _AGENT_CATALOG_DDL:
        conn.execute(statement)


def migration_002_agent_catalog_register_limits(conn: sqlite3.Connection) -> None:
    """Per-domain registration budget (§17.4) for the public register route."""
    conn.execute("""
        create table if not exists agent_catalog_register_limits (
            canonical_domain text not null,
            window_start text not null,
            request_count integer not null default 0,
            updated_at text not null,
            primary key (canonical_domain, window_start)
        )
        """)


def migration_003_agent_catalog_write_idempotency(conn: sqlite3.Connection) -> None:
    """Generic idempotency + rate-limit tables for Agent Catalog writes (§10.4)."""
    conn.execute("""
        create table if not exists agent_catalog_write_idempotency (
            endpoint text not null,
            actor_key text not null,
            idempotency_key text not null,
            request_hash text not null,
            status text not null,
            response_json text not null default '{}',
            created_at text not null,
            updated_at text not null,
            primary key (endpoint, actor_key, idempotency_key)
        )
        """)
    conn.execute("""
        create table if not exists agent_catalog_write_rate_limits (
            actor_key text not null,
            window_start text not null,
            request_count integer not null default 0,
            updated_at text not null,
            primary key (actor_key, window_start)
        )
        """)


def migration_004_agent_trust_observations(conn: sqlite3.Connection) -> None:
    """§5.7 private-only agent_trust_observations table.

    DDL 与 db/models.py 的 SCHEMA 逐字一致——此前为空函数，旧库走迁移路径
    升级后缺少该表（fresh DB 走 SCHEMA 有，同一 schema 两种行为）。
    """
    conn.execute(
        """
        create table if not exists agent_trust_observations (
            observation_id integer primary key autoincrement,
            catalog_agent_id text not null,
            kind text not null
                check(kind in (
                    'protocol_compliance','timeout_rate','schema_error_rate',
                    'successful_exchange','local_asserted_dispute'
                )),
            value real not null,
            source text not null default '',
            evidence_ref text not null default '',
            observed_at text not null,
            expires_at text not null default ''
        )
        """
    )



def migration_005_a2a_inbound_idempotency(conn: sqlite3.Connection) -> None:
    """Hosted A2A inbound idempotency ledger (binding rc1 §3.6)."""
    conn.execute(_A2A_INBOUND_IDEMPOTENCY_DDL)


def migration_006_verification_queue_tasks(conn: sqlite3.Connection) -> None:
    """Persistent verification queue ledger (v3.0-P4)."""
    conn.execute(_VERIFICATION_QUEUE_TASKS_DDL)
    conn.execute(_VERIFICATION_QUEUE_RECOVERY_INDEX_DDL)


def migration_007_merchant_single_agent(conn: sqlite3.Connection) -> None:
    """一商家一 agent 约束：merchant_id 非空时唯一（部分唯一索引）。

    弱引用 schema 下 merchant_id 是普通列——本索引从数据层兜底
    「一个商家只能有一个 catalog agent」，服务层另有显式校验
    （ConflictError 而非 IntegrityError）。

    审查 P2：建索引前检测历史重复绑定——旧库若已存在重复，直接建索引会
    硬失败让整条迁移链回滚、服务无法启动且无任何诊断；改为 fail-closed
    给出数据清单。
    """
    duplicates = conn.execute(
        "select merchant_id, count(*) as n, group_concat(catalog_agent_id, ',') as ids"
        " from catalog_agents where merchant_id != ''"
        " group by merchant_id having count(*) > 1"
    ).fetchall()
    if duplicates:
        detail = "; ".join(
            f"{row['merchant_id']}(n={row['n']}: {row['ids']})" for row in duplicates
        )
        raise RuntimeError(
            "cannot create merchant unique index — duplicate merchant bindings exist: "
            + detail
        )
    conn.execute(
        "create unique index if not exists idx_catalog_agents_merchant_unique"
        " on catalog_agents(merchant_id) where merchant_id != ''"
    )


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """SQLite 列存在性检查（幂等 ALTER 的前提）。"""
    rows = conn.execute(f"pragma table_info({table})").fetchall()
    return any(row[1] == column for row in rows)


def migration_008_three_state_domains(conn: sqlite3.Connection) -> None:
    """三正交状态域（产品文档 kiwi-catalog v0.3 §7）。

    legacy 单列 ``verification_status`` 保留为折叠投影（折叠优先级
    rejected > suspended > unreachable > stale > verification_level），
    legacy /v1/agent-catalog/* 消费方与 metrics 继续读它。新列：

    * verification_level —— 证据链级别（5 阶阶梯）；
    * freshness_state    —— FRESH / STALE / UNREACHABLE；
    * administrative_state —— ACTIVE / SUSPENDED / REJECTED（终态）；
    * handoff_destination_types —— KTH destination_type 词表 JSON 数组；
    * last_refresh_attempt_at / last_refresh_result —— 刷新审计。

    幂等：全新库的列由 models.py SCHEMA 直接创建（本迁移对已存在的列跳过
    ALTER，避免 duplicate column）；旧库（user_version < 8）在这里补列。
    回填：legacy 的 stale/unreachable 归 freshness，suspended/rejected 归
    administrative，阶梯值归 verification_level；折叠结果与旧值一致。
    回填在 migration 运行窗口内是安全的（user_version 门保证每库只跑一次）。

    审查 P2：回填加 WHERE 守卫——只回填仍持默认值（未被中间版本写入）的行；
    中间版本已写入真实三域值的行不得被 legacy 推导值覆盖（数据丢失不可恢复）。
    """
    new_columns: list[tuple[str, str]] = [
        (
            "verification_level",
            (
                "text not null default 'discovered' check(verification_level in ("
                " 'discovered','profile_valid','domain_verified','agent_verified','commerce_verified'))"
            ),
        ),
        (
            "freshness_state",
            "text not null default 'fresh' check(freshness_state in ('fresh','stale','unreachable'))",
        ),
        (
            "administrative_state",
            "text not null default 'active' check(administrative_state in ('active','suspended','rejected'))",
        ),
        ("handoff_destination_types", "text not null default '[]'"),
        ("last_refresh_attempt_at", "text not null default ''"),
        ("last_refresh_result", "text not null default ''"),
    ]
    for name, ddl in new_columns:
        if not _column_exists(conn, "catalog_agents", name):
            conn.execute(f"alter table catalog_agents add column {name} {ddl}")
    conn.execute(
        """
        update catalog_agents set
          verification_level = case
            when verification_status in (
              'discovered','profile_valid','domain_verified','agent_verified','commerce_verified')
            then verification_status else 'discovered' end,
          freshness_state = case
            when verification_status = 'stale' then 'stale'
            when verification_status = 'unreachable' then 'unreachable'
            else 'fresh' end,
          administrative_state = case
            when verification_status = 'suspended' then 'suspended'
            when verification_status = 'rejected' then 'rejected'
            else 'active' end
        where verification_level = 'discovered'
          and freshness_state = 'fresh'
          and administrative_state = 'active'
        """
    )


def migration_009_shadow_tables(conn: sqlite3.Connection) -> None:
    """影子表（merchants / audit_events / meta）补齐。

    独立 schema 的弱引用影子表在 fresh SCHEMA（models.py）里创建，但迁移链
    提取时遗漏——旧库（user_version < 9）升级后 audit/merchants 缺失，审计
    事件无处落。DDL 与 models.py 逐字一致（弱引用、无 FK）。
    """
    conn.execute(
        """
        create table if not exists merchants (
            id text primary key,
            name text not null,
            city text not null default '',
            service_area text not null default '',
            contact text not null default '',
            hours text not null default '',
            automation_boundaries text not null default '',
            tags_json text not null default '[]',
            created_at text not null,
            updated_at text not null
        )
        """
    )
    conn.execute(
        """
        create table if not exists audit_events (
            id integer primary key autoincrement,
            conversation_id text not null default '',
            actor text not null,
            event text not null,
            details_json text not null default '{}',
            created_at text not null
        )
        """
    )
    conn.execute(
        """
        create table if not exists meta (
            key text primary key,
            value text not null default ''
        )
        """
    )


_MERCHANT_TOKEN_DDL = [
    """
    create table if not exists merchant_tokens (
        merchant_id text primary key,
        token_hash text not null,
        token_encrypted text not null default '',
        status text not null default 'active'
            check(status in ('active','revoked')),
        issued_at text not null,
        rotated_at text not null default '',
        revoked_at text not null default ''
    ) without rowid
    """,
    """
    create table if not exists merchant_applications (
        application_id integer primary key autoincrement,
        status text not null default 'pending'
            check(status in ('pending','approved','rejected')),
        domain text not null,
        agent_name text not null,
        contact_email text not null,
        purpose text not null default '',
        phone text not null default '',
        merchant_id text not null default '',
        review_note text not null default '',
        account_id integer not null default 0,
        created_at text not null,
        reviewed_at text not null default ''
    )
    """,
    """
    create table if not exists merchant_application_limits (
        actor_key text not null,
        window_start text not null,
        request_count integer not null default 0,
        updated_at text not null,
        primary key (actor_key, window_start)
    )
    """,
    """
    create table if not exists usage_metrics (
        metric text not null,
        day text not null,
        count integer not null default 0,
        updated_at text not null,
        primary key (metric, day)
    )
    """,
]


_USAGE_METRICS_DDL = [
    """
    create table if not exists usage_metrics (
        metric text not null,
        day text not null,
        count integer not null default 0,
        updated_at text not null,
        primary key (metric, day)
    )
    """,
]

_ACCOUNTS_DDL = [
    """
    create table if not exists merchant_accounts (
        account_id integer primary key autoincrement,
        email text not null unique,
        password_hash text not null,
        merchant_id text not null default '',
        application_id integer not null default 0,
        status text not null default 'active'
            check(status in ('active','suspended')),
        created_at text not null,
        updated_at text not null
    )
    """,
    """
    create table if not exists account_sessions (
        session_token_hash text primary key,
        account_id integer not null,
        expires_at text not null,
        created_at text not null
    )
    """,
]


_COMMERCE_LISTINGS_DDL = [
    """
    create table if not exists commerce_listings (
        id integer primary key autoincrement,
        listing_id text not null unique,
        listing_type text not null
            check(listing_type in ('product','capability')),
        owner_agent_id text not null,
        merchant_id text not null,
        source_product_ref text,
        publisher_listing_key text,
        source_revision text not null default '',
        title text not null,
        summary text not null default '',
        category text not null,
        brand text not null default '',
        attributes_json text not null default '{}',
        regions_json text not null default '[]',
        tags_json text not null default '[]',
        commercial_hints_json text not null default '{}',
        handoff_destination_types_json text not null default '[]',
        listing_digest text not null,
        publication_state text not null default 'ACTIVE'
            check(publication_state in ('ACTIVE','WITHDRAWN','SUSPENDED')),
        listing_freshness_state text not null default 'FRESH'
            check(listing_freshness_state in ('FRESH','STALE')),
        published_at text not null,
        updated_at text not null,
        fresh_until text not null,
        created_at text not null
    )
    """,
    """
    create index if not exists idx_commerce_listings_owner
        on commerce_listings(owner_agent_id)
    """,
    """
    create index if not exists idx_commerce_listings_type_category
        on commerce_listings(listing_type, category)
    """,
    """
    create index if not exists idx_commerce_listings_publication_freshness
        on commerce_listings(publication_state, listing_freshness_state)
    """,
    """
    create index if not exists idx_commerce_listings_updated
        on commerce_listings(updated_at, id)
    """,
    """
    create unique index if not exists idx_commerce_listings_product_ref_unique
        on commerce_listings(owner_agent_id, listing_type, source_product_ref)
        where source_product_ref is not null
    """,
    """
    create unique index if not exists idx_commerce_listings_publisher_key_unique
        on commerce_listings(owner_agent_id, listing_type, publisher_listing_key)
        where publisher_listing_key is not null
    """,
]


def migration_011_search_indexes_and_domain_unique(conn: sqlite3.Connection) -> None:
    """审查 P2：分页/翻转索引 + 一域一 agent 数据层兜底。

    - idx_commerce_listings_fresh_until（partial，FRESH 行）：STALE 惰性翻转
      （每次读/搜索执行 ``fresh_until < now AND state='FRESH'`` 的 UPDATE）
      此前全表扫描 + WAL 写放大，匿名读洪泛 = 写锁竞争放大器；
    - idx_catalog_agents_canonical_domain_unique（partial，非空域）：
      canonical_domain 并发注册重复行的数据层兜底（服务层 check-then-act
      有竞态窗口，曾产生永久重复行）。建索引前检测历史重复——fail-closed
      给出数据清单而非静默失败（v7 merchant 唯一索引的教训）。
    """
    conn.execute(
        "create index if not exists idx_commerce_listings_fresh_until"
        " on commerce_listings(fresh_until) where listing_freshness_state = 'FRESH'"
    )
    duplicates = conn.execute(
        "select canonical_domain, count(*) as n,"
        " group_concat(catalog_agent_id, ',') as ids"
        " from catalog_agents where canonical_domain != ''"
        " group by canonical_domain having count(*) > 1"
    ).fetchall()
    if duplicates:
        detail = "; ".join(
            f"{row['canonical_domain']}(n={row['n']}: {row['ids']})" for row in duplicates
        )
        raise RuntimeError(
            "cannot create canonical_domain unique index — duplicate domains exist: " + detail
        )
    conn.execute(
        "create unique index if not exists idx_catalog_agents_canonical_domain_unique"
        " on catalog_agents(canonical_domain) where canonical_domain != ''"
    )


def migration_010_commerce_listings(conn: sqlite3.Connection) -> None:
    """Listing 域（产品文档 kiwi-catalog v0.4；升级计划 §3）。

    DDL 与 db/models.py 的 SCHEMA 逐字一致（tests/test_shadow_tables.py
    锁定 fresh 路径与迁移路径等价）。listing_freshness_state 是 Listing 域
    独立状态（FRESH/STALE 大写），与 catalog_agents.freshness_state 分离。
    """
    for statement in _COMMERCE_LISTINGS_DDL:
        conn.execute(statement)


def migration_012_merchant_tokens(conn: sqlite3.Connection) -> None:
    """Merchant token 分发（docs/kiwi-catalog-token-portal-design-v0.1 §3）。

    DDL 与 db/models.py 的 SCHEMA 逐字一致（tests/test_shadow_tables.py
    锁定 fresh 路径与迁移路径等价）。merchant_tokens 每 merchant 至多一条
    active 行；token_hash = SHA-256(明文)，明文永不落库。
    """
    for statement in _MERCHANT_TOKEN_DDL:
        conn.execute(statement)


def migration_013_usage_metrics(conn: sqlite3.Connection) -> None:
    """运营埋点（dashboard 数据源）。

    DDL 与 db/models.py 的 SCHEMA 逐字一致（test_shadow_tables 守护）。
    """
    for statement in _USAGE_METRICS_DDL:
        conn.execute(statement)


def migration_014_accounts(conn: sqlite3.Connection) -> None:
    """账号体系（docs/accounts.md）：幂等 ALTER + 回填 + 新表。

    - merchant_tokens 加 token_encrypted（Fernet 加密明文，存量行回填空串）；
    - merchant_applications 加 account_id（存量行回填 0）；
    - merchant_accounts / account_sessions 建表。
    """
    for column, table in (
        ("token_encrypted text not null default ''", "merchant_tokens"),
        ("account_id integer not null default 0", "merchant_applications"),
    ):
        existing = {
            str(row[1])
            for row in conn.execute(f"pragma table_info({table})").fetchall()
        }
        column_name = column.split()[0]
        if column_name not in existing:
            conn.execute(f"alter table {table} add column {column}")
    for statement in _ACCOUNTS_DDL:
        conn.execute(statement)


def migration_015_email_verification(conn: sqlite3.Connection) -> None:
    """邮箱验证（docs/accounts.md）：merchant_accounts 幂等加 3 列。"""
    for column in (
        "email_verified integer not null default 0",
        "verification_code_hash text not null default ''",
        "verification_expires_at text not null default ''",
    ):
        existing = {
            str(row[1]) for row in conn.execute("pragma table_info(merchant_accounts)").fetchall()
        }
        column_name = column.split()[0]
        if column_name not in existing:
            conn.execute(f"alter table merchant_accounts add column {column}")


def migration_016_account_profile(conn: sqlite3.Connection) -> None:
    """账户基本信息（docs/accounts.md）：merchant_name/phone 列 + 工单 phone。"""
    for column, table in (
        ("merchant_name text not null default ''", "merchant_accounts"),
        ("phone text not null default ''", "merchant_accounts"),
        ("phone text not null default ''", "merchant_applications"),
    ):
        existing = {
            str(row[1]) for row in conn.execute(f"pragma table_info({table})").fetchall()
        }
        column_name = column.split()[0]
        if column_name not in existing:
            conn.execute(f"alter table {table} add column {column}")
    for column, table in (
        ("token_encrypted text not null default ''", "merchant_tokens"),
        ("account_id integer not null default 0", "merchant_applications"),
    ):
        existing = {
            str(row[1])
            for row in conn.execute(f"pragma table_info({table})").fetchall()
        }
        column_name = column.split()[0]
        if column_name not in existing:
            conn.execute(f"alter table {table} add column {column}")
    for statement in _ACCOUNTS_DDL:
        conn.execute(statement)


def migration_017_drop_domain_unique_index(conn: sqlite3.Connection) -> None:
    """注册规则（2026-08-10 用户要求）：一个域名可注册多个商家，一个商家只能有一个 agent。

    - 删除 `idx_catalog_agents_canonical_domain_unique`（一域一 agent 的数据层
      兜底）——域名不再是全局唯一键，不同商家的 agent 可注册同一域名；
    - 保留 `idx_catalog_agents_merchant_unique`（一商家一 agent）不变。
    register 写入层已改为以 merchant 为主键（services/agent_catalog_writes.py）。
    """
    conn.execute("drop index if exists idx_catalog_agents_canonical_domain_unique")


_BUYER_SEARCH_EVENTS_DDL = [
    """
create table if not exists buyer_search_events (
        event_id integer primary key autoincrement,
        search_type text not null,
        query text not null default '',
        filters_json text not null default '{}',
        result_count integer not null default 0,
        result_summary_json text not null default '[]',
        created_at text not null
    )
    """,
    """
create index if not exists idx_buyer_search_events_created
        on buyer_search_events(created_at desc, event_id desc)

    """,
]


def migration_018_buyer_search_events(conn: sqlite3.Connection) -> None:
    """买家搜索事件保留（运营数据源）。

    DDL 与 db/models.py 的 SCHEMA 逐字一致（test_shadow_tables 守护）。
    """
    for statement in _BUYER_SEARCH_EVENTS_DDL:
        conn.execute(statement)


def migration_019_listing_handoff_destination_ref(conn: sqlite3.Connection) -> None:
    """commerce_listings.handoff_destination_ref 列（每商品成交入口，KTH）。

    幂等 ALTER（参照 v16 模式）；fresh 路径由 models.py SCHEMA 创建，旧库在此补列。
    """
    if not _column_exists(conn, "commerce_listings", "handoff_destination_ref"):
        conn.execute(
            "alter table commerce_listings add column handoff_destination_ref text not null default ''"
        )


def migration_020_merchant_shopping_token(conn: sqlite3.Connection) -> None:
    """merchant_tokens.shopping_token_encrypted 列（"我的商品"写回 shopping-cli 用）。

    商家在 portal 绑定自己的 SHOPPING_MERCHANT_TOKEN，Fernet 加密存储（与 owner
    token 的 token_encrypted 同机制）。幂等 ALTER（参照 v16 模式）。
    """
    if not _column_exists(conn, "merchant_tokens", "shopping_token_encrypted"):
        conn.execute(
            "alter table merchant_tokens add column shopping_token_encrypted text not null default ''"
        )


def migration_021_merchant_application_agent_id(conn: sqlite3.Connection) -> None:
    """merchant_applications.agent_id 列（申请令牌必填，商家指定 agent 标识）。"""
    if not _column_exists(conn, "merchant_applications", "agent_id"):
        conn.execute(
            "alter table merchant_applications add column agent_id text not null default ''"
        )


_DISCOVERY_ENTRIES_DDL = [
    """
    create table if not exists discovery_entries (
        entry_id text primary key,
        merchant_id text not null,
        name text not null,
        created_at text not null,
        updated_at text not null
    )
    """,
    """
    create index if not exists idx_discovery_entries_merchant
        on discovery_entries(merchant_id)
    """,
    """
    create index if not exists idx_discovery_entries_name_lower
        on discovery_entries(lower(name))
    """,
]


def migration_022_discovery_entries(conn: sqlite3.Connection) -> None:
    """发现条目表（catalog-local discovery entry，替代 shopping-cli 代理通道）。

    商家经门户上传商品名称（仅名称），买家 agent 经 /v1/discovery/search
    匿名检索并按 agent 引用跳转。DDL 与 db/models.py 的 SCHEMA 逐字一致
    （tests/test_shadow_tables.py 锁定 fresh 路径与迁移路径等价）。

    伴随变更（无数据迁移——代理/绑定功能从未部署）：
    merchant_tokens.shopping_token_encrypted 列保留在库中（无害），但代码
    已不再读写——shopping-token 绑定面随代理通道一并移除。
    """
    for statement in _DISCOVERY_ENTRIES_DDL:
        conn.execute(statement)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "agent_catalog", migration_001_agent_catalog),
    Migration(2, "agent_catalog_register_limits", migration_002_agent_catalog_register_limits),
    Migration(3, "agent_catalog_write_idempotency", migration_003_agent_catalog_write_idempotency),
    Migration(4, "agent_trust_observations", migration_004_agent_trust_observations),
    Migration(5, "a2a_inbound_idempotency", migration_005_a2a_inbound_idempotency),
    Migration(6, "verification_queue_tasks", migration_006_verification_queue_tasks),
    Migration(7, "merchant_single_agent", migration_007_merchant_single_agent),
    Migration(8, "three_state_domains", migration_008_three_state_domains),
    Migration(9, "shadow_tables", migration_009_shadow_tables),
    Migration(10, "commerce_listings", migration_010_commerce_listings),
    Migration(11, "search_indexes_and_domain_unique", migration_011_search_indexes_and_domain_unique),
    Migration(12, "merchant_tokens", migration_012_merchant_tokens),
    Migration(13, "usage_metrics", migration_013_usage_metrics),
    Migration(14, "accounts", migration_014_accounts),
    Migration(15, "email_verification", migration_015_email_verification),
    Migration(16, "account_profile", migration_016_account_profile),
    Migration(17, "drop_domain_unique_index", migration_017_drop_domain_unique_index),
    Migration(18, "buyer_search_events", migration_018_buyer_search_events),
    Migration(19, "listing_handoff_destination_ref", migration_019_listing_handoff_destination_ref),
    Migration(20, "merchant_shopping_token", migration_020_merchant_shopping_token),
    Migration(21, "merchant_application_agent_id", migration_021_merchant_application_agent_id),
    Migration(22, "discovery_entries", migration_022_discovery_entries),
)


def run_migrations(conn: sqlite3.Connection) -> None:
    current_version = schema_user_version(conn)
    for migration in MIGRATIONS:
        if migration.version <= current_version:
            continue
        migration.apply(conn)
        _set_schema_user_version(conn, migration.version)
    conn.commit()
