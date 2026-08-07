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
from dataclasses import dataclass
from typing import Callable

CURRENT_SCHEMA_VERSION = 7


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
        updated_at text not null,
        foreign key (merchant_id) references merchants(id),
        foreign key (hosted_runtime_agent_id) references agents(id)
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
        last_checked_at text not null default '',
        foreign key (catalog_agent_id) references catalog_agents(catalog_agent_id)
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
        primary key (catalog_agent_id, namespace, capability_id),
        foreign key (catalog_agent_id) references catalog_agents(catalog_agent_id)
    )
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
        primary key (catalog_agent_id, skill_id),
        foreign key (catalog_agent_id) references catalog_agents(catalog_agent_id)
    )
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
        validation_status text not null default 'pending',
        foreign key (catalog_agent_id) references catalog_agents(catalog_agent_id)
    )
    """,
    """
    create table if not exists agent_verifications (
        verification_id integer primary key autoincrement,
        catalog_agent_id text not null,
        verification_type text not null,
        result text not null default '',
        evidence_json text not null default '{}',
        checked_at text not null default '',
        expires_at text not null default '',
        foreign key (catalog_agent_id) references catalog_agents(catalog_agent_id)
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
    """§5.7 private-only agent_trust_observations table."""



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
    """
    conn.execute(
        "create unique index if not exists idx_catalog_agents_merchant_unique"
        " on catalog_agents(merchant_id) where merchant_id != ''"
    )


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "agent_catalog", migration_001_agent_catalog),
    Migration(2, "agent_catalog_register_limits", migration_002_agent_catalog_register_limits),
    Migration(3, "agent_catalog_write_idempotency", migration_003_agent_catalog_write_idempotency),
    Migration(4, "agent_trust_observations", migration_004_agent_trust_observations),
    Migration(5, "a2a_inbound_idempotency", migration_005_a2a_inbound_idempotency),
    Migration(6, "verification_queue_tasks", migration_006_verification_queue_tasks),
    Migration(7, "merchant_single_agent", migration_007_merchant_single_agent),
)


def run_migrations(conn: sqlite3.Connection) -> None:
    current_version = schema_user_version(conn)
    for migration in MIGRATIONS:
        if migration.version <= current_version:
            continue
        migration.apply(conn)
        _set_schema_user_version(conn, migration.version)
    conn.commit()
